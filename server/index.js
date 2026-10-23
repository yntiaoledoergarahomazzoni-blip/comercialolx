import 'dotenv/config';
import crypto from 'node:crypto';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import express from 'express';
import helmet from 'helmet';
import cookieParser from 'cookie-parser';
import { rateLimit } from 'express-rate-limit';
import { z } from 'zod';
import { applicationDefault, cert, initializeApp } from 'firebase-admin/app';
import { getAuth } from 'firebase-admin/auth';
import { FieldValue, getFirestore, Timestamp } from 'firebase-admin/firestore';

const app = express();
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const isProduction = process.env.NODE_ENV === 'production';
const COOKIE_BASE = { httpOnly: true, secure: isProduction, sameSite: 'strict', path: '/' };
const ADMIN_COOKIE = 'portal_admin_session';
const CLIENT_COOKIE = 'portal_client_session';
const sessionSecret = process.env.ACCESS_SESSION_SECRET || '';
const port = Number(process.env.PORT || 3000);

let db = null;
let firebaseApp = null;
const firebaseConfig = {
  apiKey: process.env.FIREBASE_API_KEY || '',
  authDomain: process.env.FIREBASE_AUTH_DOMAIN || '',
  projectId: process.env.FIREBASE_PROJECT_ID || '',
  appId: process.env.FIREBASE_APP_ID || ''
};
const databaseConfigured = Boolean(process.env.FIREBASE_PROJECT_ID);

if (databaseConfigured) {
  try {
    const serviceAccount = process.env.FIREBASE_SERVICE_ACCOUNT_JSON ? JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT_JSON) : null;
    const credential = serviceAccount
      ? cert({ ...serviceAccount, privateKey: serviceAccount.private_key?.replace(/\\n/g, '\n') })
      : applicationDefault();
    firebaseApp = initializeApp({
      credential,
      projectId: process.env.FIREBASE_PROJECT_ID
    });
    db = getFirestore(firebaseApp);
  } catch (err) {
    console.error('Firebase Admin não inicializou:', err.message);
  }
}

app.disable('x-powered-by');
app.set('trust proxy', 1);
app.use(helmet({
  contentSecurityPolicy: { directives: {
    defaultSrc: ["'self'"], scriptSrc: ["'self'", "'unsafe-inline'"], styleSrc: ["'self'", "'unsafe-inline'"],
    imgSrc: ["'self'", 'data:'], connectSrc: ["'self'", 'https://identitytoolkit.googleapis.com'],
    objectSrc: ["'none'"], baseUri: ["'self'"], frameAncestors: ["'none'"]
  } }, crossOriginEmbedderPolicy: false
}));
app.use(express.json({ limit: '1mb' }));
app.use(cookieParser());
app.use('/api/', (req, res, next) => {
  const origin = req.get('origin');
  if (origin && origin !== `${req.protocol}://${req.get('host')}`) return fail(res, 403, 'Origem não autorizada.');
  next();
});
app.use('/api/', (req, res, next) => {
  res.set('Cache-Control', 'no-store');
  next();
});

const loginLimit = rateLimit({ windowMs: 15 * 60 * 1000, limit: 8, standardHeaders: 'draft-8', legacyHeaders: false });
const tokenLimit = rateLimit({ windowMs: 15 * 60 * 1000, limit: 12, standardHeaders: 'draft-8', legacyHeaders: false });
const clientWriteLimit = rateLimit({ windowMs: 15 * 60 * 1000, limit: 30, standardHeaders: 'draft-8', legacyHeaders: false });
const asyncRoute = fn => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);
const fail = (res, status, message) => res.status(status).json({ error: message });
const needDb = (req, res, next) => db ? next() : fail(res, 503, 'Firebase ainda não está configurado.');
const clean = value => String(value ?? '').trim();
const now = () => Timestamp.now();
const randomToken = () => {
  const alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  const bytes = crypto.randomBytes(12);
  const value = [...bytes].map(n => alphabet[n % alphabet.length]).join('');
  return value.match(/.{1,4}/g).join('-');
};
const tokenHash = value => crypto.createHash('sha256').update(clean(value).toUpperCase()).digest('hex');
const publicNumber = async () => {
  for (let i = 0; i < 8; i++) {
    const n = String(crypto.randomInt(100000, 999999));
    const snap = await db.collection('operations').where('publicOperationNumber', '==', n).limit(1).get();
    if (snap.empty) return n;
  }
  throw new Error('Não foi possível gerar o número público.');
};
const addHistory = async (ref, action, actor) => {
  await ref.collection('history').add({ action, actor, createdAt: now() });
  await ref.update({ updatedAt: now() });
};
const serialize = (data, id) => ({ id, ...data,
  createdAt: data.createdAt?.toDate?.().toISOString() || data.createdAt || null,
  updatedAt: data.updatedAt?.toDate?.().toISOString() || data.updatedAt || null,
  completedAt: data.completedAt?.toDate?.().toISOString() || data.completedAt || null
});

function signClientSession(operationId, tokenDocId, expiresAt) {
  const body = Buffer.from(JSON.stringify({ operationId, tokenDocId, exp: expiresAt })).toString('base64url');
  const sig = crypto.createHmac('sha256', sessionSecret).update(body).digest('base64url');
  return `${body}.${sig}`;
}
function verifyClientSession(value) {
  if (!value || !sessionSecret) return null;
  const [body, signature] = value.split('.');
  if (!body || !signature) return null;
  const expected = crypto.createHmac('sha256', sessionSecret).update(body).digest();
  let actual;
  try { actual = Buffer.from(signature, 'base64url'); } catch { return null; }
  if (actual.length !== expected.length || !crypto.timingSafeEqual(actual, expected)) return null;
  try {
    const payload = JSON.parse(Buffer.from(body, 'base64url').toString());
    return payload.exp > Date.now() ? payload : null;
  } catch { return null; }
}
const requireAdmin = asyncRoute(async (req, res, next) => {
  if (!db || !firebaseApp) return fail(res, 503, 'Firebase ainda não está configurado.');
  const value = req.cookies[ADMIN_COOKIE];
  if (!value) return fail(res, 401, 'Autenticação necessária.');
  try {
    const decoded = await getAuth(firebaseApp).verifySessionCookie(value, true);
    if (decoded.admin !== true) return fail(res, 403, 'Acesso administrativo não autorizado.');
    req.admin = decoded;
    next();
  } catch { return fail(res, 401, 'Sessão inválida ou expirada.'); }
});
const requireClient = asyncRoute(async (req, res, next) => {
  const payload = verifyClientSession(req.cookies[CLIENT_COOKIE]);
  if (!payload) return fail(res, 401, 'Acesso expirado. Informe novamente sua chave.');
  const tokenSnap = await db.collection('access_tokens').doc(payload.tokenDocId).get();
  if (!tokenSnap.exists || tokenSnap.data().active !== true || tokenSnap.data().operationId !== payload.operationId)
    return fail(res, 401, 'Chave revogada ou indisponível.');
  const opSnap = await db.collection('operations').doc(payload.operationId).get();
  if (!opSnap.exists) return fail(res, 404, 'Operação não encontrada.');
  const operation = opSnap.data();
  if (operation.status === 'CONCLUIDA' && operation.blockClientAfterCompletion)
    return fail(res, 403, 'O acesso a esta operação foi encerrado.');
  req.operationRef = opSnap.ref;
  req.operation = operation;
  req.operationId = payload.operationId;
  req.tokenDocId = payload.tokenDocId;
  next();
});
const adminOperation = asyncRoute(async (req, res, next) => {
  const snap = await db.collection('operations').doc(req.params.id).get();
  if (!snap.exists) return fail(res, 404, 'Operação não encontrada.');
  req.operationRef = snap.ref;
  req.operation = snap.data();
  next();
});

app.get('/api/health', (req, res) => res.json({ ok: true, firebaseConfigured: Boolean(db && firebaseConfig.apiKey && firebaseConfig.authDomain && firebaseConfig.appId && sessionSecret.length >= 32) }));
app.get('/api/config', (req, res) => res.json({ firebase: firebaseConfig, appName: process.env.APP_NAME || 'LKX', appUrl: process.env.NEXT_PUBLIC_APP_URL || '', ready: Boolean(firebaseConfig.apiKey && firebaseConfig.projectId) }));

app.post('/api/auth/session', loginLimit, needDb, asyncRoute(async (req, res) => {
  const idToken = z.string().min(20).safeParse(req.body?.idToken);
  if (!idToken.success) return fail(res, 400, 'Credencial de acesso inválida.');
  try {
    const decoded = await getAuth(firebaseApp).verifyIdToken(idToken.data, true);
    if (decoded.admin !== true) return fail(res, 403, 'Esta conta não tem acesso administrativo.');
    const session = await getAuth(firebaseApp).createSessionCookie(idToken.data, { expiresIn: 5 * 24 * 60 * 60 * 1000 });
    res.cookie(ADMIN_COOKIE, session, { ...COOKIE_BASE, maxAge: 5 * 24 * 60 * 60 * 1000 });
    return res.json({ ok: true, email: decoded.email });
  } catch { return fail(res, 401, 'E-mail, senha ou sessão inválidos.'); }
}));
app.get('/api/auth/me', needDb, requireAdmin, (req, res) => res.json({ uid: req.admin.uid, email: req.admin.email }));
app.post('/api/auth/logout', (req, res) => {
  res.clearCookie(ADMIN_COOKIE, COOKIE_BASE);
  res.clearCookie(CLIENT_COOKIE, COOKIE_BASE);
  res.json({ ok: true });
});

app.post('/api/client/session', tokenLimit, needDb, asyncRoute(async (req, res) => {
  if (sessionSecret.length < 32) return fail(res, 503, 'Configure uma chave de sessão segura no servidor.');
  const parsed = z.object({ token: z.string().min(12).max(20) }).safeParse(req.body);
  if (!parsed.success) return fail(res, 400, 'Informe uma chave válida.');
  const hash = tokenHash(parsed.data.token);
  const snap = await db.collection('access_tokens').doc(hash).get();
  if (!snap.exists || snap.data().active !== true) return fail(res, 401, 'Chave inválida ou indisponível.');
  const tokenData = snap.data();
  const opRef = db.collection('operations').doc(tokenData.operationId);
  const opSnap = await opRef.get();
  if (!opSnap.exists) return fail(res, 401, 'Chave inválida ou indisponível.');
  const operation = opSnap.data();
  if (operation.status === 'CONCLUIDA' && operation.blockClientAfterCompletion)
    return fail(res, 403, 'O acesso a esta operação foi encerrado.');
  const expiresAt = Date.now() + 12 * 60 * 60 * 1000;
  res.cookie(CLIENT_COOKIE, signClientSession(tokenData.operationId, hash, expiresAt), { ...COOKIE_BASE, maxAge: 12 * 60 * 60 * 1000 });
  await snap.ref.update({ lastAccessAt: now(), accessCount: FieldValue.increment(1) });
  await addHistory(opRef, 'Cliente acessou o portal', 'Cliente');
  res.json({ ok: true });
}));
app.get('/api/client/operation', needDb, requireClient, asyncRoute(async (req, res) => {
  const [customer, steps, pickup, delivery, messages, history] = await Promise.all([
    db.collection('customers').doc(req.operationId).get(),
    req.operationRef.collection('steps').get(),
    db.collection('pickup_schedules').doc(req.operationId).get(),
    db.collection('delivery_partners').doc(req.operationId).get(),
    req.operationRef.collection('messages').orderBy('createdAt', 'desc').limit(30).get(),
    req.operationRef.collection('history').orderBy('createdAt', 'desc').limit(30).get()
  ]);
  const o = req.operation;
  res.json({ operation: {
    id: req.operationId, number: o.publicOperationNumber, customerName: o.customerName,
    productName: o.productName, availableAmount: o.availableAmount, status: o.status,
    steps: steps.docs.map(d => ({ id: d.id, ...d.data() })),
    customer: customer.exists ? { name: customer.data().name, phone: customer.data().phone, email: customer.data().email, registrationComplete: customer.data().registrationComplete === true } : null,
    pickup: pickup.exists ? pickup.data() : null,
    delivery: delivery.exists ? { name: delivery.data().name, company: delivery.data().company, operationalPhone: delivery.data().operationalPhone, identification: delivery.data().identification, vehicleType: delivery.data().vehicleType, vehicleModel: delivery.data().vehicleModel, plateMasked: delivery.data().plateMasked, eta: delivery.data().eta, status: delivery.data().status } : null,
    finalMessage: o.finalMessage || '', updatedAt: o.updatedAt?.toDate?.().toISOString() || null,
    messages: messages.docs.map(d => ({ ...d.data(), author: 'Equipe de operações', createdAt: d.data().createdAt?.toDate?.().toISOString() })),
    history: history.docs.map(d => ({ ...d.data(), actor: d.data().actor === 'Cliente' ? 'Cliente' : 'Equipe de operações', createdAt: d.data().createdAt?.toDate?.().toISOString() }))
  }});
}));
app.post('/api/client/logout', (req, res) => { res.clearCookie(CLIENT_COOKIE, COOKIE_BASE); res.json({ ok: true }); });

const registrationSchema = z.object({
  name: z.string().trim().min(3).max(120), document: z.string().trim().min(8).max(24),
  phone: z.string().trim().min(8).max(24), email: z.string().email().max(180),
  productName: z.string().trim().min(2).max(180),
  bank: z.string().trim().min(2).max(100), agency: z.string().trim().min(1).max(30),
  account: z.string().trim().min(1).max(40), accountType: z.string().trim().min(2).max(40),
  pix: z.string().trim().min(3).max(180), zip: z.string().trim().min(5).max(12),
  street: z.string().trim().min(2).max(180), addressNumber: z.string().trim().min(1).max(30),
  complement: z.string().trim().max(100).optional().default(''), neighborhood: z.string().trim().min(2).max(100),
  city: z.string().trim().min(2).max(100), state: z.string().trim().length(2)
});
app.post('/api/client/registration', clientWriteLimit, needDb, requireClient, asyncRoute(async (req, res) => {
  if (req.operation.status !== 'AGUARDANDO_CADASTRO') return fail(res, 409, 'O cadastro não está disponível nesta etapa.');
  const parsed = registrationSchema.safeParse(req.body);
  if (!parsed.success) return fail(res, 400, 'Revise os dados do cadastro e tente novamente.');
  const currentCustomer = await db.collection('customers').doc(req.operationId).get();
  if (currentCustomer.data()?.registrationComplete === true) return fail(res, 409, 'O cadastro já foi concluído.');
  const data = parsed.data;
  const customerRef = db.collection('customers').doc(req.operationId);
  await customerRef.set({ operationId: req.operationId, name: data.name, document: data.document, phone: data.phone, email: data.email, registrationComplete: true, updatedAt: now() }, { merge: true });
  await db.collection('bank_details').doc(req.operationId).set({ operationId: req.operationId, bank: data.bank, agency: data.agency, account: data.account, accountType: data.accountType, pix: data.pix, updatedAt: now() });
  await db.collection('pickup_addresses').doc(req.operationId).set({ operationId: req.operationId, zip: data.zip, street: data.street, number: data.addressNumber, complement: data.complement, neighborhood: data.neighborhood, city: data.city, state: data.state, updatedAt: now() });
  const registeredAddress = `${data.street}, ${data.addressNumber}${data.complement ? `, ${data.complement}` : ''} - ${data.neighborhood}, ${data.city}/${data.state} - CEP ${data.zip}`;
  await req.operationRef.update({ customerName: data.name, productName: data.productName, pickupAddress: registeredAddress, status: 'AGUARDANDO_EMBALAGEM', currentStep: 'EMBALAGEM', updatedAt: now() });
  await req.operationRef.collection('steps').doc('cadastro').set({ status: 'CONCLUIDO', completedAt: now() }, { merge: true });
  await req.operationRef.collection('steps').doc('embalagem').set({ status: 'PENDENTE' }, { merge: true });
  await addHistory(req.operationRef, 'Dados cadastrados', 'Cliente');
  res.json({ ok: true });
}));
app.post('/api/client/pickup', clientWriteLimit, needDb, requireClient, asyncRoute(async (req, res) => {
  const schema = z.object({ date: z.string().regex(/^\d{4}-\d{2}-\d{2}$/), period: z.string().min(3).max(40), address: z.string().trim().min(5).max(300), notes: z.string().max(1000).optional().default('') });
  const parsed = schema.safeParse(req.body);
  if (!parsed.success) return fail(res, 400, 'Revise os dados do agendamento.');
  if (req.operation.status !== 'AGUARDANDO_AGENDAMENTO' && req.operation.status !== 'EMBALAGEM_APROVADA') return fail(res, 409, 'O agendamento não está disponível nesta etapa.');
  const material = await req.operationRef.collection('steps').doc('embalagem').get();
  if (material.data()?.status !== 'APROVADO') return fail(res, 409, 'Conclua o envio da foto e do vídeo para liberar a retirada.');
  await db.collection('pickup_schedules').doc(req.operationId).set({ operationId: req.operationId, ...parsed.data, status: 'CONFIRMADO', updatedAt: now() });
  await req.operationRef.update({ status: 'RETIRADA_AGENDADA', currentStep: 'ENTREGADOR', updatedAt: now() });
  await addHistory(req.operationRef, 'Retirada agendada', 'Cliente');
  res.json({ ok: true });
}));

app.get('/api/admin/operations', needDb, requireAdmin, asyncRoute(async (req, res) => {
  const snap = await db.collection('operations').orderBy('updatedAt', 'desc').limit(300).get();
  const rows = await Promise.all(snap.docs.map(async doc => {
    const customer = await db.collection('customers').doc(doc.id).get();
    const pickup = await db.collection('pickup_schedules').doc(doc.id).get();
    const delivery = await db.collection('delivery_partners').doc(doc.id).get();
    return { ...serialize(doc.data(), doc.id), customerName: customer.data()?.name || doc.data().customerName, phone: customer.data()?.phone || '', email: customer.data()?.email || '', pickup: pickup.exists ? pickup.data() : null, delivery: delivery.exists ? { name: delivery.data().name, company: delivery.data().company, status: delivery.data().status } : null };
  }));
  res.json({ operations: rows });
}));
app.get('/api/admin/settings', needDb, requireAdmin, asyncRoute(async (req, res) => {
  const snap = await db.collection('settings').doc('portal').get();
  res.json({ settings: snap.exists ? snap.data() : { companyName: 'LKX', phone: '', whatsapp: '', email: '', domain: process.env.NEXT_PUBLIC_APP_URL || '', institutional: '', support: '', primaryColor: '#6545a5', secondaryColor: '#706a78', accentColor: '#de8845' } });
}));
app.put('/api/admin/settings', needDb, requireAdmin, asyncRoute(async (req, res) => {
  const schema = z.object({ companyName: z.string().trim().min(2).max(100), phone: z.string().max(30).optional().default(''), whatsapp: z.string().max(30).optional().default(''), email: z.string().email().or(z.literal('')).optional().default(''), domain: z.string().max(200).optional().default(''), institutional: z.string().max(1000).optional().default(''), support: z.string().max(200).optional().default(''), primaryColor: z.string().regex(/^#[0-9a-fA-F]{6}$/), secondaryColor: z.string().regex(/^#[0-9a-fA-F]{6}$/), accentColor: z.string().regex(/^#[0-9a-fA-F]{6}$/) }).strict();
  const parsed = schema.safeParse(req.body);
  if (!parsed.success) return fail(res, 400, 'Revise as configurações informadas.');
  await db.collection('settings').doc('portal').set({ ...parsed.data, updatedAt: now(), updatedBy: req.admin.email }, { merge: true });
  await db.collection('operation_history').add({ action: 'Configurações do portal atualizadas', actor: req.admin.email, createdAt: now() });
  res.json({ ok: true, settings: parsed.data });
}));
app.post('/api/admin/operations', needDb, requireAdmin, asyncRoute(async (req, res) => {
  const schema = z.object({ availableAmount: z.number().finite().nonnegative(), blockClientAfterCompletion: z.boolean().default(true) }).strict();
  const parsed = schema.safeParse(req.body);
  if (!parsed.success) return fail(res, 400, 'Revise os dados da operação.');
  const id = crypto.randomUUID();
  const token = randomToken();
  const hashed = tokenHash(token);
  const number = await publicNumber();
  const opRef = db.collection('operations').doc(id);
  const serverNow = now();
  const value = parsed.data;
  await db.runTransaction(async tx => {
    tx.create(opRef, { publicOperationNumber: number, customerName: 'Cadastro pendente', productName: 'Aguardando cadastro', availableAmount: value.availableAmount, status: 'AGUARDANDO_CADASTRO', currentStep: 'CADASTRO', pickupAddress: '', blockClientAfterCompletion: value.blockClientAfterCompletion, createdAt: serverNow, updatedAt: serverNow });
    tx.create(db.collection('access_tokens').doc(hashed), { operationId: id, active: true, createdAt: serverNow, accessCount: 0 });
    tx.create(db.collection('customers').doc(id), { operationId: id, registrationComplete: false, createdAt: serverNow });
    tx.create(opRef.collection('steps').doc('cadastro'), { status: 'ATUAL', createdAt: serverNow });
    tx.create(opRef.collection('steps').doc('embalagem'), { status: 'PENDENTE' });
    tx.create(opRef.collection('steps').doc('retirada'), { status: 'BLOQUEADO' });
    tx.create(opRef.collection('steps').doc('entregador'), { status: 'BLOQUEADO' });
    tx.create(opRef.collection('steps').doc('conclusao'), { status: 'BLOQUEADO' });
    tx.create(opRef.collection('history').doc(), { action: 'Operação criada', actor: req.admin.email || 'Administração', createdAt: serverNow });
  });
  res.status(201).json({ operation: { id, number, customerName: 'Cadastro pendente' }, token, accessPath: '/acesso' });
}));
app.get('/api/admin/operations/:id', needDb, requireAdmin, adminOperation, asyncRoute(async (req, res) => {
  const id = req.params.id;
  const [customer, bank, address, steps, pickup, delivery, messages, history, tokens] = await Promise.all([
    db.collection('customers').doc(id).get(), db.collection('bank_details').doc(id).get(), db.collection('pickup_addresses').doc(id).get(),
    req.operationRef.collection('steps').get(), db.collection('pickup_schedules').doc(id).get(), db.collection('delivery_partners').doc(id).get(),
    req.operationRef.collection('messages').orderBy('createdAt', 'desc').get(),
    req.operationRef.collection('history').orderBy('createdAt', 'desc').get(), db.collection('access_tokens').where('operationId', '==', id).get()
  ]);
  res.json({ operation: serialize(req.operation, id), customer: customer.data() || null, bankDetails: bank.data() || null, pickupAddress: address.data() || null, steps: steps.docs.map(d => ({ id: d.id, ...d.data() })), pickup: pickup.data() || null, delivery: delivery.data() || null, messages: messages.docs.map(d => d.data()), history: history.docs.map(d => d.data()), tokens: tokens.docs.map(d => ({ id: d.id, active: d.data().active, lastAccessAt: d.data().lastAccessAt || null })) });
}));
app.patch('/api/admin/operations/:id', needDb, requireAdmin, adminOperation, asyncRoute(async (req, res) => {
  const schema = z.object({ customerName: z.string().trim().min(2).max(120).optional(), customerDocument: z.string().trim().min(8).max(24).optional(), phone: z.string().trim().min(8).max(24).optional(), email: z.string().email().optional(), productName: z.string().trim().min(2).max(180).optional(), availableAmount: z.number().finite().nonnegative().optional(), pickupAddress: z.string().max(500).optional(), status: z.enum(['CONCLUIDA','CANCELADA']).optional(), blockClientAfterCompletion: z.boolean().optional(), internalNotes: z.string().max(2000).optional(), finalMessage: z.string().max(2000).optional() }).strict();
  const parsed = schema.safeParse(req.body);
  if (!parsed.success || Object.keys(parsed.data).length === 0) return fail(res, 400, 'Nenhuma alteração válida foi informada.');
  const { customerDocument, phone, email, ...operationFields } = parsed.data;
  await req.operationRef.update({ ...operationFields, updatedAt: now(), ...(parsed.data.status === 'CONCLUIDA' ? { completedAt: now() } : {}) });
  if (parsed.data.customerName || customerDocument || phone || email) await db.collection('customers').doc(req.params.id).set({ ...(parsed.data.customerName ? { name: parsed.data.customerName } : {}), ...(customerDocument ? { document: customerDocument } : {}), ...(phone ? { phone } : {}), ...(email ? { email } : {}), updatedAt: now() }, { merge: true });
  await addHistory(req.operationRef, 'Informações da operação atualizadas', req.admin.email);
  res.json({ ok: true });
}));
app.delete('/api/admin/operations/:id', needDb, requireAdmin, adminOperation, asyncRoute(async (req, res) => {
  const id = req.params.id;
  const tokenDocs = await db.collection('access_tokens').where('operationId', '==', id).get();
  const writer = db.bulkWriter();
  tokenDocs.docs.forEach(doc => writer.delete(doc.ref));
  await writer.close();
  await Promise.all([
    db.collection('customers').doc(id).delete(),
    db.collection('bank_details').doc(id).delete(),
    db.collection('pickup_addresses').doc(id).delete(),
    db.collection('pickup_schedules').doc(id).delete(),
    db.collection('delivery_partners').doc(id).delete(),
    db.recursiveDelete(req.operationRef)
  ]);
  res.json({ ok: true });
}));
app.post('/api/admin/operations/:id/reopen', needDb, requireAdmin, adminOperation, asyncRoute(async (req, res) => {
  const parsed = z.object({ stage: z.enum(['cadastro','embalagem','retirada','entregador','conclusao']) }).safeParse(req.body);
  if (!parsed.success) return fail(res, 400, 'Etapa inválida.');
  const definitions = { cadastro: ['AGUARDANDO_CADASTRO','CADASTRO'], embalagem: ['AGUARDANDO_EMBALAGEM','EMBALAGEM'], retirada: ['AGUARDANDO_AGENDAMENTO','RETIRADA'], entregador: ['ENTREGADOR_DESIGNADO','ENTREGADOR'], conclusao: ['EM_CONFERENCIA','CONCLUSAO'] };
  const [status, currentStep] = definitions[parsed.data.stage];
  await req.operationRef.update({ status, currentStep, updatedAt: now() });
  await req.operationRef.collection('steps').doc(parsed.data.stage).set({ status: 'ATUAL', reopenedAt: now(), reopenedBy: req.admin.email }, { merge: true });
  if (parsed.data.stage === 'cadastro') await db.collection('customers').doc(req.params.id).set({ registrationComplete: false, updatedAt: now() }, { merge: true });
  if (parsed.data.stage === 'retirada') await db.collection('pickup_schedules').doc(req.params.id).delete();
  if (parsed.data.stage === 'entregador') await db.collection('delivery_partners').doc(req.params.id).delete();
  await addHistory(req.operationRef, `Etapa ${parsed.data.stage} reaberta`, req.admin.email);
  res.json({ ok: true });
}));
app.post('/api/admin/operations/:id/token', needDb, requireAdmin, adminOperation, asyncRoute(async (req, res) => {
  const old = await db.collection('access_tokens').where('operationId', '==', req.params.id).where('active', '==', true).get();
  const token = randomToken();
  const hash = tokenHash(token);
  const batch = db.batch();
  old.docs.forEach(doc => batch.update(doc.ref, { active: false, revokedAt: now() }));
  batch.create(db.collection('access_tokens').doc(hash), { operationId: req.params.id, active: true, createdAt: now(), accessCount: 0 });
  batch.set(req.operationRef.collection('history').doc(), { action: 'Chave de acesso renovada', actor: req.admin.email, createdAt: now() });
  await batch.commit();
  res.json({ token, accessPath: '/acesso' });
}));
app.post('/api/admin/operations/:id/messages', needDb, requireAdmin, adminOperation, asyncRoute(async (req, res) => {
  const parsed = z.object({ content: z.string().trim().min(1).max(2000) }).safeParse(req.body);
  if (!parsed.success) return fail(res, 400, 'Escreva uma mensagem de até 2.000 caracteres.');
  await req.operationRef.collection('messages').add({ content: parsed.data.content, author: req.admin.email || 'Administração', createdAt: now() });
  await addHistory(req.operationRef, 'Comunicado enviado ao cliente', req.admin.email);
  res.status(201).json({ ok: true });
}));
app.post('/api/admin/operations/:id/delivery', needDb, requireAdmin, adminOperation, asyncRoute(async (req, res) => {
  const schema = z.object({ name: z.string().trim().min(2).max(120), company: z.string().trim().min(2).max(120), operationalPhone: z.string().trim().min(8).max(24), identification: z.string().trim().min(2).max(80), vehicleType: z.string().trim().min(2).max(40), vehicleModel: z.string().trim().min(2).max(120), plate: z.string().trim().min(5).max(12), eta: z.string().trim().min(2).max(40) });
  const parsed = schema.safeParse(req.body);
  if (!parsed.success) return fail(res, 400, 'Revise os dados do parceiro de coleta.');
  const d = parsed.data;
  await db.collection('delivery_partners').doc(req.params.id).set({ operationId: req.params.id, ...d, plateMasked: `${d.plate.slice(0, 3)}••••`, status: 'ENTREGADOR_DESIGNADO', updatedAt: now() });
  await req.operationRef.update({ status: 'ENTREGADOR_DESIGNADO', currentStep: 'ENTREGADOR', updatedAt: now() });
  await req.operationRef.collection('messages').add({ content: `${d.name} foi designado pela ${d.company}. Previsão: ${d.eta}.`, author: req.admin.email, createdAt: now() });
  await addHistory(req.operationRef, 'Entregador designado', req.admin.email);
  res.json({ ok: true });
}));
app.patch('/api/admin/operations/:id/delivery/status', needDb, requireAdmin, adminOperation, asyncRoute(async (req, res) => {
  const allowed = ['ENTREGADOR_DESIGNADO','ENTREGADOR_A_CAMINHO','ENTREGADOR_NO_LOCAL','PRODUTO_COLETADO'];
  const parsed = z.object({ status: z.enum(allowed) }).safeParse(req.body);
  if (!parsed.success) return fail(res, 400, 'Status de coleta inválido.');
  const dRef = db.collection('delivery_partners').doc(req.params.id);
  await dRef.update({ status: parsed.data.status, updatedAt: now() });
  const opStatus = parsed.data.status === 'PRODUTO_COLETADO' ? 'EM_CONFERENCIA' : parsed.data.status;
  await req.operationRef.update({ status: opStatus, currentStep: parsed.data.status === 'PRODUTO_COLETADO' ? 'CONCLUSAO' : 'ENTREGADOR', updatedAt: now() });
  await addHistory(req.operationRef, `Status do entregador: ${parsed.data.status}`, req.admin.email);
  res.json({ ok: true });
}));
app.patch('/api/admin/operations/:id/pickup', needDb, requireAdmin, adminOperation, asyncRoute(async (req, res) => {
  const schema = z.object({ date: z.string().regex(/^\d{4}-\d{2}-\d{2}$/), period: z.string().min(3).max(40), address: z.string().trim().min(5).max(300), notes: z.string().max(1000).optional().default('') });
  const parsed = schema.safeParse(req.body);
  if (!parsed.success) return fail(res, 400, 'Revise os dados da retirada.');
  await db.collection('pickup_schedules').doc(req.params.id).set({ operationId: req.params.id, ...parsed.data, status: 'CONFIRMADO', updatedAt: now() });
  await req.operationRef.update({ status: 'RETIRADA_AGENDADA', currentStep: 'ENTREGADOR', updatedAt: now() });
  await addHistory(req.operationRef, 'Agendamento de retirada atualizado', req.admin.email);
  res.json({ ok: true });
}));
app.post('/api/admin/operations/:id/token/revoke', needDb, requireAdmin, adminOperation, asyncRoute(async (req, res) => {
  const docs = await db.collection('access_tokens').where('operationId', '==', req.params.id).where('active', '==', true).get();
  const batch = db.batch(); docs.docs.forEach(d => batch.update(d.ref, { active: false, revokedAt: now() })); await batch.commit();
  await addHistory(req.operationRef, 'Chave de acesso revogada', req.admin.email);
  res.json({ ok: true });
}));

app.post('/api/client/uploads/submit', clientWriteLimit, needDb, requireClient, asyncRoute(async (req, res) => {
  const fileSchema = z.object({
    type: z.enum(['product_photo','package_video']),
    fileName: z.string().trim().min(1).max(180),
    contentType: z.string().min(3).max(80),
    size: z.number().int().positive()
  }).strict();
  const parsed = z.object({ files: z.array(fileSchema).length(2) }).strict().safeParse(req.body);
  if (!parsed.success) return fail(res, 400, 'Selecione uma foto e um v\u00eddeo v\u00e1lidos antes de continuar.');
  const types = new Set(parsed.data.files.map(file => file.type));
  if (types.size !== 2) return fail(res, 400, 'Selecione uma foto e um v\u00eddeo v\u00e1lidos antes de continuar.');
  for (const file of parsed.data.files) {
    const photo = file.type === 'product_photo';
    const contentTypes = photo ? ['image/jpeg','image/png','image/webp'] : ['video/mp4','video/quicktime'];
    const extensions = photo ? ['.jpg','.jpeg','.png','.webp'] : ['.mp4','.mov'];
    const maxSize = photo ? 10 * 1024 * 1024 : 50 * 1024 * 1024;
    if (!contentTypes.includes(file.contentType) || !extensions.includes(path.extname(file.fileName).toLowerCase()) || file.size > maxSize)
      return fail(res, 400, 'Confira os formatos e tamanhos permitidos para a foto e o v\u00eddeo.');
  }
  const submittedAt = now();
  await db.runTransaction(async tx => {
    const operationSnap = await tx.get(req.operationRef);
    const stepRef = req.operationRef.collection('steps').doc('embalagem');
    const stepSnap = await tx.get(stepRef);
    if (!operationSnap.exists || !['AGUARDANDO_EMBALAGEM','PENDENCIA'].includes(operationSnap.data().status))
      throw Object.assign(new Error('A seleção de foto e vídeo não está disponível nesta etapa.'), { status: 409 });
    if (stepSnap.data()?.status === 'APROVADO') throw Object.assign(new Error('Esta etapa já foi concluída.'), { status: 409 });
    tx.set(stepRef, { status: 'APROVADO', submittedAt, approval: 'AUTOMATICA' }, { merge: true });
    tx.update(req.operationRef, { status: 'AGUARDANDO_AGENDAMENTO', currentStep: 'RETIRADA', updatedAt: submittedAt });
  });
  await addHistory(req.operationRef, 'Cliente selecionou foto e v\u00eddeo; etapa liberada automaticamente, sem an\u00e1lise da equipe', 'Sistema');
  res.json({ ok: true });
}));

app.use('/api', (req, res) => fail(res, 404, 'Rota da API nao encontrada.'));
app.use('/api', (err, req, res, next) => {
  console.error('API error:', err.message);
  if (res.headersSent) return next(err);
  res.status(500).json({ error: 'Não foi possível concluir a solicitação.' });
});

app.use('/assets', express.static(path.join(__dirname, '..', 'assets'), { index: false, dotfiles: 'deny', etag: true, maxAge: isProduction ? '1h' : 0 }));
app.get('*path', (req, res) => res.sendFile(path.join(__dirname, '..', 'index.html')));

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) app.listen(port, () => {
  console.log(`Portal de Operações disponível na porta ${port}. Firebase: ${db ? 'configurado' : 'pendente'}.`);
});
export default app;
