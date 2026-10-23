import 'dotenv/config';
import { applicationDefault, cert, initializeApp } from 'firebase-admin/app';
import { getAuth } from 'firebase-admin/auth';

if (!process.env.FIREBASE_PROJECT_ID) throw new Error('Configure FIREBASE_PROJECT_ID antes de continuar.');
const serviceAccount = process.env.FIREBASE_SERVICE_ACCOUNT_JSON ? JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT_JSON) : null;
const credential = serviceAccount
  ? cert({ ...serviceAccount, privateKey: serviceAccount.private_key?.replace(/\\n/g, '\n') })
  : applicationDefault();
const app = initializeApp({ credential, projectId: process.env.FIREBASE_PROJECT_ID });
const uid = process.argv[2];
if (!uid) throw new Error('Uso: npm run admin:grant -- <uid-do-usuario-firebase>');
getAuth(app).getUser(uid)
  .then(user => getAuth(app).setCustomUserClaims(uid, { ...(user.customClaims || {}), admin: true }))
  .then(() => { console.log(`Acesso administrativo habilitado para ${uid}. Faça login novamente para renovar as credenciais.`); process.exit(0); })
  .catch(err => { console.error(err.message); process.exit(1); });
