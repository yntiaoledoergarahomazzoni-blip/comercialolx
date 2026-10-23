/* Frontend adapter: all production reads/writes go through the protected API. */
(() => {
  'use strict';
  const portal = window.__portal;
  if (!portal) return;
  const api = async (url, options = {}) => {
    const response = await fetch(url, {
      credentials: 'same-origin',
      headers: { ...(options.body && !(options.body instanceof FormData) ? { 'Content-Type': 'application/json' } : {}), ...(options.headers || {}) },
      ...options
    });
    const data = response.status === 204 ? {} : await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(data.error || 'Não foi possível concluir a solicitação.');
    return data;
  };
  const flash = message => portal.toast(message);
  const error = err => flash(err?.message || 'Ocorreu um erro. Tente novamente.');
  const toIso = value => {
    if (value?.toDate) return value.toDate().toISOString();
    if (value && typeof value === 'object' && Number.isFinite(value._seconds)) return new Date(value._seconds * 1000).toISOString();
    return typeof value === 'string' || typeof value === 'number' ? value : null;
  };
  const stepFor = status => ({ AGUARDANDO_CADASTRO: 0, CADASTRO_CONCLUIDO: 1, AGUARDANDO_EMBALAGEM: 1, EMBALAGEM_ENVIADA: 1, EMBALAGEM_EM_ANALISE: 1, EMBALAGEM_APROVADA: 2, AGUARDANDO_AGENDAMENTO: 2, RETIRADA_AGENDADA: 3, ENTREGADOR_DESIGNADO: 3, ENTREGADOR_A_CAMINHO: 3, ENTREGADOR_NO_LOCAL: 3, PRODUTO_COLETADO: 4, EM_CONFERENCIA: 4, CONCLUIDA: 5, PENDENCIA: 1, CANCELADA: 0 })[status] ?? 0;
  const mapMessage = item => ({ text: item.content || item.text || '', author: item.author || 'Equipe de operações', date: toIso(item.createdAt || item.date) });
  const mapHistory = item => ({ text: item.action || item.text || '', author: item.actor || item.author || 'Sistema', date: toIso(item.createdAt || item.date) });
  function mapOperation(item, detail = {}) {
    const d = detail.delivery || item.delivery;
    const p = detail.pickup || item.pickup;
    const customer = detail.customer || item.customer || {};
    const packageStep = (detail.steps || item.steps || []).find(s => s.id === 'embalagem');
    const packageStatus = packageStep?.status === 'APROVADO' ? 'approved' : packageStep?.status === 'NOVO_ENVIO_SOLICITADO' ? 'resubmit' : 'pending';
    const history = (detail.history || item.history || []).map(mapHistory);
    const messages = (detail.messages || item.messages || []).map(mapMessage);
    const activeToken = (detail.tokens || []).find(t => t.active);
    return {
      id: item.id || detail.operation?.id,
      number: item.publicOperationNumber || item.number,
      customer: customer.name || item.customerName || item.customer || '',
      document: customer.document || '', phone: customer.phone || item.phone || '', email: customer.email || item.email || '',
      product: item.productName || item.product || '', amount: Number(item.availableAmount ?? item.amount ?? 0),
      status: item.status || 'AGUARDANDO_CADASTRO', step: stepFor(item.status),
      created: toIso(item.createdAt || item.created), updated: toIso(item.updatedAt || item.updated),
      tokenActive: activeToken ? activeToken.active : item.tokenActive ?? true,
      blockWhenCompleted: item.blockClientAfterCompletion ?? item.blockWhenCompleted ?? true,
      lastAccess: toIso(activeToken?.lastAccessAt || item.lastAccess),
      registration: customer.registrationComplete ? { complete: true } : null,
      package: { status: packageStatus, files: [], request: packageStep?.reviewMessage || '' },
      pickup: p ? { date: p.date, period: p.period, address: p.address, notes: p.notes || '' } : null,
      pickupAddress: item.pickupAddress || '',
      delivery: d ? { name: d.name, company: d.company, phone: d.operationalPhone || d.phone, identification: d.identification, vehicle: d.vehicleType || d.vehicle, model: d.vehicleModel || d.model, plate: (d.plate || d.plateMasked || '').slice(0, 3), eta: d.eta, status: d.status } : null,
      messages, history, finalMessage: item.finalMessage || detail.finalMessage || '', notes: item.internalNotes || item.notes || ''
    };
  }
  const setOperations = list => { portal.db.operations = list; };
  async function refreshAdmin(id) {
    const response = await api('/api/admin/operations');
    const list = response.operations.map(op => mapOperation(op));
    setOperations(list);
    if (id) {
      const detail = await api(`/api/admin/operations/${encodeURIComponent(id)}`);
      const index = list.findIndex(op => op.id === id);
      const mapped = mapOperation(detail.operation, detail);
      if (index >= 0) list[index] = mapped; else list.unshift(mapped);
      setOperations(list);
    }
    return list;
  }
  async function refreshSettings() {
    const response = await api('/api/admin/settings');
    portal.db.settings = { ...portal.db.settings, ...response.settings };
  }
  const adminRoute = path => path.startsWith('/admin') && path !== '/admin/login';

  window.go = async path => {
    try {
      if (adminRoute(path)) {
        if (sessionStorage.getItem('portal_admin_auth') !== 'yes') {
          history.pushState({}, '', '/admin/login'); portal.render(); return;
        }
        const detailId = path.match(/^\/admin\/operacoes\/([^/]+)$/)?.[1];
        await Promise.all([refreshAdmin(detailId), refreshSettings()]);
      }
      history.pushState({}, '', path);
      portal.render();
    } catch (err) { error(err); }
  };

  window.adminLogin = async event => {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    const errorNode = document.getElementById('login-error');
    try {
      const config = await api('/api/config');
      if (!config.ready) throw new Error('O projeto Firebase ainda não foi configurado.');
      const credential = await fetch(`https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key=${encodeURIComponent(config.firebase.apiKey)}`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: form.get('email'), password: form.get('password'), returnSecureToken: true })
      }).then(response => response.json());
      if (!credential.idToken) throw new Error('E-mail ou senha inválidos.');
      await api('/api/auth/session', { method: 'POST', body: JSON.stringify({ idToken: credential.idToken }) });
      sessionStorage.setItem('portal_admin_auth', 'yes');
      await Promise.all([refreshAdmin(), refreshSettings()]);
      history.replaceState({}, '', '/admin/dashboard'); portal.render();
    } catch (err) { if (errorNode) errorNode.textContent = err.message || 'Não foi possível entrar.'; }
  };
  window.logout = async () => {
    try { await api('/api/auth/logout', { method: 'POST' }); } catch { /* always clear local state */ }
    sessionStorage.removeItem('portal_admin_auth');
    history.replaceState({}, '', '/admin/login'); portal.render();
  };
  window.accessOperation = async event => {
    event.preventDefault();
    const token = new FormData(event.currentTarget).get('token');
    const errorNode = document.getElementById('access-error');
    try {
      await api('/api/client/session', { method: 'POST', body: JSON.stringify({ token }) });
      const response = await api('/api/client/operation');
      const op = mapOperation({ ...response.operation, id: response.operation.id, publicOperationNumber: response.operation.number, customerName: response.operation.customer?.name || response.operation.customerName, productName: response.operation.productName, availableAmount: response.operation.availableAmount, pickup: response.operation.pickup, delivery: response.operation.delivery, messages: response.operation.messages, history: response.operation.history, finalMessage: response.operation.finalMessage }, response.operation);
      setOperations([op]); sessionStorage.setItem('portal_client_op', op.id);
      history.pushState({}, '', '/operacao'); portal.render(); startClientRefresh();
    } catch (err) { if (errorNode) errorNode.textContent = err.message || 'Chave inválida ou indisponível.'; }
  };
  let clientTimer = null;
  async function refreshClient() {
    if (location.pathname !== '/operacao') return;
    try {
      const response = await api('/api/client/operation');
      const raw = response.operation;
      const op = mapOperation({ id: raw.id, publicOperationNumber: raw.number, customerName: raw.customer?.name || raw.customerName, productName: raw.productName, availableAmount: raw.availableAmount, status: raw.status, pickup: raw.pickup, delivery: raw.delivery, messages: raw.messages, history: raw.history, updatedAt: raw.updatedAt, steps: raw.steps, finalMessage: raw.finalMessage }, raw);
      setOperations([op]); portal.render();
    } catch (err) { if (err.message.includes('expirado') || err.message.includes('revogada')) { sessionStorage.removeItem('portal_client_op'); history.replaceState({}, '', '/acesso'); portal.render(); } }
  }
  function startClientRefresh() { clearInterval(clientTimer); clientTimer = setInterval(refreshClient, 30000); }
  window.clientLogout = async () => {
    clearInterval(clientTimer);
    try { await api('/api/client/logout', { method: 'POST' }); } catch { /* clear local view regardless */ }
    sessionStorage.removeItem('portal_client_op'); setOperations([]); history.replaceState({}, '', '/acesso'); portal.render();
  };

  window.createOperation = async event => {
    event.preventDefault();
    const data = Object.fromEntries(new FormData(event.currentTarget));
    const payload = { availableAmount: Number(data.amount), blockClientAfterCompletion: true };
    try {
      const result = await api('/api/admin/operations', { method: 'POST', body: JSON.stringify(payload) });
      await refreshAdmin(result.operation.id); window.closeModal();
      history.pushState({}, '', `/admin/operacoes/${result.operation.id}`); portal.render();
      document.getElementById('modal-root').innerHTML = `<div class="modal-backdrop"><div class="modal"><div class="modal-head"><h2>Operação criada com sucesso</h2></div><div class="modal-body"><div class="success-block">Operação <b>#${result.operation.number}</b> criada. A chave aparece somente nesta tela.</div><div class="key-display">${result.token}</div><p class="small muted" style="margin-top:14px">Compartilhe o link público e a chave em mensagens separadas.</p></div><div class="modal-foot"><button class="btn btn-outline" onclick="navigator.clipboard.writeText('${result.token}').then(()=>window.__portal.toast('Chave copiada'))">Copiar chave</button><button class="btn btn-outline" onclick="navigator.clipboard.writeText(location.origin+'/acesso').then(()=>window.__portal.toast('Link copiado'))">Copiar link</button><button class="btn btn-primary" onclick="document.getElementById('modal-root').innerHTML=''">Concluir</button></div></div></div>`;
    } catch (err) { error(err); }
  };
  window.changeStatus = async (id, status) => runAdminChange(id, '/api/admin/operations/'+encodeURIComponent(id), 'PATCH', { status });
  window.toggleToken = async (id, active) => {
    try {
      if (active) {
        const result = await api(`/api/admin/operations/${encodeURIComponent(id)}/token`, { method: 'POST', body: '{}' });
        await refreshAdmin(id); portal.render(); showOneTimeToken(result.token);
      } else { await api(`/api/admin/operations/${encodeURIComponent(id)}/token/revoke`, { method: 'POST', body: '{}' }); await refreshAdmin(id); portal.render(); }
    } catch (err) { error(err); }
  };
  window.rotateToken = async id => {
    try { const result = await api(`/api/admin/operations/${encodeURIComponent(id)}/token`, { method: 'POST', body: '{}' }); await refreshAdmin(id); portal.render(); showOneTimeToken(result.token); }
    catch (err) { error(err); }
  };
  window.copyToken = () => flash('A chave não é armazenada em texto. Gere uma nova chave para compartilhá-la.');
  function showOneTimeToken(token) {
    document.getElementById('modal-root').innerHTML = `<div class="modal-backdrop"><div class="modal"><div class="modal-head"><h2>Nova chave gerada</h2></div><div class="modal-body"><p class="small muted">Copie agora. Por segurança, a chave não poderá ser consultada novamente.</p><div class="key-display">${token}</div></div><div class="modal-foot"><button class="btn btn-outline" onclick="navigator.clipboard.writeText('${token}').then(()=>window.__portal.toast('Chave copiada'))">Copiar chave</button><button class="btn btn-primary" onclick="document.getElementById('modal-root').innerHTML=''">Fechar</button></div></div></div>`;
  }
  async function runAdminChange(id, url, method, body) {
    try { await api(url, { method, body: JSON.stringify(body) }); await refreshAdmin(id); portal.render(); }
    catch (err) { error(err); }
  }
  window.toggleBlock = async (id, checked) => runAdminChange(id, `/api/admin/operations/${encodeURIComponent(id)}`, 'PATCH', { blockClientAfterCompletion: checked });
  window.sendNotice = async (event, id) => {
    event.preventDefault(); const content = new FormData(event.currentTarget).get('text');
    try { await api(`/api/admin/operations/${encodeURIComponent(id)}/messages`, { method: 'POST', body: JSON.stringify({ content }) }); window.closeModal(); await refreshAdmin(id); portal.render(); }
    catch (err) { error(err); }
  };
  window.doReopen = async (event, id) => {
    event.preventDefault(); const index = Number(new FormData(event.currentTarget).get('stage'));
    const stage = ['cadastro','embalagem','retirada','entregador','conclusao'][index];
    try { await api(`/api/admin/operations/${encodeURIComponent(id)}/reopen`, { method: 'POST', body: JSON.stringify({ stage }) }); window.closeModal(); await refreshAdmin(id); portal.render(); }
    catch (err) { error(err); }
  };
  window.saveDelivery = async (event, id) => {
    event.preventDefault(); const data = Object.fromEntries(new FormData(event.currentTarget));
    const payload = { name: data.name, company: data.company, operationalPhone: data.phone, identification: data.identification, vehicleType: data.vehicle, vehicleModel: data.model, plate: data.plate, eta: data.eta };
    try { await api(`/api/admin/operations/${encodeURIComponent(id)}/delivery`, { method: 'POST', body: JSON.stringify(payload) }); window.closeModal(); await refreshAdmin(id); portal.render(); }
    catch (err) { error(err); }
  };
  window.deliveryStatus = async (id, status) => runAdminChange(id, `/api/admin/operations/${encodeURIComponent(id)}/delivery/status`, 'PATCH', { status });
  window.saveEdit = async (event, id) => {
    event.preventDefault(); const f = Object.fromEntries(new FormData(event.currentTarget));
    try { await api(`/api/admin/operations/${encodeURIComponent(id)}`, { method: 'PATCH', body: JSON.stringify({ customerName: f.customer, customerDocument: f.document, phone: f.phone, email: f.email, productName: f.product, availableAmount: Number(f.amount), pickupAddress: f.pickupAddress || '', internalNotes: f.notes || '' }) }); window.closeModal(); await refreshAdmin(id); portal.render(); }
    catch (err) { error(err); }
  };
  window.saveEditedPickup = async (event, id) => {
    event.preventDefault(); const body = Object.fromEntries(new FormData(event.currentTarget));
    try { await api(`/api/admin/operations/${encodeURIComponent(id)}/pickup`, { method: 'PATCH', body: JSON.stringify(body) }); window.closeModal(); await refreshAdmin(id); portal.render(); }
    catch (err) { error(err); }
  };
  window.saveNotes = async (event, id) => {
    event.preventDefault(); const internalNotes = new FormData(event.currentTarget).get('notes');
    try { await api(`/api/admin/operations/${encodeURIComponent(id)}`, { method: 'PATCH', body: JSON.stringify({ internalNotes }) }); window.closeModal(); await refreshAdmin(id); portal.render(); }
    catch (err) { error(err); }
  };
  window.saveFinal = async id => {
    const finalMessage = document.getElementById('final-msg').value;
    await runAdminChange(id, `/api/admin/operations/${encodeURIComponent(id)}`, 'PATCH', { finalMessage });
  };
  window.finishOperation = async id => {
    const finalMessage = document.getElementById('final-msg').value;
    await runAdminChange(id, `/api/admin/operations/${encodeURIComponent(id)}`, 'PATCH', { status: 'CONCLUIDA', finalMessage });
  };
  window.cancelOperation = async id => {
    if (!confirm('Deseja cancelar esta operação?')) return;
    await runAdminChange(id, `/api/admin/operations/${encodeURIComponent(id)}`, 'PATCH', { status: 'CANCELADA' });
  };
  window.saveSettings = async event => {
    event.preventDefault(); const values = Object.fromEntries(new FormData(event.currentTarget));
    try { const response = await api('/api/admin/settings', { method: 'PUT', body: JSON.stringify(values) }); portal.db.settings = { ...portal.db.settings, ...response.settings }; window.__portal.render(); flash('Configurações salvas'); }
    catch (err) { error(err); }
  };
  window.saveRegistration = async event => {
    event.preventDefault(); const data = Object.fromEntries(new FormData(event.currentTarget));
    try { await api('/api/client/registration', { method: 'POST', body: JSON.stringify(data) }); await refreshClient(); flash('Dados enviados com sucesso.'); }
    catch (err) { error(err); }
  };
  window.savePickup = async event => {
    event.preventDefault(); const body = Object.fromEntries(new FormData(event.currentTarget));
    try { await api('/api/client/pickup', { method: 'POST', body: JSON.stringify(body) }); await refreshClient(); flash('Retirada agendada.'); }
    catch (err) { error(err); }
  };
  window.submitPackage = async event => {
    event.preventDefault(); const form = event.currentTarget, photo = form.photo.files[0], video = form.video.files[0];
    const choices = [{ file: photo, type: 'product_photo' }, { file: video, type: 'package_video' }];
    try {
      if (choices.some(({ file }) => !file)) throw new Error('Selecione a foto e o vídeo da embalagem.');
      await api('/api/client/uploads/submit', {
        method: 'POST',
        body: JSON.stringify({ files: choices.map(({ file, type }) => ({ type, fileName: file.name, contentType: file.type, size: file.size })) })
      });
      await refreshClient(); flash('Seleção confirmada. A próxima etapa foi liberada.');
    } catch (err) { error(err); }
  };

  window.addEventListener('popstate', async () => {
    try {
      const path = location.pathname;
      if (adminRoute(path) && sessionStorage.getItem('portal_admin_auth') === 'yes') await refreshAdmin(path.match(/^\/admin\/operacoes\/([^/]+)$/)?.[1]);
      if (path === '/operacao') await refreshClient();
    } catch (err) { error(err); }
    portal.render();
  });

  function setupPage() {
    document.getElementById('app').innerHTML = `<main class="access-page"><section class="access-aside" style="background:linear-gradient(145deg,#f4effa 0%,#ffffff 85%)"><div class="aside-copy"><div class="brand"><div class="logo-mark">LKX</div><div class="brand-copy">LKX<small>Portal de operações</small></div></div><div style="height:54px"></div><div class="eyebrow">Acompanhamento seguro</div><h2>Clareza e tranquilidade em cada etapa.</h2><p>Acompanhe sua operação com informações organizadas e acesso protegido.</p><div class="notice" style="background:#fff;border-color:#e9e1f2">Seus dados são acessíveis somente por meio de uma sessão autorizada.</div></div></section><section class="access-main"><div class="access-box"><div class="eyebrow" style="margin-bottom:12px">Portal do cliente</div><h1>Estamos preparando seu acesso</h1><p>Não foi possível carregar o portal neste momento. Tente novamente em instantes.</p><div class="notice"><b>Seu acesso continua protegido.</b><br>Se a mensagem persistir, entre em contato com a equipe que forneceu sua chave.</div><button class="btn btn-primary" type="button" onclick="location.reload()">Tentar novamente</button></div></section></main>`;
  }

  async function bootstrap() {
    try {
      try { localStorage.removeItem('portal_operacoes_demo_v1'); } catch { /* storage may be disabled */ }
      portal.db.operations = [];
      const health = await api('/api/health');
      if (!health.firebaseConfigured) { setupPage(); return; }
      const path = location.pathname;
      if (path.startsWith('/admin') && path !== '/admin/login') {
        try { await api('/api/auth/me'); sessionStorage.setItem('portal_admin_auth', 'yes'); await refreshAdmin(path.match(/^\/admin\/operacoes\/([^/]+)$/)?.[1]); await refreshSettings(); }
        catch { sessionStorage.removeItem('portal_admin_auth'); }
      }
      if (path === '/operacao') {
        try { const response = await api('/api/client/operation'); const raw = response.operation; const op = mapOperation({ id: raw.id, publicOperationNumber: raw.number, customerName: raw.customer?.name, productName: raw.productName, availableAmount: raw.availableAmount, status: raw.status, pickup: raw.pickup, delivery: raw.delivery, messages: raw.messages, history: raw.history, updatedAt: raw.updatedAt, steps: raw.steps, finalMessage: raw.finalMessage }, raw); setOperations([op]); sessionStorage.setItem('portal_client_op', op.id); }
        catch { history.replaceState({}, '', '/acesso'); }
      }
      portal.render();
      if (location.pathname === '/operacao') startClientRefresh();
    } catch { setupPage(); }
  }
  bootstrap();
})();

