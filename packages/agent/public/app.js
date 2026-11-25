'use strict';
const $ = (id) => document.getElementById(id);
const log = $('log');

const esc = (v) => String(v ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
// Tiny safe renderer: escape first, then allow **bold** and `code`.
const md = (s) => esc(s).replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>').replace(/`([^`]+)`/g, '<code>$1</code>');

const SUGGESTIONS = [
  'Which orders are still processing?',
  'Do we have HPE-1001 (ProLiant DL380 Gen11) in stock in Singapore?',
  'Show me the details for order SO-10001',
  'Start an RMA for 1 Aruba Instant On AP25 access point on SO-10001, wrong model ordered',
  'Create an RMA for the Alletra storage system on SO-10008, it arrived defective',
  'Create an RMA for the Aruba CX 6300M switch on SO-10004',
  'Cancel order SO-10005, the account changed their requirements',
  'Who is account ACC-004 and what is their tier?',
];

function addMsg(kind, html) {
  const d = document.createElement('div');
  d.className = 'msg ' + kind;
  d.innerHTML = html;
  log.appendChild(d);
  log.scrollTop = log.scrollHeight;
  return d;
}

// Tool names reached over A2A (Agent2Agent), not MCP -- add more here if more A2A tools are added later.
const A2A_TOOLS = new Set(['ask_hr_agent']);

function addCalls(calls) {
  if (!calls?.length) return;
  const wrap = document.createElement('div');
  wrap.className = 'calls';
  for (const c of calls) {
    let denied = false;
    try { const j = JSON.parse(c.result); denied = c.isError && (j.error === 'forbidden_for_role' || j.error === 'insufficient_scope'); } catch {}
    const isA2a = A2A_TOOLS.has(c.name);
    const el = document.createElement('details');
    el.className = 'call' + (isA2a ? ' a2a' : '') + (denied ? ' denied' : '');
    el.innerHTML = `<summary><span class="proto ${isA2a ? 'a2a' : 'mcp'}">${isA2a ? 'A2A' : 'MCP'}</span> ${isA2a ? '🤝' : '🔧'} <code>${esc(c.name)}</code><span class="tag ${c.isError ? 'bad' : 'ok'}">${denied ? 'denied' : c.isError ? 'error' : 'ok'}</span> <span class="muted">${esc(c.ms)}ms</span></summary>
      <pre>${esc(JSON.stringify(c.args))}</pre><pre>${esc(c.result)}</pre>`;
    wrap.appendChild(el);
  }
  log.appendChild(wrap);
  log.scrollTop = log.scrollHeight;
}

function renderTrace(trace) {
  const el = $('trace');
  if (!trace?.length) return;
  el.innerHTML = trace.map((s) => `
    <div class="step ${esc(s.status)}">
      <div class="t">${s.step ? esc(s.step) + '. ' : ''}${esc(s.title)} ${s.ms != null ? `<span class="muted">(${esc(s.ms)}ms)</span>` : ''}</div>
      ${s.detail ? `<div class="d">${esc(s.detail)}</div>` : ''}
      ${s.data ? `<details><summary>${s.data.claims ? 'claims' : 'details'}</summary><pre>${esc(JSON.stringify(s.data, null, 2))}</pre></details>` : ''}
    </div>`).join('');
}

// How the agent reaches the portal: 'xaa' (the agent does the Cross App Access exchange itself) or 'gateway' (Okta Agent Gateway).
let mode = 'xaa';
let gatewayInfo = { enabled: false, signedIn: false };
let lastXaa = null; // what the governance panel showed in XAA mode, restored when switching back

// Direct A2A to the HR Agent: a separate card, not folded into the portal's own scopes/status above -- it is a
// different resource with its own scope grant (hr:read / hr:write), reached by a tool call, not by the mode
// toggle (the model can use it alongside either Direct XAA or the Okta Agent Gateway in the same conversation).
function renderHrGovernance(scope, expiresAt) {
  $('hrScopes').innerHTML = scope?.length ? scope.map((s) => `<span>${esc(s)}</span>`).join('') : '<span class="muted">–</span>';
  $('hrStatus').textContent = expiresAt
    ? `Connected. HR Agent token valid until ${new Date(expiresAt).toLocaleTimeString()}.`
    : 'Not connected yet. Ask an HR question (or the button) runs the exchange.';
}

function renderGovernance(scope, tools, expiresAt, role) {
  if (mode === 'gateway') {
    $('scopes').innerHTML = '<span class="muted">applied by the gateway, then capped by your portal role</span>';
  } else {
    lastXaa = { scope, tools, expiresAt, role };
    $('scopes').innerHTML = scope?.length ? scope.map((s) => `<span>${esc(s)}</span>`).join('') : '<span class="muted">–</span>';
  }
  $('tools').innerHTML = tools?.length ? tools.map((t) => `<span title="${esc(t.description)}">${esc(t.name)}</span>`).join('') : '<span class="muted">–</span>';
  if (expiresAt) {
    $('xstatus').textContent = mode === 'gateway'
      ? `Connected through the Okta Agent Gateway. Gateway token valid until ${new Date(expiresAt).toLocaleTimeString()}.`
      : `Connected${role ? ` as role "${role}"` : ''}. HPE Order Portal token valid until ${new Date(expiresAt).toLocaleTimeString()}.`;
  }
}

function setMode(m, announce) {
  mode = m === 'gateway' && gatewayInfo.enabled ? 'gateway' : 'xaa';
  try { localStorage.setItem('agentMode', mode); } catch {}
  document.querySelectorAll('input[name=mode]').forEach((r) => (r.checked = r.value === mode));
  $('cardTitle').textContent = mode === 'gateway' ? 'Okta Agent Gateway' : 'Cross App Access';
  $('scopesHead').textContent = mode === 'gateway' ? 'Scopes' : 'Scopes granted by Okta';
  $('connect').textContent = mode === 'gateway' ? (gatewayInfo.signedIn ? 'Refresh tools' : 'Connect to gateway') : 'Run XAA exchange';
  $('trace').innerHTML = '<span class="muted">' + (mode === 'gateway' ? 'The gateway path appears here after a message.' : 'The ID token → ID-JAG → access token steps appear here.') + '</span>';
  if (mode === 'gateway') {
    $('scopes').innerHTML = '<span class="muted">applied by the gateway, then capped by your portal role</span>';
    $('tools').innerHTML = '<span class="muted">–</span>';
    $('xstatus').textContent = gatewayInfo.signedIn ? 'Signed in to the gateway. Sending a message (or the button) lists its tools.' : 'Not signed in to the gateway yet. Click "Connect to gateway".';
    if (gatewayInfo.signedIn) void gatewayConnect();
  } else if (lastXaa) {
    renderGovernance(lastXaa.scope, lastXaa.tools, lastXaa.expiresAt, lastXaa.role);
  } else {
    $('scopes').innerHTML = '<span class="muted">–</span>';
    $('tools').innerHTML = '<span class="muted">–</span>';
    $('xstatus').textContent = 'Not connected yet. Sending a message (or the button) runs the exchange.';
  }
  if (announce) addMsg('sys', mode === 'gateway' ? 'Now using the <strong>Okta Agent Gateway</strong>: the agent calls the gateway, which adds the portal credential.' : 'Now using <strong>direct Cross App Access</strong>: the agent exchanges your Okta token itself.');
}

/** List the tools the gateway exposes (also proves the gateway token works). */
async function gatewayConnect() {
  $('xstatus').textContent = 'Asking the gateway for its tools…';
  const { ok, j } = await api('/api/gateway/connect', {});
  if (j.trace) renderTrace(j.trace);
  if (ok) { gatewayInfo.signedIn = true; renderGovernance([], j.tools, j.expiresAt); }
  else showGatewayProblem(j);
}

function showGatewayProblem(j) {
  if (j.error === 'gateway_not_signed_in') {
    gatewayInfo.signedIn = false;
    $('connect').textContent = 'Connect to gateway';
    $('xstatus').textContent = 'Not signed in to the gateway yet. Click "Connect to gateway".';
    addMsg('err', `Sign in to the Okta Agent Gateway first: <a href="${esc(j.loginUrl || '/gateway/login?return=/')}">Sign in to the gateway</a>.`);
  } else if (j.error === 'consent_required' && /^https:\/\//.test(j.consentUrl || '')) {
    addMsg('err', `${esc(j.message)} <a class="btn small" target="_blank" rel="noopener" href="${esc(j.consentUrl)}">Connect your account</a> then ask again.`);
  } else {
    $('xstatus').textContent = j.message || 'Gateway request failed.';
    addMsg('err', esc(j.message || j.error || 'Gateway request failed'));
  }
}

async function api(path, body) {
  const r = await fetch(path, { method: body === undefined ? 'GET' : 'POST', headers: { 'Content-Type': 'application/json' }, body: body === undefined ? undefined : JSON.stringify(body) });
  const j = await r.json().catch(() => ({}));
  return { ok: r.ok, status: r.status, j };
}

// Wording and endpoint of the connect button; the on-behalf-of agent app overrides them through /api/me -> ui.
let connectPath = '/api/xaa/connect';
let welcome = 'Signed in. Ask a question — the agent will use Okta Cross App Access to reach the HPE Order Portal on your behalf.';
function applyUi(ui) {
  if (!ui) return;
  if (ui.subtitle) $('subtitle').textContent = ui.subtitle;
  if (ui.heroText) $('heroText').innerHTML = ui.heroText;
  if (ui.cardTitle) $('cardTitle').textContent = ui.cardTitle;
  if (ui.connectLabel) $('connect').textContent = ui.connectLabel;
  if (ui.scopesHead) $('scopesHead').textContent = ui.scopesHead;
  if (ui.traceHint) $('trace').innerHTML = `<span class="muted">${esc(ui.traceHint)}</span>`;
  if (ui.connectPath) connectPath = ui.connectPath;
  if (ui.welcome) welcome = ui.welcome;
}

async function init() {
  const { j: me } = await api('/api/me');
  applyUi(me.ui);
  if (me.agentName) {
    $('agentName').textContent = me.agentName;
    document.title = 'HPE ' + me.agentName;
  }
  if (!me.authenticated) {
    $('signedout').classList.remove('hidden');
    return;
  }
  $('app').classList.remove('hidden');
  const label = me.user?.email || me.user?.name || me.user?.sub;
  $('who').innerHTML = `<span>${esc(label)}</span> · <span>${esc(me.model)}</span> <a class="btn small" href="/logout">Sign out</a>`;
  renderGovernance(me.retail?.scope, me.tools, me.retail?.expiresAt, me.retail?.role);
  if (me.hrAgent?.enabled) {
    $('hrCard').classList.remove('hidden');
    renderHrGovernance(me.hrAgent.scope, me.hrAgent.expiresAt);
  }
  gatewayInfo = me.gateway || gatewayInfo;
  if (gatewayInfo.enabled) {
    $('modeBox').classList.remove('hidden');
    document.querySelectorAll('input[name=mode]').forEach((r) => (r.onchange = () => setMode(r.value, true)));
    let saved = 'xaa';
    try { saved = localStorage.getItem('agentMode') || 'xaa'; } catch {}
    if (saved === 'gateway') setMode('gateway', false);
  }
  addMsg('sys', esc(welcome));
  if (!me.llmConfigured) addMsg('err', 'ANTHROPIC_API_KEY is not set on the server, so chat will fail. Add it to .env and restart.');
  $('chips').innerHTML = SUGGESTIONS.map((s) => `<button type="button">${esc(s)}</button>`).join('');
  $('chips').querySelectorAll('button').forEach((b) => (b.onclick = () => { $('input').value = b.textContent; $('form').requestSubmit(); }));
}

function handleAuthExpired(j) {
  if (j.error === 'not_authenticated') addMsg('err', 'Your session ended (the agent app was restarted). <a href="/login">Sign in again</a>.');
  if (j.error === 'id_token_expired' || (j.error === 'invalid_grant' && j.step === 2)) addMsg('err', 'Your Okta session expired. <a href="/login">Sign in again</a>.');
}

$('form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const text = $('input').value.trim();
  if (!text) return;
  $('input').value = '';
  $('send').disabled = true;
  addMsg('user', esc(text));
  const pending = addMsg('sys', '<span class="dots">Working</span>');
  const { ok, j } = await api('/api/chat', { message: text, mode });
  pending.remove();
  renderTrace(j.trace);
  if (!ok && j.error === 'not_authenticated') {
    handleAuthExpired(j);
  } else if (!ok && mode === 'gateway') {
    showGatewayProblem(j);
  } else if (!ok) {
    addMsg('err', esc(j.message || j.error || 'Request failed'));
    handleAuthExpired(j);
  } else {
    addCalls(j.toolCalls);
    addMsg('bot', md(j.reply || '(no reply)'));
    renderGovernance(j.scope, j.tools, j.expiresAt, j.role);
    if (j.hr) renderHrGovernance(j.hr.scope, j.hr.expiresAt);
  }
  $('send').disabled = false;
  $('input').focus();
});

$('connect').addEventListener('click', async () => {
  if (mode === 'gateway') {
    if (!gatewayInfo.signedIn) { location.href = '/gateway/login?return=/'; return; }
    $('connect').disabled = true;
    await gatewayConnect();
    $('connect').disabled = false;
    return;
  }
  $('connect').disabled = true;
  $('xstatus').textContent = 'Running the token exchange…';
  const { ok, j } = await api(connectPath, {});
  renderTrace(j.trace);
  if (ok) renderGovernance(j.scope, j.tools, j.expiresAt, j.role);
  else { $('xstatus').textContent = j.message || 'XAA exchange failed.'; handleAuthExpired(j); }
  $('connect').disabled = false;
});

$('hrConnect')?.addEventListener('click', async () => {
  $('hrConnect').disabled = true;
  $('hrStatus').textContent = 'Running the HR Agent token exchange…';
  const { ok, j } = await api('/api/hr/connect', {});
  renderTrace(j.trace);
  if (ok) renderHrGovernance(j.scope, j.expiresAt);
  else { $('hrStatus').textContent = j.message || 'HR Agent exchange failed.'; handleAuthExpired(j); }
  $('hrConnect').disabled = false;
});

$('reset').addEventListener('click', async () => {
  await api('/api/chat/reset', {});
  log.innerHTML = '';
  addMsg('sys', 'Conversation cleared.');
});

init();
