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

function addCalls(calls) {
  if (!calls?.length) return;
  const wrap = document.createElement('div');
  wrap.className = 'calls';
  for (const c of calls) {
    let denied = false;
    try { const j = JSON.parse(c.result); denied = c.isError && (j.error === 'forbidden_for_role' || j.error === 'insufficient_scope'); } catch {}
    const el = document.createElement('details');
    el.className = 'call' + (denied ? ' denied' : '');
    el.innerHTML = `<summary>🔧 <code>${esc(c.name)}</code><span class="tag ${c.isError ? 'bad' : 'ok'}">${denied ? 'denied' : c.isError ? 'error' : 'ok'}</span> <span class="muted">${esc(c.ms)}ms</span></summary>
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

function renderGovernance(scope, tools, expiresAt, role) {
  $('scopes').innerHTML = scope?.length ? scope.map((s) => `<span>${esc(s)}</span>`).join('') : '<span class="muted">–</span>';
  $('tools').innerHTML = tools?.length ? tools.map((t) => `<span title="${esc(t.description)}">${esc(t.name)}</span>`).join('') : '<span class="muted">–</span>';
  if (expiresAt) $('xstatus').textContent = `Connected${role ? ` as role "${role}"` : ''}. HPE Order Portal token valid until ${new Date(expiresAt).toLocaleTimeString()}.`;
}

async function api(path, body) {
  const r = await fetch(path, { method: body === undefined ? 'GET' : 'POST', headers: { 'Content-Type': 'application/json' }, body: body === undefined ? undefined : JSON.stringify(body) });
  const j = await r.json().catch(() => ({}));
  return { ok: r.ok, status: r.status, j };
}

async function init() {
  const { j: me } = await api('/api/me');
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
  addMsg('sys', 'Signed in. Ask a question — the agent will use Okta Cross App Access to reach the HPE Order Portal on your behalf.');
  if (!me.llmConfigured) addMsg('err', 'ANTHROPIC_API_KEY is not set on the server, so chat will fail. Add it to .env and restart.');
  $('chips').innerHTML = SUGGESTIONS.map((s) => `<button type="button">${esc(s)}</button>`).join('');
  $('chips').querySelectorAll('button').forEach((b) => (b.onclick = () => { $('input').value = b.textContent; $('form').requestSubmit(); }));
}

function handleAuthExpired(j) {
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
  const { ok, j } = await api('/api/chat', { message: text });
  pending.remove();
  renderTrace(j.trace);
  if (!ok) {
    addMsg('err', esc(j.message || j.error || 'Request failed'));
    handleAuthExpired(j);
  } else {
    addCalls(j.toolCalls);
    addMsg('bot', md(j.reply || '(no reply)'));
    renderGovernance(j.scope, j.tools, j.expiresAt, j.role);
  }
  $('send').disabled = false;
  $('input').focus();
});

$('connect').addEventListener('click', async () => {
  $('connect').disabled = true;
  $('xstatus').textContent = 'Running XAA exchange…';
  const { ok, j } = await api('/api/xaa/connect', {});
  renderTrace(j.trace);
  if (ok) renderGovernance(j.scope, j.tools, j.expiresAt, j.role);
  else { $('xstatus').textContent = j.message || 'XAA exchange failed.'; handleAuthExpired(j); }
  $('connect').disabled = false;
});

$('reset').addEventListener('click', async () => {
  await api('/api/chat/reset', {});
  log.innerHTML = '';
  addMsg('sys', 'Conversation cleared.');
});

init();
