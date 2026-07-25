/* NocTORnal analyst console.
 *
 * No framework, no build step, no CDN — the app shell is served under a strict
 * `default-src 'self'` CSP, so everything lives in these three files and there
 * is no inline script or style anywhere.
 *
 * TOKEN HANDLING — read this before shipping to a browser deployment.
 * The bearer token is held in sessionStorage and sent as an Authorization
 * header. sessionStorage is readable by any script that achieves XSS on this
 * origin, so a production browser deployment should instead use the API's
 * HttpOnly session cookie plus the X-CSRF-Token double-submit it already
 * supports: the cookie is then unreadable from JS and the CSRF header defeats
 * cross-site posting. This build uses the bearer path because it is the same
 * code path an operator's CLI and the integration tests use. The token is
 * never logged, never put in a URL, and never rendered.
 */
'use strict';

const API = '/api/v1';
const TOKEN_KEY = 'noctornal.token';

/* ── vocabularies ─────────────────────────────────────────────────────── */

const TLP = ['CLEAR', 'GREEN', 'AMBER', 'AMBER_STRICT', 'RED'];

const BASES = [
  ['DIRECT_OBSERVATION', 'Direct observation'],
  ['THIRD_PARTY_REPORT', 'Third-party report'],
  ['ANALYST_INFERENCE', 'Analyst inference'],
  ['AUTOMATED_INFERENCE', 'Automated inference'],
  ['SELF_CLAIM', 'Self claim'],
  ['LEGAL_PROCESS', 'Legal process'],
];
const INFERENCE_BASES = ['ANALYST_INFERENCE', 'AUTOMATED_INFERENCE'];

/* Admiralty System — source reliability A-F, information credibility 1-6. */
const RELIABILITY = {
  A: 'Completely reliable', B: 'Usually reliable', C: 'Fairly reliable',
  D: 'Not usually reliable', E: 'Unreliable', F: 'Reliability cannot be judged',
};
const CREDIBILITY = {
  '1': 'Confirmed by other sources', '2': 'Probably true', '3': 'Possibly true',
  '4': 'Doubtful', '5': 'Improbable', '6': 'Truth cannot be judged',
};
/* ICD 203 analytic confidence. */
const CONFIDENCE = ['LOW', 'MODERATE', 'HIGH'];

/* The /ontology endpoint returns only ACTOR/ARTEFACT/CONTEXT categories, but
   docs/06 defines seven hues. Map the type key to the closest hue by meaning
   and fall back on the category for keys added after this build. */
const HUE_BY_TYPE = {
  IDENTITY: 'actor-persona',
  PERSON: 'actor-person',
  GROUP: 'actor-group', SUBGROUP: 'actor-group', ORGANISATION: 'actor-group',
  VICTIM: 'actor-group',
  WALLET: 'artefact-finance', TRANSACTION: 'artefact-finance',
  MALWARE: 'artefact-malware', SAMPLE: 'artefact-malware',
  BUILDER: 'artefact-malware', TOOL: 'artefact-malware',
};
const HUE_BY_CATEGORY = { ACTOR: 'actor-group', ARTEFACT: 'artefact-infra',
                          CONTEXT: 'context' };

/* ── state ────────────────────────────────────────────────────────────── */

const state = {
  token: sessionStorage.getItem(TOKEN_KEY),
  userId: null,
  cases: [],
  caseId: null,
  caseRec: null,
  tab: 'graph',
  ontology: { node_types: [], edge_types: [] },
  nodeTypeMeta: new Map(),   // key -> {display_name, category}
  nodes: [],
  edges: [],
  evidence: [],
  selection: null,           // {kind:'node'|'edge', id}
  includeRetracted: false,
  showInferred: true,
  graph: null,
  inspSeq: 0,
  booting: true,
};

/* ── DOM helpers ──────────────────────────────────────────────────────── */

const $ = (id) => document.getElementById(id);

function el(tag, cls, text) {
  const n = document.createElement(tag);
  if (cls) n.className = cls;
  if (text !== undefined && text !== null) n.textContent = String(text);
  return n;
}
function clear(node) { while (node.firstChild) node.removeChild(node.firstChild); }
function show(node, on) { node.hidden = !on; }
function setMsg(node, text) {
  node.textContent = text || '';
  node.hidden = !text;
}
function opts(select, pairs, selected) {
  clear(select);
  for (const [value, label] of pairs) {
    const o = el('option', null, label);
    o.value = value;
    if (value === selected) o.selected = true;
    select.appendChild(o);
  }
}
function hueClass(nodeType) {
  const meta = state.nodeTypeMeta.get(nodeType);
  const hue = HUE_BY_TYPE[nodeType] ||
              HUE_BY_CATEGORY[meta ? meta.category : ''] || 'context';
  return 'hue-' + hue;
}
function typeName(key) {
  const meta = state.nodeTypeMeta.get(key);
  return meta ? meta.display_name : key;
}
function tlpChip(value) {
  const c = el('span', 'chip tlp-' + value, value);
  return c;
}
function fmtTime(iso) {
  if (!iso) return '—';
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? String(iso) : d.toLocaleString();
}
function fmtBytes(n) {
  if (!Number.isFinite(n)) return '—';
  const u = ['B', 'KiB', 'MiB', 'GiB'];
  let i = 0, v = n;
  while (v >= 1024 && i < u.length - 1) { v /= 1024; i += 1; }
  return (i === 0 ? v : v.toFixed(1)) + ' ' + u[i];
}
function shortHash(h) { return h ? h.slice(0, 16) + '…' : '—'; }
function shortId(id) { return id ? id.slice(0, 8) : '—'; }

/* ── banners: every failure surfaces here, never only in the console ──── */

function banner(title, detail, kind) {
  const b = el('div', 'banner' + (kind ? ' ' + kind : ''));
  const text = el('div', 'banner-text');
  text.appendChild(el('div', 'banner-title', title));
  if (detail) text.appendChild(el('div', 'banner-detail', detail));
  const close = el('button', 'banner-close', '×');
  close.type = 'button';
  close.setAttribute('aria-label', 'Dismiss message');
  close.addEventListener('click', () => b.remove());
  b.append(text, close);
  $('banners').appendChild(b);
}

/* ── API layer ────────────────────────────────────────────────────────── */

class ApiError extends Error {
  constructor(status, title, detail) {
    super(title);
    this.status = status;
    this.title = title;
    this.detail = detail || '';
  }
}

async function problemOf(res) {
  try {
    const body = await res.json();
    return {
      title: body.title || ('HTTP ' + res.status),
      detail: body.detail || '',
    };
  } catch (_e) {
    return { title: 'HTTP ' + res.status, detail: res.statusText || '' };
  }
}

async function api(path, options) {
  const o = options || {};
  const headers = {};
  if (state.token) headers['Authorization'] = 'Bearer ' + state.token;
  let body;
  if (o.form) {
    body = o.form;                       // let the browser set the boundary
  } else if (o.json !== undefined) {
    headers['Content-Type'] = 'application/json';
    body = JSON.stringify(o.json);
  }
  let res;
  try {
    res = await fetch(API + path, { method: o.method || 'GET', headers, body });
  } catch (_e) {
    throw new ApiError(0, 'Cannot reach the API',
      'The request did not complete. Check the API service and your network.');
  }
  if (!res.ok) {
    const p = await problemOf(res);
    const err = new ApiError(res.status, p.title, p.detail);
    if (res.status === 401 && path !== '/auth/login') {
      endSession('Session ended', p.detail || 'Sign in again to continue.');
      err.handled = true;          // endSession already told the analyst
    }
    throw err;
  }
  if (res.status === 204) return null;
  const ct = res.headers.get('Content-Type') || '';
  return ct.includes('json') ? res.json() : res.text();
}

/** Report any unexpected failure in the banner stack. */
function fail(err) {
  if (err && err.handled) return;
  if (err instanceof ApiError) banner(err.title, err.detail);
  else banner('Unexpected error', err && err.message ? err.message : String(err));
}

/** A rejected submission belongs next to the form; anything else is a banner.
 *  problem+json `detail` is shown as the server wrote it — never embellished. */
function inlineProblem(errBox, err) {
  if (err instanceof ApiError && err.status >= 400 && err.status < 500) {
    setMsg(errBox, err.detail || err.title);
  } else {
    fail(err);
  }
}

/* ── session ──────────────────────────────────────────────────────────── */

function endSession(title, detail) {
  state.token = null;
  state.userId = null;
  state.caseId = null;
  state.caseRec = null;
  sessionStorage.removeItem(TOKEN_KEY);
  stopGraph();
  show($('view-app'), false);
  show($('view-login'), true);
  /* On first load a stale token is expected, not news — boot() handles it. */
  if (title && !state.booting) banner(title, detail, 'warn');
  $('login-password').value = '';
  $('login-totp').value = '';
  $('login-email').focus();
}

async function doLogin(event) {
  event.preventDefault();
  const errBox = $('login-error');
  setMsg(errBox, '');
  const btn = $('login-submit');
  btn.disabled = true;
  try {
    const out = await api('/auth/login', {
      method: 'POST',
      json: {
        email: $('login-email').value.trim(),
        password: $('login-password').value,
        totp_code: $('login-totp').value.trim(),
      },
    });
    state.token = out.token;
    sessionStorage.setItem(TOKEN_KEY, out.token);
    $('login-password').value = '';
    $('login-totp').value = '';
    await startApp();
  } catch (err) {
    inlineProblem(errBox, err);
  } finally {
    btn.disabled = false;
  }
}

async function doLogout() {
  try { await api('/auth/logout', { method: 'POST' }); } catch (_e) { /* local sign-out regardless */ }
  endSession(null, null);
}

async function startApp() {
  const me = await api('/auth/me');
  state.userId = me.user_id;
  $('hdr-user').textContent = me.user_id;
  show($('view-login'), false);
  show($('view-app'), true);
  await showCaseList();
}

/* ── case list ────────────────────────────────────────────────────────── */

async function showCaseList() {
  state.caseId = null;
  state.caseRec = null;
  stopGraph();
  show($('view-workspace'), false);
  show($('view-cases'), true);
  show($('btn-cases'), false);
  show($('hdr-tlp'), false);
  $('hdr-case').textContent = 'No case selected';
  try {
    state.cases = await api('/cases');
    renderCases();
  } catch (err) { fail(err); }
}

function renderCases() {
  const body = $('cases-body');
  clear(body);
  for (const c of state.cases) {
    const tr = el('tr');
    tr.appendChild(el('td', 'num', c.code));
    tr.appendChild(el('td', null, c.title));
    tr.appendChild(el('td', null, c.status));
    const tdClass = el('td');
    tdClass.appendChild(tlpChip(c.classification));
    tr.appendChild(tdClass);
    const tdOpen = el('td');
    const b = el('button', 'btn small', 'Open');
    b.type = 'button';
    b.setAttribute('aria-label', 'Open case ' + c.code);
    b.addEventListener('click', () => openCase(c.id));
    tdOpen.appendChild(b);
    tr.appendChild(tdOpen);
    body.appendChild(tr);
  }
  show($('cases-empty'), state.cases.length === 0);
}

async function createCase(event) {
  event.preventDefault();
  const errBox = $('case-error');
  setMsg(errBox, '');
  const legal = $('case-legal').value.trim();
  const retention = $('case-retention').value;
  const review = $('case-review').value;
  if (!legal) {
    setMsg(errBox, 'A lawful basis is required. A case cannot exist without one.');
    return;
  }
  if (retention && review && review > retention) {
    setMsg(errBox, 'Review due must be on or before the retention date.');
    return;
  }
  const payload = {
    code: $('case-code').value.trim(),
    title: $('case-title').value.trim(),
    legal_basis: legal,
    retention_until: retention,
    review_due: review,
    classification: $('case-class').value,
  };
  const summary = $('case-summary').value.trim();
  const authority = $('case-authority').value.trim();
  if (summary) payload.summary = summary;
  if (authority) payload.authority_ref = authority;
  try {
    const created = await api('/cases', { method: 'POST', json: payload });
    state.cases.unshift(created);
    renderCases();
    $('case-form').reset();
    $('case-class').value = 'AMBER';
    banner('Case ' + created.code + ' created', 'Status ' + created.status + '.', 'warn');
  } catch (err) {
    inlineProblem(errBox, err);
  }
}

/* ── workspace ────────────────────────────────────────────────────────── */

async function openCase(caseId) {
  state.caseId = caseId;
  state.selection = null;
  try {
    const [rec, ontology] = await Promise.all([
      api('/cases/' + caseId),
      api('/cases/' + caseId + '/ontology'),
    ]);
    state.caseRec = rec;
    state.ontology = ontology;
    state.nodeTypeMeta = new Map(
      ontology.node_types.map((t) => [t.key, t]));
    $('hdr-case').textContent = rec.code + ' — ' + rec.title;
    const tlp = $('hdr-tlp');
    tlp.className = 'chip tlp-' + rec.classification;
    tlp.textContent = 'TLP:' + rec.classification;
    show(tlp, true);
    show($('btn-cases'), true);
    show($('view-cases'), false);
    show($('view-workspace'), true);
    buildPickers();
    renderInspector();
    await loadGraph();
    await loadEvidence();
    selectTab('graph');
  } catch (err) { fail(err); }
}

function selectTab(name) {
  state.tab = name;
  for (const tab of document.querySelectorAll('.tab')) {
    const on = tab.dataset.tab === name;
    tab.setAttribute('aria-selected', on ? 'true' : 'false');
    tab.tabIndex = on ? 0 : -1;
    show($('pane-' + tab.dataset.tab), on);
  }
  if (name === 'graph') resizeGraph();
}

function initTabs() {
  const tabs = Array.from(document.querySelectorAll('.tab'));
  tabs.forEach((tab, i) => {
    tab.addEventListener('click', () => selectTab(tab.dataset.tab));
    tab.addEventListener('keydown', (e) => {
      let next = null;
      if (e.key === 'ArrowRight') next = tabs[(i + 1) % tabs.length];
      else if (e.key === 'ArrowLeft') next = tabs[(i - 1 + tabs.length) % tabs.length];
      else if (e.key === 'Home') next = tabs[0];
      else if (e.key === 'End') next = tabs[tabs.length - 1];
      if (next) { e.preventDefault(); selectTab(next.dataset.tab); next.focus(); }
    });
  });
}

/* ── graph data ───────────────────────────────────────────────────────── */

async function loadGraph() {
  try {
    const [nodes, edges] = await Promise.all([
      api('/cases/' + state.caseId + '/nodes?limit=500'),
      api('/cases/' + state.caseId + '/edges?limit=1000&include_inferred=true'),
    ]);
    state.nodes = nodes;
    state.edges = edges;
    buildEntityFilter();
    renderEntities();
    buildEdgePickers();
    buildGraph();
  } catch (err) { fail(err); }
}

/* ── sociogram: a small spring/repulsion simulation on <canvas> ───────── */

const canvas = $('graph-canvas');
const ctx = canvas.getContext('2d');
const reduceMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
const cssVar = (name) =>
  getComputedStyle(document.documentElement).getPropertyValue(name).trim();

const PAINT = {};
function loadPaint() {
  PAINT.void = cssVar('--void');
  PAINT.pos = cssVar('--sign-positive');
  PAINT.neg = cssVar('--sign-negative');
  PAINT.neu = cssVar('--sign-neutral');
  PAINT.accent = cssVar('--accent');
  PAINT.label = cssVar('--text-secondary');
  PAINT.font = '11px ' + (cssVar('--ui') || 'sans-serif');
  PAINT.hues = {};
  for (const h of ['actor-persona', 'actor-person', 'actor-group',
                   'artefact-infra', 'artefact-finance', 'artefact-malware',
                   'context']) {
    PAINT.hues[h] = cssVar('--' + h);
  }
}

function buildGraph() {
  const w = canvas.clientWidth || 800, h = canvas.clientHeight || 600;
  const prev = state.graph ? state.graph.index : null;
  const nodes = state.nodes.map((n, i) => {
    const old = prev && prev.get(n.id);
    const a = (i / Math.max(1, state.nodes.length)) * Math.PI * 2;
    return {
      id: n.id, ref: n, deg: 0,
      x: old ? old.x : w / 2 + Math.cos(a) * (60 + w / 6),
      y: old ? old.y : h / 2 + Math.sin(a) * (60 + h / 6),
      vx: 0, vy: 0,
    };
  });
  const index = new Map(nodes.map((n) => [n.id, n]));
  const links = [];
  for (const e of state.edges) {
    const a = index.get(e.src_node_id), b = index.get(e.dst_node_id);
    if (!a || !b) continue;             // endpoint above the caller's clearance
    a.deg += 1; b.deg += 1;
    links.push({ ref: e, a: a, b: b });
  }
  state.graph = { nodes, links, index, alpha: 1, drag: null, raf: 0 };
  show($('graph-empty'), nodes.length === 0);
  resizeGraph();
  settle();
}

function step() {
  const g = state.graph;
  if (!g) return;
  const w = canvas.clientWidth || 800, h = canvas.clientHeight || 600;
  const cx = w / 2, cy = h / 2;
  const ns = g.nodes;
  for (let i = 0; i < ns.length; i += 1) {
    for (let j = i + 1; j < ns.length; j += 1) {
      const a = ns[i], b = ns[j];
      let dx = a.x - b.x, dy = a.y - b.y;
      let d2 = dx * dx + dy * dy;
      if (d2 < 1) { dx = (Math.random() - 0.5); dy = (Math.random() - 0.5); d2 = 1; }
      const f = Math.min(4000 / d2, 4);
      const d = Math.sqrt(d2);
      a.vx += (dx / d) * f; a.vy += (dy / d) * f;
      b.vx -= (dx / d) * f; b.vy -= (dy / d) * f;
    }
  }
  for (const l of g.links) {
    const dx = l.b.x - l.a.x, dy = l.b.y - l.a.y;
    const d = Math.max(1, Math.hypot(dx, dy));
    const f = (d - 130) * 0.02;
    const ux = (dx / d) * f, uy = (dy / d) * f;
    l.a.vx += ux; l.a.vy += uy;
    l.b.vx -= ux; l.b.vy -= uy;
  }
  for (const n of ns) {
    n.vx += (cx - n.x) * 0.004;
    n.vy += (cy - n.y) * 0.004;
    n.vx *= 0.84; n.vy *= 0.84;
    if (n === g.drag) { n.vx = 0; n.vy = 0; continue; }
    n.x += n.vx * g.alpha;
    n.y += n.vy * g.alpha;
    n.x = Math.max(24, Math.min(w - 24, n.x));
    n.y = Math.max(20, Math.min(h - 26, n.y));
  }
  g.alpha = Math.max(0.03, g.alpha * 0.985);
}

/** Run the layout. With prefers-reduced-motion the graph settles instantly. */
function settle() {
  const g = state.graph;
  if (!g) return;
  g.alpha = 1;
  if (reduceMotion) {
    for (let i = 0; i < 320; i += 1) step();
    draw();
    return;
  }
  if (!g.raf) g.raf = requestAnimationFrame(frame);
}

function frame() {
  const g = state.graph;
  if (!g) return;
  step();
  draw();
  if (g.alpha > 0.05 || g.drag) g.raf = requestAnimationFrame(frame);
  else g.raf = 0;
}

function stopGraph() {
  if (state.graph && state.graph.raf) cancelAnimationFrame(state.graph.raf);
  state.graph = null;
}

function resizeGraph() {
  const dpr = window.devicePixelRatio || 1;
  const w = canvas.clientWidth, h = canvas.clientHeight;
  if (!w || !h) return;
  canvas.width = Math.round(w * dpr);
  canvas.height = Math.round(h * dpr);
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  draw();
}

function nodeRadius(n) { return 5 + Math.min(7, Math.log1p(n.deg) * 2.6); }
function edgeColour(sign) {
  return sign > 0 ? PAINT.pos : (sign < 0 ? PAINT.neg : PAINT.neu);
}
function confAlpha(confidence) {
  if (confidence === 'HIGH') return 1;
  if (confidence === 'MODERATE') return 0.72;
  return 0.45;
}
function nodeColour(n) {
  return PAINT.hues[hueClass(n.ref.node_type).slice(4)] || PAINT.hues.context;
}

function draw() {
  const g = state.graph;
  const w = canvas.clientWidth, h = canvas.clientHeight;
  ctx.fillStyle = PAINT.void || '#080B12';
  ctx.fillRect(0, 0, w, h);
  if (!g) return;
  const sel = state.selection;

  for (const l of g.links) {
    const e = l.ref;
    if (e.is_inferred && !state.showInferred) continue;
    const on = sel && sel.kind === 'edge' && sel.id === e.id;
    ctx.globalAlpha = confAlpha(e.confidence);
    /* Invariant: solid = asserted, dashed = inferred. Never negotiable. */
    ctx.setLineDash(e.is_inferred ? [5, 4] : []);
    ctx.strokeStyle = on ? PAINT.accent : edgeColour(e.sign);
    ctx.lineWidth = (on ? 1.5 : 0) +
      1 + Math.min(4, Math.log1p(Math.max(0, Number(e.weight) || 0)) * 1.4);
    ctx.beginPath();
    ctx.moveTo(l.a.x, l.a.y);
    ctx.lineTo(l.b.x, l.b.y);
    ctx.stroke();
  }
  ctx.setLineDash([]);
  ctx.globalAlpha = 1;

  ctx.textAlign = 'center';
  ctx.textBaseline = 'top';
  ctx.font = PAINT.font;
  for (const n of g.nodes) {
    const r = nodeRadius(n);
    ctx.beginPath();
    ctx.arc(n.x, n.y, r, 0, Math.PI * 2);
    ctx.fillStyle = nodeColour(n);
    ctx.fill();
    if (sel && sel.kind === 'node' && sel.id === n.id) {
      ctx.beginPath();
      ctx.arc(n.x, n.y, r + 4, 0, Math.PI * 2);
      ctx.strokeStyle = PAINT.accent;
      ctx.lineWidth = 2;
      ctx.stroke();
    }
    /* Label sits clear of the dot so the two never overlap. */
    const label = n.ref.label.length > 24 ? n.ref.label.slice(0, 23) + '…'
                                          : n.ref.label;
    ctx.fillStyle = PAINT.label;
    ctx.fillText(label, n.x, n.y + r + 5);
  }
}

function canvasPoint(event) {
  const r = canvas.getBoundingClientRect();
  return { x: event.clientX - r.left, y: event.clientY - r.top };
}
function nodeAt(p) {
  const g = state.graph;
  if (!g) return null;
  let best = null, bestD = Infinity;
  for (const n of g.nodes) {
    const d = Math.hypot(n.x - p.x, n.y - p.y);
    const hit = nodeRadius(n) + 6;
    if (d < hit && d < bestD) { best = n; bestD = d; }
  }
  return best;
}
function edgeAt(p) {
  const g = state.graph;
  if (!g) return null;
  for (const l of g.links) {
    if (l.ref.is_inferred && !state.showInferred) continue;
    const dx = l.b.x - l.a.x, dy = l.b.y - l.a.y;
    const len2 = dx * dx + dy * dy;
    if (len2 === 0) continue;
    let t = ((p.x - l.a.x) * dx + (p.y - l.a.y) * dy) / len2;
    t = Math.max(0, Math.min(1, t));
    const d = Math.hypot(p.x - (l.a.x + t * dx), p.y - (l.a.y + t * dy));
    if (d < 6) return l.ref;
  }
  return null;
}

function initCanvas() {
  let moved = false, downAt = null;
  canvas.addEventListener('pointerdown', (e) => {
    const g = state.graph;
    if (!g) return;
    canvas.focus();
    const p = canvasPoint(e);
    downAt = p;
    moved = false;
    const n = nodeAt(p);
    if (n) {
      g.drag = n;
      /* Capture keeps the drag alive outside the canvas. Not every pointer
         type allows it, and losing it must not cost us the drag. */
      try { canvas.setPointerCapture(e.pointerId); } catch (_e) { /* optional */ }
      if (!reduceMotion && !g.raf) g.raf = requestAnimationFrame(frame);
    }
  });
  canvas.addEventListener('pointermove', (e) => {
    const g = state.graph;
    if (!g || !g.drag) return;
    const p = canvasPoint(e);
    if (downAt && Math.hypot(p.x - downAt.x, p.y - downAt.y) > 3) moved = true;
    g.drag.x = p.x; g.drag.y = p.y;
    g.drag.vx = 0; g.drag.vy = 0;
    g.alpha = Math.max(g.alpha, 0.35);
    if (reduceMotion) draw();
  });
  canvas.addEventListener('pointerup', (e) => {
    const g = state.graph;
    if (!g) return;
    const p = canvasPoint(e);
    if (g.drag) {
      g.drag = null;
      try { canvas.releasePointerCapture(e.pointerId); } catch (_e) { /* already gone */ }
    }
    if (moved) { draw(); return; }
    const n = nodeAt(p);
    if (n) { selectNode(n.id); return; }
    const edge = edgeAt(p);
    if (edge) { selectEdge(edge.id); return; }
    state.selection = null;
    renderInspector();
    draw();
  });
  canvas.addEventListener('keydown', (e) => {
    const g = state.graph;
    if (!g || !g.nodes.length) return;
    if (e.key === 'ArrowRight' || e.key === 'ArrowLeft') {
      e.preventDefault();
      const ids = g.nodes.map((n) => n.id);
      const cur = state.selection && state.selection.kind === 'node'
        ? ids.indexOf(state.selection.id) : -1;
      const delta = e.key === 'ArrowRight' ? 1 : -1;
      const next = (cur + delta + ids.length) % ids.length;
      selectNode(ids[next]);
    } else if (e.key === ' ' || e.key === 'Spacebar') {
      /* One key answers "what do I actually know?" */
      e.preventDefault();
      state.showInferred = !state.showInferred;
      $('chk-inferred').checked = state.showInferred;
      draw();
    } else if (e.key === 'Escape') {
      state.selection = null;
      renderInspector();
      draw();
    }
  });
  if ('ResizeObserver' in window) {
    new ResizeObserver(() => { if (state.tab === 'graph') resizeGraph(); })
      .observe(canvas.parentElement);
  } else {
    window.addEventListener('resize', resizeGraph);
  }
}

/* ── entities ─────────────────────────────────────────────────────────── */

function buildEntityFilter() {
  const present = Array.from(new Set(state.nodes.map((n) => n.node_type))).sort();
  const keep = $('ent-filter').value;
  opts($('ent-filter'),
    [['', 'All types']].concat(present.map((k) => [k, typeName(k) + ' (' + k + ')'])),
    keep);
}

function renderEntities() {
  const filter = $('ent-filter').value;
  const rows = filter ? state.nodes.filter((n) => n.node_type === filter)
                      : state.nodes;
  const body = $('ent-body');
  clear(body);
  for (const n of rows) {
    const tr = el('tr');
    tr.tabIndex = 0;
    tr.setAttribute('role', 'button');
    tr.setAttribute('aria-label', 'Inspect ' + n.label);
    if (state.selection && state.selection.kind === 'node'
        && state.selection.id === n.id) tr.classList.add('selected');
    const tdType = el('td');
    const wrap = el('span', 'dot-cell ' + hueClass(n.node_type));
    wrap.appendChild(el('i', 'swatch'));
    wrap.appendChild(el('span', null, typeName(n.node_type)));
    tdType.appendChild(wrap);
    tr.appendChild(tdType);
    tr.appendChild(el('td', null, n.label));
    const tdClass = el('td');
    tdClass.appendChild(tlpChip(n.classification));
    tr.appendChild(tdClass);
    tr.appendChild(el('td', 'num', n.first_seen ? fmtTime(n.first_seen) : '—'));
    tr.addEventListener('click', () => selectNode(n.id));
    tr.addEventListener('keydown', (e) => {
      if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); selectNode(n.id); }
    });
    body.appendChild(tr);
  }
  show($('ent-empty'), rows.length === 0);
  $('ent-count').textContent = rows.length + ' of ' + state.nodes.length +
    ' entities · ' + state.edges.length + ' relationships';
}

/* ── evidence ─────────────────────────────────────────────────────────── */

async function loadEvidence() {
  try {
    state.evidence = await api('/cases/' + state.caseId + '/evidence-list?limit=200');
    renderEvidence();
  } catch (err) { fail(err); }
}

function renderEvidence() {
  const list = $('ev-list');
  clear(list);
  for (const ev of state.evidence) {
    const item = el('div', 'ev-item');
    item.id = 'ev-' + ev.id;
    const top = el('div', 'ev-top');
    top.appendChild(el('span', 'ev-title', ev.title));
    top.appendChild(tlpChip(ev.classification));
    if (ev.is_worm_locked) {
      const worm = el('span', 'chip flag', 'WORM LOCKED');
      worm.title = 'Write-once storage: the object cannot be replaced or deleted.';
      top.appendChild(worm);
    }
    item.appendChild(top);

    const meta = el('div', 'ev-meta');
    meta.appendChild(el('span', null, ev.media_type));
    meta.appendChild(el('span', null, fmtBytes(ev.byte_size)));
    meta.appendChild(el('span', null, ev.acquisition_method));
    meta.appendChild(el('span', null, 'acquired ' + fmtTime(ev.acquired_at)));
    item.appendChild(meta);

    const hash = el('div', 'ev-hash', 'sha256 ' + shortHash(ev.sha256));
    hash.title = ev.sha256 || '';
    item.appendChild(hash);

    /* No in-page render or download control here: exhibit bytes are only ever
       served as an encrypted archive from a separate origin (invariant 10). */
    const actions = el('div', 'ev-actions');
    const verdict = el('span', 'ev-verdict');
    const bVerify = el('button', 'btn small', 'Verify');
    bVerify.type = 'button';
    bVerify.setAttribute('aria-label', 'Verify stored digest of ' + ev.title);
    const bCustody = el('button', 'btn small', 'Custody');
    bCustody.type = 'button';
    bCustody.setAttribute('aria-label', 'Show chain of custody for ' + ev.title);
    actions.append(bVerify, bCustody, verdict);
    item.appendChild(actions);
    const custodyBox = el('div', 'custody');
    custodyBox.hidden = true;
    item.appendChild(custodyBox);

    bVerify.addEventListener('click', async () => {
      bVerify.disabled = true;
      verdict.className = 'ev-verdict';
      verdict.textContent = 'Verifying…';
      try {
        const out = await api('/cases/' + state.caseId + '/evidence/' + ev.id +
                              '/verify', { method: 'POST' });
        verdict.className = 'ev-verdict ' + (out.ok ? 'ok' : 'fail');
        verdict.textContent = out.ok
          ? 'Digest matches the record.'
          : 'HASH MISMATCH — stored bytes do not match the recorded digest.';
      } catch (err) {
        verdict.className = 'ev-verdict fail';
        verdict.textContent = 'Verification could not be completed.';
        fail(err);
      } finally { bVerify.disabled = false; }
    });

    bCustody.addEventListener('click', async () => {
      if (!custodyBox.hidden) { custodyBox.hidden = true; return; }
      clear(custodyBox);
      custodyBox.hidden = false;
      custodyBox.appendChild(el('p', 'help', 'Loading custody log…'));
      try {
        const log = await api('/cases/' + state.caseId + '/evidence/' + ev.id +
                              '/custody');
        clear(custodyBox);
        if (!log.length) {
          custodyBox.appendChild(el('p', 'empty', 'No custody entries recorded.'));
        }
        for (const c of log) {
          const row = el('div', 'custody-row');
          row.appendChild(el('span', null, c.action));
          row.appendChild(el('span', 'when', fmtTime(c.occurred_at)));
          row.appendChild(el('span', 'mono small', 'actor ' + shortId(c.actor_id)));
          const flag = el('span', 'chip ' + (c.hash_verified ? 'flag' : 'stale'),
            c.hash_verified ? 'hash verified' : 'hash not checked');
          row.appendChild(flag);
          custodyBox.appendChild(row);
        }
      } catch (err) {
        clear(custodyBox);
        custodyBox.appendChild(el('p', 'form-error', 'Custody log unavailable.'));
        fail(err);
      }
    });
    list.appendChild(item);
  }
  show($('ev-empty'), state.evidence.length === 0);
}

async function uploadEvidence(event) {
  event.preventDefault();
  const errBox = $('ev-error'), okBox = $('ev-result');
  setMsg(errBox, ''); setMsg(okBox, '');
  const file = $('ev-file').files[0];
  const title = $('ev-title').value.trim();
  if (!file) { setMsg(errBox, 'Choose a file to lodge as an exhibit.'); return; }
  if (!title) { setMsg(errBox, 'An exhibit needs a title.'); return; }
  const form = new FormData();
  form.append('file', file);
  form.append('title', title);
  form.append('acquisition_method', $('ev-method').value);
  form.append('classification', $('ev-class').value);
  try {
    const out = await api('/cases/' + state.caseId + '/evidence',
      { method: 'POST', form: form });
    setMsg(okBox, 'Lodged. sha256 ' + out.sha256 +
      (out.deduplicated ? ' — identical bytes were already held; the existing exhibit was reused.' : ''));
    $('ev-file').value = '';
    $('ev-title').value = '';
    await loadEvidence();
  } catch (err) {
    inlineProblem(errBox, err);
  }
}

/* ── search ───────────────────────────────────────────────────────────── */

async function runSearch(event) {
  event.preventDefault();
  const q = $('search-q').value.trim();
  if (!q) return;
  const enc = encodeURIComponent(q);
  const nodeBox = $('search-nodes'), evBox = $('search-evidence');
  clear(nodeBox); clear(evBox);
  nodeBox.appendChild(el('p', 'help', 'Searching…'));
  evBox.appendChild(el('p', 'help', 'Searching…'));
  try {
    const [nodeHits, evHits] = await Promise.all([
      api('/cases/' + state.caseId + '/search/nodes?limit=50&q=' + enc),
      api('/cases/' + state.caseId + '/search/evidence?q=' + enc),
    ]);
    renderHits(nodeBox, nodeHits, (hit) => selectNode(hit.id));
    renderHits(evBox, evHits, (hit) => focusEvidence(hit.id));
  } catch (err) {
    clear(nodeBox); clear(evBox);
    fail(err);
  }
}

function renderHits(box, hits, onPick) {
  clear(box);
  if (!hits.length) { box.appendChild(el('p', 'empty', 'No matches.')); return; }
  for (const hit of hits) {
    const b = el('button', 'hit');
    b.type = 'button';
    b.appendChild(el('span', null, hit.label));
    const rank = Number(hit.rank);
    b.appendChild(el('span', 'rank', Number.isFinite(rank) ? rank.toFixed(3) : ''));
    b.addEventListener('click', () => onPick(hit));
    box.appendChild(b);
  }
}

function focusEvidence(evidenceId) {
  selectTab('evidence');
  const item = $('ev-' + evidenceId);
  if (item) {
    for (const other of document.querySelectorAll('.ev-item.focused')) {
      other.classList.remove('focused');
    }
    item.classList.add('focused');
    item.scrollIntoView({ block: 'center' });
  } else {
    banner('Exhibit not in the loaded list',
      'It may be outside the current page of results. Reload the evidence tab.',
      'warn');
  }
}

/* ── inspector: "why do we believe this?" ─────────────────────────────── */

function selectNode(id) {
  state.selection = { kind: 'node', id: id };
  renderEntities();
  renderInspector();
  draw();
}
function selectEdge(id) {
  state.selection = { kind: 'edge', id: id };
  renderInspector();
  draw();
}

function renderInspector() {
  const sel = state.selection;
  show($('insp-empty'), !sel);
  show($('insp-body'), !!sel);
  if (!sel) return;
  const typeChip = $('insp-type');
  const classChip = $('insp-class');
  const sub = $('insp-sub');

  if (sel.kind === 'node') {
    const n = state.nodes.find((x) => x.id === sel.id);
    if (!n) { loadMissingNode(sel.id); return; }
    typeChip.className = 'chip type-chip ' + hueClass(n.node_type);
    typeChip.textContent = typeName(n.node_type);
    classChip.className = 'chip tlp-' + n.classification;
    classChip.textContent = 'TLP:' + n.classification;
    $('insp-label').textContent = n.label;
    sub.textContent = n.id + ' · first seen ' + fmtTime(n.first_seen) +
      ' · last seen ' + fmtTime(n.last_seen);
    show($('insp-sel-sec'), true);
  } else {
    const e = state.edges.find((x) => x.id === sel.id);
    if (!e) { state.selection = null; renderInspector(); return; }
    typeChip.className = 'chip type-chip';
    typeChip.textContent = e.edge_type;
    classChip.className = 'chip tlp-' + e.classification;
    classChip.textContent = 'TLP:' + e.classification;
    clear($('insp-label'));
    $('insp-label').textContent = e.src_label + ' → ' + e.dst_label;
    const signWord = e.sign > 0 ? 'positive tie'
      : (e.sign < 0 ? 'negative tie' : 'neutral tie');
    sub.textContent = signWord + ' · weight ' + e.weight +
      ' · ' + (e.is_inferred ? 'INFERRED (dashed, excluded from metrics)'
                            : 'asserted') +
      ' · review ' + e.review + ' · from ' + fmtTime(e.valid_from);
    show($('insp-sel-sec'), false);
  }

  const seq = ++state.inspSeq;
  const base = '/cases/' + state.caseId +
    (sel.kind === 'node' ? '/nodes/' : '/edges/') + sel.id;
  loadInto($('insp-assertions'), seq,
    () => api(base + '/assertions?include_retracted=' +
              (state.includeRetracted ? 'true' : 'false')),
    renderAssertions);
  loadInto($('insp-evidence'), seq, () => api(base + '/evidence'),
    renderLinkedEvidence);
  if (sel.kind === 'node') {
    loadInto($('insp-selectors'), seq, () => api(base + '/selectors'),
      renderSelectors);
  }
}

async function loadMissingNode(id) {
  try {
    const n = await api('/cases/' + state.caseId + '/nodes/' + id);
    state.nodes.push(n);
    buildEntityFilter();
    renderEntities();
    renderInspector();
  } catch (err) {
    state.selection = null;
    renderInspector();
    fail(err);
  }
}

async function loadInto(box, seq, fetcher, render) {
  clear(box);
  box.appendChild(el('p', 'help', 'Loading…'));
  try {
    const data = await fetcher();
    if (seq !== state.inspSeq) return;          // a newer selection won
    clear(box);
    render(box, data);
  } catch (err) {
    if (seq !== state.inspSeq) return;
    clear(box);
    box.appendChild(el('p', 'form-error', 'Could not load this section.'));
    fail(err);
  }
}

function renderAssertions(box, list) {
  if (!list.length) {
    box.appendChild(el('p', 'empty',
      'No live assertions. Nothing here is a fact without one.'));
    return;
  }
  for (const a of list) {
    const dead = a.retracted_at || a.superseded_at;
    const card = el('div', 'assert' + (dead ? ' dead' : ''));
    const top = el('div', 'assert-top');
    const basisLabel = (BASES.find((b) => b[0] === a.basis) || [null, a.basis])[1];
    top.appendChild(el('span', 'assert-basis', basisLabel));

    const grade = el('span', 'grading', String(a.reliability) + String(a.credibility));
    grade.title = 'Admiralty grading — ' + a.reliability + ': ' +
      (RELIABILITY[a.reliability] || 'unknown reliability') + ' · ' +
      a.credibility + ': ' + (CREDIBILITY[String(a.credibility)] ||
      'unknown credibility');
    top.appendChild(grade);

    const conf = el('span', 'conf conf-' + a.confidence, a.confidence + ' confidence');
    conf.title = 'ICD 203 analytic confidence';
    top.appendChild(conf);

    if (a.retracted_at) top.appendChild(el('span', 'chip bad', 'RETRACTED'));
    if (a.superseded_at) top.appendChild(el('span', 'chip stale', 'SUPERSEDED'));
    card.appendChild(top);

    const rationale = el('div',
      'assert-rationale' + (a.rationale ? '' : ' none'),
      a.rationale || 'No rationale recorded.');
    card.appendChild(rationale);

    const bits = ['recorded ' + fmtTime(a.recorded_at)];
    if (a.observed_at) bits.push('observed ' + fmtTime(a.observed_at));
    bits.push('by ' + shortId(a.created_by));
    if (a.evidence_id) bits.push('exhibit ' + shortId(a.evidence_id));
    if (a.external_ref) bits.push('ref ' + a.external_ref);
    if (a.retracted_at) bits.push('retracted ' + fmtTime(a.retracted_at));
    if (a.superseded_at) bits.push('superseded ' + fmtTime(a.superseded_at));
    card.appendChild(el('div', 'assert-meta', bits.join(' · ')));
    box.appendChild(card);
  }
}

function renderLinkedEvidence(box, list) {
  if (!list.length) {
    box.appendChild(el('p', 'empty', 'No exhibits linked.'));
    return;
  }
  for (const ev of list) {
    const item = el('div', 'sel-item');
    const top = el('div', 'ev-top');
    top.appendChild(el('span', 'ev-title', ev.title));
    top.appendChild(tlpChip(ev.classification));
    if (ev.is_worm_locked) top.appendChild(el('span', 'chip flag', 'WORM'));
    item.appendChild(top);
    const hash = el('div', 'sel-val', 'sha256 ' + shortHash(ev.sha256));
    hash.title = ev.sha256 || '';
    item.appendChild(hash);
    item.appendChild(el('div', 'ev-meta',
      ev.media_type + ' · ' + fmtBytes(ev.byte_size)));
    const jump = el('button', 'btn small', 'Show in evidence');
    jump.type = 'button';
    jump.addEventListener('click', () => focusEvidence(ev.id));
    item.appendChild(jump);
    box.appendChild(item);
  }
}

function renderSelectors(box, list) {
  if (!list.length) {
    box.appendChild(el('p', 'empty', 'No selectors observed.'));
    return;
  }
  for (const s of list) {
    const item = el('div', 'sel-item');
    item.appendChild(el('div', 'label', s.selector_type));
    item.appendChild(el('div', 'sel-val', s.raw_value));
    if (s.norm_value && s.norm_value !== s.raw_value) {
      item.appendChild(el('div', 'mono small muted', 'normalised ' + s.norm_value));
    }
    item.appendChild(el('div', 'ev-meta',
      'observed ' + s.observation_cnt + ' time(s)'));
    box.appendChild(item);
  }
}

/* ── create forms ─────────────────────────────────────────────────────── */

function buildPickers() {
  const tlpPairs = TLP.map((t) => [t, t]);
  for (const id of ['case-class', 'node-class', 'edge-class', 'ev-class']) {
    opts($(id), tlpPairs, 'AMBER');
  }
  opts($('node-type'),
    state.ontology.node_types.map((t) => [t.key, t.display_name + ' (' + t.key + ')']));
  for (const id of ['node-basis', 'edge-basis']) {
    opts($(id), BASES, 'DIRECT_OBSERVATION');
  }
  for (const id of ['node-conf', 'edge-conf']) {
    opts($(id), CONFIDENCE.map((c) => [c, c]), 'MODERATE');
  }
  for (const id of ['node-rel', 'edge-rel']) {
    opts($(id), Object.keys(RELIABILITY).map((k) => [k, k + ' — ' + RELIABILITY[k]]), 'C');
  }
  for (const id of ['node-cred', 'edge-cred']) {
    opts($(id), Object.keys(CREDIBILITY).map((k) => [k, k + ' — ' + CREDIBILITY[k]]), '3');
  }
}

function buildEdgePickers() {
  const pairs = state.nodes.map(
    (n) => [n.id, n.label + '  [' + n.node_type + ']']);
  const srcSel = $('edge-src'), dstSel = $('edge-dst');
  const keepSrc = srcSel.value, keepDst = dstSel.value;
  opts(srcSel, pairs, keepSrc);
  opts(dstSel, pairs, keepDst);
  refreshEdgeTypes();
}

/** Offer only edge types the ontology permits for the chosen endpoints. */
function refreshEdgeTypes() {
  const note = $('edge-type-note');
  const src = state.nodes.find((n) => n.id === $('edge-src').value);
  const dst = state.nodes.find((n) => n.id === $('edge-dst').value);
  const sel = $('edge-type');
  if (!src || !dst) {
    opts(sel, []);
    note.textContent = 'Choose a source and a target entity first.';
    return;
  }
  const legal = state.ontology.edge_types.filter((t) =>
    (!t.src.length || t.src.includes(src.node_type)) &&
    (!t.dst.length || t.dst.includes(dst.node_type)));
  opts(sel, legal.map((t) => [t.key, t.display_name + ' (' + t.key + ')']));
  if (!legal.length) {
    note.textContent = 'No relationship type in the ontology connects ' +
      src.node_type + ' to ' + dst.node_type + '. Reverse the direction, or ' +
      'model it through an intermediate entity.';
  } else {
    const first = legal[0];
    note.textContent = legal.length + ' permitted for ' + src.node_type +
      ' → ' + dst.node_type + '. Default sign ' + first.default_sign +
      (first.is_social_tie ? ', counts as a social tie.' : '.');
  }
}

function assertionFrom(prefix) {
  const basis = $(prefix + '-basis').value;
  const rationale = $(prefix + '-rationale').value.trim();
  return {
    basis: basis,
    reliability: $(prefix + '-rel').value,
    credibility: $(prefix + '-cred').value,
    confidence: $(prefix + '-conf').value,
    rationale: rationale || null,
  };
}

function rationaleProblem(assertion) {
  if (INFERENCE_BASES.includes(assertion.basis) && !assertion.rationale) {
    return 'An inference must state its reasoning. Give a rationale, or choose ' +
      'a basis that reflects an observation or report.';
  }
  return null;
}

function syncRationaleHint(prefix) {
  const needed = INFERENCE_BASES.includes($(prefix + '-basis').value);
  show($(prefix + '-rat-req'), needed);
}

async function createNode(event) {
  event.preventDefault();
  const errBox = $('node-error'), okBox = $('node-ok');
  setMsg(errBox, ''); setMsg(okBox, '');
  const label = $('node-label').value.trim();
  if (!label) { setMsg(errBox, 'An entity needs a label.'); return; }
  const assertion = assertionFrom('node');
  const problem = rationaleProblem(assertion);
  if (problem) { setMsg(errBox, problem); return; }
  try {
    const out = await api('/cases/' + state.caseId + '/nodes', {
      method: 'POST',
      json: {
        node_type: $('node-type').value,
        label: label,
        classification: $('node-class').value,
        attrs: {},
        assertion: assertion,
      },
    });
    setMsg(okBox, 'Created with its founding assertion. Opening it in the inspector.');
    $('node-label').value = '';
    $('node-rationale').value = '';
    await loadGraph();
    selectNode(out.id);
    selectTab('graph');
  } catch (err) {
    inlineProblem(errBox, err);
  }
}

async function createEdge(event) {
  event.preventDefault();
  const errBox = $('edge-error'), okBox = $('edge-ok');
  setMsg(errBox, ''); setMsg(okBox, '');
  const src = $('edge-src').value, dst = $('edge-dst').value;
  const edgeType = $('edge-type').value;
  if (!src || !dst) { setMsg(errBox, 'Choose both endpoints.'); return; }
  if (src === dst) { setMsg(errBox, 'An entity cannot relate to itself.'); return; }
  if (!edgeType) {
    setMsg(errBox, 'No relationship type is permitted between these two types.');
    return;
  }
  const assertion = assertionFrom('edge');
  const problem = rationaleProblem(assertion);
  if (problem) { setMsg(errBox, problem); return; }
  try {
    const out = await api('/cases/' + state.caseId + '/edges', {
      method: 'POST',
      json: {
        edge_type: edgeType,
        src_node_id: src,
        dst_node_id: dst,
        classification: $('edge-class').value,
        assertion: assertion,
      },
    });
    setMsg(okBox, 'Relationship recorded with its assertion.');
    $('edge-rationale').value = '';
    await loadGraph();
    selectEdge(out.id);
    selectTab('graph');
  } catch (err) {
    inlineProblem(errBox, err);
  }
}

/* ── boot ─────────────────────────────────────────────────────────────── */

function wire() {
  loadPaint();
  initTabs();
  initCanvas();
  opts($('case-class'), TLP.map((t) => [t, t]), 'AMBER');
  opts($('ev-class'), TLP.map((t) => [t, t]), 'AMBER');

  $('login-form').addEventListener('submit', doLogin);
  $('btn-logout').addEventListener('click', doLogout);
  $('btn-cases').addEventListener('click', showCaseList);
  $('case-form').addEventListener('submit', createCase);
  $('ent-filter').addEventListener('change', renderEntities);
  $('ev-form').addEventListener('submit', uploadEvidence);
  $('search-form').addEventListener('submit', runSearch);
  $('node-form').addEventListener('submit', createNode);
  $('edge-form').addEventListener('submit', createEdge);
  $('node-basis').addEventListener('change', () => syncRationaleHint('node'));
  $('edge-basis').addEventListener('change', () => syncRationaleHint('edge'));
  $('edge-src').addEventListener('change', refreshEdgeTypes);
  $('edge-dst').addEventListener('change', refreshEdgeTypes);
  $('btn-relayout').addEventListener('click', settle);
  $('btn-refresh').addEventListener('click', () => { loadGraph(); loadEvidence(); });
  $('chk-inferred').addEventListener('change', (e) => {
    state.showInferred = e.target.checked;
    draw();
  });
  $('chk-retracted').addEventListener('change', (e) => {
    state.includeRetracted = e.target.checked;
    renderInspector();
  });
}

async function boot() {
  wire();
  if (state.token) {
    try {
      await startApp();
      state.booting = false;
      return;
    } catch (_err) {
      /* A stale token is not an error worth a banner: just ask again. */
      state.token = null;
      sessionStorage.removeItem(TOKEN_KEY);
    }
  }
  state.booting = false;
  show($('view-app'), false);
  show($('view-login'), true);
  $('login-email').focus();
}

boot();
