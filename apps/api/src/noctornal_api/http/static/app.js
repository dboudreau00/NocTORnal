/* NocTORnal analyst console — Phase 2 sociogram.
 *
 * No framework, no build step, no CDN — the app shell is served under a strict
 * `default-src 'self'` CSP, so everything lives in these three files and there
 * is no inline script or style anywhere. Nothing is ever written to
 * `element.style` either: hue and state travel as classes, and everything that
 * needs pixel control (the sociogram, the timeline density strip) is drawn on a
 * <canvas>.
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
 *
 * SHAPE OF THE GRAPH LAYER (docs/03). Nothing is measured against "the graph";
 * everything is measured against a PROJECTION — a named, parameterised view.
 * The projection's parameters are on screen next to the canvas at all times,
 * because a metric without its parameters is not reproducible and therefore
 * not evidence.
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
const CONF_RANK = { LOW: 0, MODERATE: 1, HIGH: 2 };

/* The four metrics /graph/metrics actually returns. Nothing else is offered:
   betweenness, Burt's constraint and key-player fragmentation are Phase 3 and
   inventing a control for them would be inventing the number. */
const SIZE_METRICS = [
  ['degree', 'Degree — activity, visibility'],
  ['weighted_degree', 'Weighted degree — total tie strength'],
  ['k_core', 'k-core — depth in the durable core'],
  ['clustering', 'Clustering — how closed the neighbourhood is'],
];
const METRIC_LABEL = new Map(SIZE_METRICS);

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

const NODE_PAGE = 800;      // sociogram page size; beyond this, filter first

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
  nodes: [],                 // whole case, unprojected (entity list, pickers)
  edges: [],                 // whole case, unprojected
  evidence: [],
  selection: null,           // {kind:'node'|'edge', id}
  includeRetracted: false,
  inspSeq: 0,
  booting: true,

  /* projection */
  presets: [],
  presetMap: new Map(),
  proj: { preset: 'all', include_inferred: true, min_confidence: 'LOW',
          as_of: null },
  projMeta: null,            // the `projection` object the API echoed back
  projTruncated: false,
  withheld: null,
  gnodes: [],                // projection nodes
  gedges: [],                // projection edges
  nodeConf: new Map(),       // node id -> best confidence of its ties
  nodeTies: new Map(),       // node id -> tie count in the projection
  nodeProposed: new Map(),   // node id -> count of PROPOSED-review ties
  graphSeq: 0,

  /* triage (Phase 4): machine suggestions awaiting a human. */
  triage: [],
  triageCounts: {},
  triageIndex: 0,

  layoutWorker: null,        // ForceAtlas2 off the main thread (U1)
  layoutPaint: 0,            // pending rAF, so repaints coalesce

  /* E2: mark the elements that rest on no exhibit. On by default -- an
     unevidenced case SHOULD look unfinished until it is evidenced. */
  showProvenance: true,

  /* analysis (Phase 3): global structural metrics, computed on demand
     because they are a batch operation, not a live one. Held per case AND
     per projection -- changing either invalidates them. */
  analytics: null,
  analyticsKpp: null,

  /* metrics */
  metrics: null,
  metricById: new Map(),
  ranks: null,               // metric key -> Map(node id -> rank)
  rankTotal: 0,
  metricsNote: '',
  metricsWarned: false,
  sizeMetric: 'degree',

  /* focus mode */
  focus: null,               // {kind:'ego', id, depth} | {kind:'path', ...}
  pathAnchor: null,
  pathIds: null,
  hoverId: null,
  hideInferredHold: false,

  /* canvas. tx/ty start NaN so "never positioned" is distinguishable from
     "panned to exactly the origin". */
  graph: null,               // the simulation: {nodes, links, index, ...}
  view: { scale: 1, tx: NaN, ty: NaN },
  viewport: null,            // last canvas size + dpr, to recentre on resize
  canvasObserver: null,      // retained: an anonymous one can be collected
  needFit: true,
  layout: new Map(),         // node id -> {x, y, is_pinned}

  /* timeline */
  timeSpan: null,            // {min, max} in ms
  timePoints: [],            // element arrival times, for the density strip

  /* palette */
  paletteOpen: false,
  paletteItems: [],
  paletteIndex: 0,
  paletteReturn: null,
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
/** Trailing debounce. Used for the comms normalise preview: one request
 *  per pause in typing, not one per keystroke. */
function debounce(fn, ms) {
  let timer = null;
  return function debounced(...args) {
    if (timer) clearTimeout(timer);
    timer = setTimeout(() => { timer = null; fn.apply(this, args); }, ms);
  };
}
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
function clamp(v, lo, hi) { return v < lo ? lo : (v > hi ? hi : v); }

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
  return el('span', 'chip tlp-' + value, value);
}
function fmtTime(iso) {
  if (!iso) return '—';
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? String(iso) : d.toLocaleString();
}
function fmtDay(ms) {
  const d = new Date(ms);
  if (Number.isNaN(d.getTime())) return '—';
  return d.toLocaleDateString(undefined,
    { year: 'numeric', month: 'short', day: '2-digit' });
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
function num(v, dp) {
  const n = Number(v);
  if (!Number.isFinite(n)) return '—';
  return dp === undefined ? String(n) : n.toFixed(dp);
}
function ordinal(n) {
  const s = ['th', 'st', 'nd', 'rd'];
  const v = n % 100;
  return n + (s[(v - 20) % 10] || s[v] || s[0]);
}

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

/** Case-scoped path helper — every Phase 2 endpoint hangs off the case. */
function cpath(suffix) { return '/cases/' + state.caseId + suffix; }

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
  closePalette();
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
  show($('hdr-asof'), false);
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
  state.focus = null;
  state.pathAnchor = null;
  state.pathIds = null;
  state.hoverId = null;
  state.needFit = true;
  state.metricsWarned = false;
  state.proj.as_of = null;
  state.layout = new Map();
  state.gnodes = [];
  state.gedges = [];
  state.projMeta = null;
  state.view = { scale: 1, tx: NaN, ty: NaN };
  // A new case re-centres from scratch, so the previous case's
  // canvas size must not contribute a resize delta.
  state.viewport = null;
  /* Analysis is per-case and per-projection; carrying another case's
     numbers into this one would be worse than showing none. */
  state.analytics = null;
  state.analyticsKpp = null;
  state.triage = [];
  state.triageCounts = {};
  state.triageIndex = 0;
  stopWorkerLayout();
  applyMetrics(null);
  try {
    const [rec, ontology] = await Promise.all([
      api('/cases/' + caseId),
      api('/cases/' + caseId + '/ontology'),
    ]);
    state.caseRec = rec;
    state.ontology = ontology;
    state.nodeTypeMeta = new Map(ontology.node_types.map((t) => [t.key, t]));
    $('hdr-case').textContent = rec.code + ' — ' + rec.title;
    const tlp = $('hdr-tlp');
    tlp.className = 'chip tlp-' + rec.classification;
    tlp.textContent = 'TLP:' + rec.classification;
    show(tlp, true);
    show($('btn-cases'), true);
    show($('hdr-asof'), true);
    show($('view-cases'), false);
    show($('view-workspace'), true);
    buildPickers();
    renderInspector();
    /* Presets and the saved layout must land before the first projection
       fetch: the layout seeds node positions, and re-seeding after the fact
       would visibly reshuffle a picture the analyst already knows. */
    await Promise.all([loadPresets(), loadLayout()]);
    buildProjectionControls();
    renderProjectionBar();     // the parameters are on screen before the data
    await loadCaseGraph();
    await refreshSociogram();
    await loadEvidence();
    // The badge is the only signal that work is waiting, so the
    // queue is counted on open rather than on first visit.
    await loadTriage();
    await refreshInboxBadge();
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
  if (name === 'graph') { resizeGraph(); resizeDensity(); }
  if (name === 'triage') loadTriage();
  /* Platforms are reference data: fetched once, on first use, so the
     workspace does not pay for a tab nobody opened. */
  if (name === 'comms') loadCommsPlatforms().catch(fail);
  if (name === 'inbox') { loadInbox(); loadInboxPreferences(); }
}

function initTabs() {
  const tabs = Array.from(document.querySelectorAll('.tab'));
  tabs.forEach((tab, i) => {
    tab.addEventListener('click', () => selectTab(tab.dataset.tab));
    tab.addEventListener('keydown', (e) => {
      let next = null;
      /* The rail is a vertical tablist, so Up/Down are the primary keys —
         Left/Right stay wired because muscle memory from the old tab strip
         is real and costs nothing to honour. */
      if (e.key === 'ArrowDown' || e.key === 'ArrowRight') {
        next = tabs[(i + 1) % tabs.length];
      } else if (e.key === 'ArrowUp' || e.key === 'ArrowLeft') {
        next = tabs[(i - 1 + tabs.length) % tabs.length];
      } else if (e.key === 'Home') next = tabs[0];
      else if (e.key === 'End') next = tabs[tabs.length - 1];
      if (next) { e.preventDefault(); selectTab(next.dataset.tab); next.focus(); }
    });
  });
}

/* ── whole-case lists (entity table, pickers, timeline span) ───────────
 * These stay UNPROJECTED on purpose. The sociogram shows a projection; the
 * entity list is the case file, and an analyst looking for something must not
 * have it hidden by a filter chosen for the graph. They also give the timeline
 * a span that does not shrink as `as_of` moves. */

async function loadCaseGraph() {
  try {
    const [nodes, edges] = await Promise.all([
      api(cpath('/nodes?limit=1000')),
      api(cpath('/edges?limit=1000&include_inferred=true')),
    ]);
    state.nodes = nodes;
    state.edges = edges;
    buildEntityFilter();
    renderEntities();
    buildEdgePickers();
    computeTimeSpan();
    renderScrubber(true);
  } catch (err) { fail(err); }
}

/** Reload everything a write could have changed. */
async function reloadAll() {
  await loadCaseGraph();
  await refreshSociogram();
}

/* ── projection: the only thing a metric is ever computed against ─────── */

async function loadPresets() {
  try {
    const out = await api(cpath('/graph/presets'));
    state.presets = out.presets || [];
  } catch (err) {
    /* Without presets the projection selector cannot be honest about what it
       is filtering, so fall back to the one preset whose meaning is not in
       doubt and say so. */
    state.presets = [{ key: 'all', label: 'All ties',
                       description: 'Preset list unavailable — this is the ' +
                                    'server default.', edge_types: null }];
    fail(err);
  }
  state.presetMap = new Map(state.presets.map((p) => [p.key, p]));
  if (!state.presetMap.has(state.proj.preset)) {
    state.proj.preset = state.presets.length ? state.presets[0].key : 'all';
  }
}

function buildProjectionControls() {
  opts($('sel-preset'), state.presets.map((p) => [p.key, p.label]),
       state.proj.preset);
  opts($('sel-minconf'), [
    ['LOW', 'LOW — everything'],
    ['MODERATE', 'MODERATE and above'],
    ['HIGH', 'HIGH only'],
  ], state.proj.min_confidence);
  opts($('sel-metric'), SIZE_METRICS, state.sizeMetric);
  $('chk-inferred').checked = state.proj.include_inferred;
}

function projQuery() {
  const q = new URLSearchParams();
  q.set('preset', state.proj.preset);
  q.set('include_inferred', state.proj.include_inferred ? 'true' : 'false');
  q.set('min_confidence', state.proj.min_confidence);
  if (state.proj.as_of) q.set('as_of', state.proj.as_of);
  return q;
}

/** One fetch path for the sociogram. Sequence-guarded, because a scrubber drag
 *  can start three of these before the first returns and the newest must win. */
async function refreshSociogram() {
  if (!state.caseId) return;
  const seq = ++state.graphSeq;
  const q = projQuery();
  const gq = new URLSearchParams(q);
  gq.set('limit', String(NODE_PAGE));
  let g;
  try {
    g = await api(cpath('/graph?' + gq.toString()));
  } catch (err) { fail(err); return; }
  if (seq !== state.graphSeq) return;

  state.gnodes = g.nodes || [];
  state.gedges = g.edges || [];
  state.projMeta = g.projection || null;
  state.projTruncated = !!g.truncated;
  state.withheld = g.withheld || null;
  indexProjection();

  await refreshMetrics(seq, q);
  if (seq !== state.graphSeq) return;

  await reapplyFocus(seq, q);
  if (seq !== state.graphSeq) return;

  renderProjectionBar();
  renderInspector();
}

/** Per-node facts the projection implies but does not carry as columns. */
function indexProjection() {
  const conf = new Map(), ties = new Map(), proposed = new Map();
  for (const e of state.gedges) {
    for (const id of [e.src_node_id, e.dst_node_id]) {
      ties.set(id, (ties.get(id) || 0) + 1);
      const cur = conf.get(id);
      const rank = CONF_RANK[e.confidence];
      if (rank !== undefined &&
          (cur === undefined || rank > CONF_RANK[cur])) conf.set(id, e.confidence);
      /* Invariant 3: machines propose, analysts dispose. A PROPOSED review on
         an incident tie is the analyst's cue that something is waiting. */
      if (e.review === 'PROPOSED') proposed.set(id, (proposed.get(id) || 0) + 1);
    }
  }
  state.nodeConf = conf;
  state.nodeTies = ties;
  state.nodeProposed = proposed;
}

async function refreshMetrics(seq, q) {
  try {
    const m = await api(cpath('/graph/metrics?' + q.toString()));
    if (seq !== state.graphSeq) return;
    applyMetrics(m);
    state.metricsNote = 'size = ' + (METRIC_LABEL.get(state.sizeMetric) || state.sizeMetric);
    $('sel-metric').disabled = false;
  } catch (err) {
    if (seq !== state.graphSeq) return;
    applyMetrics(null);
    $('sel-metric').disabled = true;
    const why = err instanceof ApiError && err.status === 403
      ? 'the analytics.run scope is not on your token'
      : (err instanceof ApiError ? err.title : 'the request failed');
    state.metricsNote = 'metrics unavailable (' + why + ') — nodes are sized by ' +
      'the degree counted from the edges on screen, which is not the same ' +
      'number as the projection metric';
    /* Surfaced once. A scrubber drag fires this on every step and a wall of
       identical banners would bury the rest of the stack. */
    if (!state.metricsWarned) {
      state.metricsWarned = true;
      fail(err);
    }
  }
}

function applyMetrics(m) {
  state.metrics = m;
  state.metricById = new Map();
  state.ranks = null;
  state.rankTotal = 0;
  if (!m || !Array.isArray(m.nodes)) return;
  for (const row of m.nodes) state.metricById.set(row.id, row);
  const r = computeRanks(m.nodes);
  state.ranks = r.ranks;
  state.rankTotal = r.total;
}

/** docs/03: "Always show rank and percentile alongside raw value." A raw
 *  clustering of 0.4142 means nothing; "12th of 214" does. Ties share a rank. */
function computeRanks(list) {
  const ranks = {};
  for (const [key] of SIZE_METRICS) {
    const sorted = list.slice()
      .sort((a, b) => (Number(b[key]) || 0) - (Number(a[key]) || 0));
    const map = new Map();
    let rank = 0, prev = null;
    sorted.forEach((row, i) => {
      const v = Number(row[key]) || 0;
      if (prev === null || v !== prev) { rank = i + 1; prev = v; }
      map.set(row.id, rank);
    });
    ranks[key] = map;
  }
  return { ranks: ranks, total: list.length };
}

/** The analysis panel restates the projection it was computed under, so
 *  leaving its numbers on screen after the projection moves would caption
 *  one graph's metrics with another graph's parameters. Blank them and say
 *  why (docs/03: the projection parameters travel with the result). */
function invalidateAnalytics() {
  if (!state.analytics) return;
  state.analytics = null;
  state.analyticsKpp = null;
  show($('an-results'), false);
  show($('an-empty'), true);
  $('an-empty').textContent =
    'The projection changed. Run the analysis again to recompute against it.';
  setMsg($('an-status'), '');
}

function setPreset(key) {
  if (!state.presetMap.has(key) || key === state.proj.preset) return;
  state.proj.preset = key;
  $('sel-preset').value = key;
  invalidateAnalytics();
  refreshSociogram();
}
function setMinConfidence(value) {
  if (!CONF_RANK.hasOwnProperty(value) || value === state.proj.min_confidence) return;
  state.proj.min_confidence = value;
  $('sel-minconf').value = value;
  invalidateAnalytics();
  refreshSociogram();
}
function setIncludeInferred(on) {
  if (on === state.proj.include_inferred) return;
  state.proj.include_inferred = on;
  $('chk-inferred').checked = on;
  invalidateAnalytics();
  refreshSociogram();
}
function setSizeMetric(key) {
  if (!METRIC_LABEL.has(key)) return;
  state.sizeMetric = key;
  $('sel-metric').value = key;
  if (state.metrics) {
    state.metricsNote = 'size = ' + METRIC_LABEL.get(key);
  }
  renderProjectionBar();
  renderInspector();
  draw();
}

/** E2. How much of what is on screen rests on an exhibit. This is a
 *  headline number, not a detail: the difference between a graph of
 *  evidence and a graph of opinions is exactly this ratio, and the first
 *  real session of using this tool scored zero without anyone noticing. */
function renderEvidenceCoverage() {
  const box = $('evidence-coverage');
  if (!box) return;
  const cov = state.metrics && state.metrics.evidence_coverage;
  if (!cov || !cov.elements) {
    setMsg(box, '');
    return;
  }
  const pct = Math.round((cov.ratio || 0) * 100);
  const backed = cov.nodes + cov.edges;
  setMsg(box, 'evidence: ' + backed + ' of ' + cov.elements +
              ' elements (' + pct + '%) rest on an exhibit');
  box.className = 'muted small' + (pct === 0 ? ' coverage-none'
                                  : (pct < 50 ? ' coverage-low' : ''));
  box.title = cov.note + '. Unevidenced entities are drawn hollow and ' +
    'unevidenced ties are faded while "Mark unevidenced" is on.';
}

/** The always-visible projection panel. docs/03: "Show the projection
 *  parameters next to the results, always." */
function renderProjectionBar() {
  const preset = state.presetMap.get(state.proj.preset);
  const desc = $('preset-desc');
  desc.textContent = preset
    ? preset.label + ' — ' + preset.description
    : 'No projection description available.';
  $('sel-preset').title = preset ? preset.description : '';

  setMsg($('metric-note'), state.metricsNote);
  renderEvidenceCoverage();
  $('legend-size').textContent = 'size = ' +
    (state.metrics ? (METRIC_LABEL.get(state.sizeMetric) || state.sizeMetric)
                   : 'degree (local count)');

  renderFocusFlag();
  renderReadout();
  renderAsOfHeader();
}

function renderReadout() {
  const box = $('proj-readout');
  clear(box);
  const p = state.projMeta || {};
  const types = p.edge_types;
  const parts = [
    'preset=' + (p.preset || state.proj.preset),
    'edge_types=' + (Array.isArray(types)
      ? types.length + ' listed' : 'every social tie'),
    'include_inferred=' + String(p.include_inferred === undefined
      ? state.proj.include_inferred : p.include_inferred),
    'min_confidence=' + (p.min_confidence || state.proj.min_confidence),
    'as_of=' + (p.as_of ? fmtTime(p.as_of) : 'now'),
  ];
  const head = el('span', null, 'projection: ' + parts.join(' · '));
  if (Array.isArray(types)) head.title = 'edge types: ' + types.join(', ');
  box.appendChild(head);

  const drawn = state.graph
    ? state.graph.nodes.length + ' nodes, ' + state.graph.links.length + ' edges'
    : '0 nodes';
  box.appendChild(el('span', null, '  │  drawn: ' + drawn));

  if (state.metrics) {
    box.appendChild(el('span', null,
      '  │  metrics over ' + state.metrics.node_count + ' nodes, ' +
      state.metrics.edge_count + ' edges · density ' +
      num(state.metrics.density, 4)));
  } else {
    box.appendChild(el('span', 'rd-warn', '  │  metrics unavailable'));
  }
  if (state.projTruncated) {
    box.appendChild(el('span', 'rd-warn',
      '  │  TRUNCATED at ' + NODE_PAGE + ' nodes — narrow the projection ' +
      'before reading anything off this picture'));
  }
  /* docs/14 U2. Without this an analyst cannot tell a sparse network from a
     censored one, and reads structure off a picture they believe is
     complete — a broker who looks peripheral because the two ties that make
     them central are above their clearance is a wrong answer delivered
     confidently. Never says WHICH classification, WHICH compartment, or
     WHERE: the count is per case, because "a hidden tie next to this
     person" would localise the withheld material. */
  const w = state.withheld;
  if (w && w.incomplete) {
    const detail = (w.nodes === undefined)
      ? 'some of it is above your clearance'
      : w.nodes + ' entit' + (w.nodes === 1 ? 'y' : 'ies') + ' and ' +
        w.edges + ' tie' + (w.edges === 1 ? '' : 's') + ' are above your ' +
        'clearance';
    box.appendChild(el('span', 'rd-warn',
      '  │  INCOMPLETE — ' + detail + ' and are not on this canvas. ' +
      'Structural readings from it are lower bounds.'));
  }
  if (state.proj.include_inferred) {
    box.appendChild(el('span', null,
      '  │  inferred edges are IN (this projection opts in, so they count ' +
      'toward the metrics above)'));
  }
}

function renderAsOfHeader() {
  const hdr = $('hdr-asof');
  const past = !!state.proj.as_of;
  hdr.className = 'hdr-asof mono' + (past ? ' past' : '');
  hdr.textContent = past ? '⏱ as-of: ' + fmtTime(state.proj.as_of) : '⏱ as-of: now';
}

/* ── focus mode: ego networks and shortest paths ───────────────────────
 * Focus is a state the analyst must be able to see and leave. A picture that
 * silently shows a subset is a picture that gets misread. */

function renderFocusFlag() {
  const flag = $('focus-flag'), text = $('focus-text');
  /* Only the label span is rewritten — the button also holds a <kbd>Esc</kbd>
     hint, and setting textContent on the button would delete it. */
  const btn = $('focus-btn-text');
  if (!state.focus) {
    if (state.pathAnchor) {
      /* An anchor waiting for its second click is a mode too, and a mode the
         analyst cannot see is a mode they will forget they are in. */
      text.textContent = 'PATH ANCHOR · ' + labelOf(state.pathAnchor) +
        ' · shift-click a second entity';
      flag.title = '';
      btn.textContent = 'Cancel';
      show(flag, true);
      return;
    }
    show(flag, false);
    return;
  }
  btn.textContent = 'Full projection';
  if (state.focus.kind === 'ego') {
    text.textContent = 'FOCUS · ego of ' + labelOf(state.focus.id) +
      ' at depth ' + state.focus.depth;
    flag.title = 'Only this neighbourhood is on screen. The metrics panel still ' +
      'reports numbers for the whole projection, not for this subgraph.';
  } else {
    text.textContent = 'FOCUS · path ' + labelOf(state.focus.src) + ' → ' +
      labelOf(state.focus.dst) +
      (state.focus.connected ? ' · ' + state.focus.hops + ' hops'
                             : ' · NOT CONNECTED in this projection');
    flag.title = 'Shortest path, treated as undirected. The path endpoint does ' +
      'not take an as-of parameter, so the path is traced against the latest ' +
      'state of the projection even when the scrubber is in the past.';
  }
  show(flag, true);
}

/** Double-click, or Enter on the canvas: render just the ego network. */
async function enterEgo(nodeId, depth) {
  if (!nodeId) return;
  const seq = ++state.graphSeq;
  const q = projQuery();
  q.set('depth', String(depth || 1));
  try {
    const sub = await api(cpath('/graph/ego/' + nodeId + '?' + q.toString()));
    if (seq !== state.graphSeq) return;
    state.focus = { kind: 'ego', id: nodeId, depth: depth || 1 };
    state.pathIds = null;
    state.pathAnchor = null;
    state.needFit = true;
    setRendered(sub.nodes || [], sub.edges || []);
    renderProjectionBar();
  } catch (err) {
    if (seq !== state.graphSeq) return;
    fail(err);
  }
}

/** Shift-click a second node: highlight the shortest path, dim the rest. */
async function enterPath(srcId, dstId) {
  if (!srcId || !dstId || srcId === dstId) return;
  const seq = ++state.graphSeq;
  const q = projQuery();
  q.delete('as_of');           // the endpoint takes no as_of; say so, below
  q.set('src', srcId);
  q.set('dst', dstId);
  try {
    const out = await api(cpath('/graph/path?' + q.toString()));
    if (seq !== state.graphSeq) return;
    state.focus = { kind: 'path', src: srcId, dst: dstId,
                    hops: out.hops, connected: !!out.connected };
    state.pathIds = out.connected ? (out.path || []) : [];
    state.pathAnchor = null;
    /* The path is computed on the full projection, so the full projection is
       what must be on screen underneath it. */
    setRendered(state.gnodes, state.gedges, { keepView: true });
    renderProjectionBar();
    if (!out.connected) {
      banner('No path in this projection',
        labelOf(srcId) + ' and ' + labelOf(dstId) + ' are not connected under ' +
        'the current projection. A different preset, or including inferred ' +
        'edges, may connect them — and whether it does is itself a finding.',
        'warn');
    }
  } catch (err) {
    if (seq !== state.graphSeq) return;
    fail(err);
  }
}

/** What the "Full projection" / "Cancel" button and Escape both do. */
function leaveFocusOrAnchor() {
  if (state.focus) { exitFocus(); return; }
  if (state.pathAnchor) {
    state.pathAnchor = null;
    renderFocusFlag();
    draw();
  }
}

function exitFocus() {
  if (!state.focus) return;
  state.focus = null;
  state.pathIds = null;
  state.pathAnchor = null;
  state.needFit = true;
  setRendered(state.gnodes, state.gedges);
  renderProjectionBar();
}

/** After a projection change, a focus computed under the old parameters is
 *  stale. Re-derive it rather than dropping it silently — the analyst asked to
 *  look at one neighbourhood and moving the scrubber should play THAT through
 *  history, not throw them back to the whole graph. */
async function reapplyFocus(seq, q) {
  if (!state.focus) { setRendered(state.gnodes, state.gedges); return; }
  const present = new Set(state.gnodes.map((n) => n.id));
  if (state.focus.kind === 'ego') {
    if (!present.has(state.focus.id)) {
      state.focus = null;
      setRendered(state.gnodes, state.gedges);
      banner('Focus dropped', 'The focused entity is not in the projection any ' +
        'more, so the view is back to the whole projection.', 'warn');
      return;
    }
    const eq = new URLSearchParams(q);
    eq.set('depth', String(state.focus.depth));
    try {
      const sub = await api(cpath('/graph/ego/' + state.focus.id + '?' + eq.toString()));
      if (seq !== state.graphSeq) return;
      setRendered(sub.nodes || [], sub.edges || [], { keepView: true });
    } catch (err) {
      if (seq !== state.graphSeq) return;
      state.focus = null;
      setRendered(state.gnodes, state.gedges);
      fail(err);
    }
    return;
  }
  /* path focus */
  if (!present.has(state.focus.src) || !present.has(state.focus.dst)) {
    state.focus = null;
    state.pathIds = null;
    setRendered(state.gnodes, state.gedges);
    return;
  }
  const pq = new URLSearchParams(q);
  pq.delete('as_of');
  pq.set('src', state.focus.src);
  pq.set('dst', state.focus.dst);
  try {
    const out = await api(cpath('/graph/path?' + pq.toString()));
    if (seq !== state.graphSeq) return;
    state.focus.hops = out.hops;
    state.focus.connected = !!out.connected;
    state.pathIds = out.connected ? (out.path || []) : [];
  } catch (_err) {
    if (seq !== state.graphSeq) return;
    state.pathIds = null;
  }
  setRendered(state.gnodes, state.gedges, { keepView: true });
}

/* ── timeline scrubber: the signature element (docs/06) ─────────────────
 * Drag it and the graph plays through history. `as_of` is WORLD time — "the
 * thing existed then" — not record time, which is why an edge can vanish from
 * the picture without anything having been deleted.
 *
 * The span is computed from the UNPROJECTED case lists so it cannot shrink as
 * the scrubber moves; a control whose own range depends on its value is
 * unusable. */

const tlCanvas = $('tl-density');
const tlCtx = tlCanvas.getContext('2d');
let scrubTimer = 0;

function pushTime(out, value) {
  if (!value) return;
  const t = Date.parse(value);
  if (Number.isFinite(t)) out.push(t);
}

function computeTimeSpan() {
  const bounds = [];
  const arrivals = [];
  for (const n of state.nodes) {
    pushTime(bounds, n.first_seen);
    pushTime(bounds, n.last_seen);
    pushTime(bounds, n.created_at);
    const one = [];
    pushTime(one, n.first_seen);
    if (!one.length) pushTime(one, n.created_at);
    if (one.length) arrivals.push(one[0]);
  }
  for (const e of state.edges) {
    pushTime(bounds, e.valid_from);
    pushTime(bounds, e.valid_to);
    const one = [];
    pushTime(one, e.valid_from);
    if (one.length) arrivals.push(one[0]);
  }
  state.timePoints = arrivals;
  if (bounds.length < 2) { state.timeSpan = null; return; }
  const min = Math.min.apply(null, bounds);
  const max = Math.max.apply(null, bounds);
  state.timeSpan = max > min ? { min: min, max: max } : null;
}

function scrubUsable() {
  return !!(state.timeSpan && state.timeSpan.max > state.timeSpan.min);
}

/** @param syncValue write the slider position back from `as_of`. Skipped while
 *  the analyst is dragging, so the control never fights its own owner. */
function renderScrubber(syncValue) {
  const range = $('tl-range');
  const strip = $('scrubber');
  const usable = scrubUsable();
  strip.classList.toggle('dead', !usable);
  range.disabled = !usable;

  if (!usable) {
    $('tl-min').textContent = '—';
    $('tl-max').textContent = '—';
    $('tl-current').textContent = 'as-of: now';
    $('tl-note').textContent = 'No temporal data in this case yet — nothing ' +
      'carries a valid-from, first-seen or last-seen time, so there is no ' +
      'history to play through. The strip switches on as soon as one element ' +
      'does.';
    range.setAttribute('aria-valuetext', 'unavailable — no temporal data');
    if (syncValue !== false) range.value = '1000';
    drawDensity();
    return;
  }

  const span = state.timeSpan;
  $('tl-min').textContent = fmtDay(span.min);
  $('tl-max').textContent = fmtDay(span.max);
  if (syncValue !== false) range.value = String(posFromAsOf());
  const label = state.proj.as_of ? fmtTime(state.proj.as_of) : 'now (latest)';
  $('tl-current').textContent = 'as-of: ' + label;
  range.setAttribute('aria-valuetext', 'as-of ' + label);
  $('tl-note').textContent = 'density = ' + state.timePoints.length +
    ' elements entering the graph over ' +
    Math.max(1, Math.round((span.max - span.min) / 86400000)) + ' days. ' +
    'A gap here is a gap in COVERAGE, not necessarily in activity.';
  drawDensity();
}

function posFromAsOf() {
  const span = state.timeSpan;
  if (!span || !state.proj.as_of) return 1000;
  const t = Date.parse(state.proj.as_of);
  if (!Number.isFinite(t)) return 1000;
  return Math.round(clamp((t - span.min) / (span.max - span.min), 0, 1) * 1000);
}

function onScrubInput() {
  if (!scrubUsable()) return;
  const span = state.timeSpan;
  const v = Number($('tl-range').value);
  if (v >= 1000) {
    state.proj.as_of = null;
  } else {
    const t = span.min + (span.max - span.min) * (v / 1000);
    state.proj.as_of = new Date(t).toISOString();
  }
  renderScrubber(false);       // instant label + playhead, no waiting on I/O
  renderAsOfHeader();
  clearTimeout(scrubTimer);
  scrubTimer = setTimeout(() => { refreshSociogram(); }, 200);
}

function resetAsOf() {
  if (!state.proj.as_of) return;
  state.proj.as_of = null;
  renderScrubber(true);
  renderAsOfHeader();
  refreshSociogram();
}

function resizeDensity() {
  const dpr = window.devicePixelRatio || 1;
  const w = tlCanvas.clientWidth, h = tlCanvas.clientHeight;
  if (!w || !h) return;
  tlCanvas.width = Math.round(w * dpr);
  tlCanvas.height = Math.round(h * dpr);
  tlCtx.setTransform(dpr, 0, 0, dpr, 0, 0);
  drawDensity();
}

/** Collection-volume marks plus the playhead. Drawn, not styled — the CSP
 *  leaves no inline style to size a bar with, and pixels are more honest here
 *  anyway. */
function drawDensity() {
  const w = tlCanvas.clientWidth, h = tlCanvas.clientHeight;
  if (!w || !h) return;
  tlCtx.clearRect(0, 0, w, h);
  tlCtx.fillStyle = PAINT.surface2 || '#1E2432';
  tlCtx.fillRect(0, 0, w, h);

  const span = state.timeSpan;
  if (!span || span.max <= span.min) {
    tlCtx.strokeStyle = PAINT.hairline || '#303849';
    tlCtx.lineWidth = 1;
    tlCtx.beginPath();
    tlCtx.moveTo(0, h - 0.5);
    tlCtx.lineTo(w, h - 0.5);
    tlCtx.stroke();
    return;
  }

  const buckets = Math.max(24, Math.min(120, Math.floor(w / 6)));
  const counts = new Array(buckets).fill(0);
  for (const t of state.timePoints) {
    const f = (t - span.min) / (span.max - span.min);
    if (f < 0 || f > 1) continue;
    counts[Math.min(buckets - 1, Math.floor(f * buckets))] += 1;
  }
  let peak = 0;
  for (const c of counts) if (c > peak) peak = c;
  const bw = w / buckets;
  tlCtx.fillStyle = PAINT.accentDim || '#2F6B66';
  for (let i = 0; i < buckets; i += 1) {
    if (!counts[i]) continue;
    const bh = Math.max(2, (counts[i] / peak) * (h - 4));
    tlCtx.fillRect(i * bw + 0.5, h - bh, Math.max(1, bw - 1), bh);
  }
  tlCtx.strokeStyle = PAINT.hairline || '#303849';
  tlCtx.lineWidth = 1;
  tlCtx.beginPath();
  tlCtx.moveTo(0, h - 0.5);
  tlCtx.lineTo(w, h - 0.5);
  tlCtx.stroke();

  const x = (posFromAsOf() / 1000) * w;
  tlCtx.strokeStyle = state.proj.as_of ? (PAINT.alert || '#D4A03C')
                                      : (PAINT.accent || '#4EA8A0');
  tlCtx.lineWidth = 2;
  tlCtx.beginPath();
  tlCtx.moveTo(clamp(x, 1, w - 1), 0);
  tlCtx.lineTo(clamp(x, 1, w - 1), h);
  tlCtx.stroke();
}

/* ── sociogram ─────────────────────────────────────────────────────────
 * A spring/repulsion layout on <canvas>, in WORLD coordinates with a separate
 * view transform, so pan/zoom and the saved layout are independent of the
 * viewport size. Saved positions are world coordinates: reopening the case in a
 * different window size puts the picture back where the analyst left it.
 *
 * THE ENCODING RULES (docs/06) — these do not bend:
 *   node size    chosen centrality metric (the select says which)
 *   node colour  node type
 *   node opacity confidence
 *   node ring    selected / pinned / has unreviewed proposals
 *   edge colour  sign — green positive, red negative, grey neutral
 *   edge width   weight, LOG-scaled
 *   edge style   solid = asserted, DASHED = inferred. Never negotiable.
 */

const canvas = $('graph-canvas');
const ctx = canvas.getContext('2d');
const reduceMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
const cssVar = (name) =>
  getComputedStyle(document.documentElement).getPropertyValue(name).trim();

const PAINT = {};
function loadPaint() {
  PAINT.void = cssVar('--void');
  PAINT.surface2 = cssVar('--surface-2');
  PAINT.hairline = cssVar('--hairline');
  PAINT.pos = cssVar('--sign-positive');
  PAINT.neg = cssVar('--sign-negative');
  PAINT.neu = cssVar('--sign-neutral');
  PAINT.accent = cssVar('--accent');
  PAINT.accentDim = cssVar('--accent-dim');
  PAINT.alert = cssVar('--alert');
  PAINT.label = cssVar('--text-secondary');
  PAINT.dim = cssVar('--text-tertiary');
  PAINT.bright = cssVar('--text-primary');
  PAINT.font = '11px ' + (cssVar('--ui') || 'sans-serif');
  PAINT.monoFont = '10px ' + (cssVar('--mono') || 'monospace');
  PAINT.signFont = '600 13px ' + (cssVar('--mono') || 'monospace');
  PAINT.hues = {};
  for (const h of ['actor-persona', 'actor-person', 'actor-group',
                   'artefact-infra', 'artefact-finance', 'artefact-malware',
                   'context']) {
    PAINT.hues[h] = cssVar('--' + h);
  }
}

/** Swap what the canvas is showing. Positions survive: a node already on
 *  screen keeps its coordinates, so entering and leaving a focus does not
 *  rearrange the entities that were in both pictures. */
function setRendered(nodes, edges, options) {
  const o = options || {};
  const prev = state.graph ? state.graph.index : null;
  const count = Math.max(1, nodes.length);
  const ring = 90 + count * 4;
  const simNodes = nodes.map((n, i) => {
    const old = prev && prev.get(n.id);
    const saved = state.layout.get(n.id);
    const a = (i / count) * Math.PI * 2;
    let x, y, pinned = false;
    if (old) { x = old.x; y = old.y; pinned = old.pinned; }
    else if (saved) { x = Number(saved.x); y = Number(saved.y);
                      pinned = !!saved.is_pinned; }
    else { x = Math.cos(a) * ring; y = Math.sin(a) * ring; }
    if (!Number.isFinite(x)) x = Math.cos(a) * ring;
    if (!Number.isFinite(y)) y = Math.sin(a) * ring;
    return { id: n.id, ref: n, deg: 0, x: x, y: y, vx: 0, vy: 0,
             pinned: pinned, sx: 0, sy: 0, sr: 6 };
  });
  const index = new Map(simNodes.map((n) => [n.id, n]));
  const links = [];
  let maxWeight = 1;
  for (const e of edges) {
    const a = index.get(e.src_node_id), b = index.get(e.dst_node_id);
    if (!a || !b) continue;             // endpoint above the caller's clearance
    a.deg += 1; b.deg += 1;
    const wgt = Math.max(0, Number(e.weight) || 0);
    if (wgt > maxWeight) maxWeight = wgt;
    links.push({ ref: e, a: a, b: b });
  }
  state.graph = { nodes: simNodes, links: links, index: index,
                  maxWeight: maxWeight, alpha: 1, drag: null, raf: 0 };
  show($('graph-empty'), simNodes.length === 0);
  /* keepView means "the analyst is still looking at the same thing" — a
     scrubber step or a path highlight must not yank the viewport around. */
  if (o.keepView) state.needFit = false;
  resizeGraph();
  settle();
}

function stopGraph() {
  if (state.graph && state.graph.raf) cancelAnimationFrame(state.graph.raf);
  state.graph = null;
}

/* -- layout simulation ------------------------------------------------- */

function repel(a, b) {
  let dx = a.x - b.x, dy = a.y - b.y;
  let d2 = dx * dx + dy * dy;
  if (d2 < 1) { dx = Math.random() - 0.5; dy = Math.random() - 0.5; d2 = 1; }
  const d = Math.sqrt(d2);
  const f = Math.min(4000 / d2, 4);
  a.vx += (dx / d) * f;
  a.vy += (dy / d) * f;
}

/** Exact O(n²) repulsion below the threshold, a uniform-grid approximation
 *  above it. docs/03 is blunt that past a few hundred nodes you should be
 *  filtering, not waiting — but a slow canvas is still worse than an
 *  approximate one. */
function gridRepel(ns) {
  const cell = 110;
  const buckets = new Map();
  for (const n of ns) {
    const k = Math.floor(n.x / cell) + ',' + Math.floor(n.y / cell);
    let b = buckets.get(k);
    if (!b) { b = []; buckets.set(k, b); }
    b.push(n);
  }
  for (const n of ns) {
    const cx = Math.floor(n.x / cell), cy = Math.floor(n.y / cell);
    for (let dx = -1; dx <= 1; dx += 1) {
      for (let dy = -1; dy <= 1; dy += 1) {
        const b = buckets.get((cx + dx) + ',' + (cy + dy));
        if (!b) continue;
        for (const o of b) { if (o !== n) repel(n, o); }
      }
    }
  }
}

function step() {
  const g = state.graph;
  if (!g) return;
  const ns = g.nodes;
  if (ns.length > 320) {
    gridRepel(ns);
  } else {
    for (let i = 0; i < ns.length; i += 1) {
      for (let j = i + 1; j < ns.length; j += 1) {
        repel(ns[i], ns[j]);
        repel(ns[j], ns[i]);
      }
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
    n.vx += (0 - n.x) * 0.004;
    n.vy += (0 - n.y) * 0.004;
    n.vx *= 0.84; n.vy *= 0.84;
    /* A pinned node is the analyst's decision and the simulation does not get
       to overrule it — that is the whole point of pinning. */
    if (n.pinned || n === g.drag) { n.vx = 0; n.vy = 0; continue; }
    n.x = clamp(n.x + n.vx * g.alpha, -8000, 8000);
    n.y = clamp(n.y + n.vy * g.alpha, -8000, 8000);
  }
  g.alpha = Math.max(0.03, g.alpha * 0.985);
}

/* ── layout worker (U1, docs/02) ───────────────────────────────────────
 * ForceAtlas2 with Barnes-Hut runs OFF the main thread, so a large case
 * settles without freezing the interface. The main-thread spring
 * simulation below is kept for interactive drag: dragging perturbs a
 * couple of nodes locally and wants an immediate response, which is the
 * one job round-tripping to a worker would make worse.
 *
 * The worker is a same-origin script file, so it satisfies
 * `script-src 'self'` without a bundler — which is why this is hand-written
 * rather than graphology's implementation. Adopting a build step is a real
 * decision (docs/14 U1) and should not arrive as a side effect. */

const LAYOUT_WORKER_MIN_NODES = 60;   // below this the main loop is fine

function startWorkerLayout() {
  const g = state.graph;
  if (!g || !window.Worker) return false;
  if (g.nodes.length < LAYOUT_WORKER_MIN_NODES) return false;
  try {
    stopWorkerLayout();
    state.layoutWorker = new Worker('layout-worker.js');
  } catch (_e) {
    // A blocked or unavailable worker must degrade to the old path, not
    // leave the analyst with a graph that never lays out.
    state.layoutWorker = null;
    return false;
  }
  const index = new Map(g.nodes.map((n, i) => [n.id, i]));
  const links = [];
  for (const l of g.links) {
    const a = index.get(l.a.id), b = index.get(l.b.id);
    if (a === undefined || b === undefined || a === b) continue;
    links.push({ a: a, b: b, w: 1 });
  }
  const degree = new Array(g.nodes.length).fill(0);
  for (const l of links) { degree[l.a] += 1; degree[l.b] += 1; }

  /* Moving the maths off the main thread is only half the win. The worker
     posts progress dozens of times per run, and redrawing on every message
     puts the cost straight back where it was: 400 nodes laid out in under a
     second still froze the interface for most of it, because that second
     contained ~67 full canvas repaints. Positions are applied immediately
     (they are cheap) and the REPAINT is coalesced onto an animation frame,
     so the browser draws at most once per frame no matter how chatty the
     worker is. */
  state.layoutWorker.onerror = (err) => {
    // A worker that dies silently leaves the graph in its scattered initial
    // positions with no explanation. Fall back to the main-thread loop.
    stopWorkerLayout();
    setMsg($('layout-status'), '');
    banner('Layout worker failed',
           'Falling back to the in-page layout, which is slower on large '
           + 'graphs. ' + ((err && err.message) || ''), 'warn');
    if (!reduceMotion && !g.raf) g.raf = requestAnimationFrame(frame);
  };
  state.layoutWorker.onmessage = (e) => {
    const msg = e.data;
    const pos = new Float32Array(msg.positions);
    const cur = state.graph;
    if (!cur || cur !== g) return;      // the case changed under us
    for (let i = 0; i < cur.nodes.length; i += 1) {
      const n = cur.nodes[i];
      if (n.pinned || n === cur.drag) continue;
      n.x = pos[i * 2];
      n.y = pos[i * 2 + 1];
      n.vx = 0; n.vy = 0;
    }
    if (state.needFit) { state.needFit = false; fitView(); }
    if (!state.layoutPaint) {
      state.layoutPaint = requestAnimationFrame(() => {
        state.layoutPaint = 0;
        draw();
      });
    }
    /* Reaching the iteration cap is a normal outcome on a big graph, not a
       failure: the picture is usable, it simply had not stopped moving. Say
       that plainly rather than in the language of an error. */
    setMsg($('layout-status'), msg.type === 'done'
      ? (msg.settled ? '' : 'layout good enough; still drifting slightly when it stopped')
      : 'laying out ' + Math.round(100 * msg.iteration / msg.maxIterations) + '%');
    if (msg.type === 'done') {
      stopWorkerLayout();
      syncLayoutFromSim();
      draw();                    // one guaranteed repaint at the final state
    }
  };
  state.layoutWorker.postMessage({
    type: 'start',
    nodes: g.nodes.map((n, i) => ({
      x: n.x, y: n.y, degree: degree[i], pinned: !!n.pinned,
    })),
    links: links,
    // 800 is where a mid-size graph actually converges rather than
    // stopping mid-expansion; big graphs trade some of that for time.
    iterations: g.nodes.length > 1500 ? 300 : 800,
  });
  return true;
}

function stopWorkerLayout() {
  if (state.layoutWorker) {
    state.layoutWorker.terminate();
    state.layoutWorker = null;
  }
  if (state.layoutPaint) {
    cancelAnimationFrame(state.layoutPaint);
    state.layoutPaint = 0;
  }
}

/** Run the layout. With prefers-reduced-motion the graph settles instantly. */
function settle() {
  const g = state.graph;
  if (!g) return;
  g.alpha = 1;
  // Big graph: hand it to the worker and let the interface stay responsive.
  if (!reduceMotion && startWorkerLayout()) return;
  if (reduceMotion) {
    for (let i = 0; i < 320; i += 1) step();
    if (state.needFit) { state.needFit = false; fitView(); }
    draw();
    return;
  }
  if (!g.raf) g.raf = requestAnimationFrame(frame);
}

function frame() {
  const g = state.graph;
  if (!g) return;
  step();
  if (state.needFit && g.alpha < 0.35) { state.needFit = false; fitView(); }
  draw();
  if (g.alpha > 0.05 || g.drag) g.raf = requestAnimationFrame(frame);
  else { g.raf = 0; syncLayoutFromSim(); }
}

/* -- view transform ---------------------------------------------------- */

function toWorld(sx, sy) {
  const v = state.view;
  return { x: (sx - v.tx) / v.scale, y: (sy - v.ty) / v.scale };
}

function zoomAt(sx, sy, factor) {
  const v = state.view;
  const w = toWorld(sx, sy);
  v.scale = clamp(v.scale * factor, 0.12, 6);
  v.tx = sx - w.x * v.scale;
  v.ty = sy - w.y * v.scale;
  draw();
}

function fitView() {
  const g = state.graph;
  const w = canvas.clientWidth || 800, h = canvas.clientHeight || 600;
  if (!g || !g.nodes.length) {
    state.view = { scale: 1, tx: w / 2, ty: h / 2 };
    draw();
    return;
  }
  let minX = Infinity, minY = Infinity, maxX = -Infinity, maxY = -Infinity;
  for (const n of g.nodes) {
    if (n.x < minX) minX = n.x;
    if (n.x > maxX) maxX = n.x;
    if (n.y < minY) minY = n.y;
    if (n.y > maxY) maxY = n.y;
  }
  const pad = 70;
  const bw = Math.max(1, maxX - minX), bh = Math.max(1, maxY - minY);
  const scale = clamp(Math.min((w - pad * 2) / bw, (h - pad * 2) / bh), 0.12, 2);
  state.view.scale = scale;
  state.view.tx = w / 2 - ((minX + maxX) / 2) * scale;
  state.view.ty = h / 2 - ((minY + maxY) / 2) * scale;
  draw();
}

function resizeGraph() {
  const dpr = window.devicePixelRatio || 1;
  const w = canvas.clientWidth, h = canvas.clientHeight;
  if (!w || !h) return;
  const prev = state.viewport;
  // Nothing changed: bail before touching canvas.width, which CLEARS the
  // canvas and forces a full repaint even when assigned an identical value.
  // This is what makes it safe to call from both the observer and the
  // window listener, and on every tab switch.
  if (prev && prev.w === w && prev.h === h && prev.dpr === dpr) return;

  canvas.width = Math.round(w * dpr);
  canvas.height = Math.round(h * dpr);
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);

  if (!Number.isFinite(state.view.tx) || !Number.isFinite(state.view.ty)) {
    state.view.tx = w / 2;
    state.view.ty = h / 2;
  } else if (prev && (prev.w !== w || prev.h !== h)) {
    /* Keep whatever the analyst was looking at in the middle.
     *
     * The canvas backing store was already being resized here, but the
     * translation was left alone, so growing the window pinned the graph to
     * the old top-left and opened empty space on the right and bottom —
     * maximising appeared to do nothing but add margin.
     *
     * Since screen = world * scale + t, holding the centred world point
     * still means shifting t by half the size change. Deliberately NOT a
     * re-fit: docs/03 is explicit that "analysts build a spatial memory of
     * their network — reshuffling it on every load destroys real analytic
     * value", and a window resize is not a request to rearrange the case.
     * Zoom is untouched for the same reason: a node keeps the size it had.
     */
    state.view.tx += (w - prev.w) / 2;
    state.view.ty += (h - prev.h) / 2;
  }
  state.viewport = { w: w, h: h, dpr: dpr };
  draw();
}

/* -- the encodings ----------------------------------------------------- */

/** Raw value behind node size, log-compressed except for clustering, which is
 *  already a 0-1 ratio. Raw counts destroy the scale — the same reason edge
 *  width is log-scaled. */
function sizeRaw(n) {
  if (!state.metrics) return Math.log1p(n.deg);
  const row = state.metricById.get(n.id);
  const v = row ? Number(row[state.sizeMetric]) : 0;
  if (!Number.isFinite(v)) return 0;
  return state.sizeMetric === 'clustering' ? v : Math.log1p(Math.max(0, v));
}

function sizeScale() {
  const g = state.graph;
  let lo = Infinity, hi = -Infinity;
  for (const n of g.nodes) {
    const v = sizeRaw(n);
    if (v < lo) lo = v;
    if (v > hi) hi = v;
  }
  const flat = !(hi > lo);
  return (n) => {
    if (flat) return 8;
    const t = clamp((sizeRaw(n) - lo) / (hi - lo), 0, 1);
    return 5 + Math.sqrt(t) * 11;
  };
}

function edgeColour(sign) {
  return sign > 0 ? PAINT.pos : (sign < 0 ? PAINT.neg : PAINT.neu);
}
function confAlpha(confidence) {
  if (confidence === 'HIGH') return 1;
  if (confidence === 'MODERATE') return 0.72;
  if (confidence === 'LOW') return 0.45;
  return 1;                      // no confidence recorded: do not fake one
}
function nodeColour(n) {
  return PAINT.hues[hueClass(n.ref.node_type).slice(4)] || PAINT.hues.context;
}
function edgeWidth(e) {
  const g = state.graph;
  const w = Math.max(0, Number(e.weight) || 0);
  const t = Math.log1p(w) / Math.log1p(Math.max(1, g ? g.maxWeight : 1));
  return 1 + clamp(t, 0, 1) * 3.4;
}

function syncScreen() {
  const g = state.graph;
  if (!g) return;
  const v = state.view;
  const zf = clamp(v.scale, 0.55, 1.6);
  const size = sizeScale();
  for (const n of g.nodes) {
    n.sx = n.x * v.scale + v.tx;
    n.sy = n.y * v.scale + v.ty;
    n.sr = size(n) * zf;
  }
}

function pairKey(a, b) { return a < b ? a + '|' + b : b + '|' + a; }

/** What is emphasised, and therefore what is dimmed. Path focus wins over
 *  hover: an explicit question outranks the mouse happening to be somewhere. */
function focusSets() {
  const g = state.graph;
  if (!g) return null;
  if (state.pathIds && state.pathIds.length) {
    const nodes = new Set(state.pathIds);
    const pairs = new Set();
    for (let i = 0; i < state.pathIds.length - 1; i += 1) {
      pairs.add(pairKey(state.pathIds[i], state.pathIds[i + 1]));
    }
    return { mode: 'path', nodes: nodes, pairs: pairs };
  }
  if (state.hoverId && g.index.has(state.hoverId)) {
    const nodes = new Set([state.hoverId]);
    for (const l of g.links) {
      if (l.ref.src_node_id === state.hoverId) nodes.add(l.ref.dst_node_id);
      else if (l.ref.dst_node_id === state.hoverId) nodes.add(l.ref.src_node_id);
    }
    return { mode: 'hover', nodes: nodes, pairs: null };
  }
  return null;
}

function edgeHidden(e) {
  return e.is_inferred && state.hideInferredHold;
}

function draw() {
  const g = state.graph;
  const w = canvas.clientWidth, h = canvas.clientHeight;
  ctx.fillStyle = PAINT.void || '#080B12';
  ctx.fillRect(0, 0, w, h);
  if (!g) return;
  syncScreen();
  const sel = state.selection;
  const fs = focusSets();
  const scale = state.view.scale;
  const showLabels = scale >= 0.7;
  const showEdgeLabels = scale >= 1.9;

  /* edges */
  for (const l of g.links) {
    const e = l.ref;
    if (edgeHidden(e)) continue;
    const on = sel && sel.kind === 'edge' && sel.id === e.id;
    let lit = true;
    if (fs) {
      lit = fs.mode === 'path'
        ? fs.pairs.has(pairKey(e.src_node_id, e.dst_node_id))
        : (e.src_node_id === state.hoverId || e.dst_node_id === state.hoverId);
    }
    ctx.globalAlpha = lit ? confAlpha(e.confidence) : 0.08;
    /* Invariant: solid = asserted, dashed = inferred. Never negotiable. */
    ctx.setLineDash(e.is_inferred ? [5, 4] : []);
    ctx.strokeStyle = on ? PAINT.accent : edgeColour(e.sign);
    ctx.lineWidth = edgeWidth(e) + (on ? 1.5 : 0) +
                    (lit && fs && fs.mode === 'path' ? 1.5 : 0);
    /* E2. An unevidenced tie is drawn FAINTER, never dashed: dashed already
       means inferred, and overloading it would make an unevidenced observed
       tie indistinguishable from a machine-suggested one. */
    if (state.showProvenance && e.has_evidence === false && lit) {
      ctx.globalAlpha = confAlpha(e.confidence) * 0.45;
    }
    ctx.beginPath();
    ctx.moveTo(l.a.sx, l.a.sy);
    ctx.lineTo(l.b.sx, l.b.sy);
    ctx.stroke();
    /* Sign is a hue, and a hue alone is not an encoding — a red/green
       confusion would invert the meaning of a vouch. A midpoint + / − gives
       sign a second, achromatic channel. It cannot be the dash pattern:
       solid-vs-dashed already means asserted-vs-inferred and that does not
       bend. Held back to closer zooms so the wide view stays readable. */
    if (lit && e.sign !== 0 && (scale >= 1.2 || on ||
        (fs && fs.mode === 'path'))) {
      ctx.setLineDash([]);
      ctx.globalAlpha = 1;
      ctx.fillStyle = edgeColour(e.sign);
      ctx.font = PAINT.signFont;
      ctx.textAlign = 'center';
      ctx.textBaseline = 'middle';
      ctx.fillText(e.sign > 0 ? '+' : '−',
                   (l.a.sx + l.b.sx) / 2, (l.a.sy + l.b.sy) / 2);
      ctx.setLineDash(e.is_inferred ? [5, 4] : []);
    }
    if (showEdgeLabels && lit) {
      ctx.setLineDash([]);
      ctx.globalAlpha = 0.85;
      ctx.fillStyle = PAINT.dim;
      ctx.font = PAINT.monoFont;
      ctx.textAlign = 'center';
      ctx.textBaseline = 'middle';
      ctx.fillText(e.edge_type, (l.a.sx + l.b.sx) / 2, (l.a.sy + l.b.sy) / 2 - 9);
    }
  }
  ctx.setLineDash([]);
  ctx.globalAlpha = 1;

  /* nodes */
  ctx.textAlign = 'center';
  ctx.textBaseline = 'top';
  ctx.font = PAINT.font;
  for (const n of g.nodes) {
    const lit = !fs || fs.nodes.has(n.id);
    const selected = sel && sel.kind === 'node' && sel.id === n.id;
    const r = n.sr;
    /* Node opacity IS confidence (docs/06). A node carries no confidence
       column of its own, so this is the best confidence among its ties in
       THIS projection; the inspector states that in words and gives the
       number, so the encoding is never colour or opacity alone. */
    ctx.globalAlpha = lit ? confAlpha(state.nodeConf.get(n.id)) : 0.1;
    ctx.beginPath();
    ctx.arc(n.sx, n.sy, r, 0, Math.PI * 2);
    ctx.fillStyle = nodeColour(n);
    ctx.fill();

    ctx.globalAlpha = lit ? 1 : 0.14;
    /* E2. An UNEVIDENCED entity gets a hollow core: a ring cut out of its
       centre, so the eye reads "something missing here" without a legend.
       Confidence is already opacity and the node type is already hue, so
       this had to be a shape, not another colour ramp.

       Deliberately marks the ABSENCE rather than the presence of evidence.
       An unevidenced case should look conspicuously unfinished; if the mark
       meant "evidenced", a case with no exhibits at all would look calm and
       complete, which is the exact impression to avoid. */
    if (state.showProvenance && n.has_evidence === false) {
      ctx.beginPath();
      ctx.arc(n.sx, n.sy, Math.max(1.5, r * 0.42), 0, Math.PI * 2);
      ctx.fillStyle = PAINT.void;
      ctx.fill();
    }
    /* rings: unreviewed proposal, then pinned, then selected — drawn at
       increasing radii so all three can be true at once and still be read. */
    if (state.nodeProposed.get(n.id)) {
      ctx.beginPath();
      ctx.arc(n.sx, n.sy, r + 2.5, 0, Math.PI * 2);
      ctx.setLineDash([3, 3]);
      ctx.strokeStyle = PAINT.alert;
      ctx.lineWidth = 1.5;
      ctx.stroke();
      ctx.setLineDash([]);
    }
    if (n.pinned) {
      ctx.beginPath();
      ctx.arc(n.sx, n.sy, r + 6, 0, Math.PI * 2);
      ctx.setLineDash([1, 3]);
      ctx.strokeStyle = PAINT.label;
      ctx.lineWidth = 1.5;
      ctx.stroke();
      ctx.setLineDash([]);
    }
    if (selected) {
      ctx.beginPath();
      ctx.arc(n.sx, n.sy, r + 4, 0, Math.PI * 2);
      ctx.strokeStyle = PAINT.accent;
      ctx.lineWidth = 2;
      ctx.stroke();
    }
    if (state.pathAnchor === n.id) {
      ctx.beginPath();
      ctx.arc(n.sx, n.sy, r + 9, 0, Math.PI * 2);
      ctx.setLineDash([2, 4]);
      ctx.strokeStyle = PAINT.accent;
      ctx.lineWidth = 1.5;
      ctx.stroke();
      ctx.setLineDash([]);
    }
    if (state.focus && state.focus.kind === 'ego' && state.focus.id === n.id) {
      ctx.beginPath();
      ctx.arc(n.sx, n.sy, r + 12, 0, Math.PI * 2);
      ctx.strokeStyle = PAINT.accentDim;
      ctx.lineWidth = 1;
      ctx.stroke();
    }

    /* Progressive disclosure: labels above a zoom threshold, plus always for
       whatever the analyst is pointing at or has selected. */
    if (showLabels || selected || state.hoverId === n.id) {
      ctx.globalAlpha = lit ? 1 : 0.12;
      const raw = n.ref.label || '';
      const label = raw.length > 24 ? raw.slice(0, 23) + '…' : raw;
      ctx.font = PAINT.font;
      ctx.fillStyle = (selected || state.hoverId === n.id) ? PAINT.bright
                                                           : PAINT.label;
      ctx.fillText(label, n.sx, n.sy + r + 5);
    }
  }
  ctx.globalAlpha = 1;
}

/* ── hit testing ──────────────────────────────────────────────────────── */

function canvasPoint(event) {
  const r = canvas.getBoundingClientRect();
  return { x: event.clientX - r.left, y: event.clientY - r.top };
}

function nodeAt(p) {
  const g = state.graph;
  if (!g) return null;
  syncScreen();
  let best = null, bestD = Infinity;
  for (const n of g.nodes) {
    const d = Math.hypot(n.sx - p.x, n.sy - p.y);
    if (d < n.sr + 6 && d < bestD) { best = n; bestD = d; }
  }
  return best;
}

function edgeAt(p) {
  const g = state.graph;
  if (!g) return null;
  syncScreen();
  for (const l of g.links) {
    if (edgeHidden(l.ref)) continue;
    const dx = l.b.sx - l.a.sx, dy = l.b.sy - l.a.sy;
    const len2 = dx * dx + dy * dy;
    if (len2 === 0) continue;
    let t = ((p.x - l.a.sx) * dx + (p.y - l.a.sy) * dy) / len2;
    t = clamp(t, 0, 1);
    const d = Math.hypot(p.x - (l.a.sx + t * dx), p.y - (l.a.sy + t * dy));
    if (d < 6) return l.ref;
  }
  return null;
}

/* ── canvas interaction (docs/06's interaction model) ──────────────────── */

function initCanvas() {
  let mode = null;              // 'pan' | 'drag'
  let downAt = null, downView = null, moved = false;

  canvas.addEventListener('pointerdown', (e) => {
    const g = state.graph;
    if (!g || e.button !== 0) return;
    canvas.focus();
    const p = canvasPoint(e);
    downAt = p;
    moved = false;
    const n = nodeAt(p);
    if (n) {
      mode = 'drag';
      g.drag = n;
      yieldLayoutToDrag();
      if (!reduceMotion && !g.raf) g.raf = requestAnimationFrame(frame);
    } else {
      mode = 'pan';
      downView = { tx: state.view.tx, ty: state.view.ty };
    }
    /* Capture keeps the gesture alive outside the canvas. Not every pointer
       type allows it, and losing it must not cost us the gesture. */
    try { canvas.setPointerCapture(e.pointerId); } catch (_e) { /* optional */ }
  });

  canvas.addEventListener('pointermove', (e) => {
    const g = state.graph;
    if (!g) return;
    const p = canvasPoint(e);
    if (downAt && Math.hypot(p.x - downAt.x, p.y - downAt.y) > 3) moved = true;

    if (mode === 'drag' && g.drag) {
      const w = toWorld(p.x, p.y);
      g.drag.x = w.x; g.drag.y = w.y;
      g.drag.vx = 0; g.drag.vy = 0;
      /* Dragging a node IS pinning it — docs/03: pinned nodes stay pinned, and
         an analyst who positioned something meant it. */
      g.drag.pinned = true;
      g.alpha = Math.max(g.alpha, 0.35);
      if (reduceMotion) draw();
      return;
    }
    if (mode === 'pan' && downView) {
      state.view.tx = downView.tx + (p.x - downAt.x);
      state.view.ty = downView.ty + (p.y - downAt.y);
      draw();
      return;
    }
    /* Hover: dim everything beyond the neighbourhood, no tooltip delay. */
    const hit = nodeAt(p);
    const id = hit ? hit.id : null;
    if (id !== state.hoverId) {
      state.hoverId = id;
      draw();
    }
  });

  canvas.addEventListener('pointerup', (e) => {
    const g = state.graph;
    if (!g) return;
    const p = canvasPoint(e);
    const wasDrag = mode === 'drag';
    if (g.drag) { g.drag = null; syncLayoutFromSim(); }
    mode = null;
    downView = null;
    try { canvas.releasePointerCapture(e.pointerId); } catch (_e) { /* already gone */ }
    if (moved) { draw(); return; }

    const n = nodeAt(p);
    if (n) {
      if (e.shiftKey) {
        if (!state.pathAnchor || state.pathAnchor === n.id) {
          state.pathAnchor = n.id;
          selectNode(n.id);
          renderFocusFlag();
        } else {
          enterPath(state.pathAnchor, n.id);
        }
        return;
      }
      selectNode(n.id);
      return;
    }
    if (wasDrag) { draw(); return; }
    const edge = edgeAt(p);
    if (edge) { selectEdge(edge.id); return; }
    state.selection = null;
    renderInspector();
    draw();
  });

  canvas.addEventListener('pointercancel', () => {
    const g = state.graph;
    if (g && g.drag) { g.drag = null; syncLayoutFromSim(); }
    mode = null;
    downView = null;
  });

  canvas.addEventListener('pointerleave', () => {
    if (state.hoverId) { state.hoverId = null; draw(); }
  });

  canvas.addEventListener('dblclick', (e) => {
    e.preventDefault();
    const n = nodeAt(canvasPoint(e));
    if (n) enterEgo(n.id, 1);
  });

  /* Scroll zoom. Not passive: the page must not scroll instead. */
  canvas.addEventListener('wheel', (e) => {
    if (!state.graph) return;
    e.preventDefault();
    const p = canvasPoint(e);
    zoomAt(p.x, p.y, e.deltaY < 0 ? 1.12 : 1 / 1.12);
  }, { passive: false });

  canvas.addEventListener('keydown', onCanvasKey);
  canvas.addEventListener('keyup', (e) => {
    if (e.key === ' ' || e.key === 'Spacebar') {
      state.hideInferredHold = false;
      draw();
    }
  });
  /* Losing focus mid-hold would otherwise leave inferred edges hidden with
     nothing on screen explaining why. */
  window.addEventListener('blur', () => {
    if (state.hideInferredHold) { state.hideInferredHold = false; draw(); }
  });

  /* Two paths, both installed, on purpose.
   *
   * The observer is RETAINED on state rather than left anonymous:
   * `new ResizeObserver(cb).observe(el)` keeps no reference to the
   * observer, and an observer that gets collected stops delivering
   * silently — the canvas would simply stop tracking its container with
   * nothing on screen to say why.
   *
   * The window listener is no longer an either/or fallback. It costs one
   * event handler and covers the cases the observer misses: a callback
   * that never arrives because the page was in a background tab when the
   * window changed, and a device-pixel-ratio change from dragging the
   * window to a monitor with different scaling, which alters what the
   * backing store should be without changing the element's CSS size at
   * all. resizeGraph() no-ops when nothing actually changed, so running
   * both is free. */
  const onResize = () => {
    if (state.tab === 'graph') { resizeGraph(); resizeDensity(); }
  };
  if ('ResizeObserver' in window) {
    state.canvasObserver = new ResizeObserver(onResize);
    state.canvasObserver.observe(canvas.parentElement);
  }
  window.addEventListener('resize', onResize);
}

function onCanvasKey(e) {
  const g = state.graph;
  if (!g || !g.nodes.length) return;
  const ids = g.nodes.map((n) => n.id);
  const cur = state.selection && state.selection.kind === 'node'
    ? ids.indexOf(state.selection.id) : -1;

  if (e.key === 'ArrowRight' || e.key === 'ArrowDown') {
    e.preventDefault();
    selectNode(ids[(cur + 1 + ids.length) % ids.length]);
  } else if (e.key === 'ArrowLeft' || e.key === 'ArrowUp') {
    e.preventDefault();
    selectNode(ids[(cur - 1 + ids.length) % ids.length]);
  } else if (e.key === ' ' || e.key === 'Spacebar') {
    /* Held, not toggled: one key answers "what do I actually KNOW?" and
       releasing it puts the inference back. */
    e.preventDefault();
    if (!state.hideInferredHold) { state.hideInferredHold = true; draw(); }
  } else if (e.key === 'Enter') {
    e.preventDefault();
    if (cur >= 0) enterEgo(ids[cur], 1);
  } else if (e.key === 'p' || e.key === 'P') {
    e.preventDefault();
    if (cur < 0) return;
    if (!state.pathAnchor || state.pathAnchor === ids[cur]) {
      state.pathAnchor = ids[cur];
      renderFocusFlag();
      draw();
    } else {
      enterPath(state.pathAnchor, ids[cur]);
    }
  } else if (e.key === '+' || e.key === '=') {
    e.preventDefault();
    zoomAt(canvas.clientWidth / 2, canvas.clientHeight / 2, 1.2);
  } else if (e.key === '-' || e.key === '_') {
    e.preventDefault();
    zoomAt(canvas.clientWidth / 2, canvas.clientHeight / 2, 1 / 1.2);
  } else if (e.key === '0') {
    e.preventDefault();
    fitView();
  } else if (e.key === 'Escape') {
    e.preventDefault();
    if (state.focus || state.pathAnchor) { leaveFocusOrAnchor(); return; }
    state.selection = null;
    renderInspector();
    draw();
  }
}

/* ── layout persistence and pinning ────────────────────────────────────
 * docs/03: analysts build a spatial memory of their network, and reshuffling
 * it on every load destroys real analytic value. */

async function loadLayout() {
  try {
    const rows = await api(cpath('/graph/layout'));
    state.layout = new Map((rows || []).map((r) => [String(r.node_id), r]));
  } catch (err) {
    state.layout = new Map();
    fail(err);
  }
}

/** Positions of nodes NOT currently rendered are left alone, so saving from
 *  inside an ego focus cannot wipe the rest of the case's layout. */
/** A drag means the analyst is placing something by hand, and a worker
 *  still writing positions would fight them for it. The hand wins. */
function yieldLayoutToDrag() {
  if (state.layoutWorker) {
    stopWorkerLayout();
    setMsg($('layout-status'), '');
  }
}

function syncLayoutFromSim() {
  const g = state.graph;
  if (!g) return;
  for (const n of g.nodes) {
    state.layout.set(n.id, { node_id: n.id, x: n.x, y: n.y,
                             is_pinned: !!n.pinned });
  }
}

async function saveLayout() {
  if (!state.caseId) return;
  syncLayoutFromSim();
  const positions = Array.from(state.layout.values()).map((p) => ({
    node_id: p.node_id,
    x: Number(p.x) || 0,
    y: Number(p.y) || 0,
    is_pinned: !!p.is_pinned,
  }));
  if (!positions.length) {
    banner('Nothing to save', 'There are no positions on the canvas yet.', 'warn');
    return;
  }
  const btn = $('btn-save-layout');
  btn.disabled = true;
  try {
    await api(cpath('/graph/layout'), { method: 'PUT',
                                        json: { positions: positions } });
    const pinned = positions.filter((p) => p.is_pinned).length;
    banner('Layout saved', positions.length + ' positions stored, ' + pinned +
      ' pinned. This is what the canvas will look like on your next visit.',
      'warn');
  } catch (err) {
    fail(err);
  } finally {
    btn.disabled = false;
  }
}

async function clearPins() {
  const g = state.graph;
  if (g) for (const n of g.nodes) n.pinned = false;
  for (const [id, p] of state.layout) {
    state.layout.set(id, { node_id: id, x: p.x, y: p.y, is_pinned: false });
  }
  settle();
  draw();
  /* Persist the unpinning too — a pin that comes back on reload was not
     cleared, it was hidden. */
  try {
    const positions = Array.from(state.layout.values()).map((p) => ({
      node_id: p.node_id, x: Number(p.x) || 0, y: Number(p.y) || 0,
      is_pinned: false,
    }));
    if (positions.length) {
      await api(cpath('/graph/layout'), { method: 'PUT',
                                          json: { positions: positions } });
    }
    banner('Pins cleared', 'Every node is back under the simulation.', 'warn');
  } catch (err) { fail(err); }
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
  /* Case totals, not projection totals: this list is the case file, and the
     projection's own counts live next to the canvas where they belong. */
  $('ent-count').textContent = rows.length + ' of ' + state.nodes.length +
    ' entities · ' + state.edges.length + ' relationships in the case';
}

/* ── evidence ─────────────────────────────────────────────────────────── */

async function loadEvidence() {
  try {
    state.evidence = await api(cpath('/evidence-list?limit=200'));
    renderEvidence();
    // E1: keep the entity/relationship exhibit pickers in step, so an
    // exhibit uploaded a moment ago is immediately attachable.
    refreshEvidencePickers();
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
        const out = await api(cpath('/evidence/' + ev.id + '/verify'),
                              { method: 'POST' });
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
        const log = await api(cpath('/evidence/' + ev.id + '/custody'));
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
    const out = await api(cpath('/evidence'), { method: 'POST', form: form });
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
      api(cpath('/search/nodes?limit=50&q=' + enc)),
      api(cpath('/search/evidence?q=' + enc)),
    ]);
    renderHits(nodeBox, nodeHits, (hit) => { selectNode(hit.id); selectTab('graph'); });
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

function nodeById(id) {
  return state.nodes.find((x) => x.id === id) ||
         state.gnodes.find((x) => x.id === id) || null;
}
function labelOf(id) {
  const n = nodeById(id);
  return n ? n.label : shortId(id);
}
/** /graph edges carry endpoint ids, /edges carries endpoint labels. Prefer the
 *  richer record and synthesise the labels when only the projection has it. */
function edgeById(id) {
  const e = state.edges.find((x) => x.id === id);
  if (e) return e;
  const g = state.gedges.find((x) => x.id === id);
  if (!g) return null;
  return Object.assign({}, g, { src_label: labelOf(g.src_node_id),
                                dst_label: labelOf(g.dst_node_id) });
}

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
    const n = nodeById(sel.id);
    if (!n) { loadMissingNode(sel.id); return; }
    typeChip.className = 'chip type-chip ' + hueClass(n.node_type);
    typeChip.textContent = typeName(n.node_type);
    classChip.className = 'chip tlp-' + n.classification;
    classChip.textContent = 'TLP:' + n.classification;
    $('insp-label').textContent = n.label;
    sub.textContent = n.id + ' · first seen ' + fmtTime(n.first_seen) +
      ' · last seen ' + fmtTime(n.last_seen);
    show($('insp-sel-sec'), true);
    show($('insp-metrics-sec'), true);
    show($('insp-merge-sec'), true);
    renderMergePanel(n);
    renderNodeMetrics(sel.id);
  } else {
    const e = edgeById(sel.id);
    if (!e) { state.selection = null; renderInspector(); return; }
    typeChip.className = 'chip type-chip';
    typeChip.textContent = e.edge_type;
    classChip.className = 'chip tlp-' + e.classification;
    classChip.textContent = 'TLP:' + e.classification;
    $('insp-label').textContent = e.src_label + ' → ' + e.dst_label;
    const signWord = e.sign > 0 ? 'positive tie'
      : (e.sign < 0 ? 'negative tie' : 'neutral tie');
    sub.textContent = signWord + ' · weight ' + e.weight +
      ' · confidence ' + e.confidence +
      ' (opacity ' + confAlpha(e.confidence).toFixed(2) + ')' +
      ' · ' + (e.is_inferred ? 'INFERRED (dashed, excluded from metrics unless ' +
                              'the projection opts in)' : 'asserted') +
      ' · review ' + e.review + ' · from ' + fmtTime(e.valid_from);
    show($('insp-sel-sec'), false);
    show($('insp-metrics-sec'), false);
    show($('insp-merge-sec'), false);
  }

  const seq = ++state.inspSeq;
  const base = cpath((sel.kind === 'node' ? '/nodes/' : '/edges/') + sel.id);
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

/** The metrics panel. Every number arrives with its rank, and the projection
 *  that produced it is named right underneath — docs/03: a metric without its
 *  parameters is not reproducible, and "0.0341" means nothing to anyone while
 *  "3rd of 214" means something to everyone. */
function renderNodeMetrics(nodeId) {
  const box = $('insp-metrics');
  const scope = $('insp-metrics-scope');
  const projLine = $('insp-metrics-proj');
  clear(box);

  const inProjection = state.gnodes.some((n) => n.id === nodeId);
  const row = state.metricById.get(nodeId);

  if (!state.metrics) {
    scope.textContent = 'unavailable';
    box.appendChild(el('p', 'empty', state.metricsNote ||
      'Metrics could not be loaded for this projection.'));
    projLine.textContent = '';
    return;
  }
  if (!inProjection || !row) {
    scope.textContent = 'not in projection';
    box.appendChild(el('p', 'empty',
      'This entity is outside the current projection, so it has no numbers ' +
      'here. Widen the preset, lower the minimum confidence, or move the ' +
      'as-of position forward.'));
    projLine.textContent = projectionSentence();
    return;
  }

  scope.textContent = state.projMeta ? state.projMeta.preset : state.proj.preset;
  const ties = state.nodeTies.get(nodeId) || 0;
  const conf = state.nodeConf.get(nodeId);
  const proposed = state.nodeProposed.get(nodeId) || 0;

  const rows = [
    ['degree', 'Degree', num(row.degree), true],
    ['weighted_degree', 'Weighted degree', num(row.weighted_degree, 4), true],
    ['positive_degree', 'Positive degree', num(row.positive_degree), false],
    ['negative_degree', 'Negative degree', num(row.negative_degree), false],
    ['clustering', 'Clustering', num(row.clustering, 4), true],
    ['k_core', 'k-core', num(row.k_core), true],
  ];
  for (const [key, label, value, ranked] of rows) {
    const k = el('div', 'metric-k' + (key === state.sizeMetric ? ' on' : ''), label);
    if (key === state.sizeMetric) k.title = 'This is the metric driving node size.';
    box.appendChild(k);
    box.appendChild(el('div', 'metric-v', value));
    if (ranked && state.ranks && state.ranks[key]) {
      const r = state.ranks[key].get(nodeId);
      box.appendChild(el('div', 'metric-rank',
        r ? ordinal(r) + ' of ' + state.rankTotal : '—'));
    } else if (key === 'positive_degree') {
      const t = el('div', 'metric-rank', 'vouches');
      t.title = 'docs/03: received vouches are accumulated reputation; given ' +
        'vouches are reputation staked. They mean opposite things, and this ' +
        'count is undirected, so it is the sum of both.';
      box.appendChild(t);
    } else if (key === 'negative_degree') {
      const t = el('div', 'metric-rank', 'disputes');
      t.title = 'Rip reports, accusations and bans. A node with many negative ' +
        'ties is not a well-connected node.';
      box.appendChild(t);
    } else {
      box.appendChild(el('div', 'metric-rank', ''));
    }
  }

  box.appendChild(el('div', 'metric-k', 'Ties in projection'));
  box.appendChild(el('div', 'metric-v', String(ties)));
  box.appendChild(el('div', 'metric-rank', ''));

  /* Confidence is an opacity on the canvas, so it is also a number here —
     never an encoding the analyst has to read off a colour. */
  box.appendChild(el('div', 'metric-k', 'Tie confidence (best)'));
  box.appendChild(el('div', 'metric-v',
    conf ? conf + ' / ' + confAlpha(conf).toFixed(2) : 'none / 1.00'));
  const ct = el('div', 'metric-rank', 'opacity');
  ct.title = 'Node opacity on the canvas is this value. A node carries no ' +
    'confidence column of its own — this is the highest confidence among its ' +
    'ties in this projection. An isolated node draws at full opacity because ' +
    'no confidence has been claimed either way.';
  box.appendChild(ct);

  if (proposed) {
    box.appendChild(el('div', 'metric-k', 'Unreviewed proposals'));
    box.appendChild(el('div', 'metric-v', String(proposed)));
    const pt = el('div', 'metric-rank', 'ringed');
    pt.title = 'Machines propose, analysts dispose. This node is ringed on the ' +
      'canvas because at least one incident relationship is still PROPOSED.';
    box.appendChild(pt);
  }

  projLine.textContent = projectionSentence();
}

function projectionSentence() {
  const p = state.projMeta || state.proj;
  const bits = [
    'preset=' + (p.preset || '—'),
    'include_inferred=' + String(!!p.include_inferred),
    'min_confidence=' + (p.min_confidence || '—'),
    'as_of=' + (p.as_of ? fmtTime(p.as_of) : 'now'),
  ];
  let line = 'computed over projection ' + bits.join(' · ');
  if (state.metrics) {
    line += ' · ' + state.metrics.node_count + ' nodes, ' +
      state.metrics.edge_count + ' edges, density ' + num(state.metrics.density, 4);
  }
  if (state.projTruncated) {
    line += ' · WARNING: the node page was truncated, so these numbers describe ' +
      'a slice of the case rather than all of it';
  }
  return line;
}

async function loadMissingNode(id) {
  try {
    const n = await api(cpath('/nodes/' + id));
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

    if (a.retraction_reason) {
      card.appendChild(el('div', 'assert-retraction',
        'Retracted: ' + a.retraction_reason));
    }

    /* E3. Retraction is the operation that makes the assertion model mean
       something: withdraw the last live claim behind an element and the
       element leaves the live graph, taking its degree and its edges with
       it, while the row survives for temporal replay. */
    if (!dead) {
      const actions = el('div', 'assert-actions');
      const btn = el('button', 'btn small danger', 'Retract');
      btn.type = 'button';
      btn.title = 'Withdraw this claim. Nothing is deleted -- the row is ' +
        'stamped and kept -- but if this is the last live assertion behind ' +
        'the element, the element leaves the live graph.';
      btn.addEventListener('click', () => retractAssertion(a.id, list.length));
      actions.appendChild(btn);
      card.appendChild(actions);
    }
    box.appendChild(card);
  }
}

/** E3. The confirmation says what will actually happen, which depends on
 *  whether this is the last live claim holding the element up. An analyst
 *  should never be surprised by an entity vanishing. */
async function retractAssertion(assertionId, liveCount) {
  const last = liveCount <= 1;
  const warning = last
    ? '\n\nThis is the LAST live assertion behind this element. Retracting ' +
      'it will remove the element from the live graph, along with every ' +
      'edge that depends on it. History is kept: an earlier as-of position ' +
      'will still show it.'
    : '\n\nOther live assertions remain, so the element stays in the graph.';
  const reason = window.prompt(
    'Why is this claim being withdrawn? The reason is recorded permanently ' +
    'and cannot be edited.' + warning);
  if (reason === null) return;
  if (!reason.trim()) {
    banner('Retraction needs a reason',
           'A withdrawn source without a recorded reason is not auditable.',
           'warn');
    return;
  }
  try {
    await api(cpath('/assertions/' + assertionId + '/retract'), {
      method: 'POST', json: { reason: reason.trim() },
    });
    /* The graph itself may have changed shape, so reload rather than
       patching the inspector: an element that just dissolved must not stay
       drawn on the canvas. */
    invalidateAnalytics();
    await reloadAll();
    banner('Assertion retracted',
           last ? 'It was the last live claim, so the element has left the '
                + 'live graph. Move the as-of scrubber back to see it as it '
                + 'stood.'
                : 'The element remains: other live assertions still support it.',
           'info');
  } catch (err) { fail(err); }
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
  /* An element may not be classified BELOW its case (the server enforces a
   * floor), so defaulting to a fixed AMBER makes every entity form fail in
   * an AMBER_STRICT or RED case — and the rejection reads as a mysterious
   * 400 rather than "you picked something too low". Default to the case's
   * own classification, which is always legal, and drop the options that
   * are not: an analyst cannot choose a value the server will refuse. */
  const caseClass = state.caseRec ? state.caseRec.classification : 'AMBER';
  const floor = TLP.indexOf(caseClass);
  const legal = tlpPairs.filter(([t]) => TLP.indexOf(t) >= floor);
  for (const id of ['node-class', 'edge-class', 'ev-class']) {
    opts($(id), legal, caseClass);
  }
  /* The case form itself is unconstrained: a new case has no floor. */
  opts($('case-class'), tlpPairs, 'AMBER');
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
  const evidence = $(prefix + '-evidence').value;
  const observed = $(prefix + '-observed').value;
  const ref = $(prefix + '-ref').value.trim();
  return {
    basis: basis,
    reliability: $(prefix + '-rel').value,
    credibility: $(prefix + '-cred').value,
    confidence: $(prefix + '-conf').value,
    rationale: rationale || null,
    // E1: the exhibit travels with the claim.
    evidence_id: evidence || null,
    external_ref: ref || null,
    observed_at: observed ? new Date(observed).toISOString() : null,
  };
}

/** U3. A bare `<input type="date">` gives a local calendar day; the API
 *  wants an instant. Midnight UTC is the honest reading of "this was true
 *  from the 3rd of March" — the graph records world time to the day, and
 *  pretending to know the hour would be false precision. */
function intervalFrom(prefix) {
  const from = $(prefix + '-valid-from').value;
  const to = $(prefix + '-valid-to').value;
  return {
    valid_from: from ? new Date(from + 'T00:00:00Z').toISOString() : null,
    // Inclusive end: "until 30 June" means the tie held through that day.
    valid_to: to ? new Date(to + 'T23:59:59Z').toISOString() : null,
  };
}

function intervalProblem(interval) {
  if (interval.valid_from && interval.valid_to &&
      interval.valid_to < interval.valid_from) {
    return 'The interval ends before it starts.';
  }
  return null;
}

/** E1. The exhibit picker is only useful if it is populated, so it is
 *  refreshed whenever the case's evidence list is. An empty list says so
 *  rather than showing a silently empty dropdown. */
function refreshEvidencePickers() {
  const list = state.evidence || [];
  for (const prefix of ['node', 'edge']) {
    const select = $(prefix + '-evidence');
    if (!select) continue;
    const keep = select.value;
    const pairs = [['', list.length ? 'None' : 'No exhibits uploaded yet']];
    for (const ev of list) {
      pairs.push([ev.id, ev.title + '  (' + ev.media_type + ')']);
    }
    opts(select, pairs, keep);
  }
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
  const interval = intervalFrom('node');
  const badInterval = intervalProblem(interval);
  if (badInterval) { setMsg(errBox, badInterval); return; }
  try {
    const out = await api(cpath('/nodes'), {
      method: 'POST',
      json: {
        node_type: $('node-type').value,
        label: label,
        classification: $('node-class').value,
        attrs: {},
        assertion: assertion,
        valid_from: interval.valid_from,
        valid_to: interval.valid_to,
      },
    });
    setMsg(okBox, assertion.evidence_id
      ? 'Created with its founding assertion and exhibit. Opening it in the inspector.'
      : 'Created with its founding assertion. It has NO exhibit behind it yet.');
    $('node-label').value = '';
    $('node-rationale').value = '';
    $('node-ref').value = '';
    await reloadAll();
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
  const interval = intervalFrom('edge');
  const badInterval = intervalProblem(interval);
  if (badInterval) { setMsg(errBox, badInterval); return; }
  try {
    const out = await api(cpath('/edges'), {
      method: 'POST',
      json: {
        edge_type: edgeType,
        src_node_id: src,
        dst_node_id: dst,
        classification: $('edge-class').value,
        assertion: assertion,
        valid_from: interval.valid_from,
        valid_to: interval.valid_to,
      },
    });
    setMsg(okBox, assertion.evidence_id
      ? 'Relationship recorded with its assertion and exhibit.'
      : 'Relationship recorded. It has NO exhibit behind it yet.');
    $('edge-rationale').value = '';
    $('edge-ref').value = '';
    await reloadAll();
    selectEdge(out.id);
    selectTab('graph');
  } catch (err) {
    inlineProblem(errBox, err);
  }
}

/* ── command palette (⌘K / Ctrl+K) ─────────────────────────────────────
 * docs/06: "Power users will live here." Everything reachable from a control
 * on screen is reachable from a keystroke, and nothing here does anything the
 * UI cannot also do — a palette that hides capabilities is a trap. */

const TAB_NAMES = [
  ['graph', 'Sociogram'],
  ['entities', 'Entity list'],
  ['evidence', 'Evidence'],
  ['search', 'Search'],
  ['add-node', 'Add entity'],
  ['add-edge', 'Add relationship'],
];

function buildPaletteItems() {
  const items = [];
  const inCase = !!state.caseId;

  if (!inCase) {
    for (const c of state.cases) {
      items.push({ kind: 'Case', label: c.code + ' — ' + c.title,
                   hint: c.status, run: () => openCase(c.id) });
    }
    return items;
  }

  for (const [key, label] of TAB_NAMES) {
    items.push({ kind: 'View', label: 'Go to ' + label, hint: 'tab',
                 run: () => selectTab(key) });
  }
  for (const p of state.presets) {
    items.push({
      kind: 'Projection',
      label: 'Projection: ' + p.label +
             (p.key === state.proj.preset ? '  (current)' : ''),
      hint: p.description,
      run: () => setPreset(p.key),
    });
  }
  for (const [key, label] of SIZE_METRICS) {
    items.push({
      kind: 'Node size',
      label: 'Size by ' + label + (key === state.sizeMetric ? '  (current)' : ''),
      hint: state.metrics ? 'from /graph/metrics' : 'metrics unavailable',
      run: () => setSizeMetric(key),
    });
  }
  items.push({
    kind: 'Projection',
    label: state.proj.include_inferred ? 'Exclude inferred edges'
                                       : 'Include inferred edges',
    hint: 'refetches the projection',
    run: () => setIncludeInferred(!state.proj.include_inferred),
  });
  for (const c of CONFIDENCE) {
    items.push({ kind: 'Projection', label: 'Minimum confidence: ' + c,
                 hint: c === state.proj.min_confidence ? 'current' : '',
                 run: () => setMinConfidence(c) });
  }
  items.push({ kind: 'Layout', label: 'Save layout', hint: 'PUT positions',
               run: saveLayout });
  items.push({ kind: 'Layout', label: 'Clear pins', hint: 'unpin every node',
               run: clearPins });
  items.push({ kind: 'Layout', label: 'Re-layout', hint: 'settle the simulation',
               run: () => { settle(); } });
  items.push({ kind: 'Layout', label: 'Fit view', hint: 'zoom to the graph',
               run: fitView });
  items.push({ kind: 'Graph', label: 'Reload graph', hint: 'refetch everything',
               run: reloadAll });
  if (state.proj.as_of) {
    items.push({ kind: 'Timeline', label: 'Reset as-of to now',
                 hint: fmtTime(state.proj.as_of), run: resetAsOf });
  }
  if (state.focus) {
    items.push({ kind: 'Focus', label: 'Leave focus mode',
                 hint: 'back to the full projection', run: exitFocus });
  }
  if (state.selection && state.selection.kind === 'node') {
    const id = state.selection.id;
    items.push({ kind: 'Focus', label: 'Ego network of ' + labelOf(id),
                 hint: 'depth 1', run: () => enterEgo(id, 1) });
    items.push({ kind: 'Focus', label: 'Ego network of ' + labelOf(id),
                 hint: 'depth 2', run: () => enterEgo(id, 2) });
  }
  for (const n of state.nodes) {
    items.push({
      kind: 'Entity', label: n.label, hint: typeName(n.node_type),
      run: () => { selectNode(n.id); selectTab('graph'); },
    });
  }
  return items;
}

function openPalette() {
  if (state.paletteOpen) return;
  state.paletteOpen = true;
  state.paletteReturn = document.activeElement;
  state.paletteIndex = 0;
  show($('palette-scrim'), true);
  const input = $('palette-input');
  input.value = '';
  renderPalette();
  input.focus();
}

function closePalette() {
  if (!state.paletteOpen) return;
  state.paletteOpen = false;
  show($('palette-scrim'), false);
  const back = state.paletteReturn;
  state.paletteReturn = null;
  /* Focus goes back where it came from — losing it to <body> strands a
     keyboard user at the top of the document. */
  if (back && typeof back.focus === 'function' && document.contains(back)) {
    back.focus();
  }
}

function renderPalette() {
  const q = $('palette-input').value.trim().toLowerCase();
  const all = buildPaletteItems();
  const terms = q ? q.split(/\s+/) : [];
  const matches = all.filter((it) => {
    if (!terms.length) return true;
    const hay = (it.kind + ' ' + it.label + ' ' + (it.hint || '')).toLowerCase();
    return terms.every((t) => hay.includes(t));
  }).slice(0, 200);

  state.paletteItems = matches;
  state.paletteIndex = clamp(state.paletteIndex, 0, Math.max(0, matches.length - 1));

  const list = $('palette-list');
  clear(list);
  matches.forEach((it, i) => {
    const li = el('li', 'pal-opt');
    li.id = 'pal-opt-' + i;
    li.setAttribute('role', 'option');
    li.setAttribute('aria-selected', i === state.paletteIndex ? 'true' : 'false');
    li.appendChild(el('span', 'pal-kind', it.kind));
    li.appendChild(el('span', 'pal-label', it.label));
    if (it.hint) li.appendChild(el('span', 'pal-hint', it.hint));
    li.addEventListener('mousedown', (e) => {
      e.preventDefault();                 // keep focus in the input
      runPaletteItem(i);
    });
    list.appendChild(li);
  });
  show($('palette-empty'), matches.length === 0);

  const active = list.children[state.paletteIndex];
  $('palette-input').setAttribute('aria-activedescendant',
    active ? active.id : '');
  if (active) active.scrollIntoView({ block: 'nearest' });
}

function movePalette(delta) {
  if (!state.paletteItems.length) return;
  const n = state.paletteItems.length;
  state.paletteIndex = (state.paletteIndex + delta + n) % n;
  renderPalette();
}

function runPaletteItem(index) {
  const it = state.paletteItems[index];
  if (!it) return;
  closePalette();
  try {
    const out = it.run();
    if (out && typeof out.catch === 'function') out.catch(fail);
  } catch (err) { fail(err); }
}

function initPalette() {
  const input = $('palette-input');
  input.addEventListener('input', () => { state.paletteIndex = 0; renderPalette(); });
  input.addEventListener('keydown', (e) => {
    if (e.key === 'ArrowDown') { e.preventDefault(); movePalette(1); }
    else if (e.key === 'ArrowUp') { e.preventDefault(); movePalette(-1); }
    else if (e.key === 'Home') { e.preventDefault(); state.paletteIndex = 0; renderPalette(); }
    else if (e.key === 'End') {
      e.preventDefault();
      state.paletteIndex = Math.max(0, state.paletteItems.length - 1);
      renderPalette();
    } else if (e.key === 'Enter') { e.preventDefault(); runPaletteItem(state.paletteIndex); }
    else if (e.key === 'Escape') { e.preventDefault(); closePalette(); }
    else if (e.key === 'Tab') { e.preventDefault(); }   // focus stays trapped
  });
  $('palette-scrim').addEventListener('mousedown', (e) => {
    if (e.target === $('palette-scrim')) closePalette();
  });
  $('btn-palette').addEventListener('click', openPalette);

  document.addEventListener('keydown', (e) => {
    if ((e.ctrlKey || e.metaKey) && (e.key === 'k' || e.key === 'K')) {
      e.preventDefault();
      if (state.paletteOpen) closePalette();
      else if (state.token) openPalette();
    }
  });

  /* macOS reads ⌘; everywhere else that glyph is noise. */
  const mac = /Mac|iPhone|iPad/i.test(navigator.platform || navigator.userAgent || '');
  $('btn-palette').textContent = mac ? '⌘K' : 'Ctrl K';
}


/* ── notifications ────────────────────────────────────────────────────
 *
 * Phase 5. Two things about this panel are load-bearing rather than
 * cosmetic.
 *
 * The BADGE is the only thing that tells an analyst a second signature is
 * waiting for them, so it is polled with the case rather than refreshed
 * only when the tab is open — the same reasoning as the triage badge. An
 * approval nobody is told about is an approval nobody gives, and then dual
 * control is just a merge button that does not work.
 *
 * The BODY of a notification renders here and only here. docs/07: email
 * carries a summary and a link, never the content, and anything above
 * TLP:AMBER does not leave the platform at all. The server enforces that
 * (the email renderer cannot even reach the body — see transports.py); this
 * panel is the other end of that arrangement, the place where the detail is
 * safe to show because the reader has already passed the access gate.
 */

async function loadInbox() {
  const unreadOnly = $('inbox-unread-only').checked;
  try {
    const data = await api('/notifications?limit=100'
      + (unreadOnly ? '&unread_only=true' : ''));
    state.inbox = data.notifications || [];
    state.inboxUnread = data.unread || 0;
  } catch (err) {
    state.inbox = [];
    if (!(err instanceof ApiError && err.status === 403)) fail(err);
  }
  renderInbox();
}

/** Polled with the case. Cheap: one indexed COUNT. */
async function refreshInboxBadge() {
  try {
    const data = await api('/notifications/unread-count');
    state.inboxUnread = data.unread || 0;
  } catch (_e) {
    /* A badge that cannot be counted is not worth an error banner. */
    return;
  }
  renderInboxBadge();
}

function renderInboxBadge() {
  const badge = $('inbox-badge');
  const n = state.inboxUnread || 0;
  badge.textContent = n > 99 ? '99+' : String(n);
  show(badge, n > 0);
  badge.title = n + ' unread notification(s)';
}

const PRIORITY_LABEL = { 1: 'urgent', 2: 'normal', 3: 'low' };

function renderInbox() {
  const box = $('inbox-list');
  clear(box);
  const rows = state.inbox || [];
  show($('inbox-empty'), rows.length === 0);
  renderInboxBadge();

  rows.forEach((n) => {
    const card = el('article', 'card notification' + (n.read_at ? '' : ' unread'));

    const head = el('div', 'row space-between');
    head.appendChild(el('strong', null, n.subject));
    const tags = el('span', 'tags');
    /* The TLP marking travels with the text, always (docs/07). An analyst
       reading a notification has to know what they are allowed to do with
       what it says. */
    tags.appendChild(el('span', 'chip tlp-' + n.classification, 'TLP:' + n.classification));
    if (n.priority === 1) tags.appendChild(el('span', 'chip bad', 'urgent'));
    else tags.appendChild(el('span', 'chip stale', PRIORITY_LABEL[n.priority]));
    head.appendChild(tags);
    card.appendChild(head);

    const body = el('p', 'notification-body');
    /* textContent, never innerHTML: a notification body carries a case
       label, and a case label is analyst-supplied text. */
    body.textContent = n.body;
    card.appendChild(body);

    const foot = el('div', 'row space-between');
    foot.appendChild(el('span', 'muted small', fmtTime(n.created_at)));

    const actions = el('span', 'row');
    if (!n.read_at) {
      const read = el('button', 'btn ghost small', 'Mark read');
      read.type = 'button';
      read.addEventListener('click', async () => {
        await api('/notifications/' + n.id + '/read', { method: 'POST' });
        await loadInbox();
      });
      actions.appendChild(read);
    }
    if (!n.acknowledged_at) {
      const ack = el('button', 'btn ghost small', 'Acknowledge');
      ack.type = 'button';
      /* Acknowledgement is distinct from reading (docs/07): it is the
         signal that stops a thing nagging, and glancing at a list is not
         that. */
      ack.title = 'Stops this nagging. Distinct from reading it.';
      ack.addEventListener('click', async () => {
        await api('/notifications/' + n.id + '/acknowledge', { method: 'POST' });
        await loadInbox();
      });
      actions.appendChild(ack);
    }
    if (n.object_type === 'approval_request' && n.case_id) {
      const go = el('button', 'btn ghost small', 'Open approvals');
      go.type = 'button';
      go.addEventListener('click', () => selectTab('triage'));
      actions.appendChild(go);
    }
    foot.appendChild(actions);
    card.appendChild(foot);
    box.appendChild(card);
  });
}

async function loadInboxPreferences() {
  const box = $('inbox-prefs');
  clear(box);
  let data;
  try {
    data = await api('/notifications/preferences');
  } catch (_e) { return; }

  (data.preferences || []).forEach((p) => {
    if (p.channel === 'IN_APP') return;    // always on; there is nothing to set
    const row = el('div', 'row pref-row');
    row.appendChild(el('span', 'label', p.channel));

    const enabled = el('input');
    enabled.type = 'checkbox';
    enabled.checked = p.enabled;
    enabled.title = 'Deliver on this channel at all';
    row.appendChild(enabled);

    const priority = el('select');
    opts(priority, [['1', 'urgent only'], ['2', 'normal and up'],
                    ['3', 'everything']], String(p.min_priority));
    row.appendChild(priority);

    const digest = el('input');
    digest.type = 'checkbox';
    digest.checked = p.digest;
    digest.title = 'Roll up to the next hour instead of sending immediately';
    row.appendChild(digest);
    row.appendChild(el('span', 'muted small', 'digest'));

    const from = el('input');
    from.type = 'time';
    from.value = p.quiet_from || '';
    from.title = 'Quiet hours start (your local time)';
    const to = el('input');
    to.type = 'time';
    to.value = p.quiet_to || '';
    to.title = 'Quiet hours end';
    row.appendChild(el('span', 'muted small', 'quiet'));
    row.appendChild(from);
    row.appendChild(to);

    const save = el('button', 'btn ghost small', 'Save');
    save.type = 'button';
    save.addEventListener('click', async () => {
      try {
        await api('/notifications/preferences/' + p.channel, {
          method: 'PUT',
          json: {
            enabled: enabled.checked,
            min_priority: Number(priority.value),
            digest: digest.checked,
            /* Both halves or neither: half a quiet window is a bug that
               reads as a working one, and the server refuses it. */
            quiet_from: (from.value && to.value) ? from.value : null,
            quiet_to: (from.value && to.value) ? to.value : null,
          },
        });
        setMsg($('inbox-prefs-msg'), 'Saved.');
      } catch (err) { fail(err); }
    });
    row.appendChild(save);
    box.appendChild(row);
  });
  const msg = el('p', 'muted small');
  msg.id = 'inbox-prefs-msg';
  box.appendChild(msg);
}

function initInbox() {
  $('inbox-unread-only').addEventListener('change', loadInbox);
  $('inbox-read-all').addEventListener('click', async () => {
    await api('/notifications/read-all', { method: 'POST' });
    await loadInbox();
  });
}


/* ── comms: channels, durable selectors, contact blocks (Phase 7) ──────
 *
 * docs/10: "Read the durable selector column carefully. Getting this wrong
 * is the single biggest source of false attribution in this domain."
 *
 * So the centrepiece of this pane is the NORMALISE PREVIEW, not the form.
 * An analyst who cannot see that their 76-hex Tox ID will be indexed on
 * its first 64 characters has no way to understand why two observations
 * did or did not correlate — and the failure is silent either way: the
 * graph simply shows one person, or two.
 *
 * Every refusal is shown WITH ITS REASON for the same reason. "No durable
 * value" on its own reads as a broken form; "a Telegram @username is not
 * durable because usernames are recycled" is a fact the analyst can act on.
 */

let commsPlatforms = [];

async function loadCommsPlatforms() {
  if (commsPlatforms.length) return commsPlatforms;
  const body = await api('/comms/platforms');
  commsPlatforms = body.platforms || [];
  for (const id of ['comms-platform', 'comms-corr-platform']) {
    const sel = $(id);
    clear(sel);
    for (const p of commsPlatforms) {
      const opt = el('option', null, p.display_name);
      opt.value = p.key;
      sel.appendChild(opt);
    }
  }
  renderPlatformNote();
  return commsPlatforms;
}

function platformByKey(key) {
  return commsPlatforms.find((p) => p.key === key) || null;
}

/** What this platform's identifier MEANS, and what sparse data means. */
function renderPlatformNote() {
  const p = platformByKey($('comms-platform').value);
  const note = $('comms-platform-note');
  const cover = $('comms-platform-coverage');
  if (!p) { show(note, false); show(cover, false); return; }
  note.textContent = p.durable_selector_type
    ? p.durable_selector_type + ' — ' + p.note
    : 'No durable identifier exists. ' + p.note;
  show(note, true);
  /* Surfaced rather than buried: an actor on a platform with no coverage
     looks INACTIVE, and an analyst reads inactivity as a finding. */
  cover.textContent = p.coverage || '';
  show(cover, Boolean(p.coverage));
}

/** Ask the API what an identifier reduces to, WITHOUT storing it. */
async function previewNormalise() {
  const box = $('comms-preview');
  const observed = $('comms-observed').value.trim();
  const platform = $('comms-platform').value;
  if (!observed || !platform) { show(box, false); return; }
  try {
    const q = '?platform_key=' + encodeURIComponent(platform)
            + '&observed=' + encodeURIComponent(observed);
    const body = await api('/comms/normalise' + q);
    const durable = $('comms-preview-durable');
    if (body.durable_value) {
      durable.textContent = body.durable_value;
      durable.classList.remove('bad');
    } else {
      durable.textContent = 'nothing durable';
      durable.classList.add('bad');
    }
    $('comms-preview-note').textContent = body.note || '';
    show(box, true);
  } catch (_e) {
    /* A preview that cannot reach the API is not worth a banner: the
       submit will report it properly. */
    show(box, false);
  }
}

function initCommsBind() {
  $('comms-platform').addEventListener('change', () => {
    renderPlatformNote();
    previewNormalise();
  });
  $('comms-observed').addEventListener('input', debounce(previewNormalise, 250));

  $('comms-bind-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const msg = $('comms-bind-msg');
    setMsg(msg, '');
    try {
      const body = await api(cpath('/comms/bindings'), {
        method: 'POST',
        json: {
          platform_key: $('comms-platform').value,
          observed: $('comms-observed').value.trim(),
          verification: $('comms-verification').value,
          co_declaration_ref: $('comms-codecl').value.trim() || null,
        },
      });
      setMsg(msg, body.durable_value
        ? 'Recorded, indexed as ' + body.durable_value
        : 'Recorded. ' + (body.note || 'No durable value — it will not correlate.'));
      $('comms-observed').value = '';
      show($('comms-preview'), false);
    } catch (err) {
      if (err instanceof ApiError) setMsg(msg, err.detail || err.title);
      else fail(err);
    }
  });
}

function initCommsCorrelate() {
  $('comms-correlate-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const out = $('comms-correlate-out');
    clear(out);
    try {
      const q = '?platform_key='
              + encodeURIComponent($('comms-corr-platform').value)
              + '&observed='
              + encodeURIComponent($('comms-corr-observed').value.trim());
      const body = await api(cpath('/comms/correlate') + q);
      const head = el('p', 'hint');
      head.textContent = body.durable_value
        ? 'Correlating on ' + body.durable_value + ' — ' + body.matches.length
          + ' binding(s) in this case.'
        : 'No durable value, so nothing can correlate. ' + (body.note || '');
      out.appendChild(head);
      for (const m of body.matches) {
        const row = el('div', 'hit');
        row.appendChild(el('code', 'mono', m.observed));
        row.appendChild(el('span', 'pill', m.verification));
        out.appendChild(row);
      }
      if (body.durable_value && !body.matches.length) {
        out.appendChild(el('p', 'hint',
          'Nothing else in this case reduces to that value.'));
      }
    } catch (err) { fail(err); }
  });
}

/* ── contact blocks ─────────────────────────────────────────────────── */

const ROLE_PILL = {
  SELF: 'pill ok',
  THIRD_PARTY: 'pill warn',
  UNPARSED: 'pill',
};

function renderContactBlock(block) {
  const out = $('comms-block-out');
  clear(out);

  const card = el('div', 'card stack');
  const h = el('h3', 'h-sm', block.already_parsed
    ? 'Already parsed — showing the existing reading'
    : 'Parsed');
  card.appendChild(h);

  const codecl = (block.co_declaration || []).length;
  card.appendChild(el('p', 'hint',
    codecl + ' identifier(s) read as the publisher’s own. '
    + 'That SET is the finding — a vendor running Jabber, Tox and Session '
    + 'with a PGP key operates differently from one running a Telegram bot.'));

  for (const e of block.entries) {
    const row = el('div', 'entry-row');

    const role = el('span', ROLE_PILL[e.role] || 'pill', e.role);
    row.appendChild(role);

    const kind = e.platform_key || e.selector_type || 'unresolved';
    row.appendChild(el('span', 'pill', kind));

    row.appendChild(el('code', 'mono grow', e.observed_value));

    const score = el('span', 'pill', e.score.toFixed(2));
    row.appendChild(score);

    if (e.durable_value) {
      const d = el('div', 'entry-sub');
      d.appendChild(el('span', 'label', 'indexed as'));
      d.appendChild(el('code', 'mono', e.durable_value));
      row.appendChild(d);
    }
    /* The reason is not decoration. docs/03: a bare 0.87 will be either
       over-trusted or ignored, and the same is true of a bare role. */
    row.appendChild(el('p', 'hint', e.role_reason));
    row.appendChild(el('p', 'hint mono-sm', e.score_reason));
    if (e.stoplisted) {
      row.appendChild(el('p', 'hint warn',
        'On the service stoplist — this belongs to a known escrow, '
        + 'guarantor or admin, not to the publisher.'));
    }
    if (e.shared_service_publishers) {
      row.appendChild(el('p', 'hint warn',
        'Advertised by ' + e.shared_service_publishers
        + ' other publisher(s): a shared SERVICE, not a shared identity.'));
    }
    if (e.proposal_id) {
      row.appendChild(el('p', 'hint',
        'Raised as a proposal for review. Nothing was written to the graph.'));
    }
    card.appendChild(row);
  }

  card.appendChild(el('p', 'hint', block.notice || ''));
  out.appendChild(card);
}

function initCommsBlocks() {
  $('comms-block-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const msg = $('comms-block-msg');
    setMsg(msg, '');
    try {
      const block = await api(cpath('/comms/contact-blocks'), {
        method: 'POST',
        json: {
          raw_text: $('comms-block-text').value,
          source_ref: $('comms-block-source').value.trim(),
          publisher_handle: $('comms-block-handle').value.trim() || null,
        },
      });
      renderContactBlock(block);
    } catch (err) {
      if (err instanceof ApiError) setMsg(msg, err.detail || err.title);
      else fail(err);
    }
  });
}

function initComms() {
  initCommsBind();
  initCommsCorrelate();
  initCommsBlocks();
}

/* ── boot ─────────────────────────────────────────────────────────────── */

function wire() {
  loadPaint();
  initTabs();
  initInbox();
  initComms();
  initCanvas();
  initPalette();
  opts($('case-class'), TLP.map((t) => [t, t]), 'AMBER');
  opts($('ev-class'), TLP.map((t) => [t, t]), 'AMBER');
  opts($('cap-class'), TLP.map((t) => [t, t]), 'AMBER');
  opts($('sel-metric'), SIZE_METRICS, state.sizeMetric);
  opts($('sel-minconf'), [
    ['LOW', 'LOW — everything'],
    ['MODERATE', 'MODERATE and above'],
    ['HIGH', 'HIGH only'],
  ], state.proj.min_confidence);

  $('login-form').addEventListener('submit', doLogin);
  $('btn-logout').addEventListener('click', doLogout);
  $('btn-cases').addEventListener('click', showCaseList);
  $('case-form').addEventListener('submit', createCase);
  $('ent-filter').addEventListener('change', renderEntities);
  $('chk-provenance').addEventListener('change', (e) => {
    state.showProvenance = e.target.checked;
    renderProjectionBar();
    draw();
  });
  $('merge-run').addEventListener('click', runMerge);
  $('cap-run').addEventListener('click', runCapture);
  $('triage-state').addEventListener('change', () => {
    state.triageIndex = 0;
    loadTriage();
  });
  document.addEventListener('keydown', onTriageKey);
  $('an-run').addEventListener('click', runAnalysis);
  /* Changing a parameter invalidates what is on screen. Blank it rather
     than leave numbers that no longer match the controls above them. */
  for (const id of ['an-decay', 'an-kpp-n']) {
    $(id).addEventListener('change', () => {
      state.analytics = null;
      state.analyticsKpp = null;
      show($('an-results'), false);
      show($('an-empty'), true);
      $('an-empty').textContent =
        'Parameters changed. Run the analysis again.';
      setMsg($('an-status'), '');
    });
  }
  $('ev-form').addEventListener('submit', uploadEvidence);
  $('search-form').addEventListener('submit', runSearch);
  $('node-form').addEventListener('submit', createNode);
  $('edge-form').addEventListener('submit', createEdge);
  $('node-basis').addEventListener('change', () => syncRationaleHint('node'));
  $('edge-basis').addEventListener('change', () => syncRationaleHint('edge'));
  $('edge-src').addEventListener('change', refreshEdgeTypes);
  $('edge-dst').addEventListener('change', refreshEdgeTypes);

  /* projection */
  $('sel-preset').addEventListener('change', (e) => setPreset(e.target.value));
  $('sel-minconf').addEventListener('change', (e) => setMinConfidence(e.target.value));
  $('sel-metric').addEventListener('change', (e) => setSizeMetric(e.target.value));
  $('chk-inferred').addEventListener('change', (e) => setIncludeInferred(e.target.checked));

  /* canvas actions */
  $('btn-fit').addEventListener('click', fitView);
  $('btn-relayout').addEventListener('click', () => settle());
  $('btn-save-layout').addEventListener('click', saveLayout);
  $('btn-clear-pins').addEventListener('click', clearPins);
  $('btn-refresh').addEventListener('click', () => { reloadAll(); loadEvidence(); });
  $('btn-exit-focus').addEventListener('click', leaveFocusOrAnchor);

  /* timeline */
  $('tl-range').addEventListener('input', onScrubInput);
  $('btn-asof-now').addEventListener('click', resetAsOf);

  $('chk-retracted').addEventListener('change', (e) => {
    state.includeRetracted = e.target.checked;
    renderInspector();
  });

  window.addEventListener('resize', () => { resizeDensity(); });
}

/* A token handed over in the URL fragment (#token=...) is adopted and the
 * fragment immediately erased, so it never reaches a bookmark, the history
 * entry, or a Referer header. Written for `bootstrap.py session`, which is
 * the way in when TOTP cannot work — a host whose clock disagrees with the
 * phone's can never produce a matching code. A fragment is not sent to the
 * server, so the token does not appear in the access log either. */
function adoptTokenFromFragment() {
  const match = /(?:^|[#&])token=([^&]+)/.exec(window.location.hash || '');
  if (!match) return;
  const token = decodeURIComponent(match[1]);
  history.replaceState(null, '', window.location.pathname);
  state.token = token;
  sessionStorage.setItem(TOKEN_KEY, token);
}


/* =====================================================================
 * ENTITY RESOLUTION (Phase 6)
 *
 * docs/01: "Merging is the operation most likely to quietly corrupt a
 * case." So the control says what it will do BEFORE it does it, names
 * which record loses, and every merge stays listed with a one-click
 * reversal beside it.
 *
 * Only same-type entities are offered. Merging a persona into a person is
 * an ATTRIBUTION carrying a confidence (invariant 2) and the server
 * refuses it -- but an interface that offers a choice the server will
 * reject is worse than one that never offered it.
 * ===================================================================== */

function labelOf(nodeId) {
  const n = state.nodes.find((x) => x.id === nodeId);
  return n ? n.label : null;
}

function renderMergePanel(node) {
  const select = $('merge-target');
  const candidates = state.nodes
    .filter((n) => n.id !== node.id && n.node_type === node.node_type)
    .sort((a, b) => a.label.localeCompare(b.label));
  const head = candidates.length
    ? 'Choose the surviving entity'
    : 'No other ' + typeName(node.node_type) + ' in this case';
  opts(select, [['', head]].concat(candidates.map((n) => [n.id, n.label])), '');
  select.disabled = candidates.length === 0;
  $('merge-run').disabled = candidates.length === 0;
  setMsg($('merge-error'), '');
  loadMergeHistory(node.id);
}

async function loadMergeHistory(nodeId) {
  const box = $('merge-history');
  clear(box);
  try {
    const data = await api(cpath('/merges'));
    const mine = (data.merges || []).filter(
      (m) => m.source_node_id === nodeId || m.target_node_id === nodeId);
    if (!mine.length) return;
    box.appendChild(el('h4', 'h-sm', 'Merge history'));
    for (const m of mine) {
      const item = el('div', 'sel-item');
      const isSource = m.source_node_id === nodeId;
      const other = isSource ? m.target_node_id : m.source_node_id;
      const top = el('div');
      top.appendChild(el('span', 'chip' + (m.is_live ? '' : ' stale'),
                         m.is_live ? 'LIVE' : 'REVERSED'));
      top.appendChild(document.createTextNode(
        (isSource ? ' merged INTO ' : ' absorbed ') +
        (labelOf(other) || shortId(other))));
      item.appendChild(top);
      item.appendChild(el('div', 'muted small',
        m.reason + ' \u00b7 ' + m.edges_repointed + ' tie(s) moved \u00b7 ' +
        fmtTime(m.merged_at)));
      if (m.reversal_reason) {
        item.appendChild(el('div', 'muted small',
                            'reversed: ' + m.reversal_reason));
      }
      if (m.is_live) {
        const undo = el('button', 'btn small', 'Reverse');
        undo.type = 'button';
        undo.title = 'Restore every tie to its original endpoints and bring ' +
                     'the losing entity back into the graph.';
        undo.addEventListener('click', () => reverseMerge(m));
        item.appendChild(undo);
      }
      box.appendChild(item);
    }
  } catch (err) {
    if (!(err instanceof ApiError && err.status === 403)) fail(err);
  }
}

async function runMerge() {
  const sel = state.selection;
  if (!sel || sel.kind !== 'node') return;
  const targetId = $('merge-target').value;
  if (!targetId) {
    setMsg($('merge-error'), 'Choose the surviving entity.');
    return;
  }
  const losing = labelOf(sel.id), surviving = labelOf(targetId);
  /* Naming BOTH records and the direction, because the commonest merge
     mistake is doing it backwards and noticing weeks later. */
  const reason = window.prompt(
    'Merge "' + losing + '" INTO "' + surviving + '".\n\n' +
    '"' + losing + '" leaves the live graph and its ties move to "' +
    surviving + '". This is reversible, and the reason is recorded ' +
    'permanently.\n\nWhy are these the same entity?');
  if (reason === null) return;
  if (!reason.trim()) {
    setMsg($('merge-error'), 'A merge must say why: docs/01 calls this the ' +
           'operation most likely to quietly corrupt a case.');
    return;
  }
  try {
    await api(cpath('/merges'), {
      method: 'POST',
      json: { source_node_id: sel.id, target_node_id: targetId,
              reason: reason.trim() },
    });
    invalidateAnalytics();
    await reloadAll();
    selectNode(targetId);
    banner('Merged', '"' + losing + '" now redirects to "' + surviving +
           '". Reverse it from the entity resolution panel if this was wrong.',
           'info');
  } catch (err) {
    if (err instanceof ApiError) inlineProblem($('merge-error'), err);
    else fail(err);
  }
}

async function reverseMerge(m) {
  const reason = window.prompt('Why is this merge being reversed?');
  if (reason === null) return;
  if (!reason.trim()) {
    banner('A reversal needs a reason', 'It is recorded permanently.', 'warn');
    return;
  }
  try {
    await api(cpath('/merges/' + m.id + '/reverse'), {
      method: 'POST', json: { reason: reason.trim() },
    });
    invalidateAnalytics();
    await reloadAll();
    banner('Merge reversed',
           'Every tie is back at its original endpoints and the entity has ' +
           'returned to the graph.', 'info');
  } catch (err) { fail(err); }
}

/* =====================================================================
 * TRIAGE (Phase 4)
 *
 * The human half of "machines propose, analysts dispose". Every row here
 * is a suggestion that has NOT touched the graph, and the only ways out
 * are accept, reject and defer.
 *
 * Two things shape the design. Every suggestion shows the text it came
 * from, because a handle lifted out of a quoted signature block looks
 * identical to a real one until you see the sentence around it. And it is
 * keyboard driven, because docs/09 wants triage to be "a pleasant hour
 * rather than a grim one" and reaching for a mouse a hundred times is what
 * makes it grim.
 * ===================================================================== */

async function loadTriage() {
  if (!state.caseId) return;
  const wanted = $('triage-state').value;
  try {
    const data = await api(cpath('/proposals?state=' + wanted + '&limit=200'));
    state.triage = data.proposals;
    state.triageCounts = data.counts || {};
    renderTriage();
  } catch (err) {
    state.triage = [];
    renderTriage();
    if (!(err instanceof ApiError && err.status === 403)) fail(err);
  }
}

/** The rail badge is the only thing that tells an analyst work is waiting,
 *  so it is refreshed with the case rather than only when the tab is open. */
function renderTriageBadge() {
  const badge = $('triage-badge');
  const waiting = (state.triageCounts || {}).PROPOSED || 0;
  badge.textContent = waiting > 99 ? '99+' : String(waiting);
  show(badge, waiting > 0);
  badge.title = waiting + ' suggestion(s) awaiting review';
}

function renderTriage() {
  const box = $('triage-list');
  clear(box);
  const rows = state.triage || [];
  show($('triage-empty'), rows.length === 0);
  const c = state.triageCounts || {};
  setMsg($('triage-counts'),
    ['PROPOSED', 'DISPUTED', 'ACCEPTED', 'REJECTED']
      .filter((k) => c[k]).map((k) => c[k] + ' ' + k.toLowerCase()).join(' · '));
  renderTriageBadge();

  rows.forEach((p, i) => {
    const card = el('div', 'triage-card' + (i === state.triageIndex ? ' on' : ''));
    card.tabIndex = -1;
    card.dataset.id = p.id;

    const head = el('div', 'triage-head');
    head.appendChild(el('span', 'chip', p.kind));
    const label = p.payload && p.payload.label ? p.payload.label : '(no label)';
    head.appendChild(el('strong', 'triage-label', label));
    if (p.payload && p.payload.attrs && p.payload.attrs.selector_type) {
      head.appendChild(el('span', 'chip small', p.payload.attrs.selector_type));
    }
    /* The score says how often the PATTERN is wrong in prose, not how
       important the finding is. Labelling it "pattern confidence" stops it
       being read as "probability this matters". */
    if (p.score !== null && p.score !== undefined) {
      const s = el('span', 'muted small', 'pattern confidence ' + num(p.score, 2));
      s.title = 'How reliable this KIND of match is in running text, not how '
              + 'significant the finding is. It only orders the queue.';
      head.appendChild(s);
    }
    card.appendChild(head);

    card.appendChild(el('p', 'triage-why', p.rationale));
    card.appendChild(el('p', 'muted small', 'from ' + p.origin));

    if (p.state === 'PROPOSED') {
      const actions = el('div', 'triage-actions');
      const mk = (text, cls, fn, title) => {
        const b = el('button', 'btn small' + (cls ? ' ' + cls : ''), text);
        b.type = 'button';
        if (title) b.title = title;
        b.addEventListener('click', () => fn(p));
        return b;
      };
      actions.appendChild(mk('Accept', 'primary', acceptProposal,
        'Create the element, attributed to you, with an AUTOMATED_INFERENCE '
        + 'assertion recording that a machine suggested it.'));
      actions.appendChild(mk('Reject', 'danger', rejectProposal,
        'Dispose of it. A reason is required -- parser drift is found by '
        + 'reading rejections.'));
      actions.appendChild(mk('Defer', '', deferProposal,
        'Park it as unresolved rather than forcing a decision now.'));
      card.appendChild(actions);
    } else {
      const meta = el('p', 'muted small',
        p.state + (p.review_note ? ' — ' + p.review_note : ''));
      card.appendChild(meta);
    }
    card.addEventListener('click', () => { state.triageIndex = i; renderTriage(); });
    box.appendChild(card);
  });
}

async function disposition(p, path, body, verb) {
  try {
    await api(cpath('/proposals/' + p.id + '/' + path), {
      method: 'POST', json: body,
    });
    await loadTriage();
    if (path === 'accept') {
      // The graph just gained an element, so anything derived from it is
      // stale: the sociogram, the metrics and any computed analysis.
      invalidateAnalytics();
      await reloadAll();
    }
  } catch (err) {
    if (err instanceof ApiError && err.status === 409) {
      banner('Already dispositioned', err.detail || '', 'warn');
      await loadTriage();
    } else { fail(err); }
  }
}

function acceptProposal(p) {
  return disposition(p, 'accept', { note: null }, 'accepted');
}

function rejectProposal(p) {
  const note = window.prompt(
    'Why is this being rejected? Rejections are how parser drift gets '
    + 'found, so the reason matters.');
  if (note === null) return;
  if (!note.trim()) {
    banner('A rejection needs a reason', 'Say what was wrong with it.', 'warn');
    return;
  }
  return disposition(p, 'reject', { note: note.trim() }, 'rejected');
}

function deferProposal(p) {
  const note = window.prompt('What is unresolved about this one?');
  if (note === null) return;
  if (!note.trim()) {
    banner('A deferral needs a note', 'Say what would settle it.', 'warn');
    return;
  }
  return disposition(p, 'defer', { note: note.trim() }, 'deferred');
}

/** docs/09: "triage is a pleasant hour rather than a grim one". */
function onTriageKey(e) {
  if (state.tab !== 'triage') return;
  const target = e.target;
  // Never steal a key from someone typing into the capture box.
  if (target && /^(INPUT|TEXTAREA|SELECT)$/.test(target.tagName)) return;
  const rows = state.triage || [];
  if (!rows.length) return;
  const key = e.key.toLowerCase();
  if (key === 'j' || e.key === 'ArrowDown') {
    state.triageIndex = Math.min(rows.length - 1, state.triageIndex + 1);
  } else if (key === 'k' || e.key === 'ArrowUp') {
    state.triageIndex = Math.max(0, state.triageIndex - 1);
  } else if (key === 'a') {
    acceptProposal(rows[state.triageIndex]); e.preventDefault(); return;
  } else if (key === 'r') {
    rejectProposal(rows[state.triageIndex]); e.preventDefault(); return;
  } else if (key === 'd') {
    deferProposal(rows[state.triageIndex]); e.preventDefault(); return;
  } else { return; }
  e.preventDefault();
  renderTriage();
  const card = $('triage-list').children[state.triageIndex];
  if (card) card.scrollIntoView({ block: 'nearest' });
}

async function runCapture() {
  const btn = $('cap-run');
  const errBox = $('cap-error'), okBox = $('cap-result');
  setMsg(errBox, ''); setMsg(okBox, '');
  const text = $('cap-text').value;
  if (!text.trim()) { setMsg(errBox, 'Paste something first.'); return; }
  btn.disabled = true;
  try {
    const out = await api(cpath('/proposals/capture'), {
      method: 'POST',
      json: {
        text: text,
        title: $('cap-title').value.trim() || null,
        external_url: $('cap-url').value.trim() || null,
        classification: $('cap-class').value,
      },
    });
    const found = Object.entries(out.by_type || {})
      .map(([k, v]) => v + ' ' + k).join(', ');
    setMsg(okBox,
      (out.deduplicated ? 'Already captured; ' : '') +
      out.selectors_found + ' selector(s) found' +
      (found ? ' (' + found + ')' : '') + '. ' +
      out.proposals_created + ' proposal(s) raised' +
      (out.already_known ? ', ' + out.already_known + ' already known' : '') +
      '. ' + out.note);
    $('cap-text').value = '';
    await loadTriage();
  } catch (err) {
    inlineProblem(errBox, err);
  } finally {
    btn.disabled = false;
  }
}

/* =====================================================================
 * ANALYSIS PANEL (Phase 3)
 *
 * Global structural metrics: brokerage, structural holes, communities,
 * cut vertices, signed balance and the key-player set.
 *
 * Two rules from docs/03 shape everything below. The projection
 * parameters are restated on the panel, because the same actor has
 * different centrality under a different filter and a number without its
 * projection is not reproducible. And every caveat the API returns is
 * rendered rather than dropped: an approximation flag, a truncated node
 * set, a two-mode graph or a disconnected eigenvector basis all change
 * what a number is allowed to mean, and an analyst deciding who to arrest
 * is entitled to know.
 * ===================================================================== */

/** num() coerces null to 0, which for a structural metric is a lie: an
 *  isolate has no effective size, and printing 0.00 ranks it as the worst
 *  broker in the case rather than as undefined. The API returns null for
 *  exactly these cases, so preserve the distinction. */
function metricNum(v, dp) {
  return (v === null || v === undefined) ? '—' : num(v, dp);
}

function anQuery() {
  const q = projQuery();
  const decay = $('an-decay').value;
  if (decay) q.set('decay_half_life_months', decay);
  return q;
}

async function runAnalysis() {
  if (!state.caseId) return;
  const btn = $('an-run');
  btn.disabled = true;
  setMsg($('an-status'), 'computing...');
  try {
    const q = anQuery();
    const kq = new URLSearchParams(q);
    kq.set('n', $('an-kpp-n').value);
    /* The suite and the key player are separate runs: the suite is one
       pass over one materialised graph, while key player is combinatorial
       and is cached against its own removal-set size. A failure of the
       expensive one must not blank the cheap one. */
    const suite = await api(cpath('/analytics?' + q.toString()));
    state.analytics = suite;
    let kpp = null;
    try {
      kpp = await api(cpath('/analytics/key-player?' + kq.toString()));
    } catch (err) {
      kpp = { error: err instanceof ApiError ? err.detail || err.title
                                             : 'the request failed' };
    }
    state.analyticsKpp = kpp;
    renderAnalytics();
    /* computed_at_ms is how long the ORIGINAL run took, so on a cache hit
       it describes that run, not this response. Saying "served from cache
       in 24 ms" would claim the cache took 24 ms. */
    setMsg($('an-status'), suite.cached
      ? 'unchanged since the last run, served from cache (computed in '
        + (suite.computed_at_ms || 0) + ' ms)'
      : 'computed in ' + (suite.computed_at_ms || 0) + ' ms');
  } catch (err) {
    show($('an-results'), false);
    show($('an-empty'), true);
    $('an-empty').textContent = err instanceof ApiError
      ? (err.detail || err.title)
      : 'The analysis request failed.';
    setMsg($('an-status'), '');
    if (!(err instanceof ApiError) || err.status !== 422) fail(err);
  } finally {
    btn.disabled = false;
  }
}

function renderAnalytics() {
  const a = state.analytics;
  if (!a) return;
  show($('an-empty'), false);
  show($('an-results'), true);

  const p = a.projection || {};
  $('an-projection').textContent =
    'Projection: ' + (p.label || p.preset) + ' | confidence >= ' +
    p.min_confidence + ' | inferred ' + (p.include_inferred ? 'in' : 'out') +
    (p.as_of ? ' | as of ' + p.as_of : '') +
    ' | ' + a.node_count + ' actors, ' + a.dyad_count + ' dyads' +
    ' | decay: ' + (a.decay ? a.decay.note : 'off');

  renderAnalyticsFlags(a);
  renderAnalyticsLeads(a);
  renderAnalyticsTable(a);
  renderKeyPlayer();
  renderCohesion(a);
  renderBalance(a);
}

/** Every caveat the API returned, rendered as a visible warning. Dropping
 *  one would let a number read as more certain than it is. */
function renderAnalyticsFlags(a) {
  const box = $('an-flags');
  clear(box);
  const flags = [];
  if (a.truncated) flags.push(['warn', a.truncation_note]);
  if (a.is_approximate) flags.push(['warn', a.approximation_note]);
  if (a.mode_warning) flags.push(['warn', a.mode_warning]);
  if (a.eigenvector_meaningful === false) flags.push(['note', a.eigenvector_note]);
  if (a.decay && a.decay.half_life_months && a.decay.undated_edges) {
    flags.push(['note', 'Trust decay: ' + a.decay.note]);
  }
  for (const [kind, text] of flags) {
    const row = el('p', 'an-flag an-flag-' + kind, text);
    box.appendChild(row);
  }
}

/** docs/03 wants the interface to TEACH the broker pattern rather than
 *  print a number: "high betweenness with low degree is the classic broker
 *  signature ... that person is usually far more consequential than the
 *  loudest poster." */
function renderAnalyticsLeads(a) {
  const box = $('an-leads');
  clear(box);
  const brokers = (a.nodes || []).filter((n) => n.broker_signature);
  if (!brokers.length) return;
  const card = el('div', 'card an-leads-card');
  card.appendChild(el('h4', 'h4', 'Brokers worth a look'));
  for (const n of brokers.slice(0, 5)) {
    const item = el('div', 'an-lead');
    const head = el('p', 'an-lead-head');
    head.appendChild(el('strong', null, n.label));
    head.appendChild(document.createTextNode(
      ' — degree ' + n.degree + ', brokerage ' +
      ordinal(n.betweenness_rank) + ' of ' + a.node_count +
      ', constraint ' + ordinal(n.constraint_rank) + ' lowest'));
    item.appendChild(head);
    item.appendChild(el('p', 'muted small', n.broker_signature));
    card.appendChild(item);
  }
  box.appendChild(card);
}

function renderAnalyticsTable(a) {
  const body = $('an-body');
  clear(body);
  for (const n of a.nodes || []) {
    const tr = el('tr');
    const name = el('td', hueClass(n.node_type));
    name.appendChild(el('i', 'swatch'));
    name.appendChild(document.createTextNode(n.label));
    if (n.is_cut_vertex) {
      name.appendChild(document.createTextNode(' '));
      const chip = el('span', 'chip small', 'cut');
      chip.title = 'Articulation point: removing this actor disconnects the '
                 + 'network. A single point of failure in the structure.';
      name.appendChild(chip);
    }
    tr.appendChild(name);
    tr.appendChild(el('td', null, String(n.degree)));
    /* docs/03: vouches RECEIVED (accumulated reputation) and vouches GIVEN
       (reputation staked) mean opposite things, so they never collapse into
       one number. Accusations are shown alongside only when there are any. */
    const vouch = el('td', null,
      n.positive_in_degree + ' / ' + n.positive_out_degree);
    if (n.negative_in_degree || n.negative_out_degree) {
      const bad = el('span', 'muted small',
        '  accused ' + n.negative_in_degree + ' / accuser ' +
        n.negative_out_degree);
      vouch.appendChild(bad);
    }
    tr.appendChild(vouch);
    tr.appendChild(rankCell(n.betweenness, n.betweenness_rank,
                            n.betweenness_percentile, a.node_count));
    tr.appendChild(rankCell(n.constraint, n.constraint_rank,
                            n.constraint_percentile, a.node_count));
    tr.appendChild(el('td', null, metricNum(n.effective_size, 2)));
    tr.appendChild(el('td', null,
      n.community === null || n.community === undefined
        ? '—' : String(n.community)));
    tr.addEventListener('click', () => {
      selectTab('graph');
      selectNode(n.id);
    });
    body.appendChild(tr);
  }
}

/** Raw value with its rank and percentile, because "3rd of 214" is the
 *  part an analyst can actually act on (docs/03). */
function rankCell(value, rank, percentile, total) {
  const td = el('td');
  if (value === null || value === undefined) {
    td.appendChild(el('span', 'muted', '—'));
    td.title = 'Undefined for this actor (an isolate has no structural '
             + 'position to measure).';
    return td;
  }
  td.appendChild(document.createTextNode(metricNum(value, 3)));
  const meta = el('span', 'muted small',
    '  ' + ordinal(rank) + ' of ' + total +
    (percentile === null || percentile === undefined
      ? '' : ' · p' + num(percentile, 0)));
  td.appendChild(meta);
  return td;
}

function renderKeyPlayer() {
  const box = $('an-kpp');
  clear(box);
  const k = state.analyticsKpp;
  if (!k) return;
  if (k.error) {
    box.appendChild(el('p', 'muted small', k.error));
    return;
  }
  const r = k.key_player;
  const card = el('div', 'card');
  card.appendChild(el('p', null,
    'Removing these ' + r.n_remove + ' actors fragments the network from F=' +
    num(r.fragmentation_before, 3) + ' to F=' + num(r.fragmentation_after, 3) +
    ', leaving components of ' + r.fragments_after.join(', ') + '.'));
  const set = el('p');
  set.appendChild(el('strong', null, 'Removal set: '));
  set.appendChild(document.createTextNode(
    r.removal_set.map((x) => x.label).join(', ')));
  card.appendChild(set);

  /* The whole point of KPP-Neg, per docs/03: the optimal set is usually
     NOT the top-n most central actors, because two brokers often span the
     same gap and removing both is redundant. Showing the comparison is
     what makes that surprise legible instead of asking for trust. */
  const cmp = el('p', 'muted small');
  cmp.textContent = 'Top ' + r.n_remove + ' by betweenness (' +
    r.top_betweenness_set.map((x) => x.label).join(', ') + ') would reach only F=' +
    num(r.top_betweenness_fragmentation, 3) + '. ' +
    (r.beats_top_betweenness
      ? 'The optimised set is a genuinely different and better answer: '
        + 'removing the most central actors individually is not the same as '
        + 'removing the set that breaks the network.'
      : 'On this graph the two coincide.');
  card.appendChild(cmp);
  card.appendChild(el('p', 'muted small', 'Method: ' + r.method + '.'));
  box.appendChild(card);
}

function renderCohesion(a) {
  const box = $('an-cohesion');
  clear(box);
  const c = a.cohesion || {};
  const card = el('div', 'card');
  card.appendChild(el('p', null,
    c.community_count + ' communities (Leiden, modularity ' +
    metricNum(c.modularity, 3) + ') across ' + c.components +
    ' connected component(s) of size ' + (c.component_sizes || []).join(', ') + '.'));
  if ((c.cut_vertices || []).length) {
    card.appendChild(el('p', null, 'Cut vertices: ' +
      c.cut_vertices.map((v) => v.label).join(', ')));
    card.appendChild(el('p', 'muted small',
      'Removing any one of these disconnects the network. They are single '
      + 'points of failure in the structure, and the cheap exact companion '
      + 'to the key-player search.'));
  }
  if ((c.bridges || []).length) {
    card.appendChild(el('p', null, 'Bridges: ' + c.bridges.map(
      (b) => b.source_label + ' — ' + b.target_label).join(', ')));
  }
  box.appendChild(card);
}

function renderBalance(a) {
  const box = $('an-balance');
  clear(box);
  const b = a.balance || {};
  const card = el('div', 'card');
  if (b.unavailable) {
    card.appendChild(el('p', 'muted small', b.unavailable));
    box.appendChild(card);
    return;
  }
  if (!b.signed_triads) {
    card.appendChild(el('p', 'muted small',
      'No triad in this projection has a signed tie on all three sides, so '
      + 'there is nothing to balance. ' + (b.skipped_unsigned_triads
        ? b.skipped_unsigned_triads + ' triad(s) were skipped because at '
          + 'least one tie carries no valence.'
        : 'That is thin data, not a balanced network.')));
  } else {
    card.appendChild(el('p', null,
      b.balanced + ' of ' + b.signed_triads + ' signed triads are balanced ('
      + num((b.balance_ratio || 0) * 100, 0) + '%).'));
    for (const t of (b.unbalanced_triads || []).slice(0, 10)) {
      const item = el('div', 'an-lead');
      item.appendChild(el('p', 'an-lead-head',
        t.nodes.map((n) => n.label).join(' · ')));
      item.appendChild(el('p', 'muted small', t.reading));
      card.appendChild(item);
    }
    if (b.unbalanced_truncated) {
      card.appendChild(el('p', 'muted small',
        'More unbalanced triads exist than are listed here.'));
    }
  }
  if ((b.contested_dyads || []).length) {
    card.appendChild(el('p', null, 'Contested pairs: ' + b.contested_dyads.map(
      (d) => d.source_label + ' — ' + d.target_label).join(', ')));
    card.appendChild(el('p', 'muted small',
      'These pairs carry BOTH a positive and a negative tie. That combination '
      + 'is a lead in its own right: a vouch and an accusation between the '
      + 'same two actors usually means a relationship that changed.'));
  }
  box.appendChild(card);
}

async function boot() {
  wire();
  adoptTokenFromFragment();
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

