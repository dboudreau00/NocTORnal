/* NocTORnal analyst console — Phase 2 sociogram.
 *
 * No framework, no build step, no CDN — the app shell is served under a strict
 * `default-src 'self'` CSP, so everything lives in these three files and there
 * is no inline script or style anywhere. Nothing is ever written to
 * `element.style` either: hue and state travel as classes, and everything that
 * needs pixel control (the sociogram, the timeline density strip) is drawn on a
 * <canvas>.
 *
 * SESSION HANDLING (2026-09-09; the previous design is recorded below).
 * The console runs on the API's cookie session: `POST /auth/login` sets
 * `__Host-session` (HttpOnly, Secure, SameSite=Strict) and a readable
 * `__Host-csrf`, every request goes out with `credentials: 'same-origin'`,
 * and every unsafe method copies the CSRF cookie into the `x-csrf-token`
 * header -- the double-submit `deps.session_token` demands. What that
 * buys, stated exactly: after a RELOAD the session is cookie-only, so
 * script on this origin can act as the analyst while the tab lives and
 * holds no token it could replay from anywhere else. Since 2026-09-10
 * that is true from the first request as well, not only after a reload:
 * `POST /auth/login` answers 204 with the pair and NO BODY, so a form
 * sign-in leaves nothing for `state.token` to hold. The two paths that
 * forced a readable token had to be closed first, and were: the live
 * websocket authenticates from `__Host-session` itself
 * (`routers/live.py` `_handshake` prefers the cookie over the first
 * frame it used to insist on), and the Lab download crosses to the
 * sample origin on a one-shot ticket minted here under the cookie
 * session instead of carrying the session token there as a Bearer.
 * Those two were the whole reason a token had to be readable from
 * script; what is still allowed to put one in memory is below, and a
 * form sign-in is not it.
 *
 * Sign-out asks the server to revoke the session and delete both cookies
 * (with the attributes they were set with -- a `__Host-` deletion without
 * Secure is ignored by the browser, and that was the second half of this
 * defect). When the server refuses -- the double-submit rejecting the
 * POST because the readable half is gone, a rate limit, an unreachable
 * API -- the console keeps the app up and says so (`doLogout`): it never
 * shows the sign-in form for a session the server still holds, because a
 * reload would restore that session. A session the cookie restores
 * WITHOUT its readable half is not shown at all (`startApp`): it could
 * read and never write, and could not even sign out.
 *
 * Until 2026-09-09 the bearer token from the login body was held in
 * sessionStorage and sent as an Authorization header, while the server had
 * set the cookie pair on every login for nobody. sessionStorage is readable
 * by any script on the origin, and the header comment here said a browser
 * deployment "should instead" use the cookie -- a claim the code did not
 * back, which is the shape of defect the Alpha 4 review kept finding.
 *
 * ONE thing still puts a token in memory (`state.token`, never
 * storage), and it is not a sign-in: the `#token=` hand-off, which must
 * present the NEW token rather than the cookie the tab already holds.
 * Where the browser accepts the pair, the exchange below is that token's
 * last use in this page. Where it does not -- plain HTTP from a
 * non-localhost address, where `Secure` cookies are refused outright --
 * the handed-over token IS the session for the life of the tab:
 * `authHeaders` falls back to it, and the socket's hello -- its
 * first frame -- carries it, which is the only thing that keeps such a
 * console live. A FORM sign-in on that host produces no credential at all,
 * and `doLogin` says exactly that instead of opening an app that could
 * not read anything (docs/17 F22). The token field is in the socket's
 * protocol for the same caller: `scripts/bootstrap.py session` mints in
 * a shell, for a browser it has never met, and a shell has no cookie jar.
 *
 * That script hands its token over in the URL fragment;
 * `adoptSessionFromFragment` exchanges it once for the cookie pair
 * through `POST /auth/cookie` -- and only when this browser holds no
 * usable session already, because a link must never replace the session
 * the browser has (the server refuses a different account with 409
 * regardless). The token is never logged, never put in a URL by this
 * page, and never rendered.
 *
 * SHAPE OF THE GRAPH LAYER (docs/03). Nothing is measured against "the graph";
 * everything is measured against a PROJECTION — a named, parameterised view.
 * The projection's parameters are on screen next to the canvas at all times,
 * because a metric without its parameters is not reproducible and therefore
 * not evidence.
 */
'use strict';

const API = '/api/v1';
/* The readable half of the cookie pair and the header it is copied into.
   Both names are `deps.py`'s (CSRF_COOKIE, CSRF_HEADER) and
   `test_ui_invariants` holds the two files to each other. The session
   cookie's name is deliberately NOT here: it is HttpOnly, and a script
   that names it is a script trying to read it. */
const CSRF_COOKIE = '__Host-csrf';
const CSRF_HEADER = 'x-csrf-token';
/* Where the previous build kept the bearer token. Named only so boot()
   can remove a token a tab open across the upgrade still holds. */
const LEGACY_TOKEN_STORAGE = 'noctornal.token';

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
   betweenness, Burt's constraint and key-player fragmentation are global,
   computed by the Analysis pane's run and not by this endpoint, and a size
   control for them here would be inventing the number. */
const SIZE_METRICS = [
  ['degree', 'Degree (activity, visibility)'],
  ['weighted_degree', 'Weighted degree (total tie strength)'],
  ['k_core', 'k-core (depth in the durable core)'],
  ['clustering', 'Clustering (how closed the neighbourhood is)'],
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

/* Sociogram page size. 800 is the DEFAULT, not the ceiling.
 *
 * docs/09 Phase 2's exit criterion is "a 2,000-node case renders at 60fps",
 * and a 2026-07-26 audit found the console could not put a 2,000-node case
 * on the canvas at all: it asked for 800 and printed "TRUNCATED", while
 * `routers/graphview.py` defaults to 2000 and accepts up to 5000. The
 * client was the only constraint, and the criterion was unmeetable through
 * the UI.
 *
 * Raised by the analyst rather than by default, because the cost is real:
 * layout is a hand-written Barnes-Hut FA2 in a worker, and 5,000 nodes is
 * a different experience from 800 on a laptop. Defaulting to 2000 would
 * have made the common case worse to satisfy a benchmark. The steps are
 * offered where the truncation is reported, so the choice appears exactly
 * when it is relevant.
 */
const NODE_PAGE = 800;
const NODE_PAGE_STEPS = [800, 2000, 5000];   // 5000 is the server's own cap

/* ── state ────────────────────────────────────────────────────────────── */

const state = {
  /* The bearer token, IN MEMORY ONLY and only when this page saw it (a
     login response or a #token= hand-off). Null after a reload: the
     session then lives in the HttpOnly cookie, which this script cannot
     and need not read. See the header comment for the two uses. */
  token: null,
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
  evidencePolicy: null,      // GET /cases/{id}/evidence/policy, read once
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
  /* The sociogram node ceiling in force right now. Starts at the
     default and is raised by the analyst from the truncation notice;
     never lowered automatically, because silently shrinking a view
     somebody widened on purpose is how a picture becomes a lie. */
  nodeLimit: NODE_PAGE,
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
  /* Metric history is per-node and, unlike the suite, NOT per-projection:
     the series spans every completed run in the case. So a projection
     change does not invalidate it — but a case change does, and so does
     picking a different actor. */
  analyticsHistory: null,
  analyticsHistoryNode: null,
  analyticsHistoryLabel: '',
  analyticsHistoryMetric: 'betweenness',
  /* The caller's own user id, from /admin/users, so the pane can grey out
     self-footguns the server refuses anyway. */
  adminYou: null,

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

  /* deep links, read from the URL fragment at boot and consumed once */
  deepLinkTab: null,
  deepLinkCase: null,
  /* null = not probed, false = refused (stop asking). Latched so ordinary
     tab-switching does not write an AUTHZ_DENIED row per navigation into
     an append-only audit log. */
  quarantineVisible: null,

  /* palette */
  paletteOpen: false,
  paletteItems: [],
  paletteIndex: 0,
  paletteReturn: null,

  /* ACH (Phase 6). `ach` is the last matrix the server returned. The
     matrix names its evidence rows by label only; the basis and the
     Admiralty grading behind each assertion arrive through the
     inspector's and the scorer's `/assertions` reads, and are remembered
     here by assertion id so the stance chooser can show what a cell rests
     on (2026-09-09). */
  ach: null,
  assertionMeta: new Map(),  // assertion id -> {basis, reliability, ...}
  achPick: [],               // live assertions of the selected element
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

/** Make an identifier click-to-copy.
 *
 *  Copying a selector, a hash or a TLS key to paste it into the next tool
 *  is the single most repeated action in this console, and the alternative
 *  is a triple-click that reliably catches a trailing space or the
 *  neighbouring chip.
 *
 *  `copyValue` exists because the DISPLAYED and USEFUL forms differ in the
 *  one place it matters most: a defanged URL reads `hxxps://evil[.]com`
 *  and that is what belongs in a report, so that is what is copied. An
 *  analyst who wants the live form has the capture detail, where the
 *  original is shown. Copying a re-fanged URL to the clipboard would put a
 *  working link one careless paste away from a browser — the same hazard
 *  the defanging exists to prevent.
 *
 *  Deliberately a <button>: it is an action, it must be keyboard
 *  reachable, and a <span> with a click handler is neither.
 */
function copyable(node, copyValue, label) {
  const value = copyValue === undefined || copyValue === null
    ? node.textContent : String(copyValue);
  if (!value) return node;
  const wrap = el('span', 'copyable');
  wrap.appendChild(node);
  const btn = el('button', 'copy-btn', '⎘');
  btn.type = 'button';
  btn.title = 'Copy ' + (label || 'to clipboard');
  btn.setAttribute('aria-label', btn.title);
  btn.addEventListener('click', (e) => {
    e.stopPropagation();          /* never select the row underneath */
    copyText(value, btn);
  });
  wrap.appendChild(btn);
  return wrap;
}
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

/* Unicode characters that change what a string LOOKS like without changing
 * what it IS. Rendering them faithfully is how "harmless<RLO>fdp.exe"
 * appears on screen as "harmlessexe.pdf".
 *
 * Bidi overrides (202A–202E, 2066–2069, 200E/200F, 061C), the zero-width
 * family (200B–200D, FEFF) and the C0/C1 controls.
 *
 * NOT confusables. Latin "a" versus Cyrillic "а" is a different problem
 * needing a script-mixing check rather than a substitution, and this
 * domain's primary venues are Russian-language — a rule that flagged
 * Cyrillic would fire on almost every handle in the case file and be
 * turned off within a day.
 *
 * Written as \u escapes, deliberately. A character class of LITERAL
 * invisible characters is unreadable in review and is silently mangled by
 * anything that normalises, trims or re-encodes — which would remove a
 * defence with no diff anybody would notice. That happened once while this
 * very line was being written. The escapes are also the only form a test
 * can assert on.
 */
const _DECEPTIVE = new RegExp(
  '['
  + '\\u061C'                                 // Arabic letter mark
  + '\\u200B-\\u200F'                         // ZWSP/ZWNJ/ZWJ, LRM, RLM
  + '\\u202A-\\u202E'                         // LRE RLE PDF LRO RLO
  + '\\u2060-\\u2064'                         // word joiner, invisible ops
  + '\\u2066-\\u2069'                         // LRI RLI FSI PDI
  + '\\uFEFF'                                 // BOM / ZWNBSP
  + '\\u0000-\\u0008\\u000B\\u000C\\u000E-\\u001F'   // C0 controls
  + '\\u007F-\\u009F'                         // DEL and C1 controls
  + ']', 'g');

/** Make deceptive characters visible instead of effective.
 *
 *  `dir="ltr"` and `unicode-bidi: isolate` set the BASE direction and do
 *  not touch an explicit override character — which is the trap: the CSS
 *  looks like the defence and is not one. This substitution is, because
 *  the character is gone by the time it reaches the DOM.
 *
 *  Used on every string an attacker chose: filenames, handles, source
 *  notes, dead-letter fragments.
 */
function visibleText(s) {
  if (s === null || s === undefined) return '';
  return String(s).replace(_DECEPTIVE, (ch) =>
    '‹U+' + ch.codePointAt(0).toString(16).toUpperCase().padStart(4, '0')
    + '›');
}

/** Replace a record's `label` with its safe rendering, keeping the
 *  original as `label_raw`.
 *
 *  Applied once where graph data lands rather than at each render site,
 *  because there are two dozen of those and the defence is only worth
 *  anything if it holds at all of them.
 */
function withSafeLabel(row) {
  if (!row || typeof row.label !== 'string') return row;
  const safe = visibleText(row.label);
  if (safe === row.label) return row;
  return Object.assign({}, row, { label: safe, label_raw: row.label });
}

/** Every key that carries a human-chosen name in an analytics response. */
const _LABEL_KEYS = new Set(['label', 'source_label', 'target_label']);

/** `withSafeLabel` for a NESTED payload.
 *
 *  The analytics suite buries names several levels down — `removal_set[]`,
 *  `top_betweenness_set[]`, `cut_vertices[]`, `bridges[]`,
 *  `triads[].nodes[]`, `dyads[]` — and the flat helper above cannot reach
 *  any of them, so the pane drew eight sets of raw labels while the graph
 *  and search paths were de-fanged.
 *
 *  Applied at the boundary rather than at each draw, for the reason the
 *  console has already learned twice: there are two dozen sites that render
 *  a node label and one of them will always be the one somebody forgot.
 */
function safeLabelsDeep(value) {
  if (Array.isArray(value)) return value.map(safeLabelsDeep);
  if (!value || typeof value !== 'object') return value;
  const out = {};
  for (const key of Object.keys(value)) {
    const v = value[key];
    if (_LABEL_KEYS.has(key) && typeof v === 'string') {
      const safe = visibleText(v);
      out[key] = safe;
      /* Keep the original under `_raw`, as withSafeLabel does: the exact
         bytes matter when the question is what the subject actually wrote. */
      if (safe !== v) out[key + '_raw'] = v;
    } else {
      out[key] = safeLabelsDeep(v);
    }
  }
  return out;
}
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
/* ── dates: one zone, said out loud ────────────────────────────────────
 *
 * Every time on screen is UTC and carries the word "UTC", and every
 * day-precision value is a calendar date with no clock at all.
 *
 * ux05-inspector:dates-shift-a-day and ux19-copy:dates-shift-and-mixed-
 * zones (2026-09-22). The entry forms store a picked day as midnight UTC
 * (`intervalFrom`) because the graph records world time to the day. This
 * file then drew it with `toLocaleString()`, so an analyst in Halifax who
 * entered "valid from 14 December" read back "12/13/2025, 8:00:00 PM": the
 * wrong day, with an invented evening time, on a value that is evidence.
 * Twenty other sites sliced the raw ISO string instead, which is UTC with
 * no label, so the same seed run read 12:18 in the inspector and 15:18 in
 * the Lab. One zone for everything, named on every value, and no browser
 * locale anywhere (the locale also decided M/D against D/M).
 */
const MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun',
                'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];

/** What a missing time reads as. A word, not a dash: a dash in a date
 *  column reads as a rendering fault as often as it reads as "none". */
const NO_TIME = 'not recorded';

/** What any other missing value in a fact or a cell reads as, for the
 *  same reason. The console printed a lone dash for these, and the
 *  owner's copy rule allows no dashes in anything a reader sees (README
 *  screenshot review, 2026-09-23). */
const NO_VALUE = 'not recorded';

function pad2(n) { return String(n).padStart(2, '0'); }

/** An instant, in UTC, labelled: "2026-09-17 15:18 UTC". */
function fmtTime(iso, withSeconds) {
  if (!iso) return NO_TIME;
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return String(iso);
  const clock = pad2(d.getUTCHours()) + ':' + pad2(d.getUTCMinutes())
    + (withSeconds ? ':' + pad2(d.getUTCSeconds()) : '');
  return d.getUTCFullYear() + '-' + pad2(d.getUTCMonth() + 1) + '-'
    + pad2(d.getUTCDate()) + ' ' + clock + ' UTC';
}

/** A calendar day: "14 Dec 2025".
 *
 *  A bare "YYYY-MM-DD" is formatted from its own digits and never goes
 *  through `Date`: `new Date('2025-12-14')` is midnight UTC, and any
 *  local-zone formatting of it west of Greenwich is the 13th. An instant
 *  (or epoch milliseconds, which the timeline passes) gives its UTC day. */
function fmtDate(value) {
  if (value === null || value === undefined || value === '') return NO_TIME;
  const bare = typeof value === 'string'
    && /^(\d{4})-(\d{2})-(\d{2})$/.exec(value);
  if (bare) {
    const m = Number(bare[2]);
    if (m < 1 || m > 12) return value;
    return Number(bare[3]) + ' ' + MONTHS[m - 1] + ' ' + bare[1];
  }
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return String(value);
  return d.getUTCDate() + ' ' + MONTHS[d.getUTCMonth()] + ' '
    + d.getUTCFullYear();
}

/** A stored value that may be day-precision: a day when it sits on a UTC
 *  day boundary, an instant otherwise.
 *
 *  `intervalFrom` writes `valid_from` as 00:00:00Z and an inclusive
 *  `valid_to` as 23:59:59Z, and seeded `observed_at` values are midnight
 *  UTC. Printing "00:00 UTC" on those would be the false precision the
 *  form's own comment refuses. A real observation that happens to fall at
 *  exactly midnight loses only a clock time nobody could tell from a day,
 *  and never the day itself: the "Observed at" field is labelled and read
 *  as UTC (`observedAtUtc`), so a typed 00:00 is 00:00Z on the day typed.
 *  Read in the browser's zone, 17:00 in Los Angeles was 00:00Z the next
 *  day and came back as that day (verifier, fix round, 2026-09-22). */
function fmtWhen(iso) {
  if (!iso) return NO_TIME;
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return String(iso);
  const h = d.getUTCHours(), m = d.getUTCMinutes(), s = d.getUTCSeconds();
  const boundary = (h === 0 && m === 0 && s === 0)
    || (h === 23 && m === 59 && s === 59);
  return boundary ? fmtDate(iso) : fmtTime(iso);
}

/** A validity interval as one phrase, both ends shown.
 *
 *  ux05-inspector:dates-shift-a-day: the edge line printed `valid_from`
 *  alone, so a tie ended with `valid_to` (which the Retire dialog tells
 *  analysts to use) still read as open. */
function fmtInterval(from, to) {
  if (!from && !to) return 'no validity interval recorded';
  if (from && to) return 'valid ' + fmtWhen(from) + ' to ' + fmtWhen(to);
  if (from) return 'valid from ' + fmtWhen(from) + ', no end recorded';
  return 'valid until ' + fmtWhen(to) + ', no start recorded';
}

/** The density timeline's axis labels. Kept as a name because the graph
 *  region calls it; it is now the same UTC day as everything else. */
function fmtDay(ms) { return fmtDate(ms); }
/* The placeholders below say what is missing rather than printing a
   dash: a size or a hash the record does not carry, an account or an
   element with no id, a number that did not arrive as one (README
   screenshot review, 2026-09-23). */
function fmtBytes(n) {
  if (!Number.isFinite(n)) return 'size ' + NO_VALUE;
  const u = ['B', 'KiB', 'MiB', 'GiB'];
  let i = 0, v = n;
  while (v >= 1024 && i < u.length - 1) { v /= 1024; i += 1; }
  return (i === 0 ? v : v.toFixed(1)) + ' ' + u[i];
}
function shortHash(h) { return h ? h.slice(0, 16) + '…' : NO_VALUE; }
function shortId(id) { return id ? id.slice(0, 8) : 'unknown'; }
function num(v, dp) {
  const n = Number(v);
  if (!Number.isFinite(n)) return 'not computed';
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

/* ── a read that failed is not an empty list ───────────────────────────
 *
 * ux17-failure:failure-renders-as-empty-claim (2026-09-22). On a 503 the
 * triage queue said "Nothing awaiting review.", the inbox "Nothing
 * waiting.", the tombstone register "Nothing has been destroyed." and the
 * source list "Every source has been polled." Each of those is a claim
 * about the data, made at the one moment the console knew nothing about
 * it, and the banner that said otherwise was dismissable while the pane
 * kept asserting. The approvals pane already said it right ("They are not
 * known to be absent"); this is that sentence as one shared control, so a
 * failure looks the same in every pane and always offers a retry.
 *
 * The notice is a SIBLING placed just before the pane's empty element,
 * never text written into it. Several empties keep their markup default
 * ("Nothing awaiting review.") and are only ever shown or hidden; writing
 * the failure into one would leave "could not load" standing after the
 * next successful, genuinely empty read. `renderList` clears the notice on
 * every successful render, so panes built on it need no extra call. */

/** Why a read failed, in a few words an analyst can act on. */
function failureReason(err) {
  if (err instanceof ApiError) {
    if (err.status === 0) return 'the API could not be reached';
    if (/re-authentication/i.test(err.detail || '')) {
      return 'your step-up has expired; sign out and back in';
    }
    const said = err.detail || err.title || '';
    return 'HTTP ' + err.status + (said ? ': ' + said : '');
  }
  return err && err.message ? err.message : String(err);
}

/** The sentence the notice says. Built so that the grammatical number of
 *  `what` never matters: "Your notifications was refused" is what a verb
 *  agreeing with a singular subject made of a plural one (verifier, fix
 *  round of 2026-09-22). A refusal names the access, not the list. */
function loadFailureText(what, err) {
  const refused = err instanceof ApiError && err.status === 403;
  const lead = refused
    ? 'Access to ' + what.charAt(0).toLowerCase() + what.slice(1)
      + ' was refused ('
    : what + ' could not be loaded (';
  return lead + failureReason(err)
    + '). Until a read succeeds, this is unknown, not empty.';
}

/** Say in the pane that `what` could not be read, hide the empty state,
 *  and offer `retry`. `what` is a noun phrase, singular or plural: "The
 *  triage queue", "Your notifications". */
function showLoadFailure(emptyId, what, err, retry) {
  const empty = $(emptyId);
  if (!empty) return;
  show(empty, false);
  let box = $(emptyId + '-failed');
  if (!box) {
    box = el('div', 'load-failed');
    box.id = emptyId + '-failed';
    box.setAttribute('role', 'alert');
    empty.parentNode.insertBefore(box, empty);
  }
  clear(box);
  box.appendChild(el('p', 'load-failed-text', loadFailureText(what, err)));
  if (retry) {
    const again = el('button', 'btn small', 'Retry');
    again.type = 'button';
    again.addEventListener('click', () => {
      again.disabled = true;
      Promise.resolve(retry()).finally(() => { again.disabled = false; });
    });
    box.appendChild(again);
  }
  show(box, true);
}

/** Remove the failure notice once a read has succeeded. */
function clearLoadFailure(emptyId) {
  const box = $(emptyId + '-failed');
  if (box) box.remove();
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

/* ── the request indicator ─────────────────────────────────────────────
 *
 * One place, driven by an in-flight counter in `api()`, so every fetch in
 * the app is covered without a single per-pane change. A pane that fetches
 * and shows nothing is indistinguishable from a pane that is broken, and
 * several here fetch four sections independently.
 *
 * Delayed by 180ms before it appears. Most requests against a local
 * Postgres finish in under 30ms, and a bar that flashes on every one is
 * noise that trains people to ignore it — which is exactly what you do not
 * want on the request that takes four seconds.
 */
let _inflight = 0;
let _busyTimer = null;

function _busy(delta) {
  _inflight = Math.max(0, _inflight + delta);
  const bar = $('busy');
  if (!bar) return;                       // login screen: no workspace yet
  if (_inflight > 0) {
    if (_busyTimer === null) {
      _busyTimer = setTimeout(() => { bar.hidden = false; }, 180);
    }
    return;
  }
  if (_busyTimer !== null) { clearTimeout(_busyTimer); _busyTimer = null; }
  bar.hidden = true;
}

/** The readable CSRF cookie, or null when the browser holds none -- which
 *  is also how the console learns that a Secure cookie was refused (plain
 *  HTTP from a non-localhost address) and falls back to the bearer. */
function csrfCookie() {
  for (const part of document.cookie.split(';')) {
    const [k, ...rest] = part.trim().split('=');
    if (k === CSRF_COOKIE) return rest.join('=') || null;
  }
  return null;
}

/* A lapsed session is not signed in, although the app stays on screen
   behind the sign-in sheet (expiry-drops-context, 2026-09-22): the
   palette, the shortcuts and the live reconnect all ask this, and none of
   them should act for a session the server has ended. */
function signedIn() { return !!state.userId && !SESSION.lapsed; }

/** Which credential a request carries, decided in ONE place for `api()`.
 *  The report download used to fetch a blob outside it and does not since
 *  2026-09-22: the file now comes back inside the egress decision's JSON.
 *  The sample download did too once and is not any more either: it
 *  crosses to another origin on a ticket minted through `api()`, and
 *  nothing this function returns would survive that preflight.
 *
 *  Cookie session first: the browser attaches `__Host-session` itself,
 *  and an unsafe method copies the CSRF cookie into the header the server
 *  demands. The in-memory bearer is used only when no CSRF cookie exists
 *  (the browser refused the Secure pair) or when a caller forces it -- the
 *  one forced case is the `#token=` exchange, which must present the NEW
 *  token and not whatever cookie session the tab already had. */
function authHeaders(method, forceBearer) {
  const headers = {};
  if (forceBearer) {
    headers['Authorization'] = 'Bearer ' + forceBearer;
    return headers;
  }
  const csrf = csrfCookie();
  if (csrf) {
    if (!/^(GET|HEAD|OPTIONS)$/i.test(method || 'GET')) headers[CSRF_HEADER] = csrf;
  } else if (state.token) {
    headers['Authorization'] = 'Bearer ' + state.token;
  }
  return headers;
}

async function api(path, options) {
  const o = options || {};
  const headers = authHeaders(o.method || 'GET', o.bearer);
  let body;
  if (o.form) {
    body = o.form;                       // let the browser set the boundary
  } else if (o.json !== undefined) {
    headers['Content-Type'] = 'application/json';
    body = JSON.stringify(o.json);
  }
  _busy(+1);
  try {
    return await _fetch(path, o, headers, body);
  } finally {
    /* `finally`, so a throw cannot strand the indicator on. A busy bar
       that never clears is worse than none: it says the app is working
       when it has given up. */
    _busy(-1);
  }
}

/** The routes whose 401 judges the credential IN THE REQUEST -- a wrong
 *  password, a stale hand-off token -- and says nothing about the session
 *  this tab already holds. `_fetch` ends the session on every other 401.
 *  Until 2026-09-09 only login was here, so a stale `#token=` opened in a
 *  tab with a live cookie pair sent the exchange's 401 through
 *  `endSession`, which deleted the readable CSRF cookie browser-wide and
 *  could not touch the HttpOnly half: every tab was left able to read and
 *  unable to write or sign out. `test_ui_invariants` holds this set to the
 *  routes `routers/auth.py` defines. */
const _CREDENTIAL_CHECKS = new Set(['/auth/login', '/auth/cookie']);

async function _fetch(path, o, headers, body) {
  let res;
  const sentAt = Date.now();
  try {
    /* `same-origin`: the session cookie must travel, and nothing here ever
       talks to another origin (the CSP's connect-src 'self' would refuse
       it anyway). The one cross-origin request, the sample download,
       does not come through here: see `fetchFromSampleOrigin`. */
    res = await fetch(API + path, { method: o.method || 'GET', headers, body,
                                    credentials: 'same-origin' });
  } catch (_e) {
    throw new ApiError(0, 'Cannot reach the API',
      'The request did not complete. Check the API service and your network.');
  }
  /* An answer that is not a 401 (or a rate-limit refusal, which is
     answered before the session is read) means the server accepted the
     session and slid its idle window, so the idle warning restarts. From
     the moment the request left rather than when it came back: the
     server's clock started no later than that. */
  if (res.status !== 401 && res.status !== 429) noteSessionActivity(sentAt);
  if (!res.ok) {
    const p = await problemOf(res);
    const err = new ApiError(res.status, p.title, p.detail);
    if (res.status === 401 && !_CREDENTIAL_CHECKS.has(path)) {
      if (state.userId && !state.booting && path !== '/auth/logout') {
        /* Mid-session (expiry-drops-context, 2026-09-22). This used to
           end the session outright: the app was unmounted, the case
           forgotten, and the banner never said the Save that triggered
           it had not happened. The app now stays mounted under an
           in-place sign-in, and the error says what did not happen, so
           the form that raised it can show that next to itself. */
        const unsafe = !/^(GET|HEAD|OPTIONS)$/i.test(o.method || 'GET');
        sessionLapsed({ cause: 'server', unsafe, detail: p.detail });
        err.title = unsafe ? 'Not saved: your session had ended'
          : 'Not loaded: your session had ended';
        err.detail = unsafe
          ? 'Nothing was saved. Sign in again in the dialog, then repeat this.'
          : 'Sign in again in the dialog, then open this again.';
      } else {
        endSession('Session ended', p.detail || 'Sign in again to continue.');
      }
      err.handled = true;          // the analyst has already been told
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

/** Drop to the sign-in form. Reached from a 401 on any request that is
 *  not a credential check (`_CREDENTIAL_CHECKS`), from a sign-out the
 *  server accepted, and from `startApp` refusing a half session. The
 *  banner is suppressed while booting -- a stale session on first load
 *  is expected, not news -- unless `evenWhileBooting` says the analyst
 *  must hear it, which the half-session refusal does: without the banner
 *  the sign-in form would appear for a session the browser still holds,
 *  with no word on why.
 *
 *  An ending the analyst did not ask for (a title says so; a sign-out
 *  passes none) remembers where they were, for `startApp` to reopen if
 *  the same account signs back in (expiry-drops-context, 2026-09-22). */
function endSession(title, detail, evenWhileBooting) {
  if (title) rememberResume();
  state.token = null;
  state.userId = null;
  state.caseId = null;
  state.caseRec = null;
  /* The readable half is dropped here; the HttpOnly half can only be
     deleted by the server (logout does), and a session that 401'd is
     dead there already. Without this, `csrfCookie()` would keep steering
     requests down the cookie path against a session that is gone. */
  document.cookie = CSRF_COOKIE + '=; Max-Age=0; Path=/; Secure; SameSite=Strict';
  closePalette();
  stopGraph();
  /* Before the view swap. A socket left open on a dead session keeps a
     database connection LISTENing on the server for as long as the tab
     lives, and the reconnect loop would retry against a token that is
     gone — which reads as an attack in the audit log. */
  disconnectLive();
  forgetHeldLive();            // the next analyst inherits no held refetch
  stopSessionClock();
  show($('view-app'), false);
  show($('view-login'), true);
  /* The form as well as its view (final review C19, 2026-09-23). First
     run hides the form under its card, and a 401 between the card's own
     sign-in and the console landed here with the form still hidden: an
     empty page, the caret in a field nobody could see. A first-run card
     still on screen keeps its place; its secrets are its own to keep. */
  if ($('setup-form').hidden && $('setup-done').hidden && $('setup-codes').hidden) {
    show($('login-form'), true);
  }
  /* On first load a stale token is expected, not news — boot() handles it. */
  if (title && (evenWhileBooting || !state.booting)) {
    sessionBanner(title, detail);
  }
  $('login-password').value = '';
  $('login-totp').value = '';
  /* The email is usually still filled in: the password is the next thing
     to type, so that is where the caret goes. */
  ($('login-email').value ? $('login-password') : $('login-email')).focus();
}

/** True when this tab holds a session it cannot drive: the HttpOnly
 *  cookie authenticates reads, but with no readable `__Host-csrf` and no
 *  in-memory token `authHeaders()` has no credential to put on an unsafe
 *  method, so every write is 403 and the server cannot even be asked to
 *  sign out. Reached by any path that deletes the readable half while the
 *  server keeps the session -- until 2026-09-09, a stale `#token=` link
 *  opened in a signed-in tab. Named because two callers must agree on
 *  what "usable" means: `startApp` refuses to show the app on it, and
 *  `adoptSessionFromFragment` treats it as a session the hand-off may
 *  repair rather than one it must keep. */
function halfSession() { return !csrfCookie() && !state.token; }

const HALF_SESSION_TITLE = 'Signed-in session cannot be used';
const HALF_SESSION_DETAIL =
  'This browser holds a session cookie but not its readable CSRF half, so '
  + 'nothing could be saved and the server could not be asked to sign out. '
  + 'Sign in again to set the pair; a bootstrap.py session link for the '
  + 'same account also restores it.';

async function doLogin(event) {
  event.preventDefault();
  const errBox = $('login-error');
  setMsg(errBox, '');
  const btn = $('login-submit');
  btn.disabled = true;
  try {
    await api('/auth/login', {
      method: 'POST',
      json: {
        email: $('login-email').value.trim(),
        password: $('login-password').value,
        totp_code: $('login-totp').value.trim(),
      },
    });
    $('login-password').value = '';
    $('login-totp').value = '';
    /* Nothing comes back and nothing is kept from it. `POST /auth/login`
       has answered 204 with the cookie pair and no body since
       2026-09-10, and `_fetch` returns null for a 204 -- so the
       `state.token = out.token` that stood here threw a TypeError on
       every form sign-in, which `catch` below reported as an unexpected
       error while the server had in fact signed the analyst in and set
       their cookies. Deleted rather than guarded: there is no token in
       that response to guard for.

       Which makes the pair the only thing a form sign-in produces, and
       that is checked BEFORE the app starts. A browser that refused the
       Secure cookies leaves this tab holding nothing at all, and
       `startApp`'s /auth/me would 401 straight into `endSession` --
       "Session ended", a sentence about an expiry, for a session created
       a second ago that the browser will simply not keep. */
    if (!csrfCookie()) {
      banner('Session cookie refused by the browser',
        'This console is served over plain HTTP from a non-localhost '
        + 'address, so the browser refused the Secure session cookies. A '
        + 'sign-in no longer returns a token to fall back on, so this tab '
        + 'holds no credential and nothing was opened. Serve the console '
        + 'over HTTPS, reach it at localhost, or use a '
        + 'scripts/bootstrap.py session link, whose token this tab does '
        + 'keep, for its own life.', 'warn');
      return;
    }
    await startApp();
  } catch (err) {
    inlineProblem(errBox, err);
  } finally {
    btn.disabled = false;
  }
}

async function doLogout() {
  try {
    await api('/auth/logout', { method: 'POST' });
  } catch (err) {
    /* A 401 means the server holds no session to revoke, and `_fetch`
       has already ended this one. Anything else -- the double-submit
       refusing the POST (403) because the readable half is gone, a rate
       limit, an unreachable API -- means the server STILL HOLDS the
       session. Until 2026-09-09 this swallowed every failure and showed
       the sign-in form anyway: a sign-out reported that had not
       happened, and a reload restored the session. */
    if (err && err.handled) return;
    banner('Sign-out refused',
      (err instanceof ApiError ? (err.detail || err.title) : String(err))
      + ' The server still holds this session, so nothing was signed out. '
      + 'Reload the page to re-check it: a session the server has since '
      + 'ended lands on the sign-in form.', 'warn');
    return;
  }
  endSession(null, null);
}

async function startApp() {
  watchPresence();             // once per page: the live channel's idle hold
  const me = await api('/auth/me');
  if (halfSession()) {
    /* The cookie alone answered that read, and the cookie alone is what
       this tab has: see `halfSession`. Showing the app here would render
       every pane and refuse every save with "missing or invalid CSRF
       token", and sign-out with the same. Ended with the banner forced
       through the boot suppression, because the sign-in form for a
       session the browser visibly still holds needs its reason. */
    endSession(HALF_SESSION_TITLE, HALF_SESSION_DETAIL, true);
    const err = new ApiError(0, HALF_SESSION_TITLE, HALF_SESSION_DETAIL);
    err.handled = true;
    throw err;
  }
  state.userId = me.user_id;
  /* `display_name`, not `user_id`. /auth/me carried the id and the
     recovery-code count and nothing else until 2026-09-02, so the app
     bar showed a UUID to every signed-in analyst. The id stays as the
     tooltip because it is what a support request needs. */
  $('hdr-user').textContent = me.display_name || me.user_id;
  $('hdr-user').title = me.email
    ? me.email + ' \u00b7 ' + me.user_id : me.user_id;
  /* Session bookkeeping (2026-09-22): the account the Account sheet and
     the in-place sign-in are about, the clock the idle warning counts
     against, and the case to reopen when this is the same analyst coming
     back from an expiry. A "Session ended" banner is about the session
     that just got replaced, so it goes. */
  adoptSessionFacts(me);
  applyResume(me.user_id);
  clearSessionBanners();
  /* Whoever signed in, no one-time secret shown to the session before
     theirs is on the screen they get. `endSession` clears them too, but
     the in-place sign-in comes straight here, without it, when the
     account differs (final review C4, 2026-09-23). Nor a live change
     held for it (C20): this session starts on the case list and loads
     whatever it opens in full. */
  clearSessionSecrets();
  forgetHeldLive();
  show($('view-login'), false);
  /* The sign-in view back to its own default, for the next time it
     shows. First run hides the form under its card (`probeFirstRun`) and
     the card's sign-in comes straight here, so the first sign-out after
     a first run showed an empty page (final review C19, 2026-09-23). */
  show($('login-form'), true);
  show($('view-app'), true);
  await showCaseList();
}

/* ── case-switch resets ───────────────────────────────────────────────── */

/* Every pane that shows case-scoped data registers a reset here, in its
 * OWN region of this file, and both ways of leaving a case run them all.
 *
 * The review of 2026-09-22 found six panes (search, report, collected,
 * the deception detail, and any pane whose read failed after a switch)
 * still showing the previous case's results under the new case's header
 * and TLP chip. Each had the same cause: openCase reset the state it knew
 * about and nothing else. A registry turns "remember to add your pane to
 * openCase" into a line each pane owns next to the code it resets.
 *
 * `state.caseSeq` also increments on every switch. An async read takes a
 * token before it awaits and drops its result when `caseChanged(token)`
 * says so. Comparing `state.caseId` alone (the older guard at
 * loadCaseTags) misses A -> B -> A: the stale reply from the first visit
 * to A lands on the second, because the id matches again. */
const CASE_SWITCH_RESETS = [];

function onCaseSwitch(fn) { CASE_SWITCH_RESETS.push(fn); }

function runCaseSwitchResets() {
  state.caseSeq = (state.caseSeq || 0) + 1;
  for (const fn of CASE_SWITCH_RESETS) {
    /* One pane's broken reset must not leave every later pane showing
       the old case, which is the failure this exists to prevent. */
    try { fn(); } catch (err) { console.error('case-switch reset failed', err); }
  }
}

function caseToken() { return state.caseSeq || 0; }

function caseChanged(token) { return token !== (state.caseSeq || 0); }

/* The case file itself: entities, relationships, exhibits, the ACH matrix
 * and the timeline drawn from them.
 *
 * ux17-failure:stale-previous-case-data (2026-09-22). openCase reset the
 * projection and never these, so one failed read during a case open left
 * NIGHTJAR's 146 entities, its exhibits and its hypotheses on screen under
 * KESTREL's code and a TLP:GREEN chip, and the new-edge pickers offered
 * NIGHTJAR's entities for a write into KESTREL. Emptied here, BEFORE the
 * fetches, so a failure leaves nothing rather than the previous case; the
 * loaders then say "could not be loaded" instead of drawing an empty list.
 * The DOM is cleared rather than re-rendered from the empty state because
 * a render would print "0 of 0 entities", which is a claim about a case
 * nobody has read yet. */
onCaseSwitch(() => {
  state.nodes = [];
  state.edges = [];
  state.evidence = [];
  state.ach = null;
  state.achPick = [];
  state.assertionMeta = new Map();
  state.timeSpan = null;
  state.timePoints = [];

  clear($('ent-body'));
  $('ent-count').textContent = '';
  $('ent-filter').value = '';
  show($('ent-empty'), false);
  clearLoadFailure('ent-empty');

  clear($('ev-list'));
  show($('ev-empty'), false);
  clearLoadFailure('ev-empty');

  /* And what was chosen or typed for the case being left (final review
     C18, 2026-09-23). A file picked and titled on NIGHTJAR stayed in the
     form, and Lodge after a switch wrote it into KESTREL as a WORM exhibit
     with a custody record, filed at KESTREL's own classification because
     buildPickers resets #ev-class. Nothing can withdraw that write, so the
     form goes with the case, the way the comms reset clears a paste.
     Setting a file input's value to '' is the one way to empty it. */
  $('ev-file').value = '';
  $('ev-title').value = '';
  setMsg($('ev-result'), '');
  setMsg($('ev-error'), '');

  /* The write pickers too: they offered the previous case's entities and
     exhibits for a write into this one. The loaders refill them; until
     they do (or if they fail) there is nothing to pick. */
  clear($('edge-src'));
  clear($('edge-dst'));
  for (const id of ['node-evidence', 'edge-evidence']) {
    opts($(id), [['', 'Exhibits not loaded for this case']], '');
  }

  clear($('ach-ranking'));
  clear($('ach-matrix'));
  clear($('ach-warnings'));
  $('ach-counts').textContent = '';
  $('ach-method').textContent = '';
  show($('ach-empty'), false);
  clearLoadFailure('ach-empty');
  /* A hypothesis or an assumption worded for one case is a claim about
     that case; added after a switch it lands in the other's matrix and
     register (C18). */
  $('ach-statement').value = '';
  setMsg($('ach-msg'), '');
  $('asm-statement').value = '';
  $('asm-basis').value = '';
  setMsg($('asm-msg'), '');

  /* The density strip: NIGHTJAR's "638 elements over 949 days" stood next
     to KESTREL's projection in the ux17 captures. */
  $('tl-note').textContent = '';
  $('tl-min').textContent = '';
  $('tl-max').textContent = '';
  drawDensity();
});

/* ── the case's lifecycle state, inside the workspace ───────────────────
 *
 * ux02-cases:case-status-invisible-in-workspace (2026-09-22). The status
 * was shown on the case list and nowhere else, so an analyst who arrived
 * by the palette, a deep link or habit could not tell a CLOSED case from
 * an ACTIVE one: the canvas still said "add an entity to begin" and the
 * Add entity form was offered with no notice. Material added after
 * closed_at matters for disclosure. The server does not refuse such
 * writes yet, so the console has to say it, every time, in the chrome
 * that every pane shares. */
const CASE_STATE_TEXT = {
  DRAFT: 'This case is a DRAFT. It has not been opened for work, so '
    + 'anything added now predates the case formally starting. Move it to '
    + 'ACTIVE before working it.',
  DORMANT: 'This case is DORMANT. It was put to sleep; reactivate it before '
    + 'adding material, so the record shows when work resumed.',
  CLOSED: 'This case is CLOSED. It is kept for the record and is not taking '
    + 'new material: anything added now postdates the close, which matters '
    + 'for disclosure. Reopen it first if the work is genuinely resuming.',
  ARCHIVED: 'This case is ARCHIVED. It is a record, not a workspace, and '
    + 'nothing should be added to it.',
  PURGED: 'This case is PURGED. Its material is marked for destruction and '
    + 'nothing should be added to it.',
};

/** States in which the case is not taking new work. */
const CASE_STATES_SHUT = new Set(['CLOSED', 'ARCHIVED', 'PURGED']);

let graphEmptyOpen = null;       // the markup's own "add an entity" copy

function renderCaseState(rec) {
  const chip = $('hdr-state');
  const strip = $('case-state-strip');
  const graphEmpty = $('graph-empty');
  if (graphEmptyOpen === null) graphEmptyOpen = graphEmpty.textContent.trim();
  if (!rec) {
    show(chip, false);
    show(strip, false);
    graphEmpty.textContent = graphEmptyOpen;
    return;
  }
  const status = rec.status || 'UNKNOWN';
  const active = status === 'ACTIVE';
  /* closed_at survives a reopen (only the move to CLOSED stamps it), so it
     is stated only while the case is shut; on a reopened-then-dormant case
     it would date a close that no longer applies. */
  const closed = CASE_STATES_SHUT.has(status) && rec.closed_at
    ? fmtTime(rec.closed_at) : '';
  chip.className = 'chip case-state case-state-' + status
    + (active ? '' : ' case-state-off');
  chip.textContent = status;
  chip.title = active
    ? 'Case status: ACTIVE.'
    : 'Case status: ' + status + (closed ? ', closed ' + closed : '')
      + '. Status… in this bar changes it.';
  show(chip, true);

  const says = CASE_STATE_TEXT[status];
  if (!active && says) {
    $('case-state-text').textContent = says
      + (closed ? ' Closed ' + closed + '.' : '');
    strip.className = 'case-state-strip'
      + (CASE_STATES_SHUT.has(status) ? ' shut' : '');
    show(strip, true);
  } else {
    show(strip, false);
  }
  /* The canvas's empty state is the other place that invited new work. */
  graphEmpty.textContent = active ? graphEmptyOpen
    : 'Nothing in this projection. This case is ' + status
      + ', so it is not open for new material.';
}

/* ── case list ────────────────────────────────────────────────────────── */

async function showCaseList() {
  runCaseSwitchResets();
  state.caseId = null;
  state.caseRec = null;
  stopGraph();
  show($('view-workspace'), false);
  show($('view-cases'), true);
  show($('btn-cases'), false);
  show($('hdr-tlp'), false);
  show($('hdr-asof'), false);
  renderCaseState(null);
  $('hdr-case').textContent = 'No case selected';
  try {
    state.cases = await api('/cases');
    renderCases();
    /* A `#case=` deep link opens straight through the list. Consumed once,
       so "All cases" is not a button that bounces you back where you came
       from. */
    const wanted = state.deepLinkCase;
    state.deepLinkCase = null;
    if (wanted && state.cases.some((c) => c.id === wanted)) openCase(wanted);
    /* `#tab=admin` with no case opens Administration from the list: it is
       deployment-wide, and the deep link was honoured only inside a case
       (ux16 admin-unreachable-without-a-case, 2026-09-22). */
    else if (!wanted && state.deepLinkTab === 'admin') {
      state.deepLinkTab = null;
      showAdmin();
    }
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
  runCaseSwitchResets();
  /* An open that a newer switch has overtaken must stop, not finish. Left
     running, a slow open of case A could write A's code and TLP into the
     header after case B had drawn, which is the shape of
     case-switch-carries-previous-case-results (2026-09-22) arriving by a
     race instead of by omission. */
  const token = caseToken();
  /* Nor does the previous case's header stand while this one loads: until
     the record arrives the bar names what is being opened, with no TLP
     chip, because the old chip over reset panes is a marking for nothing
     on screen. */
  const listed = (state.cases || []).find((c) => c.id === caseId);
  const openingCode = listed ? listed.code : 'case';
  $('hdr-case').textContent = 'Opening ' + openingCode + '…';
  show($('hdr-tlp'), false);
  renderCaseState(null);
  state.caseRec = null;
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
  /* The trend names ONE actor. Left standing across a case switch it would
     chart case A's person under case B's header. */
  state.analyticsHistory = null;
  state.analyticsHistoryNode = null;
  state.analyticsHistoryLabel = '';
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
    if (caseChanged(token)) return;
    state.caseRec = rec;
    state.ontology = ontology;
    state.nodeTypeMeta = new Map(ontology.node_types.map((t) => [t.key, t]));
    $('hdr-case').textContent = rec.code + ' · ' + rec.title;
    const tlp = $('hdr-tlp');
    tlp.className = 'chip tlp-' + rec.classification;
    tlp.textContent = 'TLP:' + rec.classification;
    show(tlp, true);
    renderCaseState(rec);
    show($('btn-cases'), true);
    show($('btn-case-edit'), true);
    show($('btn-case-share'), true);
    show($('btn-case-status'), true);
    show($('hdr-asof'), true);
    show($('view-cases'), false);
    show($('view-workspace'), true);
    buildPickers();
    /* The tag vocabulary, once per case rather than per selection. Not
       awaited: the inspector's tag chips come from the node's own tags and
       render without it; only the "apply an existing tag" picker depends
       on this, and blocking the whole case open on a curation read would
       be the wrong trade. */
    loadCaseTags();
    renderInspector();
    /* Presets and the saved layout must land before the first projection
       fetch: the layout seeds node positions, and re-seeding after the fact
       would visibly reshuffle a picture the analyst already knows. */
    await Promise.all([loadPresets(), loadLayout()]);
    if (caseChanged(token)) return;
    buildProjectionControls();
    renderProjectionBar();     // the parameters are on screen before the data
    await loadCaseGraph();
    if (caseChanged(token)) return;
    await refreshSociogram();
    if (caseChanged(token)) return;
    await loadEvidence();
    if (caseChanged(token)) return;
    // The badge is the only signal that work is waiting, so the
    // queue is counted on open rather than on first visit.
    await loadTriage();
    if (caseChanged(token)) return;
    await refreshInboxBadge();
    if (caseChanged(token)) return;
    /* Not awaited: an analyst without `sample.read` will 403 on it, and
       neither the wait nor the failure should delay a workspace that is
       otherwise ready. The badge counts THIS case's waiting samples since
       2026-09-22 (ux13-lab:lab-not-case-scoped) and drops a reply that
       lands after a later case switch. */
    refreshSampleBadge();
    /* After the first full load, so an event arriving mid-boot cannot
       race the initial fetch and redraw a half-built workspace. */
    connectLive();
    selectTab('graph');
    // After the graph, so a deep-linked pane lands on a workspace that is
    // already populated rather than one still fetching.
    applyDeepLinkTab();
  } catch (err) {
    if (caseChanged(token)) return;
    /* The record itself could not be read: say so in the bar rather than
       leaving "Opening…" there as if it were still on its way. */
    if (!state.caseRec) $('hdr-case').textContent = 'Could not open ' + openingCode;
    fail(err);
  }
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
  /* A canvas in a hidden pane has clientWidth 0, so it has to be sized on
     the way in or the trend draws into nothing and reads as "no data". */
  if (name === 'analytics') { resizeHistory(); loadLatestAnalysis(); }
  if (name === 'triage') { loadTriage(); loadApprovals(); }
  if (name === 'admin') { loadAdminUsers(); loadReadiness(); }
  /* Platforms are reference data: fetched once, on first use, so the
     workspace does not pay for a tab nobody opened. */
  if (name === 'comms') {
    loadCommsPlatforms().catch(fail);
    /* The unverified queue loads with the pane; co-participation does NOT.
       It is a projection over every conversation in the case and belongs
       behind a button for the same reason the report does. */
    loadUnverified();
  }
  if (name === 'inbox') { loadInbox(); loadInboxPreferences(); }
  /* Only the visible subtab loads. Four fetches on tab-open would mean
     three of them are for a panel nobody is looking at, and one of those
     three is a rate-limited search. */
  if (name === 'ach') { loadAch(); loadAssumptions(); }
  if (name === 'feeds' && selectFeedsSub) selectFeedsSub(currentSub('pane-feeds'));
  if (name === 'governance' && selectGovSub) {
    selectGovSub(currentSub('pane-governance'));
  }
  if (name === 'samples' && selectSamplesSub) {
    /* The policy banner loads on every visit, not once: whether ingest is
       lawfully permitted is the first thing this pane has to say, and a
       cached "declared" after somebody unset the variable would be the
       worst possible stale value. */
    loadSamplePolicy();
    selectSamplesSub(currentSub('pane-samples'));
  }
  if (name === 'deception' && selectDeceptionSub) {
    selectDeceptionSub(currentSub('pane-deception'));
  }
}

/** Which subtab is selected in a pane, so re-entering it reloads THAT one
 *  rather than snapping back to the first. */
function currentSub(paneId) {
  const on = $(paneId).querySelector('.subtab[aria-selected="true"]');
  return on ? on.dataset.subtab : null;
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
  const token = caseToken();
  try {
    const [nodes, edges] = await Promise.all([
      api(cpath('/nodes?limit=1000')),
      api(cpath('/edges?limit=1000&include_inferred=true')),
    ]);
    /* A reply for a case the analyst has since left is dropped, never
       drawn under the new header (ux17-failure, 2026-09-22). */
    if (caseChanged(token)) return;
    clearLoadFailure('ent-empty');
    /* Sanitised HERE, at the boundary, not at the twenty-five places a
       label is drawn. An IDENTITY node's label IS a forum handle — the
       analyst pastes it — so it is attacker-chosen, and a bidi override in
       one would silently flip how that actor reads in the sociogram, the
       entity table, the palette, the inspector and every analytics
       summary. One of those sites will always be the one somebody forgets.
       `label_raw` keeps the original for any path that needs the true
       bytes; nothing currently does. */
    state.nodes = nodes.map(withSafeLabel);
    state.edges = edges;
    buildEntityFilter();
    renderEntities();
    buildEdgePickers();
    computeTimeSpan();
    renderScrubber(true);
  } catch (err) {
    if (caseChanged(token)) return;
    /* Not an empty case: an unread one. The entity list says so with a
       retry, and the timeline does not claim "no temporal data" about
       elements it never received. */
    showLoadFailure('ent-empty', "This case's entities and relationships",
      err, reloadAll);
    $('tl-note').textContent = 'The case could not be read, so its timeline '
      + 'is unknown rather than empty.';
    fail(err);
  }
}

/** Reload everything a write could have changed. */
async function reloadAll() {
  await loadCaseGraph();
  await refreshSociogram();
}

/* ── projection: the only thing a metric is ever computed against ─────── */

async function loadPresets() {
  /* Token-guarded like loadLayout below (final review U15, 2026-09-23):
     openCase checks the case only after both land, and by then an older
     case's reply has already written the shared state. */
  const token = caseToken();
  try {
    const out = await api(cpath('/graph/presets'));
    if (caseChanged(token)) return;
    state.presets = out.presets || [];
  } catch (err) {
    if (caseChanged(token)) return;
    /* Without presets the projection selector cannot be honest about what it
       is filtering, so fall back to the one preset whose meaning is not in
       doubt and say so. */
    state.presets = [{ key: 'all', label: 'All ties',
                       description: 'Preset list unavailable. This is the ' +
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
    ['LOW', 'LOW and above'],
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
  gq.set('limit', String(state.nodeLimit));
  let g;
  try {
    g = await api(cpath('/graph?' + gq.toString()));
  } catch (err) {
    /* Only the newest request may raise a banner: an older one, including
       one for the case the analyst has left (the canvas reset below takes
       a number too), failing inside the next case is noise about nothing
       on screen (final review C16, 2026-09-23). */
    if (seq === state.graphSeq) fail(err);
    return;
  }
  if (seq !== state.graphSeq) return;

  /* The projection is a second fetch of the same labels, so it needs the
     same boundary treatment as `loadCaseGraph` — the sociogram canvas is
     the single most consequential place a flipped handle could sit. */
  state.gnodes = (g.nodes || []).map(withSafeLabel);
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
    state.metricsNote = 'metrics unavailable (' + why + '), so nodes are sized by ' +
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
  /* A run or a stored-run read still in flight was started under the old
     projection, so it is retired even when nothing is on screen yet: it
     returned early here, and the reply drew the old projection's numbers
     under the new one (final review C3, 2026-09-23). */
  if (!state.analytics && !state.analyticsRunning) {
    state.analyticsGen = (state.analyticsGen || 0) + 1;
    return;
  }
  blankAnalytics(
    'The projection changed. Run the analysis again to recompute against it.');
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
    'unevidenced ties carry a hollow bead at their midpoint while ' +
    '"Mark unevidenced" is on.';
}

/** The always-visible projection panel. docs/03: "Show the projection
 *  parameters next to the results, always." */
function renderProjectionBar() {
  const preset = state.presetMap.get(state.proj.preset);
  const desc = $('preset-desc');
  desc.textContent = preset
    ? preset.label + ': ' + preset.description
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
    ? countOf(state.graph.nodes.length, 'node', 'nodes') + ', '
      + countOf(state.graph.links.length, 'edge', 'edges')
    : '0 nodes';
  box.appendChild(el('span', null, '  │  drawn: ' + drawn));

  if (state.metrics) {
    box.appendChild(el('span', null,
      '  │  metrics over ' + countOf(state.metrics.node_count, 'node', 'nodes')
      + ', ' + countOf(state.metrics.edge_count, 'edge', 'edges') + ' · density ' +
      num(state.metrics.density, 4)));
  } else {
    box.appendChild(el('span', 'rd-warn', '  │  metrics unavailable'));
  }
  if (state.projTruncated) {
    box.appendChild(el('span', 'rd-warn',
      '  │  TRUNCATED at ' + state.nodeLimit + ' nodes. Narrow the projection ' +
      'before reading anything off this picture'));
    /* The way OUT of the truncation, offered where the truncation is
       reported. Until 2026-07-26 this notice was a dead end: the console
       was hard-capped at 800 while the API served up to 5,000, so an
       analyst told to "narrow the projection" had no alternative even when
       the whole case would have fitted.
       The warning stays regardless — raising the ceiling and still hitting
       it is exactly when somebody most needs to know the picture is
       partial. */
    const next = NODE_PAGE_STEPS.find(function (n) { return n > state.nodeLimit; });
    if (next) {
      const more = el('button', 'btn ghost small', 'show up to ' + next);
      more.type = 'button';
      more.title = 'Re-fetch with a higher node ceiling. Layout is a ' +
                   'force-directed simulation; larger projections take ' +
                   'longer to settle.';
      more.addEventListener('click', function () {
        state.nodeLimit = next;
        refreshSociogram();
      });
      box.appendChild(more);
    }
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
      '  │  INCOMPLETE: ' + detail + ' and are not on this canvas. ' +
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
    /* Three states, not two. `null` is "the recompute failed, so nobody
       knows" — distinct from `false`, which is a real finding about the
       graph. Collapsing them is how a failure becomes an assertion. */
    const verdict = state.focus.connected === null
      ? ' · CONNECTIVITY UNKNOWN: the recompute failed'
      : state.focus.connected
        ? ' · ' + state.focus.hops + ' hops'
        : ' · NOT CONNECTED in this projection';
    text.textContent = 'FOCUS · path ' + labelOf(state.focus.src) + ' → ' +
      labelOf(state.focus.dst) + verdict;
    flag.title = state.focus.connected === null
      ? 'The path could not be recomputed for this projection. Whether '
        + 'these two are connected is UNKNOWN. This is NOT a finding that '
        + 'they are unconnected. Change the projection, or press Escape and '
        + 'shift-click them again.'
      : 'Shortest path, treated as undirected. The path endpoint does '
        + 'not take an as-of parameter, so the path is traced against the '
        + 'latest state of the projection even when the scrubber is in the '
        + 'past.';
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
        'edges, may connect them, and whether it does is itself a finding.',
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
  } catch (err) {
    if (seq !== state.graphSeq) return;
    /* This swallowed the error and cleared only the highlight, leaving
       `state.focus.connected` and `.hops` holding the verdict from the
       PREVIOUS projection — which `renderFocusFlag` then kept printing
       against the new one. So after a failed recompute the flag went on
       asserting "· 3 hops" for a projection where nothing had computed a
       path, and the canvas showed no path at all: two contradictory
       claims, neither of them labelled.

       The inverse is worse. If the earlier answer was NOT CONNECTED and
       the new projection would have connected them, the flag kept saying
       NOT CONNECTED — a false negative on the one question the control
       exists to answer.

       Connectivity is now explicitly UNKNOWN, which is a third state and
       the honest one. The focus itself is KEPT (unlike the ego branch,
       which drops it): the two endpoints are still in the projection, the
       analyst chose them, and throwing that away on a transient 500 costs
       them the selection for no reason. */
    state.focus.connected = null;
    state.focus.hops = null;
    state.pathIds = null;
    fail(err);
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
    /* Blank, as they are before a case opens, rather than a dash at each
       end: the note between them says there is no axis to label (README
       screenshot review, 2026-09-23). */
    $('tl-min').textContent = '';
    $('tl-max').textContent = '';
    $('tl-current').textContent = 'as-of: now';
    $('tl-note').textContent = 'No temporal data in this case yet: nothing ' +
      'carries a valid-from, first-seen or last-seen time, so there is no ' +
      'history to play through. The strip switches on as soon as one element ' +
      'does.';
    range.setAttribute('aria-valuetext', 'unavailable: no temporal data');
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
  tlCtx.fillStyle = PAINT.surface2;
  tlCtx.fillRect(0, 0, w, h);

  const span = state.timeSpan;
  if (!span || span.max <= span.min) {
    tlCtx.strokeStyle = PAINT.grid;
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
  tlCtx.fillStyle = PAINT.accentDim;
  for (let i = 0; i < buckets; i += 1) {
    if (!counts[i]) continue;
    const bh = Math.max(2, (counts[i] / peak) * (h - 4));
    tlCtx.fillRect(i * bw + 0.5, h - bh, Math.max(1, bw - 1), bh);
  }
  tlCtx.strokeStyle = PAINT.grid;
  tlCtx.lineWidth = 1;
  tlCtx.beginPath();
  tlCtx.moveTo(0, h - 0.5);
  tlCtx.lineTo(w, h - 0.5);
  tlCtx.stroke();

  const x = (posFromAsOf() / 1000) * w;
  tlCtx.strokeStyle = state.proj.as_of ? PAINT.alert : PAINT.accent;
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
 * THE ENCODING RULES (docs/06). These do not bend:
 *   node size    chosen centrality metric (the select says which)
 *   node colour  node type: the body, and a type ring inset inside the disc
 *   node opacity confidence and nothing else. The body takes the theme's
 *                --canvas-node-body-* step, ring and core take --conf-*,
 *                at every radius. No tie in the projection = the LOW step.
 *   node shape   body + core = evidenced; hollow (--void inside the ring,
 *                no core) = rests on no exhibit (E2)
 *   state rings  OUTSIDE the node and 3px clear of it: unreviewed proposal,
 *                selected, pinned, path anchor, ego centre (STATE_RINGS)
 *   edge colour  sign: green positive, red negative, grey neutral
 *   edge width   weight, LOG-scaled over the projection's own range
 *   edge style   solid = asserted, DASHED = inferred. Never negotiable.
 *   edge bead    a hollow bead at the midpoint = rests on no exhibit (E2)
 *   parallel     two ties on one pair bow apart, so each can be seen and hit
 */

const canvas = $('graph-canvas');
const ctx = canvas.getContext('2d');
const reduceMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
const cssVar = (name) =>
  getComputedStyle(document.documentElement).getPropertyValue(name).trim();

const PAINT = {};
/* The constant part of the ground (--void plus the key light), painted
   once per canvas size into an offscreen canvas and blitted each frame.
   See buildGround. */
const GROUND = { canvas: null };

/* Painters below read PAINT directly and carry NO literal fallback. A
   token that does not resolve must be a visible, reported fault -- not a
   silent reversion to whichever palette happened to be hard-coded at the
   call site. `cssVar` returns '' for an undefined custom property, so an
   empty string here is the whole signal. */
function paintIsComplete() {
  const missing = [];
  for (const [k, v] of Object.entries(PAINT)) {
    if (typeof v === 'string' && v === '') missing.push(k);
    if (typeof v === 'number' && !Number.isFinite(v)) missing.push(k);
  }
  for (const [k, v] of Object.entries(PAINT.hues || {})) {
    if (v === '') missing.push('hues.' + k);
  }
  for (const [k, v] of Object.entries(PAINT.conf || {})) {
    if (!Number.isFinite(v)) missing.push('conf.' + k);
  }
  for (const [k, v] of Object.entries(PAINT.body || {})) {
    if (!Number.isFinite(v)) missing.push('body.' + k);
  }
  if (missing.length) {
    console.error('theme tokens did not resolve: ' + missing.join(', ') +
                  '. The canvas will paint with the browser default, '
                  + 'which is the intended loud failure.');
  }
  return missing.length === 0;
}

function loadPaint() {
  PAINT.void = cssVar('--void');
  PAINT.surface2 = cssVar('--surface-2');
  PAINT.hairline = cssVar('--hairline');
  PAINT.grid = cssVar('--chart-grid');
  PAINT.canvasGrid = cssVar('--canvas-grid');
  PAINT.canvasKeylight = cssVar('--canvas-keylight');
  PAINT.canvasKeylightOut = cssVar('--canvas-keylight-out');
  PAINT.pos = cssVar('--sign-positive');
  PAINT.neg = cssVar('--sign-negative');
  PAINT.neu = cssVar('--sign-neutral');
  PAINT.accent = cssVar('--accent');
  PAINT.accentDim = cssVar('--accent-dim');
  PAINT.alert = cssVar('--alert');
  PAINT.label = cssVar('--text-secondary');
  PAINT.dim = cssVar('--text-tertiary');
  PAINT.bright = cssVar('--text-primary');
  PAINT.monoFont = '10px ' + (cssVar('--mono') || 'monospace');
  /* Sociogram labels. 11px, the bottom of docs/06's type scale: the
     restyle drew them at 10px, which is on no scale at all
     (cr02 docs-describe-old-canvas, 2026-09-22). Mono because a handle
     is an identifier and analysts compare them character by character. */
  PAINT.labelFont = '11px ' + (cssVar('--mono') || 'monospace');
  PAINT.signFont = '600 13px ' + (cssVar('--mono') || 'monospace');
  /* Label strength is a theme number for the same reason the confidence
     steps are: test_theme_contract composites it and holds it to 4.5:1. */
  PAINT.labelAlpha = parseFloat(cssVar('--canvas-label-alpha'));
  /* Confidence is opacity (docs/06), and the three steps are theme
     tokens, so the canvas reads the same numbers the DOM's `.conf-*`
     rules apply. The sociogram carried its own 1 / 0.72 / 0.45 until
     2026-09-11: the theme had raised --conf-low to 0.58 for contrast
     and the canvas never noticed, so the inspector said one opacity
     and the edge was drawn at another. */
  PAINT.conf = {
    HIGH: parseFloat(cssVar('--conf-high')),
    MODERATE: parseFloat(cssVar('--conf-moderate')),
    LOW: parseFloat(cssVar('--conf-low')),
  };
  /* The node BODY's alpha, one per confidence step, also from the theme.
     The restyle multiplied confAlpha by a 0.40 literal here and switched
     that off below a 5px radius, so a node's apparent certainty moved
     with its size and with the zoom (cr01 ring-threshold-borrows-
     opacity-channel, cr02 node-opacity-follows-size-not-confidence,
     2026-09-22). These are steps in their own right, not a multiplier,
     and theme.css holds HIGH against LOW to 2:1 for every node hue. */
  PAINT.body = {
    HIGH: parseFloat(cssVar('--canvas-node-body-high')),
    MODERATE: parseFloat(cssVar('--canvas-node-body-moderate')),
    LOW: parseFloat(cssVar('--canvas-node-body-low')),
  };
  PAINT.hues = {};
  for (const h of ['actor-persona', 'actor-person', 'actor-group',
                   'artefact-infra', 'artefact-finance', 'artefact-malware',
                   'context']) {
    PAINT.hues[h] = cssVar('--' + h);
  }
  paintIsComplete();
  buildGround();
  if (state.graph) state.graph.labelW = new Map();
}

/** Swap what the canvas is showing. Positions survive: a node already on
 *  screen keeps its coordinates, so entering and leaving a focus does not
 *  rearrange the entities that were in both pictures. */
function setRendered(nodes, edges, options) {
  const o = options || {};
  const prevGraph = state.graph;
  const prev = prevGraph ? prevGraph.index : null;
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
  const pairs = new Map();
  /* The OBSERVED weight range, not 0..max(1, heaviest). The seeded
     weights are 0..1 ratios, so a floor of 1 left the bottom half of the
     width ramp unreachable and put the whole flagship case inside one
     pixel (cr01 edge-width-range-under-a-pixel, 2026-09-22). */
  let minWeight = Infinity, maxWeight = -Infinity;
  for (const e of edges) {
    const a = index.get(e.src_node_id), b = index.get(e.dst_node_id);
    if (!a || !b) continue;             // endpoint above the caller's clearance
    a.deg += 1; b.deg += 1;
    const wgt = Math.max(0, Number(e.weight) || 0);
    if (wgt < minWeight) minWeight = wgt;
    if (wgt > maxWeight) maxWeight = wgt;
    /* p and q are the pair in a fixed order, whatever the tie's
       direction, so a reciprocal A->B and B->A bow to opposite sides
       rather than both to the same one. */
    const fwd = String(a.id) < String(b.id);
    const link = { ref: e, a: a, b: b, p: fwd ? a : b, q: fwd ? b : a, bend: 0 };
    links.push(link);
    if (a !== b) {
      const k = pairKey(a.id, b.id);
      if (!pairs.has(k)) pairs.set(k, []);
      pairs.get(k).push(link);
    }
  }
  /* Parallel ties. The model records disagreement as separate edges
     ("two analysts, two claims, both recorded"), and drawn as straight
     lines between the same two centres only the last one painted could be
     seen and only the first one listed could be clicked: a red dispute
     opened as a green vouch (ux05 parallel-ties-unreachable, 2026-09-22).
     Each tie on a pair now gets its own bow, centred on the chord. */
  for (const group of pairs.values()) {
    if (group.length < 2) continue;
    group.forEach((l, i) => { l.bend = i - (group.length - 1) / 2; l.pair = group; });
  }
  if (!Number.isFinite(minWeight)) { minWeight = 0; maxWeight = 0; }
  /* Entities with no tie in THIS projection. They are laid out on a shelf
     beside the connected graph (shelveIsolates) instead of being flung
     outward by repulsion, which is what put OP-NIGHTJAR-26's 46 wallets
     and hosts 3,000 units from everything else. */
  const loose = simNodes.filter((n) => n.deg === 0)
    .sort((x, y) => String(x.ref.node_type).localeCompare(String(y.ref.node_type))
      || String(x.ref.label || '').localeCompare(String(y.ref.label || '')));
  /* `revealed` is carried over, not reset. It records which selection the
     view has already been brought to, and a new graph object is not a new
     selection: resetting it made every re-render (a scrubber step, a
     projection change, a path highlight) pan the view back to an entity
     the analyst had deliberately panned away from. */
  state.graph = { nodes: simNodes, links: links, index: index,
                  minWeight: minWeight, maxWeight: maxWeight,
                  live: simNodes.filter((n) => n.deg > 0), loose: loose,
                  shelf: null, labelW: new Map(),
                  revealed: prevGraph ? prevGraph.revealed : null,
                  labelsDrawn: 0, labelsWanted: 0, settled: false,
                  alpha: 1, drag: null, raf: 0 };
  shelveIsolates(state.graph);
  show($('graph-empty'), simNodes.length === 0);
  /* keepView means "the analyst is still looking at the same thing": a
     path highlight or an ego refresh must not move the viewport.
     Otherwise a view that is still the FIT stays the fit. A projection
     change that strips ties moves entities onto the shelf, and with the
     old one-shot fit 'HIGH only' on OP-NIGHTJAR-26 left 70 of 146 of them
     off the canvas (ux03 minconf-isolates-full-opacity, 2026-09-22). Once
     the analyst pans or zooms (takeView), the view is theirs and no
     render re-fits it; the canvas note counts what is outside instead. */
  if (o.keepView) state.needFit = false;
  else if (state.viewFitted) state.needFit = true;
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
  /* Only the connected entities are simulated. The unconnected ones sit
     on the shelf, and repulsion from them would push the graph about for
     no structural reason. */
  const ns = g.live;
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
  /* The worker lays out the CONNECTED entities only. ForceAtlas2's
     gravity is constant in distance, so an entity with no tie had nothing
     to balance repulsion from the whole graph and drifted until the
     iteration cap ran out: about 3,500 world units on OP-NIGHTJAR-26,
     which is why Fit could not frame the flagship case (ux03 fit-cannot-
     fit-flagship, ux04 fit-cannot-frame-flagship, 2026-09-22). */
  const live = g.live;
  if (live.length < LAYOUT_WORKER_MIN_NODES) return false;
  try {
    stopWorkerLayout();
    state.layoutWorker = new Worker('layout-worker.js');
  } catch (_e) {
    // A blocked or unavailable worker must degrade to the old path, not
    // leave the analyst with a graph that never lays out.
    state.layoutWorker = null;
    return false;
  }
  const index = new Map(live.map((n, i) => [n.id, i]));
  const links = [];
  for (const l of g.links) {
    const a = index.get(l.a.id), b = index.get(l.b.id);
    if (a === undefined || b === undefined || a === b) continue;
    links.push({ a: a, b: b, w: 1 });
  }
  const degree = new Array(live.length).fill(0);
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
    for (let i = 0; i < live.length; i += 1) {
      const n = live[i];
      if (n.pinned || n === cur.drag) continue;
      n.x = pos[i * 2];
      n.y = pos[i * 2 + 1];
      n.vx = 0; n.vy = 0;
    }
    shelveIsolates(cur);
    /* Fit on EVERY report until the layout is done, not on the first.
       The first report arrives before ForceAtlas2 has expanded the graph,
       so a one-shot fit framed a picture a fraction of its final size and
       the rest spilled off the canvas (ux18 laptop-canvas-fit,
       2026-09-22). An analyst gesture clears needFit and stops this. */
    if (state.needFit) frameAll();
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
      cur.settled = true;
      if (state.needFit && frameAll()) state.needFit = false;
      syncLayoutFromSim();
      draw();                    // one guaranteed repaint at the final state
    }
  };
  state.layoutWorker.postMessage({
    type: 'start',
    nodes: live.map((n, i) => ({
      x: n.x, y: n.y, degree: degree[i], pinned: !!n.pinned,
    })),
    links: links,
    // 800 is where a mid-size graph actually converges rather than
    // stopping mid-expansion; big graphs trade some of that for time.
    iterations: live.length > 1500 ? 300 : 800,
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
  g.settled = false;
  // Big graph: hand it to the worker and let the interface stay responsive.
  if (!reduceMotion && startWorkerLayout()) return;
  if (reduceMotion) {
    for (let i = 0; i < 320; i += 1) step();
    shelveIsolates(g);
    g.settled = true;
    if (state.needFit && frameAll()) state.needFit = false;
    draw();
    return;
  }
  if (!g.raf) g.raf = requestAnimationFrame(frame);
}

function frame() {
  const g = state.graph;
  if (!g) return;
  /* Cleared FIRST. draw() used to run before g.raf was reassigned, so a
     draw that threw left a stale id in g.raf and every `if (!g.raf)`
     restart guard skipped forever: one bad token froze the layout for
     the rest of the session (cr01 missing-token-now-kills-canvas,
     2026-09-22). */
  g.raf = 0;
  step();
  // Not while a hand is on a node: the shelf would slide under the drag.
  if (!g.drag) shelveIsolates(g);
  if (state.needFit && g.alpha < 0.35) frameAll();
  const running = g.alpha > 0.05 || !!g.drag;
  if (!running) g.settled = true;
  if (!running && state.needFit && frameAll()) state.needFit = false;
  if (running) g.raf = requestAnimationFrame(frame);
  else syncLayoutFromSim();
  draw();
}

/* -- view transform ---------------------------------------------------- */

function toWorld(sx, sy) {
  const v = state.view;
  return { x: (sx - v.tx) / v.scale, y: (sy - v.ty) / v.scale };
}

/* Zoom limits. The OUT limit is not a constant any more: a fixed 0.12
   floor in both fitView and the wheel meant a graph wider than about
   eight canvases could never be seen whole, by either route (ux03
   fit-cannot-fit-flagship, 2026-09-22). The floor now follows the last
   fit, so zooming out always reaches at least the whole graph. */
const ZOOM_MIN = 0.12;
const ZOOM_MAX = 6;
const FIT_MAX = 2;
const FIT_MIN = 0.005;

/** The margin Fit leaves around the graph, in px. A padding in proportion
 *  to the canvas, not a flat 70px: on a 1366x768 laptop the canvas is
 *  under 300px tall and 140px of it went on margin before a single node
 *  was placed. One function, because the reveal test (inView) must never
 *  be stricter than this: an entity Fit put on the canvas IS on the
 *  canvas, and selecting it must not move the view. */
function fitPad(w, h) { return clamp(Math.min(w, h) * 0.1, 24, 70); }

/** The analyst has taken the view: the layout stops fitting it now, and
 *  later renders stop re-fitting it (see setRendered). Every pan and zoom
 *  goes through here. Dragging a node does not: that is a statement about
 *  where the node goes, not about what the view should show. */
function takeView() {
  state.needFit = false;
  state.viewFitted = false;
}

function zoomAt(sx, sy, factor) {
  const v = state.view;
  const w = toWorld(sx, sy);
  v.scale = clamp(v.scale * factor, state.zoomFloor || ZOOM_MIN, ZOOM_MAX);
  v.tx = sx - w.x * v.scale;
  v.ty = sy - w.y * v.scale;
  takeView();
  draw();
}

/** Frame every entity, the shelf included, without painting. Returns
 *  false when the canvas has no size yet (a hidden pane), so the caller
 *  keeps needFit and the fit happens when the pane is shown. */
function frameAll() {
  const g = state.graph;
  const w = canvas.clientWidth, h = canvas.clientHeight;
  if (!w || !h) return false;
  state.viewFitted = true;
  if (!g || !g.nodes.length) {
    state.view = { scale: 1, tx: w / 2, ty: h / 2 };
    return true;
  }
  let minX = Infinity, minY = Infinity, maxX = -Infinity, maxY = -Infinity;
  for (const n of g.nodes) {
    if (n.x < minX) minX = n.x;
    if (n.x > maxX) maxX = n.x;
    if (n.y < minY) minY = n.y;
    if (n.y > maxY) maxY = n.y;
  }
  const pad = fitPad(w, h);
  const bw = Math.max(1, maxX - minX), bh = Math.max(1, maxY - minY);
  const fit = Math.min((w - pad * 2) / bw, (h - pad * 2) / bh);
  const scale = clamp(fit, FIT_MIN, FIT_MAX);
  state.view.scale = scale;
  state.view.tx = w / 2 - ((minX + maxX) / 2) * scale;
  state.view.ty = h / 2 - ((minY + maxY) / 2) * scale;
  state.zoomFloor = Math.min(ZOOM_MIN, scale * 0.5);
  return true;
}

function fitView() {
  const g = state.graph;
  if (!frameAll()) {
    const w = canvas.clientWidth || 800, h = canvas.clientHeight || 600;
    if (!g || !g.nodes.length) state.view = { scale: 1, tx: w / 2, ty: h / 2 };
  }
  draw();
}

/** Pan so an entity is on screen. Called from draw() when the selection
 *  changes, which covers every way a selection arrives: arrow keys, the
 *  palette, search hits and the entity table all used to select a node
 *  that could be off the canvas, leaving the inspector and the canvas
 *  disagreeing about what was selected (ux18 no-keyboard-pan-or-reveal,
 *  2026-09-22). Pans only; the zoom is the analyst's. Returns false when
 *  the canvas has no size yet, so the reveal is retried once it has. */
function revealNode(n) { return revealPoint(n.x, n.y, (n.sr || 0) + 2); }

/** Is a world point on the canvas, `r` px clear of every edge? For an
 *  entity `r` is its drawn radius, so "shown" means its whole disc is on
 *  the canvas, and a disc cut by the edge still counts as off.
 *
 *  Never stricter than Fit's padding. This test once used a flat margin
 *  of up to 40px, wider than the 29px Fit leaves at 1366x768, so an entity
 *  on the rim of a fitted view counted as hidden: selecting it re-centred
 *  the view and threw 50 of NIGHTJAR's 146 entities off the canvas, the
 *  very symptom the fit exists to cure (found by the verifier of the
 *  2026-09-22 fix round). Capped at fitPad less a pixel, every centre Fit
 *  placed passes. */
function inView(x, y, w, h, r) {
  const v = state.view;
  const sx = x * v.scale + v.tx, sy = y * v.scale + v.ty;
  const m = Math.max(0, Math.min(r || 0, fitPad(w, h) - 1));
  return sx >= m && sx <= w - m && sy >= m && sy <= h - m;
}

function revealPoint(x, y, r) {
  const w = canvas.clientWidth, h = canvas.clientHeight;
  if (!w || !h) return false;
  if (inView(x, y, w, h, r)) return true;
  state.view.tx = w / 2 - x * state.view.scale;
  state.view.ty = h / 2 - y * state.view.scale;
  takeView();
  return true;
}

/** Bring a tie into view, but only when no part of it is on the canvas.
 *  A click lands on the visible stretch of a long tie, and panning to a
 *  midpoint that happens to be off screen would move the view out from
 *  under the pointer. */
function revealLink(l) {
  const w = canvas.clientWidth, h = canvas.clientHeight;
  if (!w || !h) return false;
  for (let i = 0; i <= 4; i += 1) {
    const t = i / 4;
    if (inView(l.a.x + (l.b.x - l.a.x) * t, l.a.y + (l.b.y - l.a.y) * t, w, h, 0)) {
      return true;
    }
  }
  return revealPoint((l.a.x + l.b.x) / 2, (l.a.y + l.b.y) / 2, 0);
}

/** Keyboard pan: the arrow keys with Shift. A mouse can drag the canvas
 *  and the keyboard had no equivalent at all. A fifth of the canvas per
 *  press, the same proportion at any window size. */
function panView(dx, dy) {
  state.view.tx += dx;
  state.view.ty += dy;
  takeView();
  draw();
}

/* ── the shelf ─────────────────────────────────────────────────────────
 * Entities with no tie in the current projection, in a labelled block to
 * the right of the connected graph (a wide canvas has room to spare on
 * that side), grouped by type and then by label. They used to be left to
 * the layout, which flung them to the edges of the world: fitting the
 * case then meant fitting 5,000 units of empty space. Pinned ones stay
 * where the analyst put them. When nothing is connected the whole
 * projection IS the shelf, laid out in reading order. */
const SHELF_ROWS = 18;        // rows beside a connected graph before a new column
const SHELF_CELL_MIN = 90;    // world units between shelved entities
const SHELF_CELL_ALONE = 130; // spacing when nothing is connected at all

function shelveIsolates(g) {
  if (!g) return;
  const loose = g.loose.filter((n) => !n.pinned && n !== g.drag);
  if (!loose.length) { g.shelf = null; return; }
  const onShelf = new Set(loose);
  let minX = Infinity, minY = Infinity, maxX = -Infinity, maxY = -Infinity;
  for (const n of g.nodes) {
    if (onShelf.has(n)) continue;
    if (n.x < minX) minX = n.x;
    if (n.x > maxX) maxX = n.x;
    if (n.y < minY) minY = n.y;
    if (n.y > maxY) maxY = n.y;
  }
  const alone = !Number.isFinite(minX);
  let cell, rows, cols, x0, y0;
  if (alone) {
    cell = SHELF_CELL_ALONE;
    const w = canvas.clientWidth || 800, h = canvas.clientHeight || 400;
    cols = Math.max(1, Math.ceil(Math.sqrt(loose.length * (w / h))));
    rows = Math.ceil(loose.length / cols);
    x0 = -((cols - 1) * cell) / 2;
    y0 = -((rows - 1) * cell) / 2;
  } else {
    const coreH = Math.max(1, maxY - minY);
    cell = Math.max(SHELF_CELL_MIN, coreH / SHELF_ROWS);
    // As tall as the graph, and never flatter than square: a small graph
    // with many unconnected entities would otherwise get a long thin strip
    // that Fit then has to shrink everything to hold.
    rows = clamp(Math.max(Math.floor(coreH / cell) + 1,
                          Math.ceil(Math.sqrt(loose.length))), 1, loose.length);
    cols = Math.ceil(loose.length / rows);
    rows = Math.ceil(loose.length / cols);
    x0 = maxX + cell * 2;
    y0 = (minY + maxY) / 2 - ((rows - 1) * cell) / 2;
  }
  loose.forEach((n, i) => {
    // Reading order when the shelf is the whole picture, columns beside a graph.
    const c = alone ? i % cols : Math.floor(i / rows);
    const r = alone ? Math.floor(i / cols) : i % rows;
    n.x = x0 + c * cell;
    n.y = y0 + r * cell;
    n.vx = 0; n.vy = 0;
  });
  g.shelf = { x: x0, y: y0, count: loose.length, alone: alone };
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
  if (prev && prev.w === w && prev.h === h && prev.dpr === dpr) {
    /* Same size, but work may have queued while the pane was hidden and
       the canvas had no size to do it in: a fit the layout finished
       without, or a selection made on another tab (a search hit, the
       palette, the entity table) that could not be revealed. Showing the
       pane is the moment for both. Returning here without a draw left
       the jumped-to entity off the canvas, the inspector and the canvas
       disagreeing again (ux18 no-keyboard-pan-or-reveal, found by the
       verifier of the 2026-09-22 fix round). */
    const g = state.graph;
    if (!g) return;
    const fit = state.needFit && g.settled;
    if (fit && frameAll()) state.needFit = false;
    if (fit || state.selection !== g.revealed) draw();
    return;
  }

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
     * re-fit of a view the analyst has panned or zoomed (a view that is
     * still the fit is re-fitted below): docs/03 is explicit that "analysts build a spatial memory of
     * their network — reshuffling it on every load destroys real analytic
     * value", and a window resize is not a request to rearrange the case.
     * Zoom is untouched for the same reason: a node keeps the size it had.
     */
    state.view.tx += (w - prev.w) / 2;
    state.view.ty += (h - prev.h) / 2;
  }
  state.viewport = { w: w, h: h, dpr: dpr };
  buildGround();
  /* Two cases re-fit here. A layout that finished while the pane was
     hidden could not fit into a canvas with no size, and kept needFit for
     this moment. And a view that is still the fit (the analyst never took
     it) stays the fit: the pane's height changes as the chrome around it
     wraps, and holding the centre then left the edges of a fitted graph
     outside the smaller canvas. Neither moves a node, so the spatial
     memory the comment above protects is untouched. */
  const g = state.graph;
  if ((state.needFit || state.viewFitted) && g && g.settled && frameAll()) {
    state.needFit = false;
  }
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
  /* The theme's steps, read once in loadPaint. No confidence recorded:
     full opacity, never a fake one. An unknown grade is the same, and a
     token that did not resolve is reported by paintIsComplete rather
     than papered over here with a literal. */
  const a = PAINT.conf && PAINT.conf[confidence];
  return Number.isFinite(a) ? a : 1;
}
/** The confidence step a node is drawn at: the best among its ties in
 *  THIS projection. A node with no tie that meets the filter is drawn at
 *  the LOWEST step, never the highest. It used to fall through to full
 *  opacity, so raising the floor to "HIGH only" made every entity look
 *  surer, not less sure (ux03 minconf-isolates-full-opacity, ux04
 *  fit-cannot-frame-flagship, 2026-09-22). Nothing vouches for it here,
 *  and the inspector says so in words. */
function nodeStep(id) {
  const c = state.nodeConf.get(id);
  return PAINT.conf && Number.isFinite(PAINT.conf[c]) ? c : 'LOW';
}
/** The opacity the canvas gives a node's ring and core. The inspector
 *  quotes this number, so the two can never disagree. */
function nodeConfAlpha(id) { return confAlpha(nodeStep(id)); }
/** The body's alpha for a confidence step, a theme token per step. */
function bodyAlpha(step) {
  const a = PAINT.body && PAINT.body[step];
  return Number.isFinite(a) ? a : confAlpha(step);
}
/** E2. The flag lives on the ROW (n.ref), which is what the API sends.
 *  The sim node never carried it, so every earlier read of
 *  `n.has_evidence` was undefined and no entity was ever drawn hollow,
 *  on any case (cr01 e2-hollow-core-never-fires, 2026-09-22). */
function nodeUnevidenced(n) {
  return state.showProvenance && n.ref.has_evidence === false;
}
function edgeUnevidenced(e) {
  return state.showProvenance && e.has_evidence === false;
}
function nodeColour(n) {
  return PAINT.hues[hueClass(n.ref.node_type).slice(4)] || PAINT.hues.context;
}
/* Edge width, in px. The range is the restyle's (it was 1 to 4.4, which
   turned a dense projection into a mat of green), but it is now actually
   SPANNED: t runs over the projection's own lightest-to-heaviest range,
   log-scaled, so the lightest tie on screen is EDGE_W_MIN and the
   heaviest EDGE_W_MAX. When every tie weighs the same there is nothing to
   compare, and they all draw at the middle of the ramp rather than at
   its top. */
const EDGE_W_MIN = 0.9;
const EDGE_W_MAX = 2.8;
function edgeWidth(e) {
  const g = state.graph;
  const lo = Math.log1p(g ? g.minWeight : 0), hi = Math.log1p(g ? g.maxWeight : 0);
  const w = Math.max(0, Number(e.weight) || 0);
  const t = hi > lo ? clamp((Math.log1p(w) - lo) / (hi - lo), 0, 1) : 0.5;
  return EDGE_W_MIN + t * (EDGE_W_MAX - EDGE_W_MIN);
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

/* ── the ground ─────────────────────────────────────────────────────────
 *
 * Until 2026-09-20 this was `fillRect` in --void and nothing else, which
 * made the sociogram the only part of the console outside the elevation
 * system theme.css describes: a flat black rectangle butted up against
 * panels built from glass over plum. It read as a hole.
 *
 * Two marks fix it, both theme tokens and both held by test_theme_contract
 * to a measured ceiling (the binding mark is --sign-neutral, the colour of
 * every neutral tie, at a grid line under the brightest part of the light):
 *
 *   - the key light `body` casts, so the top of the workspace is where the
 *     room is brightest. It depends only on the canvas size, so it is
 *     painted ONCE per size into an offscreen canvas (buildGround) and
 *     blitted each frame. It used to be a fresh gradient and a second
 *     full-canvas fill on every frame, the largest single cost of a frame
 *     on a software-rastered VDI (cr01 ground-repainted-every-frame,
 *     2026-09-22);
 *   - a graph-paper grid in WORLD space, so it pans and zooms with the
 *     graph. A grid pinned to the viewport while the content slides under
 *     it reads as a broken layer.
 *
 * The grid spacing halves and doubles to stay inside GRID_MIN..GRID_MAX
 * screen pixels, which is what controls its density at every zoom. There
 * is deliberately no zoom threshold: the first cut had one, a fitted
 * projection sat below it, and the grid never drew at all. */
const GRID_WORLD = 80;      // world units between lines at 1x
const GRID_MIN = 22;        // screen px: below this, double the spacing
const GRID_MAX = 128;       // screen px: above this, halve it

function buildGround() {
  const bw = canvas.width, bh = canvas.height;
  if (!bw || !bh || !PAINT.void) { GROUND.canvas = null; return; }
  const gc = GROUND.canvas || document.createElement('canvas');
  gc.width = bw;
  gc.height = bh;
  const gx = gc.getContext('2d');
  gx.fillStyle = PAINT.void;
  gx.fillRect(0, 0, bw, bh);
  /* A gradient stop that is not a colour THROWS, where fillStyle quietly
     ignores it. A stop read straight off an unresolved token threw out of
     draw() on every frame and left the canvas blank, which breaks the
     "paint with the browser default" contract paintIsComplete states
     (cr01 missing-token-now-kills-canvas, 2026-09-22). An empty token
     skips the light (paintIsComplete has already reported it), and a
     token that is present but unparseable is caught here. */
  if (PAINT.canvasKeylight && PAINT.canvasKeylightOut) {
    try {
      // Centred above the top edge, so the falloff crosses the canvas
      // rather than sitting in it as a visible blob.
      const cx = bw / 2, cy = -bh * 0.28, far = Math.max(bw, bh) * 1.05;
      const lamp = gx.createRadialGradient(cx, cy, 0, cx, cy, far);
      lamp.addColorStop(0, PAINT.canvasKeylight);
      lamp.addColorStop(1, PAINT.canvasKeylightOut);
      gx.fillStyle = lamp;
      gx.fillRect(0, 0, bw, bh);
    } catch (err) {
      console.error('canvas key light skipped: ' + err.message);
    }
  }
  GROUND.canvas = gc;
}

function paintGround(w, h) {
  const gc = GROUND.canvas;
  if (gc && gc.width === canvas.width && gc.height === canvas.height) {
    ctx.save();
    ctx.setTransform(1, 0, 0, 1, 0, 0);
    ctx.globalAlpha = 1;
    ctx.drawImage(gc, 0, 0);
    ctx.restore();
  } else {
    ctx.globalAlpha = 1;
    ctx.fillStyle = PAINT.void;
    ctx.fillRect(0, 0, w, h);
  }
  paintGrid(w, h);
}

/* ONE path of 1px rectangles, filled ONCE. Stroked as lines, Chromium
   composited each 1px hairline on its own at DPR 1, so every crossing
   took the grid's alpha twice and was the brightest point of the ground:
   --sign-neutral measured 4.48:1 there, under the floor the theme claimed
   (cr02 ceiling-comment-wrong-token, 2026-09-22). A fill covers the union
   of the rectangles once, which is the case test_theme_contract models. */
function paintGrid(w, h) {
  const v = state.view;
  if (!v || !(v.scale > 0) || !PAINT.canvasGrid) return;
  let step = GRID_WORLD * v.scale;
  while (step < GRID_MIN) step *= 2;
  while (step > GRID_MAX) step /= 2;
  // Anchored to world coordinates: the first line on screen is wherever
  // world 0 lands, modulo the step.
  const ox = ((v.tx % step) + step) % step;
  const oy = ((v.ty % step) + step) % step;
  ctx.beginPath();
  for (let x = ox; x < w; x += step) ctx.rect(Math.round(x), 0, 1, h);
  for (let y = oy; y < h; y += step) ctx.rect(0, Math.round(y), w, 1);
  ctx.globalAlpha = 1;
  ctx.fillStyle = PAINT.canvasGrid;
  ctx.fill();
}

/* ── node geometry ──────────────────────────────────────────────────────
 * A node is a translucent BODY in its type hue, a TYPE RING inset inside
 * the disc, and a small solid CORE. The old treatment was one opaque fill,
 * which at this density read as confetti and buried the edges under it.
 *
 * One treatment at EVERY radius. The restyle drew nodes under 5px as solid
 * dots and larger ones with a 0.40 body, so a node's apparent certainty
 * moved with its centrality and with the zoom, and one node visibly dimmed
 * by half when a wheel step carried it across 5px (cr01
 * ring-threshold-borrows-opacity-channel, cr02
 * node-opacity-follows-size-not-confidence, 2026-09-22). Ring width and
 * core size are fractions of r now, so the proportions are the same at
 * every size and a node's body pixel is the same whatever its radius. */
const NODE_RING_FRAC = 0.2;    // type ring width as a fraction of r
const NODE_RING_W_MIN = 0.75;  // px
const NODE_RING_W_MAX = 1.5;   // px
const NODE_CORE_FRAC = 0.3;    // core radius as a fraction of r
/* Hover and path focus: everything outside the question recedes to one
   level whatever its confidence, and plainly is not part of the answer. */
const NODE_DIM_ALPHA = 0.1;
const NODE_DIM_BODY = 0.05;
const EDGE_DIM_ALPHA = 0.08;
const RING_DIM_ALPHA = 0.14;

/* STATE rings, outside the node: [offset from r, width], innermost first.
   The type ring is inset, so its outer edge IS r, and the first state
   ring's inner edge sits 3.25px beyond it. The restyle stroked the type
   ring ON r and the dashed --alert proposal ring 1px outside that, so on
   a group node, whose hue sits close to --alert, pending review read as
   part of the type colour (cr02 hue-ring-overloads-state-ring,
   2026-09-22). test_sociogram_canvas holds the gaps. */
const STATE_RINGS = {
  proposal: [4, 1.5],
  selected: [6.5, 2],
  pinned: [9, 1.5],
  anchor: [11.5, 1.5],
  ego: [14, 1],
};

/* E2 on a TIE: a hollow bead at its midpoint, a --void disc ringed in the
   tie's own colour at the tie's own confidence. It was a 0.45 fade, which
   borrowed the opacity channel from confidence and reversed its order: an
   unevidenced HIGH tie drew fainter than an evidenced LOW one (ux07
   unevidenced-fade-hijacks-confidence-opacity, 2026-09-22). It cannot be a
   dash either, because dashed means inferred and that does not bend. So a
   shape, and the same shape as the hollow entity. */
const BEAD_R = 2.2;            // px beyond half the line width
const BEAD_R_SIGN = 7;         // wide enough to hold the + / - mark

/* Parallel ties bow apart by this much at the apex, per step. */
const PARALLEL_GAP = 9;

/* Labels. */
const LABEL_H = 13;            // line box of the 11px face
const LABEL_GAP = 4;           // px between a node's outermost ring and its label
const LABEL_PAD = 2;           // clear space kept round every label
const LABEL_CELL = 64;         // spatial hash cell, px
const LABEL_CHARS = 24;        // longer handles are cut with an ellipsis
const EDGE_LABEL_SCALE = 1.9;  // edge types only this close in

/** Screen geometry of a tie: its ends, its midpoint, and for a parallel tie
 *  the control point of its bow. The midpoint is ON the curve, so the sign
 *  mark, the bead and the label sit on the line they belong to. */
function linkGeom(l) {
  const ax = l.a.sx, ay = l.a.sy, bx = l.b.sx, by = l.b.sy;
  const mx = (ax + bx) / 2, my = (ay + by) / 2;
  if (!l.bend) {
    return { ax: ax, ay: ay, bx: bx, by: by, mx: mx, my: my, cx: null, cy: null };
  }
  const dx = l.q.sx - l.p.sx, dy = l.q.sy - l.p.sy;
  const len = Math.hypot(dx, dy) || 1;
  const off = l.bend * PARALLEL_GAP;
  const nx = (-dy / len) * off, ny = (dx / len) * off;
  // A quadratic's midpoint is halfway to its control point, so the control
  // point sits at twice the apex offset.
  return { ax: ax, ay: ay, bx: bx, by: by, mx: mx + nx, my: my + ny,
           cx: mx + nx * 2, cy: my + ny * 2 };
}

function traceLink(geo) {
  ctx.beginPath();
  ctx.moveTo(geo.ax, geo.ay);
  if (geo.cx === null) ctx.lineTo(geo.bx, geo.by);
  else ctx.quadraticCurveTo(geo.cx, geo.cy, geo.bx, geo.by);
}

function canvasDisc(x, y, r) {
  ctx.beginPath();
  ctx.arc(x, y, Math.max(0, r), 0, Math.PI * 2);
}

/** One state ring. Returns how far out from the centre it reaches. */
function stateRing(n, key, colour, dash) {
  const spec = STATE_RINGS[key];
  canvasDisc(n.sx, n.sy, n.sr + spec[0]);
  ctx.setLineDash(dash);
  ctx.strokeStyle = colour;
  ctx.lineWidth = spec[1];
  ctx.stroke();
  ctx.setLineDash([]);
  return n.sr + spec[0] + spec[1] / 2;
}

/** Keep the selection on screen (see revealNode). Not while the layout is
 *  still fitting itself: the fit frames every entity anyway, and a pan
 *  here would cancel it.
 *
 *  Keyed on the selection OBJECT, not its id. selectNode and selectEdge
 *  build a new object every time, so choosing the same entity again from
 *  the palette or the entity table, after panning it off with Shift and
 *  an arrow, is a new request and brings it back. Keyed on the id it was
 *  ignored, and the inspector and the canvas disagreed again (ux18
 *  no-keyboard-pan-or-reveal, found in the 2026-09-22 fix round). A
 *  re-render keeps the same object, so it does not pan (setRendered).
 *
 *  A click is never a reason to move. What was clicked is under the
 *  pointer, on the canvas, however near the rim; panning it to the middle
 *  moved the view out from under the hand and threw a fitted case off the
 *  canvas (found by the verifier of the 2026-09-22 fix round). The pointer
 *  handler raises `pickedOnCanvas` around its selectNode and selectEdge,
 *  and such a selection is recorded as already shown.
 *
 *  A selection made while the pane is hidden (a search hit, the palette,
 *  the entity table, all on other tabs) cannot be revealed into a canvas
 *  with no size, so `revealed` stays behind and resizeGraph draws again
 *  when the pane is shown. */
let pickedOnCanvas = false;
function followSelection(g) {
  if (state.needFit) return;
  const sel = state.selection;
  if (sel === g.revealed) return;
  if (pickedOnCanvas) { g.revealed = sel; return; }
  const n = sel && sel.kind === 'node' ? g.index.get(sel.id) : null;
  const l = sel && sel.kind === 'edge' ? linkOf(g, sel.id) : null;
  if (!n && !l) { g.revealed = sel; return; }
  if (n ? revealNode(n) : revealLink(l)) g.revealed = sel;
}

/** Run a selection the pointer made (see followSelection). */
function pickOnCanvas(select) {
  pickedOnCanvas = true;
  try { select(); } finally { pickedOnCanvas = false; }
}

/** The drawn tie for an edge id, or null. */
function linkOf(g, id) {
  for (const l of g.links) { if (l.ref.id === id) return l; }
  return null;
}

/** Ties by keyboard. The arrows only ever reached entities, so a tie, and
 *  above all the second tie on a pair, could not be opened without a
 *  mouse (ux05 parallel-ties-unreachable, 2026-09-22). [ and ] step
 *  through the ties of the selected entity, or, with a tie selected, of
 *  the entity whose ties are being stepped. Ordered by the other end, so
 *  the ties on one pair are neighbours, in the order they bow. */
function tiesOf(g, id) {
  const other = (l) => (l.a.id === id ? l.b : l.a);
  return g.links
    .filter((l) => !edgeHidden(l.ref) && (l.a.id === id || l.b.id === id))
    .sort((x, y) => String(other(x).ref.label || '')
      .localeCompare(String(other(y).ref.label || ''))
      || String(other(x).id).localeCompare(String(other(y).id))
      || x.bend - y.bend);
}

function stepTie(g, dir) {
  const sel = state.selection;
  if (!sel) return;
  let anchor = null, cur = null;
  if (sel.kind === 'node') {
    anchor = sel.id;
  } else if (sel.kind === 'edge') {
    cur = linkOf(g, sel.id);
    if (!cur) return;
    const a = state.tieAnchor;
    anchor = a === cur.a.id || a === cur.b.id ? a : cur.a.id;
  }
  if (anchor === null || !g.index.has(anchor)) return;
  const ties = tiesOf(g, anchor);
  if (!ties.length) return;
  const at = cur ? ties.indexOf(cur) : -1;
  const next = at < 0 ? (dir > 0 ? 0 : ties.length - 1)
    : (at + dir + ties.length) % ties.length;
  state.tieAnchor = anchor;
  selectEdge(ties[next].ref.id);
}

function draw() {
  const g = state.graph;
  const w = canvas.clientWidth, h = canvas.clientHeight;
  paintGround(w, h);
  if (!g) { setGraphNote(''); return; }
  followSelection(g);
  syncScreen();
  const sel = state.selection;
  const fs = focusSets();
  const scale = state.view.scale;
  // Marks a name may not be printed over: beads and sign marks here,
  // node discs in drawLabels.
  const marks = boxHash();

  /* edges */
  for (const l of g.links) {
    const e = l.ref;
    l.lit = false;
    if (edgeHidden(e)) continue;
    const on = sel && sel.kind === 'edge' && sel.id === e.id;
    let lit = true;
    if (fs) {
      lit = fs.mode === 'path'
        ? fs.pairs.has(pairKey(e.src_node_id, e.dst_node_id))
        : (e.src_node_id === state.hoverId || e.dst_node_id === state.hoverId);
    }
    l.lit = lit;
    const geo = linkGeom(l);
    l.geo = geo;
    /* Opacity is the tie's confidence and nothing else. */
    const alpha = lit ? confAlpha(e.confidence) : EDGE_DIM_ALPHA;
    const colour = on ? PAINT.accent : edgeColour(e.sign);
    const width = edgeWidth(e) + (on ? 1.5 : 0) +
                  (lit && fs && fs.mode === 'path' ? 1.5 : 0);
    ctx.globalAlpha = alpha;
    /* Invariant: solid = asserted, dashed = inferred. Never negotiable. */
    ctx.setLineDash(e.is_inferred ? [5, 4] : []);
    ctx.strokeStyle = colour;
    ctx.lineWidth = width;
    traceLink(geo);
    ctx.stroke();
    ctx.setLineDash([]);
    /* Sign is a hue, and a hue alone is not an encoding: a red/green
       confusion would invert the meaning of a vouch. A midpoint + / - gives
       sign a second, achromatic channel. It cannot be the dash pattern,
       which already means asserted versus inferred. Held back to closer
       zooms so the wide view stays readable. */
    const signMark = lit && e.sign !== 0 &&
      (scale >= 1.2 || on || (fs && fs.mode === 'path'));
    if (lit && edgeUnevidenced(e)) {
      const br = signMark ? BEAD_R_SIGN : width / 2 + BEAD_R;
      marks.add(geo.mx - br, geo.my - br, br * 2, br * 2, null);
      canvasDisc(geo.mx, geo.my, br);
      ctx.globalAlpha = 1;
      ctx.fillStyle = PAINT.void;
      ctx.fill();
      ctx.globalAlpha = alpha;
      ctx.strokeStyle = colour;
      ctx.lineWidth = 1;
      ctx.stroke();
    }
    if (signMark) {
      marks.add(geo.mx - BEAD_R_SIGN, geo.my - BEAD_R_SIGN,
                BEAD_R_SIGN * 2, BEAD_R_SIGN * 2, null);
      ctx.globalAlpha = 1;
      ctx.fillStyle = edgeColour(e.sign);
      ctx.font = PAINT.signFont;
      ctx.textAlign = 'center';
      ctx.textBaseline = 'middle';
      ctx.fillText(e.sign > 0 ? '+' : '−', geo.mx, geo.my);
    }
  }
  ctx.setLineDash([]);

  /* nodes */
  for (const n of g.nodes) {
    const lit = !fs || fs.nodes.has(n.id);
    const selected = sel && sel.kind === 'node' && sel.id === n.id;
    const r = n.sr;
    /* Node opacity IS confidence (docs/06). A node carries no confidence
       column of its own, so this is the best confidence among its ties in
       THIS projection (nodeStep); the inspector states that in words and
       gives the number, so the encoding is never colour or opacity alone.
       Body, ring and core all take their alpha from the step. */
    const conf = nodeStep(n.id);
    const base = lit ? confAlpha(conf) : NODE_DIM_ALPHA;
    const hue = nodeColour(n);
    const ringW = clamp(r * NODE_RING_FRAC, NODE_RING_W_MIN, NODE_RING_W_MAX);
    if (nodeUnevidenced(n)) {
      /* E2. An entity that rests on no exhibit is HOLLOW: --void inside
         the ring, no body, no core. The difference from an evidenced node
         is the whole interior, not a 2.5px dot, so it survives the small
         radii of a fitted view. Confidence is opacity and type is hue, so
         this had to be a shape.
         It marks the ABSENCE of evidence rather than its presence, on
         purpose: an unevidenced case should look conspicuously unfinished.
         If the mark meant "evidenced", a case with no exhibits at all
         would look calm and complete, which is the exact impression to
         avoid. */
      canvasDisc(n.sx, n.sy, r);
      ctx.globalAlpha = 1;
      ctx.fillStyle = PAINT.void;
      ctx.fill();
    } else {
      canvasDisc(n.sx, n.sy, r);
      ctx.globalAlpha = lit ? bodyAlpha(conf) : NODE_DIM_BODY;
      ctx.fillStyle = hue;
      ctx.fill();
      canvasDisc(n.sx, n.sy, r * NODE_CORE_FRAC);
      ctx.globalAlpha = base;
      ctx.fill();
    }
    canvasDisc(n.sx, n.sy, r - ringW / 2);
    ctx.globalAlpha = base;
    ctx.strokeStyle = hue;
    ctx.lineWidth = ringW;
    ctx.stroke();

    /* State rings: unreviewed proposal, selected, pinned, path anchor, ego
       centre, at increasing radii so all of them can be true at once and
       still be read. */
    ctx.globalAlpha = lit ? 1 : RING_DIM_ALPHA;
    let reach = r;
    if (state.nodeProposed.get(n.id)) {
      reach = stateRing(n, 'proposal', PAINT.alert, [3, 3]);
    }
    if (selected) reach = stateRing(n, 'selected', PAINT.accent, []);
    if (n.pinned) reach = stateRing(n, 'pinned', PAINT.label, [1, 3]);
    if (state.pathAnchor === n.id) {
      reach = stateRing(n, 'anchor', PAINT.accent, [2, 4]);
    }
    if (state.focus && state.focus.kind === 'ego' && state.focus.id === n.id) {
      reach = stateRing(n, 'ego', PAINT.accentDim, []);
    }
    n.reach = reach;
  }
  ctx.globalAlpha = 1;
  drawLabels(g, fs, sel, w, h, scale >= EDGE_LABEL_SCALE, marks);
  ctx.globalAlpha = 1;
  noteView(g, w, h);
}

/* ── labels ─────────────────────────────────────────────────────────────
 * One pass AFTER every node, in priority order, each placed only where it
 * overprints nothing. The old rule was all or nothing by zoom (every label
 * from 0.7x, none below it), drawn inside the node loop: a fitted flagship
 * case showed no names at all, and where labels did show they collided,
 * fusing 'lupine_ram' and 'spectre_viper' into one plausible handle, with
 * later discs painted over earlier names (ux04
 * labels-all-or-nothing-and-colliding, 2026-09-22).
 *
 * Now: what the analyst points at or has selected is always named; then
 * the largest nodes by the size metric, each tried below, above, right and
 * left of its node and skipped if every spot would cover a node, a bead,
 * a sign mark or another label. Zooming in makes room, so more names
 * appear. Every name sits on a --void plate (placeText), which is why
 * test_theme_contract measures label contrast against --void. */
function labelText(n) {
  const raw = n.ref.label || '';
  return raw.length > LABEL_CHARS ? raw.slice(0, LABEL_CHARS - 1) + '…' : raw;
}

function labelWidth(g, text) {
  let tw = g.labelW.get(text);
  if (tw === undefined) {
    tw = ctx.measureText(text).width;
    g.labelW.set(text, tw);
  }
  return tw;
}

/** A uniform spatial hash of screen boxes, so each label is tested only
 *  against what is near it. */
function boxHash() {
  const cells = new Map();
  const visit = (x, y, bw, bh, fn) => {
    const x0 = Math.floor(x / LABEL_CELL), x1 = Math.floor((x + bw) / LABEL_CELL);
    const y0 = Math.floor(y / LABEL_CELL), y1 = Math.floor((y + bh) / LABEL_CELL);
    for (let cx = x0; cx <= x1; cx += 1) {
      for (let cy = y0; cy <= y1; cy += 1) {
        if (fn(cx + ',' + cy)) return true;
      }
    }
    return false;
  };
  return {
    add: (x, y, bw, bh, owner) => {
      const box = [x, y, x + bw, y + bh, owner];
      visit(x, y, bw, bh, (k) => {
        let c = cells.get(k);
        if (!c) { c = []; cells.set(k, c); }
        c.push(box);
        return false;
      });
    },
    hits: (x, y, bw, bh, self) => visit(x, y, bw, bh, (k) => {
      const c = cells.get(k);
      if (!c) return false;
      for (const b of c) {
        if (b[4] && b[4] === self) continue;
        if (x < b[2] && x + bw > b[0] && y < b[3] && y + bh > b[1]) return true;
      }
      return false;
    }),
  };
}

/* Each name sits on a --void plate. A halo round the glyphs was tried
   first and left a tie crossing the gap in "Meridian crew" reading as an
   underscore, which is the one misreading a handle cannot afford. The
   plate only ever covers plain lengths of tie: nodes, beads and sign
   marks are obstacles the placement avoids. */
function placeText(hash, text, tw, x, y, colour, alpha) {
  hash.add(x - LABEL_PAD, y - LABEL_PAD, tw + LABEL_PAD * 2, LABEL_H + LABEL_PAD * 2, null);
  ctx.globalAlpha = 1;
  ctx.fillStyle = PAINT.void;
  ctx.fillRect(x - 1, y, tw + 2, LABEL_H);
  ctx.globalAlpha = alpha;
  ctx.fillStyle = colour;
  ctx.fillText(text, x, y + 1);
}

function drawLabels(g, fs, sel, w, h, withEdges, hash) {
  const hot = new Set();
  if (sel && sel.kind === 'node') hot.add(sel.id);
  if (state.hoverId) hot.add(state.hoverId);
  const cands = [];
  for (const n of g.nodes) {
    if (fs && !fs.nodes.has(n.id)) continue;
    const k = n.reach || n.sr;
    if (n.sx < -k || n.sy < -k || n.sx > w + k || n.sy > h + k) continue;
    hash.add(n.sx - k, n.sy - k, k * 2, k * 2, n);
    if (n.sx >= 0 && n.sy >= 0 && n.sx <= w && n.sy <= h) cands.push(n);
  }
  ctx.font = PAINT.labelFont;
  ctx.textAlign = 'left';
  ctx.textBaseline = 'top';

  /* The shelf names a region, so it is placed before any handle can take
     its spot. */
  const first = g.shelf ? g.loose.find((n) => !n.pinned) : null;
  if (first && first.sx >= 0 && first.sx <= w) {
    /* When the confidence floor is what emptied the picture, the caption
       says so: 'HIGH only' on a case with no HIGH tie otherwise looked
       like a case with no ties at all (ux03 minconf-isolates-full-opacity,
       2026-09-22). */
    const floor = state.proj && state.proj.min_confidence;
    const graded = floor === 'HIGH' ? 'graded HIGH'
      : (floor === 'MODERATE' ? 'graded MODERATE or above' : '');
    const text = g.shelf.alone
      ? (graded ? 'no tie in this projection is ' + graded : 'no ties in this projection')
      : g.shelf.count + ' with no tie in this projection';
    const tw = labelWidth(g, text);
    const x = clamp(first.sx - first.sr, 0, Math.max(0, w - tw));
    const y = first.sy - (first.reach || first.sr) - LABEL_GAP - LABEL_H;
    if (y >= 0 && y + LABEL_H <= h) placeText(hash, text, tw, x, y, PAINT.dim, 1);
  }

  // Stable sort: equal-sized nodes keep the projection's own order.
  cands.sort((a, b) => ((hot.has(b.id) ? 1 : 0) - (hot.has(a.id) ? 1 : 0))
    || (b.sr - a.sr));
  let drawn = 0, wanted = 0;
  for (const n of cands) {
    const text = labelText(n);
    if (!text) continue;
    wanted += 1;
    const tw = labelWidth(g, text);
    const d = (n.reach || n.sr) + LABEL_GAP;
    const spots = [
      n.sx - tw / 2, n.sy + d,                 // below
      n.sx - tw / 2, n.sy - d - LABEL_H,       // above
      n.sx + d, n.sy - LABEL_H / 2,            // right
      n.sx - d - tw, n.sy - LABEL_H / 2,       // left
    ];
    const isHot = hot.has(n.id);
    let at = -1;
    for (let i = 0; i < spots.length; i += 2) {
      const x = spots[i], y = spots[i + 1];
      if (x < 0 || y < 0 || x + tw > w || y + LABEL_H > h) continue;
      if (hash.hits(x - LABEL_PAD, y - LABEL_PAD, tw + LABEL_PAD * 2,
                    LABEL_H + LABEL_PAD * 2, n)) continue;
      at = i;
      break;
    }
    // What the analyst is pointing at is always named.
    if (at < 0 && isHot) at = 0;
    if (at < 0) continue;
    placeText(hash, text, tw, spots[at], spots[at + 1],
              isHot ? PAINT.bright : PAINT.label, isHot ? 1 : PAINT.labelAlpha);
    drawn += 1;
  }
  g.labelsDrawn = drawn;
  g.labelsWanted = wanted;

  /* Edge types, only close in and only where they fit: a name outranks a
     relationship type, which the inspector gives in full anyway. */
  if (!withEdges) return;
  for (const l of g.links) {
    if (!l.lit || !l.geo) continue;
    const text = String(l.ref.edge_type || '');
    if (!text) continue;
    const tw = labelWidth(g, text);
    const x = l.geo.mx - tw / 2, y = l.geo.my - 9 - LABEL_H / 2;
    if (x < 0 || y < 0 || x + tw > w || y + LABEL_H > h) continue;
    if (hash.hits(x - LABEL_PAD, y - LABEL_PAD, tw + LABEL_PAD * 2,
                  LABEL_H + LABEL_PAD * 2, null)) continue;
    placeText(hash, text, tw, x, y, PAINT.dim, 1);
  }
}

/* What the canvas is not showing, said in words. The readout under the
   canvas said "drawn: 146 nodes" while half of them were off screen, and
   nothing on the canvas said so (ux03 fit-cannot-fit-flagship, ux18
   laptop-canvas-fit, 2026-09-22). The count of entities outside the view
   sits on the canvas, and only appears once the analyst has zoomed or
   panned away from the fit. How many names were held back to avoid
   overprinting goes in the legend, beside the size metric, so it never
   covers the graph it describes. */
function noteView(g, w, h) {
  if (!w || !h) return;
  let off = 0;
  for (const n of g.nodes) {
    if (n.sx < 0 || n.sy < 0 || n.sx > w || n.sy > h) off += 1;
  }
  const notes = [];
  if (off) {
    notes.push(off + ' of ' + g.nodes.length +
               ' entities outside the view: 0 or Fit shows all');
  }
  /* A tie with a twin on the same pair says so, on the canvas where the
     twin is drawn. The inspector opened one tie at a time and nothing said
     a second one existed, which is how a dispute was read as a vouch (ux05
     parallel-ties-unreachable, 2026-09-22). */
  const sel = state.selection;
  const link = sel && sel.kind === 'edge' ? linkOf(g, sel.id) : null;
  if (link && link.pair) {
    notes.push('tie ' + (link.pair.indexOf(link) + 1) + ' of ' + link.pair.length +
               ' between these two: [ and ] step through them');
  }
  setCanvasText('graph-note', notes.join('. '));
  setCanvasText('legend-names', g.labelsWanted > g.labelsDrawn
    ? 'names: ' + g.labelsDrawn + ' of ' + g.labelsWanted + ', zoom in for more'
    : '');
}

/** Only touches the DOM when the text changes, because draw() calls it on
 *  every frame of a pan. */
function setCanvasText(id, text) {
  const box = $(id);
  if (!box) return;
  if (box.textContent !== text) box.textContent = text;
  if (box.hidden !== !text) show(box, !!text);
}

function setGraphNote(text) { setCanvasText('graph-note', text); }

/* The previous case's graph goes the moment the case changes. openCase
   used to keep it until the new projection arrived, and resizeGraph,
   finding a SETTLED graph with needFit set for the new case, framed the
   old graph and spent the new case's fit on it: switching from a settled
   case left OP-NIGHTJAR-26 with 144 of 146 entities off the canvas
   (ux03 fit-cannot-fit-flagship, found again in the 2026-09-22 fix
   round). It was also case A's picture under case B's header for as long
   as B took to load, which is the bleed this registry exists to stop.

   It takes a sociogram number as well (final review C16, 2026-09-23).
   refreshSociogram, enterEgo, enterPath and reapplyFocus are guarded by
   state.graphSeq alone, and only they moved it, so a NIGHTJAR /graph reply
   still out at the switch passed every check while KESTREL's open waited
   on its record, layout and case graph. It rewrote gnodes and projMeta
   and repainted this cleared canvas with NIGHTJAR's actors under
   "Opening OP-KESTREL-26", and stayed there for good when KESTREL's
   record could not be read. */
onCaseSwitch(() => {
  stopWorkerLayout();
  stopGraph();
  state.graphSeq = (state.graphSeq || 0) + 1;
  state.needFit = true;
  state.viewFitted = false;
  state.zoomFloor = null;
  state.tieAnchor = null;
  setCanvasText('graph-note', '');
  setCanvasText('legend-names', '');
  draw();
});

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

function segDist(px, py, x1, y1, x2, y2) {
  const dx = x2 - x1, dy = y2 - y1;
  const len2 = dx * dx + dy * dy;
  const t = len2 === 0 ? 0 : clamp(((px - x1) * dx + (py - y1) * dy) / len2, 0, 1);
  return Math.hypot(px - (x1 + t * dx), py - (y1 + t * dy));
}

/** Distance from a point to a tie as drawn: the chord, or the bow of a
 *  parallel tie walked as sixteen short segments. */
function linkDist(p, geo) {
  if (geo.cx === null) return segDist(p.x, p.y, geo.ax, geo.ay, geo.bx, geo.by);
  let d = Infinity, px = geo.ax, py = geo.ay;
  for (let i = 1; i <= 16; i += 1) {
    const t = i / 16, u = 1 - t;
    const x = u * u * geo.ax + 2 * u * t * geo.cx + t * t * geo.bx;
    const y = u * u * geo.ay + 2 * u * t * geo.cy + t * t * geo.by;
    d = Math.min(d, segDist(p.x, p.y, px, py, x, y));
    px = x;
    py = y;
  }
  return d;
}

/** The tie under the pointer: the NEAREST one within reach, not the first
 *  in list order. The first-in-list rule meant a later parallel tie could
 *  never be hit, and the one that answered was not the one drawn on top
 *  (ux05 parallel-ties-unreachable, 2026-09-22). `<=` so that of two ties
 *  at the same distance the later-drawn one, the one on top, wins. */
function edgeAt(p) {
  const g = state.graph;
  if (!g) return null;
  syncScreen();
  let best = null, bestD = Infinity;
  for (const l of g.links) {
    if (edgeHidden(l.ref)) continue;
    const d = linkDist(p, linkGeom(l));
    const reach = Math.max(6, edgeWidth(l.ref) / 2 + 3);
    if (d < reach && d <= bestD) { best = l.ref; bestD = d; }
  }
  return best;
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
      // A hand on the canvas ends the layout's auto-fit.
      state.needFit = false;
      if (reduceMotion) draw();
      return;
    }
    if (mode === 'pan' && downView) {
      state.view.tx = downView.tx + (p.x - downAt.x);
      state.view.ty = downView.ty + (p.y - downAt.y);
      if (moved) takeView();
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
          pickOnCanvas(() => selectNode(n.id));
          renderFocusFlag();
        } else {
          enterPath(state.pathAnchor, n.id);
        }
        return;
      }
      pickOnCanvas(() => selectNode(n.id));
      return;
    }
    if (wasDrag) { draw(); return; }
    const edge = edgeAt(p);
    if (edge) { pickOnCanvas(() => selectEdge(edge.id)); return; }
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

  /* Shift with an arrow pans, a fifth of the canvas per press: the
     keyboard had no way to move the view at all, so a keyboard-only
     analyst could select an entity off the canvas and never see it
     (ux18 no-keyboard-pan-or-reveal, 2026-09-22). The arrow names the
     direction the view travels, as a scrollbar would. A plain arrow still
     steps the selection, and draw() brings that entity into view. */
  const PAN_KEYS = { ArrowLeft: [1, 0], ArrowRight: [-1, 0],
                     ArrowUp: [0, 1], ArrowDown: [0, -1] };
  if (e.shiftKey && PAN_KEYS[e.key]) {
    e.preventDefault();
    const d = PAN_KEYS[e.key];
    panView(d[0] * canvas.clientWidth / 5, d[1] * canvas.clientHeight / 5);
    return;
  }

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
  } else if (e.key === ']' || e.key === '[') {
    e.preventDefault();
    stepTie(g, e.key === ']' ? 1 : -1);
  } else if (e.key === 'Home') {
    /* Back to the selection, entity or tie, wherever the view has been
       panned to. */
    e.preventDefault();
    const sel = state.selection;
    const l = sel && sel.kind === 'edge' ? linkOf(g, sel.id) : null;
    const n = cur >= 0 ? g.nodes[cur] : null;
    const x = n ? n.x : (l ? (l.a.x + l.b.x) / 2 : null);
    const y = n ? n.y : (l ? (l.a.y + l.b.y) / 2 : null);
    if (x !== null) {
      panView(canvas.clientWidth / 2 - (x * state.view.scale + state.view.tx),
            canvas.clientHeight / 2 - (y * state.view.scale + state.view.ty));
    }
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
  /* final review U15, 2026-09-23. openCase checks caseChanged only after
     this returns, and this assigns state.layout itself, so NIGHTJAR's reply
     landing after KESTREL's replaced KESTREL's saved positions: KESTREL
     drew with none of its pins, and the next Save layout overwrote its
     stored placement with the fresh simulation. A reply for a case the
     analyst has left writes nothing, and its failure raises no banner. */
  const token = caseToken();
  try {
    const rows = await api(cpath('/graph/layout'));
    if (caseChanged(token)) return;
    state.layout = new Map((rows || []).map((r) => [String(r.node_id), r]));
  } catch (err) {
    if (caseChanged(token)) return;
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
    banner('Layout saved', countOf(positions.length, 'position', 'positions')
      + ' stored, ' + pinned +
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
    /* An absent date reads as absent: the words stay, in the quiet style
       every other missing value takes. At full strength "not recorded" was
       the brightest text in the table (README screenshot review,
       2026-09-23). */
    tr.appendChild(el('td', n.first_seen ? 'num' : 'num absent',
      fmtWhen(n.first_seen)));
    tr.addEventListener('click', () => selectNode(n.id));
    tr.addEventListener('keydown', (e) => {
      if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); selectNode(n.id); }
    });
    body.appendChild(tr);
  }
  show($('ent-empty'), rows.length === 0);
  /* Case totals, not projection totals: this list is the case file, and the
     projection's own counts live next to the canvas where they belong. */
  $('ent-count').textContent = rows.length + ' of '
    + countOf(state.nodes.length, 'entity', 'entities') + ' · '
    + countOf(state.edges.length, 'relationship', 'relationships')
    + ' in the case';
}

/* ── evidence ─────────────────────────────────────────────────────────── */

async function loadEvidence() {
  const token = caseToken();
  try {
    if (!state.evidencePolicy) {
      /* The cap is the deployment's, not the case's, so it is read once
         and shown beside the picker: an analyst learns the limit before
         choosing a file, not from a 413 after the upload. */
      state.evidencePolicy = await api(cpath('/evidence/policy'));
      renderEvidencePolicy();
    }
    const list = await api(cpath('/evidence-list?limit=200'));
    if (caseChanged(token)) return;          // ux17-failure, 2026-09-22
    clearLoadFailure('ev-empty');
    state.evidence = list;
    renderEvidence();
    // E1: keep the entity/relationship exhibit pickers in step, so an
    // exhibit uploaded a moment ago is immediately attachable.
    refreshEvidencePickers();
  } catch (err) {
    if (caseChanged(token)) return;
    showLoadFailure('ev-empty', "This case's exhibits", err, loadEvidence);
    fail(err);
  }
}

function renderEvidencePolicy() {
  const p = state.evidencePolicy;
  setMsg($('ev-cap'), !p ? '' :
    'Exhibits up to ' + fmtBytes(p.max_bytes) + '. Every accepted byte is '
    + 'written once and locked for the retention period; the cap is '
    + (p.declared ? 'this deployment\'s declared policy.'
                  : 'the default, which this deployment has not declared.'));
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
          : 'HASH MISMATCH: the stored bytes do not match the recorded digest.';
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
      /* A case switch mid-read must not land this exhibit's log in the next
         case's pane (the 2026-09-22 case-switch registry). */
      const token = caseToken();
      try {
        const log = await api(cpath('/evidence/' + ev.id + '/custody'));
        if (caseChanged(token)) return;
        clear(custodyBox);
        if (!log.length) {
          custodyBox.appendChild(el('p', 'empty', 'No custody entries recorded.'));
        }
        for (const c of log) custodyBox.appendChild(renderCustodyRow(c));
      } catch (err) {
        if (caseChanged(token)) return;
        clear(custodyBox);
        custodyBox.appendChild(el('p', 'form-error', 'Custody log unavailable.'));
        fail(err);
      }
    });
    list.appendChild(item);
  }
  show($('ev-empty'), state.evidence.length === 0);
}

/** The integrity chip on one custody row: [className, text, title], or
 *  null for no chip. THREE states, never two.
 *
 *  ux07 custody-failed-hash-shown-as-not-checked (2026-09-22). This was
 *  `c.hash_verified ? 'hash verified' : 'hash not checked'`, a truthiness
 *  test that read `false` (the stored bytes did NOT match: the tamper
 *  alarm) exactly like `null` (this row attests no check), and filed both
 *  under the quiet grey `.chip.stale`. So a tampered exhibit's log read as
 *  routine, under an action name (HASH_VERIFIED) that sounds like
 *  reassurance, on the record that goes to court; and every clean
 *  acquisition read "hash not checked", a lapse that never happened.
 *  Compared with `=== true` / `=== false` on purpose: a truthiness test is
 *  the bug. */
function custodyHashChip(action, verified) {
  if (verified === true) {
    return ['chip good', 'hash verified',
      'The stored bytes matched the recorded digest when this row was written.'];
  }
  if (verified === false) {
    return ['chip bad', 'HASH MISMATCH',
      'The stored bytes did NOT match the recorded digest when this row was '
      + 'written. The exhibit\'s integrity is in question. The mismatch '
      + 'raised an integrity alarm in the audit log, and this row keeps it '
      + 'on the custody record permanently.'];
  }
  if (action === 'ACQUIRED') {
    /* NULL on ACQUIRED: the digest of the bytes as received is on the
       record, but this row does not itself attest a read-back of the
       stored object. New acquisitions write TRUE (evidence.py ingest); a
       re-acquisition of bytes already held, and rows written before
       2026-09-22, stay NULL. */
    return ['chip stale', 'digest recorded',
      'The SHA-256 of the bytes as received is recorded. This row does not '
      + 'attest a read-back of the stored object: the bytes were already '
      + 'held, or the row predates that record. Verify checks them now.'];
  }
  return null;
}

/** One custody row. Separate from the click handler so the three chip
 *  states can be rendered by a test (test_inspector_evidence_ui.py). */
function renderCustodyRow(c) {
  const row = el('div', 'custody-row' + (c.hash_verified === false ? ' bad' : ''));
  row.appendChild(el('span', null, c.action));
  row.appendChild(el('span', 'when', fmtTime(c.occurred_at)));
  /* A person, not an eight-hex id: the log answers "who touched this
     exhibit" (README screenshot review, 2026-09-23). The id stays in the
     title, and is the text only when the account no longer resolves. */
  const who = c.actor_name
    ? el('span', 'small', 'by ' + visibleText(c.actor_name))
    : el('span', 'mono small', 'actor ' + shortId(c.actor_id));
  who.title = 'Account ' + c.actor_id;
  row.appendChild(who);
  const chip = custodyHashChip(c.action, c.hash_verified);
  if (chip) {
    const flag = el('span', chip[0], chip[1]);
    flag.title = chip[2];
    row.appendChild(flag);
  }
  return row;
}

async function uploadEvidence(event) {
  event.preventDefault();
  const errBox = $('ev-error'), okBox = $('ev-result');
  setMsg(errBox, ''); setMsg(okBox, '');
  const file = $('ev-file').files[0];
  const title = $('ev-title').value.trim();
  if (!file) { setMsg(errBox, 'Choose a file to lodge as an exhibit.'); return; }
  if (!title) { setMsg(errBox, 'An exhibit needs a title.'); return; }
  const cap = state.evidencePolicy && state.evidencePolicy.max_bytes;
  if (cap && file.size > cap) {
    /* The server refuses this before reading a byte (413); saying so
       here saves the upload. The server stays the authority: a stale
       policy here changes a sentence, never what is accepted. */
    setMsg(errBox, 'This file is ' + fmtBytes(file.size) + '; this deployment '
      + 'accepts an exhibit up to ' + fmtBytes(cap) + ' and would refuse it. '
      + 'Do not split it: the digest of the whole is what custody attests.');
    return;
  }
  const form = new FormData();
  form.append('file', file);
  form.append('title', title);
  form.append('acquisition_method', $('ev-method').value);
  form.append('classification', $('ev-class').value);
  /* An exhibit lodged is in custody for good, so where it went is said
     even when the answer lands after a switch; it is said in a banner
     naming that case, not in this case's cleared form (final review C18,
     2026-09-23). */
  const token = caseToken();
  const code = caseCodeNow();
  try {
    const out = await api(cpath('/evidence'), { method: 'POST', form: form });
    if (caseChanged(token)) {
      banner('Exhibit lodged in ' + code, 'sha256 ' + out.sha256 + '. You had '
        + 'moved to another case before the reply arrived, so it is not '
        + 'shown here.', 'warn');
      return;
    }
    setMsg(okBox, 'Lodged. sha256 ' + out.sha256 +
      (out.deduplicated ? '. Identical bytes were already held, so the existing exhibit was reused.' : ''));
    $('ev-file').value = '';
    $('ev-title').value = '';
    await loadEvidence();
  } catch (err) {
    if (caseChanged(token)) {
      banner('Lodging an exhibit in ' + code + ' failed', failureReason(err));
      return;
    }
    inlineProblem(errBox, err);
  }
}

/* ── search ───────────────────────────────────────────────────────────── */

/* The first page, and the server's cap (`le=200` in routers/search.py).
   The pane asks for the first page and offers the rest on request rather
   than drawing two hundred buttons for every query. */
const SEARCH_FIRST = 50;
const SEARCH_MAX = 200;

/* Every search and every case switch takes a new number. A reply for an
   older number belongs to a query the analyst has replaced, or to a case
   they have left, and is dropped rather than drawn. */
let searchSeq = 0;

/* stale-results-across-cases (ux09-search, 2026-09-22): switching cases
   left the old query and the old case's hits on screen under the new
   case's header and TLP chip. KESTREL appeared to hold NIGHTJAR's
   umbra_shrike, AMBER labels sat under a GREEN banner, and a click on one
   landed on "node does not exist in this case". */
onCaseSwitch(() => {
  searchSeq += 1;
  $('search-q').value = '';
  clear($('search-nodes'));
  clear($('search-evidence'));
  setMsg($('search-scope'), '');
});

/* Per column: what a hit is called, where a click goes, and what to say
   when nothing matched. The empty text suggests the next move, because a
   bare "No matches." reads as "this is not in the case", and until
   2026-09-22 that was often wrong (whole-token-false-negatives). */
const SEARCH_COLUMNS = {
  nodes: {
    one: 'entity', many: 'entities',
    none: 'No entities match. Try a shorter fragment of the name, handle '
      + 'or selector value.',
    pick: (hit) => { selectNode(hit.id); selectTab('graph'); },
  },
  evidence: {
    one: 'exhibit', many: 'exhibits',
    none: 'No exhibits match. Try one word of the title, or a shorter '
      + 'fragment of it.',
    pick: (hit) => focusEvidence(hit.id),
  },
};

function searchPath(kind, q, limit) {
  return cpath('/search/' + kind + '?with_total=true&limit=' + limit
    + '&q=' + encodeURIComponent(q));
}

async function runSearch(event) {
  event.preventDefault();
  const q = $('search-q').value.trim();
  if (!q) return;
  const token = caseToken();
  const seq = ++searchSeq;
  const nodeBox = $('search-nodes'), evBox = $('search-evidence');
  clear(nodeBox); clear(evBox);
  nodeBox.appendChild(el('p', 'help', 'Searching…'));
  evBox.appendChild(el('p', 'help', 'Searching…'));
  /* The case the results belong to, named on screen, so a screenshot or a
     shared screen says which case file they came from. */
  const code = state.caseRec ? state.caseRec.code : 'this case';
  setMsg($('search-scope'), 'Results for "' + visibleText(q) + '" in ' + code + '.');
  /* CR18: allSettled, so one column's failure does not blank the other.
     The two calls share the `search` rate-limit meter and race it, so a
     429 on one is ordinary. Before CR18 it cleared both boxes and reported
     a single error, losing results that had already arrived. */
  const [nodeRes, evRes] = await Promise.allSettled([
    api(searchPath('nodes', q, SEARCH_FIRST)),
    api(searchPath('evidence', q, SEARCH_FIRST)),
  ]);
  if (caseChanged(token) || seq !== searchSeq) return;
  showSearchColumn(nodeBox, 'nodes', nodeRes, q);
  showSearchColumn(evBox, 'evidence', evRes, q);
}

function showSearchColumn(box, kind, settled, q) {
  if (settled.status === 'fulfilled') renderHits(box, kind, settled.value, q);
  else searchProblem(box, settled.reason);
}

/* A failed column says so in the column. An empty box after "Searching…"
   reads as "no matches", which is the one wrong answer a search pane can
   give without anyone noticing. */
function searchProblem(box, err) {
  clear(box);
  const why = err instanceof ApiError ? (err.detail || err.title) : '';
  box.appendChild(el('p', 'form-error',
    why ? 'Search failed: ' + why : 'Search failed.'));
  if (!(err instanceof ApiError && err.status >= 400 && err.status < 500)) fail(err);
}

function renderHits(box, kind, page, q) {
  const column = SEARCH_COLUMNS[kind];
  clear(box);
  const hits = (page && page.hits) || [];
  const total = page && Number.isFinite(page.total) ? page.total : hits.length;
  if (!hits.length) { box.appendChild(el('p', 'empty', column.none)); return; }
  /* silent-truncation-50 (ux09-search, 2026-09-22): the pane drew the
     first 50 of 73 with nothing to say so, and the analyst took the list
     as every entity matching the term. */
  box.appendChild(el('p', 'hit-count', hits.length < total
    ? 'Showing ' + hits.length + ' of ' + total + ' ' + column.many
      + ', best match first.'
    : total + ' ' + (total === 1 ? column.one : column.many) + '.'));
  for (const hit of hits) box.appendChild(hitButton(hit, q, column.pick));
  if (hits.length >= total) return;
  if (hits.length < SEARCH_MAX) {
    const more = el('button', 'btn small hit-more',
      'Show ' + (Math.min(total, SEARCH_MAX) === total ? 'all ' : 'the first ')
      + Math.min(total, SEARCH_MAX));
    more.type = 'button';
    more.addEventListener('click', () => moreHits(box, kind, q, more));
    box.appendChild(more);
  } else {
    box.appendChild(el('p', 'help', 'The server returns at most ' + SEARCH_MAX
      + '. Narrow the query to reach the rest.'));
  }
}

async function moreHits(box, kind, q, button) {
  const token = caseToken();
  const seq = searchSeq;
  button.disabled = true;
  button.textContent = 'Loading…';
  let settled;
  try {
    settled = { status: 'fulfilled', value: await api(searchPath(kind, q, SEARCH_MAX)) };
  } catch (err) {
    settled = { status: 'rejected', reason: err };
  }
  if (caseChanged(token) || seq !== searchSeq) return;
  showSearchColumn(box, kind, settled, q);
}

function hitButton(hit, q, onPick) {
  const b = el('button', 'hit');
  b.type = 'button';
  const main = el('span', 'hit-main');
  /* CR14: the bulk load paths map through `withSafeLabel` at landing (see
     loadCaseGraph). Search did not, and Search is the primary find-by-name
     tool, so a label carrying U+202E rendered de-fanged everywhere else
     and raw here, in the one place an analyst clicks a name to decide
     which entity they are looking at. The selector value below gets the
     same treatment for the same reason. */
  main.appendChild(el('span', 'hit-label', visibleText(hit.label)));
  const via = viaLine(hit, q);
  if (via) main.appendChild(el('span', 'hit-via', via));
  b.appendChild(main);
  const rank = Number(hit.rank);
  b.appendChild(el('span', 'rank', Number.isFinite(rank) ? rank.toFixed(3) : ''));
  b.addEventListener('click', () => onPick(hit));
  return b;
}

/* The selector that put an entity in the results (selectors-unsearchable,
   ux09-search, 2026-09-22). Shown when the name does not already say why
   the entity is here, which is the usual case for a wallet or a Jabber id,
   and always for an exact match, because "this wallet is this entity's"
   is the finding. */
function viaLine(hit, q) {
  const v = hit.via;
  /* final review U10, 2026-09-23: a merged record's own name now finds
     its survivor, and the server names the record whose name matched
     when it is the only reason or the better one. Without this line the
     survivor would be a hit whose name does not contain the query, or
     ranks 1.000 on a partial match of it, and nothing on screen says why.
     An exact selector still says more, so it wins. */
  if (hit.merged_name && !(v && v.exact)) {
    return 'via the name of merged record ' + visibleText(hit.merged_name);
  }
  /* Names and attributes share one search vector, so "meridian" found
     mer_ash, mer_kite and mer_ledger through crew=meridian and the hits
     read as a match on the "mer" of their names. The server names the
     attribute only when nothing else explains the hit (README screenshot
     review, 2026-09-23). An attribute key is data like a label, so it is
     de-fanged the same way. */
  if (!v && hit.attribute) {
    return 'via attribute ' + visibleText(hit.attribute);
  }
  if (!v) return '';
  const inName = String(hit.label || '').toLowerCase()
    .includes(String(q || '').toLowerCase());
  if (inName && !v.exact) return '';
  let line = 'via selector ' + v.selector_type + ' ' + visibleText(v.value);
  if (v.exact) line += ' (exact)';
  if (v.more) line += ', and ' + v.more + ' more';
  if (v.merged_from) line += ', held by merged record ' + visibleText(v.merged_from);
  return line;
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
/** The display label for a node id, never null.
 *
 *  Falls through the entity list (the richer record), then the projection
 *  (a node the sociogram drew that the entity page does not hold), then a
 *  placeholder that says what it stands in for and carries the short id.
 *
 *  THE ONLY declaration. Until 2026-09-09 there were two: this one, and a
 *  second at the merge panel that consulted `state.nodes` alone and
 *  returned `null`. Function declarations hoist and the last one wins, so
 *  every caller written against this one -- the focus flag, the path
 *  anchor, `edgeById`'s synthesised endpoint labels, the palette -- printed
 *  "ego of null" for any projection-only node. Nothing threw, which is why
 *  it shipped. The merge panel's own callers are served by the same
 *  fallback and no longer guard against a null this cannot return.
 */
function labelOf(id) {
  const n = nodeById(id);
  if (n && typeof n.label === 'string' && n.label) return n.label;
  return 'entity ' + shortId(id);
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
    /* fmtWhen, not a local-time formatter: a day-precision value read
       back a day early west of UTC (ux05-inspector:dates-shift-a-day,
       2026-09-22). The validity interval is the node's world time, which
       the form records and this line never showed. */
    sub.textContent = n.id + ' · ' + fmtInterval(n.valid_from, n.valid_to)
      + ' · first seen ' + fmtWhen(n.first_seen)
      + ' · last seen ' + fmtWhen(n.last_seen);
    show($('insp-sel-sec'), true);
    show($('insp-metrics-sec'), true);
    show($('insp-merge-sec'), true);
    renderMergePanel(n);
    renderNodeMetrics(sel.id);
  } else {
    /* `relTieCache`: a tie the Relationships list fetched for one entity
       can lie beyond the case's first 1000, which is all `state.edges`
       holds, and opening it from that list must not drop the selection. */
    const e = edgeById(sel.id) || relTieCache.get(sel.id) || null;
    if (!e) { state.selection = null; renderInspector(); return; }
    typeChip.className = 'chip type-chip';
    typeChip.textContent = e.edge_type;
    classChip.className = 'chip tlp-' + e.classification;
    classChip.textContent = 'TLP:' + e.classification;
    /* Through `tieEndLabel`: `/edges` hands back endpoint labels raw, and
       this line names the two actors the analyst is judging. */
    $('insp-label').textContent = tieEndLabel(e, 'src') + ' → ' + tieEndLabel(e, 'dst');
    const signWord = e.sign > 0 ? 'positive tie'
      : (e.sign < 0 ? 'negative tie' : 'neutral tie');
    /* Named for what it is (ux05 two-disagreeing-confidences, 2026-09-23).
       The data half of that finding made a tie's stored confidence its
       strongest live claim (migration 0064), so this and the assertion
       cards below can no longer disagree, and a disagreement flag would
       never fire. What was left was the wording: a bare 'opacity 1.00'
       read as a probability, and nothing said this is the value the canvas
       draws and the confidence filter tests.
       "LOW when none grades it" since the final review (U11, 2026-09-23):
       a tie held up only by a weight or attribute correction has no live
       claim that grades it, takes LOW, and was described as resting on
       "its strongest live claim" when it rested on none. */
    sub.textContent = signWord + ' · weight ' + e.weight +
      ' · confidence ' + e.confidence +
      ' (the highest grade among its live claims, LOW when none grades it;' +
      ' the canvas and the filter use it)' +
      ' · ' + (e.is_inferred ? 'INFERRED (dashed, excluded from metrics unless ' +
                              'the projection opts in)' : 'asserted') +
      ' · review ' + e.review + ' · ' + fmtInterval(e.valid_from, e.valid_to);
    show($('insp-sel-sec'), false);
    show($('insp-metrics-sec'), false);
    show($('insp-merge-sec'), false);
  }

  show($('insp-actions'), true);
  /* Linking starts from an entity, never from a tie. */
  show($('btn-link-from'), sel.kind === 'node');
  show($('btn-link-to'), sel.kind === 'node');
  /* Adding a claim is offered on a tie (final review C14, 2026-09-23). */
  syncTieClaim(sel);

  const seq = ++state.inspSeq;
  renderRelationships(sel, seq);
  const base = cpath((sel.kind === 'node' ? '/nodes/' : '/edges/') + sel.id);
  /* ALWAYS with the retracted rows; the checkbox decides only what
     renderAssertions SHOWS. The Retract confirmation has to count what
     actually holds the element up, and the projection's live-provenance
     leg is `retracted_at IS NULL AND superseded_at IS NULL` (the second
     half since the final review, U11): counting the rendered list instead told
     an analyst with "Include retracted" ticked that the element would stay
     when it was about to vanish (ux05 retract-confirmation-wrong,
     2026-09-22). */
  /* What the section holds, and whether it is still loading or failed,
     so the Evidence section's "Show assertion" can say WHY a card is
     missing instead of always blaming the checkbox. */
  const load = assertLoad = { key: sel.kind + ':' + sel.id, all: null, failed: false };
  loadInto($('insp-assertions'), seq, async () => {
    try {
      const all = await api(base + '/assertions?include_retracted=true');
      load.all = all;
      return all;
    } catch (err) { load.failed = true; throw err; }
  }, renderAssertions);
  loadInto($('insp-evidence'), seq, () => api(base + '/evidence'),
    renderLinkedEvidence);
  /* Tags are node-only for now: `core.tag_assignment` can carry an edge or
     an evidence target too, but the router exposes node assignment alone,
     so the section is hidden rather than rendered empty against an edge —
     an empty panel reads as "no tags", not "not supported here". */
  const tagSec = $('insp-tags-sec');
  if (tagSec) tagSec.hidden = sel.kind !== 'node';

  if (sel.kind === 'node') {
    loadInto($('insp-selectors'), seq, () => api(base + '/selectors'),
      renderSelectors);
    loadInto($('insp-tags'), seq,
      () => api(cpath('/curation/nodes/' + sel.id + '/tags')),
      (box, list) => renderTags(box, list, sel));
  }
}

/* The inspector's reads are case-scoped. A case switch bumps `inspSeq`, so
 * a section still loading for the old case's selection drops its reply in
 * `loadInto` instead of rendering it under the new case, and forgets what
 * the old selection had linked (the 2026-09-22 case-switch registry). */
onCaseSwitch(() => {
  state.inspSeq = (state.inspSeq || 0) + 1;
  state.linkedEvidenceIds = [];
  relTieCache.clear();
  relShowAll = null;
  assertLoad = null;
});

/* ── inspector: relationships ──────────────────────────────────────────
 *
 * ux05 parallel-ties-unreachable and ux18 edges-mouse-only (2026-09-22).
 * An existing tie could be opened ONE way: a mouse click on the canvas,
 * which `edgeAt` resolves to the first link within 6px. Two ties between
 * one pair lie along the same line, so the second could never be opened
 * (NIGHTJAR holds 49 such pairs, one of them a vouch and a dispute, where
 * clicking the red dispute line opened the vouch), and a keyboard or
 * screen-reader analyst could open no tie at all, because `onCanvasKey`
 * steps through entities only. The model records disagreement as separate
 * ties on purpose ("two analysts, two claims, both recorded"), so an
 * inspector that reaches only one of them shows the wrong one.
 *
 * So the entity inspector lists EVERY tie at the entity, and the tie
 * inspector names its two ends and every OTHER tie between the same pair.
 * Every row is a <button> into the tie inspector, and T on the sociogram
 * jumps here. Drawing parallel ties apart on the canvas is the painter's
 * half of the fix and is not done here.
 *
 * Rows come from the projection first (what the canvas draws), then from
 * the unprojected tie list marked "not drawn": a tie a filter leaves off
 * the canvas is still a claim somebody may need to open. That list is
 * fetched for the ENTITY (`/edges?node_id=`), not taken from the case-wide
 * page the console loads at open, because that page stops at 1000 ties
 * and a list that says "every tie" must not quietly stop there too (the
 * 2026-09-22 verifier). The rows the console already holds are painted at
 * once, and repainted when the entity's own list arrives.
 */

const TIE_ROWS_SHOWN = 8;
/** The most ties one entity's list is fetched with. The server caps
 *  `/edges` at 2000; a full page is said to be a page. */
const REL_TIE_PAGE = 2000;
/** Ties fetched for an entity's list: id -> the `/edges` record. Cleared
 *  on a case switch. Read by renderInspector for a tie not in state.edges. */
const relTieCache = new Map();
/** The selection whose list the analyst expanded with "Show all", so a
 *  repaint when the full list arrives does not fold it back up. */
let relShowAll = null;

/** Every tie the console holds: id -> {e, drawn}, projection first. */
function allTies() {
  const out = new Map();
  for (const g of state.gedges) out.set(g.id, { e: g, drawn: true });
  for (const x of state.edges) {
    if (!out.has(x.id)) out.set(x.id, { e: x, drawn: false });
  }
  for (const x of relTieCache.values()) {
    if (!out.has(x.id)) out.set(x.id, { e: x, drawn: false });
  }
  return out;
}

/** One end of a tie, by name, de-fanged. The node records went through
 *  `withSafeLabel` where they landed; `/edges` endpoint labels did not. */
function tieEndLabel(e, end) {
  const id = end === 'src' ? e.src_node_id : e.dst_node_id;
  const n = nodeById(id);
  if (n && typeof n.label === 'string' && n.label) return n.label;
  const raw = end === 'src' ? e.src_label : e.dst_label;
  return raw ? visibleText(raw) : labelOf(id);
}

function tieSignWord(sign) {
  return sign > 0 ? 'positive' : (sign < 0 ? 'negative' : 'neutral');
}

function samePair(a, b) {
  return (a.src_node_id === b.src_node_id && a.dst_node_id === b.dst_node_id)
      || (a.src_node_id === b.dst_node_id && a.dst_node_id === b.src_node_id);
}

/** Drawn ties first, then by the other end's name, then by type, so the
 *  list reads the same way twice. */
function tieOrder(from) {
  const other = (e) => (from && e.src_node_id === from
    ? tieEndLabel(e, 'dst') : tieEndLabel(e, 'src')).toLowerCase();
  return (a, b) => (Number(b.drawn) - Number(a.drawn))
    || other(a.e).localeCompare(other(b.e))
    || String(a.e.edge_type).localeCompare(String(b.e.edge_type));
}

/** Select an element from inside the inspector and put focus on its name.
 *  The list that held the button has just been rebuilt under it, so focus
 *  would otherwise fall to <body> and a screen reader would say nothing
 *  about what was opened. */
function openFromInspector(kind, id) {
  if (kind === 'edge') selectEdge(id); else selectNode(id);
  const label = $('insp-label');
  if (label) label.focus();
}

/** One tie as a button into the tie inspector. `from` is the entity the
 *  list belongs to, so a tie reads as outgoing (→) or incoming (←); null
 *  names both ends. Type, direction, sign, confidence and review are all
 *  on the row, because telling a vouch from a dispute between the same two
 *  actors is the reason the row exists. */
function tieButton(rec, from) {
  const e = rec.e;
  const src = tieEndLabel(e, 'src'), dst = tieEndLabel(e, 'dst');
  const out = from && e.src_node_id === from;
  const b = el('button', 'tie-item' + (rec.drawn ? '' : ' undrawn'));
  b.type = 'button';
  /* So a repaint can put focus back on the same tie. */
  b.dataset.tieFocus = 'tie-' + e.id;
  let who, dir;
  if (!from) { who = src + ' → ' + dst; dir = 'from ' + src + ' to ' + dst; }
  else if (out && e.dst_node_id === from) { who = '↻ itself'; dir = 'to itself'; }
  else if (out) { who = '→ ' + dst; dir = 'to ' + dst; }
  else { who = '← ' + src; dir = 'from ' + src; }
  b.appendChild(el('span', 'tie-who', who));
  const facts = el('span', 'tie-facts');
  facts.appendChild(el('span', 'tie-type', e.edge_type));
  facts.appendChild(el('span', 'tie-sign ' + tieSignWord(e.sign),
    e.sign > 0 ? '+' : (e.sign < 0 ? '−' : '0')));
  /* Confidence as the same opacity-plus-word the assertion cards use:
     never a hue (docs/06). */
  facts.appendChild(el('span', 'conf conf-' + e.confidence, e.confidence));
  facts.appendChild(el('span', 'tie-flag', e.review));
  if (e.is_inferred) facts.appendChild(el('span', 'tie-flag', 'inferred'));
  if (!rec.drawn) facts.appendChild(el('span', 'tie-flag', 'not drawn'));
  b.appendChild(facts);
  b.setAttribute('aria-label', e.edge_type + ' ' + dir + ', '
    + tieSignWord(e.sign) + ' tie, confidence ' + e.confidence + ', review '
    + e.review + (e.is_inferred ? ', inferred' : ', asserted')
    + (rec.drawn ? '' : ', not drawn in this projection')
    + '. Opens the tie in the inspector.');
  b.addEventListener('click', () => openFromInspector('edge', e.id));
  return b;
}

/** Rows up to TIE_ROWS_SHOWN, then a button for the rest: a hub with sixty
 *  ties would otherwise push Assertions off the bottom of the rail. `key`
 *  names the selection, so an expanded list stays expanded on a repaint. */
function appendTieRows(box, recs, from, key) {
  const all = relShowAll === key;
  const first = all ? recs : recs.slice(0, TIE_ROWS_SHOWN);
  for (const rec of first) box.appendChild(tieButton(rec, from));
  if (all || recs.length <= TIE_ROWS_SHOWN) return;
  const more = el('button', 'btn ghost small',
    'Show all ' + recs.length + ' ties');
  more.type = 'button';
  more.dataset.tieFocus = 'more';
  more.addEventListener('click', () => {
    relShowAll = key;
    const rest = recs.slice(TIE_ROWS_SHOWN).map((rec) => tieButton(rec, from));
    more.replaceWith(...rest);
    if (rest.length) rest[0].focus();
  });
  box.appendChild(more);
}

function endButton(e, end) {
  const id = end === 'src' ? e.src_node_id : e.dst_node_id;
  const name = tieEndLabel(e, end);
  const b = el('button', 'btn ghost small tie-end', name);
  b.type = 'button';
  b.dataset.tieFocus = 'end-' + end;
  b.setAttribute('aria-label', 'Open the ' + (end === 'src' ? 'source' : 'target')
    + ' entity, ' + name);
  b.addEventListener('click', () => openFromInspector('node', id));
  return b;
}

/** What the list cannot yet vouch for, as a sentence, or null when it is
 *  complete. `status`: 'loading' (only what the console held at case
 *  open is painted), 'failed' (the entity's own list could not be read),
 *  'page-full' (it filled a page, so there may be more) or 'complete'.
 *  `kind` is the selection's. Pure, for test_inspector_evidence_ui.py. */
function tieListNote(status, kind) {
  const scope = kind === 'edge' ? 'Other ties between this pair'
    : 'Ties at this entity';
  if (status === 'loading') {
    return 'Reading every tie ' + (kind === 'edge' ? 'between this pair'
      : 'at this entity') + ' from the case…';
  }
  if (status === 'failed') {
    return 'The full tie list could not be read, so this shows only the ties '
      + 'loaded when the case opened (its first 1000). ' + scope
      + ' may be missing.';
  }
  if (status === 'page-full') {
    return 'This entity has more ties than one read returns, so only the '
      + 'first ' + REL_TIE_PAGE + ' are listed. ' + scope + ' may be missing.';
  }
  return null;
}

/** Paint the Relationships section from the ties the console holds now.
 *  Called twice per selection: at once, and again when the entity's own
 *  tie list arrives. Focus on a tie row survives the repaint. */
function paintRelationships(sel, status) {
  const sec = $('insp-rel-sec'), box = $('insp-rel'), count = $('insp-rel-count');
  if (!sec || !box) return;
  const active = document.activeElement;
  const focusKey = active && box.contains(active) && active.dataset
    ? (active.dataset.tieFocus || 'first') : null;
  clear(box);
  show(sec, true);
  const ties = allTies();
  const key = sel.kind + ':' + sel.id;
  const note = tieListNote(status, sel.kind);
  const more = status === 'page-full' || status === 'failed' ? '+' : '';

  if (sel.kind === 'node') {
    const mine = [];
    for (const rec of ties.values()) {
      if (rec.e.src_node_id === sel.id || rec.e.dst_node_id === sel.id) mine.push(rec);
    }
    mine.sort(tieOrder(sel.id));
    const undrawn = mine.filter((r) => !r.drawn).length;
    /* Drawn and not drawn counted apart, so this agrees with the metrics
       panel's "Ties in projection" rather than appearing to contradict it. */
    count.textContent = (mine.length - undrawn) + ' drawn'
      + (undrawn || more ? ' · ' + undrawn + more + ' not' : '');
    if (!mine.length) {
      box.appendChild(el('p', 'empty', status === 'complete'
        ? 'No ties at this entity.' : 'No ties at this entity loaded yet.'));
    } else {
      appendTieRows(box, mine, sel.id, key);
    }
    if (undrawn) {
      box.appendChild(el('p', 'help', undrawn + ' of these ' + (undrawn === 1
        ? 'is' : 'are') + ' not drawn: the projection\'s preset, confidence, '
        + 'inferred or as-of filter leaves ' + (undrawn === 1 ? 'it' : 'them')
        + ' off the canvas, or no live assertion holds ' + (undrawn === 1
        ? 'it' : 'them') + ' up any more.'));
    }
  } else {
    const rec = ties.get(sel.id);
    const e = rec ? rec.e : edgeById(sel.id);
    if (!e) { show(sec, false); return; }
    const ends = el('div', 'tie-ends');
    ends.appendChild(el('span', 'label', 'Between'));
    ends.appendChild(endButton(e, 'src'));
    ends.appendChild(el('span', 'tie-arrow', '→'));
    ends.appendChild(endButton(e, 'dst'));
    box.appendChild(ends);
    if (rec && !rec.drawn) {
      box.appendChild(el('p', 'help', 'This tie is not drawn in the current '
        + 'projection.'));
    }
    const others = [];
    for (const r of ties.values()) {
      if (r.e.id !== e.id && samePair(r.e, e)) others.push(r);
    }
    others.sort(tieOrder(null));
    count.textContent = others.length
      ? (others.length + 1) + more + ' ties in this pair'
      : (more ? 'others unknown' : 'the only tie');
    if (!others.length) {
      if (status === 'complete') {
        box.appendChild(el('p', 'help', 'No other tie joins this pair.'));
      }
    } else {
      /* Said out loud and in the alert tone: until 2026-09-22 nothing here
         admitted a second tie existed, and the one the click opened was not
         necessarily the one drawn on top. */
      box.appendChild(el('p', 'help warn', 'This pair has ' + others.length
        + more + ' other tie' + (others.length === 1 && !more ? '' : 's')
        + '. Each is a separate claim with its own assertions and grading; '
        + 'open ' + (others.length === 1 ? 'it' : 'each') + ' here.'));
      appendTieRows(box, others, null, key);
    }
  }
  if (note) box.appendChild(el('p', 'help' + (status === 'loading' ? '' : ' warn'), note));
  /* The keyboard analyst who pressed T before the full list arrived keeps
     their place: the same row if it is still listed, else the first. */
  if (focusKey) {
    const buttons = Array.from(box.querySelectorAll('button'));
    const again = buttons.find((b) => b.dataset.tieFocus === focusKey)
      || buttons[0] || box;
    again.focus();
  }
}

/** The Relationships section for a selection: painted at once from what
 *  the console holds, then completed from the entity's own tie list (for a
 *  tie, its source end's, which holds every tie of the pair). `seq` is the
 *  inspector's, so a reply for a selection or a case that has since
 *  changed is dropped. */
function renderRelationships(sel, seq) {
  paintRelationships(sel, 'loading');
  let anchor = sel.id;
  if (sel.kind === 'edge') {
    const e = edgeById(sel.id) || relTieCache.get(sel.id);
    if (!e) return;
    anchor = e.src_node_id;
  }
  const token = caseToken();
  api(cpath('/edges?node_id=' + encodeURIComponent(anchor) + '&limit='
            + REL_TIE_PAGE + '&include_inferred=true'))
    .then((list) => {
      if (seq !== state.inspSeq || caseChanged(token)) return;
      for (const x of list) relTieCache.set(x.id, x);
      paintRelationships(sel, list.length >= REL_TIE_PAGE ? 'page-full' : 'complete');
    })
    .catch(() => {
      /* No banner: the section says what it could not read, in place, and
         still lists every tie the console already held. */
      if (seq !== state.inspSeq || caseChanged(token)) return;
      paintRelationships(sel, 'failed');
    });
}

/** T on the sociogram: move focus into the Relationships list, the one
 *  keyboard route to a tie. A listener of its own, next to the list it
 *  serves, rather than another branch in `onCanvasKey`. */
function focusRelationships() {
  const sec = $('insp-rel-sec'), box = $('insp-rel');
  if (!sec || sec.hidden || !box) return false;
  const target = box.querySelector('button') || box;
  target.focus();
  return true;
}

function wireRelationshipKeys() {
  canvas.addEventListener('keydown', (e) => {
    if (e.key !== 't' && e.key !== 'T') return;
    if (e.ctrlKey || e.metaKey || e.altKey || !state.selection) return;
    e.preventDefault();
    focusRelationships();
  });
}

/* Tags on the selected node, plus the controls to add and remove them.
 *
 * `state.caseTags` is the case's vocabulary, fetched once per case render
 * so the picker does not re-query on every selection change. A tag the
 * node already carries is excluded — assigning twice is idempotent at the
 * endpoint, but offering it invites a click that appears to do nothing.
 */
function renderTags(box, list, sel) {
  if (!list.length) box.appendChild(el('p', 'empty', 'No tags.'));

  const chips = el('div', 'tag-chips');
  for (const t of list) {
    const chip = el('span', 'chip tag-chip');
    /* namespace:name, because a bare "broker" means different things in
       different namespaces and the schema keys uniqueness on the pair. */
    chip.appendChild(el('span', null, t.namespace + ':' + t.name));
    if (t.scope === 'global') {
      /* A global tag is shared vocabulary (MITRE ATT&CK and the like).
         Marked so nobody assumes an unfamiliar one was coined on this
         case. */
      chip.appendChild(el('span', 'tag-scope', 'global'));
    }
    const drop = el('button', 'tag-x', '×');
    drop.type = 'button';
    drop.title = 'Remove this tag from the entity';
    drop.setAttribute('aria-label', 'Remove tag ' + t.namespace + ':' + t.name);
    drop.addEventListener('click', async () => {
      drop.disabled = true;
      try {
        await api(cpath('/curation/tags/' + t.id + '/nodes/' + sel.id),
                  { method: 'DELETE' });
        renderInspector();
      } catch (err) { fail(err); drop.disabled = false; }
    });
    chip.appendChild(drop);
    chips.appendChild(chip);
  }
  if (list.length) box.appendChild(chips);

  const already = new Set(list.map((t) => t.id));
  const free = (state.caseTags || []).filter((t) => !already.has(t.id));
  const row = el('div', 'insp-linker');
  if (free.length) {
    const pick = el('select', 'input small');
    pick.setAttribute('aria-label', 'Tag to apply');
    pick.appendChild(el('option', null, 'Apply a tag…'));
    for (const t of free) {
      const o = el('option', null,
                   t.namespace + ':' + t.name +
                   (t.scope === 'global' ? ' (global)' : ''));
      o.value = t.id;
      pick.appendChild(o);
    }
    const go = el('button', 'btn small', 'Tag');
    go.type = 'button';
    go.addEventListener('click', async () => {
      if (!pick.value) return;
      go.disabled = true;
      try {
        await api(cpath('/curation/tags/' + pick.value + '/nodes'),
                  { method: 'POST', json: { node_id: sel.id } });
        renderInspector();
      } catch (err) { fail(err); go.disabled = false; }
    });
    row.appendChild(pick);
    row.appendChild(go);
  }

  const make = el('button', 'btn ghost small', 'New tag…');
  make.type = 'button';
  make.addEventListener('click', async () => {
    /* `prompt` rather than a modal: this is one short string, the console
       has no modal primitive, and inventing one for a tag name would be
       more surface than the feature is worth. */
    const raw = window.prompt(
      'New tag as namespace:name (e.g. role:broker)');
    if (!raw) return;
    const at = raw.indexOf(':');
    if (at < 1 || at === raw.length - 1) {
      banner('Tag not created',
             'Use namespace:name. Both halves are required, because the ' +
             'same name means different things in different namespaces.');
      return;
    }
    try {
      const made = await api(cpath('/curation/tags'), {
        method: 'POST',
        json: { namespace: raw.slice(0, at).trim(), name: raw.slice(at + 1).trim() },
      });
      await loadCaseTags();
      await api(cpath('/curation/tags/' + made.id + '/nodes'),
                { method: 'POST', json: { node_id: sel.id } });
      renderInspector();
    } catch (err) { fail(err); }
  });
  row.appendChild(make);
  box.appendChild(row);
}

/* ── correcting and retiring the selected element ──────────────────────
 *
 * Both endpoints landed 2026-07-30 and neither had a caller. The verbs
 * (`graph.node.update`, `graph.node.delete`, `graph.edge.update`,
 * `graph.edge.delete`) were seeded in 0017 and granted in 0021, and
 * nothing had ever checked them.
 *
 * TWO THINGS HERE ARE EASY TO GET WRONG AND ARE DELIBERATE:
 *
 * `attrs` is NEVER sent. The endpoint treats it as a WHOLE-OBJECT
 * REPLACEMENT (`COALESCE(%s::jsonb, attrs)`), so sending a partial object
 * silently deletes every attribute not in it. Omitting the field entirely
 * is the only safe thing a label-correction dialogue can do, and editing
 * attributes needs a real form that starts from the current object.
 *
 * The DELETEs REQUIRE a JSON body `{reason}`. A bodyless
 * `fetch(..., {method:'DELETE'})` returns 422 — the most likely
 * integration break in this pair, and the reason is not optional because
 * retiring a hub dissolves every tie it carries and a reviewer six months
 * later cannot reconstruct why.
 */
/* Case lifecycle: correct, share, close.
 *
 * `CaseService.update_metadata` and `assign_user_checked` have existed
 * since Phase 1 with no router, and `POST /status` had a router that
 * nothing called. So a case could be created from the browser and then
 * never corrected, shared or closed from it — only through
 * `scripts/bootstrap.py`, which is not a thing an analyst has.
 *
 * CLASSIFICATION IS NOT EDITABLE HERE, and the endpoint refuses to lower
 * it at all. Raising is safe (every element is read at the stricter of its
 * own label and the case's, so the case going RED covers everything
 * inside it); lowering declassifies in one statement everything that was
 * protected only by the case label, and is not undone by raising it back.
 * It needs its own verb with step-up, so it is absent rather than
 * half-offered.
 */
function wireCaseActions() {
  const edit = $('btn-case-edit');
  const share = $('btn-case-share');
  const status = $('btn-case-status');
  if (!edit || !share || !status) return;
  /* The non-ACTIVE strip's own way to the lifecycle control, so "reopen
     it first" is one click from where it is said (ux02-cases, 2026-09-22). */
  $('case-state-change').addEventListener('click', () => status.click());

  edit.addEventListener('click', async () => {
    const rec = state.caseRec;
    if (!rec || !state.caseId) return;
    const title = window.prompt('Case title', rec.title);
    if (title === null) return;
    if (!title.trim()) {
      banner('Not saved', 'A case title cannot be blank.');
      return;
    }
    try {
      await api('/cases/' + state.caseId,
                { method: 'PATCH', json: { title: title.trim() } });
      await openCase(state.caseId);
    } catch (err) { fail(err); }
  });

  /* A panel, not two prompts: see `openShare`. */
  share.addEventListener('click', openShare);
  $('share-form').addEventListener('submit', submitShare);
  $('share-close').addEventListener('click', closeShare);
  $('share-scrim').addEventListener('click', (e) => {
    if (e.target === e.currentTarget) closeShare();
  });
  /* On the document, not the sheet: a button disabled while its request
     is in flight drops focus to <body>, and a listener on the sheet then
     never hears the Escape. */
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && !$('share-scrim').hidden) {
      e.preventDefault();
      closeShare();
    }
  });

  status.addEventListener('click', async () => {
    const rec = state.caseRec;
    if (!rec || !state.caseId) return;
    const next = window.prompt(
      'Current status: ' + rec.status + '\n\n' +
      'New status: DRAFT, ACTIVE, DORMANT, CLOSED, ARCHIVED or PURGED.\n' +
      'The transition table decides what is legal from here.',
      rec.status === 'ACTIVE' ? 'CLOSED' : 'ACTIVE');
    if (next === null || !next.trim()) return;
    try {
      await api('/cases/' + state.caseId + '/status',
                { method: 'POST', json: { status: next.trim().toUpperCase() } });
      await openCase(state.caseId);
      banner('Status changed', 'This case is now ' + next.trim().toUpperCase() + '.');
    } catch (err) { fail(err); }
  });
}

/* The audit chain, verified on demand.
 *
 * Deliberately a button rather than a load-on-open: this recomputes a
 * SHA-256 over every audit row ever written, and a panel that did it on
 * every visit would be a self-inflicted denial of service on the one
 * surface an officer reaches for during an incident.
 *
 * `checked` is reported next to the verdict on purpose. `intact` is true
 * for an empty window as well as a verified one — "0 events, intact" is
 * not a pass, and a UI that showed only a green tick would say it was.
 */
function wireAuditVerify() {
  const btn = $('btn-audit-verify');
  if (!btn) return;
  btn.addEventListener('click', async () => {
    const box = $('audit-verdict');
    box.textContent = '';
    btn.disabled = true;
    box.appendChild(el('p', 'help', 'recomputing…'));
    let r;
    try {
      r = await api('/audit/verify');
    } catch (err) {
      box.textContent = '';
      /* A 403 here is the expected answer for most accounts, not a
         malfunction, so it is explained rather than thrown at the banner
         stack as an error.
         THROUGH `refusalText`, which puts the SERVER's detail first. The
         first version of this asserted "your account does not hold
         audit.read" — a guess about the caller, and exactly the mistake
         `refusalText` exists to stop: three strings in this file once
         told the holder of a permission that they did not hold it,
         because the real refusal was a stale step-up. An inactive account
         403s the same way here. The written context is kept after it,
         because WHY the verb is scarce is worth saying. */
      if (err instanceof ApiError && err.status === 403) {
        box.appendChild(el('p', 'help warn', refusalText(err,
          'audit.read is granted to SECURITY_OFFICER alone: the ' +
          'administrator configures, the officer audits, and neither ' +
          'reads case content by default.')));
      } else { fail(err); }
      btn.disabled = false;
      return;
    }
    btn.disabled = false;
    box.textContent = '';

    const ok = r.intact && r.checked > 0;
    const head = el('div', 'card');
    head.appendChild(el('span', 'chip ' + (ok ? 'good' : 'bad'),
      r.checked === 0 ? 'NOTHING TO CHECK' : (r.intact ? 'INTACT' : 'BROKEN')));
    /* Counts agree with their nouns and verbs: a bracketed plural
       hedged a number the line already knew (README screenshot set
       review, 2026-09-23). The noun is chosen from the number, not from
       the grouped text, which a locale can print as "1.000". */
    head.appendChild(el('p', 'help',
      r.checked.toLocaleString() + ' ' + agree(r.checked, 'event', 'events')
      + ' checked' +
      (r.first_seq ? ' · seq ' + r.first_seq + ' to ' + r.last_seq : '')));
    if (r.windowed && r.caveat) head.appendChild(el('p', 'help warn', r.caveat));
    /* Forks are shown as a SEPARATE, quieter line and never as a break.
       They come from concurrent writers, not from editing, and a real
       database has them: counting them as tampering made this panel answer
       BROKEN on untouched history, which is the one answer a tamper-
       evidence tool cannot afford to get wrong twice. */
    if (r.forks) {
      head.appendChild(el('p', 'help',
        countOf(r.forks, 'row shares', 'rows share') + ' a predecessor. '
        + (r.fork_note || '')));
    }
    box.appendChild(head);

    if (!r.breaks.length) return;
    /* Each break names WHICH failure it is, because they point in opposite
       directions: LINK means a row was removed, FORK means one was
       inserted or two writers raced, CONTENT means one was edited. */
    const list = el('div', 'insp-list');
    for (const b of r.breaks.slice(0, 200)) {
      const item = el('div', 'sel-item');
      item.appendChild(el('span', 'chip bad', b.kind));
      item.appendChild(el('span', 'sel-val',
        'seq ' + b.seq + ' · ' + b.action + ' · ' + fmtTime(b.occurred_at)));
      list.appendChild(item);
    }
    box.appendChild(list);
    if (r.breaks.length > 200) {
      box.appendChild(el('p', 'help', 'showing the first 200 of ' +
                                      r.breaks.length + '.'));
    }
  });
}

function wireElementActions() {
  /* Here rather than in `wire()`: it belongs to the inspector, and this is
     the inspector's own wiring (2026-09-22, ux18 edges-mouse-only). */
  wireRelationshipKeys();
  /* The two ends of the Link form, from the entity in hand. The link-form
     group and the inspector group were built in parallel on 2026-09-22:
     the Link form grew openLinkFormFrom() for exactly this, and the
     inspector, which was not its to edit, never called it. Wired at merge. */
  for (const [id, which] of [['btn-link-from', 'src'], ['btn-link-to', 'dst']]) {
    const btn = $(id);
    if (!btn) continue;
    btn.addEventListener('click', () => {
      const sel = state.selection;
      if (sel && sel.kind === 'node') openLinkFormFrom(which, sel.id);
    });
  }
  wireTieClaim();
  const edit = $('btn-edit-element');
  const retire = $('btn-retire-element');
  if (!edit || !retire) return;

  edit.addEventListener('click', async () => {
    const sel = state.selection;
    if (!sel) return;
    let body;
    if (sel.kind === 'node') {
      const n = nodeById(sel.id);
      const label = window.prompt('Corrected label', n ? n.label : '');
      if (label === null) return;
      if (!label.trim()) {
        banner('Not corrected', 'A label cannot be blank.');
        return;
      }
      body = { label: label.trim() };
    } else {
      const e = edgeById(sel.id) || relTieCache.get(sel.id) || null;
      const now = e ? e.confidence : null;
      const conf = window.prompt(
        'Confidence: LOW, MODERATE or HIGH' +
        (now ? ' (the tie is ' + now + ' now)' : ''), now || 'LOW');
      if (conf === null) return;
      const up = conf.trim().toUpperCase();
      if (['LOW', 'MODERATE', 'HIGH'].indexOf(up) < 0) {
        banner('Not corrected', 'Confidence must be LOW, MODERATE or HIGH.');
        return;
      }
      /* Refused HERE, before the analyst writes a reason, when the
         correction would lower the tie (final review C14, 2026-09-23).
         Since 0064 the server refuses it (a correction cannot lower a tie
         past a claim that still stands), and this dialogue used to collect
         the reason first and then show a 409 naming a remedy the console
         had no control for. The only route left, retract then correct,
         recorded the founding claim as withdrawn and left the tie resting
         on an ungraded correction with no exhibit. The claim form this
         opens is the remedy the server names. */
      const lowering = tieLoweringWords(now, up);
      if (lowering) {
        openTieClaim(up);
        banner('Not corrected', lowering, 'warn');
        return;
      }
      body = { confidence: up };
    }
    /* The rationale is the assertion, and the assertion is what makes this
       a correction rather than an overwrite: the original claim survives,
       so the sequence of assertions is the history of what this element
       has been called (invariant 1). */
    const why = window.prompt('Why? This is recorded as an assertion.');
    if (why === null) return;
    /* ONLY the rationale. Everything else is left to the server's defaults
       — basis DIRECT_OBSERVATION, reliability F, credibility 6,
       confidence LOW — because those are the "not graded" values and the
       analyst has not graded anything.
       The first version of this sent `confidence: 'MODERATE'`, which the
       analyst never said. In a system whose entire premise is that nothing
       is a fact and every claim carries its Admiralty grading, inventing a
       grade on the analyst's behalf is not a small liberty: it launders an
       untyped edit into a MODERATE-confidence assertion that a reviewer
       six months later reads as somebody's considered judgement. If a
       correction should be gradable, the dialogue has to ASK — which is a
       real form, not two more prompts. */
    body.assertion = { rationale: why || null };
    try {
      await api(cpath('/graph/' + (sel.kind === 'node' ? 'nodes/' : 'edges/') + sel.id),
                { method: 'PATCH', json: body });
      await loadCaseGraph();
      refreshSociogram();
      renderInspector();
    } catch (err) { fail(err); }
  });

  retire.addEventListener('click', async () => {
    const sel = state.selection;
    if (!sel) return;
    /* NAME the element, COUNT what goes with it, and promise no undo. The
       prompt said "clearing the flag brings it back", and no route,
       service method or control ever clears `deleted_at`: for an analyst a
       retirement is final, and the text said the opposite at the moment of
       decision (ux17 retire-promises-nonexistent-undo, 2026-09-22). The
       tie count arrived only afterwards, in a banner. */
    let what;
    if (sel.kind === 'node') {
      const ties = state.nodeTies.get(sel.id) || 0;
      what = 'Retire "' + labelOf(sel.id) + '" and every tie it carries ('
        + ties + ' in the current view)?\n\n';
    } else {
      const e = edgeById(sel.id);
      what = e ? 'Retire the tie between "' + e.src_label + '" and "'
        + e.dst_label + '"?\n\n' : 'Retire this tie?\n\n';
    }
    const reason = window.prompt(
      /* SAY WHAT IT ACTUALLY DOES. The first version of this promised
         "an as-of query into the past still shows it", which is false:
         `projections.py` filters `deleted_at IS NULL` unconditionally, with
         no as_of interaction at all, so a retirement leaves EVERY view
         including the historical ones. That is precisely the difference
         from `valid_to`, and telling an analyst the opposite would have
         them retire things believing the record of last week survives on
         screen. It survives in the TABLE; it does not survive in a view. */
      what + 'Why is this being retired? (required)\n\n' +
      'Nothing is destroyed: the row, its assertions and its evidence ' +
      'links stay in the database, and the act is recorded against your ' +
      'name. But it cannot be undone from the console, and it leaves every ' +
      'view, including as-of queries into the past. To say instead "this ' +
      'stopped being true in March", set valid_to.');
    if (reason === null) return;
    if (!reason.trim()) {
      banner('Not retired', 'A reason is required, exactly as it is for a ' +
                            'retraction.');
      return;
    }
    try {
      const out = await api(
        cpath('/graph/' + (sel.kind === 'node' ? 'nodes/' : 'edges/') + sel.id),
        { method: 'DELETE', json: { reason: reason.trim() } });
      /* Report the collateral. Retiring one actor can take six ties with
         it, and the analyst who clicked once should not have to count the
         difference on the canvas to find that out (invariant 12). */
      if (out && out.edges_retired) {
        banner('Retired', 'That entity carried '
               + countOf(out.edges_retired, 'tie', 'ties') + ', which '
               + agree(out.edges_retired, 'was', 'were')
               + ' retired with it. Nothing was destroyed.');
      }
      state.selection = null;
      await loadCaseGraph();
      refreshSociogram();
      renderInspector();
    } catch (err) { fail(err); }
  });
}

/** The case's tag vocabulary, including the global taxonomy.
 *
 * CLEARED FIRST, AND GUARDED ON THE CASE IT WAS FETCHED FOR. This is not
 * awaited by `openCase` — blocking a case open on a curation read would be
 * the wrong trade — which leaves two ways for the picker to offer another
 * case's tags:
 *
 *   1. between opening case B and its vocabulary arriving, `state.caseTags`
 *      still held case A's;
 *   2. two case opens in quick succession can resolve out of order, so A's
 *      slower response lands last and wins.
 *
 * Neither could cause a cross-case WRITE — the router re-checks the tag
 * against the path's case and 404s — but the console would be offering an
 * analyst a vocabulary from a case they may have just left, and (1) is
 * indefinite if the second fetch fails. The same `Seq` guard the sociogram
 * and the inspector already use fixes both.
 */
async function loadCaseTags() {
  state.caseTags = [];
  const forCase = state.caseId;
  let tags;
  try {
    tags = await api(cpath('/curation/tags'));
  } catch (err) {
    /* A missing vocabulary must not blank the inspector: the chips above
       come from the node's own tags and render fine without it. Only the
       picker degrades, and "New tag…" still works. */
    return;
  }
  if (state.caseId !== forCase) return;   // a newer case won the race
  state.caseTags = tags;
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
        r ? ordinal(r) + ' of ' + state.rankTotal : 'unranked'));
    } else if (key === 'positive_degree') {
      const t = el('div', 'metric-rank', 'vouches');
      t.title = 'Received vouches are accumulated reputation; given ' +
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
    (conf || 'none') + ' / ' + nodeConfAlpha(nodeId).toFixed(2)));
  const ct = el('div', 'metric-rank', 'opacity');
  ct.title = 'Node opacity on the canvas is this value. A node carries no ' +
    'confidence column of its own: this is the highest confidence among its ' +
    'ties in this projection. A node with no tie that meets the filter is ' +
    'drawn at the lowest step, because nothing here vouches for it.';
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
    'preset=' + (p.preset || 'unset'),
    'include_inferred=' + String(!!p.include_inferred),
    'min_confidence=' + (p.min_confidence || 'unset'),
    'as_of=' + (p.as_of ? fmtTime(p.as_of) : 'now'),
  ];
  let line = 'computed over projection ' + bits.join(' · ');
  if (state.metrics) {
    line += ' · ' + countOf(state.metrics.node_count, 'node', 'nodes') + ', '
      + countOf(state.metrics.edge_count, 'edge', 'edges') + ', density '
      + num(state.metrics.density, 4);
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
    /* CR14: same defence as the bulk paths, at the same boundary. This
       record feeds the inspector directly. */
    state.nodes.push(withSafeLabel(n));
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

/* ── inspector: what each assertion claims, from what, by whom ─────────
 *
 * ux05 assertion-drops-claim-and-source (2026-09-22). A card showed the
 * basis, the grading, the rationale and "by 335dfe6b", and nothing about
 * WHAT was claimed or FROM what. So a label correction (the Correct...
 * dialogue sends only a rationale, and the server fills in its ungraded
 * defaults) read "Direct observation · F6 · LOW CONFIDENCE", identical to
 * a first-hand sighting; a triage-accepted attribute showed neither the
 * attribute nor its value nor the document it came from; and the author
 * was a hash nobody could resolve. `GET .../assertions` now returns the
 * claim, the document and source, the author's name, the exhibit's title
 * (only when the reader may see it) and whether the row is a correction.
 */

/** A claimed value, short enough for one line, de-fanged: an attribute
 *  claim's value can be a handle an attacker published. */
function claimValueText(v) {
  if (v === null || v === undefined) return 'nothing';
  if (typeof v === 'string') return '"' + visibleText(v) + '"';
  let s;
  try { s = JSON.stringify(v); } catch (_e) { s = String(v); }
  s = visibleText(s);
  return s.length > 160 ? s.slice(0, 159) + '…' : s;
}

/** What the assertion claims, as one line. */
function claimLine(a, kind) {
  if (a.is_correction) {
    const v = a.claim_value;
    if (v && typeof v === 'object' && !Array.isArray(v)) {
      const keys = a.claim_path ? [a.claim_path] : Object.keys(v);
      return 'Correction: ' + keys.map((k) =>
        k + ' → ' + claimValueText(v[k])).join(', ');
    }
    return 'Correction: ' + (a.claim_path || 'value') + ' → ' + claimValueText(v);
  }
  if (a.claim_path) {
    return 'Claims ' + visibleText(a.claim_path) + ' is '
      + claimValueText(a.claim_value);
  }
  return 'Claims this ' + (kind === 'edge' ? 'tie' : 'entity') + ' as recorded';
}

function basisName(basis) {
  return (BASES.find((b) => b[0] === basis) || [null, basis])[1];
}

/** The captured document and collection source an assertion came from,
 *  as card parts: by name when the server returned one (it returns names
 *  only under `collection.read` and the reader's clearance), always with
 *  the copyable id. Titles and forum names are attacker-chosen text, so
 *  they go through visibleText. */
function documentFacts(a) {
  const parts = [];
  if (a.document_id) {
    const named = typeof a.document_title === 'string';
    const text = named
      ? 'Document: ' + (a.document_title ? visibleText(a.document_title) : '(untitled)')
      : 'document ' + shortId(a.document_id);
    const doc = el('span', named ? 'small' : 'mono small', text);
    doc.title = named ? 'Captured document ' + a.document_id
      : 'Captured document ' + a.document_id + '. Its title needs '
        + 'collection.read and a clearance at or above its own.';
    parts.push(copyable(doc, a.document_id, 'captured document id'));
  }
  if (a.source_name) {
    parts.push(el('span', 'small', 'from ' + visibleText(a.source_name)));
  } else if (a.source_id) {
    parts.push(copyable(el('span', 'mono small',
      'source ' + shortId(a.source_id)), a.source_id, 'collection source id'));
  }
  return parts;
}

/** The inspector's Assertions section for the current selection: its
 *  selection key, the rows once read (retracted included) and whether the
 *  read failed. Set by renderInspector, cleared on a case switch. */
let assertLoad = null;

/** Why an assertion's card is not on screen, as a sentence. Pure, for
 *  test_inspector_evidence_ui.py.
 *
 *  Until the 2026-09-22 verifier this always said the assertion was
 *  superseded and hidden by the checkbox, which was also what it said
 *  while the section was still loading or had failed to load. */
function assertionNotListedWords(assertionId, load, key, includeRetracted) {
  if (!load || load.key !== key || (load.all === null && !load.failed)) {
    return 'The Assertions section is still loading. Try again when it has '
      + 'loaded.';
  }
  if (load.failed) {
    return 'The Assertions section could not be loaded, so its cards cannot '
      + 'be shown. Select the element again to retry.';
  }
  const a = load.all.find((x) => x.id === assertionId);
  if (a && (a.retracted_at || a.superseded_at) && !includeRetracted) {
    return 'It is ' + (a.retracted_at ? 'retracted' : 'superseded') + ', so '
      + 'it is hidden. Tick Include retracted to list it.';
  }
  return 'It is not among the assertions read for this element. It may have '
    + 'changed since; select the element again to refresh.';
}

/** Scroll the inspector to one assertion's card and focus it, for the
 *  Evidence section's "which assertion backs this" link. */
function focusAssertionCard(assertionId) {
  const card = $('assert-' + assertionId);
  if (!card) {
    const sel = state.selection;
    banner('Assertion not shown', assertionNotListedWords(assertionId,
      assertLoad, sel ? sel.kind + ':' + sel.id : null, state.includeRetracted),
    'info');
    return;
  }
  card.scrollIntoView({ block: 'nearest' });
  card.focus();
}

function renderAssertions(box, all) {
  /* `all` includes retracted rows (see renderInspector); the checkbox
     decides only what is shown here. */
  const list = state.includeRetracted ? all
    : all.filter((a) => !a.retracted_at && !a.superseded_at);
  const hidden = all.length - list.length;
  const kind = state.selection ? state.selection.kind : 'node';
  if (!list.length) {
    box.appendChild(el('p', 'empty',
      'No live assertions. Nothing here is a fact without one.'));
  }
  const owner = selectionLabel();
  for (const a of list) {
    rememberAssertion(a, owner);
    const dead = a.retracted_at || a.superseded_at;
    const card = el('div', 'assert' + (dead ? ' dead' : '')
      + (a.is_correction ? ' correction' : ''));
    /* Addressable, so the Evidence section can say WHICH assertion
       carries an exhibit and take the analyst to it. */
    card.id = 'assert-' + a.id;
    card.tabIndex = -1;
    const top = el('div', 'assert-top');
    /* A correction is marked as one INSTEAD of showing its recorded basis
       up here: the basis it carries is the server's ungraded default, not
       a judgement anyone made, and "Direct observation" on an edit note is
       the misreading this fixes. The recorded basis stays in the meta line
       below, so nothing is hidden. */
    top.appendChild(el('span', 'assert-basis',
      a.is_correction ? 'Correction' : basisName(a.basis)));

    const grade = el('span', 'grading', String(a.reliability) + String(a.credibility));
    grade.title = 'Admiralty grading: ' + a.reliability + ', ' +
      (RELIABILITY[a.reliability] || 'unknown reliability') + ' · ' +
      a.credibility + ', ' + (CREDIBILITY[String(a.credibility)] ||
      'unknown credibility');
    top.appendChild(grade);

    const conf = el('span', 'conf conf-' + a.confidence, a.confidence + ' confidence');
    conf.title = 'ICD 203 analytic confidence';
    top.appendChild(conf);

    if (a.retracted_at) top.appendChild(el('span', 'chip bad', 'RETRACTED'));
    if (a.superseded_at) top.appendChild(el('span', 'chip stale', 'SUPERSEDED'));
    card.appendChild(top);

    const claim = el('div', 'assert-claim', claimLine(a, kind));
    if (a.claim_value !== null && a.claim_value !== undefined) {
      let full;
      try { full = JSON.stringify(a.claim_value); } catch (_e) { full = ''; }
      claim.title = visibleText(full);
    }
    card.appendChild(claim);

    const rationale = el('div',
      'assert-rationale' + (a.rationale ? '' : ' none'),
      a.rationale ? visibleText(a.rationale) : 'No rationale recorded.');
    card.appendChild(rationale);

    /* Where the claim came from: the exhibit it cites (by title, and one
       click from the exhibit itself), the captured document and the
       collection source, by name when the reader may see them (the server
       applies the Collected documents list's own rule) and always with
       the copyable id, because no pane opens a document by id yet. */
    if (a.evidence_id || a.document_id || a.source_id) {
      const src = el('div', 'assert-source');
      if (a.evidence_id) {
        if (a.evidence_title) {
          const ex = el('button', 'btn ghost small',
            'Exhibit: ' + visibleText(a.evidence_title));
          ex.type = 'button';
          ex.title = 'Show this exhibit in the Evidence pane';
          ex.addEventListener('click', () => focusEvidence(a.evidence_id));
          src.appendChild(ex);
        } else {
          /* The id was always returned; the title is withheld because the
             exhibit is above this reader's clearance. */
          src.appendChild(el('span', 'mono small',
            'exhibit ' + shortId(a.evidence_id) + ' (not visible to you)'));
        }
      }
      for (const part of documentFacts(a)) src.appendChild(part);
      card.appendChild(src);
    }

    const bits = ['recorded ' + fmtTime(a.recorded_at)];
    if (a.observed_at) bits.push('observed ' + fmtWhen(a.observed_at));
    bits.push('by ' + (a.created_by_name
      ? visibleText(a.created_by_name) : shortId(a.created_by)));
    if (a.is_correction) bits.push('recorded basis ' + basisName(a.basis));
    if (a.external_ref) bits.push('ref ' + visibleText(a.external_ref));
    if (a.retracted_at) bits.push('retracted ' + fmtTime(a.retracted_at));
    if (a.superseded_at) bits.push('superseded ' + fmtTime(a.superseded_at));
    const meta = el('div', 'assert-meta', bits.join(' · '));
    meta.title = 'author id ' + a.created_by;
    card.appendChild(meta);

    if (a.retraction_reason) {
      card.appendChild(el('div', 'assert-retraction',
        'Retracted: ' + a.retraction_reason));
    }

    /* E3. Retraction is the operation that makes the assertion model mean
       something: withdraw the last live claim behind an element and the
       element leaves the live graph, taking its degree and its edges with
       it, while the row survives in the table. */
    if (!dead) {
      const actions = el('div', 'assert-actions');
      const btn = el('button', 'btn small danger', 'Retract');
      btn.type = 'button';
      btn.title = 'Withdraw this claim. Nothing is deleted: the row is ' +
        'stamped and kept. But if this is the last live assertion behind ' +
        'the element, the element leaves the graph.';
      /* What else holds the element up, counted the way the projection
         counts: every row neither retracted nor superseded, whatever the
         checkbox shows. Superseded rows counted until the final review
         (U11, 2026-09-23), so after the demo seed's --regrade the last
         live claim was offered as "1 other live assertion remains" and the
         tie stayed drawn on a replaced claim nobody could retract. */
      const others = all.filter(
        (x) => !x.retracted_at && !x.superseded_at && x.id !== a.id);
      btn.addEventListener('click', () => retractAssertion(a.id, others));
      actions.appendChild(btn);
      card.appendChild(actions);
    }
    box.appendChild(card);
  }
  if (hidden) {
    box.appendChild(el('p', 'help', hidden + ' retracted or superseded '
      + 'assertion' + (hidden === 1 ? ' is' : 's are') + ' hidden. Tick '
      + 'Include retracted to list ' + (hidden === 1 ? 'it' : 'them') + '.'));
  }
}

/** What retracting one assertion will do, in the words of what the code
 *  actually does. Pure, so test_inspector_evidence_ui.py can hold it to that.
 *
 *  ux05 retract-confirmation-wrong (2026-09-22). This used to be told the
 *  length of the RENDERED list, which with "Include retracted" ticked
 *  counted dead rows, so a claim that was the last support read "Other
 *  live assertions remain, so the element stays in the graph" and the
 *  element then vanished. It also promised "an earlier as-of position
 *  will still show it", and the banner "Move the as-of scrubber back to
 *  see it": false, because the projection's live-provenance leg is
 *  `retracted_at IS NULL` with no as-of term, so a retracted element is
 *  gone at EVERY as-of position. The Retire dialogue had already been
 *  corrected for the same false promise; this one had not.
 *
 *  `others`: the element's other unretracted assertions. `kind`: 'node'
 *  or 'edge'. `ties`: for an entity, how many ties the canvas draws at
 *  it. Returns {last, prompt, done}. */
function retractionWords(others, kind, ties) {
  const what = kind === 'edge' ? 'tie' : 'entity';
  const last = others.length === 0;
  const onlyEdits = !last && others.every((x) => x.is_correction);
  const n = others.length;
  let prompt, done;
  if (last) {
    prompt = 'This is the LAST live assertion behind this ' + what + '. '
      + 'Retracting it removes the ' + what + ' from the graph'
      + (kind !== 'edge' && ties
        ? ', and the ' + ties + ' tie' + (ties === 1 ? '' : 's')
          + ' drawn at it leave' + (ties === 1 ? 's' : '') + ' the canvas with it'
        : '')
      + '. It stays out at every as-of position, earlier ones included, '
      + 'because the graph leaves out a retracted claim at every date. The '
      + 'assertion row and your reason are kept on record.';
    done = 'It was the last live claim, so the ' + what + ' has left the '
      + 'graph at every as-of position. The assertion row and its reason '
      + 'are kept on record.';
  } else if (onlyEdits) {
    /* Corrections count as live support in the projection. Said plainly,
       because "other assertions remain" would suggest another source still
       stands behind it when only edit notes do. */
    prompt = 'The ' + what + ' will stay in the graph, but only because '
      + n + ' correction' + (n === 1 ? '' : 's') + ' (edit note'
      + (n === 1 ? ') still counts as a live assertion' : 's) still count as '
        + 'live assertions') + ' behind it. No other claim supports it.';
    done = 'The ' + what + ' remains, held up only by ' + n + ' correction'
      + (n === 1 ? '' : 's') + '.';
  } else {
    prompt = n + ' other live assertion' + (n === 1 ? '' : 's') + ' remain'
      + (n === 1 ? 's' : '') + ', so the ' + what + ' stays in the graph.';
    done = 'The ' + what + ' remains: ' + n + ' other live assertion'
      + (n === 1 ? '' : 's') + ' still support' + (n === 1 ? 's' : '') + ' it.';
  }
  return { last: last, prompt: prompt, done: done };
}

async function retractAssertion(assertionId, others) {
  const sel = state.selection;
  const kind = sel ? sel.kind : 'node';
  const ties = sel && kind === 'node' ? (state.nodeTies.get(sel.id) || 0) : 0;
  const words = retractionWords(others, kind, ties);
  const reason = window.prompt(
    'Why is this claim being withdrawn? The reason is recorded permanently ' +
    'and cannot be edited.\n\n' + words.prompt);
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
    banner('Assertion retracted', words.done, 'info');
  } catch (err) { fail(err); }
}

/* ── inspector: add a claim about the selected tie ─────────────────────
 *
 * Final review C14 (2026-09-23). Since migration 0064 a tie's confidence
 * is the highest grade among its live claims, so a correction can raise a
 * tie and cannot lower it past a claim that still stands: the server
 * answers 409 and names the remedy, "add the lower claim, then retract the
 * higher one". Nothing in the console could add a claim to an existing
 * tie (`POST /edges/{id}/assertions` had no caller), so the one route left
 * was to retract the founding claim and correct afterwards. That recorded
 * the claim as withdrawn when only its grade had changed, dropped its
 * exhibit from the tie's backing, and left the tie resting on a correction
 * with the server's ungraded defaults (DIRECT_OBSERVATION, F6, no exhibit),
 * which ACH then weighted as F6.
 *
 * This form is that missing control. It is graded the way the create
 * forms are (nothing chosen for the analyst, `gradingProblem`,
 * `rationaleProblem`, the exhibit picker), it belongs to ONE tie and is
 * emptied when the selection moves to another element or the case
 * changes, so a claim typed for one tie can never be recorded against the
 * next. A correction is still not superseded on the analyst's behalf:
 * invariant 5 makes it a retraction plus a new assertion, and the
 * retraction carries a reason.
 */

/** Which tie the form's contents belong to, or null. */
const tieClaim = { edgeId: null };

/** What the Correct... dialogue says INSTEAD of sending a correction that
 *  would lower the tie, or null when the correction may go. `current` is
 *  the tie's confidence as last read, `wanted` the one asked for. Pure,
 *  for test_tie_claim_ui.py. */
function tieLoweringWords(current, wanted) {
  if (!(current in CONF_RANK) || !(wanted in CONF_RANK)) return null;
  if (CONF_RANK[wanted] >= CONF_RANK[current]) return null;
  return 'This tie is ' + current + ', the highest grade among its live '
    + 'claims, and a correction cannot lower it past a claim that still '
    + 'stands, so nothing was sent. To bring it down to ' + wanted + ' and '
    + 'keep it graded and evidenced: add a ' + wanted + ' claim with its '
    + 'own basis, grading and exhibit in the Add a claim form under the '
    + "tie's assertions (open now, with " + wanted + ' chosen), then '
    + 'retract each claim graded above ' + wanted + ', giving the reason.';
}

/** The banner after a claim is recorded: what the tie is now and, when
 *  the claim is below it, what lowers it. `claimed` is the new claim's
 *  grade, `tie` the tie's confidence as read back (null if unknown). Pure,
 *  for test_tie_claim_ui.py. */
function tieClaimDoneWords(claimed, tie, withExhibit) {
  const exhibit = withExhibit ? ' It carries its exhibit.' : '';
  if (!(tie in CONF_RANK) || !(claimed in CONF_RANK)
      || CONF_RANK[claimed] >= CONF_RANK[tie]) {
    return 'The tie is ' + (tie in CONF_RANK ? tie : claimed) + ' now, the '
      + 'highest grade among its live claims.' + exhibit;
  }
  return 'The tie stays ' + tie + ' while a claim graded above ' + claimed
    + ' stands. To bring it down, retract each such claim, giving the '
    + 'reason; this ' + claimed + ' claim then holds the tie on the graph '
    + 'with its own grading.' + exhibit;
}

/** Empty the form. `conf`, when given, is the one field chosen: the grade
 *  the analyst has just asked Correct... for, and nothing else. */
function resetTieClaim(conf) {
  resetGrading('claim', conf ? { conf: conf } : null);
  for (const id of ['claim-rationale', 'claim-ref', 'claim-observed']) {
    $(id).value = '';
  }
  $('claim-evidence').value = '';
  setMsg($('claim-error'), '');
}

function showTieClaimForm(open) {
  show($('claim-form'), open);
  show($('claim-open'), !open);
  $('claim-open').setAttribute('aria-expanded', open ? 'true' : 'false');
}

/** Called by renderInspector for every render: shown on a tie, and
 *  emptied whenever the selection is not the tie it was filled for. A
 *  re-render of the SAME tie (a reload, a projection change) keeps what
 *  the analyst has typed. */
function syncTieClaim(sel) {
  const tie = !!sel && sel.kind === 'edge';
  show($('insp-claim'), tie);
  if (tie && tieClaim.edgeId === sel.id) return;
  tieClaim.edgeId = tie ? sel.id : null;
  resetTieClaim();
  showTieClaimForm(false);
}
/* Emptied on a case switch and a sign-out too, not only when the next
   selection is drawn: a rationale typed about case A's tie must not sit in
   the page under case B, or for the next person at the tab. */
onCaseSwitch(() => {
  tieClaim.edgeId = null;
  resetTieClaim();
  showTieClaimForm(false);
});

/** Open the form on the selected tie, with `conf` chosen when given. */
function openTieClaim(conf) {
  const sel = state.selection;
  if (!sel || sel.kind !== 'edge') return;
  syncTieClaim(sel);
  if (conf) $('claim-conf').value = conf;
  showTieClaimForm(true);
  $('claim-form').scrollIntoView({ block: 'nearest' });
  $('claim-basis').focus();
}

async function addTieClaim(event) {
  event.preventDefault();
  const errBox = $('claim-error');
  setMsg(errBox, '');
  const sel = state.selection;
  const edgeId = tieClaim.edgeId;
  /* The form's contents belong to one tie; never send them for another. */
  if (!edgeId || !sel || sel.kind !== 'edge' || sel.id !== edgeId) return;
  const ungraded = gradingProblem('claim');
  if (ungraded) { setMsg(errBox, ungraded); return; }
  const assertion = assertionFrom('claim');
  const problem = rationaleProblem(assertion);
  if (problem) { setMsg(errBox, problem); return; }
  const token = caseToken();
  const go = $('claim-submit');
  go.disabled = true;
  try {
    await api(cpath('/edges/' + edgeId + '/assertions'), {
      method: 'POST', json: assertion,
    });
    if (caseChanged(token)) return;
    resetTieClaim();
    showTieClaimForm(false);
    /* The tie's confidence can have moved, and with it every projection
       run with a floor, so the analysis on screen is stale. */
    invalidateAnalytics();
    await reloadAll();
    if (caseChanged(token)) return;
    const e = edgeById(edgeId);
    banner('Claim recorded', tieClaimDoneWords(assertion.confidence,
      e ? e.confidence : null, !!assertion.evidence_id), 'info');
  } catch (err) {
    if (caseChanged(token)) return;
    inlineProblem(errBox, err);
  } finally {
    go.disabled = false;
  }
}

/** The form's own wiring, from the inspector's (`wireElementActions`). */
function wireTieClaim() {
  $('claim-open').addEventListener('click', () => openTieClaim(null));
  $('claim-cancel').addEventListener('click', () => {
    resetTieClaim();
    showTieClaimForm(false);
    $('claim-open').focus();
  });
  $('claim-form').addEventListener('submit', addTieClaim);
  $('claim-basis').addEventListener('change', () => syncRationaleHint('claim'));
}

/* Attach an exhibit already in this case to the selected node or edge.
 *
 * `POST /evidence/{id}/links` has existed since Phase 1 and NOTHING in the
 * console has ever called it — a 2026-07-26 audit found zero occurrences of
 * "/links" in this file. The READ side was fine (the panel below is fed by
 * GET /nodes/{id}/evidence, which joins core.evidence_link), so the panel
 * was not broken so much as unfillable: an analyst could see linked
 * exhibits and could never create a link, which is why it read as
 * permanently empty.
 *
 * The picker offers only exhibits from `state.evidence` — this case's own,
 * already filtered by the caller's clearance on the way in. The server
 * re-checks the same-case constraint regardless (routers/evidence.py: the
 * comment there notes core.evidence_link has no same-case CHECK, unlike
 * core.edge), so this is convenience, never the control.
 */
function renderEvidenceLinker(box, sel) {
  if (!state.evidence.length) return;
  const already = new Set((state.linkedEvidenceIds || []));
  const free = state.evidence.filter((e) => !already.has(e.id));
  if (!free.length) return;

  const row = el('div', 'insp-linker');
  const pick = el('select', 'input small');
  pick.setAttribute('aria-label', 'Exhibit to link');
  pick.appendChild(el('option', null, 'Link an exhibit…'));
  for (const ev of free) {
    const o = el('option', null, ev.title);
    o.value = ev.id;
    pick.appendChild(o);
  }
  /* What in the exhibit supports the element. `LinkBody` has always taken
     `relevance`; the linker never sent it, so a link said that an exhibit
     mattered and never what in it did (ux07 two-evidence-paths-disagree,
     2026-09-22). Optional, because a screenshot of the handle itself needs
     no explaining. */
  const why = el('input', 'input small');
  why.type = 'text';
  why.maxLength = 500;
  why.placeholder = 'What in it supports this? (optional)';
  why.setAttribute('aria-label', 'What in the exhibit supports this (optional)');
  const go = el('button', 'btn small', 'Link');
  go.type = 'button';
  go.addEventListener('click', async () => {
    const evidenceId = pick.value;
    if (!evidenceId) return;
    go.disabled = true;
    const body = sel.kind === 'node' ? { node_id: sel.id } : { edge_id: sel.id };
    if (why.value.trim()) body.relevance = why.value.trim();
    try {
      /* `json:`, not `body:`: the api() helper only serialises `o.json`
         (or `o.form`), and a `body` key is silently ignored, so the POST
         would have gone out with no payload and come back 422. */
      await api(cpath('/evidence/' + evidenceId + '/links'), {
        method: 'POST', json: body,
      });
      /* Re-render the whole inspector rather than pushing the new row in
         by hand: the server decides what is visible, and a client that
         optimistically draws a link it has not read back can show one the
         caller is not cleared to see.
         Then refresh the projection, because a link now makes the element
         EVIDENCED: its canvas mark and the coverage figure both change, and
         until 2026-09-22 neither did. */
      renderInspector();
      refreshSociogram();
    } catch (err) { fail(err); go.disabled = false; }
  });
  row.appendChild(pick);
  row.appendChild(why);
  row.appendChild(go);
  box.appendChild(row);
}

/** One route by which an exhibit is attached, as a sentence. */
function backingLine(b) {
  const who = b.by_name ? visibleText(b.by_name) : shortId(b.by);
  const line = el('div', 'ev-backing');
  if (b.kind === 'ASSERTION') {
    line.appendChild(el('span', null, 'Carried by the ' + basisName(b.basis)
      + ' assertion recorded ' + fmtTime(b.at) + ' by ' + who + '.'));
    const jump = el('button', 'btn ghost small', 'Show assertion');
    jump.type = 'button';
    jump.setAttribute('aria-label', 'Show the assertion that carries this exhibit');
    jump.addEventListener('click', () => focusAssertionCard(b.assertion_id));
    line.appendChild(jump);
  } else {
    let text = 'Linked directly ' + fmtTime(b.at) + ' by ' + who;
    if (b.relevance) text += ': ' + visibleText(b.relevance);
    if (b.page_ref) text += ' (at ' + visibleText(b.page_ref) + ')';
    line.appendChild(el('span', null, text + '.'));
  }
  return line;
}

/** The exhibits behind the selected element, and how each is attached.
 *
 *  ux05 linked-evidence-vs-evidenced and ux07 two-evidence-paths-disagree
 *  (2026-09-22). This section read `core.evidence_link` alone while the
 *  canvas, the coverage figure and the report counted assertion-carried
 *  exhibits alone, so the two answered "is this evidenced?" in opposite
 *  directions. The server now returns both routes under the one rule
 *  (`projections.evidenced_sql`), and each exhibit says which assertion
 *  carries it or who linked it and why. */
function renderLinkedEvidence(box, list) {
  /* Remembered so the picker can exclude what is already attached, by
     EITHER route: an exhibit a claim already carries was offered again. */
  state.linkedEvidenceIds = list.map((e) => e.id);
  const sel = state.selection;
  const what = sel && sel.kind === 'edge' ? 'tie' : 'entity';
  if (!list.some((e) => e.counts)) {
    box.appendChild(el('p', 'empty', 'No exhibit backs this ' + what + '. '
      + 'The canvas, the coverage figure and the report all count it as '
      + 'unevidenced.'));
  }
  for (const ev of list) {
    const item = el('div', 'sel-item' + (ev.counts ? '' : ' purged'));
    const top = el('div', 'ev-top');
    top.appendChild(el('span', 'ev-title', ev.title));
    top.appendChild(tlpChip(ev.classification));
    if (ev.is_worm_locked) top.appendChild(el('span', 'chip flag', 'WORM'));
    if (ev.purged) top.appendChild(el('span', 'chip bad', 'PURGED'));
    item.appendChild(top);
    const hash = el('div', 'sel-val', 'sha256 ' + shortHash(ev.sha256));
    hash.title = ev.sha256 || '';
    item.appendChild(hash);
    item.appendChild(el('div', 'ev-meta',
      ev.media_type + ' · ' + fmtBytes(ev.byte_size)));
    for (const b of (ev.backing || [])) item.appendChild(backingLine(b));
    if (!ev.counts) {
      item.appendChild(el('p', 'help warn', 'Purged: the record says these '
        + 'bytes are gone, so this exhibit no longer counts as evidence.'));
    }
    const jump = el('button', 'btn small', 'Show in evidence');
    jump.type = 'button';
    jump.addEventListener('click', () => focusEvidence(ev.id));
    item.appendChild(jump);
    box.appendChild(item);
  }
  if (sel) renderEvidenceLinker(box, sel);
}

function renderSelectors(box, list) {
  if (!list.length) {
    box.appendChild(el('p', 'empty', 'No selectors observed.'));
    return;
  }
  for (const s of list) {
    const item = el('div', 'sel-item');
    item.appendChild(el('div', 'label', s.selector_type));
    /* CR13: visibleText, not raw. `el()` uses textContent, which stops
       EXECUTION but not visual reordering — a U+202E inside a Jabber
       address renders as a different address than the bytes the system
       correlated on, and two distinct selectors can render identically.
       These values are attacker-chosen forum identifiers. */
    /* Copy the RAW value, not the de-fanged rendering: the raw form is
       what the next tool needs, and visibleText only changes how it
       looks. */
    item.appendChild(copyable(
      el('div', 'sel-val', visibleText(s.raw_value)), s.raw_value, 'selector'));
    if (s.norm_value && s.norm_value !== s.raw_value) {
      item.appendChild(copyable(
        el('div', 'mono small muted', 'normalised ' + visibleText(s.norm_value)),
        s.norm_value, 'normalised value'));
    }
    item.appendChild(el('div', 'ev-meta', 'observed '
      + (Number(s.observation_cnt) === 1 ? 'once'
        : countOf(s.observation_cnt, 'time', 'times'))));
    box.appendChild(item);
  }
}

/* ── create forms ─────────────────────────────────────────────────────── */

function buildPickers() {
  /* Same case (a reopen after editing its title or status): the analyst's
     choices are put back. Another case: everything starts empty. */
  const same = adoptCaseInCreateForms();
  const tlpPairs = TLP.map((t) => [t, t]);
  /* An element may not be classified BELOW its case (the server enforces a
   * floor), so defaulting to a fixed AMBER makes every entity form fail in
   * an AMBER_STRICT or RED case, and the rejection reads as a mysterious
   * 400 rather than "you picked something too low". Default to the case's
   * own classification, which is always legal, and drop the options that
   * are not: an analyst cannot choose a value the server will refuse. */
  const caseClass = state.caseRec ? state.caseRec.classification : 'AMBER';
  const floor = TLP.indexOf(caseClass);
  const legal = tlpPairs.filter(([t]) => TLP.indexOf(t) >= floor);
  for (const id of ['node-class', 'edge-class', 'ev-class']) {
    /* A choice survives a reopen only while it is still legal: the edit
       that caused the reopen may have raised the case, and with it the
       floor. */
    const kept = same && id !== 'ev-class' ? $(id).value : null;
    opts($(id), legal, legal.some(([t]) => t === kept) ? kept : caseClass);
  }
  /* The case form itself is unconstrained: a new case has no floor. */
  opts($('case-class'), tlpPairs, 'AMBER');
  opts($('node-type'),
    state.ontology.node_types.map((t) => [t.key, t.display_name + ' (' + t.key + ')']),
    same ? $('node-type').value : undefined);
  resetGrading('node', same ? gradingOf('node') : null);
  resetGrading('edge', same ? gradingOf('edge') : null);
}

/* What the two create forms remember between entries, and nothing else.
   Module-level rather than on `state` so the whole of it lives next to the
   code that reads it and is reset in one place (`resetCreateForms`). */
const createForms = {
  /* The grading of the last claim each form recorded, offered back as an
     explicit "same grading" button and never applied on its own. */
  lastGrading: { node: null, edge: null },
  /* The relationship type the analyst CHOSE, as distinct from whatever the
     select happens to show. An endpoint change keeps it when it is still
     legal for the new pair and clears it, saying so, when it is not. */
  wantedType: '',
  /* Set when an endpoint change cleared the wanted type, so the note can
     say what happened instead of the type silently changing. */
  clearedType: '',
  /* The case everything above, and every typed field, belongs to. The
     case-switch reset runs before openCase has set the new case id, so it
     cannot tell a switch from a reopen of the same case; this is how
     `adoptCaseInCreateForms` tells, once the id is known. */
  caseId: null,
  /* The endpoints chosen when the reset emptied the entity lists, held
     until the case's entities arrive and restored only for the same case. */
  keptEnds: null,
  /* Entities the Link form was opened from that the case's entity page
     does not hold, by id (final review U12, 2026-09-23). The page is the
     newest 1000 (`/nodes?limit=1000`) and the canvas draws the oldest 800,
     so in a large case an entity can be drawn, selected and offered "Link
     from this..." without being in `state.nodes`, and the pickers, built
     from that list alone, opened on "Choose the source entity" without a
     word and could not offer the entity at all. Kept here rather than
     pushed into `state.nodes`, because every reload replaces that list
     and would drop the choice again. Emptied for another case. */
  pinnedEnds: new Map(),
};

/* The four grading fields every claim carries, with how the refusal names
   each one.
   ux06 grading-prefilled-upward (2026-09-22): both forms opened on Direct
   observation / C / 3 / MODERATE, so typing a label and pressing Create
   recorded a graded claim that nobody graded, pitched ABOVE the server's
   own not-graded defaults (F / 6 / LOW). ACH weights cells by Admiralty
   grade and the confidence filter acts on these values, and a disclosure
   reviewer cannot tell an untouched default from a considered C3. The
   Correct... dialogue already refused to invent a grade on the analyst's
   behalf; these forms did it on every entry. They now open with nothing
   chosen and refuse to submit until all four are picked. */
const GRADING_FIELDS = [
  ['basis', 'a basis'],
  ['conf', 'a confidence'],
  ['rel', 'a source reliability'],
  ['cred', 'an information credibility'],
];

/** `opts`, led by a disabled "Choose ..." option that is selected unless
 *  `selected` names a real value. Value "" makes a `required` select
 *  report :invalid until something is chosen, which is what greys it
 *  (app.css), and disabled means it cannot be chosen back. */
function optsWithPlaceholder(select, placeholder, pairs, selected) {
  opts(select, pairs, selected);
  const blank = el('option', null, placeholder);
  blank.value = '';
  blank.disabled = true;
  select.insertBefore(blank, select.firstChild);
  if (!pairs.some(([value]) => value === selected)) blank.selected = true;
}

/** "a, b and c", for sentences that name what is missing. */
function spokenList(items) {
  if (items.length < 2) return items.join('');
  return items.slice(0, -1).join(', ') + ' and ' + items[items.length - 1];
}

function resetGrading(prefix, grading) {
  const g = grading || {};
  optsWithPlaceholder($(prefix + '-basis'), 'Choose a basis', BASES, g.basis);
  optsWithPlaceholder($(prefix + '-conf'), 'Choose a confidence',
    CONFIDENCE.map((c) => [c, c]), g.conf);
  optsWithPlaceholder($(prefix + '-rel'), 'Choose a reliability',
    Object.keys(RELIABILITY).map((k) => [k, k + ': ' + RELIABILITY[k]]), g.rel);
  optsWithPlaceholder($(prefix + '-cred'), 'Choose a credibility',
    Object.keys(CREDIBILITY).map((k) => [k, k + ': ' + CREDIBILITY[k]]), g.cred);
  syncRationaleHint(prefix);
  renderSameGrading(prefix);
}

function gradingOf(prefix) {
  const out = {};
  for (const [field] of GRADING_FIELDS) out[field] = $(prefix + '-' + field).value;
  return out;
}

/** The refusal for an ungraded claim, or null. Focuses the first field
 *  still unchosen so the analyst lands where the work is. */
function gradingProblem(prefix) {
  const missing = GRADING_FIELDS.filter(([field]) => !$(prefix + '-' + field).value);
  if (!missing.length) return null;
  $(prefix + '-' + missing[0][0]).focus();
  return 'Grade the claim before recording it: choose ' +
    spokenList(missing.map(([, what]) => what)) + '. Nothing is filled in ' +
    'for you, so an ungraded claim cannot pass for a graded one.';
}

/** The explicit way to reuse a grading for batch entry. The button names
 *  the grading it will apply, so it is never a silent default. */
function renderSameGrading(prefix) {
  const btn = $(prefix + '-same-grading');
  /* The tie inspector's claim form (final review C14) is graded through
     `resetGrading` too, and offers no "same grading": each claim about an
     existing tie is graded on its own. */
  if (!btn) return;
  const last = createForms.lastGrading[prefix];
  show(btn, !!last);
  if (!last) return;
  const basis = (BASES.find(([k]) => k === last.basis) || [null, last.basis])[1];
  btn.textContent = 'Same grading as the last entry: ' + basis + ', ' +
    last.rel + last.cred + ', ' + last.conf;
}

/* What the analyst typed or chose, as distinct from what the forms were
   built from. Kept across a reopen of the same case, dropped for another. */
const CREATE_FORM_TYPED = [
  'node-label', 'node-rationale', 'node-ref', 'node-observed',
  'node-valid-from', 'node-valid-to',
  'edge-src-filter', 'edge-dst-filter', 'edge-rationale', 'edge-ref',
  'edge-observed', 'edge-valid-from', 'edge-valid-to',
];

/** The registered case-switch reset. It drops only what is case-scoped
 *  DATA: the entity lists the endpoints were built from, and the messages
 *  about the last entry.
 *
 *  It used to clear the typed fields too, and openCase(state.caseId) runs
 *  it for a reopen of the SAME case, which is what editing a case's title
 *  or status does: a half-typed label or rationale was thrown away by an
 *  unrelated edit (fix-round verifier, 2026-09-22). The typed fields are
 *  judged by `adoptCaseInCreateForms`, once the new case id is known. */
function resetCreateForms() {
  /* Held only while the lists are live: the list view and openCase both
     run this, and the second run must not overwrite the choice the first
     one saved with the emptied lists' blank. */
  if ($('edge-src').options.length || $('edge-dst').options.length) {
    createForms.keptEnds = { src: $('edge-src').value, dst: $('edge-dst').value };
  }
  /* Dropped on EVERY switch, the same case's reopen included: a pinned
     record was read under the session that pinned it, and a sign-out
     runs this too. A kept end that was pinned is read again, under the
     session then signed in, by `buildEdgePickers`. */
  createForms.pinnedEnds.clear();
  for (const id of ['edge-src', 'edge-dst']) clear($(id));
  for (const id of ['node-error', 'node-ok', 'edge-error', 'edge-ok']) setMsg($(id), '');
}
onCaseSwitch(resetCreateForms);

/** Called by buildPickers once openCase has set the new case id. Another
 *  case gets empty forms: its entities are not the old ones, and a grading
 *  remembered from one case is not a reasonable offer in another. The same
 *  case gets back everything the analyst had entered. Returns which. */
function adoptCaseInCreateForms() {
  const same = createForms.caseId !== null && createForms.caseId === state.caseId;
  if (!same) {
    createForms.lastGrading = { node: null, edge: null };
    createForms.wantedType = '';
    createForms.clearedType = '';
    createForms.keptEnds = null;
    for (const id of CREATE_FORM_TYPED) $(id).value = '';
  }
  createForms.caseId = state.caseId;
  return same;
}

/* ux06 edge-endpoint-pickers (2026-09-22). The endpoints were two plain
   selects of every entity in the case, newest first, and both opened on
   the SAME entity: the form started on a self-loop, with a note advising
   the analyst to "reverse the direction" of VICTIM to VICTIM. With twenty
   wallets that all begin "bc1q" and twenty-six hosts that all begin
   "vps-", typing to jump did not work either, so the likeliest mistake was
   picking the look-alike next door: a tie recorded against the wrong
   actor. Each endpoint now has a filter box (the palette's rule: every
   word must appear in the label or the type), the list is grouped by
   entity type and sorted by label, and both ends open unchosen. */

function endpointMatches(node, terms) {
  if (!terms.length) return true;
  const hay = (node.label + ' ' + node.node_type + ' ' +
               typeName(node.node_type)).toLowerCase();
  return terms.every((t) => hay.includes(t));
}

function endpointTerms(which) {
  const q = $('edge-' + which + '-filter').value.trim().toLowerCase();
  return q ? q.split(/\s+/) : [];
}

/** Grouped by entity type in the ontology's order, sorted by label within
 *  a type, numerals compared as numbers. */
function sortEndpoints(list) {
  const order = new Map(state.ontology.node_types.map((t, i) => [t.key, i]));
  const rank = (n) => (order.has(n.node_type) ? order.get(n.node_type) : 1e6);
  return list.sort((a, b) =>
    (rank(a) - rank(b)) ||
    a.label.localeCompare(b.label, undefined, { numeric: true, sensitivity: 'base' }));
}

/** Every entity the endpoint pickers offer: the case's entity page, plus
 *  any end pinned because the page does not hold it (U12). */
function endpointPool() {
  const extra = [...createForms.pinnedEnds.values()]
    .filter((p) => !state.nodes.some((n) => n.id === p.id));
  return extra.length ? state.nodes.concat(extra) : state.nodes;
}

function endpointNode(id) {
  return id ? endpointPool().find((n) => n.id === id) || null : null;
}

/** Make `nodeId` one the pickers offer. The entity page first, then the
 *  sociogram's own record (a drawn entity is usually there), then a read
 *  of the entity under this session's clearance. Returns null, or why it
 *  could not be offered. `token` is the case the caller started in: a
 *  reply for a case since left pins nothing. */
async function pinEndpoint(nodeId, token) {
  if (endpointNode(nodeId)) return null;
  const drawn = (state.gnodes || []).find((n) => n.id === nodeId);
  if (drawn) {
    createForms.pinnedEnds.set(nodeId, drawn);
    return null;
  }
  try {
    const n = withSafeLabel(await api(cpath('/nodes/' + nodeId)));
    if (!caseChanged(token)) createForms.pinnedEnds.set(nodeId, n);
    return null;
  } catch (err) {
    return failureReason(err);
  }
}

/** The entities that match one endpoint's filter, in display order. */
function endpointChoices(which) {
  const terms = endpointTerms(which);
  return sortEndpoints(endpointPool().filter((n) => endpointMatches(n, terms)));
}

/** Rebuild one endpoint select. `keepId`, when given, is the entity to
 *  leave chosen; otherwise the current choice is kept. */
function buildEndpointSelect(which, keepId) {
  const select = $('edge-' + which);
  const keep = keepId !== undefined ? keepId : select.value;
  const terms = endpointTerms(which);
  const matches = endpointChoices(which);
  const pool = endpointPool();
  /* The chosen entity stays in the list even when the filter no longer
     matches it: narrowing the list must never change a choice already
     made. */
  const shown = sortEndpoints(pool.filter(
    (n) => n.id === keep || endpointMatches(n, terms)));
  clear(select);
  const blank = el('option', null,
    which === 'src' ? 'Choose the source entity' : 'Choose the target entity');
  blank.value = '';
  blank.disabled = true;
  select.appendChild(blank);
  let group = null, groupType = null;
  for (const n of shown) {
    if (n.node_type !== groupType) {
      groupType = n.node_type;
      group = el('optgroup');
      group.label = typeName(n.node_type) + ' (' + n.node_type + ')';
      select.appendChild(group);
    }
    /* The type by its display name, as the entity list and the inspector
       chip name it: "oriel [IDENTITY]" printed the raw code (README
       screenshot set review, 2026-09-23). The code stays in the group
       label above, which is what the filter's "a type such as WALLET"
       refers to. */
    const o = el('option', null,
      n.label + ' (' + typeName(n.node_type) + ')');
    o.value = n.id;
    group.appendChild(o);
  }
  if (keep && pool.some((n) => n.id === keep)) select.value = keep;
  else blank.selected = true;

  const total = pool.length;
  const count = $('edge-' + which + '-count');
  $('edge-' + which + '-filter').disabled = total === 0;
  if (total < 2) {
    /* Said once, under the source, beside the way out (Add an entity):
       with nothing to link, "type above to filter" named the wrong next
       step (fix-round verifier, 2026-09-22, on the empty OP-WHEATEAR-26). */
    count.textContent = which !== 'src' ? ''
      : (total ? 'This case has one entity so far. '
               : 'This case has no entities yet. ') +
        'A relationship joins two, so add them first.';
    return;
  }
  count.textContent = !terms.length
    ? total + ' entities, grouped by type. Type above to filter by label or type.'
    : (!matches.length
      ? 'Nothing matches. Filter on part of a label, or on a type such as WALLET.'
      : matches.length + ' of ' + total + ' '
        + agree(matches.length, 'matches', 'match') + '. Enter picks ' +
        (matches.length === 1 ? 'it.' : 'the first.'));
}

function buildEdgePickers() {
  /* After a reopen of the same case, the ends chosen before it; otherwise
     whatever the selects hold (nothing, after a switch). */
  const kept = createForms.keptEnds;
  createForms.keptEnds = null;
  buildEndpointSelect('src', kept ? kept.src : undefined);
  buildEndpointSelect('dst', kept ? kept.dst : undefined);
  const enough = endpointPool().length >= 2;
  show($('edge-need-entities'), !enough);
  show($('edge-swap'), enough);
  refreshEdgeTypes();
  /* A kept end the entity page does not hold was a pinned one, which the
     reset dropped: it is read again rather than lost without a word. */
  for (const which of ['src', 'dst']) {
    if (kept && kept[which] && !endpointNode(kept[which])) {
      restoreEndpoint(which, kept[which]);
    }
  }
}

/** Put a kept end back once it is pinned again, unless the analyst has
 *  chosen that end since; say so when it cannot be read. */
async function restoreEndpoint(which, nodeId) {
  const token = caseToken();
  const problem = await pinEndpoint(nodeId, token);
  if (caseChanged(token) || $('edge-' + which).value) return;
  if (problem) {
    setMsg($('edge-error'), 'The ' + (which === 'src' ? 'source' : 'target')
      + ' entity chosen before could not be read again (' + problem
      + '), so it is no longer chosen.');
    return;
  }
  buildEndpointSelect(which, nodeId);
  refreshEdgeTypes();
}

/** Open the Link form with one end already chosen, `which` being 'src' or
 *  'dst'. The inspector's "Link from this..." and "Link to this..." call
 *  it. The other end, the type and the grading stay unchosen.
 *
 *  The entity is pinned first when the case's entity page does not hold
 *  it (final review U12, 2026-09-23): it used to open on "Choose the
 *  source entity" without a word for any entity beyond that page, which in
 *  a large case is most of the ones the canvas draws. If it cannot be read
 *  at all, the form says so instead of opening blank. */
async function openLinkFormFrom(which, nodeId) {
  const token = caseToken();
  const problem = await pinEndpoint(nodeId, token);
  if (caseChanged(token)) return;
  $('edge-' + which + '-filter').value = '';
  buildEndpointSelect(which, nodeId);
  refreshEdgeTypes();
  setMsg($('edge-error'), problem
    ? 'The entity you started from could not be read (' + problem + '), '
      + 'so it is not chosen here.'
    : '');
  selectTab('add-edge');
  $('edge-' + (which === 'src' ? 'dst' : 'src') + '-filter').focus();
}

/** Enter in a filter box picks the first match, rather than submitting a
 *  form that is not finished. */
function onEndpointFilterKey(which, event) {
  if (event.key !== 'Enter') return;
  /* Nothing typed, nothing to pick from: the first entity of the whole list
     is not a choice anyone made, and nothing on this form is chosen for
     the analyst (fix-round verifier, 2026-09-22). Enter then does what it
     does in any other field, submitting, and createEdge refuses an
     unfinished form with the reason. */
  if (!endpointTerms(which).length) return;
  event.preventDefault();
  const first = endpointChoices(which)[0];
  if (!first) return;
  $('edge-' + which).value = first.id;
  refreshEdgeTypes();
  $('edge-' + which).focus();
}

/** Swap the two ends, filters included. The answer to "nothing runs this
 *  way, N run the other way", which the note used to give as advice with
 *  no control to act on it. */
function swapEndpoints() {
  const s = $('edge-src').value, d = $('edge-dst').value;
  const fs = $('edge-src-filter').value, fd = $('edge-dst-filter').value;
  $('edge-src-filter').value = fd;
  $('edge-dst-filter').value = fs;
  buildEndpointSelect('src', d);
  buildEndpointSelect('dst', s);
  refreshEdgeTypes();
}

function legalEdgeTypes(srcType, dstType) {
  return state.ontology.edge_types.filter((t) =>
    (!t.src.length || t.src.includes(srcType)) &&
    (!t.dst.length || t.dst.includes(dstType)));
}

/* Grouped by sign, so a negative tie is never one careless press away
   from looking like any other choice. */
const SIGN_GROUPS = [
  [1, 'Positive ties'],
  [-1, 'Negative ties (accusation, dispute, rivalry)'],
  [0, 'Neutral or structural'],
];

function signWords(sign) {
  if (sign > 0) return 'a positive tie';
  if (sign < 0) return 'a NEGATIVE tie';
  return 'neutral (sign 0)';
}

/** Offer only the relationship types the ontology permits for the chosen
 *  endpoints, starting on "Choose a relationship type".
 *
 *  ux06 edge-type-defaults-to-scam-accusation (2026-09-22): this rebuilt
 *  the list with nothing selected, so the browser selected the first
 *  option, and the ontology sorts by key: for the commonest pair in the
 *  product, persona to persona, that is ACCUSED_SCAM. Pressing Create
 *  without opening the list recorded a scam accusation, a NEGATIVE tie
 *  that moves signed degree and structural balance. It also ran on every
 *  endpoint change and kept nothing, so an analyst who chose "vouched
 *  for" and then corrected the target got the accusation instead, with
 *  no word. Now nothing is chosen for them, and a choice survives an
 *  endpoint change when it is still legal and is cleared ALOUD when not. */
function refreshEdgeTypes() {
  const note = $('edge-type-note');
  const sel = $('edge-type');
  const src = endpointNode($('edge-src').value);
  const dst = endpointNode($('edge-dst').value);
  const placeholder = (text) => {
    optsWithPlaceholder(sel, text, []);
    sel.disabled = true;
  };
  /* A clearing is reported once, by the refresh that did it; a later
     endpoint change is a new state and must not repeat it about a pair it
     was never judged against. */
  createForms.clearedType = '';
  if (!src || !dst) {
    placeholder('Choose both entities first');
    note.textContent = 'The types on offer depend on what the two entities ' +
      'are, so they appear once both are chosen.';
    return;
  }
  if (src.id === dst.id) {
    /* The wanted type is kept, not cleared: there is no pair to judge it
       against until the analyst picks a different entity. */
    placeholder('Choose two different entities');
    note.textContent = 'Source and target are the same entity. An entity ' +
      'cannot relate to itself: choose a different target.';
    return;
  }
  const legal = legalEdgeTypes(src.node_type, dst.node_type);
  const pair = src.node_type + ' → ' + dst.node_type;
  if (!legal.length) {
    placeholder('No type is permitted for this pair');
    const reverse = legalEdgeTypes(dst.node_type, src.node_type).length;
    note.textContent = 'No relationship type in the ontology runs ' + pair +
      '. ' + (reverse
        ? reverse + ' run the other way: use Swap source and target.'
        : 'None runs the other way either; model it through an ' +
          'intermediate entity.');
    return;
  }
  sel.disabled = false;
  const wanted = createForms.wantedType;
  const keep = legal.some((t) => t.key === wanted) ? wanted : '';
  if (wanted && !keep) {
    /* Cleared, and said so in the note: the alternative, some other type
       silently standing in, is the defect. */
    createForms.clearedType = wanted;
    createForms.wantedType = '';
  }
  clear(sel);
  const blank = el('option', null, 'Choose a relationship type');
  blank.value = '';
  blank.disabled = true;
  sel.appendChild(blank);
  for (const [sign, label] of SIGN_GROUPS) {
    const members = legal.filter((t) => Math.sign(t.default_sign) === sign)
      .sort((a, b) => a.display_name.localeCompare(b.display_name));
    if (!members.length) continue;
    const group = el('optgroup');
    group.label = label;
    for (const t of members) {
      const o = el('option', null, t.display_name + ' (' + t.key + ')');
      o.value = t.key;
      group.appendChild(o);
    }
    sel.appendChild(group);
  }
  if (keep) sel.value = keep;
  else blank.selected = true;
  describeEdgeType(legal.length, pair);
}

/** The note under the type select: what the chosen type means, or why
 *  there is none. Separate so a change of the type alone can re-say it. */
function describeEdgeType(permitted, pair) {
  const note = $('edge-type-note');
  const chosen = state.ontology.edge_types.find((t) => t.key === $('edge-type').value);
  if (chosen) {
    note.textContent = '"' + chosen.display_name + '" is ' +
      signWords(chosen.default_sign) +
      (chosen.is_social_tie ? ' and counts as a social tie.'
                            : ' and is not counted as a social tie.');
    return;
  }
  const cleared = createForms.clearedType &&
    state.ontology.edge_types.find((t) => t.key === createForms.clearedType);
  note.textContent = cleared
    ? 'The type you chose, "' + cleared.display_name + '", is not permitted ' +
      'for ' + pair + ', so it was cleared. Choose again from the ' +
      permitted + ' that are.'
    : permitted + ' permitted for ' + pair + '. Choose one.';
}

function onEdgeTypeChange() {
  createForms.wantedType = $('edge-type').value;
  createForms.clearedType = '';
  const src = endpointNode($('edge-src').value);
  const dst = endpointNode($('edge-dst').value);
  if (src && dst) {
    describeEdgeType(legalEdgeTypes(src.node_type, dst.node_type).length,
      src.node_type + ' → ' + dst.node_type);
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
    observed_at: observedAtUtc(observed),
  };
}

/** The "Observed at (UTC)" field's value as an instant.
 *
 *  A `datetime-local` input has no zone, and `new Date(value)` read it in
 *  the browser's. Every time the console shows is now UTC, so 17:00 typed
 *  in Los Angeles came back as "observed 13 Jul" (00:00Z the next day,
 *  which `fmtWhen` reads as a bare day): the analyst's own entry, read back
 *  as another date (verifier, ux05 fix round, 2026-09-22). The field is
 *  labelled UTC and read as UTC, so what is typed is what is shown. */
function observedAtUtc(value) {
  if (!value) return null;
  const d = new Date(value + 'Z');
  return Number.isNaN(d.getTime()) ? null : d.toISOString();
}

/** U3. A bare `<input type="date">` gives a local calendar day; the API
 *  wants an instant. Midnight UTC is the honest reading of "this was true
 *  from the 3rd of March": the graph records world time to the day, and
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
  /* 'claim': the tie inspector's Add a claim form (final review C14). */
  for (const prefix of ['node', 'edge', 'claim']) {
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
  const ungraded = gradingProblem('node');
  if (ungraded) { setMsg(errBox, ungraded); return; }
  const assertion = assertionFrom('node');
  const problem = rationaleProblem(assertion);
  if (problem) { setMsg(errBox, problem); return; }
  const interval = intervalFrom('node');
  const badInterval = intervalProblem(interval);
  if (badInterval) { setMsg(errBox, badInterval); return; }
  const token = caseToken();
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
    /* Written for a case the analyst has since left: the reload and the
       selection below would land in the wrong workspace. */
    if (caseChanged(token)) return;
    setMsg(okBox, assertion.evidence_id
      ? 'Created with its founding assertion and exhibit. Opening it in the inspector.'
      : 'Created with its founding assertion. It has NO exhibit behind it yet.');
    $('node-label').value = '';
    $('node-rationale').value = '';
    $('node-ref').value = '';
    /* The next entry is graded afresh, with this grading one explicit
       click away rather than silently carried over. */
    createForms.lastGrading.node = gradingOf('node');
    resetGrading('node');
    await reloadAll();
    if (caseChanged(token)) return;
    selectNode(out.id);
    selectTab('graph');
  } catch (err) {
    if (caseChanged(token)) return;
    inlineProblem(errBox, err);
  }
}

async function createEdge(event) {
  event.preventDefault();
  const errBox = $('edge-error'), okBox = $('edge-ok');
  setMsg(errBox, ''); setMsg(okBox, '');
  const src = $('edge-src').value, dst = $('edge-dst').value;
  const edgeType = $('edge-type').value;
  if (!src || !dst) { setMsg(errBox, 'Choose both entities.'); return; }
  if (src === dst) {
    setMsg(errBox, 'Source and target are the same entity. An entity cannot ' +
      'relate to itself.');
    return;
  }
  if (!edgeType) {
    /* Two different refusals: a pair the ontology does not connect, and a
       type nobody has chosen yet. The second used to be impossible only
       because the form chose one itself (see refreshEdgeTypes). */
    const s = endpointNode(src);
    const d = endpointNode(dst);
    const none = s && d && !legalEdgeTypes(s.node_type, d.node_type).length;
    setMsg(errBox, none
      ? 'No relationship type is permitted between these two types.'
      : 'Choose a relationship type. None is chosen for you.');
    if (!none) $('edge-type').focus();
    return;
  }
  const ungraded = gradingProblem('edge');
  if (ungraded) { setMsg(errBox, ungraded); return; }
  const assertion = assertionFrom('edge');
  const problem = rationaleProblem(assertion);
  if (problem) { setMsg(errBox, problem); return; }
  const interval = intervalFrom('edge');
  const badInterval = intervalProblem(interval);
  if (badInterval) { setMsg(errBox, badInterval); return; }
  const token = caseToken();
  try {
    /* The confidence travels in `assertion` and only there. Since 0064 a
       tie's confidence IS its assertions' (the highest live one), so the
       grade chosen here is the one the canvas, the filter and the metrics
       read (ux06 edge-confidence-not-stored, 2026-09-22). */
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
    if (caseChanged(token)) return;
    setMsg(okBox, assertion.evidence_id
      ? 'Relationship recorded with its assertion and exhibit.'
      : 'Relationship recorded. It has NO exhibit behind it yet.');
    $('edge-rationale').value = '';
    $('edge-ref').value = '';
    /* The next relationship starts from nothing: no endpoints, no type,
       no grading (one explicit click restores the grading). Leaving the
       last pair and type in place invites recording the next tie against
       the previous actor. */
    createForms.lastGrading.edge = gradingOf('edge');
    createForms.wantedType = '';
    $('edge-src-filter').value = '';
    $('edge-dst-filter').value = '';
    buildEndpointSelect('src', '');
    buildEndpointSelect('dst', '');
    refreshEdgeTypes();
    resetGrading('edge');
    await reloadAll();
    if (caseChanged(token)) return;
    selectEdge(out.id);
    selectTab('graph');
  } catch (err) {
    if (caseChanged(token)) return;
    inlineProblem(errBox, err);
  }
}

/* ── command palette (⌘K / Ctrl+K) ─────────────────────────────────────
 * docs/06: "Power users will live here." Everything reachable from a control
 * on screen is reachable from a keystroke, and nothing here does anything the
 * UI cannot also do — a palette that hides capabilities is a trap. */

/* Every pane in the rail, in rail order. This list was written when
   the rail had six panes and stayed at six while the rail grew to
   seventeen, so until 2026-09-09 the palette's "Go to" offered a third
   of the console and said nothing about the rest. `test_ui_invariants`
   holds it to the `data-tab` set in index.html, in order. */
const TAB_NAMES = [
  ['graph', 'Sociogram'],
  ['entities', 'Entity list'],
  ['evidence', 'Evidence'],
  ['triage', 'Triage'],
  ['inbox', 'Inbox'],
  ['analytics', 'Analysis'],
  ['search', 'Search'],
  ['comms', 'Comms'],
  ['feeds', 'Feeds'],
  ['ach', 'ACH'],
  ['report', 'Report'],
  ['governance', 'Lifecycle'],
  ['admin', 'Admin'],
  ['samples', 'Lab'],
  ['deception', 'Deception'],
  ['add-node', 'Add entity'],
  ['add-edge', 'Add relationship'],
];

function buildPaletteItems() {
  const items = [];
  const inCase = !!state.caseId;

  if (!inCase) {
    for (const c of state.cases) {
      items.push({ kind: 'Case', label: c.code + ': ' + c.title,
                   hint: c.status, run: () => openCase(c.id) });
    }
    /* Deployment-wide, so offered with no case open, to the same accounts
       the header offers it to (ux16, 2026-09-22). */
    if (canAdmin || canReview) {
      items.push({ kind: 'View', label: 'Go to ' + adminViewName(),
                   hint: canAdmin ? 'accounts and readiness'
                                  : 'the security officer queue',
                   run: showAdmin });
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
      kind: 'Entity', nodeId: n.id, label: n.label, hint: typeName(n.node_type),
      run: () => { selectNode(n.id); selectTab('graph'); },
    });
  }
  return items;
}

/* Selectors in the palette (selectors-unsearchable, ux09-search,
   2026-09-22). The palette matches names in memory, and a wallet, a Jabber
   id or an email lives in the selector table, which only the server can
   search: pasting ember_hobby's own wallet here answered "Nothing
   matches." So input that could be a selector (three characters or more,
   no spaces, or a value behind its type label: PAL_SEL_LABELLED) is also
   sent to `/search/selectors`, once it settles, and the
   entities it finds are listed with the selector as their hint. Cached per
   query for one opening of the palette and at most PAL_SEL_TTL_MS, and
   dropped on a case switch; a command typed with spaces never spends the
   search meter the Search pane shares.

   The cache is short on purpose. Held for the whole case, an empty answer
   stuck: a wallet looked up before anyone recorded it kept answering
   "Nothing matches." until a case switch or a reload, which is this
   finding again in a narrower window (verifier of the 2026-09-22 fix). */
const PAL_SEL_DELAY_MS = 250;
const PAL_SEL_LIMIT = 20;
const PAL_SEL_TTL_MS = 30000;
function freshPalSel() {
  return { token: caseToken(), results: new Map(), inflight: new Set(),
           pending: '', timer: null };
}
let palSel = freshPalSel();

function resetPalSel() {
  clearTimeout(palSel.timer);
  palSel = freshPalSel();
}

onCaseSwitch(() => {
  resetPalSel();
});

/* Also a value pasted behind its one-word type label ("ICQ: 123456789",
   "IMEI 490154203237518"), which the server reads as that type's value
   (curation.type_label). Spaced, it was never sent, so the palette
   answered "Nothing matches." for a number the Search pane finds
   (verifier of the second 2026-09-22 fix round). A label followed by a
   colon, or by a value holding a digit: two-word commands ("Save layout",
   "Fit view") are neither, so they still never spend the search meter. */
const PAL_SEL_LABELLED = /^[A-Za-z][\w-]*(?::\s*\S{3,}|\s+(?=\S*\d)\S{3,})$/;

function palSelectorQuery(raw) {
  if (!state.caseId || raw.length < 3) return '';
  return !/\s/.test(raw) || PAL_SEL_LABELLED.test(raw) ? raw : '';
}

/* An answer the palette may still show without asking again: not a
   failure (a 429 from the shared meter clears in seconds, and the next
   keystroke should ask again) and not older than PAL_SEL_TTL_MS. */
function palSelFresh(entry) {
  return !!entry && !entry.error && Date.now() - entry.at < PAL_SEL_TTL_MS;
}

function schedulePaletteSelectors(sq) {
  clearTimeout(palSel.timer);
  palSel.timer = null;
  palSel.pending = '';
  if (!sq || palSel.token !== caseToken()) return;
  if (palSelFresh(palSel.results.get(sq))) return;
  palSel.pending = sq;
  if (palSel.inflight.has(sq)) return;      // its reply will render
  palSel.timer = setTimeout(() => { fetchPaletteSelectors(sq); }, PAL_SEL_DELAY_MS);
}

async function fetchPaletteSelectors(sq) {
  const token = caseToken();
  const mine = palSel;
  mine.inflight.add(sq);
  let entry;
  try {
    const page = await api(cpath('/search/selectors?with_total=true&limit='
      + PAL_SEL_LIMIT + '&q=' + encodeURIComponent(sq)));
    entry = { hits: page.hits || [], total: page.total || 0, at: Date.now() };
  } catch (err) {
    /* Said in the palette, not in a banner: the names above it are still
       searched, and a banner per keystroke would bury the workspace. A 401
       has already ended the session in `_fetch`. */
    entry = { error: err instanceof ApiError ? (err.detail || err.title) : 'unavailable',
              at: Date.now() };
  }
  mine.inflight.delete(sq);
  if (caseChanged(token) || palSel !== mine) return;
  palSel.results.set(sq, entry);
  if (palSel.pending === sq) palSel.pending = '';
  if (state.paletteOpen
      && palSelectorQuery($('palette-input').value.trim()) === sq) renderPalette();
}

/* Appends the selector matches for `sq` to `matches` (skipping an entity
   the names already matched) and returns the status line to show. */
function addSelectorMatches(matches, sq) {
  if (!sq || palSel.token !== caseToken()) return '';
  if (palSel.pending === sq) return 'Searching selector values…';
  const entry = palSel.results.get(sq);
  if (!entry) return '';
  if (entry.error) return 'Selector search failed: ' + entry.error;
  const listed = new Set(matches.map((it) => it.nodeId).filter(Boolean));
  for (const hit of entry.hits) {
    if (listed.has(hit.id)) continue;
    const v = hit.via || {};
    matches.push({
      kind: 'Entity', nodeId: hit.id, label: visibleText(hit.label),
      hint: 'via ' + v.selector_type + ' ' + visibleText(v.value)
        + (v.exact ? ' (exact)' : ''),
      run: () => { selectNode(hit.id); selectTab('graph'); },
    });
  }
  return entry.total > entry.hits.length
    ? entry.hits.length + ' of ' + entry.total + ' entities matched by a '
      + 'selector ' + agree(entry.hits.length, 'is', 'are')
      + ' listed. Search shows the rest.'
    : '';
}

function openPalette() {
  if (state.paletteOpen) return;
  state.paletteOpen = true;
  state.paletteReturn = document.activeElement;
  state.paletteIndex = 0;
  /* Each opening asks the server afresh: what the last one learned about
     the selector table may no longer be true (see PAL_SEL_TTL_MS). */
  resetPalSel();
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
  const raw = $('palette-input').value.trim();
  const q = raw.toLowerCase();
  const all = buildPaletteItems();
  const terms = q ? q.split(/\s+/) : [];
  const matches = all.filter((it) => {
    if (!terms.length) return true;
    const hay = (it.kind + ' ' + it.label + ' ' + (it.hint || '')).toLowerCase();
    return terms.every((t) => hay.includes(t));
  }).slice(0, 200);
  const remote = addSelectorMatches(matches, palSelectorQuery(raw));

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
  /* "Nothing matches." waits for the selector lookup: said while it is
     still running, it is the premature answer this lookup exists to fix. */
  const waiting = palSel.pending !== '' && palSel.pending === palSelectorQuery(raw);
  show($('palette-empty'), matches.length === 0 && !waiting);
  setMsg($('palette-remote'), remote);

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
  input.addEventListener('input', () => {
    state.paletteIndex = 0;
    schedulePaletteSelectors(palSelectorQuery(input.value.trim()));
    renderPalette();
  });
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
      else if (signedIn()) openPalette();
      return;
    }
    /* `?` opens the keyboard sheet — but NOT while the caret is in a
       field, or an analyst typing a case note gets a modal instead of a
       question mark. `isContentEditable` covers the rich inputs; the tag
       check covers the rest. */
    if (e.key === '?' && !e.ctrlKey && !e.metaKey && !e.altKey) {
      const t = e.target;
      const typing = t && (t.isContentEditable
        || ['INPUT', 'TEXTAREA', 'SELECT'].includes(t.tagName));
      if (!typing && signedIn()) { e.preventDefault(); toggleKeys(); }
      return;
    }
    if (e.key === 'Escape' && !$('keys-scrim').hidden) {
      e.preventDefault();
      toggleKeys(false);
    }
    /* Alt+1..9 jumps to a pane. An analyst working one case crosses
       Graph -> Evidence -> Comms -> Report dozens of times an hour, and
       the rail is a mouse trip each way.

       ALT, not a bare digit: bare digits are typed into every field in
       this console, and Ctrl+digit is the browser's own tab switcher.
       The guard against INPUT/TEXTAREA/SELECT/contentEditable is kept
       anyway -- Alt+2 in a note should not teleport the analyst out of
       what they are writing. */
    if (e.altKey && !e.ctrlKey && !e.metaKey && /^[1-9]$/.test(e.key)) {
      const t = e.target;
      const typing = t && (t.isContentEditable
        || ['INPUT', 'TEXTAREA', 'SELECT'].includes(t.tagName));
      if (typing || !signedIn()) return;
      const tabs = Array.from(
        document.querySelectorAll('.rail-btn[data-tab]:not([hidden])'));
      const target = tabs[Number(e.key) - 1];
      if (target) { e.preventDefault(); selectTab(target.dataset.tab); }
    }
  });
  $('keys-close').addEventListener('click', () => toggleKeys(false));
  $('keys-scrim').addEventListener('mousedown', (e) => {
    if (e.target === $('keys-scrim')) toggleKeys(false);
  });

  /* macOS reads ⌘; everywhere else that glyph is noise. */
  const mac = /Mac|iPhone|iPad/i.test(navigator.platform || navigator.userAgent || '');
  /* The KEY CAP, not the button: the button also holds an icon and a
     label, and assigning textContent to it would delete both. */
  $('palette-key').textContent = mac ? '⌘K' : 'Ctrl K';
  $('keys-palette').textContent = mac ? '⌘K' : 'Ctrl K';
  /* And the hint strip under the canvas, which said ⌘K on every
     platform beside a header chip that said Ctrl K (README screenshot set
     review, 2026-09-23). */
  $('canvas-keys-palette').textContent = mac ? '⌘K' : 'Ctrl K';
}

/** Show or hide the keyboard sheet. `on` omitted means toggle. */
function toggleKeys(on) {
  const scrim = $('keys-scrim');
  const next = on === undefined ? scrim.hidden : on;
  show(scrim, next);
  /* Focus follows the dialog, and returns. A modal that steals focus and
     does not give it back strands a keyboard user on the body element. */
  if (next) $('keys-close').focus();
  else if (state.tab) {
    const tab = $('tab-' + state.tab);
    if (tab) tab.focus();
  }
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

/* Not reset on a case switch, deliberately: notifications are the
 * analyst's own, across every case they hold, so nothing here belongs to
 * the case being left. What DID need fixing is below. */
async function loadInbox() {
  const unreadOnly = $('inbox-unread-only').checked;
  try {
    const data = await api('/notifications?limit=100'
      + (unreadOnly ? '&unread_only=true' : ''));
    state.inbox = data.notifications || [];
    state.inboxUnread = data.unread || 0;
    state.inboxFailed = false;
    clearLoadFailure('inbox-empty');
  } catch (err) {
    /* ux17-failure:failure-renders-as-empty-claim (2026-09-22): a failed
       read rendered "Nothing waiting.", which is the inbox saying no
       second signature is wanted at the moment it could not tell. */
    state.inbox = [];
    state.inboxFailed = true;
    renderInbox();
    showLoadFailure('inbox-empty', 'Your notifications', err, loadInbox);
    if (!(err instanceof ApiError && err.status === 403)) fail(err);
    return;
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
  badge.title = countOf(n, 'unread notification', 'unread notifications');
}

const PRIORITY_LABEL = { 1: 'urgent', 2: 'normal', 3: 'low' };

function renderInbox() {
  const box = $('inbox-list');
  clear(box);
  const rows = state.inbox || [];
  show($('inbox-empty'), rows.length === 0 && !state.inboxFailed);
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
    /* A control with no visible label says what it sets to a screen
       reader; a title is not an accessible name everywhere. */
    priority.setAttribute('aria-label', p.channel + ': lowest priority to deliver');
    enabled.setAttribute('aria-label', p.channel + ': deliver on this channel');
    row.appendChild(priority);

    const digest = el('input');
    digest.type = 'checkbox';
    digest.checked = p.digest;
    digest.title = 'Roll up to the next hour instead of sending immediately';
    digest.setAttribute('aria-label', p.channel + ': hourly digest');
    row.appendChild(digest);
    row.appendChild(el('span', 'muted small', 'digest'));

    const from = el('input');
    from.type = 'time';
    from.value = p.quiet_from || '';
    from.title = 'Quiet hours start (your local time)';
    from.setAttribute('aria-label', p.channel + ': quiet hours start');
    const to = el('input');
    to.type = 'time';
    to.value = p.quiet_to || '';
    to.title = 'Quiet hours end';
    to.setAttribute('aria-label', p.channel + ': quiet hours end');
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

/** A normaliser note as a sentence of its own: capital first letter and a
 *  closing full stop. The service writes its notes as clauses ("a Telegram
 *  @username is NOT durable ..."), which read correctly after a colon, and
 *  this pane puts them after a full stop, so the Correlate answer began a
 *  sentence in lower case (README screenshot review, 2026-09-23). */
function asSentence(note) {
  const text = String(note || '').trim();
  if (!text) return '';
  const upper = text.charAt(0).toUpperCase() + text.slice(1);
  return /[.!?]$/.test(upper) ? upper : upper + '.';
}

/** What this platform's identifier MEANS, and what sparse data means. */
function renderPlatformNote() {
  const p = platformByKey($('comms-platform').value);
  const note = $('comms-platform-note');
  const cover = $('comms-platform-coverage');
  if (!p) { show(note, false); show(cover, false); return; }
  note.textContent = p.durable_selector_type
    ? p.durable_selector_type + ': ' + p.note
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
    $('comms-preview-note').textContent = asSentence(body.note);
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
    const token = caseToken();
    const code = caseCodeNow();
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
      /* Recorded in the case the analyst has since left: say where, and
         leave this case's form alone (the switch already cleared it). */
      if (caseChanged(token)) {
        banner('Identifier recorded in ' + code,
          'You had moved to another case before the reply arrived, so it is '
          + 'not shown here.', 'warn');
        return;
      }
      setMsg(msg, body.durable_value
        ? 'Recorded, indexed as ' + body.durable_value
        : 'Recorded. ' + asSentence(body.note
          || 'No durable value, so it will not correlate.'));
      $('comms-observed').value = '';
      show($('comms-preview'), false);
    } catch (err) {
      if (caseChanged(token)) {
        banner('Recording an identifier in ' + code + ' failed',
          failureReason(err));
        return;
      }
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
    const token = caseToken();
    try {
      const q = '?platform_key='
              + encodeURIComponent($('comms-corr-platform').value)
              + '&observed='
              + encodeURIComponent($('comms-corr-observed').value.trim());
      const body = await api(cpath('/comms/correlate') + q);
      /* "N binding(s) in this case" must be about the case on screen. */
      if (caseChanged(token)) return;
      const head = el('p', 'hint');
      /* The count's own noun: "0 binding(s)" was in the README capture
         (README screenshot review, 2026-09-23). */
      const n = body.matches.length;
      head.textContent = body.durable_value
        ? 'Correlating on ' + body.durable_value + ' finds ' + n
          + (n === 1 ? ' binding' : ' bindings') + ' in this case.'
        : ('No durable value, so nothing can correlate. '
          + asSentence(body.note)).trim();
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
    ? 'Already parsed: showing the existing reading'
    : 'Parsed');
  card.appendChild(h);

  const codecl = (block.co_declaration || []).length;
  card.appendChild(el('p', 'hint',
    countOf(codecl, 'identifier', 'identifiers')
    + ' read as the publisher’s own. '
    + 'That SET is the finding: a vendor running Jabber, Tox and Session '
    + 'with a PGP key operates differently from one running a Telegram bot.'));

  for (const e of block.entries) {
    const row = el('div', 'entry-row');

    const role = el('span', ROLE_PILL[e.role] || 'pill', e.role);
    row.appendChild(role);

    const kind = e.platform_key || e.selector_type || 'unresolved';
    row.appendChild(el('span', 'pill', kind));

    row.appendChild(el('code', 'mono grow', visibleText(e.observed_value)));

    const score = el('span', 'pill', e.score.toFixed(2));
    row.appendChild(score);

    if (e.durable_value) {
      const d = el('div', 'entry-sub');
      d.appendChild(el('span', 'label', 'indexed as'));
      d.appendChild(el('code', 'mono', visibleText(e.durable_value)));
      row.appendChild(d);
    }
    /* The reason is not decoration. docs/03: a bare 0.87 will be either
       over-trusted or ignored, and the same is true of a bare role. */
    row.appendChild(el('p', 'hint', e.role_reason));
    row.appendChild(el('p', 'hint mono-sm', e.score_reason));
    if (e.stoplisted) {
      row.appendChild(el('p', 'hint warn',
        'On the service stoplist: this belongs to a known escrow, '
        + 'guarantor or admin, not to the publisher.'));
    }
    if (e.shared_service_publishers) {
      row.appendChild(el('p', 'hint warn',
        'Advertised by ' + countOf(e.shared_service_publishers,
          'other publisher', 'other publishers')
        + ': a shared SERVICE, not a shared identity.'));
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
    const token = caseToken();
    const code = caseCodeNow();
    try {
      const block = await api(cpath('/comms/contact-blocks'), {
        method: 'POST',
        json: {
          raw_text: $('comms-block-text').value,
          source_ref: $('comms-block-source').value.trim(),
          publisher_handle: $('comms-block-handle').value.trim() || null,
        },
      });
      /* The parse belongs to the case it was sent to. Rendered after a
         switch it sat in the new case's output, which the switch had just
         cleared, naming another case's publisher (verifier, fix round of
         2026-09-22). */
      if (caseChanged(token)) {
        banner('Contact block parsed in ' + code,
          'You had moved to another case before the reply arrived, so the '
          + 'reading is not shown here. Any proposals it raised are in that '
          + "case's triage queue.", 'warn');
        return;
      }
      renderContactBlock(block);
    } catch (err) {
      if (caseChanged(token)) {
        banner('Parsing a contact block in ' + code + ' failed',
          failureReason(err));
        return;
      }
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
  initOpsPanes();
  initAdmin();
  initSetup();
  wireElementActions();
  wireAuditVerify();
  wireCustodyVerify();
  wireRetentionConfirm();
  wireDeliveries();
  wireAssumptions();
  wireCaseActions();
  initCanvas();
  initPalette();
  opts($('case-class'), TLP.map((t) => [t, t]), 'AMBER');
  opts($('ev-class'), TLP.map((t) => [t, t]), 'AMBER');
  opts($('cap-class'), TLP.map((t) => [t, t]), 'AMBER');
  opts($('sel-metric'), SIZE_METRICS, state.sizeMetric);
  opts($('sel-minconf'), [
    ['LOW', 'LOW and above'],
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
  $('apr-refresh').addEventListener('click', loadApprovals);
  $('apr-state').addEventListener('change', loadApprovals);
  document.addEventListener('keydown', onTriageKey);
  $('an-run').addEventListener('click', runAnalysis);
  /* Changing a parameter invalidates what is on screen. Blank it rather
     than leave numbers that no longer match the controls above them. */
  for (const id of ['an-decay', 'an-kpp-n']) {
    /* Through blankAnalytics, so a run still out under the old parameters
       is dropped rather than drawn under the new ones (final review C3). */
    $(id).addEventListener('change', () => {
      blankAnalytics('Parameters changed. Run the analysis again.');
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
  $('edge-type').addEventListener('change', onEdgeTypeChange);
  $('edge-swap').addEventListener('click', swapEndpoints);
  $('edge-need-entities').addEventListener('click', () => {
    selectTab('add-node');
    $('node-label').focus();
  });
  for (const which of ['src', 'dst']) {
    $('edge-' + which + '-filter').addEventListener('input',
      () => buildEndpointSelect(which));
    $('edge-' + which + '-filter').addEventListener('keydown',
      (e) => onEndpointFilterKey(which, e));
  }
  for (const prefix of ['node', 'edge']) {
    $(prefix + '-same-grading').addEventListener('click', () => {
      resetGrading(prefix, createForms.lastGrading[prefix]);
    });
  }

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

  /* Re-chart on a metric change, but only when an actor has been picked:
     firing a fetch for the empty selection would spend a request to render
     the same "pick an actor" line. */
  $('an-hist-metric').addEventListener('change', () => {
    state.analyticsHistoryMetric = $('an-hist-metric').value;
    if (state.analyticsHistoryNode) {
      loadMetricHistory(state.analyticsHistoryNode,
                        state.analyticsHistoryLabel);
    }
  });

  window.addEventListener('resize', () => { resizeDensity(); resizeHistory(); });
}

/* A token handed over in the URL fragment (#token=...) is adopted and the
 * fragment immediately erased, so it never reaches a bookmark, the history
 * entry, or a Referer header. Written for `bootstrap.py session`, which is
 * the way in when TOTP cannot work — a host whose clock disagrees with the
 * phone's can never produce a matching code. A fragment is not sent to the
 * server, so the token does not appear in the access log either.
 *
 * Returns the banner to show once boot() has settled the view (title,
 * detail, kind), or null. Banners raised here directly would be lost:
 * `endSession` suppresses them while `state.booting` is set. */
async function adoptSessionFromFragment() {
  const hash = window.location.hash || '';
  /* Read the deep link BEFORE the fragment is erased. `#case=<id>&tab=feeds`
   * opens a named case at a named pane — "look at the dead-letter queue on
   * NIGHTJAR" is a thing one analyst says to another, and without this the
   * answer is six words of clicking. Kept in the same fragment as the token
   * because a fragment is never sent to the server, so neither the token nor
   * the case id reaches an access log. */
  const wanted = /(?:^|[#&])tab=([a-z-]+)/.exec(hash);
  const wantedCase = /(?:^|[#&])case=([0-9a-fA-F-]{36})/.exec(hash);
  if (wanted) state.deepLinkTab = wanted[1];
  if (wantedCase) state.deepLinkCase = wantedCase[1];

  const match = /(?:^|[#&])token=([^&]+)/.exec(hash);
  if (!match) {
    /* No token, but possibly a tab: strip the fragment anyway so a
     * bookmark of this page does not carry a stale one. */
    if (hash) history.replaceState(null, '', window.location.pathname);
    return null;
  }
  const token = decodeURIComponent(match[1]);
  history.replaceState(null, '', window.location.pathname);

  /* A fragment must never replace a session this browser already holds
     (2026-09-09). Cookies are per profile, not per tab: until this check
     the exchange below ran unconditionally with the bearer forced, so a
     link of the documented deep-link shape carrying someone ELSE's token,
     opened by a signed-in analyst, swapped the cookie under every tab
     they had open -- each still showed the analyst, `authHeaders()` in
     each read the new CSRF cookie live, and every write from them was
     attributed to the other account in the audit chain. So: ask /auth/me
     on the cookie first (`state.token` is null here, so no bearer goes
     with it). A live session WITH its readable half is kept and the
     handed-over token is dropped on the floor. A live session WITHOUT it
     (`halfSession`) is one the exchange may repair: the server re-mints
     the pair for the same account and refuses a different one with 409,
     which is the line that holds even when this code is wrong. */
  let holder = null;
  try {
    holder = await api('/auth/me');
  } catch (_err) {
    /* No session (that 401 went through `endSession` with `booting` set,
       which resets a dead pair and shows nothing) or the API is
       unreachable, which the exchange below reports. */
  }
  if (holder && !halfSession()) {
    return {
      title: 'Already signed in as ' + (holder.display_name || holder.user_id),
      detail: 'The session handed over in the link was not used: a link '
        + 'never replaces the session this browser already holds. Sign '
        + 'out first to use it.',
      kind: 'warn',
    };
  }

  /* Exchange it ONCE for the cookie pair (`POST /auth/cookie`), forcing
     the bearer so the NEW token is presented and not the cookie. Held in
     memory before the call because a console the browser refuses Secure
     cookies on runs on this token alone (see the header). A refusal --
     a stale token's 401, another account's 409 -- comes back here rather
     than through `endSession`: the tab's own session, if any, is not
     what was judged. Nothing is written to storage on any path. */
  state.token = token;
  try {
    await api('/auth/cookie', { method: 'POST', bearer: token });
    return null;
  } catch (err) {
    state.token = null;
    return {
      title: 'Handed-over session not adopted',
      detail: (err instanceof ApiError ? (err.detail || err.title) : String(err))
        + ' Sign in, or mint a fresh link with bootstrap.py session.',
      kind: 'warn',
    };
  }
}

/** Honour a `#tab=` deep link once the workspace is up.
 *
 *  Called after the case loads rather than during boot: several panes are
 *  case-scoped and selecting one before `state.caseId` exists produces a
 *  pane that renders its empty state and then never refreshes, which looks
 *  exactly like "there is no data".
 */
function applyDeepLinkTab() {
  const name = state.deepLinkTab;
  state.deepLinkTab = null;
  if (!name) return;
  if (!document.querySelector('.rail-btn[data-tab="' + name + '"]')) return;
  selectTab(name);
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
 *
 * `labelOf` is the inspector's (one declaration, see there): a second copy
 * lived here until 2026-09-09 and, being declared last, silently replaced
 * the first for every caller in the file.
 * ===================================================================== */

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
        (isSource ? ' merged INTO ' : ' absorbed ') + labelOf(other)));
      item.appendChild(top);
      item.appendChild(el('div', 'muted small',
        m.reason + ' \u00b7 ' + countOf(m.edges_repointed, 'tie', 'ties')
        + ' moved \u00b7 ' +
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
    setMsg($('merge-error'), 'A merge must say why: it is the operation ' +
           'most likely to quietly corrupt a case.');
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
    /* Dual control is a refusal with a NEXT STEP, not a fault. The router
       answers 409 when the case has the switch on and no approval was
       supplied -- and before this there was nothing the analyst could do
       about it from the browser, because raising a request had no
       surface. Offer to raise it, carrying the SAME reason they just
       typed: the approver signs the reason, and a merge whose recorded
       reason is not the one signed off makes the audit log say something
       nobody agreed to. */
    if (err instanceof ApiError && err.status === 409
        && /approval/i.test(err.detail || err.title || '')) {
      const ask = window.confirm(
        'This case requires a second signature on merges.\n\n' +
        'Raise an approval request for merging "' + losing + '" into "' +
        surviving + '"?\n\nIt will carry the reason you just gave. Somebody '
        + 'other than you must approve it, and it can then be executed once '
        + 'from Triage → Dual control.');
      if (!ask) return;
      try {
        await api(cpath('/approvals'), {
          method: 'POST',
          json: {
            /* The server's catalogue key, NOT a display name. `approvals.py`
               keys OPERATIONS by 'node.merge'; sending 'MERGE' 400s with
               "unknown operation". */
            operation: MERGE_OPERATION,
            payload: { source_node_id: sel.id, target_node_id: targetId,
                       reason: reason.trim(), basis_selector_id: null },
            justification: reason.trim(),
          },
        });
        selectTab('triage');
        loadApprovals();
        banner('Approval requested',
               'Nobody has approved it yet. It is listed under Triage → '
               + 'Dual control, and you cannot decide your own request.',
               'info');
      } catch (raiseErr) {
        if (raiseErr instanceof ApiError) {
          inlineProblem($('merge-error'), raiseErr);
        } else { fail(raiseErr); }
      }
      return;
    }
    if (err instanceof ApiError) inlineProblem($('merge-error'), err);
    else fail(err);
  }
}

/** The server's catalogue key for a merge approval.
 *
 *  Named once because it is a CONTRACT, not a label. The first version of
 *  this pane sent the string 'MERGE', which `approvals.py` rejects with
 *  "unknown operation" -- so raising a request 400'd and the Execute-merge
 *  button, which compared against the same wrong string, could never
 *  appear. Both halves were internally consistent and wrong together:
 *  exactly the defect the co-participation pane shipped, in the pane
 *  written after it. Asserted against `approvals.py` in
 *  `test_ui_invariants.py`.
 */
const MERGE_OPERATION = 'node.merge';

/* --- Dual control ------------------------------------------------------
 *
 * Approvals had no analyst surface at all. The notification centre's
 * "Open approvals" button switched to the Triage tab, which contained
 * none, and `runMerge` could not supply the `approval_request_id` its own
 * 409 demands -- so on a case with dual control switched on, Merge was
 * unreachable from the browser. The control did not make merging
 * two-person; it made it impossible.
 *
 * Requests are listed with their PAYLOAD rather than a summary. An
 * approval authorises one execution of exact parameters, so an approver
 * who cannot see the parameters is signing a description of them.
 */
async function loadApprovals() {
  if (!state.caseId) return;
  const wanted = $('apr-state').value;
  try {
    const q = new URLSearchParams({ limit: '100' });
    if (wanted) q.set('state', wanted);
    const body = await api(cpath('/approvals') + '?' + q.toString());
    const rows = body.approvals || [];
    renderList('apr-list', 'apr-empty', rows, approvalRow);
    $('apr-counts').textContent = rows.length
      ? countOf(rows.length, 'request', 'requests') : '';
    if (!rows.length) {
      $('apr-empty').textContent = wanted
        ? 'No ' + wanted.toLowerCase() + ' requests in this case.'
        : 'No approval requests in this case.';
    }
  } catch (err) {
    renderList('apr-list', 'apr-empty', [], approvalRow);
    $('apr-counts').textContent = '';
    if (err instanceof ApiError && (err.status === 403 || err.status === 404)) {
      $('apr-empty').textContent = refusalText(
        err, 'Approvals need case.read on this case.');
      return;
    }
    $('apr-empty').textContent = refusalText(
      err, 'Approvals could not be read. They are not known to be absent.');
  }
}

/** What a request asks for, in words, with the entities NAMED.
 *
 *  The card was titled with the catalogue key and its body was the
 *  payload's UUIDs, so an approver deciding a merge could not see which
 *  two entities it merged: dual control as a blind click, the opposite of
 *  its purpose (ux19 raw-ids-instead-of-names, 2026-09-22). The exact
 *  parameters are still printed beneath: an approval authorises one
 *  execution of THOSE, and the sentence is how a person reads them. */
function approvalTitle(a) {
  const p = a.payload || {};
  if (a.operation === MERGE_OPERATION && p.source_node_id && p.target_node_id) {
    return 'Merge "' + labelOf(p.source_node_id) + '" into "'
      + labelOf(p.target_node_id) + '"';
  }
  return a.operation;
}

function approvalRow(a) {
  const card = el('div', 'card row-card');
  const head = el('div', 'row-head');
  const title = approvalTitle(a);
  head.appendChild(el('span', 'row-title', visibleText(title)));
  /* `is_expired` is DERIVED, never stored (0028: no EXPIRED state and no
     sweeper). A PENDING request past its expiry is not pending in any
     useful sense, and showing it as PENDING invites somebody to wait for
     a decision that can no longer be acted on. */
  const dead = a.state === 'PENDING' && a.is_expired;
  head.appendChild(el('span', 'chip ' + (
    a.state === 'APPROVED' ? 'ok'
      : (a.state === 'REJECTED' || a.state === 'WITHDRAWN') ? 'bad'
        : dead ? 'warn' : ''), dead ? 'EXPIRED' : a.state));
  if (a.consumed_at) {
    const chip = el('span', 'chip small', 'spent');
    chip.title = 'Already used. An approval authorises ONE execution of '
               + 'the parameters it was raised over.';
    head.appendChild(chip);
  }
  card.appendChild(head);

  card.appendChild(el('p', null, visibleText(a.justification)));

  const facts = el('div', 'facts');
  const asker = a.requested_by_name || ('account ' + shortId(a.requested_by));
  facts.appendChild(fact('requested by', asker));
  facts.appendChild(fact('requested', fmtTime(a.requested_at)));
  facts.appendChild(fact('expires', fmtTime(a.expires_at)));
  if (a.decided_at) {
    facts.appendChild(fact('decided by',
      a.decided_by_name || ('account ' + shortId(a.decided_by))));
    facts.appendChild(fact('decided', fmtTime(a.decided_at)));
  }
  card.appendChild(facts);

  /* The exact parameters, not a summary of them. */
  if (title !== a.operation) card.appendChild(el('p', 'help', 'Exact parameters:'));
  const payload = el('p', 'mono small');
  payload.textContent = Object.entries(a.payload || {})
    .map(([k, v]) => k + '=' + visibleText(String(v))).join('  ');
  card.appendChild(payload);
  if (a.decision_note) {
    card.appendChild(el('p', 'help', 'Note: ' + visibleText(a.decision_note)));
  }

  if (a.state === 'PENDING' && !dead) {
    const actions = el('div', 'row-actions');
    for (const [label, approve] of [['Approve', true], ['Reject', false]]) {
      const b = el('button', 'btn ghost small', label);
      b.type = 'button';
      b.addEventListener('click', async () => {
        const note = window.prompt(
          label + ' this request?\n\n' + title + '\nRequested by ' + asker
          + '\n\n' + a.justification
          + '\n\nA note is recorded with the decision.');
        if (note === null) return;
        b.disabled = true;
        try {
          await api(cpath('/approvals/' + a.id + '/decide'), {
            method: 'POST', json: { approve: approve, note: note || null },
          });
          loadApprovals();
        } catch (err) {
          b.disabled = false;
          /* The self-approval refusal arrives here, and it is a RULE
             rather than a fault -- so it is stated, not bannered as an
             error the analyst did something wrong to cause. */
          if (err instanceof ApiError) inlineProblem($('apr-counts'), err);
          else fail(err);
        }
      });
      actions.appendChild(b);
    }
    const w = el('button', 'btn ghost small', 'Withdraw');
    w.type = 'button';
    w.title = 'For the requester: take back a request nobody has decided.';
    w.addEventListener('click', async () => {
      w.disabled = true;
      try {
        await api(cpath('/approvals/' + a.id + '/withdraw'), { method: 'POST' });
        loadApprovals();
      } catch (err) {
        w.disabled = false;
        if (err instanceof ApiError) inlineProblem($('apr-counts'), err);
        else fail(err);
      }
    });
    actions.appendChild(w);
    card.appendChild(actions);
  }

  /* An APPROVED, unspent merge approval is executable from here -- which
     is the whole point of the surface. Without it the analyst holds a
     signature and still has no way to spend it. */
  if (a.state === 'APPROVED' && !a.consumed_at && !a.is_expired
      && a.operation === MERGE_OPERATION) {
    const run = el('button', 'btn small', 'Execute merge');
    run.type = 'button';
    run.addEventListener('click', async () => {
      run.disabled = true;
      try {
        await api(cpath('/merges'), {
          method: 'POST', json: { approval_request_id: a.id },
        });
        invalidateAnalytics();
        await reloadAll();
        loadApprovals();
        banner('Merged under dual control',
               'The approval is now spent and cannot be reused.', 'info');
      } catch (err) {
        run.disabled = false;
        if (err instanceof ApiError) inlineProblem($('apr-counts'), err);
        else fail(err);
      }
    });
    card.appendChild(run);
  }
  return card;
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
  const token = caseToken();
  try {
    const data = await api(cpath('/proposals?state=' + wanted + '&limit=200'));
    if (caseChanged(token)) return;
    state.triage = data.proposals;
    state.triageCounts = data.counts || {};
    state.triageFailed = false;
    clearLoadFailure('triage-empty');
    renderTriage();
  } catch (err) {
    if (caseChanged(token)) return;
    /* ux17-failure:failure-renders-as-empty-claim (2026-09-22). This drew
       an empty queue, so the pane said "Nothing awaiting review." and the
       badge disappeared: the one signal that work is waiting, reporting
       that none is, because it could not look. On a 403 there was not
       even a banner. */
    state.triage = [];
    state.triageCounts = {};
    state.triageFailed = true;
    renderTriage();
    showLoadFailure('triage-empty', 'The triage queue', err, loadTriage);
    if (!(err instanceof ApiError && err.status === 403)) fail(err);
  }
}

/* A new case's queue is not the old case's queue: the list, the counts
   and the badge go on the switch, before the new read lands. */
onCaseSwitch(() => {
  state.triage = [];
  state.triageCounts = {};
  state.triageIndex = 0;
  state.triageFailed = false;
  clear($('triage-list'));
  setMsg($('triage-counts'), '');
  show($('triage-empty'), false);
  clearLoadFailure('triage-empty');
  show($('triage-badge'), false);
  /* The capture box too (final review C18, 2026-09-23). A forum dump
     pasted on NIGHTJAR stayed in it, and Capture after a switch parsed it
     into KESTREL: a stored capture document, proposals raised and the
     owner notified, none of which can be taken back. The comms reset
     clears a pasted block for the same reason. */
  $('cap-text').value = '';
  $('cap-title').value = '';
  $('cap-url').value = '';
  $('cap-class').value = 'AMBER';
  setMsg($('cap-result'), '');
  setMsg($('cap-error'), '');
  $('cap-run').disabled = false;
});

/** The rail badge is the only thing that tells an analyst work is waiting,
 *  so it is refreshed with the case rather than only when the tab is open. */
function renderTriageBadge() {
  const badge = $('triage-badge');
  if (state.triageFailed) {
    /* Unknown is shown as unknown. A hidden badge reads as "nothing
       waiting", which the console did not find out. */
    badge.textContent = '?';
    show(badge, true);
    badge.title = 'The triage queue could not be read, so what is waiting '
      + 'is unknown.';
    return;
  }
  const waiting = (state.triageCounts || {}).PROPOSED || 0;
  badge.textContent = waiting > 99 ? '99+' : String(waiting);
  show(badge, waiting > 0);
  badge.title = countOf(waiting, 'suggestion', 'suggestions')
    + ' awaiting review';
}

function renderTriage() {
  const box = $('triage-list');
  clear(box);
  const rows = state.triage || [];
  show($('triage-empty'), rows.length === 0 && !state.triageFailed);
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
        'Dispose of it. A reason is required, because parser drift is found by '
        + 'reading rejections.'));
      actions.appendChild(mk('Defer', '', deferProposal,
        'Park it as unresolved rather than forcing a decision now.'));
      card.appendChild(actions);
    } else {
      const meta = el('p', 'muted small',
        p.state + (p.review_note ? ': ' + p.review_note : ''));
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
  /* A chord is the browser's or the operating system's, never a verdict:
     Ctrl+A (select all) accepted the highlighted proposal with no prompt,
     and Ctrl+R and Ctrl+D opened the reject and defer prompts instead of
     reloading or bookmarking (README screenshot review, 2026-09-23). */
  if (e.ctrlKey || e.metaKey || e.altKey) return;
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
  /* The reply is the case's that was open at the press (C18): answered
     after a switch, it is said in a banner that names that case, and this
     case's cleared pane and fields are left alone. */
  const token = caseToken();
  const code = caseCodeNow();
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
    if (caseChanged(token)) {
      banner('Captured into ' + code,
        countOf(out.proposals_created || 0, 'proposal', 'proposals')
        + ' raised there. You had '
        + 'moved to another case before the reply arrived, so it is not '
        + 'shown here.', 'warn');
      return;
    }
    const found = Object.entries(out.by_type || {})
      .map(([k, v]) => v + ' ' + k).join(', ');
    setMsg(okBox,
      (out.deduplicated ? 'Already captured; ' : '') +
      countOf(out.selectors_found, 'selector', 'selectors') + ' found' +
      (found ? ' (' + found + ')' : '') + '. ' +
      countOf(out.proposals_created, 'proposal', 'proposals') + ' raised' +
      (out.already_known ? ', ' + out.already_known + ' already known' : '') +
      '. ' + out.note);
    $('cap-text').value = '';
    await loadTriage();
  } catch (err) {
    if (caseChanged(token)) {
      banner('Capturing into ' + code + ' failed', failureReason(err));
      return;
    }
    inlineProblem(errBox, err);
  } finally {
    /* The switch reset re-enabled it for the next case. */
    if (!caseChanged(token)) btn.disabled = false;
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
 *  exactly these cases, so preserve the distinction, in words: "not
 *  defined" and not a lone dash (README screenshot review, 2026-09-23). */
function metricNum(v, dp) {
  return (v === null || v === undefined) ? 'not defined' : num(v, dp);
}

/** The cell class for a value the row does not have. A word standing
 *  in for a number takes the quiet `td.absent` style the entity table's
 *  missing dates use, so it does not become the brightest text in a
 *  column of figures (README screenshot review, 2026-09-23). */
function absentClass(v) {
  return v === null || v === undefined || v === '' ? 'absent' : null;
}

function anQuery() {
  const q = projQuery();
  const decay = $('an-decay').value;
  if (decay) q.set('decay_half_life_months', decay);
  return q;
}

/* final review C3, 2026-09-23. No case-switch reset touched this pane, and
 * none of its loaders took a token. openCase nulled state.analytics and
 * left the screen alone, so after NIGHTJAR's Analysis had rendered,
 * KESTREL's Analysis (never analysed: /analytics/latest answers 404, which
 * returns quietly) went on showing NIGHTJAR's ranked, named actors, its
 * brokers and cut vertices under KESTREL's header and TLP chip, and a row
 * click selected a NIGHTJAR id inside KESTREL. A Run still out at the
 * switch was worse: its reply set state.analytics, and loadLatestAnalysis,
 * seeing it set, never asked for KESTREL's own run at all.
 *
 * `state.analyticsGen` numbers what may draw here. A run, a switch, a
 * changed projection and a changed parameter each take a new number, and a
 * reply carrying an older one is dropped, the way graphSeq works for the
 * canvas. The case token is checked beside it because it is the
 * codebase's one test for "this reply is for a case I have left". */
const AN_EMPTY_TEXT = 'Run the analysis to compute brokerage, structural '
  + 'holes, communities and the key-player set over the current projection.';
const AN_HIST_EMPTY_TEXT = 'Pick an actor in the table above to chart it.';

/** Nothing on screen, nothing in flight: the one way this pane is emptied.
 *  The caption and the caveats sit OUTSIDE #an-results, so hiding that
 *  alone left the previous run's projection line and its warnings above a
 *  note saying there was no result. */
function blankAnalytics(note) {
  state.analyticsGen = (state.analyticsGen || 0) + 1;
  state.analytics = null;
  state.analyticsKpp = null;
  show($('an-results'), false);
  show($('an-empty'), true);
  $('an-empty').textContent = note;
  $('an-projection').textContent = '';
  clear($('an-flags'));
  setMsg($('an-status'), '');
}

onCaseSwitch(() => {
  blankAnalytics(AN_EMPTY_TEXT);
  state.analyticsRunning = false;
  $('an-run').disabled = false;
  for (const id of ['an-body', 'an-leads', 'an-kpp', 'an-cohesion', 'an-balance']) {
    clear($(id));
  }
  /* The trend names ONE actor of the case being left. */
  state.analyticsHistory = null;
  state.analyticsHistoryNode = null;
  state.analyticsHistoryLabel = '';
  state.analyticsHistoryGen = (state.analyticsHistoryGen || 0) + 1;
  renderList('an-hist-body', 'an-hist-empty', [], histRow);
  $('an-hist-empty').textContent = AN_HIST_EMPTY_TEXT;
  $('an-hist-who').textContent = '';
  drawHistory();
});

async function runAnalysis() {
  if (!state.caseId) return;
  const btn = $('an-run');
  const token = caseToken();
  const gen = state.analyticsGen = (state.analyticsGen || 0) + 1;
  const stale = () => caseChanged(token) || gen !== state.analyticsGen;
  btn.disabled = true;
  state.analyticsRunning = true;
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
    /* Before anything is kept: this suite belongs to the case and the
       parameters the run started under (C3). */
    if (stale()) return;
    /* De-fang at the boundary. Analytics is the pane that NAMES people —
       "removing these three would disconnect the network" — so a label
       carrying a right-to-left override here renames the person an analyst
       is about to act on. */
    state.analytics = safeLabelsDeep(suite);
    let kpp = null;
    try {
      kpp = await api(cpath('/analytics/key-player?' + kq.toString()));
    } catch (err) {
      kpp = { error: err instanceof ApiError ? err.detail || err.title
                                             : 'the request failed' };
    }
    if (stale()) return;
    state.analyticsKpp = safeLabelsDeep(kpp);
    renderAnalytics();
    /* computed_at_ms is how long the ORIGINAL run took, so on a cache hit
       it describes that run, not this response. Saying "served from cache
       in 24 ms" would claim the cache took 24 ms.

       "unchanged" is a claim about the GRAPH, so it is read from `current`
       -- the API's currency verdict -- and not from `cached`, which since
       2026-09-02 says only that the bytes came out of storage. Both are
       true together on this endpoint, because a suite cache hit is a
       graph-hash match; the distinction matters because `/analytics/latest`
       also answers `cached: true` and answers `current: null`, and a
       renderer keyed on `cached` alone would have printed "unchanged since
       the last run" over a graph that had moved. */
    const ms = (suite.computed_at_ms || 0) + ' ms';
    setMsg($('an-status'), suite.cached
      ? (suite.current === true
          ? 'unchanged since the last run, served from cache (computed in '
            + ms + ')'
          : 'served from cache; currency not checked (computed in ' + ms + ')')
      : 'computed in ' + ms);
  } catch (err) {
    /* A failure for a case or projection the analyst has left says
       nothing about what is on screen now. */
    if (stale()) return;
    blankAnalytics(err instanceof ApiError
      ? (err.detail || err.title)
      : 'The analysis request failed.');
    if (!(err instanceof ApiError) || err.status !== 422) fail(err);
  } finally {
    /* The switch reset re-enables the button for the next case; a run
       left behind must not re-enable it over that case's own run. */
    if (!caseChanged(token)) {
      btn.disabled = false;
      state.analyticsRunning = false;
    }
  }
}

function renderAnalytics() {
  const a = state.analytics;
  if (!a) return;
  show($('an-empty'), false);
  show($('an-results'), true);
  /* The trend canvas is sized on tab entry, and on entry to a case with no
     run #an-results is hidden, so `resizeHistory` found a zero-width box and
     returned. Nothing sized it after Run, and the chart drew into the
     default 300x150 bitmap stretched to the CSS box: a blurred strip with an
     oversized label (README screenshot review, 2026-09-23). Sized here,
     once the box has a width. */
  resizeHistory();

  const p = a.projection || {};
  /* The as-of instant through fmtTime, as every console time is, and the
     counts agreed with their nouns ("1 actors" was possible) (README
     screenshot set review, 2026-09-23). */
  $('an-projection').textContent =
    'Projection: ' + (p.label || p.preset) + ' | confidence >= ' +
    p.min_confidence + ' | inferred ' + (p.include_inferred ? 'in' : 'out') +
    (p.as_of ? ' | as of ' + fmtTime(p.as_of) : '') +
    ' | ' + countOf(a.node_count, 'actor', 'actors') + ', '
    + countOf(a.dyad_count, 'dyad', 'dyads') +
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
      ': degree ' + n.degree + ', brokerage ' +
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
    tr.appendChild(el('td', absentClass(n.effective_size),
      metricNum(n.effective_size, 2)));
    tr.appendChild(el('td', absentClass(n.community),
      n.community === null || n.community === undefined
        ? 'none' : String(n.community)));
    /* Its own control rather than a second meaning for the row click: the
       row already means "show me this actor in the graph", and one gesture
       that does two things is one an analyst learns to distrust. */
    const trend = el('td');
    const trendBtn = el('button', 'btn ghost small', 'Trend');
    trendBtn.type = 'button';
    trendBtn.addEventListener('click', (e) => {
      e.stopPropagation();
      loadMetricHistory(n.id, n.label);
    });
    trend.appendChild(trendBtn);
    tr.appendChild(trend);
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
    td.appendChild(el('span', 'muted', 'not defined'));
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

/* ── metric history ────────────────────────────────────────────────────
 *
 * Phase 3's checklist calls a rising betweenness trend "visible". It has
 * been visible to `curl` since the endpoint was built: nothing in this file
 * called it.
 *
 * Four things this pane must not do, each of which the console has already
 * learned the hard way:
 *
 *  1. It never joins the suite in a `Promise.all`. The suite needs
 *     `analytics.run` and so does this, but a failure here must not blank a
 *     table that already rendered.
 *  2. A 403 is not an empty state. "No history" and "you may not see the
 *     history" are different facts and an analyst acts on them differently.
 *  3. A GAP IS NOT A ZERO — and the harder half of that is what this
 *     CANNOT show. `analytics_runs` skips the row entirely when a metric
 *     is undefined for a node (`if value is None: continue` — the
 *     constraint of an isolate), and `node_metric.value` is NOT NULL. So
 *     an undefined run is not a null in the series, it is ABSENT, and
 *     absent is indistinguishable from "no run happened" at this endpoint.
 *     The line therefore spans it, and the help text says so rather than
 *     letting the reader assume the axis is continuous. The `pen` break
 *     below still guards a null, because a value the client cannot render
 *     must not be drawn as a position — but it is a guard, not the
 *     mechanism, and calling it the mechanism would be the same confident
 *     wrong claim this pane is here to avoid.
 *  4. The series arrives NEWEST FIRST. A left-to-right time axis has to
 *     reverse it, and getting that backwards silently inverts every trend
 *     on screen — rising reads as falling.
 */
const histCanvas = $('an-hist-chart');
const histCtx = histCanvas.getContext('2d');

async function loadMetricHistory(nodeId, label) {
  if (!state.caseId || !nodeId) return;
  /* One actor's trend at a time, and only in the case it was asked in
     (final review C3, 2026-09-23): a reply for the case left behind, or
     for an actor picked before the latest, charted the wrong person. */
  const token = caseToken();
  const gen = state.analyticsHistoryGen = (state.analyticsHistoryGen || 0) + 1;
  const stale = () => caseChanged(token) || gen !== state.analyticsHistoryGen;
  state.analyticsHistoryNode = nodeId;
  state.analyticsHistoryLabel = label || '';
  const metric = $('an-hist-metric').value;
  state.analyticsHistoryMetric = metric;
  $('an-hist-who').textContent = 'loading ' + metric.replace(/_/g, ' ')
    + ' for ' + visibleText(state.analyticsHistoryLabel) + '…';
  try {
    const q = new URLSearchParams({ metric: metric, limit: '50' });
    const body = await api(
      cpath('/analytics/history/' + encodeURIComponent(nodeId))
      + '?' + q.toString());
    if (stale()) return;
    state.analyticsHistory = body;
    renderMetricHistory();
  } catch (err) {
    if (stale()) return;
    /* Own try/catch, own surface. `#an-results`, `#an-status` and the
       actors table are deliberately untouched. */
    state.analyticsHistory = null;
    renderList('an-hist-body', 'an-hist-empty', [], histRow);
    drawHistory();
    $('an-hist-who').textContent = '';
    if (err instanceof ApiError
        && (err.status === 403 || err.status === 404 || err.status === 400)) {
      $('an-hist-empty').textContent = refusalText(
        err, 'Metric history needs analytics.run on this case.');
      return;
    }
    $('an-hist-empty').textContent = refusalText(
      err, 'The trend could not be read. It is not known to be empty.');
  }
}

function renderMetricHistory() {
  const body = state.analyticsHistory;
  const series = (body && body.series) || [];
  renderList('an-hist-body', 'an-hist-empty', series, histRow);
  if (!series.length) {
    /* A legitimate 200 with nothing in it, which is its OWN fact and not
       the refusal above: the actor is visible, the metric is valid, and no
       completed run at this clearance has recorded it. */
    $('an-hist-empty').textContent =
      'No completed run has recorded this metric for this actor at your '
      + 'visibility. A trend needs at least two runs.';
  }
  $('an-hist-who').textContent = series.length
    ? visibleText(state.analyticsHistoryLabel) + ' · '
      + series.length + ' run' + (series.length === 1 ? '' : 's')
    : visibleText(state.analyticsHistoryLabel);
  drawHistory();
}

function histRow(p) {
  const tr = el('tr');
  tr.appendChild(el('td', null, fmtTime(p.at)));
  /* The world time the run measured. Runs at three as-of dates, taken a
     minute apart, read as one minute three times, and a rising value looked
     like noise rather than history (README screenshot set review,
     2026-09-23). A run with no as_of measured the live graph, so its own
     start is the world time it describes. */
  const asOf = (p.params && p.params.as_of) || p.at;
  tr.appendChild(el('td', absentClass(asOf), fmtTime(asOf)));
  const val = el('td', absentClass(p.value), metricNum(p.value, 4));
  if (p.is_approximate) {
    const chip = el('span', 'chip small warn', 'approx');
    chip.title = 'Computed with sampling (betweenness pivots), so this '
               + 'value is an estimate and small movements between two '
               + 'approximate runs may be sampling noise rather than change.';
    val.appendChild(document.createTextNode(' '));
    val.appendChild(chip);
  }
  tr.appendChild(val);
  tr.appendChild(el('td', absentClass(p.rank),
    p.rank === null || p.rank === undefined
      ? 'unranked' : ordinal(p.rank) + ' of ' + (p.node_count || '?')));
  tr.appendChild(el('td', absentClass(p.percentile),
    p.percentile === null || p.percentile === undefined
      ? 'unranked' : 'p' + num(p.percentile, 0)));
  /* The preset is per-point and not per-chart on purpose: weights are not
     comparable across parameters, so two points from different presets are
     two different measurements and the row has to say so. */
  const params = p.params || {};
  const preset = el('td', absentClass(p.preset), p.preset || NO_VALUE);
  if (params.decay_half_life_months) {
    preset.appendChild(el('span', 'muted small',
      '  decay ' + params.decay_half_life_months + 'mo'));
  }
  tr.appendChild(preset);
  return tr;
}

function resizeHistory() {
  const dpr = window.devicePixelRatio || 1;
  const w = histCanvas.clientWidth, h = histCanvas.clientHeight;
  if (!w || !h) return;
  histCanvas.width = Math.round(w * dpr);
  histCanvas.height = Math.round(h * dpr);
  histCtx.setTransform(dpr, 0, 0, dpr, 0, 0);
  drawHistory();
}

/** The trend, drawn rather than styled — same reason as the density strip:
 *  the CSP leaves no inline style to place a point with. */
function drawHistory() {
  const w = histCanvas.clientWidth, h = histCanvas.clientHeight;
  if (!w || !h) return;
  histCtx.clearRect(0, 0, w, h);
  histCtx.fillStyle = PAINT.surface2;
  histCtx.fillRect(0, 0, w, h);

  const baseline = () => {
    histCtx.strokeStyle = PAINT.grid;
    histCtx.lineWidth = 1;
    histCtx.beginPath();
    histCtx.moveTo(0, h - 0.5);
    histCtx.lineTo(w, h - 0.5);
    histCtx.stroke();
  };

  const body = state.analyticsHistory;
  const raw = (body && body.series) || [];
  if (raw.length < 1) { baseline(); return; }

  /* Oldest on the LEFT. The API orders newest first. */
  const pts = raw.slice().reverse();

  const pad = { l: 8, r: 8, t: 10, b: 14 };
  const iw = Math.max(1, w - pad.l - pad.r);
  const ih = Math.max(1, h - pad.t - pad.b);

  const times = pts.map((p) => Date.parse(p.at))
    .filter((t) => Number.isFinite(t));
  const tMin = Math.min.apply(null, times);
  const tMax = Math.max.apply(null, times);
  const defined = pts.filter(
    (p) => typeof p.value === 'number' && Number.isFinite(p.value));
  if (!defined.length) { baseline(); return; }
  const vals = defined.map((p) => p.value);
  let vMin = Math.min.apply(null, vals);
  let vMax = Math.max.apply(null, vals);
  /* A flat series is a real finding — "this actor has not moved" — so it
     draws as a flat line down the middle rather than dividing by zero. */
  if (vMax - vMin < 1e-12) { vMin -= 0.5; vMax += 0.5; }

  const x = (p, i) => {
    if (tMax > tMin) {
      const t = Date.parse(p.at);
      if (Number.isFinite(t)) {
        return pad.l + ((t - tMin) / (tMax - tMin)) * iw;
      }
    }
    return pad.l + (pts.length === 1 ? iw / 2 : (i / (pts.length - 1)) * iw);
  };
  const y = (v) => pad.t + ih - ((v - vMin) / (vMax - vMin)) * ih;

  baseline();

  /* The path. `pen` breaks it if a value is ever unrenderable; see the
     note above for why that is a guard and not gap handling. */
  histCtx.strokeStyle = PAINT.accent;
  histCtx.lineWidth = 2;
  histCtx.beginPath();
  let pen = false;
  pts.forEach((p, i) => {
    const ok = typeof p.value === 'number' && Number.isFinite(p.value);
    if (!ok) { pen = false; return; }
    const px = x(p, i), py = y(p.value);
    if (pen) histCtx.lineTo(px, py); else histCtx.moveTo(px, py);
    pen = true;
  });
  histCtx.stroke();

  /* Points. An approximate run is marked, because two approximate values
     can differ by sampling alone and that must not read as movement. */
  pts.forEach((p, i) => {
    const ok = typeof p.value === 'number' && Number.isFinite(p.value);
    if (!ok) return;
    histCtx.fillStyle = p.is_approximate ? PAINT.alert : PAINT.accent;
    histCtx.beginPath();
    histCtx.arc(x(p, i), y(p.value), p.is_approximate ? 3.5 : 2.5,
                0, Math.PI * 2);
    histCtx.fill();
  });

  /* Ends only. A crowded axis is unreadable at this height, and the table
     below carries every exact value anyway. */
  histCtx.fillStyle = PAINT.dim;
  histCtx.font = PAINT.monoFont || '10px monospace';
  histCtx.textBaseline = 'alphabetic';
  histCtx.textAlign = 'left';
  histCtx.fillText(num(vMax, 3), pad.l, pad.t - 1);
  histCtx.textAlign = 'right';
  histCtx.fillText(num(vMin, 3), w - pad.r, h - 2);
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
  /* "1 communities", and a bracketed plural for the components, were in
     the Analysis capture (README screenshot set review, 2026-09-23). Every
     count here is known, so every noun agrees, "size" with its list too. */
  const sizes = c.component_sizes || [];
  card.appendChild(el('p', null,
    countOf(c.community_count, 'community', 'communities')
    + ' (Leiden, modularity ' + metricNum(c.modularity, 3) + ') across '
    + countOf(c.components, 'connected component', 'connected components')
    + ' of ' + agree(sizes.length, 'size', 'sizes') + ' '
    + sizes.join(', ') + '.'));
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
      (b) => b.source_label + ' and ' + b.target_label).join('; ')));
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
        ? countOf(b.skipped_unsigned_triads, 'triad was', 'triads were')
          + ' skipped because at least one tie carries no valence.'
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
      (d) => d.source_label + ' and ' + d.target_label).join('; ')));
    card.appendChild(el('p', 'muted small',
      'These pairs carry BOTH a positive and a negative tie. That combination '
      + 'is a lead in its own right: a vouch and an accusation between the '
      + 'same two actors usually means a relationship that changed.'));
  }
  box.appendChild(card);
}

/* ── FEEDS and LIFECYCLE (Phases 9, 4, 6) ─────────────────────────────────
 *
 * Two panes over four routers. What they have in common is that everything
 * they show is a QUEUE somebody has to work, and every one of those queues
 * fails the same way: it fills up, nobody can tell what matters, and it
 * stops being read. docs/12 says it outright — "volume is the enemy".
 *
 * So each list leads with the thing that decides whether to look:
 *
 *   ingest queue   → the triage score, and WHY it scored that
 *   dead letters   → the error class, because a run of identical ones is a
 *                    partner changing their schema
 *   sources        → consecutive failures, because a parser that stopped
 *                    matching fails silently
 *   retention      → days remaining, signed, so overdue reads as overdue
 *   break-glass    → how long the grant has been waiting for review
 *
 * Nothing here renders a payload, a fragment or a credential as HTML.
 * Everything is `textContent` through `el()`. Invariant 10's reasoning is
 * about samples, but the argument — attacker-controlled bytes must not be
 * interpreted — applies to every one of these.
 */

/** A subtab group: `.subtabs > .subtab[data-subtab]` over `.subpane`s. */
function initSubtabs(paneId, onSelect) {
  const pane = $(paneId);
  const tabs = Array.from(pane.querySelectorAll('.subtab'));
  const select = (name) => {
    for (const t of tabs) {
      const on = t.dataset.subtab === name;
      t.setAttribute('aria-selected', on ? 'true' : 'false');
      t.tabIndex = on ? 0 : -1;
      show($(t.getAttribute('aria-controls')), on);
    }
    if (onSelect) onSelect(name);
  };
  tabs.forEach((t, i) => {
    t.addEventListener('click', () => select(t.dataset.subtab));
    t.addEventListener('keydown', (e) => {
      let next = null;
      if (e.key === 'ArrowRight') next = tabs[(i + 1) % tabs.length];
      else if (e.key === 'ArrowLeft') next = tabs[(i - 1 + tabs.length) % tabs.length];
      if (next) { e.preventDefault(); next.focus(); select(next.dataset.subtab); }
    });
  });
  return select;
}

/** What to put on screen when a request was refused.
 *
 *  The server's `detail` FIRST, always. Three of the strings in this file
 *  used to assert a role fact instead — "Key administration needs
 *  ingest.manage" — and told the holder of that permission they did not
 *  hold it, because `ingest.manage` is step-up gated and a stale step-up
 *  also 403s. The response said "re-authentication required" and the UI
 *  threw it away in favour of a guess.
 *
 *  The written explanation is kept as context after it: "you need to sign
 *  in again" is actionable, and "this queue exists because a record with
 *  no case cannot be reached by a case assignment" is why the queue is
 *  there at all. Both are worth having; only one of them is a fact about
 *  this caller.
 */
function refusalText(err, context) {
  const said = (err instanceof ApiError && err.detail) ? err.detail : '';
  if (!said) return context;
  if (/re-authentication/i.test(said)) {
    return 'Re-authentication required: your step-up has expired. Sign out '
      + 'and back in to refresh it. ' + context;
  }
  /* The server writes most details as clauses ("missing global permission
     break_glass.review"), and the context after it is a sentence, so the
     two ran together as one: "... break_glass.review The review belongs
     to ..." (README screenshot review, 2026-09-23). A detail that is
     followed by something is closed as a sentence first. */
  const detail = context ? closeClause(said) : said;
  return detail + (context ? ' ' + context : '');
}

/** A server clause as the first sentence of a line: a closing full stop,
 *  and a capital when it opens with an ordinary lower-case word. Unlike
 *  `asSentence` it leaves a first word that is an identifier alone, so
 *  "case.read required" is not printed as "Case.read required". */
function closeClause(text) {
  const t = String(text || '').trim();
  if (!t) return '';
  const stopped = /[.!?:]$/.test(t) ? t : t + '.';
  return /^[a-z]+(\s|$)/.test(stopped)
    ? stopped.charAt(0).toUpperCase() + stopped.slice(1) : stopped;
}

/** Signed days from now. Negative reads as overdue, which is the point. */
function daysFromNow(iso) {
  if (!iso) return null;
  return Math.round((new Date(iso) - Date.now()) / 86400000);
}

/** A deadline as days from now. A missing one is a deadline nobody set,
 *  so it says that rather than printing a dash (README screenshot
 *  review, 2026-09-23). */
function whenText(iso) {
  if (!iso) return 'not set';
  const d = daysFromNow(iso);
  if (d === null) return 'not set';
  if (d < 0) return Math.abs(d) + 'd overdue';
  if (d === 0) return 'today';
  return 'in ' + d + 'd';
}

/** A labelled key/value pair on a row. */
function fact(label, value, cls) {
  const wrap = el('span', 'fact' + (cls ? ' ' + cls : ''));
  wrap.appendChild(el('span', 'fact-k', label));
  wrap.appendChild(el('span', 'fact-v', value === null || value === undefined
    ? NO_VALUE : String(value)));
  return wrap;
}

function labelChips(row) {
  const chips = el('span', 'chips');
  if (row.classification) {
    chips.appendChild(
      el('span', 'chip tlp-' + row.classification, row.classification));
  }
  for (const c of row.compartments || []) {
    chips.appendChild(el('span', 'chip compartment', c));
  }
  return chips;
}

/** Render a list, or show its empty state. Returns whether anything drew. */
function renderList(listId, emptyId, rows, build) {
  const box = $(listId);
  clear(box);
  /* A render is an answer, so any "could not be loaded" notice from an
     earlier failed read goes (ux17-failure, 2026-09-22). */
  clearLoadFailure(emptyId);
  for (const row of rows) box.appendChild(build(row));
  show($(emptyId), rows.length === 0);
  return rows.length > 0;
}

/* --- ingest queue ------------------------------------------------------ */

/* The queue is filtered to ONE case (`case_id` below), so it goes on the
   switch like the other case-scoped lists (ux17-failure:stale-previous-
   case-data, 2026-09-22). The empty text returns to its markup wording in
   case the previous case left a refusal in it. */
onCaseSwitch(() => {
  clear($('ing-list'));
  $('ing-counts').textContent = '';
  $('ing-empty').textContent = 'Nothing in the queue for this case.';
  show($('ing-empty'), false);
  clearLoadFailure('ing-empty');
});

async function loadIngestQueue() {
  if (!state.caseId) return;
  const params = new URLSearchParams({ case_id: state.caseId, limit: '100' });
  if ($('ing-category').value) params.set('category', $('ing-category').value);
  if ($('ing-dupes').checked) params.set('include_duplicates', 'true');
  const token = caseToken();
  try {
    const body = await api('/ingest/records?' + params.toString());
    if (caseChanged(token)) return;
    renderList('ing-list', 'ing-empty', body.records, ingestRow);
    $('ing-counts').textContent = body.count
      ? body.count + ' record' + (body.count === 1 ? '' : 's') : '';
    /* Categories are populated FROM the data rather than from a fixed list:
       a category the classifier emits and the filter cannot select is a
       filter that lies. */
    const seen = new Set(body.records.map((r) => r.category));
    const sel = $('ing-category');
    const keep = sel.value;
    if (seen.size) {
      clear(sel);
      sel.appendChild(Object.assign(el('option', null, 'All'), { value: '' }));
      for (const c of Array.from(seen).sort()) {
        sel.appendChild(Object.assign(el('option', null, c), { value: c }));
      }
      sel.value = keep;
    }
  } catch (err) {
    /* 403 is not a fault: most roles do not hold `ingest.read`, and a
       banner on every tab open would train people to dismiss banners. */
    if (caseChanged(token)) return;
    if (err instanceof ApiError && err.status === 403) {
      renderList('ing-list', 'ing-empty', [], ingestRow);
      $('ing-empty').textContent = refusalText(
        err, 'Reading a case queue needs ingest.read on this case.');
      return;
    }
    /* Not "Nothing in the queue for this case." (ux17-failure). */
    renderList('ing-list', 'ing-empty', [], ingestRow);
    $('ing-counts').textContent = '';
    showLoadFailure('ing-empty', "This case's ingest queue", err,
      loadIngestQueue);
    fail(err);
  }
  /* Probed ONCE per session, not on every queue load. `ingest.manage` is
     SYS_ADMIN-only, so for every other role this 403s — and deps.py writes
     an AUTHZ_DENIED audit row BEFORE raising. Invariant 6 makes that row
     permanent, and AUTHZ_DENIED is the signal a security officer watches
     for probing: a continuous hum generated by ordinary tab-switching is
     how that signal stops being read. It also spent a search-metered
     request on a response the pane discarded. */
  if (state.quarantineVisible !== false) loadQuarantine();
}

function ingestRow(r) {
  const card = el('div', 'card row-card');
  const head = el('div', 'row-head');
  const score = el('span', 'score' + (r.priority >= 10 ? ' hot' : ''),
    r.priority.toFixed(1));
  score.title = 'Triage score. The watched-selector term dominates on '
    + 'purpose: a hit should surface in seconds and a generic combo list '
    + 'should sink.';
  head.appendChild(score);
  head.appendChild(el('span', 'row-title', r.category));
  head.appendChild(labelChips(r));
  card.appendChild(head);

  const facts = el('div', 'facts');
  facts.appendChild(fact('confidence',
    (r.category_confidence * 100).toFixed(0) + '% ' + r.category_source));
  facts.appendChild(fact('feed', r.feed));
  facts.appendChild(fact('received', fmtTime(r.received_at)));
  facts.appendChild(fact('expires', whenText(r.retain_until),
    daysFromNow(r.retain_until) < 0 ? 'bad' : ''));
  if (r.credential_count) {
    facts.appendChild(fact('credentials', r.credential_count, 'warn'));
  }
  if (r.duplicate_count) {
    const f = fact('also sent by', r.duplicate_count + ' other');
    f.title = 'Folded, not dropped. The same leak post from nine sources is '
      + 'what near-duplicate suppression exists for.';
    facts.appendChild(f);
  }
  if (r.is_duplicate) facts.appendChild(fact('', 'folded duplicate', 'muted'));
  card.appendChild(facts);

  /* WHY it scored what it scored. A score with no reason is a number an
     analyst learns to ignore. */
  const why = r.priority_detail || {};
  if (why.watched_selector_hits) {
    card.appendChild(el('p', 'why',
      why.watched_selector_hits + ' watched selector hit'
      + (why.watched_selector_hits === 1 ? '' : 's')));
  }

  const actions = el('div', 'row-actions');
  const rescore = el('button', 'btn small', 'Rescore');
  rescore.type = 'button';
  rescore.title = 'The score depends on watch selectors, which change. A '
    + 'record ingested before a selector was added scored zero against it.';
  rescore.addEventListener('click', async () => {
    try {
      await api('/ingest/records/' + r.id + '/score', { method: 'POST' });
      loadIngestQueue();
    } catch (err) { fail(err); }
  });
  actions.appendChild(rescore);

  if (r.credential_count) {
    const creds = el('button', 'btn small', 'Credentials (masked)');
    creds.type = 'button';
    creds.addEventListener('click', () => showCredentials(r, card));
    actions.appendChild(creds);
  }
  card.appendChild(actions);
  return card;
}

/** The masked view. **Never a value** — that is a separate, audited act
 *  requiring a live authorisation, and it is not a button on a queue. */
async function showCredentials(record, card) {
  let box = card.querySelector('.cred-box');
  if (box) { box.remove(); return; }
  box = el('div', 'cred-box');
  card.appendChild(box);
  try {
    const body = await api('/ingest/records/' + record.id + '/credentials');
    box.appendChild(el('p', 'help', body.notice || ''));
    for (const c of body.credentials) {
      const line = el('div', 'facts');
      line.appendChild(fact('kind', c.kind));
      line.appendChild(fact('service', c.service_domain));
      line.appendChild(fact('captured', fmtDate(c.captured_at)));
      line.appendChild(fact('value held', c.value_held ? 'yes' : 'not retained'));
      if (c.reveal_count) line.appendChild(fact('revealed', c.reveal_count, 'warn'));
      box.appendChild(line);
    }
    if (!body.credentials.length) {
      box.appendChild(el('p', 'empty', 'No credentials on this record.'));
    }
  } catch (err) {
    box.appendChild(el('p', 'form-error',
      err instanceof ApiError ? (err.detail || err.title) : String(err)));
  }
}

async function loadQuarantine() {
  const box = $('ing-quarantine-box');
  try {
    const body = await api('/ingest/quarantine?limit=50');
    show(box, true);
    renderList('ing-quarantine-list', 'ing-quarantine-empty',
      body.records, ingestRow);
  } catch (err) {
    /* Latch ONLY on the refusal this was written for.
       `ingest.manage` is SYS_ADMIN-only, so for every other role this 403s
       for the whole session, and re-probing would hum AUTHZ_DENIED into the
       one signal a security officer reads for probing. That is a DURABLE
       fact about the caller, so remembering it is right.

       Nothing else is durable. The predicate used to be "anything that is
       not a step-up expiry", which swept in a network drop (ApiError with
       status 0), a 502, a 503 and a 429 — one blip and the section was gone
       for the rest of the session, with `show(box, false)` as the only
       trace. That reports a transport failure as a permission fact, and it
       reports it by making the evidence disappear. */
    if (err instanceof ApiError && err.status === 403) {
      show(box, false);
      state.quarantineVisible = false;
      return;
    }
    /* A step-up expiry is recoverable and stays unlatched, as before. */
    const stepUp = err instanceof ApiError
      && /re-authentication/i.test(err.detail || '');
    if (stepUp) {
      show(box, false);
      return;
    }
    /* Everything else: the caller may well hold the permission and we do
       not know what is in there. Say so rather than hiding it — an empty
       section reads as "nothing unattached", which is a claim about the
       data we are in no position to make. */
    show(box, true);
    renderList('ing-quarantine-list', 'ing-quarantine-empty', [], ingestRow);
    $('ing-quarantine-empty').textContent = refusalText(
      err, 'The unattached queue could not be read. It is not known to be '
      + 'empty. Reopen this tab to retry.');
  }
}

/* --- dead letters ------------------------------------------------------ */

async function loadDeadLetters() {
  try {
    const body = await api('/ingest/dead-letters?limit=100');
    renderList('dl-list', 'dl-empty', body.dead_letters, deadLetterRow);
    $('dl-counts').textContent = body.count
      ? body.count + ' unparsed fragment' + (body.count === 1 ? '' : 's') : '';
  } catch (err) {
    if (err instanceof ApiError && err.status === 403) {
      renderList('dl-list', 'dl-empty', [], deadLetterRow);
      /* Either verb opens the listing since 2026-09-09: ingest.read for the
         caller's own scope, ingest.manage for the quarantine rows too. */
      $('dl-empty').textContent = refusalText(err,
        'This needs ingest.read, or ingest.manage for the quarantine.');
      return;
    }
    /* A failed read left the last list standing, or "Nothing has failed
       to parse." (ux17-failure, 2026-09-22). */
    renderList('dl-list', 'dl-empty', [], deadLetterRow);
    $('dl-counts').textContent = '';
    showLoadFailure('dl-empty', 'The dead-letter list', err, loadDeadLetters);
    fail(err);
  }
}

function deadLetterRow(d) {
  const card = el('div', 'card row-card');
  const head = el('div', 'row-head');
  head.appendChild(el('span', 'row-title', d.error_class));
  if (d.classification) {
    head.appendChild(
      el('span', 'chip tlp-' + d.classification, d.classification));
  }
  if (d.replayed_at) head.appendChild(el('span', 'chip ok', 'replayed'));
  card.appendChild(head);

  const facts = el('div', 'facts');
  facts.appendChild(fact('when', fmtTime(d.occurred_at)));
  facts.appendChild(fact('expires', whenText(d.retain_until)));
  card.appendChild(facts);

  if (d.error_detail) card.appendChild(el('p', 'why', d.error_detail));

  if (d.fragment_withheld) {
    card.appendChild(el('p', 'help warn',
      'Recorded before the redactor existed, so this fragment is verbatim '
      + 'and is withheld. scripts/redact_dead_letters.py --apply is the '
      + 'repair.'));
  } else if (d.fragment) {
    /* textContent, never innerHTML: this is attacker-supplied input that
       failed to parse, which is the least trustworthy string in the system.
       `visibleText` on top, because textContent stops it EXECUTING and
       does nothing about it LYING — a bidi override reorders the fragment
       on screen, and the whole reason to show a fragment is that somebody
       reads it to work out what the feed sent. */
    const pre = el('pre', 'fragment mono-sm', visibleText(d.fragment));
    pre.title = 'Structurally redacted: keys, types and lengths only.';
    card.appendChild(pre);
  }
  return card;
}

/* --- collection sources ------------------------------------------------ */

/** One section of a tab, loaded independently.
 *
 *  Independently is the point. These four sections need three different
 *  permissions — `collection.read` for sources and runs,
 *  `collection_account.manage` for personas — and gathering them with
 *  `Promise.all` meant the FIRST 403 rejected the lot: a CASE_OWNER, who
 *  holds `collection.read`, saw an empty Sources tab claiming they did
 *  not, because personas (which they genuinely may not see) failed first.
 *
 *  A section the caller may not read says so where that section is,
 *  rather than blanking its neighbours.
 */
async function section(path, listId, emptyId, pick, build, missing, retry) {
  try {
    const body = await api(path);
    renderList(listId, emptyId, pick(body) || [], build);
    return body;
  } catch (err) {
    renderList(listId, emptyId, [], build);
    if (err instanceof ApiError && (err.status === 403 || err.status === 404)) {
      $(emptyId).textContent = refusalText(err, missing);
    } else {
      /* The shared notice rather than the error written INTO the empty
         element: written there, it outlived the failure and captioned the
         next genuinely empty read (ux17-failure, 2026-09-22). */
      showLoadFailure(emptyId, 'This list', err, retry);
    }
    return null;
  }
}

async function loadSources() {
  const [unhealthy, due] = await Promise.all([
    section('/collection/sources/unhealthy', 'src-unhealthy',
      'src-unhealthy-empty', (b) => b.sources, unhealthyRow,
      'Source health needs collection.read.', loadSources)
      .then((body) => {
        /* Same response, second list. Never-polled is not an alert and
           must not pad one. When that response did not arrive the list is
           unknown: this used to render from `[]` and announce "Every
           source has been polled." (ux17-failure, 2026-09-22). */
        if (!body) {
          renderList('src-never', 'src-never-empty', [], neverPolledRow);
          showLoadFailure('src-never-empty', 'The never-polled list',
            new Error('it comes with the source-health read, which failed'),
            loadSources);
          return body;
        }
        renderList('src-never', 'src-never-empty',
          body.never_polled || [], neverPolledRow);
        return body;
      }),
    section('/collection/sources/due', 'src-due', 'src-due-empty',
      (b) => b.due, dueRow, 'The poll schedule needs collection.read.',
      loadSources),
    section('/collection/personas', 'src-personas', 'src-personas-empty',
      (b) => b.personas, personaRow,
      'Personas belong to the collector role. Credentials never leave the '
      + 'vault (invariant 7), and neither does the roster.', loadSources),
    section('/collection/runs?limit=25', 'src-runs', 'src-runs-empty',
      (b) => b.runs, runRow, 'Run history needs collection.read.',
      loadSources),
  ]);
  $('src-counts').textContent = (due && unhealthy)
    ? ((due.due || []).length + ' due · '
       + (unhealthy.sources || []).length + ' unhealthy')
    : '';
}

function unhealthyRow(s) {
  const card = el('div', 'card row-card');
  const head = el('div', 'row-head');
  head.appendChild(el('span', 'row-title', s.name));
  head.appendChild(el('span', 'chip bad', s.health));
  card.appendChild(head);
  const facts = el('div', 'facts');
  facts.appendChild(fact('consecutive failures', s.consecutive_failures, 'bad'));
  facts.appendChild(fact('last ok', s.last_ok_at ? fmtTime(s.last_ok_at) : 'never'));
  card.appendChild(facts);
  if (s.note) card.appendChild(el('p', 'why', s.note));
  return card;
}

function neverPolledRow(s) {
  const card = el('div', 'card row-card compact');
  const head = el('div', 'row-head');
  head.appendChild(el('span', 'row-title', s.name));
  head.appendChild(el('span', 'chip', s.kind));
  card.appendChild(head);
  const facts = el('div', 'facts');
  facts.appendChild(fact('added', fmtDate(s.created_at)));
  card.appendChild(facts);
  return card;
}

function dueRow(s) {
  const card = el('div', 'card row-card');
  const head = el('div', 'row-head');
  head.appendChild(el('span', 'row-title', s.name));
  head.appendChild(el('span', 'chip', s.kind));
  if (s.health && s.health !== 'OK') {
    head.appendChild(el('span', 'chip bad', s.health));
  }
  card.appendChild(head);
  const facts = el('div', 'facts');
  facts.appendChild(fact('due', fmtTime(s.due_at)));
  facts.appendChild(fact('max rps', s.max_rps));
  facts.appendChild(fact('parser', s.parser_key));
  card.appendChild(facts);

  const actions = el('div', 'row-actions');
  const run = el('button', 'btn small', 'Poll now');
  run.type = 'button';
  run.addEventListener('click', async () => {
    run.disabled = true;
    try {
      const body = await api('/collection/sources/' + s.id + '/run',
        { method: 'POST', json: {} });
      card.appendChild(el('p', body.error ? 'form-error' : 'form-ok',
        body.error || (body.items_new + ' new of ' + body.items_seen + ' seen')));
      /* A poll can succeed and still not have done everything it was asked
         to. A watch whose regex will not compile matches nothing, for
         ever, and reads exactly like a watch that has not fired — so the
         one moment somebody is looking at this source is the moment to
         say so. */
      for (const w of (body.warnings || [])) {
        card.appendChild(el('p', 'why bad', w));
      }
      loadSources();
    } catch (err) { fail(err); } finally { run.disabled = false; }
  });
  actions.appendChild(run);
  card.appendChild(actions);
  return card;
}

function personaRow(p) {
  const card = el('div', 'card row-card');
  const head = el('div', 'row-head');
  head.appendChild(el('span', 'row-title', p.handle || p.name || p.id));
  const cls = p.status === 'BURNED' ? 'bad'
    : (p.status === 'HEALTHY' ? 'ok' : 'warn');
  head.appendChild(el('span', 'chip ' + cls, p.status));
  card.appendChild(head);
  const facts = el('div', 'facts');
  if (p.platform) facts.appendChild(fact('platform', p.platform));
  facts.appendChild(fact('last used',
    p.last_used_at ? fmtTime(p.last_used_at) : 'never'));
  if (p.cooldown_until) {
    facts.appendChild(fact('cooling until', fmtTime(p.cooldown_until), 'warn'));
  }
  card.appendChild(facts);
  if (p.status === 'BURNED') {
    card.appendChild(el('p', 'why',
      'Terminal. Re-using a persona a forum admin has already flagged is how '
      + 'you burn the next one too.'));
  }
  return card;
}

function runRow(r) {
  const card = el('div', 'card row-card compact');
  const head = el('div', 'row-head');
  head.appendChild(el('span', 'row-title', r.source_name || r.source_id));
  /* PARTIAL is neither. The run fetched and stored everything it found
     and could not evaluate something — a dead watch pattern. Painting it
     'bad' alongside genuine failures buries it; painting it 'ok' is what
     the code did before PARTIAL was ever written, and is how a dead watch
     stayed invisible. `error_detail` below carries the reason. */
  head.appendChild(el('span', 'chip ' + (
    r.status === 'OK' ? 'ok' : r.status === 'PARTIAL' ? 'warn' : 'bad'),
    r.status));
  card.appendChild(head);
  const facts = el('div', 'facts');
  facts.appendChild(fact('started', fmtTime(r.started_at)));
  if (r.items_seen !== undefined) {
    facts.appendChild(fact('items', r.items_new + ' new / ' + r.items_seen));
  }
  card.appendChild(facts);
  if (r.error_detail) card.appendChild(el('p', 'why', r.error_detail));
  return card;
}

/* --- ingest keys ------------------------------------------------------- */

async function loadKeys() {
  const params = $('key-revoked').checked ? '?include_revoked=true' : '';
  try {
    const body = await api('/ingest/keys' + params);
    renderList('key-list', 'key-empty', body.keys, keyRow);
    $('key-counts').textContent = body.count + ' key'
      + (body.count === 1 ? '' : 's');
  } catch (err) {
    if (err instanceof ApiError && err.status === 403) {
      renderList('key-list', 'key-empty', [], keyRow);
      $('key-empty').textContent = refusalText(
        err,
        'Key administration needs ingest.manage, because which feeds exist and what '
        + 'they are cleared for is operational intelligence about the '
        + 'deployment.');
      return;
    }
    /* The previous list is not this read's answer (ux17-failure:stale-
       previous-case-data, 2026-09-22). */
    renderList('key-list', 'key-empty', [], keyRow);
    $('key-counts').textContent = '';
    showLoadFailure('key-empty', 'The ingest keys', err, loadKeys);
    fail(err);
  }
}

function keyRow(k) {
  const card = el('div', 'card row-card');
  const head = el('div', 'row-head');
  head.appendChild(el('span', 'row-title', k.name));
  head.appendChild(el('span', 'chip', k.environment));
  head.appendChild(el('span', 'chip tlp-' + k.classification_ceiling,
    k.classification_ceiling));
  if (k.forced_compartment) {
    head.appendChild(el('span', 'chip compartment', k.forced_compartment));
  }
  if (k.revoked_at) head.appendChild(el('span', 'chip bad', 'revoked'));
  else if (k.expired) head.appendChild(el('span', 'chip bad', 'expired'));
  card.appendChild(head);

  const facts = el('div', 'facts');
  facts.appendChild(fact('key id', k.key_id));
  facts.appendChild(fact('category', k.declared_category));
  facts.appendChild(fact('batches', k.batch_count));
  facts.appendChild(fact('expires', whenText(k.expires_at),
    k.expired ? 'bad' : ''));
  /* The column that matters. docs/12: a key unused for thirty days is
     either a dead integration or somebody else's. */
  const stale = k.stale_days === null || k.stale_days === undefined;
  facts.appendChild(fact('last used', stale ? 'never' : k.stale_days + 'd ago',
    (stale || k.stale_days > 30) ? 'warn' : ''));
  card.appendChild(facts);

  if (k.revoked_reason) card.appendChild(el('p', 'why', k.revoked_reason));
  else if (stale || k.stale_days > 30) {
    card.appendChild(el('p', 'why',
      'Unused for over thirty days, so it is either a dead '
      + 'integration or somebody else’s.'));
  }
  return card;
}

/* --- the custody chain -------------------------------------------------
 *
 * `core.evidence_custody` is the second tamper-evident ledger, hash-chained
 * by migration 0024 under a docstring that invokes FRE 902(13)-(14). Until
 * 2026-09-02 nothing recomputed it: the record actually produced to a court
 * was the one nobody verified, while `audit.event` -- an internal log -- had
 * both a verifier and a CI step.
 *
 * It is ONE chain across every exhibit, so `evidence_id` narrows what is
 * REPORTED and not what is checked. The server sends that sentence in
 * `caveat` and this renders it verbatim rather than paraphrasing: a scoped
 * pass that reads like a completeness pass is precisely the wrong answer to
 * "has anything been removed from this exhibit's history".
 */
function wireCustodyVerify() {
  const btn = $('btn-custody-verify');
  if (!btn) return;
  btn.addEventListener('click', async () => {
    const box = $('custody-verdict');
    const scope = $('custody-evidence-id').value.trim();
    clear(box);
    btn.disabled = true;
    box.appendChild(el('p', 'help', 'recomputing…'));
    let r;
    try {
      r = await api('/audit/custody/verify'
        + (scope ? '?evidence_id=' + encodeURIComponent(scope) : ''));
    } catch (err) {
      clear(box);
      /* Same treatment as the audit verdict: a 403 is the expected answer
         for most accounts, and `refusalText` puts the SERVER's reason first
         so an inactive account is not told it lacks a permission it holds. */
      if (err instanceof ApiError && err.status === 403) {
        box.appendChild(el('p', 'help warn', refusalText(err,
          'audit.read is granted to SECURITY_OFFICER alone: the '
          + 'administrator configures, the officer audits.')));
      } else if (err instanceof ApiError && err.status === 422) {
        box.appendChild(el('p', 'help warn', refusalText(err,
          'That is not a valid exhibit id.')));
      } else { fail(err); }
      btn.disabled = false;
      return;
    }
    btn.disabled = false;
    clear(box);
    box.appendChild(custodyVerdict(r));
  });
}

/** Render one custody report.
 *
 *  `intact && checked > 0`, exactly as the audit verdict computes it: an
 *  exhibit with no custody rows answers "intact, 0 checked", and a green
 *  tick on that would report an absence of history as a clean history.
 *
 *  Forks and the genesis count are NOT folded into the verdict chip. The
 *  server keeps them separate because they mean different things -- a fork
 *  means the chain cannot be linearised, a second genesis row means the
 *  trigger was bypassed -- and flattening them here would undo that.
 */
function custodyVerdict(r) {
  const ok = r.intact && r.checked > 0;
  const card = el('div', 'card');
  card.appendChild(el('span', 'chip ' + (ok ? 'good' : 'bad'),
    r.checked === 0 ? 'NOTHING TO CHECK' : (r.intact ? 'INTACT' : 'BROKEN')));
  const span = (r.first_id === null || r.first_id === undefined)
    ? '' : ' · id ' + r.first_id + ' to ' + r.last_id;
  card.appendChild(el('p', 'help',
    r.checked.toLocaleString() + ' custody '
    + agree(r.checked, 'row', 'rows') + ' checked' + span
    + (r.scoped ? ' · scoped to one exhibit' : ' · whole ledger')));
  if (r.caveat) card.appendChild(el('p', 'help warn', r.caveat));
  if (r.forks) {
    card.appendChild(el('p', 'help warn',
      countOf(r.forks, 'fork', 'forks') + '. ' + (r.fork_note || '')));
  }
  card.appendChild(el('p', 'help', 'Genesis rows: ' + r.genesis_count
    + (r.genesis_count === 1 ? ' (the chain is anchored).' : '')));
  if (r.genesis_note) card.appendChild(el('p', 'help warn', r.genesis_note));
  return card;
}

/* --- confirming a retention rule ---------------------------------------
 *
 * The point of a confirmation is not the number, it is that somebody's id
 * is attached to it: an unconfirmed rule is a period the build chose, and
 * it becomes policy by default if nobody ever looks. The console listed
 * the unconfirmed ones and offered no way to confirm one.
 */
function wireRetentionConfirm() {
  const form = $('ret-confirm');
  if (!form) return;
  $('ret-cat').addEventListener('change', () => syncRuleForm(true));
  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    const msg = $('ret-confirm-msg');
    const cat = $('ret-cat').value;
    const days = parseInt($('ret-days').value, 10);
    const why = $('ret-rationale').value.trim();
    /* Checked here as well as at the server, because the server's 422 is
       about a request body the analyst never sees -- it names a field, not
       the box they typed in. */
    if (!cat) { setMsg(msg, 'Pick a category.'); return; }
    if (!(days > 0)) {
      setMsg(msg, 'A retention period has to be at least one day.'); return;
    }
    if (why.length < 10) {
      setMsg(msg, 'The rationale has to answer "why this period" to '
        + 'somebody who was not in the room: at least 10 characters.');
      return;
    }
    /* Replacing a colleague's confirmed decision is its own step. The
       upsert overwrote one silently and the form never said whose it was
       (ux15 rule-confirm-misstates-effect, 2026-09-22). */
    const current = retRules.get(cat);
    if (current && !current.is_placeholder && !window.confirm(
        'Replace the confirmed period for ' + cat + '?\n\n'
        + (current.confirmed_by_name || 'A colleague') + ' confirmed '
        + dayCount(current.retain_days)
        + (current.confirmed_at ? ' on ' + fmtTime(current.confirmed_at) : '')
        + '. Your ' + dayCount(days) + ' replaces that decision, with your '
        + 'name on it, for every case in the deployment. Records already on '
        + 'file keep the deadline they were stamped with.')) {
      return;
    }
    const btn = $('ret-confirm-btn');
    btn.disabled = true;
    setMsg(msg, 'saving…');
    let body;
    try {
      body = await api('/retention/rules/' + encodeURIComponent(cat),
        { method: 'POST', json: { retain_days: days, rationale: why } });
    } catch (err) {
      btn.disabled = false;
      setMsg(msg, refusalText(err,
        'Confirming a rule needs retention.manage and a step-up session.'));
      return;
    }
    btn.disabled = false;
    /* The server's sentence, because it is the one that knows how many
       records the new period does NOT reach. "Now retains for N days" was
       true of the rule row and false of every record already ingested,
       which keeps the deadline it was stamped with at arrival. */
    setMsg(msg, 'Confirmed against your name. ' + (body.notice || ''));
    $('ret-rationale').value = '';
    await loadRetention();
  });
}

/** "1 day", "730 days": a retention period whose count is known. */
function dayCount(n) {
  return countOf(n, 'day', 'days');
}

/** A count and its noun in agreement: "1 item of evidence", "3 items of
 *  evidence". The number is known when the line is written, so hedging
 *  with "item(s)" only makes the reader do the agreement (README
 *  screenshot review, 2026-09-23). */
function countOf(n, one, many) {
  return n + ' ' + (Number(n) === 1 ? one : many);
}

/** The word alone, chosen by the count as countOf chooses it: for a verb
 *  ("1 check needs", "3 checks need"), or for a noun whose count is
 *  printed some other way (grouped by toLocaleString, where "1.000" would
 *  read as one). countOf keeps its own copy of the rule because tests run
 *  it standalone (README screenshot set review, 2026-09-23). */
function agree(n, one, many) {
  return Number(n) === 1 ? one : many;
}

/** Rules by category, as last loaded: the form reads the current period
 *  and whose confirmation it would replace from here. */
let retRules = new Map();

/** Fill the category picker from the rules actually loaded.
 *
 *  Not a fixed list: the categories come from `core.retention_rule`, and a
 *  picker that offered a category the deployment does not have would send
 *  a confirmation the server has nothing to attach to. Unconfirmed ones
 *  are marked, because they are the ones that need the attention.
 */
function fillRetentionCategories(rules) {
  const sel = $('ret-cat');
  if (!sel) return;
  const keep = sel.value;
  retRules = new Map(rules.map((r) => [r.category, r]));
  opts(sel, rules.map((r) => [r.category,
    r.category + (r.is_placeholder ? ' (unconfirmed)' : ' (confirmed)')]), keep);
  syncRuleForm(false);
}

/** Prefill the period in force and say whose decision the form replaces.
 *
 *  The days box started empty, so the form never said what was in force,
 *  and a category a colleague had confirmed looked exactly like one nobody
 *  had (ux15, 2026-09-22). `force` on a category change; on a reload only
 *  an empty box is filled, so a number being typed is not overwritten. */
function syncRuleForm(force) {
  const cat = $('ret-cat').value;
  const r = retRules.get(cat);
  const note = $('ret-cat-state');
  if (!r) { note.textContent = ''; return; }
  if (force || !$('ret-days').value) $('ret-days').value = String(r.retain_days);
  /* "730 day(s)" was on screen in the README capture; the count is known,
     so the word is chosen (README screenshot review, 2026-09-23). */
  note.textContent = r.is_placeholder
    ? cat + ' runs on ' + dayCount(r.retain_days) + ', a placeholder shipped '
      + 'with the build that nobody has confirmed.'
    : cat + ' was confirmed at ' + dayCount(r.retain_days) + ' by '
      + (r.confirmed_by_name || 'an account no longer listed')
      + (r.confirmed_at ? ' on ' + fmtTime(r.confirmed_at) : '')
      + '. Confirming again replaces their decision.';
}

/* --- the delivery ledger ------------------------------------------------
 *
 * `notify.delivery` has recorded every refusal with a reason since 0029 and
 * every destination since 0044, and nothing rendered it: the one table that
 * answers "did the summary leave the building, and where did it go" was
 * write-only.
 */
function wireDeliveries() {
  const btn = $('dlv-reload');
  if (!btn) return;
  btn.addEventListener('click', () => loadDeliveries());
  $('dlv-refused').addEventListener('change', () => loadDeliveries());
}

async function loadDeliveries() {
  const q = new URLSearchParams({ limit: '100' });
  const kind = $('dlv-kind').value.trim();
  if (kind) q.set('kind', kind);
  if ($('dlv-refused').checked) q.set('refused_only', 'true');
  try {
    const body = await api('/notifications/deliveries?' + q.toString());
    renderList('dlv-list', 'dlv-empty', body.deliveries, deliveryRow);
    if (!body.deliveries.length) {
      $('dlv-empty').textContent = $('dlv-refused').checked
        ? 'Nothing was refused, failed or revoked.'
        : 'Nothing has been sent yet.';
    }
  } catch (err) {
    clear($('dlv-list'));
    const empty = $('dlv-empty');
    show(empty, true);
    /* The empty line carries the refusal, rather than a banner: "no
       deliveries" and "you may not read the ledger" are different facts and
       an empty list must never stand in for the second. */
    empty.textContent = refusalText(err,
      'The delivery ledger needs integration.manage.');
  }
}

/** One delivery attempt.
 *
 *  SUPPRESSED is deliberately not styled as a failure. Two different things
 *  write it: the recipient's own channel preference (no attempt timestamp),
 *  and a clearance or assignment revoked after queueing -- which IS an
 *  absence somebody should see. The attempt time tells them apart, so it is
 *  shown rather than summarised away.
 */
function deliveryRow(d) {
  const card = el('div', 'card row-card compact');
  const head = el('div', 'row-head');
  head.appendChild(el('span', 'row-title', d.kind));
  const bad = d.outcome === 'REFUSED' || d.outcome === 'FAILED';
  head.appendChild(el('span', 'chip ' + (bad ? 'bad'
    : (d.outcome === 'SENT' ? 'good' : 'subtle')), d.outcome));
  head.appendChild(el('span', 'chip subtle', d.channel));
  if (d.redacted) head.appendChild(el('span', 'chip warn', 'redacted'));
  card.appendChild(head);
  const facts = el('div', 'facts');
  if (d.recipient) facts.appendChild(el('span', 'muted small', d.recipient));
  /* The address is the whole point of the ledger -- "where did it go" -- and
     it is already the server's redacted form where redaction applied. */
  if (d.address) facts.appendChild(el('span', 'mono small', d.address));
  if (d.attempts) {
    facts.appendChild(el('span', 'muted small',
      countOf(d.attempts, 'attempt', 'attempts')));
  }
  /* Through fmtTime like the console's other times, so it says UTC: the
     subtab appended the raw ISO string (README screenshot set review,
     2026-09-23). */
  const when = d.attempted_at || d.raised_at;
  if (when) facts.appendChild(el('span', 'muted small', fmtTime(when)));
  card.appendChild(facts);
  if (d.reason) card.appendChild(el('p', 'why', d.reason));
  return card;
}

/* --- the readiness register --------------------------------------------
 *
 * docs/16's code-side half, in one request. Each line is a claim about THIS
 * deployment with its evidence beside it, and a failed check carries the
 * action that closes it -- an "action" on a passing check would be noise,
 * so the server sends none and this renders none.
 *
 * Four of the checks carry `blocking: true` (readiness.BLOCKING_CHECKS) and
 * the collection run route refuses while any of them fails. Until
 * 2026-09-10 this pane rendered all of them identically, which made the
 * register a list rather than a control: an operator could read "4 of 11
 * check(s) need attention", learn nothing about which four stopped the
 * product from being usable, and close the tab. The failing blockers now
 * get a banner above the list, with each one's own evidence and action,
 * and it has no dismiss control.
 *
 * The report is deliberately NOT kept on `state`. It was for a day, for a
 * second pane that would explain a collection run's 409 from the last
 * report rather than ask again -- and that pane cannot be written
 * honestly. The Feeds operator holds `collection.run` and generally not
 * `user.manage`, so the copy is null in exactly the session that wanted
 * it; where it is not null it is a snapshot taken BEFORE the refusal it
 * would be shown beside, which is the stale-report defect the catch below
 * exists to prevent. The 409 names the failing checks in its own detail,
 * so there is nothing a copy here would add that the refusal has not
 * already said. Recorded because an absent field reads as an oversight
 * until somebody has worked out why it is absent.
 */
async function loadReadiness() {
  const list = $('rdy-list');
  if (!list) return;
  const summary = $('rdy-summary');
  summary.textContent = 'checking…';
  let body;
  try {
    body = await api('/admin/readiness');
  } catch (err) {
    clear(list);
    /* A refused read leaves NO banner standing. A stale "3 blocking checks
       failing" beside a refusal is a claim about a report this pane did
       not get, and the operator cannot tell it from a fresh one. */
    renderBlockingBanner(null);
    summary.textContent = refusalText(err,
      'The readiness register needs user.manage.');
    return;
  }
  clear(list);
  const failed = body.checks.filter((c) => !c.ok).length;
  /* "READY" is only ever said about the code-side checks. The legal
     register's own items are not software and this endpoint cannot see
     them, so the phrasing stays narrow on purpose. */
  summary.textContent = body.ready
    ? 'Every code-side check passes.'
    : failed + ' of ' + countOf(body.checks.length, 'check', 'checks') + ' '
      + agree(failed, 'needs', 'need') + ' attention.';
  renderBlockingBanner(body);
  for (const c of body.checks) list.appendChild(readinessRow(c));
}

/** The banner that cannot be missed while a blocking check fails.
 *
 *  Built from the CHECK ROWS rather than from `blocking_failures` alone,
 *  because the rows are what carry the evidence and the action and a
 *  banner that named a check without saying what to do about it would send
 *  the operator hunting down the same list it sits on top of. The server's
 *  own summary is still read: any name in `blocking_failures` that no row
 *  explained is listed too, bare. The two are the same fact counted twice
 *  and they cannot be allowed to disagree silently -- the failure to avoid
 *  is a blocking failure that appears in neither.
 *
 *  `null` clears it. There is deliberately no close button: this is the
 *  one notice on the pane whose entire job is to still be there.
 */
function renderBlockingBanner(body) {
  const box = $('rdy-blocking');
  clear(box);
  if (!body) { show(box, false); return; }
  const failing = (body.checks || []).filter((c) => c.blocking && !c.ok);
  const named = new Set(failing.map((c) => c.check));
  const orphans = (body.blocking_failures || []).filter((n) => !named.has(n));
  const total = failing.length + orphans.length;
  if (!total) { show(box, false); return; }

  /* Unhidden BEFORE anything is appended, and that ordering is the whole
     of what `role="alert"` buys. `hidden` is `display: none`, which takes
     the element out of the accessibility tree, and a live region that is
     not in the tree does not observe the insertions made into it: build
     first and reveal afterwards and a screen reader announces nothing at
     all. The operator this banner was written for would then open the
     admin pane, be told nothing, and read on. Revealed first, every
     append below is a mutation inside a region already being watched. */
  show(box, true);

  const head = el('p', 'rdy-blocking-head');
  head.appendChild(el('strong', null,
    countOf(total, 'BLOCKING check', 'BLOCKING checks') + ' failing'));
  head.appendChild(document.createTextNode(
    ': the collection poll route is refused. POST '
    + '/collection/sources/{id}/run answers 409 while any of these is red, '
    + 'because a covert poll against a real target must not run on a '
    + 'deployment where these are unsettled. Named as the ROUTE and not as '
    + '"collection", because that is what the register actually stops: '
    + 'anything that calls CollectionService.run_once without going through '
    + 'the API is not gated by this. Each is a decision somebody has to '
    + 'take; none of them is closed by restarting anything.'));
  box.appendChild(head);

  const items = el('ul', 'rdy-blocking-list');
  for (const c of failing) {
    const li = el('li', 'rdy-blocking-item');
    li.appendChild(el('span', 'rdy-blocking-name', c.check));
    li.appendChild(el('p', 'why', c.evidence));
    if (c.action) li.appendChild(el('p', 'help warn', c.action));
    items.appendChild(li);
  }
  for (const name of orphans) {
    const li = el('li', 'rdy-blocking-item');
    li.appendChild(el('span', 'rdy-blocking-name', name));
    li.appendChild(el('p', 'why',
      'The server lists this as a blocking failure and sent no check row '
      + 'for it. Read GET /admin/readiness directly.'));
    items.appendChild(li);
  }
  box.appendChild(items);
}

function readinessRow(c) {
  const card = el('div', 'card row-card compact'
    + (c.ok ? '' : ' row-incomplete')
    + (c.blocking && !c.ok ? ' rdy-row-blocking' : ''));
  const head = el('div', 'row-head');
  head.appendChild(el('span', 'row-title', c.check));
  head.appendChild(el('span', 'chip ' + (c.ok ? 'good' : 'bad'),
    c.ok ? 'PASS' : 'ATTENTION'));
  /* Marked on the PASSING blockers too, quietly. Which four are the gate
     is a standing fact about the register, and an operator who only ever
     sees the chip on a red row learns that "blocking" is a synonym for
     "failed" -- then reads a green pane and does not know what would have
     stopped the product had it gone the other way.

     `subtle` while it passes, because a standing fact is not a warning,
     and `bad` (--danger: the banner's red, and this card's own left
     rule) the moment it does not. Never `warn`: amber on this pane is the
     ORDINARY failed check's colour (`.row-incomplete`), and a blocker in
     that amber says "untidy" about the one thing that makes the poll
     route answer 409. The `help warn` action line below is the one amber
     that crosses the line, in the banner as well as here -- it is the
     instruction, not the verdict. app.css argues the same from its end,
     above `.rdy-blocking` and `.rdy-row-blocking`. */
  if (c.blocking) {
    head.appendChild(el('span', 'chip ' + (c.ok ? 'subtle' : 'bad'),
      'BLOCKING'));
  }
  card.appendChild(head);
  card.appendChild(el('p', 'why', c.evidence));
  if (c.action) card.appendChild(el('p', 'help warn', c.action));
  return card;
}

/* --- the last completed analysis ---------------------------------------
 *
 * Opening the pane used to show an empty scoreboard whether the case had
 * never been analysed or had been analysed an hour ago, and the only way to
 * tell was to pay for a fresh run. `/analytics/latest` reads the stored run
 * for this exact projection -- same parameters, because they are what names
 * the projection row -- and 404s when there is none.
 */
async function loadLatestAnalysis() {
  /* Not while a Run is out either: the fresh answer is on its way, and a
     stored one drawn first would put "Showing the run of ..." over
     "computing...". */
  if (!state.caseId || state.analytics || state.analyticsRunning) return;
  /* final review C3, 2026-09-23: a stored run is one case's and one
     projection's. A reply that a switch, a Run or a changed projection
     has overtaken is dropped, never drawn under the new header. */
  const token = caseToken();
  const gen = state.analyticsGen || 0;
  const stale = () => caseChanged(token) || gen !== (state.analyticsGen || 0);
  let suite;
  try {
    suite = await api(cpath('/analytics/latest?' + anQuery().toString()));
  } catch (err) {
    if (stale()) return;
    /* 404 is the ordinary answer for a case nobody has analysed, and 403
       for an account without analytics.run. Neither is a malfunction, and
       neither should raise a banner on a pane the analyst merely opened. */
    if (err instanceof ApiError
        && (err.status === 404 || err.status === 403)) return;
    fail(err);
    return;
  }
  if (stale()) return;
  /* De-fang at the boundary, exactly as runAnalysis does: this is the pane
     that NAMES people, and a stored run is no more trustworthy than a fresh
     one -- the labels came from the same graph. */
  state.analytics = safeLabelsDeep(suite);
  renderAnalytics();
  setMsg($('an-status'), suite.computed_at
    ? 'Showing the run of ' + fmtTime(suite.computed_at) + '. Not recomputed.'
    : 'Showing the last completed run. Not recomputed.');
}

/* --- the assumptions register ------------------------------------------
 *
 * Migration 0056. An assumption is a claim the analysis rests on that
 * nobody has evidenced, and the reason to write it down is that it becomes
 * reviewable: the register turns "we all sort of assumed that" into a row
 * with a name, a date and a status somebody can argue with.
 *
 * Only OPEN and CONFIRMED reach the report (`REPORTABLE_STATUSES` in
 * assumptions.py). This says so on the panel, because an analyst who thinks
 * a withdrawn assumption still appears will leave it withdrawn rather than
 * deleting it, and one who thinks the opposite will do the reverse.
 */
function wireAssumptions() {
  const form = $('asm-create');
  if (!form) return;
  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    const msg = $('asm-msg');
    const statement = $('asm-statement').value.trim();
    if (!statement) { setMsg(msg, 'Write the assumption first.'); return; }
    const btn = $('asm-create-btn');
    btn.disabled = true;
    setMsg(msg, 'recording…');
    try {
      await api(cpath('/assumptions'), {
        method: 'POST',
        json: { statement, basis: $('asm-basis').value.trim() || null },
      });
    } catch (err) {
      btn.disabled = false;
      setMsg(msg, refusalText(err, 'Recording an assumption needs case.update.'));
      return;
    }
    btn.disabled = false;
    setMsg(msg, '');
    $('asm-statement').value = '';
    $('asm-basis').value = '';
    await loadAssumptions();
  });
  $('asm-withdrawn').addEventListener('change', () => loadAssumptions());
}

async function loadAssumptions() {
  if (!state.caseId) return;
  const q = $('asm-withdrawn').checked ? '?include_withdrawn=true' : '';
  try {
    const body = await api(cpath('/assumptions' + q));
    renderList('asm-list', 'asm-empty', body.assumptions, assumptionRow);
  } catch (err) {
    clear($('asm-list'));
    const empty = $('asm-empty');
    show(empty, true);
    /* The empty line carries the refusal rather than a banner: "no
       assumptions recorded" and "you may not read them" are different
       facts, and on this panel the first one is an accusation. */
    empty.textContent = refusalText(err, 'Assumptions need case.read.');
  }
}

/** One assumption, with the two review verbs beside it.
 *
 *  CONFIRMED is not styled as a pass and REFUTED is not styled as a
 *  failure. A refuted assumption is a GOOD outcome — the register worked,
 *  somebody checked, and the analysis can be corrected while it still can
 *  be. What deserves the warning colour is an OPEN one, because that is
 *  the question still owed an answer.
 */
function assumptionRow(a) {
  const card = el('div', 'card row-card'
    + (a.status === 'OPEN' ? ' row-incomplete' : ''));
  const head = el('div', 'row-head');
  head.appendChild(el('span', 'row-title', a.statement));
  head.appendChild(el('span', 'chip ' + (a.status === 'OPEN' ? 'warn'
    : (a.status === 'CONFIRMED' ? 'good' : 'subtle')), a.status));
  card.appendChild(head);
  if (a.basis) card.appendChild(el('p', 'why', a.basis));
  const facts = el('div', 'facts');
  facts.appendChild(fact('recorded', fmtTime(a.made_at)));
  if (a.reviewed_at) facts.appendChild(fact('reviewed', fmtTime(a.reviewed_at)));
  card.appendChild(facts);
  if (a.review_note) card.appendChild(el('p', 'why', a.review_note));

  /* A withdrawn assumption is out of the analysis and out of the report;
     re-reviewing it would be a status change with no meaning, so the verbs
     are not offered. */
  if (a.status === 'WITHDRAWN') return card;
  const actions = el('div', 'row-actions');
  for (const [label, status] of [['Confirm', 'CONFIRMED'],
                                 ['Refute', 'REFUTED'],
                                 ['Withdraw', 'WITHDRAWN']]) {
    if (status === a.status) continue;
    const b = el('button', 'btn small'
      + (status === 'WITHDRAWN' ? ' danger' : ''), label);
    b.type = 'button';
    b.addEventListener('click', () => reviewAssumption(a, status));
    actions.appendChild(b);
  }
  card.appendChild(actions);
  return card;
}

/** Change one assumption's status.
 *
 *  The note is required for a REFUTED verdict by the service, and asking
 *  here rather than letting the 400 come back means the analyst types the
 *  reason once, into a prompt that says what it is for.
 */
async function reviewAssumption(a, status) {
  let note = null;
  if (status !== 'CONFIRMED') {
    note = window.prompt(status === 'REFUTED'
      ? 'What refutes it? This is kept with the assumption.'
      : 'Why withdraw it? Optional.');
    /* Cancel is null and an empty string is "typed nothing"; neither should
       become the string "null" in the record. */
    if (status === 'REFUTED' && !note) return;
    if (!note) note = null;
  }
  try {
    await api(cpath('/assumptions/' + encodeURIComponent(a.id)),
      { method: 'PATCH', json: { status, note } });
  } catch (err) {
    setMsg($('asm-msg'), refusalText(err, 'Reviewing needs case.update.'));
    return;
  }
  setMsg($('asm-msg'), '');
  await loadAssumptions();
}

/* --- retention --------------------------------------------------------- */

async function loadRetention() {
  try {
    const rules = await api('/retention/rules');
    renderList('ret-rules', 'ret-rules-notice', rules.rules, ruleRow);
    fillRetentionCategories(rules.rules);
    const notice = $('ret-rules-notice');
    /* `.length`, not the array. `unconfirmed` is a LIST and `[] ? a : b`
       takes `a`, so the alert-coloured banner was permanently lit — reading
       "every rule has been confirmed" in the same red as the real warning.
       An alarm that is always on carries no information, and this is the
       one signal separating a jurisdictional retention period from a
       number somebody typed. */
    const pending = (rules.unconfirmed || []).length;
    notice.textContent = pending ? (rules.notice || '') : '';
    show(notice, pending > 0);
  } catch (err) {
    clear($('ret-rules'));
    const notice = $('ret-rules-notice');
    /* Saying nothing was the bug. Leaving the pane blank asserts "there are
       no retention rules"; the truth was "you may not see them", and the
       purge control sits directly beneath. 0039's own docstring says the
       failure mode of hiding a deadline is that somebody discovers it by
       missing it. */
    notice.textContent = refusalText(err, 'Retention rules need retention.read.');
    show(notice, true);
    if (!(err instanceof ApiError && err.status === 403)) fail(err);
  }
  if (!state.caseId) return;
  /* Dropped when the case changed while it was in flight: case A's
     deadlines under case B's header is the failure the case-switch
     registry exists to end. */
  const token = caseToken();
  try {
    const due = await api('/retention/due?case_id=' + state.caseId);
    if (caseChanged(token)) return;
    renderList('ret-due', 'ret-due-empty', due.due || [], dueExhibitRow);
    $('ret-counts').textContent = (due.due || []).length + ' due';
  } catch (err) {
    if (caseChanged(token)) return;
    renderList('ret-due', 'ret-due-empty', [], dueExhibitRow);
    $('ret-due-empty').textContent = refusalText(
      err, 'Deadlines for this case need retention.read.');
    $('ret-counts').textContent = '';
    if (!(err instanceof ApiError && err.status === 403)) fail(err);
  }
}

function ruleRow(r) {
  const card = el('div', 'card row-card compact');
  const head = el('div', 'row-head');
  head.appendChild(el('span', 'row-title', r.category));
  head.appendChild(el('span', 'chip', r.retain_days + ' days'));
  if (r.is_placeholder) head.appendChild(el('span', 'chip warn', 'unconfirmed'));
  card.appendChild(head);
  if (!r.is_placeholder) {
    const facts = el('div', 'facts');
    facts.appendChild(fact('confirmed by',
      r.confirmed_by_name || 'an account no longer listed'));
    if (r.confirmed_at) facts.appendChild(fact('on', fmtTime(r.confirmed_at)));
    card.appendChild(facts);
  }
  if (r.rationale) card.appendChild(el('p', 'why', r.rationale));
  return card;
}

/** One item due for destruction.
 *
 *  The field names are `object_type` / `object_id` / `deadline` — NOT
 *  `category` / `id` / `retain_until`, which is what this read at first.
 *  Every row rendered "exhibit", an empty id and an em dash for the date,
 *  so an item ninety days overdue was pixel-identical to one due next
 *  year. `daysFromNow(undefined)` is null and `null < 0` is false, so the
 *  overdue styling could never fire either — the one thing this list is
 *  for. Its own comment says "negative reads as overdue, which is the
 *  point".
 */
function dueExhibitRow(d) {
  const card = el('div', 'card row-card');
  const head = el('div', 'row-head');
  const overdue = daysFromNow(d.deadline);
  const score = el('span', 'score' + (overdue !== null && overdue < 0 ? ' hot' : ''),
    overdue === null ? 'not set' : (overdue < 0 ? Math.abs(overdue) + 'd' : overdue + 'd'));
  score.title = overdue !== null && overdue < 0
    ? 'Overdue by this many days.' : 'Days until destruction.';
  head.appendChild(score);
  head.appendChild(el('span', 'row-title', d.object_type || 'object'));
  if (d.legal_hold) head.appendChild(el('span', 'chip warn', 'legal hold'));
  card.appendChild(head);
  const facts = el('div', 'facts');
  facts.appendChild(fact('id', String(d.object_id || '').slice(0, 8)));
  facts.appendChild(fact('due', whenText(d.deadline),
    (overdue !== null && overdue < 0) ? 'bad' : ''));
  if (d.rule) facts.appendChild(fact('rule', d.rule));
  card.appendChild(facts);
  if (d.legal_hold) {
    card.appendChild(el('p', 'why',
      'Held' + (d.hold_reason ? ': ' + d.hold_reason : '')
      + '. A hold outranks the retention clock, and lifting one is its own '
      + 'audited act.'));
  }
  return card;
}

/* --- purge: a preview, then a confirmation -----------------------------
 *
 * ux15 purge-one-click-destroy-with-carried-state and ux17
 * purge-no-confirmation (2026-09-22). A real purge was one click on a
 * neutral "Run", identical to the dry run but for a checkbox far above
 * it, and the unticked box and the authority text survived a case switch:
 * a preview meant for case B could destroy B's expired material under the
 * authority typed for case A. What holds now:
 *
 *   - the button says what it will do, and is --danger when it destroys;
 *   - a real run needs a dry run of THIS case under THIS authority first,
 *     and its confirmation repeats that dry run's counts and asks for the
 *     case code to be typed;
 *   - the dry run is re-ticked whenever the pane opens; the authority, the
 *     preview and the result are cleared on every case switch, and the
 *     authority after every real run.
 *
 * The server's `dry_run` still defaults to true; none of this replaces it.
 *
 * Final review U20, 2026-09-23: the confirmation repeated a dry run's
 * counts, but the real run sent only the case and the authority and the
 * server read what was due afresh. A preview of any age was kept, so a
 * hold lifted in between turned "Destroy 3 exhibits" into 14 destroyed.
 * Now the dry run's `preview` digest rides on the real run and the server
 * refuses (409) unless what is due is still exactly what was counted; the
 * console also lets a preview lapse after PURGE_PREVIEW_TTL_MS, so the
 * time the confirmation quotes is never hours old.
 */
let purgePreview = null;
const PURGE_PREVIEW_TTL_MS = 10 * 60 * 1000;

function purgeCounts(body) {
  return [
    [body.evidence_purged || 0, 'exhibit'],
    [body.documents_purged || 0, 'document'],
    [body.records_purged || 0, 'ingest record'],
    [body.dead_letters_purged || 0, 'dead letter'],
  ].filter(([n]) => n > 0)
    .map(([n, noun]) => n + ' ' + noun + (n === 1 ? '' : 's'));
}

function syncPurgeButton() {
  const dry = $('ret-dry').checked;
  const b = $('ret-purge');
  b.textContent = dry ? 'Preview (dry run)' : 'Destroy…';
  b.className = dry ? 'btn' : 'btn danger';
  if (dry) show($('ret-destroy-box'), false);
}

/** Every time the pane opens: the dry run is the default again. */
function purgeDefaults() {
  $('ret-dry').checked = true;
  syncPurgeButton();
}

/** After a real run, and on every case switch. */
function resetPurgeInputs() {
  purgePreview = null;
  $('ret-authority').value = '';
  $('ret-destroy-code').value = '';
  purgeDefaults();
}

onCaseSwitch(() => {
  resetPurgeInputs();
  setMsg($('ret-purge-msg'), '');
  clear($('ret-purge-out'));
  $('ret-purge-box').open = false;
  clear($('ret-due'));
  $('ret-counts').textContent = '';
  clear($('tomb-list'));
  $('tomb-counts').textContent = '';
  $('tomb-empty').textContent = 'Nothing has been destroyed.';
});

async function runPurge() {
  const msg = $('ret-purge-msg');
  setMsg(msg, '');
  if (!state.caseId) { setMsg(msg, 'Open a case first.'); return; }
  const authority = $('ret-authority').value.trim();
  if (authority.length < 10) {
    setMsg(msg, 'A purge has to say under what authority it runs, in at '
      + 'least 10 characters: the tombstone keeps this text after the '
      + 'material is gone.');
    return;
  }
  if ($('ret-dry').checked) { await doPurge(authority, true); return; }
  openPurgeConfirm(authority);
}

function openPurgeConfirm(authority) {
  const msg = $('ret-purge-msg');
  const p = purgePreview;
  if (!p || p.caseId !== state.caseId || p.authority !== authority) {
    show($('ret-destroy-box'), false);
    setMsg(msg, 'Run a dry run of this case under this authority first. The '
      + 'confirmation repeats what the dry run counted, and without one '
      + 'there is nothing to confirm.');
    return;
  }
  if (Date.now() - p.at.getTime() > PURGE_PREVIEW_TTL_MS) {
    purgePreview = null;
    show($('ret-destroy-box'), false);
    setMsg(msg, 'That dry run is more than '
      + Math.round(PURGE_PREVIEW_TTL_MS / 60000) + ' minutes old. Run it '
      + 'again: the confirmation repeats what a dry run counted, and an old '
      + 'count is not one to destroy on.');
    return;
  }
  if (!p.counted.length) {
    setMsg(msg, 'The dry run found nothing due on this case, so there is '
      + 'nothing to destroy.');
    return;
  }
  if (!p.preview) {
    setMsg(msg, 'That dry run gave nothing to confirm: what was due changed '
      + 'while it was counting. Run it again.');
    return;
  }
  const code = state.caseRec ? state.caseRec.code : '';
  $('ret-destroy-what').textContent = 'Destroy ' + p.counted.join(', ')
    + ' in ' + code + ', under the authority "' + authority + '". The dry '
    + 'run counted these at ' + fmtClock(p.at) + ', and exactly these go. '
    + 'If anything has changed since (something newly due, a legal hold '
    + 'placed or lifted), the server refuses and nothing is destroyed. '
    + 'This cannot be undone.';
  $('ret-destroy-label').textContent = 'Type ' + code + ' to confirm';
  $('ret-destroy-code').value = '';
  $('ret-destroy-go').disabled = true;
  show($('ret-destroy-box'), true);
  $('ret-destroy-code').focus();
}

function syncDestroyGo() {
  const code = state.caseRec ? state.caseRec.code : '';
  $('ret-destroy-go').disabled = !code
    || $('ret-destroy-code').value.trim().toUpperCase() !== code.toUpperCase();
}

/** The "Destroy now" press. Re-checks the preview it is confirming, since
 *  the authority box stays editable while the confirmation is open. */
function confirmPurge() {
  const authority = $('ret-authority').value.trim();
  const p = purgePreview;
  /* Its age too: a confirmation left open is as stale as a preview. */
  if (!p || p.caseId !== state.caseId || p.authority !== authority
      || Date.now() - p.at.getTime() > PURGE_PREVIEW_TTL_MS) {
    openPurgeConfirm(authority);
    return;
  }
  syncDestroyGo();
  if ($('ret-destroy-go').disabled) return;
  doPurge(authority, false);
}

async function doPurge(authority, dry) {
  const msg = $('ret-purge-msg');
  const out = $('ret-purge-out');
  const caseId = state.caseId;
  const token = caseToken();
  clear(out);
  /* Disabled in flight: a second press of a destroying button is a second
     destruction request. */
  $('ret-purge').disabled = true;
  $('ret-destroy-go').disabled = true;
  const json = { case_id: caseId, authority, dry_run: dry };
  /* A real run names the dry run it confirms, and the server destroys only
     if what is due still matches it (final review U20, 2026-09-23). */
  if (!dry) json.preview = purgePreview ? purgePreview.preview : null;
  let body;
  try {
    body = await api('/retention/purge', { method: 'POST', json });
  } catch (err) {
    $('ret-purge').disabled = false;
    if (caseChanged(token)) return;
    if (!dry && err instanceof ApiError
        && (err.status === 409 || err.status === 428)) {
      /* The count the confirmation quoted is no longer true, so it is
         dropped: the next step is a fresh dry run, never a retry. */
      purgePreview = null;
      show($('ret-destroy-box'), false);
      purgeDefaults();
    }
    inlineProblem(msg, err);
    syncDestroyGo();
    return;
  }
  $('ret-purge').disabled = false;
  /* A result for a case that is no longer open is not drawn under the new
     one. A real run's record is its tombstone, listed on its own case. */
  if (caseChanged(token)) return;
  /* The field names are the server's: `evidence_purged`,
     `documents_purged`, `held_back`, `storage_locked`. This read
     `body.purged` and `body.refused`, neither of which is ever sent -- so
     a real, irreversible purge reported "0 object(s) destroyed" and the
     storage-refusal warning could not fire, because the key it tested
     did not exist. decision 50 requires `storage_locked` to be REPORTED:
     object lock can refuse a delete even to satisfy a deletion order,
     and a tombstone recording a purge that did not happen is a false
     record. */
  out.appendChild(el('p', body.dry_run ? 'form-ok' : 'form-error',
    body.notice || ''));
  const verb = body.dry_run ? 'would be destroyed' : 'destroyed';
  const counted = purgeCounts(body);
  out.appendChild(el('p', null, counted.length
    ? counted.join(', ') + ' ' + verb
    : 'Nothing ' + verb + '.'));
  if (body.held_back) {
    out.appendChild(el('p', null,
      body.held_back + ' skipped under a legal hold. A hold outranks the '
      + 'retention clock.'));
  }
  if (body.storage_locked) {
    out.appendChild(el('p', 'form-error',
      'Storage REFUSED to delete '
      + countOf(body.storage_locked, 'object', 'objects') + '. '
      + 'COMPLIANCE-mode object lock can refuse even to satisfy a deletion '
      + 'order (decision 50): the bytes are still there, and a tombstone '
      + 'recording a purge that did not happen is a false record.'));
  }
  for (const w of body.warnings || []) {
    out.appendChild(el('p', 'help warn', w));
  }
  const written = (body.tombstones || []).length;
  if (written) {
    out.appendChild(el('p', 'help',
      countOf(written, 'tombstone', 'tombstones') + ' written. '
      + agree(written, 'It is append-only and outlives what it records.',
        'They are append-only and outlive what they record.')));
  }
  if (dry) {
    purgePreview = { caseId, authority, counted, at: new Date(),
                     preview: body.preview || null };
    if (counted.length) {
      out.appendChild(el('p', 'help',
        'To destroy this for real, untick Dry run and press Destroy within '
        + Math.round(PURGE_PREVIEW_TTL_MS / 60000) + ' minutes. You will be '
        + 'asked to confirm these counts and type the case code.'));
    }
  } else {
    show($('ret-destroy-box'), false);
    resetPurgeInputs();
    out.appendChild(el('p', 'help',
      'The authority has been cleared and Dry run ticked again: the next '
      + 'run starts from a preview.'));
  }
  loadRetention();
}

/* The tombstone register is the legal record of what was destroyed, and
 * it is read for ONE case. ux17-failure (2026-09-22): a failed read left
 * the markup's "Nothing has been destroyed." standing, and a case switch
 * left the previous case's destructions under the new header. */
onCaseSwitch(() => {
  clear($('tomb-list'));
  $('tomb-counts').textContent = '';
  $('tomb-empty').textContent = 'Nothing has been destroyed.';
  show($('tomb-empty'), false);
  clearLoadFailure('tomb-empty');
});

async function loadTombstones() {
  if (!state.caseId) return;
  const token = caseToken();
  try {
    const body = await api('/retention/tombstones?case_id=' + state.caseId);
    if (caseChanged(token)) return;
    clearLoadFailure('tomb-empty');
    $('tomb-empty').textContent = 'Nothing has been destroyed.';
    renderList('tomb-list', 'tomb-empty', body.tombstones || [], tombRow);
    $('tomb-counts').textContent = countOf((body.tombstones || []).length,
      'record', 'records');
  } catch (err) {
    if (caseChanged(token)) return;
    /* Cleared, then explained. The 403 branch used to return with the
       previous case's rows still listed under the refusal. */
    renderList('tomb-list', 'tomb-empty', [], tombRow);
    $('tomb-counts').textContent = '';
    if (err instanceof ApiError && err.status === 403) {
      $('tomb-empty').textContent = refusalText(
        err, 'The destruction record needs retention.read.');
      return;
    }
    showLoadFailure('tomb-empty', 'The destruction register', err,
      loadTombstones);
    fail(err);
  }
}

const TOMB_NOUN = { evidence: 'exhibit', document: 'document',
                    ingest_record: 'ingest record', dead_letter: 'dead letter' };
/* The rule keys retention.py writes, in words. An unknown key is shown as
   written rather than guessed at. */
const TOMB_RULE = {
  'case.retention_until': "the case's retention date",
  retention_rule: 'the category retention rule',
  'out-of-schedule': 'out of schedule, under a four-eyes approval',
  'dead_letter[90d default]': 'dead letters, 90-day default',
};

/** What the object store did with the bytes, as a chip and, when it did
 *  not delete them, the sentence that stops the row being read as a
 *  completed destruction (decision 50). */
function tombStorage(t) {
  const evidence = t.object_type === 'evidence';
  /* An out-of-schedule purge (four-eyes, before retention expires) has NO
     next sweep: `due()` returns only exhibits whose retention has expired,
     so a refused exhibit never comes back due (retention.py
     purge_out_of_schedule). Saying "stays due until the lock expires" or
     "before the next sweep retries" on that record described a court-ordered
     early destruction refused by object lock as self-healing (2026-09-23). */
  const early = t.rule === 'out-of-schedule';
  const noRetry = (lock) => ' Nothing will retry them: this was an '
    + 'out-of-schedule purge and those exhibits are not due'
    + (lock ? ', nor will they become due when the lock lifts' : '')
    + '. Destroying them now needs a new four-eyes approval.';
  switch (t.storage_outcome) {
    case 'DELETED':
      return { chip: 'bytes deleted', cls: 'ok', done: true, why: null };
    case 'LOCKED_UNTIL_RETENTION':
      return { chip: 'bytes NOT all deleted: object lock', cls: 'warn',
               done: false,
               why: 'The object store refused some of these deletes under a '
                 + 'retention lock. Those exhibits keep their bytes and were '
                 + 'not marked purged.'
                 + (early ? noRetry(true) : ' They stay due, so the first sweep '
                   + 'after the lock expires finishes the job.') };
    case 'FAILED':
      return { chip: 'bytes NOT all deleted: store failed', cls: 'bad',
               done: false,
               why: 'The object store did not confirm some of these deletes, '
                 + 'for a reason other than a lock. Those exhibits were not '
                 + 'marked purged, and somebody has to look'
                 + (early ? '.' + noRetry(false) : ' before the next sweep retries.') };
    case 'NOT_APPLICABLE':
      return evidence
        ? { chip: 'bytes never touched', cls: 'bad', done: false,
            why: 'No object store was contacted for this run: the rows were '
              + 'marked purged and the exhibit bytes were not deleted. Do '
              + 'not report this as a destruction.' }
        : { chip: 'database only', cls: '', done: true, why: null };
    default:
      return { chip: t.storage_outcome || 'storage outcome unknown',
               cls: 'warn', done: false, why: null };
  }
}

/** One destruction, as the record a disclosure request reads.
 *
 *  ux15 tombstone-rows-blank (2026-09-22): this read `object_id` and
 *  `sha256`, neither of which a tombstone carries (one row is one BATCH),
 *  so every row showed an empty id, and the count, the actor, the rule and
 *  the storage outcome were never drawn. A purge of 37 exhibits looked
 *  like a purge of one, nothing said who ran it, and a batch whose bytes
 *  the object lock refused was listed as destroyed. */
function tombRow(t) {
  const card = el('div', 'card row-card');
  const head = el('div', 'row-head');
  const n = t.object_count || 0;
  const noun = TOMB_NOUN[t.object_type] || (t.object_type || 'object');
  const st = tombStorage(t);
  head.appendChild(el('span', 'row-title', n + ' ' + noun + (n === 1 ? '' : 's')
    + (st.done ? ' destroyed' : ' in this purge')));
  head.appendChild(el('span', 'chip' + (st.cls ? ' ' + st.cls : ''), st.chip));
  card.appendChild(head);
  const facts = el('div', 'facts');
  facts.appendChild(fact('when', fmtTime(t.purged_at)));
  facts.appendChild(fact('by', t.purged_by_name
    || ('account ' + shortId(t.purged_by))));
  if (t.rule) facts.appendChild(fact('rule', TOMB_RULE[t.rule] || t.rule));
  card.appendChild(facts);
  if (t.authority) card.appendChild(el('p', 'why', 'Authority: ' + t.authority));
  if (st.why) card.appendChild(el('p', 'help warn', st.why));
  const ref = el('p', 'help tomb-ref');
  ref.appendChild(el('span', 'fact-k', 'record'));
  ref.appendChild(copyable(el('code', 'mono', t.id), t.id, 'tombstone id'));
  card.appendChild(ref);
  return card;
}

/* --- break-glass -------------------------------------------------------
 *
 * ux15 breakglass-grant-raises-nothing and
 * glass-review-queue-uninformative-irreversibl (2026-09-22).
 *
 * The console posted a justification alone and said "Granted. It is short,
 * counted and will be reviewed." A grant with no classification is read by
 * no access decision, so the analyst was told they had emergency access,
 * every officer was paged past quiet hours, and the exhibit still 403'd.
 * The grant was also deployment-wide rather than scoped to the case it was
 * invoked from, and it lasted whatever the router defaulted to.
 *
 * So the form names all three (case, level, hours), will not send a grant
 * that would raise nothing, says what the grant will do before it is
 * invoked, and shows the server's own sentence afterwards. A header chip
 * says so on every screen while any grant is live.
 *
 * The review queue names the person, says whether the grant is live,
 * expired or ended early, and confirms a verdict before recording it: the
 * server refuses to revisit a review, so a mis-click was permanent.
 */
const GLASS_HOURS = [1, 2, 3, 4, 6, 8];   // InvokeBody caps at 8
/* What a grant's use count covers, word for word the server's `_COUNTED`
   (governance.py), so the invoke pane, the analyst's own card and the
   officer's card cannot describe three different counts. They said "each
   exhibit it opens" while captures, messages and entity changes were
   counted too, and on a case classified above the invoker every request
   was (final review U19, 2026-09-23). test_ui_governance_invariants holds
   the two to each other. */
const GLASS_COUNTED = 'It counts each exhibit, capture or message you open '
  + 'above your own clearance and each change you make to an entity above '
  + 'it. Nothing else it widens is counted (the graph, the inspector, lists '
  + 'and search), except on a case classified above your own clearance, '
  + 'where every request on that case is.';
const GLASS_MIN_WHY = 40;                 // InvokeBody.justification
let glassMine = null;                     // the last GET /break-glass/mine
let glassTimer = null;

function tlpRank(name) { return TLP.indexOf(name); }

/** A clock time alone, in UTC and labelled: "15:18 UTC". For a deadline
 *  within the day (a grant's end, a session's end), where the date would
 *  be noise. The review card sliced ISO strings, which printed UTC with no
 *  zone (ux15, 2026-09-22); it now uses fmtTime like every other screen,
 *  since the console shows one zone and names it (fmtTime above). */
function fmtClock(iso) {
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? String(iso)
    : pad2(d.getUTCHours()) + ':' + pad2(d.getUTCMinutes()) + ' UTC';
}

function grantRaises(g, clearance) {
  const level = g.granted_classification;
  return !!(level && clearance && tlpRank(level) > tlpRank(clearance));
}

/** Whether a live grant is in force on the open case: a global grant is
 *  everywhere, a case grant only on its own case. */
function grantAppliesHere(g) {
  return g.scope !== 'case' || (!!state.caseId && g.case_id === state.caseId);
}

/** One live grant in a sentence: what it raises, where, and until when. */
function describeGrant(g, clearance) {
  const where = g.scope === 'case'
    ? (g.case_code ? 'on ' + g.case_code + ' only' : 'on one case only')
    : 'on every case you are assigned to';
  const what = grantRaises(g, clearance)
    ? 'Clearance raised from ' + clearance + ' to ' + g.granted_classification
      + ' ' + where
    : 'A grant ' + where + ' that raises nothing';
  return what + ', until ' + fmtTime(g.expires_at) + '. ' + GLASS_COUNTED
    + ' A security officer will review it once it has ended.';
}

/** The header chip. Every live grant, whatever case is open, but it names
 *  a level only where that level is in force.
 *
 *  It read "BREAK-GLASS RED" on any case while a RED grant was live
 *  anywhere, so an analyst under a grant scoped to OP-KESTREL-26 who had
 *  moved to OP-NIGHTJAR-26 was told RED was in force where it was not
 *  (verifier follow-up to ux15 breakglass-grant-raises-nothing,
 *  2026-09-23). On a case it now names the level only for a grant that
 *  applies to that case, and otherwise says where the grant is. With no
 *  case open it names the level and where it applies. */
/* Which live grant, if any, raises the open case: its id, or ''. When that
 * changes, the lists on screen were read under the other ceiling.
 *
 * The verifier of 2026-09-23 invoked a RED grant for the open case and was
 * told the lists 'now include material up to RED' while the Entities pane
 * still showed three of three: every list had been read before the grant,
 * and nothing re-read them until the case was reopened. The mirror held
 * when a grant ended. The chip is re-rendered after every invoke and on its
 * own expiry timer, so this is where both edges are seen. `null` means
 * nothing is known yet (sign-in, or a case just opened, which loads fresh
 * anyway), so the first render never triggers a reload. */
let glassHereKey = null;
onCaseSwitch(() => { glassHereKey = null; });

function noteGlassChange(grants, clearance) {
  const here = state.caseId
    ? grants.filter((x) => grantRaises(x, clearance)).find(grantAppliesHere)
    : null;
  const key = here ? String(here.id) : '';
  const changed = glassHereKey !== null && key !== glassHereKey;
  glassHereKey = key;
  if (changed && state.caseId) {
    reloadAll();
    loadEvidence();
    refreshSearchForGlass();
  }
}

/* The Search pane, and the palette's selector lookup, read under the
 * ceiling too: /search/nodes, /search/evidence and /search/selectors all
 * honour a grant on their case. So when the grant changed, the pane kept
 * the RED labels, the selector values and "Showing 50 of 73" read under a
 * grant that had ended, with no time limit, and a click on a stale hit met
 * a refusal; after a grant began it went on saying "No entities match"
 * for material the header now said was included (final review C13,
 * 2026-09-23). A search still in flight is retired, the one on screen is
 * asked again under the new ceiling, and the palette's short cache goes. */
function refreshSearchForGlass() {
  searchSeq += 1;
  resetPalSel();
  const q = $('search-q').value.trim();
  if (q && $('search-scope').textContent) {
    runSearch({ preventDefault() {} });
    return;
  }
  clear($('search-nodes'));
  clear($('search-evidence'));
  setMsg($('search-scope'), '');
}

/* final review C17, 2026-09-23. The chip saw a grant end through one
 * timer, set for just after expires_at by THIS computer's clock, and never
 * set again. A workstation clock a few seconds fast asked while the server
 * still listed the grant, got the same answer, computed a wait below zero
 * and set nothing; a refresh that failed set nothing either. The header
 * went on saying "BREAK-GLASS RED until 15:18 UTC" long after 15:18, and
 * noteGlassChange never re-read the lists at the analyst's own clearance.
 * An officer's "End it now" was never seen at all.
 *
 * It still does not poll on a plain timer. Every answered request slides
 * the idle window (the session region: "The client never polls"), so a
 * check every minute while a grant is live would keep an unattended
 * console signed in for as long as the grant lasts. Instead:
 *  - a grant the server still lists after this clock says it ended, and a
 *    refresh that failed, are asked about again on a short backoff that
 *    stops (GLASS_RETRY_MS), which covers ordinary clock skew;
 *  - while any grant is listed, the analyst's own next click or key asks
 *    again, at most once per GLASS_RECHECK_MS. That is how a revoke, or an
 *    end the backoff missed, is seen, and it slides nothing the person at
 *    the keyboard was not already sliding;
 *  - sessionRenewed asks again after an in-place sign-in. */
const GLASS_RETRY_MS = [5000, 15000, 30000, 60000];
const GLASS_RECHECK_MS = 60000;
let glassRetries = 0;
let glassAskedAt = 0;
let glassListed = false;

function armGlassRetry() {
  if (glassTimer) { clearTimeout(glassTimer); glassTimer = null; }
  if (glassRetries >= GLASS_RETRY_MS.length) return;
  glassTimer = setTimeout(refreshGlassChip, GLASS_RETRY_MS[glassRetries]);
  glassRetries += 1;
}

function recheckGlassOnActivity() {
  if (!glassListed || SESSION.lapsed) return;
  if (Date.now() - glassAskedAt < GLASS_RECHECK_MS) return;
  refreshGlassChip();
}

function renderGlassChip(body) {
  const chip = $('hdr-glass');
  if (glassTimer) { clearTimeout(glassTimer); glassTimer = null; }
  const grants = (body && body.grants) || [];
  noteGlassChange(grants, body && body.clearance);
  glassAskedAt = Date.now();
  glassListed = grants.length > 0;
  if (!grants.length) {
    glassRetries = 0;
    clear(chip);
    chip.title = '';
    chip.classList.remove('elsewhere');
    show(chip, false);
    return;
  }
  const clearance = body.clearance;
  const raising = grants.filter((x) => grantRaises(x, clearance));
  /* The grant the access gate uses here: the highest live level that
     applies, which is also how /mine orders them. */
  const here = state.caseId ? raising.find(grantAppliesHere) : raising[0];
  const where = (g) => (g.scope === 'case' ? (g.case_code || 'one case')
    : 'all cases');
  clear(chip);
  let lead;
  let rest = null;
  let until = null;
  if (here) {
    lead = 'BREAK-GLASS ' + here.granted_classification
      + (state.caseId ? '' : ' on ' + where(here));
    until = here.expires_at;
  } else if (raising.length) {
    /* Live, but not on this case: said, and not as a level. Where it IS
       live goes in the title: a second case code in the bar squeezed the
       open case's own code to "OP-NIGHTJAR-…" at 1366px, and the open
       case is the one that must stay legible. */
    lead = 'BREAK-GLASS';
    rest = ': not this case';
  } else {
    lead = 'BREAK-GLASS (raises nothing)';
    until = grants[0].expires_at;
  }
  chip.appendChild(document.createTextNode(lead));
  /* The parts that give way on a small laptop with a case open (app.css). */
  if (rest) chip.appendChild(el('span', 'hdr-glass-where', rest));
  if (until) chip.appendChild(el('span', 'hdr-glass-until', ' until ' + fmtClock(until)));
  if (grants.length > 1) {
    chip.appendChild(document.createTextNode(' +' + (grants.length - 1)));
  }
  /* Quieter when nothing it says is in force on the screen in front of
     the analyst: still visible, never the danger red. */
  chip.classList.toggle('elsewhere', !here && raising.length > 0);
  const lines = grants.map((x) => describeGrant(x, clearance));
  if (!here && raising.length && state.caseId) {
    lines.unshift('Not in force on this case: here you read at '
      + (clearance || 'your own clearance') + '.');
  }
  chip.title = lines.join('\n');
  show(chip, true);
  /* Asked again just after the soonest expiry, so the chip goes dark when
     the grant does rather than on the next navigation. A wait at or below
     zero (or NaN) means the server still lists a grant this clock says has
     ended: asked again on the backoff rather than never (C17). */
  const soonest = Math.min(...grants.map((x) => new Date(x.expires_at).getTime()));
  const wait = soonest - Date.now() + 1000;
  if (wait > 0) {
    glassRetries = 0;
    glassTimer = setTimeout(refreshGlassChip, Math.min(wait, 2147483647));
  } else {
    armGlassRetry();
  }
}

async function refreshGlassChip() {
  if ($('view-app').hidden) return;     // signed out since the timer was set
  glassAskedAt = Date.now();
  try {
    renderGlassChip(await api('/break-glass/mine'));
  } catch (err) {
    /* Left as it was rather than hidden: going dark is the one wrong
       answer for a grant that may still be live. But asked again (C17):
       a failed read used to be the last word until the analyst changed
       case. Not when the session itself ended: that failure is handled,
       and sessionRenewed asks once the analyst has signed in again. */
    if (!(err && err.handled)) armGlassRetry();
  }
}

function renderGlassMine(body) {
  const mine = $('glass-mine');
  clear(mine);
  if (!body) {
    /* "No grant" is a 200 with live:false, so only a real failure lands
       here, and swallowing it hid the one warning this card exists for
       (ux17, 2026-09-22). */
    show(mine, true);
    mine.appendChild(el('p', 'help warn',
      'Could not check whether you are operating under break-glass. Refresh '
      + 'to ask again.'));
    return;
  }
  const g = body.live ? body.grant : null;
  show(mine, !!g);
  if (!g) return;
  const full = (body.grants || []).find((x) => x.id === g.id) || g;
  mine.appendChild(el('h2', 'h-sm', 'You are operating under break-glass'));
  mine.appendChild(el('p', null, describeGrant(full, body.clearance)));
  const n = g.action_count || 0;
  mine.appendChild(el('p', 'help warn',
    'It ends on its own: that is the design, not a limitation. '
    + (n ? 'So far it has made ' + n + ' access' + (n === 1 ? '' : 'es')
      + ' possible that your own clearance would not have.'
      : 'So far nothing you opened has needed it.')));
}

/** Scope, level and duration, built from the open case and the caller's
 *  own clearance. A level the analyst already holds is listed but cannot
 *  be picked, because a grant to it would raise nothing. */
function fillGlassForm() {
  const code = state.caseRec ? state.caseRec.code : null;
  const scope = $('glass-scope');
  const keepScope = scope.value || 'case';
  opts(scope, (code ? [['case', 'This case only: ' + code]] : [])
    .concat([['deployment', 'Every case I am assigned to']]),
  code ? keepScope : 'deployment');
  const hours = $('glass-hours');
  if (!hours.options.length) {
    opts(hours, GLASS_HOURS.map((h) =>
      [String(h), h + ' hour' + (h === 1 ? '' : 's')]), '2');
  }
  const level = $('glass-level');
  const keep = level.value;
  const clearance = glassMine ? glassMine.clearance : null;
  const floor = Math.max(0, tlpRank(state.caseRec
    ? state.caseRec.classification : 'CLEAR'));
  clear(level);
  const head = el('option', null, 'Choose the level you need');
  head.value = '';
  level.appendChild(head);
  let usable = 0;
  for (const name of TLP.slice(floor)) {
    const held = !!clearance && tlpRank(name) <= tlpRank(clearance);
    const o = el('option', null, name + (held ? ' (you already hold this)' : ''));
    o.value = name;
    o.disabled = held;
    if (!held) usable += 1;
    if (name === keep && !held) o.selected = true;
    level.appendChild(o);
  }
  if (!usable) head.textContent = 'Nothing to raise: you hold ' + clearance;
  updateGlassEffect();
}

/** What the grant will do, said before it is invoked, and whether the
 *  form is complete enough to send. */
function updateGlassEffect() {
  const whyLen = $('glass-why').value.trim().length;
  $('glass-count').textContent = whyLen >= GLASS_MIN_WHY
    ? whyLen + ' characters'
    : whyLen + ' of the ' + GLASS_MIN_WHY + ' characters a security officer '
      + 'needs in order to review this';
  const level = $('glass-level').value;
  const scope = $('glass-scope').value;
  const hours = parseInt($('glass-hours').value, 10) || 2;
  const clearance = glassMine ? glassMine.clearance : null;
  const code = state.caseRec ? state.caseRec.code : '';
  const usable = [...$('glass-level').options].some((o) => o.value && !o.disabled);
  let text;
  if (!usable) {
    text = 'Your clearance is already ' + clearance + ', so there is nothing '
      + 'a grant could raise here. Invoking would still page every security '
      + 'officer and wait for their review, so the console does not send one.';
  } else if (!level) {
    text = 'Choose the level the emergency needs. A grant raises your '
      + 'clearance and nothing else: no permission your case role lacks, '
      + 'and no compartment.';
  } else {
    const until = new Date(Date.now() + hours * 3600000);
    const own = clearance || 'your own clearance';
    /* What it opens, by scope, as the server's notice says it. "On OP-X
       only" was true of one route, opening an exhibit by id: the graph,
       the lists and search still filtered at the analyst's own level
       (verifier follow-up to ux15, 2026-09-23). They honour a grant on
       their case now; writes and reports still do not. */
    const reach = scope === 'case' && code
      ? 'On ' + code + ' the graph, the entity and exhibit lists, the '
        + 'inspector, search, comms, analytics, tags and captures will '
        + 'include material up to ' + level + '. No other case changes, and '
        + 'what you create and any report you build stay within ' + own + '. '
      : 'That covers what the console shows on each of them, what you may '
        + 'create and the reports you build, and the Lab, collection and '
        + 'ingest views as well. ';
    text = 'Raises your clearance' + (clearance ? ' from ' + clearance : '')
      + ' to ' + level + ' '
      + (scope === 'case' && code ? 'on ' + code + ' only'
        : 'on every case you are assigned to')
      + ', for ' + hours + ' hour' + (hours === 1 ? '' : 's') + ' (until about '
      + fmtClock(until) + '). ' + reach + GLASS_COUNTED + ' '
      + 'The moment you invoke, every security officer '
      + 'is alerted, even in quiet hours, and one of them must review it '
      + 'afterwards. It grants no permission your case role lacks and reads '
      + 'you into no compartment.';
  }
  $('glass-effect').textContent = text;
  $('glass-invoke').disabled = !(usable && level && whyLen >= GLASS_MIN_WHY);
}

onCaseSwitch(() => {
  glassMine = null;
  clear($('glass-mine'));
  show($('glass-mine'), false);
  setMsg($('glass-msg'), '');
  clear($('glass-result'));
  /* The justification describes case A's emergency. It must not be one
     click from being invoked against case B. */
  $('glass-why').value = '';
  $('glass-box').open = false;
  clear($('glass-scope'));
  clear($('glass-level'));
  $('glass-invoke').disabled = true;
  /* Deferred until the switch has set the new case. The chip covers every
     case, so it is refreshed on the list as well as in a case. */
  setTimeout(refreshGlassChip, 0);
});

async function loadBreakGlass() {
  const token = caseToken();
  let body = null;
  try {
    body = await api('/break-glass/mine' + (state.caseId
      ? '?case_id=' + encodeURIComponent(state.caseId) : ''));
  } catch (_err) {
    /* Being signed in is all /mine needs. A failure leaves the form
       without the clearance it would name, and it says so by omission. */
  }
  if (caseChanged(token)) return;
  glassMine = body;
  renderGlassMine(body);
  if (body) renderGlassChip(body);
  fillGlassForm();
  await loadGlassQueue(token);
}

/** The officer's queue. Global rather than case-scoped, which is why the
 *  deployment view can show it with no case open. */
async function loadGlassQueue(token) {
  if (token === undefined) token = caseToken();
  try {
    const q = await api('/break-glass/unreviewed');
    if (caseChanged(token)) return;
    renderList('glass-queue', 'glass-empty', q.grants || [], glassRow);
    $('glass-counts').textContent = (q.count || 0) + ' awaiting review';
  } catch (err) {
    if (caseChanged(token)) return;
    if (err instanceof ApiError && err.status === 403) {
      renderList('glass-queue', 'glass-empty', [], glassRow);
      $('glass-counts').textContent = '';
      $('glass-empty').textContent = refusalText(
        err,
        'The review belongs to the security officer, and only to them: a '
        + 'team that can review its own emergencies is the one thing the '
        + 'separation exists to prevent.');
      return;
    }
    fail(err);
  }
}

/** Reload whatever break-glass view is on screen after a review action. */
function reloadGlass() {
  if (adminView) loadGlassQueue(); else loadBreakGlass();
}

function glassRow(g) {
  const card = el('div', 'card row-card');
  const head = el('div', 'row-head');
  const name = g.user_display_name
    ? visibleText(g.user_display_name)
      + (g.user_email ? ' (' + visibleText(g.user_email) + ')' : '')
    : 'account ' + shortId(g.user_id);
  head.appendChild(el('span', 'row-title', name));
  /* Live, expired and ended early are three different things to judge.
     The card labelled every end time "expired", live grants included. */
  const status = g.revoked_at ? 'ENDED EARLY' : (g.is_live ? 'LIVE' : 'EXPIRED');
  head.appendChild(el('span', 'chip' + (g.is_live ? ' bad' : ''), status));
  /* "raised to RED" only when it did. A grant naming a level the invoker
     already held raised nothing, and the card said otherwise (2026-09-23).
     `raised` compares with their clearance AT INVOKE; it is null for a
     grant from before that was recorded, and then the card says only
     which level was named. */
  const level = g.granted_classification;
  let raise;
  if (!level) raise = 'raised nothing';
  else if (g.raised === true) raise = 'raised ' + g.base_clearance + ' to ' + level;
  else if (g.raised === false) {
    raise = 'named ' + level + ', raised nothing (held ' + g.base_clearance + ')';
  } else raise = 'named ' + level;
  head.appendChild(el('span',
    'chip' + (level && g.raised !== false ? ' tlp-' + level : ''), raise));
  card.appendChild(head);
  const facts = el('div', 'facts');
  facts.appendChild(fact('started', fmtTime(g.started_at)));
  facts.appendChild(fact(g.revoked_at ? 'ended' : (g.is_live ? 'ends' : 'expired'),
    fmtTime(g.revoked_at || g.expires_at)));
  facts.appendChild(fact('scope', g.scope === 'case'
    ? (g.case_code || 'one case') : 'every case they work'));
  const n = g.action_count || 0;
  facts.appendChild(fact('used',
    n ? n + ' access' + (n === 1 ? '' : 'es') : 'none recorded', n ? 'warn' : 'muted'));
  card.appendChild(facts);
  if (g.justification) card.appendChild(el('p', 'why', g.justification));
  if (!n) {
    /* Not "never used". The count covers what GLASS_COUNTED says; the
       grant also widens the graph, the inspector, lists and search, and
       those reads are not counted. Telling the officer "nothing they
       opened needed it" when the analyst had in fact seen material above
       their clearance through a list is the one sentence this card must
       not say (verifier, g06, 2026-09-23; wording final review U19). */
    card.appendChild(el('p', 'help',
      'No access was recorded through it. The count covers each exhibit, '
      + 'capture or message opened above their clearance and each change to '
      + 'an entity above it. The graph, the inspector, lists and search read '
      + 'under the grant are not counted (unless the case is classified '
      + 'above their clearance), so this does not show that nothing above '
      + 'their clearance was seen.'));
  }
  /* Disabled here as the server refuses it there: reviewing your own
     emergency is not a review. Said, rather than left as a 409. */
  if (g.user_id === state.userId) {
    card.appendChild(el('p', 'help warn',
      'This is your own grant. Somebody else has to review it: reviewing '
      + 'your own emergency is not a review.'));
    return card;
  }
  const actions = el('div', 'row-actions');
  const msg = el('p', 'msg');
  msg.hidden = true;
  /* A live grant cannot be reviewed: the server refuses the verdict,
     because a review judges everything done under the grant and while it
     is live that is still growing. Before, a verdict took a live grant
     out of the only list and away from the only End it now (final review
     U2, 2026-09-23). So the card offers the one thing that can be done. */
  if (g.is_live) {
    card.appendChild(el('p', 'help',
      'Still live, so it cannot be reviewed yet. End it now, or review it '
      + 'once it has expired: it stays in this list until it is reviewed.'));
    const end = el('button', 'btn small danger', 'End it now');
    end.type = 'button';
    end.title = 'Revoke the grant at once. The review is still owed afterwards.';
    end.addEventListener('click', async () => {
      if (!window.confirm('End the grant ' + name + ' is operating under, '
          + 'now?\n\nTheir raised clearance stops at once. The review is '
          + 'still owed afterwards: ending a grant is not reviewing it.')) return;
      end.disabled = true;
      try {
        await api('/break-glass/' + g.id + '/revoke', { method: 'POST' });
        reloadGlass();
      } catch (err) {
        end.disabled = false;
        inlineProblem(msg, err);
      }
    });
    actions.appendChild(end);
    card.appendChild(actions);
    card.appendChild(msg);
    return card;
  }
  const note = el('textarea', 'glass-note');
  note.rows = 2;
  /* Required. A permanent finding about a named colleague, written by one
     click with no reasoning, cannot be defended later (ux15 and ux17,
     2026-09-22). The server takes the note; only the console asks for it. */
  note.placeholder = 'Why: the reasoning behind your verdict (required)';
  note.setAttribute('aria-label', 'Review note for ' + name);
  card.appendChild(note);

  const buttons = [];
  for (const [outcome, label, cls] of [
    ['JUSTIFIED', 'Justified', 'btn small'],
    ['INCONCLUSIVE', 'Inconclusive', 'btn small'],
    ['UNJUSTIFIED', 'Not justified', 'btn small danger'],
  ]) {
    const b = el('button', cls, label);
    b.type = 'button';
    b.addEventListener('click', async () => {
      const why = note.value.trim();
      if (why.length < 10) {
        setMsg(msg, 'Write the reasoning first, in at least 10 characters: '
          + 'the verdict is permanent and the note is what defends it.');
        note.focus();
        return;
      }
      /* A review is final at the server: no un-review, no revisit. So the
         verdict is confirmed, naming whose grant it closes and what was
         done under it. */
      if (!window.confirm('Record "' + label + '" for the break-glass '
          + name + ' invoked at ' + fmtTime(g.started_at) + ' ('
          + (n ? n + ' access' + (n === 1 ? '' : 'es') + ' under it'
            : 'no access recorded under it') + ')?\n\n'
          + 'A review is final. It cannot be revisited or undone, and a '
          + 'later disagreement becomes its own record.')) return;
      for (const x of buttons) x.disabled = true;
      try {
        await api('/break-glass/' + g.id + '/review',
          { method: 'POST', json: { outcome, note: why } });
        reloadGlass();
      } catch (err) {
        for (const x of buttons) x.disabled = false;
        inlineProblem(msg, err);
      }
    });
    buttons.push(b);
    actions.appendChild(b);
  }
  card.appendChild(actions);
  card.appendChild(msg);
  return card;
}

async function invokeBreakGlass() {
  const msg = $('glass-msg');
  const out = $('glass-result');
  setMsg(msg, '');
  clear(out);
  const justification = $('glass-why').value.trim();
  const classification = $('glass-level').value;
  const hours = parseInt($('glass-hours').value, 10);
  const scope = $('glass-scope').value;
  /* Never sent without a level. A grant naming none raises nothing and
     still pages every officer, which is the defect this form replaced. */
  if (!classification) {
    setMsg(msg, 'Choose a level. A grant that names none raises nothing, so '
      + 'the console does not send one.');
    return;
  }
  if (justification.length < GLASS_MIN_WHY) {
    setMsg(msg, 'Say what the emergency is in at least ' + GLASS_MIN_WHY
      + ' characters: this is the text a security officer reviews.');
    return;
  }
  const payload = { justification, classification, duration_hours: hours };
  if (scope === 'case' && state.caseId) payload.case_id = state.caseId;
  const btn = $('glass-invoke');
  btn.disabled = true;
  const token = caseToken();
  let g;
  try {
    g = await api('/break-glass', { method: 'POST', json: payload });
  } catch (err) {
    if (!caseChanged(token)) {
      if (err instanceof ApiError && err.status === 403) {
        setMsg(msg, refusalText(err, 'Break-glass needs break_glass.invoke '
          + '(CASE_OWNER or SYS_ADMIN) and a fresh second factor.'));
      } else {
        inlineProblem(msg, err);
      }
      updateGlassEffect();
    }
    return;
  }
  /* The chip first, whatever case is open by now: the grant exists. */
  refreshGlassChip();
  if (caseChanged(token)) return;
  $('glass-why').value = '';
  /* The server's own sentence, verbatim. It is computed from the grant and
     the analyst's own clearance, so it is the one that can say "raises
     nothing", and the console never calls that "Granted". */
  out.appendChild(el('p', g.raises ? 'danger-text glass-granted' : 'help warn',
    g.raises ? 'Emergency access is live.' : 'Recorded, and it raises nothing.'));
  out.appendChild(el('p', 'help', g.notice || ''));
  loadBreakGlass();
}

/** The Lifecycle controls that are not a plain click-to-load. */
function wireGovernanceControls() {
  $('ret-dry').addEventListener('change', syncPurgeButton);
  $('ret-authority').addEventListener('input', () => {
    if (purgePreview
        && purgePreview.authority !== $('ret-authority').value.trim()) {
      show($('ret-destroy-box'), false);
    }
  });
  $('ret-destroy-code').addEventListener('input', syncDestroyGo);
  $('ret-destroy-cancel').addEventListener('click', () => {
    show($('ret-destroy-box'), false);
    $('ret-purge').focus();
  });
  $('ret-destroy-go').addEventListener('click', confirmPurge);
  for (const id of ['glass-scope', 'glass-level', 'glass-hours']) {
    $(id).addEventListener('change', updateGlassEffect);
  }
  $('glass-why').addEventListener('input', updateGlassEffect);
}

/* --- ACH (Phase 6, docs/13 tier 2) -------------------------------------
 *
 * The ranking is by INCONSISTENCY, ascending. That is the whole method and
 * it is counter-intuitive enough that the UI has to say so before it shows
 * a number: the hypothesis that survives is the one with the least
 * evidence AGAINST it, not the most for it. Ranking by support ranks
 * whichever theory the team has been collecting for longest, which is the
 * bias ACH exists to defeat.
 *
 * So `refute_first` is given equal billing with `least_inconsistent`. An
 * ACH matrix that only tells you which hypothesis is winning has been read
 * as a scoreboard, which is the failure mode.
 */

const STANCE_CLASS = {
  '-2': 'st-cc', '-1': 'st-c', '0': 'st-n', '1': 'st-s', '2': 'st-ss',
};

/* The stances the router accepts: `StanceBody.stance` is `Field(ge=-2,
   le=2)` in routers/ach.py and `ach.STANCE_LABEL` names the same five.
   Named ONCE here so `test_ui_invariants` can hold the three copies to
   each other; the wording on screen comes from the response's
   `stance_scale`, so the label is the service's and not a fourth copy. */
const ACH_STANCES = [-2, -1, 0, 1, 2];

async function loadAch() {
  if (!state.caseId) return;
  const q = $('ach-rejected').checked ? '?include_rejected=true' : '';
  const token = caseToken();
  let body;
  try {
    body = await api(cpath('/ach') + q);
  } catch (err) {
    if (caseChanged(token)) return;          // ux17-failure, 2026-09-22
    if (err instanceof ApiError && err.status === 403) {
      clear($('ach-ranking'));
      show($('ach-empty'), true);
      $('ach-empty').textContent =
        'An ACH matrix is an analytical product with a conclusion in it, '
        + 'so reading one needs report.generate rather than case.read.';
      return;
    }
    /* The previous matrix must not stand as this case's conclusions. */
    state.ach = null;
    clear($('ach-ranking'));
    clear($('ach-matrix'));
    clear($('ach-warnings'));
    $('ach-counts').textContent = '';
    showLoadFailure('ach-empty', "This case's ACH matrix", err, loadAch);
    fail(err);
    return;
  }
  if (caseChanged(token)) return;
  clearLoadFailure('ach-empty');
  state.ach = body;
  $('ach-method').textContent = body.method || '';
  renderAchWarnings(body);
  renderAchRanking(body);
  renderAchMatrix(body);
  $('ach-counts').textContent =
    countOf(body.hypotheses.length, 'hypothesis', 'hypotheses') + ' · '
    + countOf(body.evidence.length, 'item of evidence', 'items of evidence');
}

function renderAchWarnings(body) {
  const box = $('ach-warnings');
  clear(box);
  for (const w of body.warnings || []) {
    box.appendChild(el('p', 'help warn', w));
  }
}

function renderAchRanking(body) {
  const box = $('ach-ranking');
  clear(box);
  show($('ach-empty'), body.hypotheses.length === 0);
  if (!body.hypotheses.length) return;

  body.hypotheses.forEach((h, i) => {
    const card = el('div', 'card row-card');
    const head = el('div', 'row-head');
    /* Inconsistency first and in the score slot, because that is what the
       list is ordered by. Putting support there would be showing the
       number the method deliberately does not rank on.
       `against`, not the shared `hot`: `hot` is the accent, which drew the
       losing hypotheses in the colour of the "least inconsistent" chip and
       the "strongly consistent" cells. Evidence against is the matrix's
       red (README screenshot review, 2026-09-23). */
    const score = el('span', 'score' + (h.inconsistency === 0 ? '' : ' against'),
      h.inconsistency.toFixed(1));
    score.title = 'Inconsistency: evidence AGAINST this hypothesis. '
      + 'Lower survives. This is what the ranking uses.';
    head.appendChild(score);
    /* The matrix heads its columns H1, H2, H3 in this order, and a column
       header's statement was only in its tooltip, which a printed or
       captured page never shows (README screenshot review, 2026-09-23). */
    const key = el('span', 'ach-hkey', 'H' + (i + 1));
    key.setAttribute('aria-label', 'Column H' + (i + 1) + ' in the matrix');
    head.appendChild(key);
    head.appendChild(el('span', 'row-title', h.statement));
    if (String(h.id) === body.least_inconsistent) {
      const chip = el('span', 'chip ok', 'least inconsistent');
      chip.title = 'Survives best. NOT "proven": ACH eliminates, it does '
        + 'not confirm.';
      head.appendChild(chip);
    }
    const status = (body.statuses || {})[String(h.id)];
    if (status && status !== 'PROPOSED') {
      head.appendChild(el('span', 'chip', status));
    }
    card.appendChild(head);

    const facts = el('div', 'facts');
    facts.appendChild(fact('support', h.support.toFixed(1), 'muted'));
    facts.appendChild(fact('assessed', h.assessed));
    if (h.unassessed) {
      const f = fact('NOT assessed', h.unassessed, 'warn');
      f.title = 'Evidence nobody has taken a position on against this '
        + 'hypothesis. An unassessed cell is not a neutral one.';
      facts.appendChild(f);
    }
    card.appendChild(facts);
    box.appendChild(card);
  });

  /* `refute_first` is an ASSERTION id (ach.py: "the most diagnostic item
     that some live hypothesis has not yet been scored against"). This pane
     compared it with each HYPOTHESIS id, so it never matched and the half of
     the method the header comment gives equal billing never rendered
     (README screenshot review, 2026-09-23). It is said here, under the
     ranking it could change, and marked on its row in the matrix. */
  const next = achNextTest(body);
  if (next) {
    const line = el('p', 'help ach-next');
    line.appendChild(el('span', 'chip warn', 'next test'));
    /* Read as English for both kinds of row (README screenshot set review,
       2026-09-23): "against H2, H3" became "H2 and H3", "not a neutral"
       lacked its noun, and an unfinished row's diagnosticity is unknown,
       so calling it "the most diagnostic item" claimed what the matrix
       beside it says nobody knows yet. */
    const cols = next.missing.length > 1
      ? next.missing.slice(0, -1).join(', ') + ' and '
        + next.missing[next.missing.length - 1]
      : next.missing[0];
    line.appendChild(document.createTextNode(' Score ' + next.label
      + ' against ' + cols + '. ' + (next.is_incomplete
        ? 'Its row is unfinished, so its diagnosticity is unknown rather '
          + 'than zero, and finishing the row is the cheapest work '
          + 'available here.'
        : 'It is the most diagnostic item with a blank cell, and a blank '
          + 'cell is a gap, not a neutral one.')));
    box.appendChild(line);
  }
}

/** The evidence row `refute_first` names, its label made safe, with the
 *  H numbers it has not been scored against; or null. */
function achNextTest(body) {
  if (!body || !body.refute_first) return null;
  const row = (body.evidence || []).find(
    (e) => String(e.assertion_id) === String(body.refute_first));
  if (!row) return null;
  const scored = new Set((body.cells || [])
    .filter((c) => String(c.assertion_id) === String(row.assertion_id))
    .map((c) => String(c.hypothesis_id)));
  const missing = [];
  (body.hypotheses || []).forEach((h, i) => {
    if (!scored.has(String(h.id))) missing.push('H' + (i + 1));
  });
  if (!missing.length) return null;
  return Object.assign({}, withSafeLabel(row), { missing: missing });
}

/** The grid. Evidence down, hypotheses across.
 *
 *  Every evidence x hypothesis cell is a BUTTON that opens the stance
 *  chooser. Until 2026-09-09 each cell was a `<td>` with a tooltip: the
 *  router had accepted `PUT .../hypotheses/{hid}/stance` since Phase 6 and
 *  the console never called it, so a matrix could be read here and only
 *  ever written with curl -- a pane that looked finished and could not be
 *  driven, which is the shape of defect the Alpha 4 review kept finding.
 */
function renderAchMatrix(body) {
  const box = $('ach-matrix');
  clear(box);
  renderAchHypothesisPicker(body);
  if (!body.hypotheses.length) return;
  if (!body.evidence.length) {
    /* Not silence. A grid that draws nothing is indistinguishable from a
       grid that failed to load, and with hypotheses on the page the
       honest statement is that nobody has scored anything yet. */
    box.appendChild(el('p', 'empty',
      'No evidence has been scored against these hypotheses yet. Score an '
      + 'assertion below to put the first row in the matrix.'));
    return;
  }

  const stance = new Map();
  for (const c of body.cells || []) {
    stance.set(c.assertion_id + '|' + c.hypothesis_id, c.stance);
  }

  const table = el('table', 'ach-table');
  const thead = el('thead');
  const hrow = el('tr');
  hrow.appendChild(el('th', 'ach-eh', 'Evidence'));
  body.hypotheses.forEach((h, i) => {
    const th = el('th', 'ach-hh', 'H' + (i + 1));
    th.title = h.statement;
    hrow.appendChild(th);
  });
  hrow.appendChild(el('th', 'ach-eh', 'Diagnosticity'));
  thead.appendChild(hrow);
  table.appendChild(thead);

  const tbody = el('tbody');
  /* The evidence label is a node label or an edge type name the server
     picked for the row -- attacker-chosen in the IDENTITY case -- so it
     goes through the same boundary sanitiser as every other label. */
  for (const e of body.evidence.map(withSafeLabel)) {
    /* Three states, not two. "Settles nothing" and "we have not finished
       entering this row" both render 0.00 and mean opposite things: one is
       a judgement about the evidence, the other is a gap in the matrix.
       Showing them identically told an analyst their evidence was
       worthless when it was merely half-entered (docs/17 F20). */
    const tr = el('tr', e.is_incomplete ? 'row-incomplete'
      : (e.is_diagnostic ? '' : 'not-diagnostic'));
    const label = el('td', 'ach-el', e.label);
    label.title = e.label + achBasisSuffix(e.assertion_id);
    tr.appendChild(label);
    body.hypotheses.forEach((h, i) => {
      const s = stance.get(e.assertion_id + '|' + h.id);
      const td = el('td', 'ach-cell '
        + (s === undefined ? 'st-none' : (STANCE_CLASS[String(s)] || 'st-n')));
      const text = s === undefined ? '·' : stanceText(s, body);
      const btn = el('button', 'ach-cell-btn', text);
      btn.type = 'button';
      /* So a save can put focus back on THIS cell after the re-render
         replaces it: the button that opened the chooser is gone by then. */
      btn.dataset.assertion = e.assertion_id;
      btn.dataset.hypothesis = String(h.id);
      btn.title = (s === undefined
        ? 'Not assessed. Not the same as neutral.'
        : (h.statement + ': ' + text + '.')) + ' Click to score.';
      btn.setAttribute('aria-label',
        e.label + ' against H' + (i + 1) + ': '
        + (s === undefined ? 'not assessed' : text) + '. Change stance.');
      btn.addEventListener('click', () => openStanceChooser(
        { assertion_id: e.assertion_id, label: e.label }, h, s, btn));
      td.appendChild(btn);
      tr.appendChild(td);
    });
    /* A word, not a dash: the warning above counts these rows as
       "unfinished", and a lone glyph in a numeric column read as "no
       value" rather than "not finished" (README screenshot review,
       2026-09-23). */
    const diag = el('td', 'ach-diag',
      e.is_incomplete ? 'unfinished' : e.diagnosticity.toFixed(2));
    if (e.is_incomplete) {
      diag.title = achUnknownWhy(e, body.hypotheses.length);
    } else if (!e.is_diagnostic) {
      diag.title = 'Says the same thing about every hypothesis, so it '
        + 'discriminates nothing and is excluded from the ranking. Kept in '
        + 'the record rather than deleted.';
    }
    if (String(e.assertion_id) === String(body.refute_first)) {
      const chip = el('span', 'chip warn small', 'next test');
      /* An unfinished row is not "the most diagnostic": its diagnosticity
         is unknown (README screenshot set review, 2026-09-23). */
      chip.title = (e.is_incomplete
        ? 'An unfinished row with a blank cell: '
        : 'The most diagnostic item with a blank cell: ')
        + 'scoring it against the rest is the cheapest next test.';
      diag.appendChild(document.createTextNode(' '));
      diag.appendChild(chip);
    }
    tr.appendChild(diag);
    tbody.appendChild(tr);
  }
  table.appendChild(tbody);
  box.appendChild(table);

  /* The key. "-2" means nothing without it, and a legend below a grid is
     read after the grid has already been misread. */
  const key = el('p', 'help');
  key.textContent = 'Scale: '
    + Object.entries(body.stance_scale || {})
      .sort((a, b) => Number(a[0]) - Number(b[0]))
      .map(([k, v]) => k + ' = ' + v).join(' · ');
  box.appendChild(key);
}

/** Why a row's diagnosticity reads "unfinished". Two cases since ach.py stopped
 *  treating two agreeing cells as a finished row (README screenshot review,
 *  2026-09-23): too few cells to compare, or agreement so far with a
 *  hypothesis still blank, which could be the one it separates. */
function achUnknownWhy(e, live) {
  const n = e.assessed_against || 0;
  if (n < 2) {
    return 'UNKNOWN, not zero. This item has been scored against '
      + (n === 1 ? 'only one hypothesis' : 'no hypotheses')
      + ', so whether it discriminates cannot be said yet. Finishing the '
      + 'row is the cheapest work available here.';
  }
  return 'UNKNOWN, not zero. This item has been scored against ' + n
    + ' of ' + live + ' hypotheses and says the same thing about each so '
    + 'far. The blank one could be the hypothesis it separates, so it is '
    + 'not called undiagnostic until the row is finished.';
}

/** The service's wording for a stance, from the response's `stance_scale`;
 *  the bare number only when the scale is missing. */
function stanceText(s, body) {
  const scale = (body || state.ach || {}).stance_scale || {};
  return scale[String(s)] || String(s);
}

/* --- what a cell rests on ----------------------------------------------
 *
 * routers/ach.py: "Evidence in an ACH matrix is an ASSERTION, not free
 * text" -- every cell inherits the Admiralty grading and the retraction
 * status of the claim behind it. The matrix response names each row by
 * label only, so the basis is remembered from the `/assertions` reads
 * (inspector and scorer) and shown wherever a stance is chosen. Where it
 * has not been read yet, the chooser SAYS so rather than showing nothing:
 * "grading unknown" and "ungraded" are different facts.
 */

function rememberAssertion(a, ownerLabel) {
  if (!a || !a.id) return;
  state.assertionMeta.set(a.id, {
    basis: a.basis, reliability: a.reliability, credibility: a.credibility,
    rationale: a.rationale || null, owner: ownerLabel || null,
    live: !(a.retracted_at || a.superseded_at),
  });
}

/** The selected element's name, for the assertion memory and the scorer. */
function selectionLabel() {
  const sel = state.selection;
  if (!sel) return '';
  if (sel.kind === 'node') return labelOf(sel.id);
  const e = edgeById(sel.id);
  return e ? (e.src_label + ' → ' + e.dst_label) : 'tie ' + shortId(sel.id);
}

function gradingText(meta) {
  return String(meta.reliability) + String(meta.credibility) + ' · '
    + (RELIABILITY[meta.reliability] || 'unknown reliability') + ', '
    + (CREDIBILITY[String(meta.credibility)] || 'unknown credibility');
}

function achBasisSuffix(assertionId) {
  const meta = state.assertionMeta.get(assertionId);
  if (!meta) return '';
  const basis = (BASES.find((b) => b[0] === meta.basis) || [null, meta.basis])[1];
  return ' · ' + basis + ' · Admiralty ' + gradingText(meta);
}

function renderStanceBasis(box, assertionId) {
  clear(box);
  const meta = state.assertionMeta.get(assertionId);
  if (!meta) {
    box.appendChild(el('span', 'help warn',
      'Basis and Admiralty grading not loaded in this console: the matrix '
      + 'names the row and does not carry its grading. Open the element in '
      + 'the inspector, or load its assertions in "Score an assertion", to '
      + 'see what this cell rests on.'));
    return;
  }
  const basis = (BASES.find((b) => b[0] === meta.basis) || [null, meta.basis])[1];
  box.appendChild(el('span', 'assert-basis', basis));
  const grade = el('span', 'grading',
    String(meta.reliability) + String(meta.credibility));
  grade.title = 'Admiralty grading: ' + gradingText(meta);
  box.appendChild(grade);
  box.appendChild(el('span', 'help', 'Admiralty ' + gradingText(meta)));
  if (meta.owner) box.appendChild(el('span', 'help', 'on ' + meta.owner));
  if (meta.rationale) box.appendChild(el('span', 'help', meta.rationale));
}

/* --- the stance chooser --------------------------------------------------
 *
 * One dialog for every cell and for a first score from the picker. The
 * five options are ACH_STANCES with the service's labels; the note is
 * offered, not demanded: `core.hypothesis_evidence.note` is nullable
 * (0007), `StanceBody.note` defaults to None and the service never reads
 * it, and a client that refuses what the server accepts is inventing a
 * rule the audit trail cannot see.
 */

let _stanceCtx = null;   // {assertionId, label, hypothesis, current, back}

function openStanceChooser(evidence, hypothesis, current, returnFocus) {
  _stanceCtx = {
    assertionId: evidence.assertion_id, label: evidence.label,
    hypothesis: hypothesis, current: current, back: returnFocus || null,
  };
  $('ach-stance-evidence').textContent = evidence.label;
  renderStanceBasis($('ach-stance-basis'), evidence.assertion_id);
  $('ach-stance-hypothesis').textContent = hypothesis.statement;

  const fs = $('ach-stance-options');
  while (fs.lastChild && fs.lastChild.tagName !== 'LEGEND') {
    fs.removeChild(fs.lastChild);
  }
  for (const s of ACH_STANCES) {
    const lab = el('label', 'stance-option ' + (STANCE_CLASS[String(s)] || ''));
    const r = el('input');
    r.type = 'radio';
    r.name = 'ach-stance';
    r.value = String(s);
    if (current === s) r.checked = true;
    lab.appendChild(r);
    lab.appendChild(el('span', 'stance-k', (s > 0 ? '+' : '') + s));
    lab.appendChild(el('span', null, stanceText(s)));
    fs.appendChild(lab);
  }
  $('ach-stance-note').value = '';
  setMsg($('ach-stance-msg'), '');
  $('ach-stance-save').disabled = false;
  show($('ach-stance-scrim'), true);
  const first = fs.querySelector('input:checked') || fs.querySelector('input');
  if (first) first.focus();
}

function closeStanceChooser() {
  show($('ach-stance-scrim'), false);
  const back = _stanceCtx && _stanceCtx.back;
  _stanceCtx = null;
  if (back && document.contains(back)) back.focus();
}

/** Tab stays inside the dialog while it is open; Escape closes it. */
function stanceChooserKeys(e) {
  if (e.key === 'Escape') { e.preventDefault(); closeStanceChooser(); return; }
  if (e.key !== 'Tab') return;
  const focusable = Array.from($('ach-stance-form').querySelectorAll(
    'input, textarea, button')).filter((n) => !n.disabled);
  if (!focusable.length) return;
  const first = focusable[0], last = focusable[focusable.length - 1];
  if (e.shiftKey && document.activeElement === first) {
    e.preventDefault(); last.focus();
  } else if (!e.shiftKey && document.activeElement === last) {
    e.preventDefault(); first.focus();
  }
}

async function saveStance(event) {
  event.preventDefault();
  const ctx = _stanceCtx;
  if (!ctx) return;
  const msg = $('ach-stance-msg');
  const picked = $('ach-stance-options').querySelector('input:checked');
  if (!picked) { setMsg(msg, 'Choose a stance.'); return; }
  const note = $('ach-stance-note').value.trim();
  $('ach-stance-save').disabled = true;
  try {
    await api(cpath('/ach/hypotheses/' + ctx.hypothesis.id + '/stance'), {
      method: 'PUT',
      json: { assertion_id: ctx.assertionId, stance: Number(picked.value),
              note: note || null },
    });
    closeStanceChooser();
    /* Re-read rather than patch the cell: the ranking, the diagnosticity
       column and the service's warnings all move with one stance, and
       loadAch renders the warnings through the pane's existing path. */
    await loadAch();
    /* The re-render replaced every cell, so the focus closeStanceChooser
       put back landed on a detached button and fell to <body>. Find the
       same cell in the new grid; a keyboard user scoring a row must not
       be thrown back to the top of the page after every save. */
    const again = document.querySelector(
      '.ach-cell-btn[data-assertion="' + ctx.assertionId + '"]'
      + '[data-hypothesis="' + ctx.hypothesis.id + '"]');
    if (again) again.focus();
  } catch (err) {
    inlineProblem(msg, err);
  } finally {
    $('ach-stance-save').disabled = false;
  }
}

/* --- putting a first row in the matrix ---------------------------------
 *
 * A cell exists only once an assertion has a stance against some
 * hypothesis, so a matrix with hypotheses and no evidence has nothing to
 * click. The scorer reads the live assertions of the element selected in
 * the graph (the same `/assertions` read the inspector makes) and opens
 * the chooser for one of them; after that first save the row is in the
 * grid and every other cell is a click.
 */

function assertionOptionLabel(a) {
  const basis = (BASES.find((b) => b[0] === a.basis) || [null, a.basis])[1];
  const why = a.rationale ? visibleText(a.rationale) : 'no rationale recorded';
  const short = why.length > 70 ? why.slice(0, 67) + '…' : why;
  return basis + ' · ' + a.reliability + a.credibility + ' · ' + short;
}

function renderAchHypothesisPicker(body) {
  const hyp = $('ach-evidence-hyp');
  const keep = hyp.value;
  const pairs = body.hypotheses.map((h, i) => [h.id, 'H' + (i + 1) + ': '
    + h.statement]);
  opts(hyp, pairs.length ? pairs : [['', 'Add a hypothesis first']],
       pairs.some((p) => p[0] === keep) ? keep : (pairs.length ? pairs[0][0] : ''));
  hyp.disabled = !pairs.length;
  updateAchScoreControls();
}

function updateAchScoreControls() {
  $('ach-evidence-add').disabled =
    !($('ach-evidence-pick').value && $('ach-evidence-hyp').value);
}

async function loadAchEvidenceOfSelection() {
  const msg = $('ach-evidence-msg');
  setMsg(msg, '');
  const pick = $('ach-evidence-pick');
  const sel = state.selection;
  if (!sel) {
    setMsg(msg, 'Select an entity or a tie in the graph first. Its live '
      + 'assertions are the evidence this matrix can score.');
    return;
  }
  const base = cpath((sel.kind === 'node' ? '/nodes/' : '/edges/') + sel.id);
  let list;
  try {
    list = await api(base + '/assertions?include_retracted=false');
  } catch (err) {
    inlineProblem(msg, err);
    return;
  }
  const owner = selectionLabel();
  const live = (list || []).filter((a) => !a.retracted_at && !a.superseded_at);
  for (const a of live) rememberAssertion(a, owner);
  state.achPick = live;
  $('ach-evidence-of').textContent = owner + ' · ' + live.length
    + ' live assertion' + (live.length === 1 ? '' : 's');
  opts(pick, live.length
    ? live.map((a) => [a.id, assertionOptionLabel(a)])
    : [['', 'No live assertions on this element']],
  live.length ? live[0].id : '');
  pick.disabled = !live.length;
  updateAchScoreControls();
}

function scorePickedAssertion() {
  const aid = $('ach-evidence-pick').value;
  const hid = $('ach-evidence-hyp').value;
  if (!aid || !hid || !state.ach) return;
  const h = (state.ach.hypotheses || []).find((x) => String(x.id) === hid);
  if (!h) return;
  const meta = state.assertionMeta.get(aid);
  const existing = (state.ach.cells || []).find(
    (c) => c.assertion_id === aid && c.hypothesis_id === hid);
  const row = (state.ach.evidence || []).find((e) => e.assertion_id === aid);
  const label = row ? visibleText(row.label)
    : ((meta && meta.owner) || 'assertion ' + shortId(aid));
  openStanceChooser({ assertion_id: aid, label: label }, h,
    existing ? existing.stance : undefined, $('ach-evidence-add'));
}

async function addHypothesis() {
  const msg = $('ach-msg');
  setMsg(msg, '');
  const statement = $('ach-statement').value.trim();
  try {
    await api(cpath('/ach/hypotheses'), {
      method: 'POST',
      json: { statement, confidence: $('ach-confidence').value },
    });
    $('ach-statement').value = '';
    loadAch();
  } catch (err) { inlineProblem(msg, err); }
}

/* --- PGP verification and co-participation (Phase 7) --------------------
 *
 * PGP is the one path in this phase that produces a CONFIRMATION rather
 * than a claim, so it is the one place where being wrong is worst —
 * docs/10 says a CONFIRMED binding may carry weight in automatic identity
 * resolution.
 *
 * The outcomes are therefore rendered as three visually distinct classes,
 * not as pass/fail:
 *
 *   VERIFIED             — cryptographic evidence of control
 *   BAD_SIGNATURE,
 *   KEY_MISMATCH,
 *   VALUE_NOT_IN_PAYLOAD — checked, and it did not hold
 *   NO_VERIFIER          — NOBODY CHECKED
 *
 * That last one is the reason this is not a boolean. "Nobody checked" and
 * "checked and failed" must never look the same, or an unchecked claim
 * reads as a checked-and-rejected one and an analyst discounts a real
 * lead — or, worse, treats an unavailable verifier as a refutation.
 */

const PGP_GOOD = 'VERIFIED';
const PGP_UNCHECKED = new Set(['NO_VERIFIER', 'KEY_UNAVAILABLE', 'MALFORMED']);

async function verifyPgp(e) {
  e.preventDefault();
  const msg = $('comms-pgp-msg');
  const out = $('comms-pgp-out');
  setMsg(msg, '');
  clear(out);
  const token = caseToken();
  try {
    const body = await api(cpath('/comms/pgp/verify'), {
      method: 'POST',
      json: {
        signed_message: $('comms-pgp-message').value,
        public_key: $('comms-pgp-key').value,
        claimed_fingerprint: $('comms-pgp-fpr').value.trim(),
        confirms_value: $('comms-pgp-confirms').value.trim() || null,
      },
    });
    /* The verdict belongs to the case it was posted to; after a switch it
       would read as the new case's binding. */
    if (caseChanged(token)) return;
    out.appendChild(pgpOutcome(body));
    loadUnverified();
  } catch (err) {
    if (caseChanged(token)) return;
    inlineProblem(msg, err);
  }
}

function pgpOutcome(body) {
  const outcome = body.outcome || 'MALFORMED';
  const card = el('div', 'card row-card');
  const head = el('div', 'row-head');
  const chip = el('span', 'chip '
    + (outcome === PGP_GOOD ? 'ok'
      : (PGP_UNCHECKED.has(outcome) ? 'warn' : 'bad')), outcome);
  head.appendChild(chip);
  head.appendChild(el('span', 'row-title',
    outcome === PGP_GOOD ? 'Cryptographic evidence of control'
      : (PGP_UNCHECKED.has(outcome)
        ? 'Nobody checked, so this is not a finding about the evidence'
        : 'Checked, and it did not hold')));
  card.appendChild(head);

  const facts = el('div', 'facts');
  if (body.signing_fingerprint) {
    facts.appendChild(fact('signed by',
      String(body.signing_fingerprint).slice(0, 16)));
  }
  if (body.value_in_payload !== undefined) {
    facts.appendChild(fact('identifier inside the signed region',
      body.value_in_payload ? 'yes' : 'no',
      body.value_in_payload ? '' : 'bad'));
  }
  if (body.binding_upgraded) {
    facts.appendChild(fact('binding', 'upgraded to CONFIRMED', 'warn'));
  }
  card.appendChild(facts);
  if (body.detail || body.note) {
    card.appendChild(el('p', 'why', body.detail || body.note));
  }
  if (PGP_UNCHECKED.has(outcome)) {
    card.appendChild(el('p', 'help warn',
      'A failure to LOOK, not a finding about the evidence. The binding '
      + 'stays CLAIMED and should be checked again when a verifier is '
      + 'available.'));
  }
  return card;
}

/* Every comms result on this pane was read from, or written into, ONE
 * case: the correlation says "binding(s) in this case", the contact block
 * and the PGP verdict were posted to it, and the co-participation network
 * is the case's own. case-switch-carries-previous-case-results
 * (2026-09-22) named the co-participation and PGP output; the rest share
 * the fault and go with them. The empties return to their markup wording
 * so a refusal read in the previous case does not stand in this one. */
/* Id, markup wording, and whether it may show before the read: the
   unverified queue loads with the pane, so "Nothing awaiting
   verification." would be a claim made before asking; co-participation
   sits behind Load, so "none computed" is simply true until it is. */
const COMMS_EMPTY_TEXT = [
  ['comms-unverified-empty', 'Nothing awaiting verification.', false],
  ['comms-copart-empty', 'No co-participation computed for this case.', true],
];

onCaseSwitch(() => {
  for (const id of ['comms-pgp-out', 'comms-correlate-out', 'comms-block-out',
                    'comms-unverified', 'comms-copart',
                    'comms-copart-coverage']) {
    clear($(id));
  }
  setMsg($('comms-pgp-msg'), '');
  setMsg($('comms-block-msg'), '');
  setMsg($('comms-bind-msg'), '');
  $('comms-unverified-count').textContent = '';
  $('comms-copart-count').textContent = '';
  for (const [id, text, before] of COMMS_EMPTY_TEXT) {
    $(id).textContent = text;
    show($(id), before);
    clearLoadFailure(id);
  }
  /* What was typed or pasted belongs to the case it was typed in. A
     contact block pasted on NIGHTJAR and submitted after a switch would be
     parsed into KESTREL, and its proposals raised there (verifier, fix
     round of 2026-09-22). The platform pickers stay: they are a global
     list, not case material. */
  for (const id of ['comms-observed', 'comms-codecl', 'comms-corr-observed',
                    'comms-block-source', 'comms-block-handle',
                    'comms-block-text', 'comms-pgp-message', 'comms-pgp-key',
                    'comms-pgp-fpr', 'comms-pgp-confirms']) {
    $(id).value = '';
  }
  show($('comms-preview'), false);
});

/** The case a write was sent to, by the name the analyst knows it by. A
 *  write whose reply lands after a switch is reported against this rather
 *  than in the new case's pane. */
function caseCodeNow() {
  return state.caseRec && state.caseRec.code
    ? state.caseRec.code : shortId(state.caseId);
}

async function loadUnverified() {
  if (!state.caseId) return;
  const token = caseToken();
  try {
    const body = await api(cpath('/comms/pgp/unverified'));
    if (caseChanged(token)) return;
    const claims = body.claims || [];
    renderList('comms-unverified', 'comms-unverified-empty', claims,
      (c) => {
        const card = el('div', 'card row-card compact');
        const head = el('div', 'row-head');
        head.appendChild(el('span', 'row-title',
          c.observed_value || c.durable_value || c.id));
        head.appendChild(el('span', 'chip', c.platform_key || '?'));
        /* The split the endpoint exists for. Without it, "not confirmed"
           and "not checked" look identical. */
        head.appendChild(c.attempted
          ? el('span', 'chip bad', 'checked, not confirmed')
          : el('span', 'chip warn', 'never checked'));
        card.appendChild(head);
        if (c.last_outcome) card.appendChild(el('p', 'why', c.last_outcome));
        return card;
      });
    $('comms-unverified-count').textContent = claims.length
      ? countOf(claims.length, 'claim', 'claims') : '';
  } catch (err) {
    if (caseChanged(token)) return;
    if (err instanceof ApiError && err.status === 403) {
      renderList('comms-unverified', 'comms-unverified-empty', [], () => el('div'));
      $('comms-unverified-empty').textContent = refusalText(
        err, 'This needs comms.read on the case.');
      return;
    }
    /* Not "Nothing awaiting verification.": that is a finding about the
       claims, and this read produced none (ux17-failure, 2026-09-22). */
    renderList('comms-unverified', 'comms-unverified-empty', [], () => el('div'));
    $('comms-unverified-count').textContent = '';
    showLoadFailure('comms-unverified-empty', 'The unverified claims', err,
      loadUnverified);
    fail(err);
  }
}

/* Co-participation coverage: what was left OUT of the network.
 *
 * `coparticipation.py` states the rule this renders — "a cap that silently
 * drops data is worse than no cap, because the output looks complete" —
 * and then reports every exclusion so the analyst can tell a sparse network
 * from a filtered one. The browser dropped all of it: it read
 * `body.warnings`, a key the service has never emitted. So the one cap the
 * module refuses to apply silently was, on screen, silent.
 *
 * Rendered even when nothing was excluded. "Nothing was excluded" is a
 * finding about the network; a blank space is not.
 */
function renderCoParticipationCoverage(body) {
  const host = $('comms-copart-coverage');
  clear(host);
  const cov = body && body.coverage;
  if (!cov) return;

  const facts = el('div', 'facts');
  facts.appendChild(fact('rooms seen', cov.conversations_seen));
  facts.appendChild(fact('projected', cov.conversations_projected));
  facts.appendChild(fact('too small', cov.conversations_too_small));
  facts.appendChild(fact('oversized', cov.conversations_oversized,
    cov.conversations_oversized ? 'warn' : ''));
  facts.appendChild(fact('excluded: incidental',
    cov.participants_excluded_incidental));
  facts.appendChild(fact('excluded: unresolved',
    cov.participants_excluded_unresolved));
  /* Not-visible is a CLEARANCE fact, not a data-quality one: the network is
     smaller because of who is asking. Kept distinct for that reason. */
  facts.appendChild(fact('excluded: not visible to you',
    cov.participants_excluded_not_visible,
    cov.participants_excluded_not_visible ? 'warn' : ''));
  host.appendChild(facts);

  for (const room of cov.oversized || []) {
    host.appendChild(el('p', 'help warn',
      'Room ' + visibleText(room.conversation_id)
      + ' on ' + visibleText(room.platform)
      + ' excluded: ' + room.participants + ' participants ('
      + room.projectable_participants + ' projectable)'
      + (room.provenance_class
        ? ' · ' + visibleText(room.provenance_class) : '')));
  }
  if (cov.note) host.appendChild(el('p', 'help', cov.note));
  if (body.reading) host.appendChild(el('p', 'help', body.reading));
}

async function loadCoParticipation() {
  if (!state.caseId) return;
  const token = caseToken();
  try {
    const body = await api(cpath('/comms/co-participation'));
    if (caseChanged(token)) return;
    const ties = body.edges || [];
    /* An edge carries vertex KEYS (`node:<uuid>` / `handle:<h>`), never a
       label — so the map is not decoration. Without it this pane cannot
       name anybody, which is how it came to render "undefined — undefined"
       on every row while looking populated.

       `visibleText` is mandatory and not defensive habit: a HANDLE vertex's
       label is a string the subject chose on a forum. A right-to-left
       override in it reorders the two names either side of the dash, so the
       tie reads backwards while the DOM says otherwise. */
    const labels = new Map();
    for (const n of body.nodes || []) {
      labels.set(n.key, visibleText(n.label || n.key));
    }
    const name = (key) => labels.get(key) || visibleText(key);
    const weighting = (body.projection || {}).weighting;
    renderList('comms-copart', 'comms-copart-empty', ties, (t) => {
      const card = el('div', 'card row-card compact');
      const head = el('div', 'row-head');
      const w = Number(t.weight || 0);
      head.appendChild(el('span', 'score', w.toFixed(2)));
      head.appendChild(el('span', 'row-title',
        name(t.src) + ' and ' + name(t.dst)));
      /* Invariant 4: an inferred edge stays visually distinct and never
         silently becomes an asserted one. */
      head.appendChild(el('span', 'chip warn', 'inferred'));
      card.appendChild(head);
      const facts = el('div', 'facts');
      facts.appendChild(fact('shared rooms', t.shared_conversations));
      if (t.inference_method) {
        facts.appendChild(fact('method', t.inference_method));
      }
      card.appendChild(facts);
      return card;
    });
    /* Weighting is a property of the RUN, not of a tie, and the service
       says weights are not comparable across parameters — so it is stated
       once for the network rather than repeated on every row. */
    $('comms-copart-count').textContent = ties.length
      ? countOf(ties.length, 'inferred tie', 'inferred ties')
        + (weighting ? ' · ' + weighting + ' weighting' : '')
      : '';
    renderCoParticipationCoverage(body);
  } catch (err) {
    if (caseChanged(token)) return;
    if (err instanceof ApiError && (err.status === 403 || err.status === 400)) {
      renderList('comms-copart', 'comms-copart-empty', [], () => el('div'));
      /* The count and the coverage block describe the PREVIOUS successful
         load. Left standing under a refusal they attribute one case's
         network to another — and a refusal is not an empty state. */
      $('comms-copart-count').textContent = '';
      clear($('comms-copart-coverage'));
      $('comms-copart-empty').textContent = refusalText(
        err, 'Co-participation needs comms.read on the case.');
      return;
    }
    /* Any other failure: the same reasoning as the refusal above, which
       only ever cleared on 403 and 400 (ux17-failure, 2026-09-22). */
    renderList('comms-copart', 'comms-copart-empty', [], () => el('div'));
    $('comms-copart-count').textContent = '';
    clear($('comms-copart-coverage'));
    showLoadFailure('comms-copart-empty', 'Co-participation', err,
      loadCoParticipation);
    fail(err);
  }
}

/* --- Report (Phase 6, docs/08) -----------------------------------------
 *
 * Build and release are two controls because they are two decisions, and
 * one control that did both would be a single click between a case file
 * and somebody's inbox.
 *
 * The redaction statement is rendered FIRST and prominently, above the
 * document. A report that quietly omitted eleven nodes and said so in a
 * footer is a report somebody quotes as complete.
 *
 * Three rules added by the review of 2026-09-22 (ux15-report and
 * ux02-cases), each of which the pane used to break:
 *
 *  - The preview IS the document. It printed every relationship as
 *    "undefined -> undefined" (it read field names the server has never
 *    sent) and left out the legal basis, the assumptions with their
 *    authors' names and the hypothesis statements, all of which were in
 *    the file. It now lists those, and shows the exact text beneath.
 *  - A file comes out of the egress decision and nothing else. "Download
 *    markdown" fetched its own build, with no step-up and no gate, so a
 *    RED document went to disk one click after Prepare; the check beside
 *    it judged a third build, with hypotheses on regardless. Now the only
 *    Save is the document the gate just cleared, offered only when its
 *    digest matches the preview's.
 *  - Nothing survives a change of case, or of the choices it was made
 *    with. A NIGHTJAR preview and a "May leave" line stood under a KESTREL
 *    header while Check egress acted on KESTREL. Any change to the target,
 *    hypotheses, destination, ceiling or note now withdraws what depended
 *    on it, as the target select alone used to.
 */

/** The /release answer the Save button would write, or null. Held apart
 *  from the preview because it is withdrawn more often: a new destination
 *  voids the verdict without voiding what was prepared. */
let reportCleared = null;

/* Generation counters for the two requests this pane makes. A reset
   withdraws what is on screen, but a Prepare or Check egress still in
   flight used to land afterwards and put back the very thing the reset
   removed: an AMBER preview under a control that now said GREEN, or a
   "May leave ... to smtp" verdict, with its Save, under a destination
   that now said in_app (verifier, ux15-report fix round, 2026-09-22).
   Every reset bumps its counter, and a reply whose counter has moved on
   is dropped. The case token cannot do this job: the case did not
   change, the choices did. */
let reportGen = 0;
let verdictGen = 0;
/* Whether a Prepare or a Check egress is in flight, so the control that
   withdrew it can say so. Without a word the analyst sees a click that
   did nothing. */
let reportPending = false;
let verdictPending = false;

/** Withdraw the egress verdict and the Save it enabled. */
function resetReportVerdict() {
  verdictGen += 1;
  verdictPending = false;
  reportCleared = null;
  clear($('rep-release-out'));
  setMsg($('rep-release-msg'), '');
  show($('rep-download'), false);
}

/** Back to "nothing prepared". */
function resetReport() {
  reportGen += 1;
  reportPending = false;
  state.report = null;
  resetReportVerdict();
  setMsg($('rep-msg'), '');
  clear($('rep-redaction'));
  clear($('rep-body'));
  show($('rep-release-box'), false);
  show($('rep-empty'), true);
}

/** A change to the target or to Include hypotheses: what was prepared
 *  (or is being prepared) was made with the old value. */
function withdrawReport() {
  const pending = reportPending || verdictPending;
  resetReport();
  if (pending) {
    setMsg($('rep-msg'), 'The target or Include hypotheses changed while a '
      + 'request was running, so its answer was set aside. Prepare again.');
  }
}

/** A change to the destination, ceiling or note: the verdict (given or
 *  still being asked for) was about the old one. */
function withdrawReportVerdict() {
  const pending = verdictPending;
  resetReportVerdict();
  if (pending) {
    setMsg($('rep-release-msg'), 'The destination, ceiling or note changed '
      + 'while the check was running, so its answer was set aside. Check '
      + 'again.');
  }
}

/* The preview, the verdict and the controls all belong to the case they
   were set in. The controls go back to their markup defaults as well: a
   target of GREEN chosen on NIGHTJAR stayed GREEN on KESTREL in the ux15
   capture, which is a choice nobody made for KESTREL. */
onCaseSwitch(() => {
  resetReport();
  $('rep-tlp').value = 'AMBER';
  $('rep-hypotheses').checked = true;
  $('rep-destination').value = 'export';
  $('rep-ceiling').value = '';
  $('rep-note').value = '';
});

async function buildReport() {
  if (!state.caseId) return;
  const token = caseToken();
  resetReport();
  const gen = reportGen;
  reportPending = true;
  const params = {
    target_tlp: $('rep-tlp').value,
    include_hypotheses: $('rep-hypotheses').checked,
    /* The whole case, stated rather than implied. The builder has its own
       projection (asserted ties, no as-of), so the graph's current preset
       and as-of do NOT apply, and the preview says so. */
    preset: 'all',
  };
  const q = new URLSearchParams({
    target_tlp: params.target_tlp,
    include_hypotheses: params.include_hypotheses ? 'true' : 'false',
    preset: params.preset,
  });
  try {
    const body = await api(cpath('/report') + '?' + q.toString(),
      { method: 'POST' });
    /* A newer case, or a newer choice or Prepare, has withdrawn this. */
    if (caseChanged(token) || gen !== reportGen) return;
    reportPending = false;
    state.report = {
      body: body,
      params: params,
      caseId: state.caseId,
      caseCode: state.caseRec ? state.caseRec.code : shortId(state.caseId),
      graphAsOf: state.proj.as_of,
    };
    show($('rep-empty'), false);
    renderRedaction(state.report);
    renderReportBody(body);
    show($('rep-release-box'), true);
  } catch (err) {
    if (caseChanged(token) || gen !== reportGen) return;
    reportPending = false;
    inlineProblem($('rep-msg'), err);
  }
}

/** Save the document the egress gate cleared: the same bytes, the name
 *  the server gave them (classification included, because a file saved
 *  out of a browser loses everything that was only on the page).
 *
 *  The anchor is appended before the click and the object URL revoked a
 *  moment later rather than at once: a detached anchor or a URL revoked
 *  in the same turn is a download that silently never starts in some
 *  browsers. */
function saveClearedReport() {
  const cleared = reportCleared;
  if (!cleared || typeof cleared.document !== 'string') return;
  const blob = new Blob([cleared.document], { type: 'text/markdown' });
  const url = URL.createObjectURL(blob);
  const link = el('a');
  link.href = url;
  link.download = cleared.filename || 'report.md';
  document.body.appendChild(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

/** What was left OUT, and what the preview was made from. The most
 *  important card on the pane. */
function renderRedaction(prepared) {
  const box = $('rep-redaction');
  clear(box);
  const body = prepared.body;
  const r = body.redaction || {};
  const card = el('div', 'card row-card');
  const head = el('div', 'row-head');
  head.appendChild(el('span', 'row-title', 'Prepared at'));
  head.appendChild(el('span', 'chip tlp-' + (r.built_at_tlp || ''),
    r.built_at_tlp || '?'));
  card.appendChild(head);

  /* Which case, when, and from what. Without these a preview carried
     across a case switch looked exactly like one prepared here. */
  const made = el('div', 'facts');
  made.appendChild(fact('case', prepared.caseCode));
  made.appendChild(fact('prepared', fmtTime(body.generated_at)));
  /* What the builder reads: the case as it stands now (no as-of), its
     asserted social ties only (preset 'all', include_inferred=False in
     reports.py). "The whole case" was false beside a relationship count
     smaller than the case's own: inferred ties and non-social types such
     as CONTROLS and USED are in the case and never in a report (README
     screenshot set review, 11-report). */
  made.appendChild(fact('built from',
    'the case as it stands now, asserted social ties only'));
  /* Asked for is not the same as in the document: a case whose header is
     above the target keeps its hypotheses with it (final review C2). */
  made.appendChild(fact('hypotheses',
    !prepared.params.include_hypotheses ? 'left out'
      : (r.hypotheses_withheld ? 'withheld with the case header'
        : 'included'),
    prepared.params.include_hypotheses && r.hypotheses_withheld ? 'warn' : ''));
  card.appendChild(made);
  if (prepared.graphAsOf) {
    card.appendChild(el('p', 'help warn',
      'The graph is showing the case as of ' + fmtTime(prepared.graphAsOf)
      + '. A report is always built from the case as it stands now, so this '
      + 'document can contain material the graph is not showing.'));
  }

  const facts = el('div', 'facts');
  const withheld = (r.nodes_withheld || 0) + (r.edges_withheld || 0)
    + (r.evidence_withheld || 0);
  facts.appendChild(fact('entities withheld', r.nodes_withheld || 0,
    r.nodes_withheld ? 'warn' : ''));
  facts.appendChild(fact('relationships withheld', r.edges_withheld || 0,
    r.edges_withheld ? 'warn' : ''));
  facts.appendChild(fact('exhibits withheld', r.evidence_withheld || 0,
    r.evidence_withheld ? 'warn' : ''));
  /* Only when there is some: the matrix's scores leave these out (C2). */
  if (r.hypothesis_evidence_withheld) {
    facts.appendChild(fact('hypothesis evidence withheld',
      r.hypothesis_evidence_withheld, 'warn'));
  }
  card.appendChild(facts);

  const anything = withheld || r.header_withheld || r.assumptions_withheld
    || r.hypotheses_withheld || r.hypothesis_evidence_withheld;
  /* The statement is the document's own Markdown sentence, which bolds
     "Every figure below is computed over the redacted graph" with `**`.
     Printed through textContent, the card showed the asterisks the moment
     anything was withheld (README screenshot review, 2026-09-23). */
  card.appendChild(withStrongRuns(el('p', anything ? 'why prose' : 'help'),
    r.statement || (withheld
      ? withheld + ' element(s) were withheld from this document.'
      : 'Nothing was withheld at this classification.')));
  box.appendChild(card);
}

/** Append `text` to `node`, with each `**run**` as a <strong> and the rest
 *  as text nodes. Markup is never parsed: the only thing read is the `**`
 *  pair, so a stray `<` in a statement is shown as a `<`. An unpaired `**`
 *  is left as written rather than guessed at. */
function withStrongRuns(node, text) {
  const parts = String(text || '').split('**');
  const paired = parts.length % 2 === 1;
  parts.forEach((part, i) => {
    if (!paired && i === parts.length - 1 && i % 2 === 1) {
      node.appendChild(document.createTextNode('**' + part));
    } else if (i % 2 === 1) {
      node.appendChild(el('strong', null, part));
    } else if (part) {
      node.appendChild(document.createTextNode(part));
    }
  });
  return node;
}

/** One named list in the preview, capped so a large case stays readable;
 *  the full text below always has everything. */
function reportList(box, title, rows, render, none) {
  box.appendChild(el('h2', 'h-sm', title + ' (' + rows.length + ')'));
  const list = el('div', 'hit-list');
  if (!rows.length) {
    list.appendChild(el('p', 'empty', none || 'None at this classification.'));
  }
  for (const row of rows.slice(0, 100)) list.appendChild(render(row));
  if (rows.length > 100) {
    list.appendChild(el('p', 'help',
      (rows.length - 100) + ' more are in the full text below.'));
  }
  box.appendChild(list);
}

/** A preview row: the text, then any flags as chips. */
function reportRow(text, flags) {
  const row = el('div', 'entry-row');
  row.appendChild(el('span', null, text));
  for (const [label, cls] of flags || []) {
    row.appendChild(el('span', 'chip small' + (cls ? ' ' + cls : ''), label));
  }
  return row;
}

const REPORT_SIGN = { '1': 'positive', '-1': 'negative', '0': 'neutral' };

function renderReportBody(body) {
  const box = $('rep-body');
  clear(box);
  const summary = body.summary || {};
  const hyp = (body.hypotheses || {}).hypotheses || [];
  const counts = el('div', 'facts');
  for (const [label, value] of [
    ['entities', summary.entities],
    ['relationships', summary.relationships],
    ['exhibits', summary.exhibits],
    ['hypotheses', body.hypotheses && body.hypotheses.hypotheses
      ? hyp.length : null],
  ]) {
    if (value !== undefined && value !== null) {
      counts.appendChild(fact(label, value));
    }
  }
  if (summary.truncated) {
    const f = fact('', 'TRUNCATED', 'warn');
    f.title = 'The projection hit its size cap. This document does not '
      + 'describe the whole case.';
    counts.appendChild(f);
  }
  if (counts.childNodes.length) box.appendChild(counts);

  if (summary.computed_over) {
    /* A metric without its projection is not reproducible (docs/03), so
       the projection travels with the numbers rather than being implied
       by them. */
    box.appendChild(el('p', 'help', 'Computed over ' + summary.computed_over));
  }

  /* The authority the material was collected under: in the file, so on
     the screen. */
  const c = body.case || {};
  box.appendChild(el('h2', 'h-sm', 'Authority and retention'));
  const auth = el('div', 'facts');
  auth.appendChild(fact('legal basis', c.legal_basis));
  auth.appendChild(fact('authority', c.authority_ref || 'not recorded'));
  /* A withheld header sends its dates as null, and "not recorded" would
     say the case has none. The markdown prints the withheld mark for them
     (reports.WITHHELD_MARK), and so does this preview: the server already
     put that mark in legal_basis, so the two cannot drift (README
     screenshot review, 2026-09-23). */
  const headerOut = !!(body.redaction && body.redaction.header_withheld);
  const headerDate = (v) => (headerOut && !v ? c.legal_basis : fmtDate(v));
  auth.appendChild(fact('retention until', headerDate(c.retention_until)));
  auth.appendChild(fact('next review', headerDate(c.review_due)));
  box.appendChild(auth);

  /* Named lists, so an analyst can see WHAT survived the redaction rather
     than only how much was removed. `textContent` throughout: these are
     labels that came from a forum. The server sends `type`, `src` and
     `dst`; a relationship names its ends through the actor list, which
     always holds both (the projection admits a tie only when both ends
     are visible at this classification). */
  const labelOf = new Map((body.actors || []).map((a) => [a.id, a.label]));
  const unevidenced = ['not evidenced', 'warn'];

  const assumptions = body.assumptions || [];
  const assumptionsWithheld = (body.redaction || {}).assumptions_withheld || 0;
  if (assumptions.length || !assumptionsWithheld) {
    reportList(box, 'Assumptions', assumptions, (a) => reportRow(
      a.statement + ' (' + a.status + ', made by ' + (a.made_by_name || '?')
      + ', ' + (a.reviewed_at ? 'reviewed' : 'not yet reviewed') + ')'),
      'None recorded against this case. The document says so, because a '
      + 'finding whose premises are unwritten is one its reader cannot '
      + 'challenge.');
  } else {
    box.appendChild(el('h2', 'h-sm', 'Assumptions'));
    box.appendChild(el('p', 'help warn', countOf(assumptionsWithheld,
      'recorded assumption', 'recorded assumptions')
      + ' withheld with the case header.'));
  }

  reportList(box, 'Entities', body.actors || [], (a) => reportRow(
    (a.label || a.id) + ' (' + typeName(a.type) + ', ' + a.classification + ')',
    a.has_evidence ? [] : [unevidenced]));
  reportList(box, 'Relationships', body.relationships || [], (r) => reportRow(
    (labelOf.get(r.src) || shortId(r.src)) + ' → '
      + (labelOf.get(r.dst) || shortId(r.dst)) + ' (' + r.type + ', '
      + (REPORT_SIGN[r.sign] || r.sign) + ', ' + r.confidence + ')',
    r.has_evidence ? [] : [unevidenced]));
  reportList(box, 'Exhibits', body.evidence || [], (e) => reportRow(
    (e.title || e.id) + (e.sha256 ? ' · sha256 ' + String(e.sha256).slice(0, 12) : '')));
  if (body.hypotheses && body.hypotheses.hypotheses) {
    /* The statements, not a count: they often name suspects, and they
       are in the file. With the status the document now prints, so a
       ruled-out alternative reads as one (README screenshot review,
       2026-09-23). */
    const statuses = body.hypotheses.statuses || {};
    reportList(box, 'Competing hypotheses', hyp, (h) => reportRow(
      h.statement + ' (' + (statuses[String(h.id)] || 'status not recorded')
        + ', inconsistency ' + h.inconsistency + ', support '
        + h.support + ')'));
    for (const w of body.hypotheses.warnings || []) {
      box.appendChild(el('p', 'help warn', w));
    }
  } else if ((body.redaction || {}).hypotheses_withheld) {
    /* Said, as the document says it: a missing section reads as "no
       alternatives were considered" (final review C2). */
    box.appendChild(el('h2', 'h-sm', 'Competing hypotheses'));
    /* Agreed as the document's own line agrees ("_1 competing hypothesis
       withheld with the case header"), not a bracketed plural (README
       screenshot set review, 2026-09-23). */
    box.appendChild(el('p', 'help warn',
      countOf(body.redaction.hypotheses_withheld, 'competing hypothesis',
        'competing hypotheses') + ' withheld with the case header.'));
  }

  if (typeof body.document === 'string') {
    const full = el('details', 'card rep-document');
    /* Exact apart from one line, and it says which: a saved copy is built
       again when it is cleared, so its "Generated" line carries that time.
       The digest leaves the line out, which is how Save knows the rest is
       unchanged (verifier, ux15 fix round, 2026-09-22). */
    full.appendChild(el('summary', null,
      'The full text as it would be saved (a saved copy\'s "Generated" line '
      + 'gives the time it was cleared)'));
    full.appendChild(el('pre', 'rep-document-text', body.document));
    box.appendChild(full);
  }
}

/* Check egress is the one path to a file, and `/report/release` is
   step-up gated: it needs a sign-in from the last 15 minutes. Until final
   review C15 (2026-09-23) nothing here knew that. Every check more than 15
   minutes into a session came back "missing permission report.export",
   shown as an egress refusal "audited as loudly as a permission", to a
   Lead investigator who holds it, and the only way out was signing out
   and preparing again. The sign-in is now asked for in place, first when
   this tab knows the gate is shut and once more if the server says so,
   and the three kinds of 403 are told apart. */

/** True when `err` is the server asking for a fresh sign-in rather than
 *  judging the document or the caller's role. The route says this only
 *  when the sign-in is all that is missing (routers/reports.py
 *  `_require_export`), so a role a sign-in would not fix is never sent
 *  round the sheet again. */
function reportNeedsSignIn(err) {
  return err instanceof ApiError && err.status === 403
    && err.title !== 'Egress refused'
    && /re-authenticat/i.test(err.detail || '');
}

/** Ask for the sign-in `/report/release` needs, over the pane, which stays
 *  as it is. True when the check may go ahead. */
async function reportStepUp(msg, stale) {
  const ok = await confirmIdentity('Checking egress needs a sign-in from '
    + 'the last 15 minutes. The prepared preview stays as it is.');
  if (stale()) return false;
  if (!ok || !signedIn()) {
    verdictPending = false;
    setMsg(msg, 'Nothing was checked. Checking egress needs a sign-in from '
      + 'the last 15 minutes; press Check egress again to be asked for one.');
    return false;
  }
  return true;
}

/** A 403 that is not the gate's verdict on the document: the caller's
 *  session or role, which is said as that, never as an egress refusal. */
function reportAccessRefusal(err) {
  if (reportNeedsSignIn(err)) {
    return 'Not checked: the server still asks for a fresh sign-in ('
      + err.detail + '). Press Check egress again to be asked for one.';
  }
  return 'Not checked: ' + (err.detail || err.title) + '. Saving or sending '
    + 'a report needs the report.export permission on this case, which '
    + 'comes with the Lead investigator role. The document itself was not '
    + 'judged; the refused request is in the audit log.';
}

async function releaseReport() {
  const prepared = state.report;
  if (!prepared) return;
  const token = caseToken();
  const msg = $('rep-release-msg');
  const out = $('rep-release-out');
  resetReportVerdict();
  const gen = verdictGen;
  verdictPending = true;
  /* A reply is dropped when the case changed, when the preview it judged
     was withdrawn, or when the destination, ceiling or note it was asked
     about changed while it was in flight. */
  const stale = () => caseChanged(token) || state.report !== prepared
    || gen !== verdictGen;
  const send = () => api(cpath('/report/release'), {
    method: 'POST',
    json: {
      /* The PREVIEW's parameters, not whatever the controls now say:
         any change to them has already withdrawn the preview. */
      target_tlp: prepared.params.target_tlp,
      include_hypotheses: prepared.params.include_hypotheses,
      preset: prepared.params.preset,
      destination: $('rep-destination').value,
      destination_ceiling: $('rep-ceiling').value || null,
      recipient_note: $('rep-note').value.trim() || null,
    },
  });
  try {
    /* Asked FIRST when this tab knows the gate is shut: a request sent to
       be refused is an AUTHZ_DENIED row for nothing. */
    if (stepUpStale() && !(await reportStepUp(msg, stale))) return;
    let body;
    try {
      body = await send();
    } catch (err) {
      if (stale() || !reportNeedsSignIn(err)) throw err;
      /* The gate shut sooner than this tab knew (a clock, or a server
         that does not say): ask here and try once more. */
      SESSION.stepUpUntil = 0;
      if (!(await reportStepUp(msg, stale))) return;
      body = await send();
    }
    if (stale()) return;
    verdictPending = false;
    out.appendChild(el('p', 'form-ok',
      'May leave at ' + body.classification + ' to '
      + body.destination + '.'));
    out.appendChild(el('p', 'help', body.notice || ''));
    if (body.redaction) out.appendChild(el('p', 'why', body.redaction));
    if (body.content_digest !== prepared.body.content_digest) {
      /* The gate judged a fresh build, and something in the case changed
         since Prepare. Offering that file would hand over a document
         nobody has looked at, under a preview of a different one. */
      out.appendChild(el('p', 'form-error',
        'The case changed after this preview was prepared, so the document '
        + 'just cleared is not the one shown above. Prepare again, read it, '
        + 'and check again before saving anything.'));
      return;
    }
    if (body.destination === 'in_app') {
      out.appendChild(el('p', 'help',
        'In-app means the document stays inside the platform, so there is '
        + 'no file to save. To save it, check it again with the destination '
        + '"export".'));
      return;
    }
    reportCleared = body;
    $('rep-download').textContent = 'Save the cleared document ('
      + (body.filename || 'report.md') + ')';
    show($('rep-download'), true);
  } catch (err) {
    if (stale()) return;
    verdictPending = false;
    /* A refusal is the system working, so it is reported where the
       control is rather than as a banner, and the server's explanation
       is shown verbatim, because it names which rule stopped it. Only
       the gate's own verdict is an egress refusal: a stale sign-in or a
       role without report.export never reached the document (C15). */
    if (err instanceof ApiError && err.status === 403
        && err.title === 'Egress refused') {
      out.appendChild(el('p', 'form-error', err.detail || err.title));
      out.appendChild(el('p', 'help',
        'Refused, and audited as loudly as a permission would be. An '
        + 'unrecorded refusal is indistinguishable from nobody having '
        + 'tried.'));
      return;
    }
    if (err instanceof ApiError && err.status === 403) {
      out.appendChild(el('p', 'form-error', reportAccessRefusal(err)));
      return;
    }
    inlineProblem(msg, err);
  }
}


/* --- deception: phishing captures, BEC email, vishing calls ------------
 *
 * docs/19. The pane's whole design is one rule applied three times:
 * SHOW WHAT THE ATTACKER CHOSE, MARKED AS SUCH, NEXT TO WHAT THE
 * INFRASTRUCTURE PROVED.
 *
 * Concretely, and each of these is a real failure mode rather than a
 * stylistic preference:
 *
 *  - Every URL is defanged and rendered as text, never as an anchor. A
 *    live href is one mis-click from fetching attacker infrastructure
 *    from this machine, which is a drive-by surface AND tells the actor
 *    the investigation exists.
 *  - No message body is rendered. An HTML email loads remote images; the
 *    tracking pixel fires from this organisation's IP. The extracted plain
 *    text is shown only as the server's defanged runs (`body_segments`),
 *    never from `body_text`, which keeps the sender's live URLs.
 *  - The Received chain is drawn recipient-first with the trust boundary
 *    marked, and every hop below it (further from the recipient) is
 *    greyed and labelled "claimed".
 *  - A screenshot's <img> src is built from an /api/v1/ path and never
 *    from a value in the response -- enforced by a test, because the UI
 *    invariant suite did not police `.src` until this pane needed one.
 */

function dcpUrl(value) {
  /* No URL is said in words and offers nothing to copy. It was a dash
     in the defanged style beside a copy button that copied the dash
     (README screenshot review, 2026-09-23). */
  if (!value) return el('span', 'muted', NO_VALUE);
  /* Defanged, monospaced, and deliberately NOT an anchor. */
  const shown = visibleText(value);
  const span = el('span', 'mono defanged', shown);
  span.title = 'Defanged and non-clickable on purpose. Fetching this from '
    + 'an analyst workstation would announce the investigation.';
  /* Copies the DEFANGED form. That is what belongs in a report, and a
     re-fanged URL on the clipboard is a working link one careless paste
     from a browser. */
  return copyable(span, shown, 'the defanged URL');
}

/* The two detail cards, and which row each one is showing.
 *
 * ux14-deception:detail-cards-invisible (2026-09-22). Both cards sat at
 * opacity 0 from the day they shipped: app.css held `.detail-card`
 * invisible until an `is-in` class arrived, and only the Lab's openSample
 * ever added it. Open appeared to do nothing, while the invisible Close
 * and copy buttons still took keyboard focus and a screen reader still
 * read the redirect chain and the Received chain aloud. The resting state
 * is visible in app.css now, and this is the one way either card opens, so
 * a third open path cannot forget to scroll it into view or to move focus
 * to its heading.
 *
 * `seq` is per open, so a slow reply for the capture opened first cannot
 * land on top of the one opened second; `token` is the case-switch token,
 * so it cannot land under another case's header either. */
const DCP_DETAIL = {
  cap: { box: 'dcp-cap-detail', body: 'dcp-cap-body',
    title: 'dcp-cap-title', blank: 'Capture' },
  eml: { box: 'dcp-eml-detail', body: 'dcp-eml-body',
    title: 'dcp-eml-title', blank: 'Message' },
};
const dcpOpen = { cap: null, eml: null };
let dcpOpenSeq = 0;

function dcpDetailOpen(kind, id, opener) {
  const d = DCP_DETAIL[kind];
  const box = $(d.box);
  const body = $(d.body);
  const heading = $(d.title);
  dcpOpenSeq += 1;
  dcpOpen[kind] = { id, seq: dcpOpenSeq, opener: opener || null };
  clear(body);
  heading.textContent = d.blank;
  show(box, true);
  body.appendChild(el('p', 'muted', 'Loading…'));
  /* Focus without letting it scroll, then scroll on purpose. The card
     opens BELOW the list, usually under the fold, and a focus-driven
     scroll puts the heading wherever the browser likes. `nearest` now,
     because a card holding only "Loading" is too short to bring to the
     top; dcpDetailSettle brings it up once its content has arrived. */
  heading.focus({ preventScroll: true });
  box.scrollIntoView({ block: 'nearest', behavior: reduceMotion ? 'auto' : 'smooth' });
  return { token: caseToken(), seq: dcpOpenSeq };
}

/** The card's content has arrived: bring its top to the top of the pane,
 *  so what shows is the chain and not the row it was opened from. */
function dcpDetailSettle(kind) {
  $(DCP_DETAIL[kind].box).scrollIntoView({
    block: 'start', behavior: reduceMotion ? 'auto' : 'smooth' });
}

/** Has a newer open, a close or a case switch overtaken this read? */
function dcpDetailStale(kind, ticket) {
  const cur = dcpOpen[kind];
  return caseChanged(ticket.token) || !cur || cur.seq !== ticket.seq;
}

function dcpDetailClose(kind, restoreFocus) {
  const d = DCP_DETAIL[kind];
  const was = dcpOpen[kind];
  dcpOpen[kind] = null;
  show($(d.box), false);
  /* Emptied, not only hidden: a hidden card still holding case A's
     infrastructure is one `show()` away from presenting it as case B's. */
  clear($(d.body));
  $(d.title).textContent = d.blank;
  if (restoreFocus && was && was.opener && was.opener.isConnected) {
    was.opener.focus();
  }
}

/** A reload that no longer returns the open row closes its card. */
function dcpDetailKeepIfListed(kind, rows) {
  const cur = dcpOpen[kind];
  if (cur && !rows.some((r) => r.id === cur.id)) dcpDetailClose(kind);
}

/* The three lists and the empty-state line each one rests on. `blank` is
   index.html's own text (a test holds the two equal): a refusal writes
   over that line, and the next case's successful load has to put it back
   or a case with no captures would go on saying "needs evidence.read". */
const DCP_LISTS = {
  cap: { list: 'dcp-cap-list', empty: 'dcp-cap-empty',
    counts: 'dcp-cap-counts', blank: 'No captures recorded.',
    noun: ['capture', 'captures'] },
  eml: { list: 'dcp-eml-list', empty: 'dcp-eml-empty',
    counts: 'dcp-eml-counts', blank: 'No messages recorded.',
    noun: ['message', 'messages'] },
  call: { list: 'dcp-call-list', empty: 'dcp-call-empty',
    counts: 'dcp-call-counts', blank: 'No calls recorded.',
    noun: ['call', 'calls'] },
};

/** A list with nothing in it and nothing claimed about it: no rows, no
 *  count, and no "No captures recorded." either, because until the new
 *  case's read returns nobody knows that (invariant 12). */
function dcpListReset(kind) {
  const d = DCP_LISTS[kind];
  clear($(d.list));
  $(d.counts).textContent = '';
  $(d.empty).textContent = d.blank;
  show($(d.empty), false);
}

/** A read came back: its rows, its count, and the resting empty line. */
function dcpListRender(kind, rows, build) {
  const d = DCP_LISTS[kind];
  $(d.counts).textContent = rows.length + ' '
    + d.noun[rows.length === 1 ? 0 : 1];
  $(d.empty).textContent = d.blank;
  renderList(d.list, d.empty, rows, build);
}

/* ux14-deception:stale-detail-on-case-switch (2026-09-22). openCase reset
   the graph and nothing here, so an open capture or message from case A
   sat under case B's header and TLP chip: NIGHTJAR's AMBER redirect chain
   presented as KESTREL's evidence. Cleared on every switch, both ways.
   The LISTS too: selecting Deception on case B reloads only the subtab on
   screen, so until B's read returned (and on the other two subtabs until
   they were opened) A's rows, notes included, sat under B's header. The
   fix's verifier caught that one. */
onCaseSwitch(() => {
  dcpDetailClose('cap');
  dcpDetailClose('eml');
  dcpListReset('cap');
  dcpListReset('eml');
  dcpListReset('call');
});

/* Free text as the server's defanged runs (`defang_text`), each URL run
 * marked the way the URL list marks one, so a reader can tell the
 * defanger's characters from the writer's. `room` caps the characters
 * drawn; the return says whether anything was cut, so the caller can say
 * so (invariant 12). The one way this pane draws typed text that may hold
 * a link: the email body and the analysts' notes both come through here. */
function dcpRuns(parent, runs, room) {
  let left = room === undefined ? Infinity : room;
  let cut = false;
  for (const run of runs) {
    if (left <= 0) { cut = true; break; }
    const whole = visibleText(run.text);
    const text = whole.slice(0, left);
    if (text.length < whole.length) cut = true;
    left -= text.length;
    if (run.defanged) {
      const span = el('span', 'defanged', text);
      span.title = 'Defanged by this system, not by the writer.';
      parent.appendChild(span);
    } else {
      parent.appendChild(document.createTextNode(text));
    }
  }
  return cut;
}

/* An analyst's note on a capture or a call.
 *
 * ux14-deception:notes-never-rendered (2026-09-22). The API returned
 * `note` on both and nothing read it, so the only record that the victim
 * had already entered credentials was invisible, and a capture row with
 * no input chip read as if nobody had typed anything into the kit.
 * Labelled and attributed, because a note is a person's statement and
 * not the system's finding, and drawn apart from the `.why` lines, which
 * are the system talking.
 *
 * Drawn from `note_segments` and never from `note`. The fix's verifier
 * showed a note reading "Victim clicked https://..." put that link on
 * screen live, under the capture pane's promise that every URL in it is
 * defanged: an analyst recording what the victim clicked pastes the link. */
function dcpNote(runs, author, when) {
  if (!runs || !runs.length) return null;
  const box = el('div', 'analyst-note');
  const head = el('p', 'analyst-note-head');
  head.appendChild(el('span', 'fact-k', 'Analyst note'));
  const by = author ? 'by ' + visibleText(author) : 'author not recorded';
  const at = when ? fmtTime(when) : '';
  head.appendChild(el('span', 'muted small', at ? by + ', ' + at : by));
  box.appendChild(head);
  const text = el('p', 'analyst-note-text');
  dcpRuns(text, runs);
  box.appendChild(text);
  return box;
}

/* A failed deception load must not leave the previous case's rows on
 * screen.
 *
 * All three of these panes reported the error into the COUNTS span and
 * returned before the render, so the list kept whatever it last held. Open
 * Deception on case A, switch to case B, get a 403 — and case A's defanged
 * attacker URLs, BEC subject lines and spoofed caller IDs sit under case
 * B's header and its TLP chip. The 403 is the likely path, not the rare
 * one: all three endpoints gate on `evidence.read`.
 *
 * There is no third state to invent here, unlike the graph's UNKNOWN: an
 * empty list plus a named refusal already says "not known", whereas the
 * previous case's rows say "these are case B's captures".
 */
function deceptionLoadFailed(err, kind, rowFn, need) {
  const d = DCP_LISTS[kind];
  /* Clear BEFORE reporting. Reporting first and returning is exactly how
     the stale rows survived. */
  renderList(d.list, d.empty, [], rowFn);
  $(d.empty).textContent = refusalText(err, need);
  /* A stale "12 captures" is the same lie in miniature. */
  $(d.counts).textContent = '';
  /* The open detail card belongs to a row that is no longer on screen.
     Calls have no detail card. */
  if (DCP_DETAIL[kind]) dcpDetailClose(kind);
  inlineProblem($(d.counts), err);
}

/* Each loader drops a reply that a case switch overtook: A's rows landing
   after the switch to B would be the stale-detail defect again, one level
   up (ux14-deception:stale-detail-on-case-switch). "Loading" goes in the
   count first, because after a switch the list is empty on purpose
   (dcpListReset) and an empty list with no word beside it reads as a case
   with nothing in it. */
async function loadCaptures() {
  if (!state.caseId) return;
  const token = caseToken();
  $('dcp-cap-counts').textContent = 'Loading…';
  let data;
  try {
    data = await api(cpath('/deception/captures'));
  } catch (err) {
    if (caseChanged(token)) return;
    deceptionLoadFailed(err, 'cap', captureRow, 'Reading deception captures '
      + 'needs evidence.read on this case.');
    return;
  }
  if (caseChanged(token)) return;
  const rows = data.captures || [];
  dcpListRender('cap', rows, captureRow);
  dcpDetailKeepIfListed('cap', rows);
}

function captureRow(c) {
  const card = el('div', 'card row-card');
  const head = el('div', 'row-head');
  head.appendChild(el('span', 'row-glyph', '⚑'));
  head.appendChild(dcpUrl(c.requested_url_defanged));
  if (c.is_live === false) head.appendChild(el('span', 'chip', 'dead'));
  if (c.is_live === true) head.appendChild(el('span', 'chip bad', 'live'));
  if (c.submitted_input) {
    /* Named for WHO submitted. "input submitted" alone read as a statement
       about the victim, so its absence read as "the victim typed nothing",
       and the demo's note says the opposite (ux14-deception:
       notes-never-rendered). */
    const chip = el('span', 'chip bad', 'analyst submitted input');
    chip.title = 'An analyst entered credentials or other input into this '
      + 'page under a recorded authority (legal item L5). It says nothing '
      + 'about what the victim entered.';
    head.appendChild(chip);
  }
  head.appendChild(labelChips(c));
  card.appendChild(head);

  const facts = el('div', 'facts');
  facts.appendChild(fact('method', c.capture_method));
  facts.appendChild(fact('status', c.http_status));
  facts.appendChild(fact('captured',
    fmtTime(c.captured_at)));
  if (c.tls_spki_sha256) {
    const f = fact('TLS key', c.tls_spki_sha256.slice(0, 12) + '…');
    f.title = 'The certificate public-key hash. Phishing infrastructure '
      + 'rotates domains constantly and keys rarely, so this outlives the '
      + 'domain and is the durable identifier for pivoting.';
    facts.appendChild(f);
  }
  if (!c.egress_profile_id
      && !['ANALYST_UPLOAD', 'VICTIM_SUPPLIED', 'PASSIVE_FEED']
        .includes(c.capture_method)) {
    facts.appendChild(fact('egress', 'undeclared', 'muted'));
  }
  card.appendChild(facts);

  if (c.final_url_defanged
      && c.final_url_defanged !== c.requested_url_defanged) {
    const p = el('p', 'why');
    p.appendChild(el('span', 'fact-k', 'redirected to'));
    p.appendChild(dcpUrl(c.final_url_defanged));
    card.appendChild(p);
  }
  const note = dcpNote(c.note_segments, c.captured_by_name, c.captured_at);
  if (note) card.appendChild(note);
  const open = el('button', 'btn subtle', 'Open');
  open.type = 'button';
  open.setAttribute('aria-controls', 'dcp-cap-detail');
  open.addEventListener('click', () => openCapture(c.id, open));
  card.appendChild(open);
  return card;
}

async function openCapture(id, opener) {
  const ticket = dcpDetailOpen('cap', id, opener);
  const body = $('dcp-cap-body');
  let c;
  try {
    c = await api(cpath('/deception/captures/' + encodeURIComponent(id)));
  } catch (err) {
    if (dcpDetailStale('cap', ticket)) return;
    clear(body);
    body.appendChild(el('p', 'msg bad', refusalText(err,
      'Reading a capture needs evidence.read.')));
    return;
  }
  if (dcpDetailStale('cap', ticket)) return;
  clear(body);
  $('dcp-cap-title').textContent = 'Capture ' + id.slice(0, 8);

  /* First, because it is the context the rest is read in: in the demo it
     is the only record that the victim had already entered credentials. */
  const note = dcpNote(c.note_segments, c.captured_by_name, c.captured_at);
  if (note) body.appendChild(note);

  /* The screenshot. The src is an API path built HERE from the capture
     id; nothing out of the response body reaches it. The endpoint
     re-derives the content type from the magic bytes and refuses anything
     that is not a raster image, so a DOM mislabelled image/png cannot
     arrive here. */
  if (c.screenshot_evidence_id) {
    const shot = el('img', 'capture-shot');
    shot.src = '/api/v1/cases/' + encodeURIComponent(state.caseId)
      + '/deception/captures/' + encodeURIComponent(id) + '/screenshot';
    shot.alt = 'Screenshot of the captured page';
    shot.loading = 'lazy';
    shot.referrerPolicy = 'no-referrer';
    body.appendChild(shot);
  } else {
    body.appendChild(el('p', 'muted', 'No screenshot on this capture.'));
  }

  if (c.dom_evidence_id) {
    const note = el('p', 'why');
    note.textContent = 'The page DOM is held as evidence and is not shown. '
      + 'It is attacker-authored code, so it is download-only from the '
      + 'separate sample origin (invariant 10).';
    body.appendChild(note);
  }

  const facts = el('div', 'facts');
  facts.appendChild(fact('method', c.capture_method));
  facts.appendChild(fact('tool', c.capture_tool));
  facts.appendChild(fact('status', c.http_status));
  /* The kit wrote the title, so it is read defanged like every other
     string the attacker authored. */
  facts.appendChild(fact('title',
    visibleText(c.page_title_defanged || 'not recorded')));
  body.appendChild(facts);

  if (c.tls_subject || c.tls_spki_sha256) {
    const tls = el('div', 'card sub-card');
    tls.appendChild(el('h3', 'h-xs', 'TLS certificate'));
    const tf = el('div', 'facts');
    tf.appendChild(fact('subject', visibleText(c.tls_subject || NO_VALUE)));
    tf.appendChild(fact('issuer', visibleText(c.tls_issuer || NO_VALUE)));
    tf.appendChild(fact('not after', fmtDate(c.tls_not_after)));
    tls.appendChild(tf);
    if (c.tls_spki_sha256) {
      const k = el('p', 'mono small', c.tls_spki_sha256);
      k.title = 'SPKI SHA-256: pivot on this, not the domain.';
      tls.appendChild(copyable(k, c.tls_spki_sha256, 'the TLS key hash'));
    }
    body.appendChild(tls);
  }

  const hops = c.hops || [];
  if (hops.length) {
    const chain = el('div', 'card sub-card');
    chain.appendChild(el('h3', 'h-xs',
      'Redirect chain (' + hops.length + ' hop'
      + (hops.length === 1 ? '' : 's') + ')'));
    for (const h of hops) {
      const row = el('p', 'hop-row');
      row.appendChild(el('span', 'fact-k', String(h.seq)));
      row.appendChild(dcpUrl(h.url_defanged));
      if (h.http_status) {
        row.appendChild(el('span', 'chip', String(h.http_status)));
      }
      if (h.resolved_ip) {
        row.appendChild(el('span', 'mono small', h.resolved_ip));
      }
      if (h.hop_kind) row.appendChild(el('span', 'chip subtle', h.hop_kind));
      chain.appendChild(row);
    }
    body.appendChild(chain);
  }

  if (c.submitted_input) {
    const l5 = el('p', 'msg bad');
    l5.textContent = 'An analyst submitted input to this page. Authority: '
      + (c.submission_authority_ref || '(not recorded)');
    body.appendChild(l5);
  }
  dcpDetailSettle('cap');
}

async function loadDeceptionEmails() {
  if (!state.caseId) return;
  const token = caseToken();
  $('dcp-eml-counts').textContent = 'Loading…';
  let data;
  try {
    data = await api(cpath('/deception/emails')
      + ($('dcp-divergent').checked ? '?divergent_only=true' : ''));
  } catch (err) {
    if (caseChanged(token)) return;
    deceptionLoadFailed(err, 'eml', emailRow, 'Reading deception messages '
      + 'needs evidence.read on this case.');
    return;
  }
  if (caseChanged(token)) return;
  const rows = data.emails || [];
  dcpListRender('eml', rows, emailRow);
  dcpDetailKeepIfListed('eml', rows);
}

/* A message, split the way a call is split.
 *
 * ux14-deception:email-durable-origin-missing (2026-09-22). The row showed
 * the display name, From and Reply-To in the same neutral style, every one
 * of them typed by the sender, while the pane's rule is to show what the
 * attacker chose MARKED AS SUCH next to what the infrastructure proved.
 * The call row did that and the email row did not, so the spoofed CFO
 * address sat unmarked and the host the recipient's own relay saw connect
 * (docs/19's "first trusted Received hop") lived only in the detail card.
 * The same three builders draw the row and the top of the detail card, so
 * the two cannot drift apart. */
function emailSignalChips(m) {
  const chips = [];
  if (m.from_replyto_divergent) {
    const chip = el('span', 'chip bad', 'From != Reply-To');
    chip.title = 'A reply to this message goes somewhere other than where '
      + 'it claims to be from. The classic BEC tell.';
    chips.push(chip);
  }
  if (m.reply_to_is_freemail) {
    chips.push(el('span', 'chip bad', 'free-mail reply'));
  }
  if (m.from_returnpath_divergent) {
    /* Amber, not red: bulk mail sent through a provider diverges here
       legitimately, so this is a signal to weigh and not the tell that
       From != Reply-To is. */
    const chip = el('span', 'chip warn', 'From != Return-Path');
    chip.title = 'The envelope sender the receiving server recorded is at a '
      + 'different domain from the From: header. Ordinary for mail sent '
      + 'through a bulk provider; in a message claiming to be from a '
      + 'colleague it means the From: was not the sending system’s.';
    chips.push(chip);
  }
  if (m.display_name_impersonates) {
    const chip = el('span', 'chip bad',
      'impersonates ' + visibleText(m.display_name_impersonates));
    chip.title = 'Recorded by the analyst who filed this message: the party '
      + 'the display name imitates. An analyst’s reading of the lure, '
      + 'not something the headers prove.';
    chips.push(chip);
  }
  return chips;
}

function emailSaw(m) {
  const shown = el('div', 'card sub-card presented-block');
  shown.appendChild(el('h3', 'h-xs', 'What the recipient saw'));
  /* Display name and address are two facts, never concatenated.
     "Jane Okafor, CFO <attacker@evil.example>" read as one string is
     exactly how a display name gets mistaken for an identity. */
  const f = el('div', 'facts');
  if (m.header_from_display_defanged) {
    f.appendChild(fact('display name',
      visibleText(m.header_from_display_defanged)));
  }
  f.appendChild(fact('from', visibleText(m.header_from || 'not present')));
  if (m.header_reply_to) {
    f.appendChild(fact('reply-to', visibleText(m.header_reply_to)));
  }
  const to = m.header_to || [];
  if (to.length) f.appendChild(fact('to', to.map(visibleText).join(', ')));
  const cc = m.header_cc || [];
  if (cc.length) f.appendChild(fact('cc', cc.map(visibleText).join(', ')));
  if (m.date_header) {
    const d = fact('date', fmtTime(m.date_header));
    d.title = 'The Date: header the sender wrote, shown in UTC. The time the '
      + 'recipient’s relay observed is under what the infrastructure '
      + 'proved.';
    f.appendChild(d);
  }
  /* The defanged form only. The kit writes the Message-ID, and
     `<a@pay.evil.example/verify>` gives a "host" with a path, which every
     chat client links (final review U17, 2026-09-23). */
  if (m.message_id_domain_defanged) {
    const k = fact('message-id host', visibleText(m.message_id_domain_defanged));
    k.title = 'The domain in the Message-ID. Generated by the sending kit, '
      + 'so it fingerprints the kit and never the sender.';
    f.appendChild(k);
  }
  const warn = el('span', 'chip bad', 'attacker-chosen');
  warn.title = 'Every header here was written by whoever sent the message. '
    + 'The display name and From are the lure; none of them is an identity.';
  f.appendChild(warn);
  shown.appendChild(f);
  return shown;
}

function emailProved(m) {
  const real = el('div', 'card sub-card durable-block');
  real.appendChild(el('h3', 'h-xs', 'What the infrastructure proved'));
  const f = el('div', 'facts');
  const origin = m.sending_host;
  if (origin) {
    /* The HELO name is the sender's choice, recorded as given, so it is
       read in its defanged form like every other string the sender wrote:
       EHLO `pay.evil.example/verify` was drawn live here (final review
       U17, 2026-09-23). */
    const where = [origin.host_defanged ? visibleText(origin.host_defanged)
      : null, origin.ip].filter(Boolean).join(' ');
    const host = fact('sending host', where || 'not recorded');
    /* "Below it, further from the recipient": the chain is drawn hop 0
       first, and "above" pointed at the organisation's own hops (README
       screenshot review, 2026-09-23). */
    host.title = 'Received hop ' + origin.seq + ': the host that connected to '
      + visibleText(origin.observed_by_defanged || 'the recipient’s relay')
      + ', written by that relay. Every hop below it in the chain, further '
      + 'from the recipient, is a claim; this line is an observation.';
    f.appendChild(host);
    if (origin.boundary_confirmed !== true) {
      /* Unknown is said as unknown (invariant 12). At hop 0 the stored
         chain cannot tell a configured single-MX estate from the parser's
         default, and in the default case this host can be the recipient's
         OWN internal relay. */
      const chip = el('span', 'chip warn', 'boundary not confirmed');
      chip.title = 'The trust boundary is hop 0, which is also where it '
        + 'falls when nobody has named the recipient’s mail servers '
        + '(NOCTORNAL_TRUSTED_MTA_HOSTS). If none were named, this host may '
        + 'be the recipient’s own relay rather than the sender.';
      f.appendChild(chip);
    }
    if (origin.received_at) {
      f.appendChild(fact('received', fmtTime(origin.received_at)));
    }
  } else {
    f.appendChild(fact('sending host', 'no Received chain', 'muted'));
  }
  if (m.envelope_from) {
    f.appendChild(fact('envelope from', visibleText(m.envelope_from)));
  }
  if (m.header_return_path) {
    const rp = fact('return-path', visibleText(m.header_return_path));
    rp.title = 'Written by the receiving server from the SMTP envelope. It '
      + 'is authenticated only where SPF passed for its domain.';
    f.appendChild(rp);
  }
  if ((m.envelope_from || m.header_return_path) && m.spf_result !== 'PASS') {
    /* The relay recorded the envelope sender faithfully, but the sender
       chose it, and only a passing SPF check ties it to its domain. Said
       on the face of the block, because in a block headed "proved" a
       bounce domain that failed SPF read as proven, with the one sentence
       saying otherwise hidden in a tooltip (the verifier of the 2026-09-22
       email-durable-origin-missing fix). */
    const spf = m.spf_result || 'not checked';
    const chip = el('span', 'chip warn', 'envelope unauthenticated: SPF '
      + spf);
    chip.title = 'The receiving server recorded this envelope sender as the '
      + 'sending system gave it. Without a passing SPF check for its '
      + 'domain it is the sender’s claim, observed, and not proof of where '
      + 'the message came from.';
    f.appendChild(chip);
  }
  real.appendChild(f);

  const auth = el('div', 'facts');
  auth.appendChild(authChip('SPF', m.spf_result));
  auth.appendChild(authChip('DKIM', m.dkim_result));
  auth.appendChild(authChip('DMARC', m.dmarc_result));
  if (m.dkim_domain) {
    const d = fact('authenticated', m.dkim_domain);
    d.title = 'DKIM PASSED for this domain: the only cryptographically '
      + 'authenticated field in an email.';
    auth.appendChild(d);
  }
  real.appendChild(auth);
  return real;
}

function emailRow(m) {
  const card = el('div', 'card row-card');
  const head = el('div', 'row-head');
  head.appendChild(el('span', 'row-glyph', '✉'));
  /* `subject_defanged`, never `subject`: the sender wrote it, and a lure
     links from the subject line as readily as from the body. */
  head.appendChild(el('span', 'row-title',
    visibleText(m.subject_defanged || '(no subject)')));
  for (const chip of emailSignalChips(m)) head.appendChild(chip);
  head.appendChild(labelChips(m));
  card.appendChild(head);

  card.appendChild(emailSaw(m));
  card.appendChild(emailProved(m));

  if ((m.parse_gaps || []).length) {
    const gaps = el('p', 'why gaps',
      m.parse_gaps.length + ' parse gap'
      + (m.parse_gaps.length === 1 ? '' : 's'));
    gaps.title = m.parse_gaps.map((g) => g.step + ': ' + g.reason).join('\n');
    card.appendChild(gaps);
  }
  const open = el('button', 'btn subtle', 'Open');
  open.type = 'button';
  open.setAttribute('aria-controls', 'dcp-eml-detail');
  open.addEventListener('click', () => openDeceptionEmail(m.id, open));
  card.appendChild(open);
  return card;
}

function authChip(name, result) {
  const wrap = el('span', 'fact');
  wrap.appendChild(el('span', 'fact-k', name));
  if (!result) {
    /* Invariant 12 on screen: "nobody checked" and "it failed" must not
       look the same. */
    const chip = el('span', 'chip subtle', 'not checked');
    chip.title = 'No Authentication-Results header said anything about '
      + name + '. That is an absence, not a failure.';
    wrap.appendChild(chip);
    return wrap;
  }
  /* "Not PASS" is three different facts and this painted all of them red.
     TEMPERROR means the receiving MTA could not COMPLETE the check — a DNS
     timeout at delivery time. PERMERROR means the published record is
     malformed. NONE means the domain publishes no policy at all. None of
     those is the mail failing authentication, and showing them as FAIL is
     the same error the gaps mechanism exists to prevent, made on screen:
     an inconclusive check reported as an adverse finding. An analyst who
     believes DKIM failed has an attribution; the truth is that nobody
     knows. Only FAIL and SOFTFAIL are adverse. */
  const adverse = result === 'FAIL' || result === 'SOFTFAIL';
  const inconclusive = result === 'TEMPERROR' || result === 'PERMERROR';
  const chip = el('span',
    'chip ' + (result === 'PASS' ? 'good' : adverse ? 'bad'
      : inconclusive ? 'warn' : 'subtle'),
    result);
  chip.title = result === 'PASS'
    ? name + ' passed.'
    : adverse
      ? name + ' FAILED: the check ran and the message did not pass.'
      : inconclusive
        ? name + ' could not be completed by the receiving MTA (' + result
          + '). This is not a failure and not a pass: it is unknown.'
        : name + ' returned ' + result + ': no policy or no verdict. '
          + 'An absence, not a failure.';
  wrap.appendChild(chip);
  return wrap;
}

async function openDeceptionEmail(id, opener) {
  const ticket = dcpDetailOpen('eml', id, opener);
  const body = $('dcp-eml-body');
  let m;
  try {
    m = await api(cpath('/deception/emails/' + encodeURIComponent(id)));
  } catch (err) {
    if (dcpDetailStale('eml', ticket)) return;
    clear(body);
    body.appendChild(el('p', 'msg bad', refusalText(err,
      'Reading a message needs evidence.read.')));
    return;
  }
  if (dcpDetailStale('eml', ticket)) return;
  clear(body);
  $('dcp-eml-title').textContent = visibleText(m.subject_defanged || 'Message');

  /* The row's signals again, at the top of the card: once the card is
     scrolled into view its row is usually off screen. */
  const signals = emailSignalChips(m);
  if (signals.length) {
    const line = el('div', 'chips');
    for (const chip of signals) line.appendChild(chip);
    body.appendChild(line);
  }
  body.appendChild(emailSaw(m));
  body.appendChild(emailProved(m));

  const hops = m.hops || [];
  if (hops.length) {
    const chain = el('div', 'card sub-card');
    chain.appendChild(el('h3', 'h-xs', 'Received chain'));
    const note = el('p', 'help');
    /* The chain is drawn recipient-first, hop 0 at the top, so the hops
       written outside the organisation are drawn BELOW the boundary row.
       This note and the chip's title said "above", which is docs/19's word
       for a higher `seq` and pointed the wrong way on screen (README
       screenshot review, 2026-09-23). "Further from the recipient" reads
       the same in any orientation, so it is said as well. */
    note.textContent = 'Read this from the top. Each MTA prepends its own '
      + 'line, so hop 0 is the receiving organisation’s own server. '
      + 'Every hop below the trust boundary, further from the recipient, '
      + 'was written by machines outside this organisation and can say '
      + 'anything the sender wants.';
    chain.appendChild(note);
    /* Hosts in their defanged forms: below the boundary every word of a
       line is the sender's, and a `from` or `by` with a path is a URL
       (final review U17, 2026-09-23). */
    for (const h of hops) {
      const row = el('p',
        'hop-row' + (h.is_attacker_writable ? ' claimed' : ''));
      row.appendChild(el('span', 'fact-k', String(h.seq)));
      row.appendChild(el('span', 'mono',
        visibleText(h.from_host_defanged || '?')));
      if (h.from_ip) row.appendChild(el('span', 'mono small', h.from_ip));
      row.appendChild(el('span', 'muted small', 'by'));
      row.appendChild(el('span', 'mono',
        visibleText(h.by_host_defanged || '?')));
      if (h.is_trusted_boundary) {
        const chip = el('span', 'chip good', 'trust boundary');
        chip.title = 'The last hop written by infrastructure this '
          + 'organisation controls. Its observation of who connected is '
          + 'evidence; every hop below it, further from the recipient, is '
          + 'a claim.';
        row.appendChild(chip);
      }
      if (h.is_attacker_writable) {
        row.appendChild(el('span', 'chip bad', 'claimed'));
      }
      chain.appendChild(row);
    }
    body.appendChild(chain);
  }

  if (m.has_html_body) {
    const warn = el('p', 'why');
    warn.textContent = 'This message has an HTML body. It is held in the '
      + 'exhibit and is never rendered: doing so would load the sender’s '
      + 'remote images and fire their tracking pixel from this network.';
    body.appendChild(warn);
  }
  /* The body, from the server's defanged runs and never from `body_text`.
     ux14-deception:body-url-not-defanged (2026-09-22): the <pre> held the
     sender's working URL directly above a list showing it defanged, in
     the one block an analyst selects and pastes into a ticket, where it
     is auto-linked one click from attacker infrastructure. Each URL run
     carries the same `.defanged` mark as the list. A payload without runs
     shows no body at all rather than falling back to the live text. */
  const runs = m.body_segments || [];
  if (runs.length) {
    const pre = el('pre', 'body-text mono');
    const cut = dcpRuns(pre, runs, 20000);
    body.appendChild(pre);
    if (cut) {
      /* Invariant 12: cut short is said, not silent. */
      body.appendChild(el('p', 'help',
        'Shown to 20,000 characters. The whole message is in the exhibit.'));
    }
  }

  const urls = m.extracted_urls_defanged || [];
  if (urls.length) {
    const urlBox = el('div', 'card sub-card');
    urlBox.appendChild(el('h3', 'h-xs',
      'URLs in the body (' + urls.length + ')'));
    for (const u of urls) {
      const p = el('p', 'hop-row');
      p.appendChild(dcpUrl(u));
      urlBox.appendChild(p);
    }
    body.appendChild(urlBox);
  }

  const atts = m.attachments || [];
  if (atts.length) {
    const attBox = el('div', 'card sub-card');
    attBox.appendChild(el('h3', 'h-xs',
      'Attachments (' + atts.length + ')'));
    for (const a of atts) {
      const p = el('p', 'hop-row');
      /* Same bidi treatment as the lab pane: substituted, not isolated. */
      const name = el('bdi', 'mono', visibleText(a.filename || '(unnamed)'));
      name.dir = 'ltr';
      p.appendChild(name);
      p.appendChild(el('span', 'muted small', a.media_type || '?'));
      /* A NULL size means the part could not be decoded, and `humanBytes`
         renders that as a bare em-dash — which sits one column away from a
         real "0 B" and reads the same at a glance. Say it in words. The
         reason is in the parse gaps above. */
      if (a.byte_size === null || a.byte_size === undefined) {
        const unknown = el('span', 'chip warn', 'size unknown');
        unknown.title = 'This part could not be decoded, so its size and '
          + 'hash were never established. It is NOT an empty attachment. '
          + 'See the parse gaps.';
        p.appendChild(unknown);
      } else {
        p.appendChild(el('span', 'muted small', humanBytes(a.byte_size)));
      }
      p.appendChild(el('span', 'chip subtle',
        a.sample_id ? 'in the lab' : 'metadata only'));
      attBox.appendChild(p);
    }
    body.appendChild(attBox);
  }
  dcpDetailSettle('eml');
}

async function loadDeceptionCalls() {
  if (!state.caseId) return;
  const token = caseToken();
  $('dcp-call-counts').textContent = 'Loading…';
  let data;
  try {
    data = await api(cpath('/deception/calls'));
  } catch (err) {
    if (caseChanged(token)) return;
    deceptionLoadFailed(err, 'call', callRow, 'Reading deception calls '
      + 'needs evidence.read on this case.');
    return;
  }
  if (caseChanged(token)) return;
  dcpListRender('call', data.calls || [], callRow);
}

function callRow(c) {
  const card = el('div', 'card row-card');
  const head = el('div', 'row-head');
  head.appendChild(el('span', 'row-glyph', '☎'));
  head.appendChild(el('span', 'row-title',
    fmtTime(c.started_at)));
  head.appendChild(el('span', 'chip subtle', c.record_source));
  if (c.recording_evidence_id) {
    const chip = el('span', 'chip bad', 'recording held');
    chip.title = 'Intercepted content, retained under a recorded lawful '
      + 'basis (legal item L4): ' + (c.recording_lawful_basis || '');
    head.appendChild(chip);
  }
  head.appendChild(labelChips(c));
  card.appendChild(head);

  /* THE layout decision in this pane. The two blocks are visually
     separate and separately labelled, because a single "caller" column
     is how a spoofed number ends up attributed to a real subscriber. */
  const shown = el('div', 'card sub-card presented-block');
  shown.appendChild(el('h3', 'h-xs', 'What the victim saw'));
  const sf = el('div', 'facts');
  sf.appendChild(fact('number',
    c.presented.number_e164 || c.presented.number));
  sf.appendChild(fact('name', visibleText(c.presented.name || NO_VALUE)));
  const warn = el('span', 'chip bad', 'attacker-chosen');
  warn.title = 'Caller ID and CNAM are set by the calling party. This is '
    + 'the attack, not a detail, and it never becomes a selector.';
  sf.appendChild(warn);
  shown.appendChild(sf);
  card.appendChild(shown);

  const real = el('div', 'card sub-card durable-block');
  real.appendChild(el('h3', 'h-xs', 'What the network vouched for'));
  const rf = el('div', 'facts');
  rf.appendChild(fact('trunk', c.durable.originating_trunk));
  rf.appendChild(fact('P-Asserted-Identity', c.durable.p_asserted_identity));
  rf.appendChild(fact('carrier', c.durable.carrier_name));
  const att = c.durable.stir_shaken_attestation;
  const attWrap = el('span', 'fact');
  attWrap.appendChild(el('span', 'fact-k', 'STIR/SHAKEN'));
  if (!att) {
    attWrap.appendChild(el('span', 'chip subtle', 'none'));
  } else if (c.durable.stir_shaken_verified) {
    attWrap.appendChild(el('span', 'chip good', att + ' verified'));
  } else {
    const chip = el('span', 'chip bad', att + ' unverified');
    chip.title = 'An attestation letter nobody checked is a claim. It '
      + 'promotes nothing.';
    attWrap.appendChild(chip);
  }
  rf.appendChild(attWrap);
  real.appendChild(rf);
  card.appendChild(real);

  const cands = c.selector_candidates || [];
  if (cands.length) {
    const p = el('p', 'why');
    p.textContent = cands.length + ' selector candidate'
      + (cands.length === 1 ? '' : 's') + ' (durable fields only)';
    p.title = cands.map((x) => x.selector_type + ' ' + x.value
      + ' (' + x.strength + '): ' + x.why).join('\n');
    card.appendChild(p);
  }
  /* On a call the note is where the pretext lives, and in the demo the
     only line that says what attestation C means. */
  const note = dcpNote(c.note_segments, c.recorded_by_name, c.recorded_at);
  if (note) card.appendChild(note);
  return card;
}

/* --- wiring ------------------------------------------------------------ */

/* --- Collected: the Phase 4 read path ----------------------------------
 *
 * The collector wrote `collect.document` and `collect.watch_hit` from the
 * day the phase landed, and nothing read them: no endpoint, no UI, no
 * search reach. The only trace of a poll an analyst could see was three
 * integers on a run card, so a watch that fired four hundred times showed
 * the number 400 and nothing to open.
 *
 * Two lists, loaded independently and never in one `Promise.all`: hits are
 * case-scoped behind `collection.read` ON THE CASE, documents are global
 * behind the same permission GLOBALLY. Those are different checks and one
 * can be refused while the other succeeds.
 */
/* ux12-feeds:collected-stale-across-case-switch (2026-09-22). Nothing
 * cleared this list on a case switch, so KESTREL's Collected tab showed
 * "No watch has matched anything on this case yet." from a read of
 * NIGHTJAR that KESTREL was never asked, and with hits it would have shown
 * NIGHTJAR's AMBER excerpts and handles under a TLP:GREEN header, with an
 * Acknowledge that posted NIGHTJAR's hit id to KESTREL's path. The hits
 * now go on the switch and load when the sub-tab is entered; the global
 * documents list below is not case-scoped and keeps its own Load. */
const COL_HITS_NOT_LOADED = 'Not loaded for this case yet.';

onCaseSwitch(() => {
  clear($('col-hits-list'));
  $('col-hits-counts').textContent = '';
  $('col-hits-empty').textContent = COL_HITS_NOT_LOADED;
  show($('col-hits-empty'), true);
  clearLoadFailure('col-hits-empty');
});

async function loadWatchHits() {
  if (!state.caseId) return;
  const unack = $('col-hits-unack').checked;
  const token = caseToken();
  try {
    const q = new URLSearchParams({ limit: '100' });
    if (unack) q.set('unacknowledged_only', 'true');
    const body = await api(cpath('/collection/watch-hits') + '?' + q.toString());
    if (caseChanged(token)) return;
    const hits = body.hits || [];
    renderList('col-hits-list', 'col-hits-empty', hits, watchHitRow);
    $('col-hits-counts').textContent = hits.length
      ? countOf(hits.length, 'hit', 'hits') + ', ' + (body.unacknowledged || 0)
        + ' unread'
      : '';
    if (!hits.length) {
      $('col-hits-empty').textContent = unack
        ? 'Nothing unacknowledged on this case.'
        : 'No watch has matched anything on this case yet.';
    }
  } catch (err) {
    if (caseChanged(token)) return;
    renderList('col-hits-list', 'col-hits-empty', [], watchHitRow);
    $('col-hits-counts').textContent = '';
    if (err instanceof ApiError && (err.status === 403 || err.status === 404)) {
      $('col-hits-empty').textContent = refusalText(
        err, 'Watch hits need collection.read on this case.');
      return;
    }
    /* The shared failure notice, so this pane offers the same Retry as
       every other one. */
    $('col-hits-empty').textContent = COL_HITS_NOT_LOADED;
    showLoadFailure('col-hits-empty', "This case's watch hits", err,
      loadWatchHits);
  }
}

function watchHitRow(h) {
  const card = el('div', 'card row-card');
  const head = el('div', 'row-head');
  if (h.score !== null && h.score !== undefined) {
    head.appendChild(el('span', 'score' + (h.score >= 0.8 ? ' hot' : ''),
      Number(h.score).toFixed(2)));
  }
  /* A forum title is attacker-chosen text. */
  head.appendChild(el('span', 'row-title',
    visibleText(h.title || '(untitled)')));
  if (!h.acknowledged_at) head.appendChild(el('span', 'chip warn', 'unread'));
  if (h.suppressed) {
    const chip = el('span', 'chip', 'suppressed');
    chip.title = h.suppress_reason || 'suppressed by alert hygiene';
    head.appendChild(chip);
  }
  head.appendChild(el('span', 'chip small', h.classification));
  card.appendChild(head);

  const facts = el('div', 'facts');
  facts.appendChild(fact('watch', visibleText(h.watch_name)));
  facts.appendChild(fact('author', visibleText(h.author_handle)));
  facts.appendChild(fact('posted', fmtTime(h.posted_at)));
  // The collector writes matched_on as a LIST of reasons ("regex:...",
  // "selector:..."). This rendered Object.keys() of it, which on a list is
  // its indices -- so every real hit said it fired on "0" or "0, 1". The
  // read-path test fixture had fabricated a dict, and both sides were
  // green. A dict is still accepted for any legacy row; a list renders as
  // the reasons themselves.
  const why = Array.isArray(h.matched_on)
    ? h.matched_on : Object.keys(h.matched_on || {});
  facts.appendChild(fact('matched', why.join(', ')));
  card.appendChild(facts);

  if (h.excerpt) card.appendChild(el('p', 'muted small', visibleText(h.excerpt)));
  /* The URL is DISPLAYED and never linked: fetching attacker
     infrastructure from an analyst's browser announces the investigation
     (docs/19) and hands over a referer. Same rule as the capture pane. */
  if (h.external_url) {
    card.appendChild(el('p', 'mono small', visibleText(h.external_url)));
  }
  if (h.suppressed && h.suppress_reason) {
    card.appendChild(el('p', 'help', 'Suppressed: ' + h.suppress_reason));
  }

  if (!h.acknowledged_at) {
    const ack = el('button', 'btn ghost small', 'Acknowledge');
    ack.type = 'button';
    ack.addEventListener('click', async () => {
      ack.disabled = true;
      try {
        await api(cpath('/collection/watch-hits/' + encodeURIComponent(h.id)
                        + '/acknowledge'), { method: 'POST' });
        loadWatchHits();
      } catch (err) { ack.disabled = false; fail(err); }
    });
    card.appendChild(ack);
  } else {
    card.appendChild(el('p', 'muted small',
      'Acknowledged ' + fmtTime(h.acknowledged_at)));
  }
  return card;
}

async function loadCollectedDocuments() {
  const triage = $('col-doc-triage').value;
  try {
    const q = new URLSearchParams({ limit: '100' });
    if (triage) q.set('triage_state', triage);
    const body = await api('/collection/documents?' + q.toString());
    const docs = body.documents || [];
    renderList('col-doc-list', 'col-doc-empty', docs, collectedDocRow);
    $('col-doc-counts').textContent = docs.length
      ? countOf(docs.length, 'document', 'documents') : '';
    if (!docs.length) {
      $('col-doc-empty').textContent =
        'Nothing collected yet at your clearance.';
    }
  } catch (err) {
    renderList('col-doc-list', 'col-doc-empty', [], collectedDocRow);
    $('col-doc-counts').textContent = '';
    if (err instanceof ApiError && err.status === 403) {
      $('col-doc-empty').textContent = refusalText(
        err, 'Collected documents need collection.read.');
      return;
    }
    $('col-doc-empty').textContent = refusalText(
      err, 'Documents could not be read. They are not known to be absent.');
  }
}

function collectedDocRow(d) {
  const card = el('div', 'card row-card compact');
  const head = el('div', 'row-head');
  head.appendChild(el('span', 'row-title', visibleText(d.title || '(untitled)')));
  head.appendChild(el('span', 'chip small', d.triage_state));
  head.appendChild(el('span', 'chip small', d.classification));
  if (d.is_deleted_upstream) {
    const chip = el('span', 'chip warn', 'deleted upstream');
    chip.title = 'Gone from the source since capture. This copy is why '
               + 'collection persists what it reads.';
    head.appendChild(chip);
  }
  card.appendChild(head);
  const facts = el('div', 'facts');
  facts.appendChild(fact('source', visibleText(d.source_name)));
  facts.appendChild(fact('author', visibleText(d.author_handle)));
  facts.appendChild(fact('posted', fmtTime(d.posted_at)));
  if (d.version > 1) facts.appendChild(fact('version', d.version));
  card.appendChild(facts);
  if (d.excerpt) {
    card.appendChild(el('p', 'muted small', visibleText(d.excerpt)));
  }
  /* Says the excerpt is an excerpt. Without it a truncated post reads as
     a short one, and "the thread said nothing more" is a finding. */
  if (d.truncated) {
    card.appendChild(el('p', 'help',
      'Excerpt of ' + d.body_length + ' characters.'));
  }
  if (d.external_url) {
    card.appendChild(el('p', 'mono small', visibleText(d.external_url)));
  }
  return card;
}

/** The roles this panel may grant — the SAME set as
 *  `iam_admin.GRANTABLE_ROLES`, which the server enforces.
 *
 *  Named once because it is a contract, not a menu: the server widened
 *  its allowlist to ten and the two pickers here still offered six, so a
 *  deployment could not staff its own collection surface from the panel
 *  that exists so nobody has to shell into the server. SERVICE is
 *  deliberately absent on both sides — it is a machine identity.
 *  Asserted against the Python set by `test_ui_invariants.py`.
 */
const GRANTABLE_ROLES = ['ANALYST', 'CASE_OWNER', 'COLLECTOR', 'CONTRIBUTOR',
                         'LIAISON', 'MALWARE_ANALYST', 'READ_ONLY',
                         'REVIEWER', 'SECURITY_OFFICER', 'SYS_ADMIN'];

/* --- Admin: role names --------------------------------------------------
 *
 * The owner's decision of 2026-09-22 (migration 0062): CASE_OWNER is shown
 * by the name Lead investigator. The KEY is unchanged, so nothing that checks a
 * permission moves; what moves is every place this pane shows a role to a
 * person, which until then was the raw key in all four (the account card,
 * the grant picker, the revoke buttons and the create form).
 *
 * The names come from `GET /admin/roles`, which reads `iam.role`, and are
 * not written down here: a label table in the console is a second copy of
 * the server's, and the copy is the one that goes stale. The key stays in
 * each option's value and in a tooltip, because the readiness register and
 * the docs speak keys. If the names cannot be read, the keys stand in, so
 * the pane degrades to what it showed before rather than to blanks.
 */
const roleNames = new Map();

async function loadRoleNames() {
  try {
    const body = await api('/admin/roles');
    roleNames.clear();
    for (const r of body.roles || []) roleNames.set(r.key, r.display_name);
  } catch (_) {
    /* A refusal here is the same refusal /admin/users reports in full
       beside it; the keys are an honest fallback for a label. */
  }
  labelRoleOptions($('adm-roles'));
}

/** The name a person reads for a role key, or the key when no name is known. */
function roleLabel(key) {
  return roleNames.get(key) || key;
}

/** "Lead investigator (CASE_OWNER)", the console's name-then-key form for a
 *  picker (the ontology pickers read the same way). */
function roleOptionText(key) {
  const name = roleNames.get(key);
  return name ? name + ' (' + key + ')' : key;
}

/** Relabel a static role picker in place. The option VALUE is pinned to the
 *  key first: an <option> with no value attribute submits its text, and
 *  its text is about to become a name the server would refuse. */
function labelRoleOptions(select) {
  if (!select) return;
  for (const o of select.options) {
    const key = o.value;
    o.value = key;
    o.textContent = roleOptionText(key);
    o.title = key;
  }
}

/* --- Admin: analyst accounts -------------------------------------------
 *
 * Behind `user.manage` (SYS_ADMIN, step-up) — the server refuses, this
 * pane only explains. Two rules carried from the rest of the console:
 * a 403 is not an empty state, and credentials render exactly once.
 */
async function loadAdminUsers() {
  try {
    /* Names alongside the accounts, so a card is drawn with them
       (loadRoleNames never throws). */
    const [body] = await Promise.all([api('/admin/users'), loadRoleNames()]);
    state.adminYou = body.you;
    renderList('adm-list', 'adm-empty', body.users || [], adminUserRow);
    $('adm-counts').textContent = body.count
      ? countOf(body.count, 'account', 'accounts') + ', '
        + (body.users || []).filter((u) => u.is_active).length + ' active'
      : '';
  } catch (err) {
    renderList('adm-list', 'adm-empty', [], adminUserRow);
    $('adm-counts').textContent = '';
    if (err instanceof ApiError && err.status === 403) {
      $('adm-empty').textContent = refusalText(
        err, 'Managing accounts needs user.manage (SYS_ADMIN), and it is '
        + 'step-up: sign in again if your re-challenge has expired.');
      return;
    }
    $('adm-empty').textContent = refusalText(
      err, 'Accounts could not be read. They are not known to be absent.');
  }
}

async function adminAct(path, opts, btn) {
  if (btn) btn.disabled = true;
  try {
    const body = await api(path, opts);
    await loadAdminUsers();
    return body;
  } catch (err) {
    if (btn) btn.disabled = false;
    /* The refusals here are RULES (last SYS_ADMIN, own account, stranded
       owner), so they surface as statements, not error banners. */
    if (err instanceof ApiError) inlineProblem($('adm-counts'), err);
    else fail(err);
    return null;
  }
}

function adminUserRow(u) {
  const card = el('div', 'card row-card');
  const head = el('div', 'row-head');
  head.appendChild(el('span', 'row-title',
    visibleText(u.display_name) + ' (' + visibleText(u.email) + ')'));
  head.appendChild(el('span', 'chip tlp-' + u.tlp_clearance, u.tlp_clearance));
  if (!u.is_active) head.appendChild(el('span', 'chip bad', 'DEACTIVATED'));
  if (u.locked_until) {
    const chip = el('span', 'chip warn', 'LOCKED');
    chip.title = 'Locked until ' + fmtTime(u.locked_until) + ' after '
               + u.failed_logins + ' failed logins.';
    head.appendChild(chip);
  }
  if (!u.totp_enrolled) head.appendChild(el('span', 'chip warn', 'no TOTP'));
  if (u.id === state.adminYou) head.appendChild(el('span', 'chip flag', 'you'));
  card.appendChild(head);

  const facts = el('div', 'facts');
  facts.appendChild(fact('roles',
    (u.roles || []).map(roleLabel).join(', ') || 'none'));
  facts.appendChild(fact('last login', u.last_login_at
    ? fmtTime(u.last_login_at) : 'never'));
  facts.appendChild(fact('created', fmtTime(u.created_at)));
  card.appendChild(facts);
  /* The account id, copyable. Sharing a case asked for exactly this id and
     no screen showed it (ux16 no-user-id-for-share, 2026-09-22). Share now
     takes an email; the id stays here for the API and for support. */
  const idLine = el('p', 'help adm-id');
  idLine.appendChild(el('span', 'fact-k', 'account id'));
  idLine.appendChild(copyable(el('code', 'mono', u.id), u.id, 'account id'));
  card.appendChild(idLine);

  const actions = el('div', 'row-actions');
  const act = (label, path, opts, title) => {
    const b = el('button', 'btn ghost small', label);
    b.type = 'button';
    if (title) b.title = title;
    b.addEventListener('click', () => adminAct(path, opts, b));
    actions.appendChild(b);
    return b;
  };

  if (u.is_active) {
    const d = act('Deactivate', '/admin/users/' + u.id + '/deactivate',
                  { method: 'POST' },
                  'Revokes their sessions. The account and its history '
                  + 'remain, and every past action stays attributed.');
    if (u.id === state.adminYou) {
      /* The server refuses this anyway; disabling it here keeps the
         refusal from reading like a fault. */
      d.disabled = true;
      d.title = 'You cannot deactivate your own account.';
    }
  } else {
    act('Reactivate', '/admin/users/' + u.id + '/reactivate',
        { method: 'POST' });
  }
  if (u.locked_until) {
    act('Unlock', '/admin/users/' + u.id + '/unlock', { method: 'POST' });
  }
  const totpBtn = el('button', 'btn ghost small', 'Re-enrol TOTP');
  totpBtn.type = 'button';
  totpBtn.title = 'Issues a NEW secret; the old authenticator stops '
                + 'working immediately. For the analyst whose phone is gone.';
  totpBtn.addEventListener('click', async () => {
    if (!window.confirm('Issue a new TOTP secret for ' + u.email + '?\n\n'
        + 'Their current authenticator stops working the moment this is '
        + 'done, and the new secret is shown once.')) return;
    const creds = await adminAct('/admin/users/' + u.id + '/totp',
                                 { method: 'POST' }, totpBtn);
    if (creds) renderOneTimeCreds($('adm-creds'), creds);
  });
  actions.appendChild(totpBtn);

  /* Clearance and role edits: small selects beside their verbs, because a
     wrong pick plus an eager handler is an authz change nobody meant.
     Nothing fires until its button is pressed. */
  const clr = el('select', 'select');
  for (const c of ['CLEAR', 'GREEN', 'AMBER', 'RED']) {
    const o = el('option', null, c); o.value = c;
    if (c === u.tlp_clearance) o.selected = true;
    clr.appendChild(o);
  }
  actions.appendChild(clr);
  const setClr = el('button', 'btn ghost small', 'Set clearance');
  setClr.type = 'button';
  setClr.title = 'Their ceiling everywhere. Lowering below a case they own '
               + 'is refused. Transfer or close those cases first.';
  setClr.addEventListener('click', () => adminAct(
    '/admin/users/' + u.id + '/clearance',
    { method: 'POST', json: { clearance: clr.value } }, setClr));
  actions.appendChild(setClr);

  const roleSel = el('select', 'select');
  for (const r of GRANTABLE_ROLES) {
    if ((u.roles || []).includes(r)) continue;
    const o = el('option', null, roleOptionText(r));
    o.value = r;
    o.title = r;
    roleSel.appendChild(o);
  }
  if (roleSel.options.length) {
    actions.appendChild(roleSel);
    const g = el('button', 'btn ghost small', 'Grant role');
    g.type = 'button';
    g.addEventListener('click', () => adminAct(
      '/admin/users/' + u.id + '/roles',
      { method: 'POST', json: { role: roleSel.value } }, g));
    actions.appendChild(g);
  }
  for (const r of u.roles || []) {
    const b = el('button', 'btn ghost small', 'Revoke ' + roleLabel(r));
    b.type = 'button';
    b.title = 'Revoke the ' + r + ' role from this account.';
    b.addEventListener('click', () => adminAct(
      '/admin/users/' + u.id + '/roles/' + encodeURIComponent(r),
      { method: 'DELETE' }, b));
    actions.appendChild(b);
  }
  card.appendChild(actions);
  if (u.is_active) card.appendChild(adminAssignBox(u));
  return card;
}

/** "Add to a case" from the account card, so creating an analyst and
 *  putting them on a case is one loop in one place (ux16
 *  no-user-id-for-share, 2026-09-22). Offers the cases THIS administrator
 *  can open; the server still requires case.grant on the one picked. */
function adminAssignBox(u) {
  const det = el('details', 'adm-assign');
  det.appendChild(el('summary', null, 'Add to a case'));
  const cases = state.cases || [];
  if (!cases.length) {
    det.appendChild(el('p', 'help',
      'You are on no case yourself, so there is none to offer here. A case '
      + 'owner can add them from the case\'s Share panel, by work email.'));
    return det;
  }
  const row = el('div', 'row-actions');
  const caseSel = el('select', 'select');
  caseSel.setAttribute('aria-label', 'Case');
  opts(caseSel, cases.map((c) => [c.id, c.code]), cases[0].id);
  const roleSel = el('select', 'select');
  roleSel.setAttribute('aria-label', 'Case role');
  opts(roleSel, CASE_ROLES.map((r) => [r, r]), 'ANALYST');
  const go = el('button', 'btn ghost small', 'Add');
  go.type = 'button';
  const msg = el('p', 'msg');
  msg.hidden = true;
  go.addEventListener('click', async () => {
    go.disabled = true;
    const c = cases.find((x) => x.id === caseSel.value);
    try {
      const body = await api('/cases/' + caseSel.value + '/users', {
        method: 'POST', json: { user_id: u.id, role_key: roleSel.value },
      });
      setMsg(msg, shareOutcome(body, c ? c.code : 'the case'));
    } catch (err) {
      setMsg(msg, shareRefusal(err));
    } finally {
      go.disabled = false;
    }
  });
  row.append(caseSel, roleSel, go);
  det.append(row, msg);
  return det;
}

function initAdmin() {
  $('btn-admin').addEventListener('click', showAdmin);
  $('adm-refresh').addEventListener('click', loadAdminUsers);
  /* The button has been in the markup since the register shipped and was
     wired to nothing: `selectTab('admin')` called loadReadiness once and
     the control that says "Check readiness" did nothing at all when
     pressed. An operator who had just changed a variable and restarted the
     API had no way to re-ask short of reloading the console. */
  $('btn-readiness').addEventListener('click', loadReadiness);
  $('adm-create').addEventListener('submit', async (e) => {
    e.preventDefault();
    setMsg($('adm-create-error'), '');
    $('adm-create-btn').disabled = true;
    try {
      const roles = [...$('adm-roles').selectedOptions].map((o) => o.value);
      const creds = await api('/admin/users', {
        method: 'POST',
        json: { email: $('adm-email').value.trim(),
                display_name: $('adm-name').value.trim(),
                clearance: $('adm-clearance').value, roles: roles },
      });
      renderOneTimeCreds($('adm-creds'), creds);
      $('adm-email').value = ''; $('adm-name').value = '';
      await loadAdminUsers();
    } catch (err) {
      if (err instanceof ApiError) {
        setMsg($('adm-create-error'), err.detail || err.title);
      } else { fail(err); }
    } finally {
      $('adm-create-btn').disabled = false;
    }
  });
}

/* --- Administration without a case ------------------------------------
 *
 * ux16 admin-unreachable-without-a-case (2026-09-22). The accounts panel
 * and the readiness register are deployment-wide, and the only way in was
 * a rail tab inside a case. 0021 gives SYS_ADMIN user.manage and no
 * case.read on purpose (the administrator configures, nobody reads case
 * content by default), so an administrator created the way the model
 * intends signed in to "No cases are open to you yet" with no way in, and
 * a first administrator had to invent a case, lawful basis and all, before
 * they could add a colleague.
 *
 * The pane is not duplicated. `showAdmin` moves #pane-admin into
 * #view-admin and the case-switch reset moves it home, so the in-case tab,
 * its ids and its loaders are the same ones.
 */
let canAdmin = false;       // user.manage: accounts and readiness
let canReview = false;      // break_glass.review: the officer's queue
let adminView = false;
let adminHome = null;
let reviewHome = null;

/** The deployment view's name, by what the account may do there. An
 *  officer-only account's view holds the break-glass review queue AND the
 *  preserved-sample authorisations, so it is not named for one of them
 *  (final review U3, 2026-09-23). */
function adminViewName() {
  return canReview && !canAdmin ? 'Oversight' : 'Administration';
}

/** The entry button's tooltip, for the same two kinds of account. */
function adminViewTitle() {
  return canReview && !canAdmin
    ? 'The break-glass review queue and the preserved-sample authorisations. '
      + 'They cover the whole deployment, so no case is needed.'
    : 'Accounts and the readiness register. They cover the whole '
      + 'deployment, so no case is needed.';
}

async function loadAdminAccess() {
  let access = {};
  try {
    access = await api('/admin/access');
  } catch (_err) {
    access = {};
  }
  canAdmin = !!access.user_manage;
  /* The officer's queue is global, and SECURITY_OFFICER is assigned to no
     case by design: reachable only through a case's Lifecycle pane, it
     was unreachable for exactly the account whose job it is. */
  canReview = !!access.break_glass_review;
}

async function refreshAdminEntry() {
  const btn = $('btn-admin');
  if (state.caseId || adminView) { show(btn, false); return; }
  await loadAdminAccess();
  btn.textContent = adminViewName();
  btn.title = adminViewTitle();
  show(btn, (canAdmin || canReview) && !state.caseId && !adminView);
}

async function showAdmin() {
  if (state.caseId) { selectTab('admin'); return; }
  /* Asked again rather than trusted from the last list render: a
     `#tab=admin` deep link arrives before that read has answered. */
  const token = caseToken();
  await loadAdminAccess();
  if (state.caseId || caseChanged(token)) return;
  const pane = $('pane-admin');
  const review = $('glass-review');
  if (!adminHome) adminHome = { parent: pane.parentNode, next: pane.nextSibling };
  if (!reviewHome) reviewHome = { parent: review.parentNode, next: review.nextSibling };
  adminView = true;
  /* An account holding neither verb still gets the accounts pane, which
     explains its own refusal: the honest answer to a hand-typed link. */
  const accounts = canAdmin || !canReview;
  if (accounts) {
    $('view-admin').appendChild(pane);
    show(pane, true);
  }
  if (canReview) {
    $('view-admin').appendChild(review);
    loadGlassQueue();
  }
  /* The officer's preserved samples (final review U3, 2026-09-23), built
     and loaded by the Lab code; hidden for an account that is not one. */
  showPreservedReview(canReview);
  show($('view-cases'), false);
  show($('view-admin'), true);
  show($('btn-admin'), false);
  show($('btn-cases'), true);
  /* No case is open, so none of the case chrome applies. */
  for (const id of ['hdr-tlp', 'hdr-asof', 'btn-case-edit', 'btn-case-share',
                    'btn-case-status']) {
    show($(id), false);
  }
  $('hdr-case').textContent = adminViewName();
  if (accounts) {
    loadAdminUsers();
    loadReadiness();
    pane.focus();
  }
}

function leaveAdmin() {
  if (!adminView) return;
  adminView = false;
  const pane = $('pane-admin');
  if (adminHome && pane.parentNode !== adminHome.parent) {
    adminHome.parent.insertBefore(pane, adminHome.next);
  }
  show(pane, false);
  const review = $('glass-review');
  if (reviewHome && review.parentNode !== reviewHome.parent) {
    reviewHome.parent.insertBefore(review, reviewHome.next);
  }
  show($('view-admin'), false);
}

onCaseSwitch(() => {
  leaveAdmin();
  /* After the switch has set (or cleared) the case: the entry is offered
     on the list only, where the rail is not. */
  setTimeout(refreshAdminEntry, 0);
});

/* --- Share: who is on this case ----------------------------------------
 *
 * ux02 share-needs-raw-uuid-and-hides-result, ux16 no-user-id-for-share
 * and ux19 raw-ids-instead-of-names (2026-09-22). Share was two
 * window.prompt calls: an `iam.app_user.id` that no screen available to a
 * case owner ever showed, then a free-text role. The server's answer (who
 * it was, what it replaced, what it confers) was thrown away for
 * "Assigned", the roster endpoint had no caller, and there was no way to
 * take anyone off again.
 *
 * The panel shows the roster by name, with whether each assignment
 * actually opens the case and why not; adds a colleague by work email,
 * which the server resolves to their account id one address at a time
 * (the stored grant is still by id, so it follows the person, not the
 * mailbox); names what a regrade replaced; and removes.
 */
const CASE_ROLES = ['ANALYST', 'REVIEWER', 'CONTRIBUTOR', 'READ_ONLY', 'LIAISON'];
let shareReturn = null;

/** The name a person reads for a role on this panel: the server's
 *  `*_name` beside each key, so CASE_OWNER reads as Lead investigator for
 *  every case worker and not only for an administrator, whose
 *  `/admin/roles` is the only other source (final review U21,
 *  2026-09-23). The key stands in when no name came back. */
function shareRoleName(name, key) {
  return visibleText(name || key || '');
}

function shareOutcome(body, code) {
  const who = visibleText(body.display_name || 'They');
  const n = (body.grants || []).length;
  const confers = ' The role confers ' + n + ' permission' + (n === 1 ? '' : 's')
    + ' on this case.';
  const ends = body.expires_at ? ' Access ends ' + fmtTime(body.expires_at) + '.' : '';
  const now = shareRoleName(body.role_name, body.role_key);
  if (!body.replaced_role) {
    return who + ' is now ' + now + ' on ' + code + '.' + ends + confers;
  }
  if (body.replaced_role === body.role_key) {
    return who + ' was already ' + now + ' on ' + code
      + ', so the grade is unchanged.' + ends;
  }
  /* Invariant 12: a demotion must not read like an addition. */
  return who + ' was ' + shareRoleName(body.replaced_role_name, body.replaced_role)
    + ' on ' + code + ' and is now ' + now + '.' + ends + confers;
}

function shareRefusal(err) {
  if (err instanceof ApiError && err.status === 403) {
    return refusalText(err, 'Sharing a case needs case.grant on it (its '
      + 'owner holds it) and a fresh second factor.');
  }
  if (err instanceof ApiError) return err.detail || err.title;
  return 'The request did not complete. Nothing is known to have changed.';
}

function openShare() {
  /* `state.caseId` is null on the case LIST, and these buttons live in the
     appbar, which the list does not hide. */
  if (!state.caseId) return;
  shareReturn = document.activeElement;
  $('share-title').textContent = 'Who is on '
    + (state.caseRec ? state.caseRec.code : 'this case');
  const role = $('share-role');
  if (!role.options.length) opts(role, CASE_ROLES.map((r) => [r, r]), 'ANALYST');
  setMsg($('share-msg'), '');
  /* Add and Remove wait for the roster to say whether this caller can use
     them; until then focus sits on Close, inside the dialog. */
  shareCanGrant(false, true);
  show($('share-scrim'), true);
  $('share-close').focus();
  loadShareRoster();
}

/** Offer Add and Remove only to a caller whose case role carries
 *  case.grant (the roster's `you_can_grant`). Every roster reader was
 *  offered both, LIAISON and READ_ONLY included, and every click ended in a
 *  403 (2026-09-23). The server still decides; this only stops the console
 *  offering what it knows will be refused. `pending` hides both without
 *  the read-only line while the roster is in flight. */
function shareCanGrant(can, pending) {
  show($('share-add-box'), can);
  show($('share-add'), can);
  show($('share-readonly'), !can && !pending);
}

function closeShare() {
  if ($('share-scrim').hidden) return;
  show($('share-scrim'), false);
  const back = shareReturn;
  shareReturn = null;
  if (back && typeof back.focus === 'function' && document.contains(back)) {
    back.focus();
  }
}

onCaseSwitch(() => {
  closeShare();
  shareCanGrant(false, true);   // the next case's roster decides afresh
  clear($('share-roster'));
  setMsg($('share-roster-msg'), '');
  setMsg($('share-msg'), '');
  $('share-email').value = '';
  $('share-expires').value = '';
});

async function loadShareRoster() {
  const token = caseToken();
  const box = $('share-roster');
  const note = $('share-roster-msg');
  setMsg(note, '');
  clear(box);
  let body;
  try {
    body = await api('/cases/' + state.caseId + '/users');
  } catch (err) {
    if (caseChanged(token)) return;
    setMsg(note, err instanceof ApiError && err.status === 403
      ? refusalText(err, 'The roster needs case.read on this case.')
      : 'The roster could not be read. It is not known to be empty.');
    /* Not known either way, so the form is offered and the server
       answers. */
    shareCanGrant(true);
    return;
  }
  if (caseChanged(token)) return;
  const can = body.you_can_grant !== false;
  shareCanGrant(can);
  if (can && document.activeElement === $('share-close')) $('share-email').focus();
  const users = body.users || [];
  for (const u of users) box.appendChild(shareRow(u, can));
  if (!users.length) setMsg(note, 'Nobody is assigned to this case.');
}

function shareRow(u, canGrant) {
  const row = el('div', 'card row-card compact share-row');
  const head = el('div', 'row-head');
  const name = visibleText(u.display_name || ('account ' + shortId(u.user_id)));
  head.appendChild(el('span', 'row-title', name));
  const role = shareRoleName(u.role_name, u.role_key);
  const chip = el('span', 'chip', role);
  chip.title = u.role_key;      // the key the docs and the register speak
  head.appendChild(chip);
  if (u.is_owner) head.appendChild(el('span', 'chip flag', 'owner'));
  head.appendChild(el('span', 'chip ' + (u.effective ? 'ok' : 'bad'),
    u.effective ? 'can open the case' : 'cannot open the case'));
  row.appendChild(head);
  const facts = el('div', 'facts');
  facts.appendChild(fact('added', fmtTime(u.granted_at)));
  if (u.granted_by_name) facts.appendChild(fact('by', u.granted_by_name));
  facts.appendChild(fact(u.expired ? 'ended' : 'ends',
    u.expires_at ? fmtTime(u.expires_at) : 'no end date', u.expired ? 'bad' : ''));
  /* Sent only to a caller who can manage the roster, and only while this
     colleague opens the case through a break-glass grant rather than
     their own clearance: at that instant they drop back to "cannot open",
     and a clearance change, not a re-share, is what fixes it (final
     review U22, 2026-09-23). */
  if (u.emergency_access_until) {
    facts.appendChild(fact('emergency access ends',
      fmtTime(u.emergency_access_until), 'warn'));
  }
  row.appendChild(facts);
  if (!u.effective && (u.reasons || []).length) {
    row.appendChild(el('p', 'help warn', 'Why not: ' + u.reasons.join('; ') + '.'));
  }
  if (!u.is_owner && canGrant) {
    const actions = el('div', 'row-actions');
    const rm = el('button', 'btn ghost small danger-text', 'Remove from case');
    rm.type = 'button';
    rm.addEventListener('click', async () => {
      const code = state.caseRec ? state.caseRec.code : 'this case';
      if (!window.confirm('Take ' + name + ' off ' + code + '?\n\nTheir '
          + role + ' access ends at once. The grant and its removal '
          + 'both stay in the audit trail, and they can be added again.')) return;
      rm.disabled = true;
      const token = caseToken();
      try {
        const out = await api('/cases/' + state.caseId + '/users/'
          + encodeURIComponent(u.user_id), { method: 'DELETE' });
        if (caseChanged(token)) return;
        setMsg($('share-msg'), visibleText(out.display_name || name)
          + ' is no longer on ' + code + ' (was '
          + shareRoleName(out.revoked_role_name, out.revoked_role) + ').');
        loadShareRoster();
      } catch (err) {
        rm.disabled = false;
        if (!caseChanged(token)) setMsg($('share-msg'), shareRefusal(err));
      }
    });
    actions.appendChild(rm);
    row.appendChild(actions);
  }
  return row;
}

async function submitShare(e) {
  e.preventDefault();
  const msg = $('share-msg');
  setMsg(msg, '');
  if (!state.caseId) return;
  const email = $('share-email').value.trim();
  if (email.indexOf('@') < 1) {
    setMsg(msg, 'Enter the colleague\'s work email address.');
    return;
  }
  const payload = { email, role_key: $('share-role').value };
  const ends = $('share-expires').value;
  if (ends) {
    /* datetime-local is read as LOCAL time, and toISOString writes UTC
       with a Z: the instant is the one the owner meant, and the offset
       the server insists on is always present. */
    const at = new Date(ends);
    if (Number.isNaN(at.getTime())) {
      setMsg(msg, 'That end time is not a date the browser can read.');
      return;
    }
    payload.expires_at = at.toISOString();
  }
  const code = state.caseRec ? state.caseRec.code : 'this case';
  const btn = $('share-add');
  btn.disabled = true;
  const token = caseToken();
  try {
    const body = await api('/cases/' + state.caseId + '/users',
      { method: 'POST', json: payload });
    if (caseChanged(token)) return;
    setMsg(msg, shareOutcome(body, code));
    $('share-email').value = '';
    $('share-expires').value = '';
    loadShareRoster();
  } catch (err) {
    if (!caseChanged(token)) setMsg(msg, shareRefusal(err));
  } finally {
    btn.disabled = false;
    /* Back to the address box: disabling the button in flight dropped
       focus to <body>, outside the dialog. */
    if (!$('share-scrim').hidden) $('share-email').focus();
  }
}

let selectFeedsSub = null;
let selectGovSub = null;
let selectSamplesSub = null;
let selectDeceptionSub = null;

function initOpsPanes() {
  selectFeedsSub = initSubtabs('pane-feeds', (name) => {
    if (name === 'queue') loadIngestQueue();
    if (name === 'dead') loadDeadLetters();
    if (name === 'sources') loadSources();
    /* Watch hits load on entry: they are case-scoped and cheap, and a
       list that waited for Load was the one that showed the previous
       case's answer (ux12-feeds, 2026-09-22). Documents are NOT loaded on
       entry: that list is global rather than case-scoped and can be long,
       so it sits behind its own Load, the way co-participation and the
       report do. */
    if (name === 'collected') loadWatchHits();
    if (name === 'keys') loadKeys();
  });
  $('col-hits-refresh').addEventListener('click', loadWatchHits);
  $('col-hits-unack').addEventListener('change', loadWatchHits);
  $('col-doc-refresh').addEventListener('click', loadCollectedDocuments);
  $('col-doc-triage').addEventListener('change', loadCollectedDocuments);
  /* The deliveries view is fetched on selection rather than on sign-in:
     it needs integration.manage, which most accounts do not hold, and a
     403 banner on every login would train people to ignore banners. */
  initSubtabs('pane-ach', (name) => {
    if (name === 'assumptions') loadAssumptions();
  });
  initSubtabs('pane-inbox', (name) => {
    if (name === 'deliveries') loadDeliveries();
  });
  selectGovSub = initSubtabs('pane-governance', (name) => {
    if (name === 'retention') { purgeDefaults(); loadRetention(); }
    if (name === 'tombstones') loadTombstones();
    if (name === 'glass') loadBreakGlass();
  });
  selectSamplesSub = initSubtabs('pane-samples', (name) => {
    if (name === 'queue') loadSamples();
    if (name === 'submit') fillSampleCase();
  });
  selectDeceptionSub = initSubtabs('pane-deception', (name) => {
    if (name === 'captures') loadCaptures();
    if (name === 'emails') loadDeceptionEmails();
    if (name === 'calls') loadDeceptionCalls();
  });
  $('dcp-cap-refresh').addEventListener('click', loadCaptures);
  $('dcp-eml-refresh').addEventListener('click', loadDeceptionEmails);
  $('dcp-divergent').addEventListener('change', loadDeceptionEmails);
  $('dcp-call-refresh').addEventListener('click', loadDeceptionCalls);
  /* Focus goes back to the row's Open button: the card is gone, and focus
     left on nothing falls to <body> and the top of the page. */
  $('dcp-cap-close').addEventListener('click', () => dcpDetailClose('cap', true));
  $('dcp-eml-close').addEventListener('click', () => dcpDetailClose('eml', true));
  $('smp-refresh').addEventListener('click', loadSamples);
  $('smp-state').addEventListener('change', loadSamples);
  $('smp-all-cases').addEventListener('change', (e) => {
    smpAllCases = e.target.checked;
    loadSamples();
  });
  $('smp-submit').addEventListener('click', submitSample);
  $('smp-close').addEventListener('click', () => {
    $('smp-detail').classList.remove('is-in');
    show($('smp-detail'), false);
  });

  $('ing-refresh').addEventListener('click', loadIngestQueue);
  $('ing-category').addEventListener('change', loadIngestQueue);
  $('ing-dupes').addEventListener('change', loadIngestQueue);
  $('dl-refresh').addEventListener('click', loadDeadLetters);
  $('src-refresh').addEventListener('click', loadSources);
  $('key-refresh').addEventListener('click', loadKeys);
  $('key-revoked').addEventListener('change', loadKeys);
  $('ret-refresh').addEventListener('click', loadRetention);
  $('ret-purge').addEventListener('click', runPurge);
  $('tomb-refresh').addEventListener('click', loadTombstones);
  $('glass-refresh').addEventListener('click', reloadGlass);
  $('glass-invoke').addEventListener('click', invokeBreakGlass);
  /* The header chip is asked again on the analyst's own activity while a
     grant is listed, never on a bare timer (final review C17). Capture
     phase, so a handler that stops propagation cannot hide the press. */
  document.addEventListener('pointerdown', recheckGlassOnActivity, true);
  document.addEventListener('keydown', recheckGlassOnActivity, true);
  wireGovernanceControls();

  $('ach-refresh').addEventListener('click', loadAch);
  $('ach-rejected').addEventListener('change', loadAch);
  $('ach-add').addEventListener('click', addHypothesis);
  /* Scoring (2026-09-09): the matrix cells open the chooser themselves;
     these wire the first-row scorer and the chooser's own controls. */
  $('ach-evidence-load').addEventListener('click', loadAchEvidenceOfSelection);
  $('ach-evidence-pick').addEventListener('change', updateAchScoreControls);
  $('ach-evidence-hyp').addEventListener('change', updateAchScoreControls);
  $('ach-evidence-add').addEventListener('click', scorePickedAssertion);
  $('ach-stance-form').addEventListener('submit', saveStance);
  $('ach-stance-form').addEventListener('keydown', stanceChooserKeys);
  $('ach-stance-cancel').addEventListener('click', closeStanceChooser);
  $('ach-stance-scrim').addEventListener('click', (e) => {
    if (e.target === e.currentTarget) closeStanceChooser();
  });

  $('comms-pgp-form').addEventListener('submit', verifyPgp);
  $('comms-unverified-refresh').addEventListener('click', loadUnverified);
  $('comms-copart-refresh').addEventListener('click', loadCoParticipation);

  $('rep-build').addEventListener('click', buildReport);
  $('rep-download').addEventListener('click', saveClearedReport);
  $('rep-release').addEventListener('click', releaseReport);
  /* Changing the target invalidates what is on screen: a redaction
     statement for AMBER next to a control set to GREEN is the shape of a
     mistake somebody makes once. The hypotheses box is the same kind of
     choice (it decides whether ACH statements, which often name suspects,
     are in the file), and it had no listener, so a preview made with them
     off could be followed by a file with them on (ux15-report,
     2026-09-22). */
  $('rep-tlp').addEventListener('change', withdrawReport);
  $('rep-hypotheses').addEventListener('change', withdrawReport);
  /* The verdict was about THIS destination, ceiling and note; a changed
     one is a question nobody has asked the gate yet. The note is audited
     with the decision, so it counts too. Both withdrawals also void a
     request still in flight (the generation counters above). */
  $('rep-destination').addEventListener('change', withdrawReportVerdict);
  $('rep-ceiling').addEventListener('change', withdrawReportVerdict);
  $('rep-note').addEventListener('input', withdrawReportVerdict);
}

/* ── LAB: malware samples (Phase 8, invariant 10) ─────────────────────────
 *
 * "Samples never render, never execute. The binary is only ever an
 *  encrypted archive download from a SEPARATE ORIGIN."
 *
 * Everything below renders metadata through `textContent`. There is no
 * innerHTML anywhere in this section, no preview, no hex view, and no
 * iframe — so the question of which `sandbox` attributes are safe to
 * combine never arises, which is the only reliable way to answer it.
 *
 * The attacker controls `original_filename`, `source_note` and every
 * string inside `findings`. They are displayed because an analyst needs
 * them; they are displayed as TEXT.
 */

let smpPolicy = null;             // cached /samples/policy

/* Whether the queue spans every case this viewer can see or only the open
   case. The Lab sits in the case rail under a case header, so it lists
   THAT case's samples unless somebody asks for more; until 2026-09-22 it
   listed every case's and named them by a uuid prefix
   (ux13-lab:lab-not-case-scoped, ux19-copy:lab-shows-other-case-samples). */
let smpAllCases = false;

/* Everything the Lab shows is scoped to the open case now, so a case
   switch clears it like any other pane: the queue, the counts, the badge
   and an open detail card would otherwise sit under the next case's
   header. The "all cases" choice goes back to this case's scope too. */
onCaseSwitch(() => {
  smpAllCases = false;
  $('smp-all-cases').checked = false;
  clear($('smp-list'));
  $('smp-counts').textContent = '';
  show($('smp-empty'), false);
  $('smp-detail').classList.remove('is-in');
  show($('smp-detail'), false);
  clear($('smp-detail-body'));
  show($('samples-badge'), false);
  /* And the submit form (final review U14, 2026-09-23): a file, and the
     note on where it came from, chosen on one case were sent from the
     next case's Lab. The case choice is rebuilt for the new case when the
     Submit tab is next opened. */
  $('smp-file').value = '';
  $('smp-note').value = '';
  clear($('smp-case'));
  setMsg($('smp-submit-msg'), '');
});

/** The submit form's case: the open case by default, or no case at all,
 *  said in words. It was a free-text uuid field, blank by default, and a
 *  blank submit landed a sample with no case, which the case-scoped queue
 *  (ux13-lab:lab-not-case-scoped) does not list: "Quarantined as 3f9a..."
 *  and then an empty queue (final review U14, 2026-09-23). */
function fillSampleCase() {
  const select = $('smp-case');
  const code = state.caseRec ? state.caseRec.code : null;
  const keep = select.value;
  const pairs = (code ? [['case', 'This case: ' + code]] : []).concat([
    ['none', 'No case: unattached, listed only under "All cases I can see"'],
  ]);
  opts(select, pairs, code && keep !== 'none' ? 'case' : 'none');
}

/** The rail badge counts what is WAITING on the open case: quarantined or
 *  triaged, the work nobody has picked up. A badge that counted every
 *  case's samples told an analyst on one case that another case's six
 *  samples were theirs (ux19-copy:lab-shows-other-case-samples), so it
 *  says in its title what it counts. Silent on failure, like the inbox
 *  counter: an analyst without `sample.read` gets no badge, not an error.
 */
async function refreshSampleBadge() {
  const token = caseToken();
  const scoped = state.caseId;
  let rows;
  try {
    rows = (await api('/samples'
      + (scoped ? '?case_id=' + encodeURIComponent(scoped) : ''))).samples || [];
  } catch (_e) {
    if (!caseChanged(token)) show($('samples-badge'), false);
    return;
  }
  if (caseChanged(token)) return;
  paintSampleBadge(rows);
}

function paintSampleBadge(rows) {
  const badge = $('samples-badge');
  const waiting = rows.filter(
    (s) => s.state === 'QUARANTINED' || s.state === 'TRIAGED').length;
  badge.textContent = waiting > 99 ? '99+' : String(waiting);
  badge.title = waiting + ' sample' + (waiting === 1 ? '' : 's')
    + (state.caseRec ? ' on ' + state.caseRec.code : '')
    + ' awaiting triage or assignment';
  show(badge, waiting > 0);
}

/* The words for each queue filter, used in the count line and in the
   empty state. "Nothing in the queue." under a Rejected filter read as
   "nothing was ever rejected", which is the one question the rejected
   path exists to answer (ux13-lab:rejected-filter-always-empty). */
const SAMPLE_STATE_WORDS = {
  QUARANTINED: 'quarantined',
  TRIAGED: 'triaged',
  ASSIGNED: 'assigned',
  IN_ANALYSIS: 'in-analysis',
  REPORTED: 'reported',
  REJECTED: 'rejected',
};

/** Where the queue is looking, in words: the open case by its code, or
 *  every case the viewer's clearance reaches. */
function smpScopeText() {
  if (smpAllCases || !state.caseRec) return 'across every case you can see';
  return 'on ' + state.caseRec.code;
}

function sampleEmptyText(wanted) {
  const scope = smpScopeText();
  if (!wanted) {
    return 'Nothing is waiting ' + scope + ': no sample you are cleared to '
      + 'see is quarantined, triaged or assigned. Choose a state above to '
      + 'see finished or rejected work.';
  }
  return 'No ' + SAMPLE_STATE_WORDS[wanted] + ' samples ' + scope
    + ' that you are cleared to see.';
}

/** The queue. The state and the case go to the SERVER since 2026-09-22:
 *  it used to be fetched as the working set and filtered here, so three
 *  of the six filters could never show a row and a rejected sample, with
 *  the reason somebody was made to type, vanished from the console the
 *  moment it was rejected. Empty `state` means the working set. */
async function loadSamples() {
  const wanted = $('smp-state').value;
  const token = caseToken();
  const params = new URLSearchParams();
  if (wanted) params.set('state', wanted);
  if (!smpAllCases && state.caseId) params.set('case_id', state.caseId);
  const qs = params.toString();
  const empty = $('smp-empty');
  let body;
  try {
    body = await api('/samples' + (qs ? '?' + qs : ''));
  } catch (err) {
    if (caseChanged(token)) return;
    renderList('smp-list', 'smp-empty', [], sampleRow);
    empty.textContent = err instanceof ApiError
      && (err.status === 403 || err.status === 404)
      ? refusalText(err, 'The sample queue needs sample.read. MALWARE_ANALYST '
        + 'holds it and deliberately holds no case access at all.')
      : (err instanceof ApiError ? (err.detail || err.title) : String(err));
    $('smp-counts').textContent = '';
    return;
  }
  if (caseChanged(token)) return;
  const rows = body.samples || [];
  renderList('smp-list', 'smp-empty', rows, sampleRow);
  empty.textContent = sampleEmptyText(wanted);
  $('smp-counts').textContent = rows.length
    ? rows.length + ' ' + (wanted ? SAMPLE_STATE_WORDS[wanted] + ' ' : '')
      + 'sample' + (rows.length === 1 ? '' : 's') + ' ' + smpScopeText()
    : '';
  /* The badge counts what is WAITING on this case, not what exists: a
     badge that includes finished work is a badge that never clears.
     Painted from this fetch when it is exactly that set, so acting on a
     sample updates it at once, and re-counted otherwise. */
  if (!wanted && !smpAllCases) paintSampleBadge(rows);
  else refreshSampleBadge();
}

/** Entropy reads as a bar because the number alone means nothing to
 *  anybody who does not do this daily: ~7.9 is packed or encrypted, ~5 is
 *  a plain PE, ~4 is text. */
function entropyMeter(value) {
  const wrap = el('span', 'meter', null);
  wrap.title = 'Shannon entropy over the whole file, 0 to 8. Above about 7.2 '
    + 'is usually packed, compressed or encrypted. It is a hint, not a '
    + 'verdict: a ZIP scores the same as a packer.';
  const bar = el('span', 'meter-bar');
  const fill = el('span', 'meter-fill');
  const pct = Math.max(0, Math.min(100, (value / 8) * 100));
  fill.style.width = pct.toFixed(1) + '%';
  if (value >= 7.2) fill.classList.add('hot');
  bar.appendChild(fill);
  wrap.appendChild(bar);
  wrap.appendChild(el('span', 'meter-val', value.toFixed(2)));
  return wrap;
}

function stateChip(s) {
  const cls = {
    QUARANTINED: 'chip state-quarantined',
    TRIAGED: 'chip state-triaged',
    ASSIGNED: 'chip state-assigned',
    IN_ANALYSIS: 'chip state-analysis',
    REPORTED: 'chip state-reported',
    REJECTED: 'chip state-rejected',
  }[s] || 'chip';
  return el('span', cls, s.replace('_', ' ').toLowerCase());
}

/** The case a sample belongs to, named the way the rest of the console
 *  names cases: by CODE, from the case list this viewer was given. A case
 *  missing from that list is one they cannot open, and it says so. The
 *  uuid prefix this used to print mapped to nothing anybody could read
 *  (ux19-copy:lab-shows-other-case-samples, 2026-09-22). */
function sampleCaseFact(caseId) {
  if (!caseId) {
    const f = fact('case', 'unattached', 'muted');
    f.title = 'Not attached to any case.';
    return f;
  }
  const c = (state.cases || []).find((x) => x.id === caseId);
  if (!c) {
    const f = fact('case', 'a case you cannot open', 'muted');
    f.title = 'The sample belongs to a case you have no access to. The Lab '
      + 'shows it because your clearance covers the sample, not because you '
      + 'can open the case.';
    return f;
  }
  const here = caseId === state.caseId;
  const f = fact('case', c.code, here ? null : 'warn');
  f.title = c.title + (here ? ' (the case you have open)' : ' (another case)');
  return f;
}

/** A person as the Lab names them: display name, email on hover. */
function smpPerson(name, email) {
  const who = el('span', 'person', name || email || 'an account that no longer exists');
  if (email) who.title = email;
  return who;
}

function personFact(label, name, email) {
  const f = el('span', 'fact');
  f.appendChild(el('span', 'fact-k', label));
  const v = el('span', 'fact-v');
  v.appendChild(smpPerson(name, email));
  f.appendChild(v);
  return f;
}

/** The attacker's filename, boxed and escaped.
 *
 *  The bidi override is SUBSTITUTED, not merely isolated. `dir="ltr"` and
 *  `unicode-bidi: isolate` set the base direction and leave an explicit
 *  U+202E doing its job, so the first version of this rendered
 *  "harmless<RLO>fdp.exe" on screen as "harmlessexe.pdf": the CSS looked
 *  like the defence and was not one. Found by taking a screenshot and
 *  reading it. Shared by the queue row and the detail card since
 *  2026-09-22, so the card can say which file it is. */
function quarantinedFilename(name) {
  const shown = visibleText(name);
  const fn = el('p', 'filename-quarantine');
  fn.appendChild(el('span', 'fact-k', 'as submitted'));
  const value = el('bdi', 'mono', shown);
  value.dir = 'ltr';
  fn.appendChild(value);
  if (shown !== name) {
    const flag = el('span', 'chip bad', 'deceptive');
    flag.title = 'The filename contains characters that change how it '
      + 'renders without changing what it is: a bidi override, a '
      + 'zero-width character or a control. They are shown as escapes.';
    fn.appendChild(flag);
  }
  fn.title = 'The filename as the submitter supplied it. Stored for the '
    + 'record; never used as a path component, and never trusted to say '
    + 'what the file is.';
  return fn;
}

/* Triage gaps by the name of the check that never ran. The service writes
   {step, reason}, and the card read `g.what || g.kind`, so every gap was
   headed with the literal word "gap": two rows read identically and the
   one that matters most, prohibited-content screening, was anonymous
   (ux13-lab:triage-gap-names-dropped, 2026-09-22). */
const TRIAGE_GAP_NAMES = {
  prohibited_content_screening: 'Prohibited-content screening',
  imphash: 'imphash',
  rich_header_hash: 'Rich header hash',
  ssdeep: 'ssdeep',
  tlsh: 'TLSH',
  yara: 'YARA',
  archive_expansion: 'Archive expansion',
};
const PROHIBITED_GAP = 'prohibited_content_screening';

function gapStep(g) { return g.step || g.what || g.kind || ''; }

function gapName(g) {
  const step = gapStep(g);
  return TRIAGE_GAP_NAMES[step] || (step ? step.replace(/_/g, ' ')
    : 'An unnamed check');
}

/** Prohibited-content screening first: an analyst about to download or
 *  share a sample needs to see that nothing screened it for material
 *  whose possession is an offence before anything else on the card. */
function orderedGaps(gaps) {
  return [...(gaps || [])].sort((a, b) =>
    (gapStep(b) === PROHIBITED_GAP) - (gapStep(a) === PROHIBITED_GAP));
}

function gapSummary(gaps) {
  const list = gaps || [];
  const unscreened = list.some((g) => gapStep(g) === PROHIBITED_GAP);
  const others = list.length - (unscreened ? 1 : 0);
  const rest = others + ' other check' + (others === 1 ? '' : 's')
    + ' never ran';
  if (unscreened) {
    return 'Not screened for prohibited content' + (others ? ' · ' + rest : '');
  }
  return others + ' triage check' + (others === 1 ? '' : 's') + ' never ran';
}

/* What happened to a rejected sample's bytes, in the words the row and the
   card use. The server derives it (`bytes_disposition`). */
const DISPOSITION_TEXT = {
  preserved: ['preserved', 'chip ok',
    'Its encrypted bytes are in the preservation store under a legal hold, '
    + 'with their data key. Retrieval needs a Security Officer\'s '
    + 'authorisation naming the person who retrieves it.'],
  destroyed: ['destroyed', 'chip bad',
    'Its bytes and data key were destroyed. The row is the record.'],
  kept: ['bytes kept', 'chip warn',
    'The rejection was recorded without disposing of the bytes: they were '
    + 'left where they were.'],
};

function dispositionChip(s) {
  const d = DISPOSITION_TEXT[s.bytes_disposition];
  if (s.state !== 'REJECTED' || !d) return null;
  const chip = el('span', d[1], d[0]);
  chip.title = d[2];
  return chip;
}

function sampleRow(s) {
  const card = el('div', 'card row-card sample-card');
  const head = el('div', 'row-head');
  head.appendChild(el('span', 'row-glyph hazard', '☢'));
  /* The HASH is the title, never the filename. The filename is
     attacker-controlled and putting it in the heading position invites it
     to be read as identity. */
  const title = el('span', 'row-title mono', s.sha256.slice(0, 16) + '…');
  title.title = s.sha256;
  /* The full digest, not the truncated display form: a 16-character
     prefix pasted into VirusTotal finds nothing. */
  head.appendChild(copyable(title, s.sha256, 'the full SHA-256'));
  head.appendChild(stateChip(s.state));
  const disposed = dispositionChip(s);
  if (disposed) head.appendChild(disposed);
  head.appendChild(labelChips(s));
  card.appendChild(head);

  const facts = el('div', 'facts');
  facts.appendChild(fact('type', s.file_type || 'unrecognised'));
  facts.appendChild(fact('size', humanBytes(s.byte_size)));
  if (s.entropy !== null && s.entropy !== undefined) {
    const f = el('span', 'fact');
    f.appendChild(el('span', 'fact-k', 'entropy'));
    f.appendChild(entropyMeter(s.entropy));
    facts.appendChild(f);
  }
  facts.appendChild(fact('submitted', fmtTime(s.submitted_at)));
  facts.appendChild(personFact('by', s.submitted_by_name, s.submitted_by_email));
  facts.appendChild(sampleCaseFact(s.case_id));
  card.appendChild(facts);

  if (s.original_filename) card.appendChild(quarantinedFilename(s.original_filename));
  /* Where it came from, truncated: the full note is on the card. It was
     collected at submission and then shown nowhere
     (ux13-lab:provenance-never-shown). Quoted, because it is the
     submitter's text and sometimes the attacker's. */
  if (s.source_note) {
    const note = s.source_note.length > 140
      ? s.source_note.slice(0, 139) + '…' : s.source_note;
    const p = el('p', 'why source-note-line');
    p.appendChild(el('span', 'fact-k', 'source'));
    p.appendChild(el('q', null, visibleText(note)));
    p.title = visibleText(s.source_note);
    card.appendChild(p);
  }

  if ((s.triage_gaps || []).length) {
    const unscreened = s.triage_gaps.some((g) => gapStep(g) === PROHIBITED_GAP);
    const gaps = el('p', 'why gaps' + (unscreened ? ' unscreened' : ''),
      gapSummary(s.triage_gaps));
    gaps.title = orderedGaps(s.triage_gaps).map(gapName).join(', ')
      + '. A recorded gap reads as "nobody looked"; a NULL would read as a '
      + 'finding.';
    card.appendChild(gaps);
  }
  if (s.state === 'REJECTED' && s.reject_reason) {
    card.appendChild(el('p', 'why bad', 'Rejected: ' + s.reject_reason));
  }

  const actions = el('div', 'row-actions');
  const open = el('button', 'btn small', 'Open');
  open.type = 'button';
  open.setAttribute('aria-label', 'Open sample ' + s.sha256.slice(0, 16));
  open.addEventListener('click', () => openSample(s.id));
  actions.appendChild(open);
  card.appendChild(actions);
  return card;
}

function humanBytes(n) {
  if (n === null || n === undefined) return 'unknown';
  /* One unit rule across the console: this divided by 1024 and printed KB
     while the Evidence pane printed KiB for the same arithmetic (README
     screenshot set review, 2026-09-23). */
  return fmtBytes(n);
}

/** Which file, whose, from where, and in what state: the header the
 *  detail card lacked. It opened as "SAMPLE 38A19C5F4753…" and went
 *  straight to hashes, so once it was open nothing confirmed which sample
 *  an analyst was about to reject (ux13-lab:provenance-never-shown). */
function sampleProvenance(s) {
  const box = el('div', 'card sub provenance');
  box.appendChild(el('h3', 'h-xs', 'Provenance'));
  if (s.original_filename) box.appendChild(quarantinedFilename(s.original_filename));
  else box.appendChild(el('p', 'muted small', 'No filename was submitted.'));

  const head = el('div', 'row-head');
  head.appendChild(stateChip(s.state));
  const disposed = dispositionChip(s);
  if (disposed) head.appendChild(disposed);
  if (s.legal_hold) {
    const hold = el('span', 'chip warn', 'legal hold');
    hold.title = 'This sample is under a legal hold. Nothing may destroy it.';
    head.appendChild(hold);
  }
  head.appendChild(labelChips(s));
  box.appendChild(head);

  const facts = el('div', 'facts');
  facts.appendChild(fact('type', s.file_type || 'unrecognised'));
  facts.appendChild(fact('size', humanBytes(s.byte_size)));
  if (s.entropy !== null && s.entropy !== undefined) {
    const f = el('span', 'fact');
    f.appendChild(el('span', 'fact-k', 'entropy'));
    f.appendChild(entropyMeter(s.entropy));
    facts.appendChild(f);
  }
  facts.appendChild(sampleCaseFact(s.case_id));
  facts.appendChild(personFact('submitted by', s.submitted_by_name,
    s.submitted_by_email));
  facts.appendChild(fact('submitted', fmtTime(s.submitted_at)));
  if (s.assigned_to) {
    facts.appendChild(personFact('assigned to', s.assigned_to_name,
      s.assigned_to_email));
  } else {
    facts.appendChild(fact('assigned to', 'nobody yet', 'muted'));
  }
  box.appendChild(facts);

  if (s.source_note) {
    const src = el('div', 'source-note');
    src.appendChild(el('span', 'fact-k', 'where it came from, as submitted'));
    src.appendChild(el('blockquote', 'source-quote', visibleText(s.source_note)));
    box.appendChild(src);
  } else {
    box.appendChild(el('p', 'muted small', 'No source note was recorded.'));
  }
  if (s.state === 'REJECTED' && s.reject_reason) {
    box.appendChild(el('p', 'why bad', 'Rejected: ' + s.reject_reason));
  }
  return box;
}

/* The access ledger's rows in words. `lab.sample_access.action` is a
   closed set of seven, and VIEWED_META covers a submission, a look and a
   failed integrity check alike, so the label comes from the action AND
   `detail.event`. The failed check is styled as the alarm it is: it
   used to read as another harmless "VIEWED_META"
   (ux13-lab:custody-ledger-hides-who-and-what, 2026-09-22). */
const ARCHIVE_WORDS = { ZIP_INFECTED: 'password-protected ZIP' };

function custodyLine(c) {
  const d = c.detail || {};
  const archiveWords = ARCHIVE_WORDS[c.archive_format] || c.archive_format
    || 'archive';
  const short = (h) => (h ? String(h).slice(0, 12) + '…' : 'nothing');
  switch (c.action) {
    case 'VIEWED_META':
      if (d.event === 'submitted') return ['Submitted into quarantine', null];
      if (d.event === 'viewed') return ['Opened this record', null];
      if (d.event === 'integrity_check_failed') {
        return ['Integrity check FAILED: recorded ' + short(d.recorded_sha256)
          + ', computed ' + short(d.computed_sha256)
          + (d.store === 'preservation' ? ' (preservation store)' : '')
          + '. Nothing was served.', 'alarm'];
      }
      return ['Read the metadata' + (d.event ? ' (' + d.event + ')' : ''), null];
    case 'DOWNLOADED':
      if (d.source === 'preservation_store') {
        return ['Retrieved from the preservation store as a ' + archiveWords
          + ', under an authorisation', 'notable'];
      }
      return ['Downloaded as a ' + archiveWords
        + (d.via === 'ticket' ? ', on a one-shot ticket' : ''), 'notable'];
    case 'REJECTED': {
      const what = {
        preserved: 'bytes preserved under a legal hold',
        destroyed: 'bytes and data key destroyed',
        kept: 'bytes left where they were',
      }[d.disposition || (d.bytes_purged ? 'destroyed' : 'kept')];
      return ['Rejected (' + what + ')' + (d.reason ? ': ' + d.reason : ''),
        'notable'];
    }
    case 'ASSIGNED':
      return ['Assigned to ' + (c.analyst_name || c.analyst_email
        || 'an account that no longer exists'), null];
    case 'ANALYSED':
      return ['Recorded an analysis' + (d.kind ? ' (' + d.kind + ')' : ''), null];
    case 'DETONATED':
      return ['Requested a detonation' + (d.target ? ' on ' + d.target : '')
        + (d.exposure_level ? ', exposure ' + d.exposure_level.toLowerCase() : ''),
      'notable'];
    case 'SHARED':
      return ['Shared', 'notable'];
    default:
      return [String(c.action || 'Unknown event'), null];
  }
}

function custodyPanel(rows) {
  const cust = el('div', 'card sub');
  cust.appendChild(el('h3', 'h-xs', 'Access ledger'));
  /* Says what IS recorded. It used to promise "every look is a row" while
     opening a sample recorded nothing; opening one now writes a row, once
     per person per five minutes, and this names that limit. */
  cust.appendChild(el('p', 'help',
    'Append-only, and it outlives the sample: a custody ledger you can '
    + 'prune is not one. It records the submission, every opening of this '
    + 'record (once per person per five minutes), every download and '
    + 'retrieval, each assignment, analysis, detonation request and '
    + 'rejection, and any failed integrity check.'));
  if (!(rows || []).length) {
    cust.appendChild(el('p', 'muted', 'No entries.'));
    return cust;
  }
  const list = el('div', 'timeline');
  for (const c of rows) {
    const [text, tone] = custodyLine(c);
    const item = el('div', 'timeline-item' + (tone ? ' is-' + tone : ''));
    item.appendChild(el('span', 'timeline-dot'));
    const t = el('div', 'timeline-body');
    t.appendChild(el('span', 'custody-when muted small',
      fmtTime(c.at || c.occurred_at)));
    t.appendChild(smpPerson(c.actor_name, c.actor_email));
    t.appendChild(el('span', 'custody-what', text));
    item.appendChild(t);
    list.appendChild(item);
  }
  cust.appendChild(list);
  return cust;
}

async function openSample(id) {
  const token = caseToken();
  const box = $('smp-detail');
  const body = $('smp-detail-body');
  clear(body);
  show(box, true);
  box.classList.remove('is-in');
  body.appendChild(el('p', 'muted', 'Loading…'));
  let data;
  try {
    data = await api('/samples/' + encodeURIComponent(id));
  } catch (err) {
    if (caseChanged(token)) return;
    clear(body);
    body.appendChild(el('p', 'msg bad', refusalText(err,
      'Reading a sample needs sample.read.')));
    return;
  }
  if (caseChanged(token)) return;
  requestAnimationFrame(() => box.classList.add('is-in'));
  clear(body);
  const s = data.sample;
  $('smp-detail-title').textContent = 'Sample ' + s.sha256.slice(0, 16) + '…';

  body.appendChild(sampleProvenance(s));

  /* --- hashes. Selectable, monospaced, one per line: these get pasted
     into other tools, and a hash that wrapped mid-string is a hash that
     gets pasted wrong. */
  const hashes = el('div', 'card sub');
  hashes.appendChild(el('h3', 'h-xs', 'Identity'));
  for (const [k, v] of [['SHA-256', s.sha256], ['SHA-1', s.sha1],
    ['MD5', s.md5]]) {
    if (!v) continue;
    const line = el('div', 'hash-line');
    line.appendChild(el('span', 'fact-k', k));
    const val = el('code', 'mono selectable', v);
    line.appendChild(val);
    const copy = el('button', 'btn tiny', 'Copy');
    copy.type = 'button';
    copy.setAttribute('aria-label', 'Copy the ' + k);
    copy.addEventListener('click', () => copyText(v, copy));
    line.appendChild(copy);
    hashes.appendChild(line);
  }
  body.appendChild(hashes);

  /* --- what triage could not do, by the name of each check. Listed
     before the findings, because an analyst reading findings needs to
     know what was never looked at, and prohibited-content screening
     leads because it is the gap with legal consequences. */
  const gaps = orderedGaps(s.triage_gaps);
  const gapBox = el('div', 'card sub');
  gapBox.appendChild(el('h3', 'h-xs', 'Checks that never ran'));
  if (!gaps.length) {
    gapBox.appendChild(el('p', 'muted', 'None recorded.'));
  } else {
    const ul = el('ul', 'rules gap-list');
    for (const g of gaps) {
      const li = el('li', gapStep(g) === PROHIBITED_GAP ? 'gap-unscreened' : null);
      li.appendChild(el('strong', null, gapName(g)));
      li.appendChild(document.createTextNode(': ' + (g.why || g.reason
        || 'no reason was recorded')));
      ul.appendChild(li);
    }
    gapBox.appendChild(ul);
    if (gaps.some((g) => gapStep(g) === PROHIBITED_GAP)) {
      gapBox.appendChild(el('p', 'help warn',
        'Nothing screened this sample for material whose possession is an '
        + 'offence. Treat it as unscreened before you download or share it.'));
    }
  }
  body.appendChild(gapBox);

  /* --- findings */
  const anal = el('div', 'card sub');
  anal.appendChild(el('h3', 'h-xs', 'Analysis'));
  if (!(data.analyses || []).length) {
    anal.appendChild(el('p', 'muted', 'Nothing recorded yet.'));
  } else {
    for (const a of data.analyses) {
      const row = el('div', 'row-card inner');
      const h = el('div', 'row-head');
      h.appendChild(el('span', 'row-title', a.kind));
      if (a.family_assessment) {
        const fam = el('span', 'chip family', a.family_assessment);
        /* A family attribution without a confidence is refused by a CHECK
           constraint, so this pair always renders together. */
        fam.title = 'An assessment, not a fact. ' + (a.confidence || '');
        h.appendChild(fam);
        h.appendChild(el('span', 'chip conf-' + (a.confidence || 'LOW'),
          a.confidence || 'LOW'));
      }
      row.appendChild(h);
      if (a.narrative) row.appendChild(el('p', 'why', a.narrative));
      if ((a.yara_hits || []).length) {
        const hits = el('div', 'chips');
        for (const y of a.yara_hits) hits.appendChild(el('span', 'chip', y));
        row.appendChild(hits);
      }
      const f = el('div', 'facts');
      if (a.tool) f.appendChild(fact('tool', a.tool + (a.tool_version
        ? ' ' + a.tool_version : '')));
      f.appendChild(fact('recorded', fmtTime(a.recorded_at || a.created_at)));
      row.appendChild(f);
      anal.appendChild(row);
    }
  }
  body.appendChild(anal);

  body.appendChild(detonationPanel(s, data.detonations || []));

  if (s.bytes_disposition === 'preserved') {
    body.appendChild(preservationPanel(s, data.preservation || {}));
  }

  body.appendChild(custodyPanel(data.custody));

  body.appendChild(sampleActions(s));
  /* The card renders below the whole queue, so on a long list it opened
     off-screen and the analyst read the first rows as the sample they had
     just opened. */
  box.scrollIntoView({ block: 'start' });
}

/* ── detonation: the VM / sandbox surface ─────────────────────────────
 *
 * docs/11 is emphatic that you INTEGRATE with a sandbox rather than build
 * one, and no integration exists. So this panel records an authorisation
 * and submits nothing — and it says so on every row rather than once at
 * the top, because a reader scanning a column of "AUTHORISED" should not
 * have to remember that none of them went anywhere.
 *
 * The exposure level is the decision the panel exists to slow down.
 * Submitting a sample to a public sandbox exposes the sample AND your
 * interest in it; operators watch public sandboxes for their own malware
 * and treat a hit as a signal they have been noticed, which can end an
 * operation that took months to build. That is why anything other than a
 * private instance needs a named authoriser and a written reason — a
 * database CHECK enforces it, and this form asks for it rather than
 * letting the server refuse after the fact.
 */

const EXPOSURE = [
  ['NONE', 'Private instance: nothing leaves your estate',
    'A sandbox you run. The sample does not leave the boundary and nobody '
    + 'outside learns you hold it. No authoriser required.'],
  ['VENDOR', 'Vendor sandbox: the vendor sees the sample',
    'The sample and its hash reach a commercial vendor. Several "private" '
    + 'tiers still share hashes with partners; confirm what yours does '
    + 'before relying on this being quiet.'],
  ['PUBLIC', 'Public sandbox: anyone watching sees it',
    'The sample, its hash and the fact somebody submitted it become '
    + 'public. Operators monitor public sandboxes for their own samples. '
    + 'Assume the subject learns you have it, the same day.'],
];

function detonationPanel(s, rows) {
  const box = el('details', 'card sub');
  const summary = el('summary', null,
    'Detonation / VM' + (rows.length ? ` (${rows.length})` : ''));
  box.appendChild(summary);

  box.appendChild(el('p', 'help warn',
    'Nothing here submits anything anywhere. There is no sandbox '
    + 'integration in this build: the design integrates an existing '
    + 'sandbox rather than building one, and none has been integrated '
    + 'yet. What this records is the '
    + 'AUTHORISATION, captured before anything could be sent, so that it '
    + 'exists whether or not an integration ever appears.'));

  if (rows.length) {
    const list = el('div', 'rows');
    for (const d of rows) list.appendChild(detonationRow(d));
    box.appendChild(list);
  } else {
    box.appendChild(el('p', 'muted', 'No detonation requested.'));
  }

  /* --- the request form */
  const form = el('div', 'stack');
  form.appendChild(el('hr', 'rule'));
  form.appendChild(el('h3', 'h-xs', 'Request a detonation'));

  const target = el('input', 'input');
  target.type = 'text';
  target.spellcheck = false;
  target.placeholder = 'which VM or sandbox, for example "lab-win10-isolated"';
  const targetField = el('label', 'field');
  targetField.appendChild(el('span', 'label', 'Target'));
  targetField.appendChild(target);
  form.appendChild(targetField);

  const exposure = el('select', 'select');
  for (const [value, label] of EXPOSURE) {
    const o = el('option', null, label);
    o.value = value;
    exposure.appendChild(o);
  }
  const exposureField = el('label', 'field');
  exposureField.appendChild(el('span', 'label', 'Exposure'));
  exposureField.appendChild(exposure);
  form.appendChild(exposureField);

  /* The consequence of the selected level, in place, updating as it
     changes. A dropdown whose options differ by one word and by an
     operation is a dropdown somebody gets wrong once. */
  const consequence = el('p', 'help');
  const paint = () => {
    const entry = EXPOSURE.find((e) => e[0] === exposure.value);
    consequence.textContent = entry ? entry[2] : '';
    consequence.className = 'help' + (exposure.value === 'NONE' ? '' : ' warn');
    show(authWrap, exposure.value !== 'NONE');
  };

  const authWrap = el('div', 'stack');
  const auth = el('input', 'input');
  auth.type = 'text';
  auth.spellcheck = false;
  auth.placeholder = 'user id of the person authorising this';
  const authField = el('label', 'field');
  authField.appendChild(el('span', 'label', 'Authorised by'));
  authField.appendChild(auth);
  authWrap.appendChild(authField);
  const note = el('textarea', 'input');
  note.rows = 2;
  note.placeholder = 'why the exposure is acceptable: this is what a later '
    + 'review reads';
  const noteField = el('label', 'field');
  noteField.appendChild(el('span', 'label', 'Authorisation note'));
  noteField.appendChild(note);
  authWrap.appendChild(noteField);
  authWrap.appendChild(el('p', 'help warn',
    'A named human and a written reason are required by a database '
    + 'constraint, not just by this form. Submitting to a vendor or public '
    + 'sandbox exposes the sample AND your interest in it, so it cannot be '
    + 'a side effect of clicking Analyse.'));

  form.appendChild(consequence);
  form.appendChild(authWrap);

  const msg = el('p', 'msg');
  msg.hidden = true;
  const btn = el('button', 'btn', 'Record the request');
  btn.type = 'button';
  btn.addEventListener('click', async () => {
    if (!target.value.trim()) {
      setMsg(msg, 'Name the VM or sandbox.');
      msg.className = 'msg bad';
      return;
    }
    btn.disabled = true;
    const payload = {
      target: target.value.trim(),
      exposure_level: exposure.value,
    };
    if (exposure.value !== 'NONE') {
      payload.authorised_by = auth.value.trim() || null;
      payload.note = note.value.trim() || null;
    }
    try {
      await api('/samples/' + encodeURIComponent(s.id) + '/detonation', {
        method: 'POST', json: payload,
      });
      setMsg(msg, 'Recorded. Nothing has been sent anywhere.');
      msg.className = 'msg ok';
      await openSample(s.id);
    } catch (err) {
      setMsg(msg, refusalText(err,
        'Requesting a detonation needs sample.detonate and a fresh second '
        + 'factor.'));
      msg.className = 'msg bad';
      btn.disabled = false;
    }
  });
  form.appendChild(msg);
  form.appendChild(btn);
  box.appendChild(form);

  exposure.addEventListener('change', paint);
  paint();
  return box;
}

function detonationRow(d) {
  const card = el('div', 'card row-card compact');
  const head = el('div', 'row-head');
  head.appendChild(el('span', 'row-title', d.target));
  head.appendChild(el('span', 'chip exposure-' + d.exposure_level,
    d.exposure_level.toLowerCase()));
  head.appendChild(el('span', 'chip', d.status.toLowerCase()));
  /* On EVERY row. "AUTHORISED" reads as "it went" unless something says
     otherwise, and nothing in this build ever sends. */
  const never = el('span', 'chip ok', 'not submitted');
  never.title = 'No sandbox integration exists. This row is an '
    + 'authorisation record, not a submission.';
  head.appendChild(never);
  card.appendChild(head);

  const facts = el('div', 'facts');
  facts.appendChild(fact('requested by', d.requested_by));
  facts.appendChild(fact('when',
    fmtTime(d.requested_at)));
  if (d.authorised_by) facts.appendChild(fact('authorised by', d.authorised_by));
  card.appendChild(facts);
  if (d.authorisation_note) {
    card.appendChild(el('p', 'why', d.authorisation_note));
  }
  return card;
}

/* ── preserved samples: two people to get one back out ─────────────────
 *
 * F2, decided by the owner on 2026-09-22: a rejected sample is PRESERVED
 * under a legal hold rather than destroyed, and retrieving it needs a
 * Security Officer's written, time-boxed authorisation naming the person
 * who retrieves it. That person cannot be the Security Officer, and the
 * table refuses it as well as the server. The retrieval is the same
 * encrypted archive a download produces, fetched from the sample origin
 * on a one-shot ticket; nothing here can lift the hold.
 */
/** The server's sentence, with the role hint only when the refusal WAS
 *  about a role. `refusalText` appends its context to every refusal, so a
 *  rejection refused for a missing object also said "Rejecting needs
 *  sample.analyse", which sends an analyst to the wrong fix. */
function smpRefusal(err, roleHint) {
  const forbidden = err instanceof ApiError && err.status === 403;
  return refusalText(err, forbidden ? roleHint : '')
    || (err instanceof ApiError ? err.title : String(err))
    || 'The request was refused.';
}

function preservationPanel(s, p) {
  const box = el('div', 'card sub preserved-panel');
  box.appendChild(el('h3', 'h-xs', 'Preserved'));
  box.appendChild(el('p', 'help',
    'Rejected and moved into the preservation store, still encrypted, under '
    + 'a legal hold. Its data key was kept, so it can be read again when '
    + 'somebody is authorised to. Nothing in this console can lift the hold '
    + 'or delete it.'));
  const facts = el('div', 'facts');
  facts.appendChild(fact('store', s.preserved_bucket || 'unknown'));
  facts.appendChild(fact('preserved', fmtTime(s.preserved_at)));
  box.appendChild(facts);
  if (s.preserved_key) {
    const line = el('div', 'hash-line');
    line.appendChild(el('span', 'fact-k', 'object'));
    line.appendChild(el('code', 'mono selectable', s.preserved_key));
    box.appendChild(line);
  }
  /* Where the officer does it, said here because this card is the only
     place the lead investigator meets the control. The authorise form and
     Revoke used to be on this card, which every reader of it was refused
     and the officer could never open (final review U3, 2026-09-23). */
  box.appendChild(el('p', 'help warn',
    'Retrieval needs a Security Officer\'s authorisation naming you. The '
    + 'officer grants it under Preserved samples, in Oversight beside the break-glass '
    + 'review queue they open from their case list, not from inside a case: '
    + 'give them this sample\'s SHA-256 and what you need it for. It is '
    + 'written down, lasts at most 30 days, and nobody can grant it to '
    + 'themselves: two people, every time.'));

  const msg = el('p', 'msg');
  msg.hidden = true;

  /* --- who is authorised, and until when */
  const auths = p.authorisations || [];
  if (!auths.length) {
    box.appendChild(el('p', 'muted small', 'Nobody has been authorised to '
      + 'retrieve this sample.'));
  } else {
    const list = el('div', 'rows');
    for (const a of auths) list.appendChild(authorisationRow(s, a, msg));
    box.appendChild(list);
  }

  /* --- retrieve. The server decides; this only says in advance whether
     it will, so the button is not a way to find out. */
  const mine = !!p.you_hold_a_live_authorisation;
  const origin = (smpPolicy && smpPolicy.sample_origin) || null;
  const get = el('button', 'btn danger',
    'Retrieve the encrypted archive');
  get.type = 'button';
  get.disabled = !mine || !origin;
  get.title = !mine
    ? 'You hold no live authorisation for this sample. Ask a Security '
      + 'Officer to authorise you by name, under Preserved samples beside '
      + 'their break-glass review queue.'
    : (!origin ? ((smpPolicy && smpPolicy.sample_origin_problem)
      || 'No separate sample origin is configured, so retrieval is refused.')
      : 'Fetched from the separate sample origin on a one-shot ticket. '
        + 'Needs a fresh second factor.');
  get.addEventListener('click', () => downloadSample(s, msg,
    '/preserved/retrieval-ticket'));
  const row = el('div', 'row-actions');
  row.appendChild(get);
  box.appendChild(row);

  box.appendChild(msg);
  return box;
}

/** One authorisation, as a record. `after` (the officer's list only) is
 *  what to reload once it is revoked; without it there is no Revoke,
 *  because nobody who can open the Lab card holds the verb that revokes
 *  (final review U3, 2026-09-23). */
function authorisationRow(s, a, msg, after) {
  const card = el('div', 'card row-card compact');
  const head = el('div', 'row-head');
  head.appendChild(el('span', 'row-title', 'For '));
  head.lastChild.appendChild(smpPerson(a.granted_to_name, a.granted_to_email));
  const status = a.live ? ['live', 'chip ok']
    : (a.revoked_at ? ['revoked', 'chip bad'] : ['expired', 'chip']);
  head.appendChild(el('span', status[1], status[0]));
  card.appendChild(head);
  const facts = el('div', 'facts');
  facts.appendChild(personFact('authorised by', a.granted_by_name,
    a.granted_by_email));
  facts.appendChild(fact('granted', fmtTime(a.created_at)));
  facts.appendChild(fact(a.revoked_at ? 'revoked' : 'until',
    fmtTime(a.revoked_at || a.expires_at)));
  facts.appendChild(fact('retrievals', a.retrieval_count));
  card.appendChild(facts);
  card.appendChild(el('p', 'why', 'Scope: ' + a.scope_note));
  card.appendChild(el('p', 'why', 'Legal basis: ' + a.legal_basis));
  if (a.live && after) {
    const revoke = el('button', 'btn small danger', 'Revoke');
    revoke.type = 'button';
    revoke.setAttribute('aria-label', 'Revoke the authorisation for '
      + (a.granted_to_name || a.granted_to_email || 'this person'));
    revoke.addEventListener('click', async () => {
      revoke.disabled = true;
      try {
        await api('/samples/' + encodeURIComponent(s.id)
          + '/preserved/authorisations/' + encodeURIComponent(a.id)
          + '/revoke', { method: 'POST' });
        await after();
      } catch (err) {
        setMsg(msg, smpRefusal(err, 'Revoking needs '
          + 'sample.preserved.authorise, which the Security Officer role '
          + 'holds.'));
        msg.className = 'msg bad';
        revoke.disabled = false;
      }
    });
    const actions = el('div', 'row-actions');
    actions.appendChild(revoke);
    card.appendChild(actions);
  }
  return card;
}

/** The Security Officer's half, drawn on the officer's own list
 *  (`preservedReviewRow`). It used to be drawn only on the Lab card, which
 *  needs sample.read, so the officer never saw it (final review U3,
 *  2026-09-23). The server still refuses anybody without
 *  `sample.preserved.authorise`. `after` reloads the list. */
function authoriseForm(s, msg, after) {
  const box = el('details', 'authorise-form');
  box.appendChild(el('summary', null, 'Authorise a retrieval (Security Officer)'));
  const form = el('div', 'stack');

  const labelled = (label, input) => {
    const f = el('label', 'field');
    f.appendChild(el('span', 'label', label));
    f.appendChild(input);
    form.appendChild(f);
    return input;
  };
  const who = el('input', 'input');
  who.type = 'text';
  who.spellcheck = false;
  who.autocomplete = 'off';
  who.placeholder = 'their email address';
  labelled('Person to authorise', who);
  const scope = el('textarea', 'input');
  scope.rows = 2;
  scope.placeholder = 'what they may retrieve and why, in words a later '
    + 'reviewer can hold them to';
  labelled('Scope', scope);
  const basis = el('input', 'input');
  basis.type = 'text';
  basis.placeholder = 'the order, warrant or policy this rests on';
  labelled('Legal basis', basis);
  const days = el('select', 'select');
  for (const d of [1, 2, 7, 14, 30]) {
    const o = el('option', null, d + (d === 1 ? ' day' : ' days'));
    o.value = String(d);
    if (d === 7) o.selected = true;
    days.appendChild(o);
  }
  labelled('For', days);
  form.appendChild(el('p', 'help',
    'The person must be a lead investigator, the role that carries '
    + 'sample.preserved.retrieve. You cannot authorise yourself.'));

  const btn = el('button', 'btn', 'Authorise');
  btn.type = 'button';
  btn.addEventListener('click', async () => {
    if (!who.value.trim() || scope.value.trim().length <= 20
        || !basis.value.trim()) {
      setMsg(msg, 'Name the person, write a scope of more than twenty '
        + 'characters, and give the legal basis.');
      msg.className = 'msg bad';
      return;
    }
    btn.disabled = true;
    try {
      await api('/samples/' + encodeURIComponent(s.id)
        + '/preserved/authorisations', {
        method: 'POST',
        json: {
          granted_to: who.value.trim(),
          scope_note: scope.value.trim(),
          legal_basis: basis.value.trim(),
          duration_days: Number(days.value),
        },
      });
      await after();
    } catch (err) {
      setMsg(msg, smpRefusal(err, 'Authorising a retrieval needs '
        + 'sample.preserved.authorise, which the Security Officer role '
        + 'holds, and a fresh second factor.'));
      msg.className = 'msg bad';
      btn.disabled = false;
    }
  });
  form.appendChild(btn);
  box.appendChild(form);
  return box;
}

/* ── the Security Officer's preserved samples ──────────────────────────
 *
 * Final review U3, 2026-09-23. The authorise form and Revoke were drawn
 * only on the Lab's sample card, which reads GET /samples/{id} under
 * sample.read. SECURITY_OFFICER holds no sample.read, because Security
 * Officers read no case content, and is assigned to no case, so the one
 * role allowed to authorise a retrieval got a 403 on the queue and on the
 * card and never saw the form. The two-person retrieval could not be
 * completed from the console at all.
 *
 * The officer's list lives on the deployment view `showAdmin` opens from
 * the case list, beside the break-glass review queue, and reads
 * GET /samples/preserved under the officer's own verb. It shows what an
 * authorisation is about (which sample, where it is held, which case code,
 * who has been authorised) and nothing of the sample's content.
 */
let preservedReview = null;
let preservedReviewGen = 0;

/** Called by `showAdmin`. Mounts the list on the deployment view for an
 *  account that may review, and hides it for one that may not, so a later
 *  sign-in on the same page never inherits the last officer's list. */
function showPreservedReview(canSee) {
  if (!preservedReview) preservedReview = buildPreservedReview();
  const view = $('view-admin');
  if (preservedReview.parentNode !== view) view.appendChild(preservedReview);
  show(preservedReview, canSee);
  if (canSee) {
    loadPreservedReview();
  } else {
    preservedReviewGen += 1;
    clear($('pres-list'));
    $('pres-counts').textContent = '';
  }
}

function buildPreservedReview() {
  /* `pane` for the layout the deployment view already gives the accounts
     pane (`.admin-view > .pane`), so this list needs no stylesheet rule of
     its own. */
  const box = el('section', 'pane preserved-review');
  box.id = 'preserved-review';
  box.setAttribute('aria-label', 'Preserved samples');
  box.hidden = true;
  box.appendChild(el('h2', 'h-sm', 'Preserved samples'));
  box.appendChild(el('p', 'help',
    'Rejected samples held in the preservation store under a legal hold. '
    + 'A lead investigator who needs one back asks you; you authorise that '
    + 'one person for that one sample, in writing, for at most 30 days, and '
    + 'they retrieve it themselves as an encrypted archive. You see which '
    + 'sample and where it is held, never its contents or the case file.'));
  const head = el('div', 'pane-head');
  const refresh = el('button', 'btn', 'Refresh');
  refresh.type = 'button';
  refresh.id = 'pres-refresh';
  refresh.addEventListener('click', () => loadPreservedReview());
  head.appendChild(refresh);
  const counts = el('span', 'muted small');
  counts.id = 'pres-counts';
  head.appendChild(counts);
  box.appendChild(head);
  const list = el('div', 'rows');
  list.id = 'pres-list';
  box.appendChild(list);
  const empty = el('p', 'empty', 'Nothing is preserved.');
  empty.id = 'pres-empty';
  empty.hidden = true;
  box.appendChild(empty);
  return box;
}

async function loadPreservedReview() {
  const gen = ++preservedReviewGen;
  const list = $('pres-list');
  const empty = $('pres-empty');
  let body;
  try {
    body = await api('/samples/preserved');
  } catch (err) {
    if (gen !== preservedReviewGen) return;
    clear(list);
    $('pres-counts').textContent = '';
    empty.textContent = err instanceof ApiError
      ? smpRefusal(err, 'The list needs sample.preserved.authorise, which '
        + 'the Security Officer role holds, and a fresh second factor.')
      : 'The preserved samples could not be read. The list is not known '
        + 'to be empty.';
    show(empty, true);
    return;
  }
  if (gen !== preservedReviewGen) return;
  const rows = body.samples || [];
  clear(list);
  for (const s of rows) list.appendChild(preservedReviewRow(s));
  $('pres-counts').textContent = rows.length + ' preserved';
  empty.textContent = 'Nothing is preserved.';
  show(empty, !rows.length);
}

function preservedReviewRow(s) {
  const card = el('div', 'card row-card');
  const head = el('div', 'row-head');
  head.appendChild(el('span', 'row-title',
    'Sample ' + s.sha256.slice(0, 16) + '…'));
  const auths = s.authorisations || [];
  const live = auths.filter((a) => a.live).length;
  head.appendChild(el('span', 'chip' + (live ? ' ok' : ''),
    live ? live + ' live' : 'none live'));
  if (s.legal_hold) head.appendChild(el('span', 'chip flag', 'legal hold'));
  card.appendChild(head);

  const facts = el('div', 'facts');
  facts.appendChild(fact('case', s.case_code || 'not attached to a case'));
  facts.appendChild(fact('preserved', fmtTime(s.preserved_at)));
  facts.appendChild(fact('size', humanBytes(s.byte_size)));
  facts.appendChild(fact('label', s.classification));
  card.appendChild(facts);
  for (const [k, v] of [['SHA-256', s.sha256], ['object', s.preserved_key]]) {
    const line = el('div', 'hash-line');
    line.appendChild(el('span', 'fact-k', k));
    line.appendChild(el('code', 'mono selectable', v));
    card.appendChild(line);
  }

  const msg = el('p', 'msg');
  msg.hidden = true;
  const reload = () => loadPreservedReview();
  if (!auths.length) {
    card.appendChild(el('p', 'muted small', 'Nobody has been authorised to '
      + 'retrieve this sample.'));
  } else {
    const list = el('div', 'rows');
    for (const a of auths) list.appendChild(authorisationRow(s, a, msg, reload));
    card.appendChild(list);
  }
  card.appendChild(authoriseForm(s, msg, reload));
  card.appendChild(msg);
  return card;
}

/* What a rejection will do on THIS deployment, from the policy endpoint,
   so the warning and the confirmation state it before it happens rather
   than the analyst learning it from the result. */
function rejectOutcome(keep) {
  if (keep) {
    return ['record',
      'The rejection and your reason will be recorded. The bytes stay where '
      + 'they are and nothing is preserved or destroyed.'];
  }
  const disposition = smpPolicy && smpPolicy.rejected_sample_disposition;
  if (disposition === 'preserve') {
    return ['preserve',
      'Its encrypted bytes will be MOVED into the preservation store under a '
      + 'legal hold, with the data key kept. Getting them back needs a '
      + 'Security Officer\'s authorisation naming the person.'];
  }
  if (disposition === 'destroy') {
    return ['destroy',
      'Its bytes and data key will be DESTROYED, permanently. This cannot be '
      + 'undone.'];
  }
  return [null, (smpPolicy && smpPolicy.rejected_sample_disposition_problem)
    || 'This deployment\'s rejected-sample disposition could not be read, so '
      + 'a rejection that disposes of the bytes will be refused.'];
}

/** The dangerous half. Deliberately below everything an analyst can act on
 *  without touching bytes. */
function sampleActions(s) {
  const box = el('details', 'card sub danger');
  box.appendChild(el('summary', null, 'Handling actions'));

  const msg = el('p', 'msg');
  msg.hidden = true;

  if (s.state === 'REJECTED') {
    /* Nothing to download and nothing to reject: the card says what
       happened and, for a preserved sample, the panel above says how to
       get it back. */
    const d = DISPOSITION_TEXT[s.bytes_disposition];
    box.appendChild(el('p', 'help', 'Rejected. ' + (d ? d[2] : '')));
    box.appendChild(msg);
    return box;
  }

  /* --- download */
  const dl = el('div', 'stack');
  dl.appendChild(el('p', 'help warn',
    'This produces a password-protected archive of a LIVE sample. The '
    + 'password is "infected": an interlock against a double-click and a '
    + 'mail gateway, not confidentiality. It requires a fresh second '
    + 'factor, and the archive is fetched from the separate sample origin, '
    + 'never from the origin this page is served from.'));
  /* The origin itself, not a boolean: this page is served from the
     application origin and the bytes are not, so the button needs
     somewhere to fetch FROM. Until 2026-09-09 it fetched this origin,
     which the server refuses by design. */
  const origin = (smpPolicy && smpPolicy.sample_origin) || null;
  const dlBtn = el('button', 'btn danger',
    origin ? 'Download encrypted archive' : 'Download: no origin configured');
  dlBtn.type = 'button';
  dlBtn.disabled = !origin;
  if (!origin) {
    dlBtn.title = (smpPolicy && smpPolicy.sample_origin_problem)
      || ('NOCTORNAL_SAMPLE_ORIGIN is not set. Invariant 10 requires '
      + 'sample bytes to come from a separate origin, and an origin split '
      + 'that is only written down does not survive the first hurried '
      + 'deploy, so the button is off rather than failing at the server.');
  }
  dlBtn.addEventListener('click', () => downloadSample(s, msg));
  dl.appendChild(dlBtn);
  box.appendChild(dl);

  /* --- reject.
   *
   * Until 2026-09-22 this sent `purge_bytes: true` on the first click,
   * from an unlabelled field, under a card that did not name the sample,
   * and the default destroyed the bytes and the key
   * (ux13-lab:reject-one-click-destroy). Now the default preserves
   * (F2), the field has a label, and the button opens a confirmation
   * that names the sample and says which of preserve, destroy or record
   * will happen. Nothing is sent until that is confirmed. */
  const rej = el('div', 'stack');
  rej.appendChild(el('hr', 'rule'));
  rej.appendChild(el('h3', 'h-xs', 'Reject'));
  const [kind, consequence] = rejectOutcome(false);
  rej.appendChild(el('p', 'help warn',
    'Rejecting takes the sample out of the working queue and keeps the row, '
    + 'with your reason: an auditor asking "did anything prohibited come '
    + 'through here" needs an answer. On this deployment, '
    /* "its encrypted bytes..." reads on from the comma; a problem
       sentence names an environment variable and keeps its case. */
    + (kind ? consequence.charAt(0).toLowerCase() + consequence.slice(1)
      : consequence)
    + (kind === 'destroy'
      ? ' A legal hold on the sample or its case refuses this.' : '')));
  const reasonField = el('label', 'field');
  reasonField.appendChild(el('span', 'label', 'Why it is rejected'));
  const reason = el('input', 'input');
  reason.type = 'text';
  reason.placeholder = 'this record is what survives';
  reason.spellcheck = false;
  reasonField.appendChild(reason);
  rej.appendChild(reasonField);
  const keep = el('label', 'field inline check');
  const keepBox = el('input');
  keepBox.type = 'checkbox';
  keep.appendChild(keepBox);
  keep.appendChild(el('span', 'label',
    'Record the rejection only, and leave the bytes where they are'));
  keep.title = 'For a sample whose bytes must not move yet, or whose object '
    + 'is not in the store. Nothing is preserved or destroyed.';
  rej.appendChild(keep);
  const rejBtn = el('button', 'btn danger', 'Reject…');
  rejBtn.type = 'button';
  rej.appendChild(rejBtn);

  const confirmBox = el('div', 'confirm-box');
  confirmBox.setAttribute('role', 'group');
  confirmBox.hidden = true;
  rej.appendChild(confirmBox);

  const closeConfirm = () => {
    clear(confirmBox);
    confirmBox.hidden = true;
    reason.disabled = false;
    keepBox.disabled = false;
    rejBtn.disabled = false;
  };

  rejBtn.addEventListener('click', () => {
    if (!reason.value.trim()) {
      setMsg(msg, 'A rejection has to say why.');
      msg.className = 'msg bad';
      reason.focus();
      return;
    }
    setMsg(msg, '');
    /* Read ONCE, here, and frozen while the question is on screen: what is
       sent has to be what was confirmed, and what is reported afterwards
       comes from the server's answer, not from where the checkbox happens
       to be when the response lands. */
    const purged = !keepBox.checked;
    const why = reason.value.trim();
    const [what, sentence] = rejectOutcome(!purged);
    reason.disabled = true;
    keepBox.disabled = true;
    rejBtn.disabled = true;
    clear(confirmBox);
    const q = el('p', 'confirm-q', 'Reject this sample?');
    q.id = 'smp-confirm-q';
    q.tabIndex = -1;
    confirmBox.setAttribute('aria-labelledby', q.id);
    confirmBox.appendChild(q);
    const facts = el('div', 'facts');
    facts.appendChild(fact('file', s.original_filename
      ? visibleText(s.original_filename) : 'no filename submitted'));
    facts.appendChild(fact('SHA-256', s.sha256.slice(0, 16) + '…'));
    facts.appendChild(sampleCaseFact(s.case_id));
    confirmBox.appendChild(facts);
    confirmBox.appendChild(el('p', 'why', 'Reason: ' + why));
    confirmBox.appendChild(el('p', 'msg ' + (what === 'destroy' ? 'bad' : 'warn'),
      sentence));
    const go = el('button', 'btn danger', {
      preserve: 'Reject and preserve',
      destroy: 'Reject and destroy',
      record: 'Reject and record only',
    }[what] || 'Reject');
    go.type = 'button';
    go.disabled = what === null;
    const cancel = el('button', 'btn', 'Cancel');
    cancel.type = 'button';
    cancel.addEventListener('click', () => { closeConfirm(); rejBtn.focus(); });
    go.addEventListener('click', async () => {
      go.disabled = true;
      cancel.disabled = true;
      let out;
      try {
        out = await api('/samples/' + encodeURIComponent(s.id) + '/reject', {
          method: 'POST',
          json: { reason: why, purge_bytes: purged },
        });
      } catch (err) {
        closeConfirm();
        setMsg(msg, smpRefusal(err, 'Rejecting needs sample.analyse, which '
          + 'the malware analyst role holds.'));
        msg.className = 'msg bad';
        /* A legal hold under `destroy`, or a working copy that is not in
           the store, names its own way out (record the rejection only),
           so surface the checkbox rather than leaving the analyst to find
           it. */
        if (err instanceof ApiError
            && /legal hold|purge_bytes/i.test(err.detail || '')) {
          keep.classList.add('is-highlighted');
        }
        return;
      }
      /* Reported from the SERVER's answer: the disposition it applied, not
         the one this page expected. */
      const d = DISPOSITION_TEXT[out.bytes_disposition];
      await loadSamples();
      await openSample(s.id);
      banner('Sample rejected', 'Sample ' + s.sha256.slice(0, 16) + '… was rejected. '
        + (d ? d[2] : ''), out.bytes_disposition === 'destroyed' ? null : 'warn');
    });
    const buttons = el('div', 'row-actions');
    buttons.appendChild(go);
    buttons.appendChild(cancel);
    confirmBox.appendChild(buttons);
    confirmBox.hidden = false;
    q.focus();
  });
  box.appendChild(rej);

  box.appendChild(msg);
  return box;
}

async function copyText(text, btn) {
  try {
    await navigator.clipboard.writeText(text);
    const was = btn.textContent;
    btn.textContent = 'Copied';
    btn.classList.add('is-ok');
    setTimeout(() => { btn.textContent = was; btn.classList.remove('is-ok'); },
      1200);
  } catch (_e) {
    btn.textContent = 'Ctrl+C';
  }
}

/** The ONE call in this file that leaves the page's origin, on purpose.
 *
 *  Every other request is fetch(API + ...) against the origin this page
 *  is served from, and the console's CSP was connect-src 'self' to hold
 *  exactly that. Sample bytes are the exception invariant 10 makes: they
 *  come from a separate origin or not at all, so the server names that
 *  origin in connect-src, answers this page's cross-origin request there
 *  (and only there, and only for this origin), and the URL fetched is the
 *  absolute one the ticket mint returned. Bound under its own name so the
 *  rule "fetch() is rooted at API" stays true of every call spelled
 *  fetch(, and the one deliberate exception is greppable.
 */
const fetchFromSampleOrigin = window.fetch.bind(window);

/** Mint a one-shot ticket HERE, spend it at the SAMPLE origin, then hand
 *  the browser a blob.
 *
 *  A plain <a href> would be a GET, and both legs are POSTs on purpose: a
 *  GET that puts working malware on a disk is one a prefetcher, a link
 *  scanner or a chat unfurl can fire without a human, and the step-up
 *  this download is gated on is asked for at the mint.
 *
 *  TWO legs because no single credential can do both (2026-09-10). A
 *  `__Host-` cookie cannot reach the sample origin -- that is the POINT
 *  of the split, not a limitation of it -- so this request used to carry
 *  the login body's session token there as a Bearer, which was the whole
 *  reason a token had to sit in `state.token` where script can read it.
 *  Now `POST /samples/{id}/download-ticket` goes through `api()` on THIS
 *  origin, so it rides the cookie and the `x-csrf-token` double-submit
 *  like every other write, and what crosses is good for one sample, one
 *  redemption and sixty seconds.
 *
 *  The second leg sends NO header at all, which is not tidiness. Setting
 *  one the CORS safelist does not cover turns this into a preflighted
 *  request, and the sample process answers a preflight with
 *  `Access-Control-Allow-Headers: authorization` alone (`app.py`
 *  `_preflight`) -- so a ticket carried in a header of its own would be
 *  refused before the server ever saw the request, and would surface
 *  here as "did not complete", which is how the CSRF header did when the
 *  cookie session landed. With no header of ours and a form body
 *  (`application/x-www-form-urlencoded` is safelisted) this is a SIMPLE
 *  cross-origin request and is not preflighted at all. The ticket
 *  travels in that body for the same reason it never travels in the URL:
 *  a query string reaches the access log, the history and the Referer,
 *  and this one buys a live binary.
 */
async function downloadSample(s, msg, mint = '/download-ticket') {
  /* `mint` is the one difference between a download and the retrieval of
     a preserved sample (F2, 2026-09-22): the retrieval is minted at
     '/preserved/retrieval-ticket', under `sample.preserved.retrieve` and a
     live authorisation, and then spent at the SAME sample-origin download
     path, because the sample process serves that path and nothing else.
     Everything after the mint is one code path on purpose. */
  const retrieval = mint !== '/download-ticket';
  /* The mint refuses an unusable split itself, with the reason. This
     asks first only so the analyst gets that reason without a round trip
     -- the button next to this message is already disabled for it. */
  const origin = smpPolicy && smpPolicy.sample_origin;
  if (!origin) {
    setMsg(msg, (smpPolicy && smpPolicy.sample_origin_problem)
      || 'No separate sample origin is configured; every download is refused.');
    msg.className = 'msg bad';
    return;
  }
  setMsg(msg, 'Requesting a download ticket…');
  msg.className = 'msg';
  let minted;
  try {
    minted = await api('/samples/' + encodeURIComponent(s.id)
      + mint, { method: 'POST' });
  } catch (err) {
    /* Through `refusalText`, so the SERVER's sentence arrives: this leg
       carries the refusals an analyst is least able to guess at -- a
       step-up that has expired, a clearance that does not reach this
       sample, a split that is configured wrong -- and each of them is
       written as a sentence there. The fallback is for a failure with no
       `detail` at all, because an empty message box is the one answer
       that is never right. */
    setMsg(msg, refusalText(err, '') || 'The ticket request was refused.');
    msg.className = 'msg bad';
    return;
  }
  setMsg(msg, 'Fetching the archive…');
  let res;
  try {
    /* `credentials: 'omit'`, spelled out: the sample origin reads no
       cookie, the ticket is the entire credential, and this page has no
       business offering one there. The URL is the server's own
       (`download_url`), not one assembled here from `location.origin` --
       assembling it is exactly how this pane came to fetch the
       application origin, which every download refuses by design. What
       bounds a URL taken from a response is the CSP: `connect-src` names
       'self' and the configured sample origin and nothing else. */
    res = await fetchFromSampleOrigin(minted.download_url, {
      method: 'POST',
      body: new URLSearchParams({ ticket: minted.ticket }),
      credentials: 'omit',
    });
  } catch (_e) {
    setMsg(msg, 'The request did not complete.');
    msg.className = 'msg bad';
    return;
  }
  if (!res.ok) {
    /* The sample origin's own sentence too, through the same
       `refusalText` rather than a second spelling of "it was refused":
       a spent or expired ticket says so and says to ask for another,
       which is the one thing the analyst can act on. */
    const p = await problemOf(res);
    const err = new ApiError(res.status, p.title, p.detail);
    setMsg(msg, refusalText(err, '') || p.title);
    msg.className = 'msg bad';
    return;
  }
  const blob = await res.blob();
  const url = URL.createObjectURL(blob);
  const a = el('a');
  a.href = url;
  a.download = s.sha256 + '.zip';
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  /* Revoked immediately: an object URL left alive is a live sample
     reachable from the page's own origin for as long as the tab is open. */
  setTimeout(() => URL.revokeObjectURL(url), 0);
  setMsg(msg, (retrieval ? 'Preserved sample retrieved as '
    : 'Archive saved as ') + s.sha256.slice(0, 12)
    + '….zip, password "infected". It is a live sample.'
    + (retrieval ? ' The legal hold on the preserved copy is unchanged.' : ''));
  msg.className = 'msg warn';
}

async function loadSamplePolicy() {
  const banner = $('smp-policy');
  try {
    smpPolicy = await api('/samples/policy');
  } catch (err) {
    setMsg(banner, refusalText(err, 'Could not read the policy status.'));
    banner.className = 'banner banner-legal';
    show(banner, true);
    return;
  }
  clear(banner);
  banner.className = 'banner banner-legal';
  banner.appendChild(el('strong', null, 'Counsel must review this deployment.'));
  banner.appendChild(document.createTextNode(' ' + smpPolicy.notice));
  const facts = el('div', 'facts');
  facts.appendChild(fact('policy',
    smpPolicy.policy_declared ? smpPolicy.policy_reference : 'NOT DECLARED',
    smpPolicy.policy_declared ? 'ok' : 'bad'));
  facts.appendChild(fact('separate origin',
    smpPolicy.sample_origin_configured ? 'configured' : 'NOT configured',
    smpPolicy.sample_origin_configured ? 'ok' : 'bad'));
  /* F2 (2026-09-22): what a rejection does here, before anybody rejects. */
  const disposition = smpPolicy.rejected_sample_disposition;
  const rejectedFact = fact('rejected samples',
    disposition === 'preserve' ? 'preserved under a legal hold'
      : (disposition === 'destroy' ? 'destroyed' : 'NOT SET'),
    disposition === 'preserve' ? 'ok' : (disposition === 'destroy' ? 'warn' : 'bad'));
  rejectedFact.title = smpPolicy.rejected_sample_disposition_problem
    || 'NOCTORNAL_REJECTED_SAMPLE_DISPOSITION on this deployment.';
  facts.appendChild(rejectedFact);
  banner.appendChild(facts);
  if (!smpPolicy.policy_declared) {
    banner.appendChild(el('p', 'help', smpPolicy.detail || ''));
  }
  show(banner, true);

  setMsg($('smp-cap'), Number.isFinite(smpPolicy.max_sample_bytes)
    ? 'Samples up to ' + fmtBytes(smpPolicy.max_sample_bytes)
      + '. Larger is a disk image or a mistake, and is refused before a byte is read.'
    : '');
  const originBox = $('smp-origin');
  clear(originBox);
  originBox.appendChild(el('strong', null, 'This deployment: '));
  originBox.appendChild(document.createTextNode(
    smpPolicy.sample_origin
      ? 'downloads are fetched from the separate sample origin '
        + smpPolicy.sample_origin + ', never from this one.'
      : (smpPolicy.sample_origin_problem
        || 'no separate sample origin is configured, so every download is '
        + 'refused. That is invariant 10 as a runtime check rather than a '
        + 'deployment note.')));
}

async function submitSample() {
  const msg = $('smp-submit-msg');
  const file = $('smp-file').files[0];
  if (!file) {
    setMsg(msg, 'Choose a file first.');
    msg.className = 'msg bad';
    return;
  }
  const cap = smpPolicy && smpPolicy.max_sample_bytes;
  if (cap && file.size > cap) {
    setMsg(msg, 'This file is ' + fmtBytes(file.size) + '; this deployment '
      + 'accepts a sample up to ' + fmtBytes(cap) + ' and would refuse it '
      + 'before reading a byte.');
    msg.className = 'msg bad';
    return;
  }
  /* The open case unless "No case" was chosen, resolved now rather than
     read from a typed id (U14). An unfilled choice means the default. */
  const attach = $('smp-case').value !== 'none' && state.caseId
    ? state.caseId : null;
  const where = attach ? caseCodeNow() : null;
  const token = caseToken();
  const form = new FormData();
  form.append('file', file);
  if (attach) form.append('case_id', attach);
  if ($('smp-note').value.trim()) form.append('source_note', $('smp-note').value.trim());
  form.append('classification', $('smp-class').value);
  const btn = $('smp-submit');
  btn.disabled = true;
  setMsg(msg, 'Uploading…');
  msg.className = 'msg';
  try {
    const out = await api('/samples', { method: 'POST', form });
    const landed = 'Quarantined as ' + out.sha256.slice(0, 16) + '… ('
      + (out.file_type || 'unrecognised') + ')'
      + (where ? ' on ' + where + '.'
        : ', with no case: it is listed only under "All cases I can see".');
    if (caseChanged(token)) {
      banner('Sample submitted', landed + ' You had moved to another case '
        + 'before the reply arrived.', 'warn');
      return;
    }
    setMsg(msg, landed);
    msg.className = 'msg ok';
    $('smp-file').value = '';
    await loadSamples();
  } catch (err) {
    if (caseChanged(token)) {
      banner('Submitting a sample failed', failureReason(err));
      return;
    }
    /* 451 is the legal refusal, and it must not read as an upload problem
       — that is the whole reason the status code is not a 400. */
    const legal = err instanceof ApiError && err.status === 451;
    setMsg(msg, (legal ? 'Refused for legal reasons. ' : '')
      + refusalText(err, ''));
    msg.className = 'msg ' + (legal ? 'warn' : 'bad');
  } finally {
    btn.disabled = false;
  }
}

/* ── live change hints ────────────────────────────────────────────────
 *
 * Until this existed there was no timer anywhere in this file. Two
 * analysts on one case each saw the graph as it was when they opened it,
 * and a merge one of them performed was invisible to the other until a
 * manual refresh — in a tool whose entire premise is a shared picture.
 *
 * The socket carries NO case content. An event says "case X changed, kind
 * node" and the client refetches through the ordinary gated endpoints. So
 * nothing here has to reason about classifications or compartments, which
 * is the point: that filtering has been got wrong in five separate places
 * in this codebase already.
 *
 * It is also entirely optional. If the socket will not connect the console
 * behaves exactly as it did before — the analyst refreshes — and the
 * status dot says so rather than pretending to be live. A push UI that
 * silently stops pushing is worse than one that never pushed, because
 * people stop refreshing.
 */

let _ws = null;
let _wsRetry = 0;
let _wsTimer = null;

/** Coalesce a burst. A bulk import fires one event per statement, and an
 *  import is many statements; refetching the projection per event would
 *  turn somebody else's write into our own denial of service.
 *
 *  Both refetches ask `signedIn()` when they fire, not only when they
 *  were scheduled. One that lands after a sign-out would 401 with no
 *  analyst in the tab, which `_fetch` answers with a "Session ended"
 *  banner over the sign-in form the analyst just asked for; one that
 *  lands under the lapsed sheet re-reports the lapse (final review C20,
 *  2026-09-23, which made a held refetch fire on the click of Sign out). */
const _refetchSoon = debounce(async () => {
  if (!state.caseId || !signedIn()) return;
  try {
    await loadCaseGraph();
    await refreshSociogram();
  } catch (_e) {
    /* A failed refetch is not worth a banner: the next event or a manual
       refresh will pick it up, and the socket is a convenience. */
  }
}, 900);

const _badgeSoon = debounce(() => { if (signedIn()) refreshInboxBadge(); }, 400);

/* Presence (final review C20, 2026-09-23). Every refetch above is a
 * request nobody at this desk asked for, and every request slides the
 * session's idle window: on the server, where `deps.current_user`
 * touches the session, and here, in `noteSessionActivity`. On a case
 * other analysts were editing, their changes alone kept an unattended
 * console signed in until the 12-hour limit, and the 30-minute idle
 * expiry and its warning never came.
 *
 * So the channel stops asking once nobody has touched this page for five
 * minutes. A change that arrives then is held, the dot says so, and the
 * next key, click, wheel or pointer movement loads it; a socket that
 * drops meanwhile is reopened then too, because its handshake slides the
 * session as well. The last request made without the analyst therefore
 * leaves at most five minutes after they did, and the idle expiry falls
 * at most 35 minutes after it. Pointer movement counts, as it does for
 * the operating system's own idle lock: an analyst reading the graph with
 * a hand on the mouse is at the desk. */
const LIVE_AWAY_MS = 5 * 60 * 1000;
let _lastPresence = Date.now();
let _presenceWatched = false;
const _liveHeld = { graph: false, badge: false, reconnect: false };

function liveAway() { return Date.now() - _lastPresence > LIVE_AWAY_MS; }

/** Once per page, from `startApp`. Window and capture phase, so the
 *  session sheets' key guards (`onSheetKey`, `keepKeysInSheet`) cannot
 *  hide a key from it. */
function watchPresence() {
  if (_presenceWatched) return;
  _presenceWatched = true;
  for (const type of ['keydown', 'pointerdown', 'pointermove', 'wheel']) {
    window.addEventListener(type, notePresence, { capture: true, passive: true });
  }
}

function notePresence() {
  _lastPresence = Date.now();
  if (!_liveHeld.graph && !_liveHeld.badge && !_liveHeld.reconnect) return;
  /* Kept through a lapse: the password typed into the sheet is presence,
     but the session behind it cannot answer until the sign-in lands. */
  if (!signedIn()) return;
  const held = { ..._liveHeld };
  forgetHeldLive();
  if (held.reconnect) connectLive();
  else if (_ws && _ws.readyState === 1) liveStatus('live');   // 1: OPEN
  /* A reopened socket refetches as well: whatever changed while it was
     down was never announced to this tab. */
  if (held.graph || held.reconnect) _refetchSoon();
  if (held.badge || held.reconnect) _badgeSoon();
}

function forgetHeldLive() {
  _liveHeld.graph = false;
  _liveHeld.badge = false;
  _liveHeld.reconnect = false;
}

/** One 'change' frame: refetch now, or hold it while nobody is here. */
function onLiveChange(msg) {
  const which = msg.kind === 'notification' ? 'badge' : 'graph';
  if (liveAway()) {
    _liveHeld[which] = true;
    liveStatus('away');
    return;
  }
  if (which === 'badge') _badgeSoon();
  else _refetchSoon();
}

/* One sentence per state, and no per-call override: the only caller that
   ever passed one was `connectLive` refusing to open a socket for a
   cookie-only session, which it no longer does. A parameter kept for a
   caller that has gone is a parameter the next person fills in with a
   guess. */
function liveStatus(state_) {
  const dot = $('live-dot');
  if (!dot) return;
  /* 'away' is drawn as 'off' (final review C20, 2026-09-23): the socket
     is up, but nothing on screen moves until the analyst is back, and a
     dot that stays lit over a picture that has stopped is the silent
     stop this dot exists to prevent. */
  dot.className = 'live-dot live-' + (state_ === 'away' ? 'off' : state_);
  dot.title = {
    live: 'Live. Changes to this case by other analysts arrive without a '
      + 'refresh.',
    connecting: 'Connecting to the live channel…',
    off: 'Not live. The console works normally; you will need to refresh '
      + 'to see another analyst\'s changes. This is a convenience, not a '
      + 'correctness feature.',
    away: 'Paused while nobody is using this console, so that it can still '
      + 'time out. Changes made meanwhile load on your next click, key press '
      + 'or mouse movement.',
  }[state_] || '';
}

/** Open the socket. NOT gated on `state.token` (2026-09-10): the upgrade
 *  is an ordinary HTTP request until the server switches protocols, so
 *  the browser attaches `__Host-session` to it, and `_handshake` in
 *  `routers/live.py` now reads that cookie in preference to the frame.
 *  A session restored from the cookie after a reload therefore goes live
 *  like any other; the gate that used to stand here refused to open a
 *  socket the server would have accepted, and the reason it printed --
 *  "sign out and in again to go live" -- is now deleted rather than
 *  demoted, because a stale sentence that sounds informed is worse than
 *  the plain "not live" the dot already carries. */
function connectLive() {
  if (!window.WebSocket) { liveStatus('off'); return; }
  disconnectLive();
  liveStatus('connecting');
  const scheme = location.protocol === 'https:' ? 'wss:' : 'ws:';
  let ws;
  try {
    ws = new WebSocket(`${scheme}//${location.host}${API}/live`);
  } catch (_e) {
    liveStatus('off');
    return;
  }
  _ws = ws;

  ws.addEventListener('open', () => {
    /* The frame is REQUIRED of everyone, because the case id has nowhere
       else to go: a hello without one subscribes to notifications alone.
       The credential is the cookie the browser just attached to the
       upgrade, so `token` is sent only when this tab actually holds one
       -- a console the browser refused the Secure pair on (plain HTTP,
       non-localhost), where there IS no cookie for `_handshake` to
       prefer. Absent rather than null: a null would still be a token
       field this page did not need to fill.

       Never the URL, on any path. A URL lands in proxy logs, browser
       history and Referer, and this one would carry a session token;
       WebSocket has no header API in a browser, so the first frame is
       the only place left. */
    const hello = { case_id: state.caseId };
    if (state.token) hello.token = state.token;
    ws.send(JSON.stringify(hello));
  });

  ws.addEventListener('message', (event) => {
    let msg;
    try { msg = JSON.parse(event.data); } catch (_e) { return; }
    if (msg.type === 'ready') { _wsRetry = 0; liveStatus('live'); return; }
    if (msg.type !== 'change') return;
    onLiveChange(msg);
  });

  ws.addEventListener('close', (event) => {
    if (_ws !== ws) return;      // closed on purpose (`disconnectLive`)
    _ws = null;
    liveStatus('off');
    /* `1008` is the policy close the server sends for a bad token, a
       revoked assignment or a refused hello: the server has decided, and
       retrying looks like an attack in the audit log. Until 2026-09-09
       this comment said exactly that while the handler ignored the code
       and retried anyway. Every other close (a dropped connection, a
       restart, the pre-accept refusal a browser reports as 1006) is
       reconnected with a backoff, and given up after a while rather than
       hammering a server that may be down. */
    if (event && event.code === 1008) return;
    /* The session, not the token: this asks whether there is still
       anything to reconnect FOR, and a null token stopped meaning "no
       session" when the socket started taking the cookie. */
    if (!signedIn() || _wsRetry >= 6) return;
    if (liveAway()) { _liveHeld.reconnect = true; return; }   // C20
    const delay = Math.min(30000, 1000 * Math.pow(2, _wsRetry));
    _wsRetry += 1;
    _wsTimer = setTimeout(connectLive, delay);
  });

  ws.addEventListener('error', () => { /* `close` follows; handled there */ });
}

/** Close this tab's socket on purpose: a case switch (`connectLive`), a
 *  lapse, a sign-out. `_ws` is let go BEFORE the close, and the socket's
 *  close handler returns for any socket that is no longer `_ws`. It used
 *  to reconnect it: the close event arrives after this has cleared the
 *  retry timer, so every case switch after the first left a loop that
 *  closed the new socket and opened another about once a second, for as
 *  long as the tab lived: measured on 2026-09-23 at 23 sockets in the 23
 *  seconds after a second case was opened. Each handshake slides the
 *  session on the server, so a console that had opened two cases never
 *  reached its idle expiry at all (final review C20). The dot is set
 *  here for the same reason: the handler no longer does it for these
 *  sockets. */
function disconnectLive() {
  if (_wsTimer) { clearTimeout(_wsTimer); _wsTimer = null; }
  if (_ws) {
    const ws = _ws;
    _ws = null;
    try { ws.close(); } catch (_e) { /* already gone */ }
    liveStatus('off');
  }
}

async function boot() {
  wire();
  /* A tab open across the 2026-09-09 upgrade still holds the previous
     build's bearer token in sessionStorage, readable by any script on
     the origin. Remove it; nothing reads it any more. */
  try { sessionStorage.removeItem(LEGACY_TOKEN_STORAGE); } catch (_e) { /* storage blocked */ }
  const notice = await adoptSessionFromFragment();
  /* Always attempted, not only with a token in hand: after a reload the
     session is the HttpOnly cookie, which this script cannot see, so the
     only way to learn whether one exists is to ask /auth/me with it.
     `startApp` refuses a session that answers there without its readable
     half (`halfSession`), with its own banner. */
  let up = false;
  try {
    await startApp();
    up = true;
  } catch (_err) {
    /* No session, or a stale one: not an error worth a banner (the 401
       path already routed through endSession with `booting` set), just
       ask again. */
    state.token = null;
  }
  state.booting = false;
  if (!up) {
    show($('view-app'), false);
    show($('view-login'), true);
    $('login-email').focus();
  }
  /* After `booting` clears, so it is not suppressed; after the view is
     settled, so it lands next to the form or the app it is about. */
  if (notice) banner(notice.title, notice.detail, notice.kind);
  if (!up) probeFirstRun();
}

/* --- session: idle warning, in-place sign-in, resume ------------------
 *
 * expiry-drops-context (2026-09-22). The server ends a session after 30
 * minutes without a request and 12 hours after sign-in
 * (`security/sessions.py`). Nothing here warned, so the analyst learned
 * of it by clicking Save; `_fetch` then unmounted the app, forgot the
 * case, and the banner did not say the Save had not happened. Now:
 *
 * - `noteSessionActivity` records every answered request, and a
 *   one-second clock shows a warning five minutes before either limit;
 * - at the limit, or on a 401 mid-session, `sessionLapsed` puts a sign-in
 *   OVER the app: case, pane, selection and form contents stay, and the
 *   sheet says whether the last action was saved;
 * - signing in there must be the same account (the email is fixed), and
 *   the app carries on where it was;
 * - if the app is torn down anyway ("Sign in as someone else", a reload),
 *   `rememberResume` keeps the case and pane for the same analyst's next
 *   sign-in, through the `#case=`/`#tab=` deep-link path that exists.
 *
 * Several tabs share one cookie session, so they share activity too, over
 * a BroadcastChannel: a tab left open behind the one being worked in must
 * not declare a session dead that the other is keeping alive. The client
 * never polls to find out; a request to ask would itself slide the idle
 * window and the timeout would never fire.
 */
const IDLE_WARN_MS = 5 * 60 * 1000;
const RESUME_KEY = 'noctornal.resume';

const SESSION = {
  lapsed: false,
  lapseUnsafe: false,     // a write failed because the session had ended
  lapseMissedRead: false, // a read failed because the session had ended
  serverEnded: false,     // the server has refused the session (a 401)
  mode: null,             // 'lapsed' | 'confirm' | 'renew' while the sheet is up
  userId: null,
  email: '',
  idleMs: 30 * 60 * 1000,
  hardAt: null,           // Date.now() at which the 12-hour limit falls
  stepUpUntil: null,      // Date.now() at which the step-up gate closes
  lastActivity: 0,
  said: '',               // what the idle warning last announced
  timer: null,
  banners: [],
  channel: null,
  lastBroadcast: 0,
  restoreFocus: null,
  confirmWaiters: [],
};

function noteSessionActivity(at) {
  const when = at || Date.now();
  if (when > SESSION.lastActivity) SESSION.lastActivity = when;
  if (SESSION.channel && SESSION.userId && when - SESSION.lastBroadcast > 10000) {
    SESSION.lastBroadcast = when;
    try {
      SESSION.channel.postMessage({ t: 'activity', at: when, user: SESSION.userId });
    } catch (_e) { /* a closed channel is not worth a banner */ }
  }
}

/** What /auth/me says about the session, turned into this tab's clock. */
function adoptSessionFacts(me) {
  SESSION.userId = me.user_id;
  SESSION.email = me.email || '';
  if (Number.isFinite(me.idle_timeout_seconds) && me.idle_timeout_seconds > 0) {
    SESSION.idleMs = me.idle_timeout_seconds * 1000;
  }
  /* Relative, not a timestamp: this computer's clock and the server's
     need not agree, and a countdown only needs the distance. */
  SESSION.hardAt = Number.isFinite(me.session_expires_in_seconds)
    ? Date.now() + me.session_expires_in_seconds * 1000 : null;
  adoptStepUp(me);
  SESSION.lapsed = false;
  SESSION.lapseUnsafe = false;
  SESSION.lapseMissedRead = false;
  SESSION.serverEnded = false;
  noteSessionActivity();
  renderAccountChip(me.recovery_codes_remaining);
  startSessionClock();
}

/** How long the step-up gate stays open, from an /auth/me answer (or a
 *  sibling tab's word, `seconds` alone). Unknown stays unknown (null): an
 *  older server that does not say leaves the 403 path to decide. */
function adoptStepUp(me, seconds) {
  const s = me ? me.step_up_fresh_seconds : seconds;
  if (Number.isFinite(s)) SESSION.stepUpUntil = Date.now() + s * 1000;
}

/** True when a step-up gated request would be refused now (with a
 *  30-second margin for the request's own trip). Asking for the sign-in
 *  first spares a doomed request, which on POST /auth/recovery-codes
 *  spends a token of its rate limit even when refused (fix round,
 *  2026-09-22). */
function stepUpStale() {
  return SESSION.stepUpUntil !== null && Date.now() > SESSION.stepUpUntil - 30000;
}

function startSessionClock() {
  if (SESSION.timer) clearInterval(SESSION.timer);
  SESSION.timer = setInterval(tickSession, 1000);
  if (!SESSION.channel && typeof BroadcastChannel === 'function') {
    try {
      SESSION.channel = new BroadcastChannel('noctornal-session');
      SESSION.channel.addEventListener('message', onSessionMessage);
    } catch (_e) { SESSION.channel = null; }
  }
}

/** One-time secrets on screen that belong to the session that showed
 *  them: this analyst's new recovery codes (Account), and the password,
 *  TOTP secret and QR code an administrator was just issued for someone
 *  else (Admin). Nothing ever cleared the Admin card: a sign-out, or
 *  "Sign in as someone else" on a lapsed sheet, left it in the Admin pane
 *  for the next analyst signed in on this tab, whose rail offers Admin
 *  inside any case, and with no password reset that password is the
 *  account's for good (final review C4, 2026-09-23). Shown as well as
 *  emptied, because a lapse hides the Admin card (`sessionLapsed`) and
 *  the next card an administrator is issued must be seen. First run's
 *  card is not here: it is shown before there is a session, and it has
 *  rules of its own (`forgetFirstRunSecrets`). */
function clearSessionSecrets() {
  clear($('account-codes-out'));
  clear($('adm-creds'));
  show($('adm-creds'), true);
}

function stopSessionClock() {
  if (SESSION.timer) { clearInterval(SESSION.timer); SESSION.timer = null; }
  SESSION.userId = null;
  SESSION.lapsed = false;
  SESSION.lapseUnsafe = false;
  SESSION.lapseMissedRead = false;
  SESSION.serverEnded = false;
  SESSION.stepUpUntil = null;
  SESSION.mode = null;
  hideIdleWarning();
  show($('reauth-scrim'), false);
  /* The sheet is taken down here without `closeReauth`, so its fields
     are emptied here too (final review U16, 2026-09-23). */
  $('reauth-password').value = '';
  $('reauth-totp').value = '';
  show($('account-scrim'), false);
  clearSessionSecrets();             // secrets do not outlive the session
  SESSION.accountWasOpen = false;
  $('view-app').inert = false;
  window.removeEventListener('beforeunload', guardUnsaved);
  const waiters = SESSION.confirmWaiters.splice(0);
  for (const w of waiters) w(false);
}

function onSessionMessage(event) {
  const m = event && event.data;
  if (!m || m.user !== SESSION.userId) return;
  if (m.t === 'activity' && m.at > SESSION.lastActivity) {
    SESSION.lastActivity = m.at;
  } else if (m.t === 'renewed') {
    /* Another tab signed the same analyst in afresh. The cookie pair is
       per browser, so this tab already holds the new session, lapsed or
       not, and counts down ITS limits from now on. Until the fix round
       of 2026-09-22 only a lapsed tab listened, and one that had not
       lapsed kept the replaced session's 12-hour deadline: it warned, and
       then covered itself with a sign-in, at a limit that no longer
       applied. Any sheet open here is answered by that sign-in too. */
    adoptStepUp(null, m.stepUpIn);
    sessionRenewed(m.expiresIn);
    const waiters = SESSION.confirmWaiters.splice(0);
    for (const w of waiters) w(true);
  }
}

function fmtCountdown(ms) {
  const s = Math.max(0, Math.ceil(ms / 1000));
  return Math.floor(s / 60) + ':' + String(s % 60).padStart(2, '0');
}

function tickSession() {
  if (!SESSION.userId || SESSION.lapsed || state.booting) return;
  const now = Date.now();
  const idleLeft = SESSION.lastActivity + SESSION.idleMs - now;
  const hardLeft = SESSION.hardAt === null ? Infinity : SESSION.hardAt - now;
  const idle = idleLeft <= hardLeft;
  const left = Math.min(idleLeft, hardLeft);
  if (left <= 0) {
    sessionLapsed({ cause: idle ? 'idle' : 'absolute', unsafe: false });
    return;
  }
  const box = $('idle-warn');
  if (left > IDLE_WARN_MS) {
    if (!box.hidden || SESSION.said) hideIdleWarning();
    return;
  }
  $('idle-warn-text').textContent = idleWarningText(idle, fmtCountdown(left));
  show($('idle-stay'), idle);
  show($('idle-renew'), !idle);
  show(box, true);
  /* The seconds are for the eye. The alert region beside them is rewritten
     only when the whole minute changes, because a live region rewritten
     every second is read out every second, for five minutes, over
     whatever the analyst is listening to (fix round, 2026-09-22).
     Written after the box is shown, so the region is in the tree when
     its text arrives. */
  const mins = Math.ceil(left / 60000);   // "under", so never an overstatement
  const said = idleWarningText(idle, mins <= 1 ? 'under a minute'
    : 'under ' + mins + ' minutes');
  if (said !== SESSION.said) {
    SESSION.said = said;
    $('idle-warn-say').textContent = said;
  }
}

function idleWarningText(idle, when) {
  return idle
    ? 'Your session ends in ' + when + ' without activity. Anything you '
      + 'have not saved stays on screen, but saving it after that needs a '
      + 'fresh sign-in.'
    : 'This session reaches its 12-hour limit in ' + when + '. Sign in '
      + 'again now to carry on without interruption.';
}

/** Take the warning down and forget what it announced, so the next one
 *  is announced afresh rather than matched against a stale sentence. */
function hideIdleWarning() {
  show($('idle-warn'), false);
  SESSION.said = '';
  $('idle-warn-say').textContent = '';
}

/** The session is over, or this tab believes it is: put the sign-in over
 *  the app instead of tearing the app down.
 *
 *  `cause` is 'server' for a 401, 'idle' or 'absolute' for this tab's
 *  own clock. Unlike `endSession`, neither deletes the readable CSRF
 *  cookie. It is per browser, not per tab: another tab may already have
 *  signed back in and set a new one, which a late 401 here would delete,
 *  leaving that tab a half session (`halfSession`). A request that goes
 *  out behind the sheet on the old pair only 401s again, the sign-in in
 *  the sheet replaces the pair, and leaving the sheet goes through
 *  `endSession`, which drops it. */
function sessionLapsed(info) {
  if (info.unsafe) SESSION.lapseUnsafe = true;
  else if (info.cause === 'server') SESSION.lapseMissedRead = true;
  if (info.cause === 'server') {
    state.token = null;              // a bearer that 401'd is dead
    SESSION.serverEnded = true;      // so leaving has nothing to revoke
  }
  if (SESSION.lapsed) {
    if (SESSION.mode === 'lapsed') describeLapse(info);
    return;
  }
  SESSION.lapsed = true;
  SESSION.lapseCause = info.cause;
  /* The socket's reconnect loop would retry against a dead session, which
     reads as an attack in the audit log (see `endSession`). */
  disconnectLive();
  closePalette();
  show($('keys-scrim'), false);
  /* Account is hidden, not cleared: a set of recovery codes on it that
     the analyst was still copying out comes back with the sheet after
     the in-place sign-in (`sessionRenewed`). */
  SESSION.accountWasOpen = !$('account-scrim').hidden;
  show($('account-scrim'), false);
  /* The Admin card of another account's one-time credentials is hidden
     for a reason of its own: a lapse is usually an empty desk, and the
     scrim over the app is translucent. Hidden, not cleared: the same
     administrator signing back in here gets it back (`sessionRenewed`),
     and anyone else never sees it (`clearSessionSecrets`). Final review
     C4, 2026-09-23. */
  show($('adm-creds'), false);
  hideIdleWarning();
  rememberResume();
  /* A reload now would throw away whatever is typed behind the sheet;
     the browser's own "leave this page?" is the last chance to say so. */
  window.addEventListener('beforeunload', guardUnsaved);
  openReauth('lapsed', info);
}

function describeLapse(info) {
  const idleMin = Math.round(SESSION.idleMs / 60000);
  const reason = {
    idle: 'You were signed out after ' + idleMin + ' minutes without activity.',
    absolute: 'This session reached its 12-hour limit.',
  }[SESSION.lapseCause || info.cause]
    || 'Your session has ended (the server said: '
      + (info.detail || 'invalid or expired session') + ').';
  $('reauth-reason').textContent = reason;
  /* Said of what is actually behind the sheet. "All cases" clears the
     case before its read, so a 401 there used to promise a case and pane
     that were already gone (fix round, 2026-09-22). */
  const behind = state.caseId ? 'your case, pane' : 'the case list';
  let after = '';
  if (SESSION.lapseMissedRead) {
    after = state.caseId
      ? ' Anything that did not load will load when you open it again.'
      : ' The case list reloads when you do.';
  }
  $('reauth-effect').textContent = SESSION.lapseUnsafe
    ? 'The change you just made was NOT saved. Everything else on screen '
      + 'is as you left it: sign in, then make that change again.'
    : 'Nothing has been lost: ' + behind + ' and anything you had typed '
      + 'are still here behind this dialog. Sign in to carry on.' + after;
}

/** Show the sign-in sheet. `mode` is 'lapsed' (the session is gone; the
 *  only other way out is a full sign-out), 'confirm' (a fresh sign-in for
 *  a step-up action such as recovery codes) or 'renew' (a fresh session
 *  before the 12-hour limit); the last two can be cancelled, because the
 *  session behind them still works. */
function openReauth(mode, info) {
  SESSION.mode = mode;
  /* First, so the focus to return to is the one under them. The idle
     warning's "Sign in again now" can be clicked over the palette. */
  closeOverSheets();
  if (!SESSION.restoreFocus) SESSION.restoreFocus = document.activeElement;
  $('reauth-email').value = SESSION.email;
  $('reauth-password').value = '';
  $('reauth-totp').value = '';
  setMsg($('reauth-error'), '');
  if (mode === 'lapsed') {
    $('reauth-title').textContent = 'Sign in to continue';
    describeLapse(info || {});
    $('reauth-leave').textContent = 'Sign in as someone else';
  } else {
    $('reauth-title').textContent = mode === 'confirm'
      ? 'Confirm it is you' : 'Sign in again';
    $('reauth-reason').textContent = mode === 'confirm'
      ? (info && info.why) || 'This needs a sign-in from the last 15 minutes.'
      : 'Signing in now starts a fresh 12-hour session.';
    $('reauth-effect').textContent =
      'Nothing on screen changes, and your current session keeps working '
      + 'if you cancel.';
    $('reauth-leave').textContent = 'Cancel';
  }
  show($('reauth-scrim'), true);
  /* Inert, not merely covered: Tab must not walk into the app behind the
     sheet and fire requests the dead session can only refuse. */
  $('view-app').inert = true;
  $('reauth-password').focus();
}

function closeReauth() {
  show($('reauth-scrim'), false);
  /* The fields go with the sheet. Only opening it or a sign-in that
     worked emptied them, so a password typed and then cancelled, or
     left behind by "Sign in as someone else", stayed in the hidden input
     for whoever used this tab next (final review U16, 2026-09-23). */
  $('reauth-password').value = '';
  $('reauth-totp').value = '';
  /* A step-up sheet opened from Account returns to Account, which is
     modal too: the app stays inert under it. */
  $('view-app').inert = !$('account-scrim').hidden;
  SESSION.mode = null;
  const back = SESSION.restoreFocus;
  SESSION.restoreFocus = null;
  if (back && document.contains(back) && typeof back.focus === 'function') {
    back.focus();
  }
}

function guardUnsaved(event) {
  event.preventDefault();
  event.returnValue = '';
}

async function submitReauth(event) {
  event.preventDefault();
  const btn = $('reauth-submit');
  const errBox = $('reauth-error');
  setMsg(errBox, '');
  btn.disabled = true;
  try {
    await api('/auth/login', {
      method: 'POST',
      json: { email: SESSION.email, password: $('reauth-password').value,
              totp_code: $('reauth-totp').value.trim() },
    });
    if (!csrfCookie()) {
      setMsg(errBox, 'The browser refused the session cookies (plain HTTP '
        + 'from an address that is not localhost), so this tab still holds '
        + 'no session. Serve the console over HTTPS or reach it at localhost.');
      return;
    }
    const me = await api('/auth/me');
    $('reauth-password').value = '';
    $('reauth-totp').value = '';
    if (me.user_id !== SESSION.userId) {
      /* The email is fixed, so this should not happen; if it does, the
         screen behind the sheet belongs to someone else and must go. */
      closeReauth();
      SESSION.lapsed = false;
      window.removeEventListener('beforeunload', guardUnsaved);
      state.caseId = null;
      await startApp();
      return;
    }
    sessionRenewed(me.session_expires_in_seconds, me);
    if (SESSION.channel) {
      try {
        SESSION.channel.postMessage({ t: 'renewed', user: me.user_id,
                                      expiresIn: me.session_expires_in_seconds,
                                      stepUpIn: me.step_up_fresh_seconds });
      } catch (_e) { /* the other tabs will find out on their next 401 */ }
    }
    /* Any fresh sign-in satisfies a pending step-up, including one that
       began as a confirmation and became a lapse while it was open. */
    const waiters = SESSION.confirmWaiters.splice(0);
    for (const w of waiters) w(true);
  } catch (err) {
    /* `/auth/login` is a credential check, so its 401 comes back here
       instead of through `sessionLapsed`: say it next to the fields. */
    if (err instanceof ApiError && err.status === 401) {
      setMsg(errBox, 'That password and code did not sign you in. Check '
        + 'both; five failures lock the account for 15 minutes.');
    } else {
      inlineProblem(errBox, err);
    }
  } finally {
    btn.disabled = false;
  }
}

/** The same analyst holds a live session again: carry on where they were. */
function sessionRenewed(expiresIn, me) {
  const unsafe = SESSION.lapseUnsafe;
  const wasLapsed = SESSION.lapsed;
  /* A case list whose read met the lapse is reloaded: it is a read, and
     the sheet said it would be. A failed read inside a case is not
     re-run, because which one failed is not known here. */
  const reloadList = wasLapsed && SESSION.lapseMissedRead && !state.caseId
    && !$('view-cases').hidden;
  SESSION.lapsed = false;
  SESSION.lapseUnsafe = false;
  SESSION.lapseMissedRead = false;
  SESSION.lapseCause = null;
  SESSION.serverEnded = false;
  if (Number.isFinite(expiresIn)) SESSION.hardAt = Date.now() + expiresIn * 1000;
  if (me) adoptStepUp(me);
  noteSessionActivity();
  hideIdleWarning();
  if (me) renderAccountChip(me.recovery_codes_remaining);
  /* A sibling tab's sign-in, seen by a tab that had neither lapsed nor a
     sheet open: the new limits above are all that changes here. */
  if (!wasLapsed && SESSION.mode === null) return;
  window.removeEventListener('beforeunload', guardUnsaved);
  forgetResume();
  if (SESSION.mode !== null) closeReauth();
  clearSessionBanners();
  if (wasLapsed && state.caseId) connectLive();
  if (wasLapsed) refreshGlassChip();  // final review C17: a lapse ate its refresh
  if (wasLapsed) show($('adm-creds'), true);   // hidden by `sessionLapsed`
  if (reloadList) showCaseList();
  if (wasLapsed && SESSION.accountWasOpen) {
    SESSION.accountWasOpen = false;
    setAccountOpen(true);
    $('account-close').focus();
  }
  if (unsafe) {
    sessionBanner('Signed in again',
      'The change you made just before the session ended was not saved. '
      + 'Everything else is as you left it: make that change again.');
  }
}

/** Leave the in-place sign-in for the full one. The case and pane are
 *  kept for this analyst's next sign-in by `endSession`. */
async function leaveReauth() {
  if (SESSION.mode !== 'lapsed') {
    const waiters = SESSION.confirmWaiters.splice(0);
    for (const w of waiters) w(false);
    closeReauth();
    return;
  }
  const email = SESSION.email;
  if (!SESSION.serverEnded) {
    /* Before `endSession`, which drops the readable CSRF cookie the
       sign-out's double-submit needs. */
    const btn = $('reauth-leave');
    btn.disabled = true;
    try { await revokeIfStillOurs(SESSION.userId); }
    finally { btn.disabled = false; }
    /* Another tab signed this analyst in while that was out: the sheet
       has been answered, and this tab carries on with them. */
    if (SESSION.mode !== 'lapsed') return;
  }
  closeReauth();
  endSession('Signed out', 'Your session had ended. Sign in to carry on.');
  $('login-email').value = email;
  $('login-password').focus();
}

/** "Sign in as someone else" after THIS tab's clock ended the session
 *  (fix round 2, 2026-09-23). The server may still hold it: its idle
 *  window is slid by requests this tab does not see (the live socket's
 *  handshake among them), and the limit here is an estimate. Leaving went
 *  through `endSession` alone, which cannot delete the HttpOnly cookie,
 *  so the previous analyst's session stayed live in this browser until
 *  the server's own timeout. It is now revoked, and only if it is still
 *  the same analyst's: the cookie pair is per browser, and another tab
 *  may have signed someone else in since. Raw requests, not `api()`: a
 *  401 here is the outcome wanted, not a lapse to report. Best effort and
 *  bounded; a server that cannot be reached ends it at its idle timeout. */
async function revokeIfStillOurs(userId) {
  /* The sign-out's CSRF header is taken NOW, from the pair this tab
     lapsed on. If another tab signs in while the check below is out, the
     cookie pair changes, this header no longer matches it, and the server
     refuses the sign-out (403) instead of revoking the new session. */
  const write = authHeaders('POST');
  const signal = typeof AbortSignal === 'function'
    && typeof AbortSignal.timeout === 'function'
    ? AbortSignal.timeout(4000) : undefined;
  try {
    const who = await fetch(API + '/auth/me', {
      headers: authHeaders('GET'), credentials: 'same-origin', signal });
    if (!who.ok) return;
    const me = await who.json();
    if (!userId || me.user_id !== userId) return;
    if (SESSION.mode !== 'lapsed') return;       // answered meanwhile
    await fetch(API + '/auth/logout', {
      method: 'POST', headers: write, credentials: 'same-origin', signal });
  } catch (_e) { /* unreachable or too slow: see above */ }
}

/** Resolve true once the analyst has signed in afresh in the sheet, false
 *  if they cancel. For step-up actions: the server gates them on a sign-in
 *  from the last 15 minutes, and a fresh sign-in is the one re-challenge
 *  the console has. */
function confirmIdentity(why) {
  return new Promise((resolve) => {
    SESSION.confirmWaiters.push(resolve);
    openReauth('confirm', { why });
  });
}

/* Where to come back to. Per tab (sessionStorage) and never a credential:
   the case id and the pane, and whose they were. */
function rememberResume() {
  if (!state.userId || !state.caseId) return;
  try {
    sessionStorage.setItem(RESUME_KEY, JSON.stringify({
      user: state.userId, caseId: state.caseId, tab: state.tab || null,
      at: Date.now(),
    }));
  } catch (_e) { /* storage blocked: the in-place sign-in still works */ }
}

function forgetResume() {
  try { sessionStorage.removeItem(RESUME_KEY); } catch (_e) { /* blocked */ }
}

/** `_fetch`'s session bookkeeping, for a request that has to call fetch()
 *  itself because it wants the raw body (a file download). An answer the
 *  server accepted slides the idle clock; a mid-session 401 opens the
 *  in-place sign-in and says, in `msg`, that `what` did not happen. True
 *  when the caller must stop there. The report download bypassed both:
 *  its 401 read "invalid or expired session" in the pane, with no way
 *  back in but a sign-out (fix round, 2026-09-22). */
async function sessionRefusedRaw(res, sentAt, msg, what) {
  if (res.status !== 401 && res.status !== 429) noteSessionActivity(sentAt);
  if (res.status !== 401 || !state.userId || state.booting) return false;
  const p = await problemOf(res);
  sessionLapsed({ cause: 'server', unsafe: false, detail: p.detail });
  if (msg) {
    setMsg(msg, what + ': your session had ended. Sign in again in the '
      + 'dialog, then try again.');
  }
  return true;
}

/** Reopen the remembered case and pane, through the deep-link path, for
 *  the SAME analyst only, within the 12 hours a session can last. A
 *  deep link already in the URL wins: it was asked for more recently. */
function applyResume(userId) {
  let saved = null;
  try { saved = JSON.parse(sessionStorage.getItem(RESUME_KEY) || 'null'); }
  catch (_e) { saved = null; }
  forgetResume();
  if (!saved || saved.user !== userId || !saved.caseId) return;
  if (Date.now() - (saved.at || 0) > 12 * 3600 * 1000) return;
  if (state.deepLinkCase) return;
  state.deepLinkCase = saved.caseId;
  if (saved.tab && !state.deepLinkTab) state.deepLinkTab = saved.tab;
}

/* Banners about the session are about THIS session: a new sign-in makes
   them false, so they are taken down instead of left over the app bar. */
function sessionBanner(title, detail) {
  banner(title, detail, 'warn');
  const node = $('banners').lastElementChild;
  if (node) SESSION.banners.push(node);
}

function clearSessionBanners() {
  for (const node of SESSION.banners.splice(0)) node.remove();
}

/* --- account: recovery codes -------------------------------------------
 *
 * recovery-codes-unobtainable (2026-09-22). The sign-in form offered
 * recovery codes, `/auth/me` counted them and `POST /auth/recovery-codes`
 * issued them, and nothing in the console called either: the only issuer
 * was `bootstrap.py recovery-codes`, on the server. Codes are now issued
 * at the first administrator's first sign-in and from this sheet, where
 * the count is shown and a set can be replaced.
 */
function renderAccountChip(remaining) {
  const flag = $('hdr-codes-flag');
  const btn = $('btn-account');
  const low = Number.isFinite(remaining) && remaining <= 2;
  const text = remaining === 0 ? 'no recovery codes'
    : remaining + ' recovery code' + (remaining === 1 ? '' : 's') + ' left';
  flag.textContent = low ? text : '';
  show(flag, low);
  btn.classList.toggle('codes-low', low);
  btn.title = low ? 'Account: ' + text + '. Open it to generate a set.'
    : 'Account: recovery codes and session';
}

function renderRecoveryCodes(box, codes, note) {
  clear(box);
  const wrap = el('div', 'card stack creds');
  wrap.appendChild(el('p', 'req', 'Shown once: store them offline'));
  const list = el('ol', 'codes-grid');
  list.setAttribute('aria-label', 'Recovery codes');
  for (const c of codes) list.appendChild(el('li', null, c));
  wrap.appendChild(list);
  const tools = el('div', 'setup-actions');
  tools.appendChild(credCopyButton(codes.join('\n'), list, 'Copy all codes',
                                   'Copy all'));
  wrap.appendChild(tools);
  if (note) wrap.appendChild(el('p', 'help', note));
  box.appendChild(wrap);
}

/** The Account sheet says aria-modal, so the app behind it is inert, as it
 *  is behind the sign-in sheet: until the fix round of 2026-09-22 Tab
 *  walked out of the sheet into the app it covered. */
function setAccountOpen(on) {
  if (on) closeOverSheets();
  show($('account-scrim'), on);
  $('view-app').inert = on || !$('reauth-scrim').hidden;
}

async function openAccount() {
  if (!signedIn()) return;
  setAccountOpen(true);
  clear($('account-codes-out'));
  show($('account-codes-confirm'), false);
  setMsg($('account-codes-msg'), '');
  $('account-close').focus();
  try {
    const me = await api('/auth/me');
    $('account-name').textContent = me.display_name || '';
    $('account-email').textContent = me.email || '';
    const idleMin = Math.round((me.idle_timeout_seconds || 1800) / 60);
    const endsAt = Number.isFinite(me.session_expires_in_seconds)
      ? new Date(Date.now() + me.session_expires_in_seconds * 1000) : null;
    $('account-session').textContent = 'Ends after ' + idleMin
      + ' minutes without activity'
      + (endsAt ? ', and at ' + fmtClock(endsAt) + ' at the latest.' : '.');
    showCodeCount(me.recovery_codes_remaining);
    renderAccountChip(me.recovery_codes_remaining);
    adoptStepUp(me);
  } catch (err) {
    if (!(err && err.handled)) setMsg($('account-codes-msg'), 'Account '
      + 'details could not be read: ' + (err.detail || err.message || err));
  }
}

function showCodeCount(n) {
  SESSION.codesLeft = n;
  $('account-codes-count').textContent = n === 0
    ? 'None issued yet. If your authenticator is lost, a recovery code is '
      + 'the way back in without an administrator.'
    : n + ' of 10 left.';
  $('account-codes-new').textContent = n === 0
    ? 'Generate recovery codes' : 'Replace them with a new set';
}

async function issueRecoveryCodes(alreadyConfirmed) {
  const btn = $('account-codes-new');
  const msg = $('account-codes-msg');
  msg.className = 'msg';
  setMsg(msg, '');
  /* The step-up gate: a sign-in within 15 minutes. When /auth/me has
     said it is shut, the sign-in is asked for FIRST. Sending the request
     to be refused cost a token of the route's rate limit (three), so
     Generate, Cancel, Generate, confirm left the analyst locked out of
     issuing codes for about twelve minutes (fix round, 2026-09-22). */
  if (!alreadyConfirmed && stepUpStale()) {
    await confirmThenIssue(msg);
    return;
  }
  btn.disabled = true;
  try {
    const out = await api('/auth/recovery-codes', { method: 'POST' });
    renderRecoveryCodes($('account-codes-out'), out.codes, out.note);
    showCodeCount(out.codes.length);
    renderAccountChip(out.codes.length);
  } catch (err) {
    if (err && err.handled) return;
    if (err instanceof ApiError && err.status === 403 && !alreadyConfirmed
        && /re-authenticate/i.test(err.detail || '')) {
      /* The gate shut sooner than this tab knew (an older server that
         does not say, or a clock): ask here and try again, rather than
         telling the analyst to sign out. */
      SESSION.stepUpUntil = 0;
      await confirmThenIssue(msg);
      return;
    }
    msg.className = 'msg bad';
    setMsg(msg, 'No codes were issued: '
      + (err instanceof ApiError ? (err.detail || err.title) : String(err)));
  } finally {
    btn.disabled = false;
  }
}

async function confirmThenIssue(msg) {
  setAccountOpen(false);
  const ok = await confirmIdentity('Issuing recovery codes needs a '
    + 'sign-in from the last 15 minutes.');
  /* Left for the full sign-in while the sheet was up: Account is gone
     with the session, and must not reopen over the sign-in form. */
  if (!signedIn()) return;
  setAccountOpen(true);
  $('account-codes-new').focus();
  if (ok) await issueRecoveryCodes(true);
  else setMsg(msg, 'No codes were issued.');
}

/* --- the session sheets hold the keyboard ------------------------------
 *
 * Fix round 2 (2026-09-23), for regressions the verifier found in the
 * 2026-09-22 fixes. `inert` on the app stops focus and clicks reaching it,
 * but not the key handlers on `document`. With Account or the sign-in
 * sheet open, a stray a, r or d still accepted, rejected or deferred the
 * selected triage proposal behind it (on a live session, from Account);
 * Ctrl+K opened the palette over Account, and one Escape then closed
 * both; and Tab walked out past the sheet to the skip link and the
 * browser. A key now belongs to the sheet on top: it reaches the field or
 * button it was pressed on and stops at the sheet's edge, a key pressed
 * with the focus outside the sheet reaches nothing, Tab cycles inside the
 * sheet, and Escape answers the sheet alone.
 */

/** The session sheet on top, or null. The sign-in sheet (z 86) sits over
 *  Account (z 80) when a step-up is confirmed from it. */
function topSessionSheet() {
  if (!$('reauth-scrim').hidden) return $('reauth-form');
  if (!$('account-scrim').hidden) return $('account-sheet');
  return null;
}

/** The palette and the keyboard sheet belong to the app a session sheet
 *  covers; they do not stay open over it. */
function closeOverSheets() {
  closePalette();
  show($('keys-scrim'), false);
}

/** The idle warning shares the keyboard with Account: it is about this
 *  session, sits outside the inert app, and floats above Account's scrim
 *  (z 85 over 80). The sign-in sheet's scrim (z 86) covers it, and a
 *  button under a scrim is not one to Tab to. */
function warningBesides(sheet) {
  return sheet === $('account-sheet') && !$('idle-warn').hidden;
}

/** What Tab may reach while a session sheet is up, in order: the sheet,
 *  then the idle warning's buttons when `warningBesides` says so. */
function sheetFocusables(sheet) {
  const regions = [sheet];
  if (warningBesides(sheet)) regions.push($('idle-warn'));
  const out = [];
  for (const region of regions) {
    for (const n of region.querySelectorAll(
      'button, input, select, textarea, a[href], summary, [tabindex]')) {
      if (n.disabled || n.tabIndex < 0 || n.closest('[hidden]')) continue;
      if (!n.getClientRects().length) continue;     // display: none
      out.push(n);
    }
  }
  return out;
}

/** Window, capture phase: before any other key handler in the page. */
function onSheetKey(e) {
  const sheet = topSessionSheet();
  if (!sheet) return;
  if (e.key === 'Tab') {
    e.preventDefault();
    e.stopPropagation();
    const list = sheetFocusables(sheet);
    if (!list.length) return;
    const at = list.indexOf(document.activeElement);
    const step = e.shiftKey ? -1 : 1;
    const next = at === -1 ? (e.shiftKey ? list.length - 1 : 0)
      : (at + step + list.length) % list.length;
    list[next].focus();
    return;
  }
  if (e.key === 'Escape') {
    e.preventDefault();
    e.stopPropagation();
    escapeSessionSheet();
    return;
  }
  /* The focus is outside the sheet, on the page itself after a click on
     the dimmed backdrop: the key is nobody's, and the page's shortcuts
     must not take it. A key inside goes on to its field or button, and
     `keepKeysInSheet` stops it on the way back up. */
  const inside = sheet.contains(e.target)
    || (warningBesides(sheet) && $('idle-warn').contains(e.target));
  if (!inside) e.stopPropagation();
}

/** Bubble phase, on each sheet's scrim and on the idle warning. */
function keepKeysInSheet(e) {
  if (topSessionSheet()) e.stopPropagation();
}

function escapeSessionSheet() {
  if (!$('reauth-scrim').hidden) {
    /* The lapsed sheet has no Escape: its ways on are to sign in or to
       leave for the full sign-in, and both are deliberate. */
    if (SESSION.mode !== 'lapsed') leaveReauth();
    return;
  }
  if (!$('account-codes-confirm').hidden) {
    $('account-codes-cancel').click();       // the question first, then the sheet
    return;
  }
  $('account-close').click();
}

function initSession() {
  $('reauth-form').addEventListener('submit', submitReauth);
  $('reauth-leave').addEventListener('click', leaveReauth);
  $('idle-stay').addEventListener('click', async () => {
    /* Any request slides the idle window; /auth/me is the cheapest. */
    try { adoptStepUp(await api('/auth/me')); hideIdleWarning(); }
    catch (err) { fail(err); }
  });
  $('idle-renew').addEventListener('click', () => openReauth('renew'));
  $('btn-account').addEventListener('click', openAccount);
  $('account-close').addEventListener('click', () => {
    clear($('account-codes-out'));   // codes leave the page with the sheet
    setAccountOpen(false);
    $('btn-account').focus();
  });
  $('account-codes-new').addEventListener('click', () => {
    if (!SESSION.codesLeft) { issueRecoveryCodes(false); return; }
    $('account-codes-confirm-text').textContent = 'Replace your '
      + SESSION.codesLeft + ' remaining code'
      + (SESSION.codesLeft === 1 ? '' : 's')
      + '? They stop working the moment the new set is issued.';
    show($('account-codes-confirm'), true);
    $('account-codes-cancel').focus();
  });
  $('account-codes-cancel').addEventListener('click', () => {
    show($('account-codes-confirm'), false);
    $('account-codes-new').focus();
  });
  $('account-codes-replace').addEventListener('click', () => {
    show($('account-codes-confirm'), false);
    issueRecoveryCodes(false);
  });
  window.addEventListener('keydown', onSheetKey, true);
  for (const id of ['reauth-scrim', 'account-scrim', 'idle-warn']) {
    $(id).addEventListener('keydown', keepKeysInSheet);
  }
}

/* --- first run ---------------------------------------------------------
 *
 * While `iam.app_user` is empty the server's /setup/first-admin door is
 * open, and asking a brand-new operator to shell into the box and run
 * bootstrap.py before they can even sign in is how evaluations end. The
 * card is convenience only: the emptiness gate lives server-side, under
 * an advisory lock, so nothing here is load-bearing for safety.
 */
async function probeFirstRun() {
  let body;
  try {
    body = await api('/setup/status');
  } catch (_err) {
    return; // the sign-in form is the right fallback for every failure
  }
  if (!body.needs_setup) return;
  show($('login-form'), false);
  show($('setup-form'), true);
  $('setup-email').focus();
}

/* --- the one-time credential card --------------------------------------
 *
 * Used by first run and by Admin (a new analyst, a re-enrolled
 * authenticator). totp-enrolment-typein (2026-09-22): enrolment was a
 * 32-character type-in, because the otpauth:// URI was printed as text
 * nothing can scan; the copy buttons were invisible until hovered; and the
 * URI ran out of the card. The card now draws the URI as a QR code, groups
 * the secret in fours for the manual path, keeps its Copy buttons visible,
 * wraps every value, and can check a code from the app against the secret
 * on this computer, so a mistyped secret is found while it can be fixed.
 */

/** QR code (ISO/IEC 18004), byte mode, error correction level M, for the
 *  enrolment URI. Written here rather than fetched: the console loads no
 *  third-party script (`script-src 'self'`, no bundler), and the server's
 *  only encoder is `bootstrap.py`'s optional `qrcode` package. One
 *  function so the test can lift it out of this file and hold its output
 *  to that package's, module for module, for every mask
 *  (`test_ui_first_run_session.py`). Returns {version, size, mask,
 *  modules} with `modules` as rows of '0'/'1', or null when the text does
 *  not fit version 40. `forceMask` is for that test; the console lets the
 *  penalty rules choose. */
function qrMatrix(text, forceMask) {
  /* Error-correction codewords per block, and blocks, for level M,
     versions 1 to 40 (ISO/IEC 18004 table 9). */
  const ECC = [10, 16, 26, 18, 24, 16, 18, 22, 22, 26, 30, 22, 22, 24, 24,
    28, 28, 26, 26, 26, 26, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28,
    28, 28, 28, 28, 28, 28, 28];
  const BLOCKS = [1, 1, 1, 2, 2, 4, 4, 4, 5, 5, 5, 8, 9, 9, 10, 10, 11, 13,
    14, 16, 17, 17, 18, 20, 21, 23, 25, 26, 28, 29, 31, 33, 35, 37, 38, 40,
    43, 45, 47, 49];
  const bytes = Array.from(new TextEncoder().encode(String(text)));
  const rawModules = (v) => {
    let r = (16 * v + 128) * v + 64;
    if (v >= 2) {
      const n = Math.floor(v / 7) + 2;
      r -= (25 * n - 10) * n - 55;
      if (v >= 7) r -= 36;
    }
    return r;
  };
  const dataCodewords = (v) =>
    Math.floor(rawModules(v) / 8) - ECC[v - 1] * BLOCKS[v - 1];
  let version = 0;
  for (let v = 1; v <= 40 && !version; v++) {
    if (4 + (v <= 9 ? 8 : 16) + 8 * bytes.length <= dataCodewords(v) * 8) {
      version = v;
    }
  }
  if (!version) return null;

  /* The bit stream: mode, length, bytes, terminator, then pad codewords. */
  const bits = [];
  const put = (val, len) => {
    for (let i = len - 1; i >= 0; i--) bits.push((val >>> i) & 1);
  };
  put(4, 4);
  put(bytes.length, version <= 9 ? 8 : 16);
  for (const b of bytes) put(b, 8);
  const capacity = dataCodewords(version) * 8;
  put(0, Math.min(4, capacity - bits.length));
  put(0, (8 - bits.length % 8) % 8);
  for (let pad = 0xEC; bits.length < capacity; pad ^= 0xEC ^ 0x11) put(pad, 8);
  const data = [];
  for (let i = 0; i < bits.length; i += 8) {
    let b = 0;
    for (let j = 0; j < 8; j++) b = (b << 1) | bits[i + j];
    data.push(b);
  }

  /* Reed-Solomon over GF(256), primitive polynomial 0x11D. */
  const EXP = new Array(512);
  const LOG = new Array(256);
  for (let i = 0, x = 1; i < 255; i++) {
    EXP[i] = x;
    LOG[x] = i;
    x <<= 1;
    if (x & 0x100) x ^= 0x11D;
  }
  for (let i = 255; i < 512; i++) EXP[i] = EXP[i - 255];
  const mul = (a, b) => (a && b ? EXP[LOG[a] + LOG[b]] : 0);
  const ecLen = ECC[version - 1];
  const nBlocks = BLOCKS[version - 1];
  let gen = [1];
  for (let i = 0; i < ecLen; i++) {
    const next = new Array(gen.length + 1).fill(0);
    for (let j = 0; j < gen.length; j++) {
      next[j] ^= gen[j];
      next[j + 1] ^= mul(gen[j], EXP[i]);
    }
    gen = next;
  }
  const ecOf = (block) => {
    const rem = new Array(ecLen).fill(0);
    for (const b of block) {
      const f = b ^ rem.shift();
      rem.push(0);
      for (let j = 0; j < ecLen; j++) rem[j] ^= mul(gen[j + 1], f);
    }
    return rem;
  };
  const rawCodewords = Math.floor(rawModules(version) / 8);
  const shortLen = Math.floor(rawCodewords / nBlocks);
  const nShort = nBlocks - rawCodewords % nBlocks;
  const blocks = [];
  for (let i = 0, k = 0; i < nBlocks; i++) {
    const n = shortLen - ecLen + (i < nShort ? 0 : 1);
    const d = data.slice(k, k + n);
    k += n;
    blocks.push({ d, e: ecOf(d) });
  }
  const codewords = [];
  for (let i = 0; i <= shortLen - ecLen; i++) {
    for (const b of blocks) if (i < b.d.length) codewords.push(b.d[i]);
  }
  for (let i = 0; i < ecLen; i++) for (const b of blocks) codewords.push(b.e[i]);

  /* Function patterns first, so the data placement can skip them. */
  const size = version * 4 + 17;
  const mod = [];
  const fn = [];
  for (let y = 0; y < size; y++) {
    mod.push(new Array(size).fill(false));
    fn.push(new Array(size).fill(false));
  }
  const setF = (x, y, dark) => { mod[y][x] = dark; fn[y][x] = true; };
  for (let i = 0; i < size; i++) {
    setF(6, i, i % 2 === 0);
    setF(i, 6, i % 2 === 0);
  }
  const finder = (cx, cy) => {
    for (let dy = -4; dy <= 4; dy++) {
      for (let dx = -4; dx <= 4; dx++) {
        const x = cx + dx;
        const y = cy + dy;
        if (x < 0 || y < 0 || x >= size || y >= size) continue;
        const d = Math.max(Math.abs(dx), Math.abs(dy));
        setF(x, y, d !== 2 && d !== 4);
      }
    }
  };
  finder(3, 3);
  finder(size - 4, 3);
  finder(3, size - 4);
  if (version > 1) {
    const n = Math.floor(version / 7) + 2;
    const step = version === 32
      ? 26 : Math.ceil((version * 4 + 4) / (n * 2 - 2)) * 2;
    const pos = [6];
    for (let p = size - 7; pos.length < n; p -= step) pos.splice(1, 0, p);
    for (let i = 0; i < n; i++) {
      for (let j = 0; j < n; j++) {
        if ((i === 0 && j === 0) || (i === 0 && j === n - 1)
            || (i === n - 1 && j === 0)) continue;
        for (let dy = -2; dy <= 2; dy++) {
          for (let dx = -2; dx <= 2; dx++) {
            setF(pos[i] + dx, pos[j] + dy,
                 Math.max(Math.abs(dx), Math.abs(dy)) !== 1);
          }
        }
      }
    }
  }
  const drawFormat = (mask) => {
    const info = mask;              // level M is 00 in the top two bits
    let rem = info;
    for (let i = 0; i < 10; i++) rem = (rem << 1) ^ ((rem >>> 9) * 0x537);
    const fmt = ((info << 10) | rem) ^ 0x5412;
    const bit = (i) => ((fmt >>> i) & 1) === 1;
    for (let i = 0; i <= 5; i++) setF(8, i, bit(i));
    setF(8, 7, bit(6));
    setF(8, 8, bit(7));
    setF(7, 8, bit(8));
    for (let i = 9; i < 15; i++) setF(14 - i, 8, bit(i));
    for (let i = 0; i < 8; i++) setF(size - 1 - i, 8, bit(i));
    for (let i = 8; i < 15; i++) setF(8, size - 15 + i, bit(i));
    setF(8, size - 8, true);
  };
  drawFormat(0);
  if (version >= 7) {
    let rem = version;
    for (let i = 0; i < 12; i++) rem = (rem << 1) ^ ((rem >>> 11) * 0x1F25);
    const ver = (version << 12) | rem;
    for (let i = 0; i < 18; i++) {
      const dark = ((ver >>> i) & 1) === 1;
      const a = size - 11 + i % 3;
      const b = Math.floor(i / 3);
      setF(a, b, dark);
      setF(b, a, dark);
    }
  }

  /* Data, in the two-column zigzag from the bottom right. */
  const total = codewords.length * 8;
  for (let right = size - 1, i = 0; right >= 1; right -= 2) {
    if (right === 6) right = 5;
    const upward = ((right + 1) & 2) === 0;
    for (let vert = 0; vert < size; vert++) {
      const y = upward ? size - 1 - vert : vert;
      for (let j = 0; j < 2; j++) {
        const x = right - j;
        if (!fn[y][x] && i < total) {
          mod[y][x] = ((codewords[i >>> 3] >>> (7 - (i & 7))) & 1) === 1;
          i++;
        }
      }
    }
  }

  const MASKS = [
    (x, y) => (x + y) % 2 === 0,
    (x, y) => y % 2 === 0,
    (x, _y) => x % 3 === 0,
    (x, y) => (x + y) % 3 === 0,
    (x, y) => (Math.floor(x / 3) + Math.floor(y / 2)) % 2 === 0,
    (x, y) => (x * y) % 2 + (x * y) % 3 === 0,
    (x, y) => ((x * y) % 2 + (x * y) % 3) % 2 === 0,
    (x, y) => ((x + y) % 2 + (x * y) % 3) % 2 === 0,
  ];
  const applyMask = (m) => {
    for (let y = 0; y < size; y++) {
      for (let x = 0; x < size; x++) {
        if (!fn[y][x] && MASKS[m](x, y)) mod[y][x] = !mod[y][x];
      }
    }
  };
  /* The standard's four penalty rules: long runs, 2x2 blocks, finder
     look-alikes, and dark/light imbalance. Only scan quality rides on
     them; every mask decodes. */
  const penalty = () => {
    let p = 0;
    const lines = (get) => {
      for (let a = 0; a < size; a++) {
        let run = 1;
        for (let b = 1; b <= size; b++) {
          if (b < size && get(a, b) === get(a, b - 1)) { run++; continue; }
          if (run >= 5) p += run - 2;
          run = 1;
        }
        const light = (from, to) => {
          for (let k = from; k < to; k++) {
            if (k >= 0 && k < size && get(a, k)) return false;
          }
          return true;
        };
        for (let b = 0; b + 7 <= size; b++) {
          if (get(a, b) && !get(a, b + 1) && get(a, b + 2) && get(a, b + 3)
              && get(a, b + 4) && !get(a, b + 5) && get(a, b + 6)
              && (light(b - 4, b) || light(b + 7, b + 11))) p += 40;
        }
      }
    };
    lines((a, b) => mod[a][b]);
    lines((a, b) => mod[b][a]);
    let dark = 0;
    for (let y = 0; y < size; y++) {
      for (let x = 0; x < size; x++) {
        if (mod[y][x]) dark++;
        if (x + 1 < size && y + 1 < size && mod[y][x] === mod[y][x + 1]
            && mod[y][x] === mod[y + 1][x] && mod[y][x] === mod[y + 1][x + 1]) {
          p += 3;
        }
      }
    }
    const cells = size * size;
    return p + (Math.ceil(Math.abs(dark * 20 - cells * 10) / cells) - 1) * 10;
  };
  let mask = Number.isInteger(forceMask) && forceMask >= 0 && forceMask < 8
    ? forceMask : -1;
  if (mask < 0) {
    let best = Infinity;
    for (let m = 0; m < 8; m++) {
      applyMask(m);
      drawFormat(m);
      const score = penalty();
      if (score < best) { best = score; mask = m; }
      applyMask(m);
    }
  }
  applyMask(mask);
  drawFormat(mask);
  return {
    version, size, mask,
    modules: mod.map((row) => row.map((c) => (c ? '1' : '0')).join('')),
  };
}

/** Paint a QR code on a canvas: dark modules on a light ground with the
 *  four-module quiet zone, from theme tokens. Dark on light whatever the
 *  theme, because several authenticator scanners do not read an inverted
 *  code. Four backing pixels a module, so a high-density display doubles
 *  it cleanly under `image-rendering: pixelated`. */
function drawQr(canvas, text) {
  const q = qrMatrix(text);
  const ctx = q && canvas.getContext ? canvas.getContext('2d') : null;
  if (!ctx) return false;
  const quiet = 4;
  const px = 4;
  const n = q.size + quiet * 2;
  canvas.width = n * px;
  canvas.height = n * px;
  ctx.fillStyle = cssVar('--text-primary');
  ctx.fillRect(0, 0, canvas.width, canvas.height);
  ctx.fillStyle = cssVar('--void');
  q.modules.forEach((row, y) => {
    for (let x = 0; x < row.length; x++) {
      if (row[x] === '1') ctx.fillRect((x + quiet) * px, (y + quiet) * px, px, px);
    }
  });
  return true;
}

/** RFC 4648 base32 to bytes, ignoring case, spaces, dashes and padding;
 *  null for any other character. */
function base32Bytes(s) {
  const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  const out = [];
  let buf = 0;
  let n = 0;
  for (const ch of String(s).toUpperCase().replace(/[\s=-]/g, '')) {
    const v = ALPHABET.indexOf(ch);
    if (v < 0) return null;
    buf = ((buf << 5) | v) & 0xFFFF;
    n += 5;
    if (n >= 8) {
      out.push((buf >>> (n - 8)) & 0xFF);
      n -= 8;
    }
  }
  return new Uint8Array(out);
}

/** The RFC 6238 codes (SHA-1, 30 s, six digits, as `security/totp.py`)
 *  for the steps within `drift` of `atMs`, computed HERE so a code can be
 *  checked against a secret without sending anything anywhere. A failed
 *  sign-in counts toward the account's lockout (five in 15 minutes);
 *  a failed check here counts toward nothing. Null when this browser has
 *  no Web Crypto (it needs HTTPS or localhost), and the caller then lets
 *  the server decide. */
async function totpCodes(secret, atMs, drift) {
  const key = base32Bytes(secret);
  const subtle = globalThis.crypto && globalThis.crypto.subtle;
  if (!key || !key.length || !subtle) return null;
  const k = await subtle.importKey('raw', key, { name: 'HMAC', hash: 'SHA-1' },
                                   false, ['sign']);
  const step = Math.floor(atMs / 1000 / 30);
  const codes = [];
  for (let d = -drift; d <= drift; d++) {
    const msg = new Uint8Array(8);
    let c = step + d;
    for (let i = 7; i >= 0; i--) { msg[i] = c % 256; c = Math.floor(c / 256); }
    const mac = new Uint8Array(await subtle.sign('HMAC', k, msg));
    const off = mac[mac.length - 1] & 0x0F;
    const bin = ((mac[off] & 0x7F) * 16777216) + (mac[off + 1] << 16)
      + (mac[off + 2] << 8) + mac[off + 3];
    codes.push(String(bin % 1000000).padStart(6, '0'));
  }
  return codes;
}

/* The server accepts the current 30-second step and one either side
   (`security/totp.py`, docs/05). The local checks used two either side
   until the fix round of 2026-09-22, so a code from two steps away (a
   phone about a minute out) passed here, was refused by the server, and
   the refusal was blamed on the server's clock. */
const TOTP_SERVER_DRIFT = 1;
const TOTP_LOOK_AROUND = 10;   // five minutes either way, to name a skew

/** Where `code` falls against `secret` at `atMs`, in 30-second steps: 0
 *  is now, and anything within TOTP_SERVER_DRIFT the server also accepts.
 *  A larger number means the secret is right and a clock is off by that
 *  many steps. Null when it matches nothing in the ten minutes around
 *  now (a wrong secret or a mistyped code), undefined when this browser
 *  cannot compute codes. Should a code match twice, the nearer step is
 *  the likelier reading, so it wins. */
async function totpStepOffset(secret, code, atMs) {
  const codes = await totpCodes(secret, atMs, TOTP_LOOK_AROUND);
  if (!codes) return undefined;
  let best = null;
  codes.forEach((c, i) => {
    const off = i - TOTP_LOOK_AROUND;
    if (c === code && (best === null || Math.abs(off) < Math.abs(best))) best = off;
  });
  return best;
}

/** What a skewed code means, in words: whose clock is ahead, by roughly
 *  how much, and what to do about it. */
function totpSkewText(offset) {
  const secs = Math.abs(offset) * 30;
  const size = secs < 90 ? 'about ' + secs + ' seconds'
    : 'about ' + Math.round(secs / 60) + ' minutes';
  return 'That code is right for this secret, but for a time ' + size + ' '
    + (offset > 0 ? 'ahead of' : 'behind') + ' this computer\'s clock, and '
    + 'the server allows only 30 seconds either way. Set the phone (or this '
    + 'computer) to take its time automatically, then use the new code.';
}

/** A visible Copy button for this card (the hover-only glyph `copyable`
 *  draws elsewhere was invisible here). When the clipboard refuses, as it
 *  does over plain HTTP or in some remote desktops, the value is SELECTED
 *  instead, so Ctrl+C still works and the secret is never unreachable. */
function credCopyButton(value, node, label, text) {
  const idle = text || 'Copy';
  const btn = el('button', 'copy-btn', idle);
  btn.type = 'button';
  btn.setAttribute('aria-label', label);
  btn.title = label;
  btn.addEventListener('click', async () => {
    try {
      await navigator.clipboard.writeText(value);
      btn.textContent = 'Copied';
      btn.classList.add('is-ok');
      setTimeout(() => { btn.textContent = idle; btn.classList.remove('is-ok'); },
                 1500);
    } catch (_e) {
      const sel = window.getSelection();
      if (sel) sel.selectAllChildren(node);
      btn.textContent = 'Selected: press Ctrl+C';
    }
  });
  return btn;
}

/** One labelled value with its Copy button. `shown` is what is displayed
 *  (the secret in groups of four), `value` what is copied (the secret as
 *  issued, which is what an authenticator's paste field wants). */
function credRow(label, value, shown, extraClass) {
  const row = el('div', 'field');
  row.appendChild(el('span', 'label', label));
  const line = el('span', 'copyable');
  const v = el('span', 'mono creds-value' + (extraClass ? ' ' + extraClass : ''),
               shown || value);
  line.appendChild(v);
  line.appendChild(credCopyButton(value, v, 'Copy ' + label.toLowerCase()));
  row.appendChild(line);
  return row;
}

/** Local check of a code against the card's secret, for an administrator
 *  enrolling an analyst in person: "does their app say what this secret
 *  says?" answered without a sign-in attempt. */
function credCheckRow(secret) {
  const row = el('div', 'field');
  row.appendChild(el('span', 'label', 'Check a code from the app'));
  const line = el('div', 'creds-check');
  const input = el('input', 'mono');
  input.type = 'text';
  input.inputMode = 'numeric';
  input.maxLength = 6;
  input.autocomplete = 'off';
  input.setAttribute('aria-label', 'Six-digit code the authenticator app shows');
  const btn = el('button', 'btn small', 'Check');
  btn.type = 'button';
  const out = el('p', 'msg', '');
  out.hidden = true;
  btn.addEventListener('click', async () => {
    const code = input.value.replace(/\s+/g, '');
    /* Only a whole code is judged: four digits typed so far used to be
       answered with "the secret was probably mistyped" (fix round,
       2026-09-22). */
    if (!/^[0-9]{6}$/.test(code)) {
      out.className = 'msg warn';
      setMsg(out, 'Enter all six digits the app shows, then press Check.');
      input.focus();
      return;
    }
    const offset = await totpStepOffset(secret, code, Date.now());
    if (offset === undefined) {
      out.className = 'msg warn';
      setMsg(out, 'This browser cannot check codes itself (it needs HTTPS '
        + 'or localhost). The first sign-in will check it.');
    } else if (offset !== null && Math.abs(offset) <= TOTP_SERVER_DRIFT) {
      out.className = 'msg ok';
      setMsg(out, 'Matches. The app is set up correctly.');
    } else if (offset !== null) {
      out.className = 'msg warn';
      setMsg(out, totpSkewText(offset));
    } else {
      out.className = 'msg bad';
      setMsg(out, 'Does not match. The secret was probably mistyped: remove '
        + 'the entry from the app and scan the code again.');
    }
  });
  line.append(input, btn);
  row.append(line, out);
  row.appendChild(el('p', 'help', 'Checked on this computer. Nothing is sent, '
    + 'so a wrong code here counts toward no lockout.'));
  return row;
}

/** One-time credential block. Everything in it is ALSO selectable text:
 *  a copy button that fails (clipboard permissions, remote desktop) must
 *  never leave the secret unreachable. `opts.checkCode` (default true)
 *  adds the local code check; first run leaves it out because its sign-in
 *  step makes the same check. */
function renderOneTimeCreds(box, creds, opts) {
  const o = opts || {};
  clear(box);
  const card = el('div', 'card stack creds');
  card.appendChild(el('p', 'req', 'Shown once: not recoverable'));
  if (creds.otpauth_uri) {
    const qr = el('div', 'creds-qr');
    const canvas = el('canvas');
    canvas.setAttribute('role', 'img');
    canvas.setAttribute('aria-label', 'QR code of the enrolment link. Scan it '
      + 'with your authenticator app.');
    if (drawQr(canvas, creds.otpauth_uri)) {
      qr.appendChild(canvas);
      qr.appendChild(el('p', 'help', 'Scan this with your authenticator app. '
        + 'Cannot scan? Type or paste the secret below instead.'));
      card.appendChild(qr);
    }
  }
  if (creds.totp_secret) {
    const grouped = String(creds.totp_secret).replace(/(.{4})/g, '$1 ').trim();
    card.appendChild(credRow('Authenticator secret', creds.totp_secret, grouped,
                             'creds-secret'));
  }
  if (creds.password) card.appendChild(credRow('Password', creds.password));
  if (creds.otpauth_uri) {
    const more = el('details', 'creds-uri');
    more.appendChild(el('summary', null, 'Enrolment link (otpauth URI)'));
    more.appendChild(credRow('Enrolment link', creds.otpauth_uri));
    card.appendChild(more);
  }
  /* Not a secret, and it stays on the account card, but shown here too:
     this is the moment an administrator puts the new analyst on a case,
     and the response always carried it (ux16 no-user-id-for-share,
     2026-09-22). */
  if (creds.user_id) card.appendChild(credRow('Account id (not secret)', creds.user_id));
  if (creds.totp_secret && o.checkCode !== false) {
    card.appendChild(credCheckRow(creds.totp_secret));
  }
  if (creds.notice) card.appendChild(el('p', 'help', creds.notice));
  box.appendChild(card);
}

/* --- first run: the administrator's first sign-in -----------------------
 *
 * firstrun-oneclick-wipe (2026-09-22). The card showed a generated
 * password and a TOTP secret, and one "I saved them" click removed both
 * from the page with nothing checked. Anyone who had saved one and not
 * the other, or mistyped the secret into their phone, had an administrator
 * who could never sign in, a first-run door closed for good, and no
 * password reset: the way back was a shell on the server. Now the secrets
 * stay (in memory, and on screen unless hidden) until the account has
 * signed in with them on this card, or until the operator confirms a
 * warning that says what is lost; a reload asks first. The secrets never
 * leave this page's memory for storage of any kind.
 */
const FIRST_RUN = { creds: null, hidden: false };

function guardFirstRun(event) {
  event.preventDefault();
  event.returnValue = '';
}

function showFirstRunCreds(on) {
  FIRST_RUN.hidden = !on;
  if (on && FIRST_RUN.creds) {
    renderOneTimeCreds($('setup-creds'), FIRST_RUN.creds, { checkCode: false });
  } else {
    clear($('setup-creds'));
  }
  show($('setup-hidden-note'), !on);
  $('setup-hide').textContent = on ? 'Hide from screen' : 'Show them again';
}

function forgetFirstRunSecrets() {
  FIRST_RUN.creds = null;
  FIRST_RUN.hidden = false;
  clear($('setup-creds'));
  $('setup-verify-password').value = '';
  $('setup-verify-code').value = '';
  setMsg($('setup-verify-error'), '');
  show($('setup-verify-force'), false);
  show($('setup-skip-confirm'), false);
  show($('setup-done'), false);
  window.removeEventListener('beforeunload', guardFirstRun);
}

async function verifyFirstRun(force) {
  const c = FIRST_RUN.creds;
  if (!c) return;
  const errBox = $('setup-verify-error');
  setMsg(errBox, '');
  show($('setup-verify-force'), false);
  const password = $('setup-verify-password').value.trim();
  const code = $('setup-verify-code').value.replace(/\s+/g, '');
  if (!password || !/^[0-9]{6}$/.test(code)) {
    setMsg(errBox, 'Enter the password and the six-digit code your app shows.');
    return;
  }
  if (c.password && password !== c.password) {
    setMsg(errBox, 'That is not the password shown above. Use its Copy '
      + 'button, or check what you saved: it is the one you will need.');
    return;
  }
  /* Checked here first, so a mistyped secret costs no failed sign-in. */
  let matchedHere = false;
  if (!force) {
    const offset = await totpStepOffset(c.totp_secret, code, Date.now());
    if (offset === null) {
      setMsg(errBox, 'That code does not match the secret above. Nothing was '
        + 'sent to the server, so no failed sign-in was counted. The secret '
        + 'in your app is most likely mistyped: remove that entry, scan the '
        + 'code again and use the new code. If this computer\'s clock is '
        + 'wrong, this check can be wrong too.');
      show($('setup-verify-force'), true);
      return;
    }
    if (offset !== undefined && Math.abs(offset) > TOTP_SERVER_DRIFT) {
      /* The secret is right; a clock is not. Sent as it is, the server
         would refuse it and count a failure. */
      setMsg(errBox, totpSkewText(offset) + ' Nothing was sent, so no '
        + 'failed sign-in was counted.');
      show($('setup-verify-force'), true);
      return;
    }
    matchedHere = offset !== undefined;
  }
  const btn = $('setup-verify-submit');
  btn.disabled = true;
  try {
    await api('/auth/login', {
      method: 'POST',
      json: { email: c.email, password, totp_code: code },
    });
  } catch (err) {
    if (err instanceof ApiError && err.status === 401) {
      setMsg(errBox, matchedHere
        ? 'The server refused the sign-in although the code matches the '
          + 'secret on this computer, so the server\'s clock probably '
          + 'disagrees with this one. An operator can confirm it with '
          + 'python scripts/bootstrap.py totp-diagnose. The password and '
          + 'secret stay here.'
        : 'The server refused the sign-in. Check the code and try again; '
          + 'five failures lock the account for 15 minutes.');
    } else {
      inlineProblem(errBox, err);
    }
    return;
  } finally {
    btn.disabled = false;
  }
  /* Proven: this account signs in with what was shown. Only now do the
     secrets leave the page. */
  forgetFirstRunSecrets();
  if (!csrfCookie()) {
    banner('Signed in, but the browser refused the session cookie',
      'The password and authenticator work. This console is served over '
      + 'plain HTTP from an address that is not localhost, so the browser '
      + 'refused the Secure session cookies and holds no session. Serve it '
      + 'over HTTPS or reach it at localhost, then sign in.', 'warn');
    show($('login-form'), true);
    return;
  }
  /* The recovery codes the sign-in form mentions, issued now because a
     sign-in this fresh satisfies the step-up the route demands. */
  let out = null;
  try {
    out = await api('/auth/recovery-codes', { method: 'POST' });
  } catch (err) {
    if (!(err && err.handled)) {
      banner('Recovery codes were not issued',
        (err instanceof ApiError ? (err.detail || err.title) : String(err))
        + ' Generate them from Account (your name, top right).', 'warn');
    }
  }
  if (out && Array.isArray(out.codes)) {
    renderRecoveryCodes($('setup-codes-list'), out.codes, out.note);
    show($('setup-codes'), true);
    $('setup-enter').focus();
    return;
  }
  try { await startApp(); } catch (err) { fail(err); }
}

function initSetup() {
  initSession();
  $('setup-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    setMsg($('setup-error'), '');
    $('setup-submit').disabled = true;
    try {
      const creds = await api('/setup/first-admin', {
        method: 'POST',
        json: { email: $('setup-email').value.trim(),
                display_name: $('setup-name').value.trim() },
      });
      FIRST_RUN.creds = creds;
      window.addEventListener('beforeunload', guardFirstRun);
      show($('setup-form'), false);
      showFirstRunCreds(true);
      $('setup-verify-email').value = creds.email;
      show($('setup-done'), true);
      $('login-email').value = creds.email;
      /* The heading, not the password field: focusing the field would
         scroll the code and the secret out of view. */
      $('setup-done-title').focus();
    } catch (err) {
      $('setup-submit').disabled = false;
      if (err instanceof ApiError) setMsg($('setup-error'), err.detail || err.title);
      else setMsg($('setup-error'), 'The request did not complete.');
    }
  });
  $('setup-hide').addEventListener('click', () => showFirstRunCreds(FIRST_RUN.hidden));
  $('setup-verify').addEventListener('submit', (e) => {
    e.preventDefault();
    verifyFirstRun(false);
  });
  $('setup-verify-force').addEventListener('click', () => verifyFirstRun(true));
  $('setup-skip').addEventListener('click', () => {
    show($('setup-skip-confirm'), true);
    $('setup-skip-keep').focus();
  });
  $('setup-skip-keep').addEventListener('click', () => {
    show($('setup-skip-confirm'), false);
    $('setup-skip').focus();
  });
  $('setup-skip-discard').addEventListener('click', () => {
    forgetFirstRunSecrets();
    show($('login-form'), true);
    $('login-password').focus();
  });
  $('setup-enter').addEventListener('click', async () => {
    clear($('setup-codes-list'));      // the codes leave with the card
    show($('setup-codes'), false);
    try { await startApp(); } catch (err) { fail(err); }
  });
}

boot();

