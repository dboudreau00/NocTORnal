/* ForceAtlas2 with Barnes-Hut, in a worker (docs/02, enhancement U1).
 *
 * The main-thread simulation this replaces is O(n^2) in repulsion with a
 * grid approximation bolted on, and it runs inside the render loop -- so on
 * a case of any size the whole interface stops responding while the graph
 * settles. Phase 3 made that worse by giving analysts a reason to load
 * bigger graphs.
 *
 * docs/02 specifies "ForceAtlas2 with Barnes-Hut in a worker", and this is
 * that, written by hand rather than pulled from graphology. The reason is
 * the CSP: the UI ships under `script-src 'self'` with no bundler and no
 * inline script, so a npm dependency would mean adopting a build step --
 * a real decision (docs/14 U1) that should be taken deliberately, not
 * smuggled in as a side effect of wanting a layout. A worker is a
 * same-origin script file, so it needs neither.
 *
 * Barnes-Hut is the part that matters: approximating a distant cluster of
 * nodes by its centre of mass turns repulsion from O(n^2) into O(n log n).
 * At 2,000 nodes that is the difference between four million force
 * calculations per tick and about twenty thousand.
 *
 * ForceAtlas2 specifics, following Jacomy et al. (2014):
 *   - a node's MASS is its degree + 1, so hubs repel more strongly and
 *     stop being buried inside their own neighbourhoods;
 *   - attraction is linear in distance, repulsion is inverse-linear;
 *   - a global swing/traction ratio adapts the step size, which is what
 *     stops the layout oscillating instead of converging.
 */

var THETA = 1.2;          // Barnes-Hut opening angle. Higher = faster, cruder.
var K_REPULSION = 120;
var K_GRAVITY = 0.08;
var TOLERANCE = 0.12;     // speed tuning; higher tolerates more swinging
var MAX_DISPLACE = 12;    // per-iteration cap, so one bad tick cannot explode
var EPSILON = 0.01;

/* --- quadtree ---------------------------------------------------------- */

function Quad(x0, y0, size) {
  this.x0 = x0; this.y0 = y0; this.size = size;
  this.mass = 0; this.cx = 0; this.cy = 0;
  this.body = null;       // a single node, while this quad stays a leaf
  this.kids = null;
}

Quad.prototype.insert = function (n) {
  // Running centre of mass, updated on the way down.
  var m = this.mass + n.mass;
  this.cx = (this.cx * this.mass + n.x * n.mass) / m;
  this.cy = (this.cy * this.mass + n.y * n.mass) / m;
  this.mass = m;

  if (this.kids === null && this.body === null) {
    this.body = n;
    return;
  }
  if (this.kids === null) {
    // A leaf that now holds two bodies has to split. Guard on size: two
    // nodes at identical coordinates would otherwise subdivide forever.
    var existing = this.body;
    this.body = null;
    this.kids = [];
    var half = this.size / 2;
    for (var i = 0; i < 4; i += 1) {
      this.kids.push(new Quad(
        this.x0 + (i % 2) * half,
        this.y0 + (i < 2 ? 0 : 1) * half,
        half
      ));
    }
    if (this.size > 0.5) this.place(existing);
  }
  this.place(n);
};

Quad.prototype.place = function (n) {
  var half = this.size / 2;
  var i = (n.x >= this.x0 + half ? 1 : 0) + (n.y >= this.y0 + half ? 2 : 0);
  this.kids[i].insert(n);
};

/** Repulsion from this quad onto n, opening the node only when it is close
 *  enough that its internal structure matters (the Barnes-Hut criterion). */
Quad.prototype.repel = function (n) {
  if (this.mass === 0) return;
  if (this.body === n && this.kids === null) return;

  var dx = this.cx - n.x, dy = this.cy - n.y;
  var dist = Math.sqrt(dx * dx + dy * dy) + EPSILON;

  if (this.kids === null || (this.size / dist) < THETA) {
    var f = -K_REPULSION * n.mass * this.mass / (dist * dist);
    n.fx += dx * f;
    n.fy += dy * f;
    return;
  }
  for (var i = 0; i < 4; i += 1) this.kids[i].repel(n);
};

/* --- the simulation ---------------------------------------------------- */

var nodes = [];
var links = [];
var running = false;
var iteration = 0;
var maxIterations = 400;

function buildTree() {
  var min = Infinity, max = -Infinity;
  for (var i = 0; i < nodes.length; i += 1) {
    var n = nodes[i];
    if (n.x < min) min = n.x;
    if (n.y < min) min = n.y;
    if (n.x > max) max = n.x;
    if (n.y > max) max = n.y;
  }
  if (!isFinite(min)) { min = -1; max = 1; }
  var size = Math.max(max - min, 1) * 1.2;
  var root = new Quad(min - size * 0.1, min - size * 0.1, size);
  for (var j = 0; j < nodes.length; j += 1) root.insert(nodes[j]);
  return root;
}

function tick() {
  var i, n;
  for (i = 0; i < nodes.length; i += 1) {
    n = nodes[i];
    n.fx = 0;
    n.fy = 0;
  }

  var root = buildTree();
  for (i = 0; i < nodes.length; i += 1) root.repel(nodes[i]);

  // Attraction along edges: linear in distance, so long edges pull hard.
  for (i = 0; i < links.length; i += 1) {
    var a = nodes[links[i].a], b = nodes[links[i].b];
    var dx = b.x - a.x, dy = b.y - a.y;
    var w = links[i].w;
    a.fx += dx * w; a.fy += dy * w;
    b.fx -= dx * w; b.fy -= dy * w;
  }

  // Gravity, so disconnected components do not drift to infinity. Scaled by
  // mass for the same reason repulsion is: otherwise hubs wander.
  for (i = 0; i < nodes.length; i += 1) {
    n = nodes[i];
    var d = Math.sqrt(n.x * n.x + n.y * n.y) + EPSILON;
    n.fx -= K_GRAVITY * n.mass * n.x / d;
    n.fy -= K_GRAVITY * n.mass * n.y / d;
  }

  // Adaptive speed (Jacomy et al.). SWING is how much a node is changing
  // direction, TRACTION how much it is making real progress; the ratio is
  // what keeps the layout from oscillating forever around its solution.
  var swing = 0, traction = 0;
  for (i = 0; i < nodes.length; i += 1) {
    n = nodes[i];
    var sdx = n.fx - n.pfx, sdy = n.fy - n.pfy;
    var s = Math.sqrt(sdx * sdx + sdy * sdy);
    var t = Math.sqrt((n.fx + n.pfx) * (n.fx + n.pfx) +
                      (n.fy + n.pfy) * (n.fy + n.pfy)) / 2;
    n.swing = s;
    swing += n.mass * s;
    traction += n.mass * t;
  }
  var speed = swing > 0 ? TOLERANCE * traction / swing : 1;
  speed = Math.min(speed, 10);

  var moved = 0;
  for (i = 0; i < nodes.length; i += 1) {
    n = nodes[i];
    // A pinned node is the analyst's decision and the simulation does not
    // get to overrule it -- that is the entire point of pinning.
    if (n.pinned) { n.pfx = n.fx; n.pfy = n.fy; continue; }
    var factor = speed / (1 + Math.sqrt(speed * n.swing));
    var mx = n.fx * factor, my = n.fy * factor;
    var mag = Math.sqrt(mx * mx + my * my);
    if (mag > MAX_DISPLACE) { mx = mx / mag * MAX_DISPLACE; my = my / mag * MAX_DISPLACE; }
    n.x += mx;
    n.y += my;
    moved += Math.abs(mx) + Math.abs(my);
    n.pfx = n.fx;
    n.pfy = n.fy;
  }

  // Convergence has to be measured RELATIVE to the layout's own size. An
  // absolute "nodes moved less than N pixels" test never fires, because
  // ForceAtlas2 keeps expanding until repulsion and attraction balance --
  // a graph twice as wide moves twice as far per iteration while being no
  // less converged. What matters is movement as a fraction of the spread.
  var radius = 0;
  for (i = 0; i < nodes.length; i += 1) {
    n = nodes[i];
    radius += Math.sqrt(n.x * n.x + n.y * n.y);
  }
  radius = Math.max(1, radius / Math.max(1, nodes.length));
  return (moved / Math.max(1, nodes.length)) / radius;
}

function post(done, settled) {
  var out = new Float32Array(nodes.length * 2);
  for (var i = 0; i < nodes.length; i += 1) {
    out[i * 2] = nodes[i].x;
    out[i * 2 + 1] = nodes[i].y;
  }
  self.postMessage({
    type: done ? 'done' : 'progress',
    iteration: iteration,
    maxIterations: maxIterations,
    settled: !!settled,
    positions: out.buffer,
  }, [out.buffer]);
}

/* Progress posts are RATE-LIMITED rather than sent every batch.
 *
 * Posting after each batch floods the main thread: 800 iterations in
 * batches of 12 is ~67 messages inside a second, and servicing that many
 * message events starves everything else. The interface then stalls just
 * as badly as it did when the maths ran in the page -- the work moved, but
 * the blocking followed it. Measured on a 400-node case, that was ~990ms
 * of main-thread lag for a layout the worker finished in 1s.
 *
 * The intermediate frames are only a settling animation, not something
 * anyone reads, so a post every ~100ms looks identical and costs a tenth
 * of the traffic. */
var POST_INTERVAL_MS = 100;
var lastPost = 0;

function run() {
  if (!running) return;
  // A slice of iterations per turn: enough to make progress, short enough
  // that a stop() lands promptly.
  var batch = nodes.length > 1500 ? 3 : 12;
  var drift = 0;
  for (var i = 0; i < batch && iteration < maxIterations; i += 1) {
    drift = tick();
    iteration += 1;
  }
  // Relative drift: nodes moving less than 0.15% of the layout's own
  // radius per iteration are, for a picture, standing still.
  var settled = drift < 0.0015 && iteration > 60;
  if (iteration >= maxIterations || settled) {
    running = false;
    post(true, settled);
    return;
  }
  var now = Date.now();
  if (now - lastPost >= POST_INTERVAL_MS) {
    lastPost = now;
    post(false, false);
  }
  setTimeout(run, 0);
}

self.onmessage = function (e) {
  var msg = e.data;
  if (msg.type === 'start') {
    nodes = msg.nodes.map(function (n) {
      return {
        x: n.x, y: n.y, mass: n.degree + 1, pinned: !!n.pinned,
        fx: 0, fy: 0, pfx: 0, pfy: 0, swing: 0,
      };
    });
    links = msg.links;
    maxIterations = msg.iterations || 400;
    iteration = 0;
    running = true;
    run();
  } else if (msg.type === 'stop') {
    running = false;
  }
};
