"""The theme contract, finally enforced.

theme.css has claimed since it was written that "app.css names no colour
that is not a token defined here", and that test_ui_invariants held it to
that rule. The second half was false. There was no such test, and by the
time anyone looked, app.css had accumulated nine raw rgba() literals and
app.js twelve hard-coded hexes -- four of the rgba values duplicating
tokens that theme.css already defined and that consequently nothing used.

The failure mode is worth naming, because it is this codebase's signature
shape: swapping theme.css did NOT fail. It produced a console that was
mostly the new theme with fragments of the old one left in the chips, the
banners, the live indicator and every canvas. A wrong answer that looks
like a right one.

These tests are pure -- no database, no browser. They read the shipped
static assets, exactly like test_ui_invariants.
"""
from __future__ import annotations

import colorsys
import itertools
import math
import re
from pathlib import Path

import pytest

STATIC = (Path(__file__).resolve().parents[1]
          / "src" / "noctornal_api" / "http" / "static")

APP_CSS = STATIC / "app.css"
THEME_CSS = STATIC / "theme.css"
APP_JS = STATIC / "app.js"


def _strip_comments(css: str) -> str:
    return re.sub(r"/\*.*?\*/", "", css, flags=re.S)


def _app_css() -> str:
    return _strip_comments(APP_CSS.read_text(encoding="utf-8"))


def _theme_css() -> str:
    return THEME_CSS.read_text(encoding="utf-8")


#: Any literal way to name a colour in CSS. Named colours are deliberately
#: NOT matched by a generic word regex -- that produces false positives on
#: every property value -- so the few that matter are listed instead.
_COLOUR_LITERAL = re.compile(
    r"#[0-9a-fA-F]{3,8}\b"
    r"|\brgba?\s*\("
    r"|\bhsla?\s*\("
    # (?<![-\w]) / (?![-\w]) rather than \b: \b happily matches inside
    # `white-space`, which produced sixteen false positives the first time
    # this ran.
    r"|(?<![-\w])(?:white|black|red|green|blue|gray|grey|silver|orange"
    r"|yellow|purple|navy|teal|olive|maroon|aqua|fuchsia|lime)(?![-\w])")


# ---------------------------------------------------------------------------
# The contract itself
# ---------------------------------------------------------------------------

def test_app_css_names_no_colour_that_is_not_a_token():
    """The rule theme.css states, checked for the first time.

    Every colour in the console goes through a var() defined by the theme.
    A literal here is not a style mistake, it is a REGRESSION IN THE
    CONTRACT: it is a colour that will survive a theme swap and leave a
    fragment of the previous palette behind.
    """
    offenders = []
    for i, line in enumerate(_app_css().splitlines(), 1):
        if _COLOUR_LITERAL.search(line):
            offenders.append(f"app.css:{i}: {line.strip()}")
    assert not offenders, (
        "app.css names colours directly instead of through a theme token.\n"
        "Each of these survives a theme swap:\n  " + "\n  ".join(offenders))


def test_the_canvas_painters_carry_no_hard_coded_palette():
    """The sociogram, the timeline strip and the metric chart draw on a
    <canvas>, so they cannot use CSS and must read tokens at runtime.

    They used to do that AND carry a literal fallback:

        tlCtx.fillStyle = PAINT.surface2 || '#2D2030';

    `cssVar()` returns '' for a property that does not resolve, and '' is
    falsy, so a renamed or deleted token did not raise -- it silently
    painted the OLD theme onto the canvas while the DOM around it painted
    the new one. The fallback has to be absent for the failure to be
    visible.
    """
    js = APP_JS.read_text(encoding="utf-8")
    hexes = re.findall(r"""['"]#[0-9a-fA-F]{3,8}['"]""", js)
    assert not hexes, (
        "app.js hard-codes palette values: " + ", ".join(sorted(set(hexes)))
        + " -- these shadow theme tokens and defeat a theme swap.")


def test_every_token_app_css_uses_is_defined_by_the_theme():
    """A var() with no definition falls back to nothing, which renders as
    `inherit` or as transparent depending on the property -- both of which
    look like a styling bug rather than a missing token.
    """
    used = set(re.findall(r"var\(\s*(--[a-zA-Z0-9-]+)", _app_css()))
    defined = set(re.findall(r"^\s*(--[a-zA-Z0-9-]+)\s*:", _theme_css(),
                             flags=re.M))
    # app.css legitimately defines one local custom property of its own:
    # the node-hue carriers set --hue for their subtree.
    # NOT anchored to line start: the node-hue carriers are written
    # `.hue-actor-group { --hue: var(--actor-group); }` on one line.
    local = set(re.findall(r"(--[a-zA-Z0-9-]+)\s*:", _app_css()))
    missing = used - defined - local
    assert not missing, (
        "app.css uses tokens the theme does not define: " + ", ".join(sorted(missing)))


def test_the_theme_defines_no_token_that_nothing_uses():
    """A dead token is how the contract rots.

    --alert-soft and --danger-soft were both defined by the theme and used
    by nothing, while app.css hand-inlined the same two rgba values four
    times. The token existing did not help, because nothing pointed at it.
    """
    theme_body = _strip_comments(_theme_css())
    defined = set(re.findall(r"^\s*(--[a-zA-Z0-9-]+)\s*:", theme_body,
                             flags=re.M))
    consumers = _app_css() + theme_body + APP_JS.read_text(encoding="utf-8")
    dead = {t for t in defined
            if consumers.count(f"var({t})") == 0
            and f"'{t}'" not in consumers
            and f'"{t}"' not in consumers
            # The hue tokens are read by JS through string concatenation:
            # cssVar('--' + h). Their names never appear whole in source.
            and t.lstrip("-") not in {
                "actor-persona", "actor-person", "actor-group",
                "artefact-infra", "artefact-finance", "artefact-malware",
                "context"}}
    assert not dead, (
        "theme.css defines tokens nothing consumes: " + ", ".join(sorted(dead))
        + " -- either use them or delete them; a dead token invites the "
          "next person to hand-inline the value instead.")


def test_the_radius_scale_is_the_only_source_of_roundness():
    """Six ad-hoc radii between 3px and 10px is what made the first cut
    look a decade old, and it is not fixable by a theme swap while the
    numbers live in app.css.
    """
    raw = []
    for i, line in enumerate(_app_css().splitlines(), 1):
        m = re.search(r"border-radius:\s*([^;]+);", line)
        if not m:
            continue
        value = m.group(1).strip()
        if "var(" in value or value == "50%":
            continue
        raw.append(f"app.css:{i}: border-radius: {value}")
    assert not raw, (
        "border-radius is set from a literal rather than the scale:\n  "
        + "\n  ".join(raw))


# ---------------------------------------------------------------------------
# The properties theme.css declares it may NOT change
# ---------------------------------------------------------------------------

def _tokens() -> dict[str, str]:
    body = _strip_comments(_theme_css())
    return {m.group(1): m.group(2).strip()
            for m in re.finditer(r"(--[a-zA-Z0-9-]+)\s*:\s*(#[0-9a-fA-F]{6})\s*;",
                                 body)}


def _rgb(h: str) -> tuple[int, int, int]:
    h = h.lstrip("#")
    return tuple(int(h[i:i + 2], 16) for i in (0, 2, 4))


def _lin(v: float) -> float:
    v /= 255.0
    return v / 12.92 if v <= 0.04045 else ((v + 0.055) / 1.055) ** 2.4


def _lum(h: str) -> float:
    r, g, b = _rgb(h)
    return 0.2126 * _lin(r) + 0.7152 * _lin(g) + 0.0722 * _lin(b)


def _ratio(a: str, b: str) -> float:
    la, lb = _lum(a), _lum(b)
    return (max(la, lb) + 0.05) / (min(la, lb) + 0.05)


def _hue(h: str) -> float:
    r, g, b = (v / 255 for v in _rgb(h))
    return colorsys.rgb_to_hls(r, g, b)[0] * 360


def _hue_gap(a: str, b: str) -> float:
    d = abs(_hue(a) - _hue(b)) % 360
    return min(d, 360 - d)


def _lab(h: str) -> tuple[float, float, float]:
    r, g, b = (_lin(v) for v in _rgb(h))
    x = r * 0.4124564 + g * 0.3575761 + b * 0.1804375
    y = r * 0.2126729 + g * 0.7151522 + b * 0.0721750
    z = r * 0.0193339 + g * 0.1191920 + b * 0.9503041

    def f(t: float) -> float:
        return t ** (1 / 3) if t > 216 / 24389 else (841 / 108) * t + 4 / 29

    fx, fy, fz = f(x / 0.95047), f(y / 1.0), f(z / 1.08883)
    return 116 * fy - 16, 500 * (fx - fy), 200 * (fy - fz)


def _delta_e(a: str, b: str) -> float:
    """CIE76. Coarser than CIEDE2000 but monotone with it for colours this
    far apart, and it keeps this file free of a 40-line formula."""
    la, aa, ba = _lab(a)
    lb, ab, bb = _lab(b)
    return math.sqrt((la - lb) ** 2 + (aa - ab) ** 2 + (ba - bb) ** 2)


NODE_TOKENS = ["--actor-persona", "--actor-person", "--actor-group",
               "--artefact-infra", "--artefact-finance",
               "--artefact-malware", "--context"]


def test_accent_and_alert_never_converge():
    """The metric-history chart draws its trend line in --accent and marks
    APPROXIMATE runs in --alert on the same canvas. A theme that lets these
    two drift together does not just look worse, it erases the distinction
    between a measured value and an estimated one.
    """
    t = _tokens()
    gap = _hue_gap(t["--accent"], t["--alert"])
    assert gap >= 60, (
        f"--accent and --alert are only {gap:.1f} degrees apart; the metric "
        "chart uses both to mean different things.")


def test_the_node_hues_stay_mutually_distinguishable():
    """Seven identification colours drawn as small dots on --void. If two
    of them converge, an analyst reads one entity type as another.

    The threshold is deliberately above the value the FIRST cut shipped
    (its closest pair was actor-persona vs context) so that this cannot
    regress quietly back to where it started.
    """
    t = _tokens()
    pairs = [(a, b, _delta_e(t[a], t[b]))
             for a, b in itertools.combinations(NODE_TOKENS, 2)]
    worst = min(pairs, key=lambda p: p[2])
    assert worst[2] >= 20.0, (
        f"{worst[0]} and {worst[1]} are only dE {worst[2]:.1f} apart on the "
        "canvas; they are two different entity types.")


def test_no_node_hue_can_be_mistaken_for_an_edge_sign():
    """Node fill and edge colour share the canvas. A node type that reads
    as "vouch green" or "accusation red" is worse than an ugly one.
    """
    t = _tokens()
    bad = []
    for n in NODE_TOKENS:
        for s in ("--sign-positive", "--sign-negative"):
            d = _delta_e(t[n], t[s])
            if d < 20.0:
                bad.append(f"{n} vs {s}: dE {d:.1f}")
    assert not bad, "node hues collide with the sign colours: " + "; ".join(bad)


@pytest.mark.parametrize("token,floor", [
    ("--text-primary", 7.0),
    ("--text-secondary", 4.5),
    ("--text-tertiary", 4.5),
])
def test_every_text_tier_is_readable_on_the_app_ground(token, floor):
    """--text-tertiary carried real labels at 3.79:1 for the whole of the
    first cut. It is a text tier; it has to clear the text threshold.
    """
    t = _tokens()
    r = _ratio(t[token], t["--surface-0"])
    assert r >= floor, f"{token} is {r:.2f}:1 on --surface-0, needs {floor}:1"


@pytest.mark.parametrize("token", [
    "--sign-positive", "--sign-negative", "--alert", "--danger", "--accent",
])
def test_every_semantic_colour_is_readable_as_text(token):
    """app.css uses all of these as `color:`, not merely as borders, so the
    3:1 UI-component threshold is not the one that applies. The old
    --danger sat at 3.70:1 while being the word that says a thing will be
    destroyed.
    """
    t = _tokens()
    r = _ratio(t[token], t["--surface-0"])
    assert r >= 4.5, f"{token} is {r:.2f}:1 on --surface-0, used as text"


def test_confidence_is_encoded_as_opacity_and_stays_legible():
    """Confidence is opacity by design (docs/06) -- never hue. That rule is
    fine; the trap is stacking it on top of an already-dim COLOUR, which
    is how `.chip.conf-LOW` reached 1.83:1.

    So: the floor has to keep the quietest step readable on its own.
    """
    theme = _strip_comments(_theme_css())
    low = float(re.search(r"--conf-low:\s*([0-9.]+)", theme).group(1))
    mod = float(re.search(r"--conf-moderate:\s*([0-9.]+)", theme).group(1))
    t = _tokens()

    # Composite --text-primary at the LOW alpha over the card it sits on.
    card = _rgb(t["--surface-1"])
    fg = _rgb(t["--text-primary"])
    mixed = "#%02X%02X%02X" % tuple(
        round(low * fg[i] + (1 - low) * card[i]) for i in range(3))
    r = _ratio(mixed, t["--surface-1"])
    assert r >= 4.5, (
        f"--conf-low ({low}) composites --text-primary to {r:.2f}:1; the "
        "lowest confidence step is still text somebody has to read.")
    assert low < mod < 1.0, "the three confidence steps must stay ordered"


def test_no_element_dims_a_colour_that_is_already_dim():
    """The specific bug, kept from coming back.

    `.conf-LOW` applies an opacity. Any rule that ALSO sets a dim colour on
    an element carrying that class composites twice. This checks the two
    that did it, by name, because a general check would need a cascade
    resolver.
    """
    css = _app_css()
    for sel in (".chip.conf-LOW", ".st-none"):
        m = re.search(re.escape(sel) + r"\s*\{([^}]*)\}", css)
        assert m, f"{sel} disappeared -- update this test with it"
        body = m.group(1)
        assert "--text-tertiary" not in body or "opacity" not in body, (
            f"{sel} sets both a dim colour and an opacity: {body.strip()}")
