"""What a similarity answer costs to explain (F6.3, embeddings,
2026-09-25).

About 64 ms of shared-terms work per hit was measured at the 8,000 and
20,000 character caps, spent on every candidate including those
the bands then dropped: about 13 s of CPU for one request of 200 hits. The
query side is now worked out once per request, every written word is
normalised once per process, and similar wording stops at the first hit
under the floor (hits come nearest first).

Pure: no database.
"""
from __future__ import annotations

from noctornal_api import embedders as E
from noctornal_api.http.routers import similarity


def _hits(similarities):
    return [{"id": str(i), "similarity": s, "text": f"hit number {i} about light seals "
             "and rangefinder cameras from the same warehouse"}
            for i, s in enumerate(similarities)]


class _Counting(E.SharedQuery):
    made = 0
    compared = 0

    def __init__(self, text):
        type(self).made += 1
        super().__init__(text)

    def against(self, hit):
        type(self).compared += 1
        return super().against(hit)


def test_similar_wording_explains_nothing_under_the_floor(monkeypatch):
    monkeypatch.setattr(E, "SharedQuery", _Counting)
    _Counting.made = _Counting.compared = 0
    hits = _hits([0.93, 0.61, 0.31, 0.19, 0.18] + [0.1] * 195)
    out = similarity._explained(E.ROLE_WORDING, "light seals and rangefinder cameras "
                                "from the same warehouse", hits, limit=200)
    assert _Counting.made == 1
    assert _Counting.compared == 3
    assert [h["band"] for h in out][:2] == ["near duplicate", "much of the same wording"]
    assert all("text" not in h for h in out)


def test_similar_meaning_explains_at_most_the_limit(monkeypatch):
    monkeypatch.setattr(E, "SharedQuery", _Counting)
    _Counting.made = _Counting.compared = 0
    out = similarity._explained(E.ROLE_MEANING, "which posts are about shutters",
                                _hits([0.4] * 60), limit=20)
    assert len(out) == 20 and _Counting.compared == 20 and _Counting.made == 1
    assert [h["position"] for h in out] == list(range(1, 21))


def test_the_query_side_is_not_rebuilt_per_hit():
    query = E.SharedQuery("camera.keeper@example.org sells the rangefinder listing")
    first = query.against("Write to camera.keeper@example.org about the rangefinder "
                          "listing today")
    assert first.selectors and first.phrases
    assert query.against("nothing in common here at all") == E.SharedTerms()
