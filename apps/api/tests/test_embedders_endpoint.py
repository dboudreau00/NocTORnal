"""The model endpoint's one call site (F6.2, 2026-09-24).

Through egress.route_for and pinned_http only (docs/20 section 9, the
per-consumer table): the route is the integration route `embeddings`,
declared with the configured endpoint and tagged embed:<uuid>; the answer
is validated item by item; errors are mapped by type and status and never
by message; and a model server's 4xx body, which can echo the input text,
appears nowhere.

No database, and no network beyond a stub on loopback.
"""
from __future__ import annotations

import logging
import math
import time
import uuid

import pytest

from embedding_stub import NoRoutes, StubModel, meaning_env
from noctornal_api import embedders as E


@pytest.fixture(autouse=True)
def _development(monkeypatch):
    for name in ("NOCTORNAL_ENV", "NOCTORNAL_EGRESS_PROXY_URL",
                 "NOCTORNAL_EGRESS_INTERNAL_CIDRS"):
        monkeypatch.delenv(name, raising=False)


@pytest.fixture
def stub():
    s = StubModel(dims=384)
    yield s
    s.close()


def _settings(stub, **overrides) -> E.MeaningSettings:
    cfg = E.configured(meaning_env(stub, **overrides))
    assert cfg.meaning_settings is not None, cfg.problems
    return cfg.meaning_settings


def _endpoint(settings, tag=None) -> E.Endpoint:
    return E.open_endpoint(settings, conn=NoRoutes(), context_id=tag)


def test_the_request_is_the_openai_shape_with_prefixes_and_truncation(stub):
    s = _settings(stub, **{E.DOCUMENT_PREFIX_ENV: "passage: ", E.MAX_CHARS_ENV: "200"})
    emb = E.EndpointEmbedder(s)
    out = emb.embed_via(_endpoint(s), ["short text", "x" * 500])
    req = stub.requests[-1]
    assert req["path"] == "/v1/embeddings"
    body = req["body"]
    assert body["model"] == stub.model and body["encoding_format"] == "float"
    assert "dimensions" not in body
    assert body["input"][0] == "passage: short text"
    assert body["input"][1] == "passage: " + "x" * 200
    assert out[1].truncated_chars == 300 and out[1].input_chars == 200
    assert all(o.status == "EMBEDDED" and len(o.vector) == 768 for o in out)
    assert req["headers"].get("User-Agent") == E.USER_AGENT


def test_the_query_prefix_and_dimensions_are_sent_when_configured(stub):
    s = _settings(stub, **{E.QUERY_PREFIX_ENV: "query: ", E.DIMENSIONS_ENV: "384"})
    E.EndpointEmbedder(s).embed_via(_endpoint(s), ["find this"], purpose="query")
    body = stub.requests[-1]["body"]
    assert body["input"] == ["query: find this"] and body["dimensions"] == 384


def test_the_bearer_header_goes_only_with_a_key(stub):
    s = _settings(stub)
    E.EndpointEmbedder(s).embed_via(_endpoint(s), ["a text"])
    assert "Authorization" not in stub.requests[-1]["headers"]
    s = _settings(stub, **{E.KEY_ENV: "sk-test-secret-value-123"})
    E.EndpointEmbedder(s).embed_via(_endpoint(s), ["a text"])
    assert stub.requests[-1]["headers"]["Authorization"] == "Bearer sk-test-secret-value-123"
    assert "sk-test" not in repr(s)


def test_an_empty_text_is_not_sent(stub):
    s = _settings(stub)
    out = E.EndpointEmbedder(s).embed_via(_endpoint(s), ["  ", "real text"])
    assert out[0].status == "EMPTY" and out[1].status == "EMBEDDED"
    assert stub.requests[-1]["body"]["input"] == ["real text"]


def test_the_route_is_tagged_with_the_embed_context(stub):
    s = _settings(stub)
    tag = uuid.uuid4()
    endpoint = _endpoint(s, tag)
    assert endpoint.tag == f"embed:{tag}"
    assert endpoint.route.context == f"embed:{tag}"
    assert endpoint.route.route_id == "integration:embeddings"


@pytest.mark.parametrize("mode,reason", [
    ("count", "endpoint_bad_response"), ("dup_index", "endpoint_bad_response"),
    ("nan", "endpoint_bad_response"), ("mixed", "endpoint_bad_response"),
    ("long", "dimension_unsupported"), ("notjson", "endpoint_bad_response"),
    # 2026-09-25: a 400-digit integer (OverflowError) and a
    # body nested 100,000 deep (RecursionError) escaped as Python errors and
    # wedged the pass; a string, a list and a zero vector are values too.
    ("bigint", "endpoint_bad_response"), ("deep", "endpoint_bad_response"),
    ("zeros", "endpoint_bad_response"), ("text_value", "endpoint_bad_response"),
    ("nested_value", "endpoint_bad_response"),
])
def test_an_answer_that_does_not_fit_the_request_fails_the_batch(stub, mode, reason):
    stub.mode = mode
    s = _settings(stub)
    with pytest.raises(E.EndpointError) as caught:
        E.EndpointEmbedder(s).embed_via(_endpoint(s), ["one text", "another text"])
    assert caught.value.reason == reason


def test_a_changed_dimension_is_refused(stub):
    s = _settings(stub)
    with pytest.raises(E.EndpointError) as caught:
        E.EndpointEmbedder(s).embed_via(_endpoint(s), ["text"], expect_dims=512)
    assert caught.value.reason == "dimension_changed"


def test_a_redirect_is_refused_and_not_followed(stub):
    stub.mode = "redirect"
    s = _settings(stub)
    with pytest.raises(E.EndpointError) as caught:
        E.EndpointEmbedder(s).embed_via(_endpoint(s), ["text"])
    assert caught.value.reason == "redirect_refused"
    assert len(stub.requests) == 1


def test_an_oversize_answer_is_refused(stub):
    stub.mode = "oversize"
    s = _settings(stub)
    with pytest.raises(E.EndpointError) as caught:
        E.EndpointEmbedder(s).embed_via(_endpoint(s), ["text"])
    assert caught.value.reason == "endpoint_bad_response"


def test_a_slow_drip_ends_inside_the_deadline(stub):
    stub.mode = "drip"
    s = _settings(stub, **{E.TIMEOUT_ENV: "2"})
    started = time.monotonic()
    with pytest.raises(E.EndpointError) as caught:
        E.EndpointEmbedder(s).embed_via(_endpoint(s), ["text"])
    assert caught.value.reason == "endpoint_unavailable"
    assert time.monotonic() - started < 6


@pytest.mark.parametrize("status,reason", [(400, "endpoint_rejected_400"),
                                           (401, "endpoint_rejected_401"),
                                           (500, "endpoint_unavailable"),
                                           (503, "endpoint_unavailable")])
def test_statuses_map_to_codes_and_the_echo_appears_nowhere(stub, caplog, status, reason):
    """A 4xx body echoing the input is never read: not in the error, not in
    a log record."""
    stub.mode, stub.status = "status", status
    s = _settings(stub)
    secret_text = "UNIQUE-CASE-TEXT-7f3a9c"
    with caplog.at_level(logging.DEBUG):
        with pytest.raises(E.EndpointError) as caught:
            E.EndpointEmbedder(s).embed_via(_endpoint(s), [secret_text])
    assert caught.value.reason == reason and caught.value.http_status == status
    assert secret_text not in str(caught.value)
    assert secret_text not in repr(caught.value.__dict__)
    assert all(secret_text not in r.getMessage() for r in caplog.records)


def test_an_unreachable_endpoint_is_unavailable():
    s = E.configured({E.URL_ENV: "http://127.0.0.1:9/v1", E.MODEL_ENV: "m",
                      E.CEILING_ENV: "AMBER", E.TIMEOUT_ENV: "2"}).meaning_settings
    with pytest.raises(E.EndpointError) as caught:
        E.EndpointEmbedder(s).embed_via(_endpoint(s), ["text"])
    assert caught.value.reason == "endpoint_unavailable"
    assert caught.value.request_sent is False


def test_zero_padding_keeps_cosine_between_padded_answers(stub):
    s = _settings(stub)
    a, b = E.EndpointEmbedder(s).embed_via(_endpoint(s), ["the rangefinder listing",
                                                         "the rangefinder list"])
    raw_a, raw_b = stub.vector("the rangefinder listing"), stub.vector("the rangefinder list")
    raw = sum(x * y for x, y in zip(raw_a, raw_b, strict=True)) / (
        math.sqrt(sum(x * x for x in raw_a)) * math.sqrt(sum(y * y for y in raw_b)))
    got = sum(x * y for x, y in zip(a.vector, b.vector, strict=True))
    assert math.isclose(got, raw, abs_tol=1e-9)


def test_the_endpoint_module_opens_no_socket_of_its_own():
    """The single-exit rule (docs/20 section 9): only pinned_http."""
    import ast
    import inspect
    tree = ast.parse(inspect.getsource(E))
    names = {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)} | {
        n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)}
    for forbidden in ("socket", "urlopen", "HTTPConnection", "create_connection",
                      "getaddrinfo", "requests", "httpx"):
        assert forbidden not in names, forbidden


# ---------------------------------------------------------------------------
# Hostile answers, parsed directly (2026-09-25)
# ---------------------------------------------------------------------------

def _answer(*vectors) -> dict:
    return {"data": [{"index": i, "embedding": v} for i, v in enumerate(vectors)]}


def _nested(depth: int):
    value: list = []
    for _ in range(depth):
        value = [value]
    return value


@pytest.mark.parametrize("answer", [
    None, [], "text", 7, {"data": "x"}, {"data": {"0": [1.0]}}, {"data": [None]},
    {"data": [{"index": "0", "embedding": [1.0]}]},
    {"data": [{"index": True, "embedding": [1.0]}]},
    {"data": [{"index": 0, "embedding": "1.0"}]},
    {"data": [{"index": 0, "embedding": {"0": 1.0}}]},
    _answer([10 ** 400, 1.0]), _answer([-(10 ** 400)]), _answer([True, 1.0]),
    _answer([None, 1.0]), _answer([float("inf")]), _answer([float("-inf"), 1.0]),
    _answer([0.0, 0.0, 0.0]), _answer([0, 0]), _answer([[1.0], 2.0]),
    _answer(_nested(50)), _answer([1.0] * 769),
])
def test_a_hostile_answer_raises_endpoint_error_and_nothing_else(answer):
    with pytest.raises(E.EndpointError) as caught:
        E.parse_response(answer, 1)
    assert caught.value.reason in ("endpoint_bad_response", "dimension_unsupported")


def test_huge_finite_values_keep_their_direction():
    """1e308 squared is infinity: normalising without scaling first turned
    such a vector into zeros."""
    got = E.parse_response(_answer([1e308, -1e308, 5e307]), 1)[0]
    assert all(math.isfinite(x) for x in got)
    assert math.isclose(math.sqrt(sum(x * x for x in got)), 1.0, abs_tol=1e-12)
    assert got[0] > 0 > got[1] and math.isclose(got[0], -got[1])
    tiny = E.parse_response(_answer([5e-324, 5e-324]), 1)[0]
    assert math.isclose(tiny[0], tiny[1]) and math.isclose(tiny[0], 2 ** -0.5)


def test_a_huge_answer_over_the_wire_keeps_its_direction(stub):
    stub.mode = "huge"
    s = _settings(stub)
    out = E.EndpointEmbedder(s).embed_via(_endpoint(s), ["one text"])
    assert out[0].status == "EMBEDDED"
    assert math.isclose(math.sqrt(sum(x * x for x in out[0].vector)), 1.0, abs_tol=1e-9)


def test_response_dims_answers_none_for_hostile_shapes():
    for answer in (None, {"data": []}, {"data": [{"embedding": 5}]},
                   {"data": "abc"}, _answer([1.0] * 800), _answer([])):
        assert E.response_dims(answer) is None
    assert E.response_dims(_answer([1.0] * 384)) == 384
