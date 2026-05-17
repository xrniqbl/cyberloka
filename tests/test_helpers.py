from cyberloka.active._helpers import append_param, has_query, iter_param_urls


def test_append_param_adds_to_existing_query():
    out = append_param("https://example.com/?a=1", "b", "two")
    assert "a=1" in out and "b=two" in out


def test_iter_param_urls_replaces_each_value():
    url = "https://example.com/?a=1&b=2&c=3"
    found = dict(iter_param_urls(url, "X"))
    assert set(found) == {"a", "b", "c"}
    assert "a=X" in found["a"] and "b=2" in found["a"]
    assert "b=X" in found["b"] and "a=1" in found["b"]


def test_iter_param_urls_no_query_yields_nothing():
    assert list(iter_param_urls("https://example.com/", "X")) == []


def test_has_query():
    assert has_query("https://x/?a=1") is True
    assert has_query("https://x/") is False
