from cyberloka.core.target import parse_target


def test_https_default_port():
    t = parse_target("https://example.com")
    assert t.scheme == "https"
    assert t.host == "example.com"
    assert t.port == 443
    assert t.is_ip is False
    assert t.base_url == "https://example.com/"


def test_http_with_path_and_port():
    t = parse_target("http://example.com:8080/api/v1")
    assert t.scheme == "http"
    assert t.port == 8080
    assert t.path == "/api/v1"
    assert t.base_url == "http://example.com:8080/api/v1"


def test_bare_host_defaults_to_https():
    t = parse_target("example.com")
    assert t.scheme == "https"
    assert t.port == 443


def test_bare_ip_defaults_to_http():
    t = parse_target("192.168.1.1")
    assert t.scheme == "http"
    assert t.is_ip is True
    assert t.port == 80


def test_origin_omits_default_port():
    t = parse_target("https://example.com:443/foo")
    assert t.origin == "https://example.com"


def test_origin_includes_nondefault_port():
    t = parse_target("http://example.com:8080/foo")
    assert t.origin == "http://example.com:8080"
