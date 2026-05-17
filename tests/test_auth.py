from cyberloka.core.auth import _extract_csrf


def test_extract_csrf_django_style():
    html = '<input type="hidden" name="csrfmiddlewaretoken" value="abc123">'
    out = _extract_csrf(html)
    assert out == {"csrfmiddlewaretoken": "abc123"}


def test_extract_csrf_underscore_token_attr_order_swapped():
    html = '<input value="xyz" name="_token" type="hidden">'
    out = _extract_csrf(html)
    assert out == {"_token": "xyz"}


def test_extract_csrf_ignores_unrelated_inputs():
    html = '<input name="email" value="a@b.com">'
    assert _extract_csrf(html) == {}


def test_extract_csrf_authenticity_token_rails():
    html = '<input type="hidden" name="authenticity_token" value="rails-token">'
    assert _extract_csrf(html) == {"authenticity_token": "rails-token"}
