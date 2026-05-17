from cyberloka.recon.crawler import _LinkParser, _normalize, _in_scope, _is_dangerous


def test_link_parser_extracts_links_and_forms():
    html = """
    <html><body>
      <a href="/a">A</a>
      <a href="https://other.com/b">B</a>
      <form action="/login" method="POST">
        <input name="u">
        <input name="p">
        <input name="csrf" value="x">
      </form>
      <script src="/app.js"></script>
    </body></html>
    """
    p = _LinkParser()
    p.feed(html)
    assert "/a" in p.links and "https://other.com/b" in p.links
    assert "/app.js" in p.scripts
    assert len(p.forms) == 1
    f = p.forms[0]
    assert f["method"] == "POST"
    assert set(f["fields"]) == {"u", "p", "csrf"}


def test_normalize_strips_fragment_and_sorts_query():
    out = _normalize("https://x/path?b=2&a=1#frag")
    assert "#" not in out
    assert out.endswith("?a=1&b=2")


def test_in_scope_matches_host():
    assert _in_scope("https://example.com/a", "example.com") is True
    assert _in_scope("https://other.com/a", "example.com") is False


def test_is_dangerous_blocks_logout():
    assert _is_dangerous("https://x/account/logout")
    assert _is_dangerous("https://x/post/123/delete")
    assert not _is_dangerous("https://x/about")
