import unittest

from starlette.requests import Request

import main


def request_for(path: str, query: str = "", cookie: str = "") -> Request:
    headers = [(b"cookie", f"site_guard_context={cookie}".encode())] if cookie else []
    return Request(
        {
            "type": "http",
            "method": "GET",
            "scheme": "https",
            "path": path,
            "raw_path": path.encode(),
            "query_string": query.encode(),
            "headers": headers,
            "client": ("127.0.0.1", 12345),
            "server": ("testserver", 443),
        }
    )


class ContextRedirectTests(unittest.TestCase):
    def test_root_and_query_are_redirected_beneath_site(self) -> None:
        token = main._issue_context_token("example", "/example")

        root = main._context_redirect(request_for("/", cookie=token))
        page = main._context_redirect(request_for("/search", "q=1", cookie=token))

        self.assertEqual(root.headers["location"], "/example/")
        self.assertEqual(page.headers["location"], "/example/search?q=1")

    def test_without_context_cookie_there_is_no_redirect(self) -> None:
        self.assertIsNone(main._context_redirect(request_for("/")))


class RewriteSiteUrlsTests(unittest.TestCase):
    def test_rewrites_srcset_style_and_meta_refresh(self) -> None:
        source = (
            '<meta http-equiv="refresh" content="0; url=/abc">'
            '<img srcset="/a.png 1x, /b.png 2x">'
            '<div style="background:url(/bg.png)"></div>'
            "<style>.a{background:url('/x.png')}</style>"
        )

        rewritten = main._rewrite_site_urls(source, "/example", "example")

        self.assertIn('content="0; url=/example/abc"', rewritten)
        self.assertIn('srcset="/example/a.png 1x, /example/b.png 2x"', rewritten)
        self.assertIn('style="background:url(/example/bg.png)"', rewritten)
        self.assertIn("<style>.a{background:url('/example/x.png')}</style>", rewritten)

    def test_ordinary_meta_content_is_untouched(self) -> None:
        source = '<meta name="description" content="/not-a-url">'

        self.assertEqual(main._rewrite_site_urls(source, "/example", "example"), source)


class ProtectHtmlTests(unittest.TestCase):
    def test_loader_matches_page_doctype_and_viewport(self) -> None:
        viewport = '<meta name="viewport" content="width=device-width, initial-scale=1">'
        standards = main._protect_html(f"<!DOCTYPE html><html><head>{viewport}</head></html>", "example")
        quirks = main._protect_html("<html><head></head></html>", "example")

        self.assertTrue(standards.startswith("<!DOCTYPE html><html>"))
        self.assertIn(viewport, standards)
        self.assertTrue(quirks.startswith("<html>"))


if __name__ == "__main__":
    unittest.main()
