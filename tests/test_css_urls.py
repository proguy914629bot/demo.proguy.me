import unittest

from main import _rewrite_css_urls


class RewriteCssUrlsTests(unittest.TestCase):
    def test_rewrites_root_relative_urls(self) -> None:
        source = (
            "@font-face{src:url('/assets/font1.ttf') format('truetype')}"
            '.hero{background:url( "/assets/hero.webp?size=2#main" )}'
            ".icon{mask:url(/assets/icon.svg#shape)}"
        )

        rewritten = _rewrite_css_urls(source, "/example", "example")

        self.assertIn("url('/example/assets/font1.ttf')", rewritten)
        self.assertIn('url( "/example/assets/hero.webp?size=2#main" )', rewritten)
        self.assertIn("url(/example/assets/icon.svg#shape)", rewritten)

    def test_preserves_non_root_and_protocol_relative_urls(self) -> None:
        source = (
            ".a{src:url(../fonts/font.ttf)}"
            ".b{src:url(https://cdn.test/font.ttf)}"
            ".c{src:url(//cdn.test/font.ttf)}"
            ".d{src:url(data:font/woff2;base64,AAAA)}"
            ".e{mask:url(#shape)}"
        )

        self.assertEqual(_rewrite_css_urls(source, "/example", "example"), source)

    def test_does_not_rewrite_comments_or_ordinary_strings(self) -> None:
        source = "/* url('/assets/comment.ttf') */.x{content:\"url('/assets/text.ttf')\"}"

        self.assertEqual(_rewrite_css_urls(source, "/example", "example"), source)

    def test_preserves_existing_site_prefix(self) -> None:
        source = ".a{src:url('/example/assets/font.ttf')}"

        self.assertEqual(_rewrite_css_urls(source, "/example", "example"), source)

    def test_adds_mount_prefix_to_site_prefixed_url(self) -> None:
        source = ".a{src:url('/client.test/assets/font.ttf')}"

        rewritten = _rewrite_css_urls(source, "/preview/client.test", "client.test")

        self.assertEqual(rewritten, ".a{src:url('/preview/client.test/assets/font.ttf')}")


if __name__ == "__main__":
    unittest.main()
