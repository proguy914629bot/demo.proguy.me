import unittest

from starlette.requests import Request

from main import _javascript_module_fetch, _javascript_source_view, _protect_javascript


def request_with_headers(**headers: str) -> Request:
    return Request(
        {
            "type": "http",
            "method": "GET",
            "scheme": "https",
            "path": "/sites/example.test/assets/main.js",
            "raw_path": b"/sites/example.test/assets/main.js",
            "query_string": b"",
            "headers": [
                (name.replace("_", "-").encode(), value.encode())
                for name, value in headers.items()
            ],
            "client": ("127.0.0.1", 12345),
            "server": ("testserver", 443),
        }
    )


class ProtectJavascriptTests(unittest.TestCase):
    def test_classic_script_is_randomized_on_every_response(self) -> None:
        source = 'window.example = "visible source";'

        first = _protect_javascript(source)
        second = _protect_javascript(source)

        self.assertNotIn(source, first)
        self.assertNotEqual(first, second)

    def test_executable_module_keeps_module_syntax(self) -> None:
        source = 'import value from "./value.js";\nexport default value;'

        self.assertEqual(_protect_javascript(source), source)
        self.assertEqual(_protect_javascript("console.log(import.meta.url);"), "console.log(import.meta.url);")
        self.assertEqual(_protect_javascript("export{value};"), "export{value};")

    def test_module_words_in_strings_and_comments_do_not_disable_encoding(self) -> None:
        source = 'const words = "export value";\n/* import.meta.url */\nconsole.log(words);'

        self.assertNotEqual(_protect_javascript(source), source)

    def test_mjs_hint_preserves_module_without_exports(self) -> None:
        source = 'console.log("module side effect");'

        self.assertEqual(_protect_javascript(source, module_hint=True), source)

    def test_direct_module_navigation_gets_encoded_view(self) -> None:
        source = 'import value from "./value.js";\nexport default value;'

        protected = _protect_javascript(source, module_hint=True, force_wrapper=True)

        self.assertNotEqual(protected, source)
        self.assertNotIn(source, protected)

    def test_document_navigation_is_source_view(self) -> None:
        self.assertTrue(_javascript_source_view(request_with_headers(sec_fetch_dest="document")))
        self.assertTrue(_javascript_source_view(request_with_headers(accept="text/html,*/*")))
        self.assertFalse(_javascript_source_view(request_with_headers(sec_fetch_dest="script")))
        self.assertFalse(_javascript_source_view(request_with_headers(accept="*/*")))

    def test_cors_script_request_is_treated_as_module_fetch(self) -> None:
        self.assertTrue(
            _javascript_module_fetch(
                request_with_headers(sec_fetch_dest="script", sec_fetch_mode="cors")
            )
        )
        self.assertFalse(
            _javascript_module_fetch(
                request_with_headers(sec_fetch_dest="document", sec_fetch_mode="navigate")
            )
        )


if __name__ == "__main__":
    unittest.main()
