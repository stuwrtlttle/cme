from html import escape
from html.parser import HTMLParser
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase, mock

import build_site


class LinkCollector(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links = []
        self.ids = set()

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if "id" in attrs:
            self.ids.add(attrs["id"])
        if tag == "a" and "href" in attrs:
            self.links.append(attrs["href"])


class OverviewTests(TestCase):
    def test_readme_is_the_source_for_overview_definitions(self):
        copy = build_site.load_overview_copy()
        self.assertIn("CVE identifies specific vulnerabilities", copy["intro"][0])
        self.assertIn("not the membership test", copy["intro"][1])
        self.assertEqual(set(copy["evidence"]), {"deterministic", "quantified", "unquantified"})
        self.assertIn("never changes an automated score", copy["evidence"]["unquantified"])

    def test_missing_shared_readme_definition_fails_build(self):
        with TemporaryDirectory() as tmp:
            readme = Path(tmp) / "README.md"
            readme.write_text(build_site.README_PATH.read_text().replace("**Unquantified** —", "**Other** —"))
            with mock.patch.object(build_site, "README_PATH", readme):
                with self.assertRaisesRegex(ValueError, "Unquantified"):
                    build_site.load_overview_copy()

    def test_generated_overview_and_links(self):
        with TemporaryDirectory() as tmp:
            output = Path(tmp) / "site"
            with mock.patch.object(build_site, "OUTPUT_DIR", output):
                build_site.main()
            html = (output / "index.html").read_text()
            copy = build_site.load_overview_copy()
            for text in (*copy["intro"], *copy["evidence"].values()):
                self.assertIn(escape(text, quote=True), html.replace("&#39;", "&#x27;"))
            for text in ("Preventive", "Detective", "Corrective", "Verification", "Remediation", "CVSS vector impacts"):
                self.assertIn(text, html)
            parser = LinkCollector()
            parser.feed(html)
            for link in parser.links:
                if link.startswith("#"):
                    self.assertIn(link[1:], parser.ids)
                elif not link.startswith(("http:", "https:", "mailto:")):
                    self.assertTrue((output / link).exists(), link)
