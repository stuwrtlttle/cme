from collections import Counter
from html import escape
from html.parser import HTMLParser
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase, mock

import build_site


class TacticPageParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.ids = set()
        self.links = []

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if "id" in attrs:
            self.ids.add(attrs["id"])
        if tag == "a" and "href" in attrs:
            self.links.append(attrs["href"])


class TacticPageTests(TestCase):
    def test_generated_tactics_have_counts_anchors_categories_and_entries(self):
        entries = build_site.load_entries()
        taxonomy = build_site.build_taxonomy(entries)
        counts = Counter(entry["tactic"] for entry in entries)
        with TemporaryDirectory() as tmp:
            output = Path(tmp) / "site"
            with mock.patch.object(build_site, "OUTPUT_DIR", output):
                build_site.main()
            html = (output / "by-tactic.html").read_text()
            parser = TacticPageParser()
            parser.feed(html)

            self.assertIn(f'<div class="stat-value">{len(entries)}</div>', html)
            self.assertIn("Total Entries", html)
            for tactic in build_site.TACTIC_ORDER:
                target = f"tactic-{tactic.lower()}"
                self.assertIn(target, parser.ids)
                self.assertIn(f"#{target}", parser.links)
                self.assertIn(f'{counts[tactic]} entries</span>', html)
                for category in taxonomy.get(tactic, {}):
                    self.assertIn(f'<h3 class="category-header">{escape(category)}</h3>', html)
            for entry in entries:
                self.assertEqual(parser.links.count(f"entries/{entry['cme_id']}.html"), 2)
