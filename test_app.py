# test_app.py
# Tests for the web layer, using Flask's test client so no server or network
# is involved. Covers routing, argument clamping, the two upload paths, and
# the abuse cases a web front end has to think about that a CLI does not.
#
#   python -m unittest test_app -v
#
# Skips itself cleanly if Flask is not installed, so the stdlib-only test
# suite still runs on a bare Python.

import io
import json
import unittest

try:
    import app as webapp
    FLASK_AVAILABLE = True
except ImportError as exc:                            # pragma: no cover
    # Skipping is only correct when Flask itself is absent — that is an
    # optional dependency and the stdlib-only suite should still run.
    # ANY OTHER ImportError means the application is broken, and swallowing
    # it would silently disable every web test rather than reporting the
    # breakage. Re-raise those.
    if "flask" not in str(exc).lower():
        raise
    FLASK_AVAILABLE = False


@unittest.skipUnless(FLASK_AVAILABLE, "Flask is not installed")
class WebTestCase(unittest.TestCase):

    def setUp(self):
        webapp.app.config["TESTING"] = True
        self.client = webapp.app.test_client()

    def post(self, payload):
        response = self.client.post("/api/analyze", json=payload)
        return response, response.get_json()


class TestPages(WebTestCase):

    def test_index_renders(self):
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Brute Force Log Analyzer", response.data)

    def test_index_hosts_the_container_the_samples_render_into(self):
        # Sample cards are built in the browser from /api/samples, so their
        # stats are computed at request time rather than baked into the page.
        body = self.client.get("/").data.decode()
        self.assertIn('id="samples"', body)

    def test_index_exposes_every_tab_panel(self):
        body = self.client.get("/").data.decode()
        for panel in ("analyse", "live", "history", "setup"):
            self.assertIn(f'data-panel="{panel}"', body)

    def test_static_assets_are_served(self):
        for path in ("/static/style.css", "/static/app.js"):
            with self.client.get(path) as response:   # closed, no ResourceWarning
                self.assertEqual(response.status_code, 200)


class TestAssetFreshness(WebTestCase):
    """A cached app.js running against a newer API is a silent, confusing
    failure: controls vanish and handlers bind to elements that no longer
    exist. Both defences are asserted here."""

    def test_static_urls_carry_a_version_stamp(self):
        import re
        body = self.client.get("/").data.decode()
        self.assertRegex(body, r"static/app\.js\?v=\d+")
        self.assertRegex(body, r"static/style\.css\?v=\d+")

    def test_the_stamp_changes_when_a_static_file_changes(self):
        import os
        import time
        path = os.path.join(webapp.STATIC_DIR, "app.js")
        before = webapp.asset_version()
        original = os.path.getmtime(path)
        try:
            os.utime(path, (original + 120, original + 120))
            self.assertNotEqual(webapp.asset_version(), before)
        finally:
            os.utime(path, (original, original))

    def test_static_files_are_served_no_cache(self):
        with self.client.get("/static/app.js") as response:
            self.assertIn("no-cache", response.headers.get("Cache-Control", ""))


class TestLookupPanelRendersWithoutJavaScript(WebTestCase):
    """The lookup controls are in the HTML, not injected afterwards, so a
    stale or failed script cannot leave the tab with nothing to click."""

    def test_every_provider_has_a_checkbox_in_the_page(self):
        body = self.client.get("/").data.decode()
        for provider in webapp.enricher.providers():
            self.assertIn(f'value="{provider["name"]}"', body)

    def test_the_offline_method_is_always_on(self):
        body = self.client.get("/").data.decode()
        self.assertIn("checked disabled", body)

    def test_unavailable_methods_are_disabled_not_hidden(self):
        providers = {p["name"]: p for p in webapp.enricher.providers()}
        body = self.client.get("/").data.decode()
        if not providers["maxmind"]["available"]:
            # Present, greyed out, and saying why.
            self.assertIn('value="maxmind"', body)
            self.assertIn("no database configured", body)

    def test_the_offsite_method_is_labelled_as_such(self):
        self.assertIn("leaves this machine", self.client.get("/").data.decode())

    def test_there_are_addresses_to_click_without_typing(self):
        import re
        body = self.client.get("/").data.decode()
        self.assertGreaterEqual(
            len(re.findall(r'data-lookup="[\d.]+"', body)), 3)

    def test_reverse_dns_is_on_by_default(self):
        # Classification alone answers "what kind of address is this", not
        # "where is it". Reverse DNS asks the operator's own resolver, sends
        # nothing to a third party, and is usually the difference between
        # "Public internet" and an actual answer — so it is on by default.
        import re
        body = self.client.get("/").data.decode()
        match = re.search(r'<input type="checkbox" value="rdns"([^>]*)>', body)
        self.assertIsNotNone(match)
        self.assertIn("checked", match.group(1))

    def test_the_offsite_method_is_not_on_by_default(self):
        import re
        body = self.client.get("/").data.decode()
        match = re.search(r'<input type="checkbox" value="online"([^>]*)>', body)
        self.assertIsNotNone(match)
        self.assertNotIn("checked", match.group(1))

    def test_the_default_selection_produces_a_useful_answer(self):
        # The failure this guards against: a lookup that returns "Public
        # internet" and stops, which reads as a broken feature.
        import re
        body = self.client.get("/").data.decode()
        picked = ["builtin"] + [
            name for name, attrs in
            re.findall(r'<input type="checkbox" value="(\w+)"([^>]*)>', body)
            if name != "builtin" and "checked" in attrs]

        data = self.client.post("/api/lookup",
                                json={"ip": "8.8.8.8",
                                      "methods": picked}).get_json()
        self.assertNotEqual(data["summary"], "Public internet",
                            "default lookup says nothing useful")

    def test_the_client_explains_a_missing_location(self):
        # Reserved ranges have no location by design. The panel must say so
        # rather than leaving the operator wondering what broke.
        import os
        path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            "static", "app.js")
        with open(path) as f:
            source = f.read()
        self.assertIn("no real-world location", source)
        self.assertIn("No location found for this address yet", source)

    def test_the_input_and_button_exist(self):
        body = self.client.get("/").data.decode()
        self.assertIn('id="lookup-ip"', body)
        self.assertIn('id="lookup-go"', body)


class TestBackendDisclosure(WebTestCase):
    """"Which library does the detecting?" has an honest answer: none."""

    def test_reports_what_the_detection_is_built_on(self):
        data = self.client.get("/api/backend").get_json()
        for section in ("detection", "stdlib", "third_party", "not_used"):
            self.assertIn(section, data)
            self.assertTrue(data[section], section)

    def test_names_the_file_each_piece_lives_in(self):
        import os
        for entry in self.client.get("/api/backend").get_json()["detection"]:
            path = os.path.join(os.path.dirname(os.path.abspath(webapp.__file__)),
                                entry["where"])
            self.assertTrue(os.path.exists(path), entry["where"])

    def test_flask_is_the_only_hard_dependency(self):
        third = {p["name"]: p for p in
                 self.client.get("/api/backend").get_json()["third_party"]}
        required = [n for n, p in third.items() if p["required"]]
        self.assertEqual(required, ["Flask"])

    def test_the_cli_really_does_import_nothing_outside_the_stdlib(self):
        # The claim above must be true, not merely stated. Each import is
        # resolved for real and its file located, rather than checked against
        # a name list — that also works on Python 3.9, where
        # sys.stdlib_module_names does not exist.
        import ast
        import importlib.util
        import os
        import sysconfig

        base = os.path.dirname(os.path.abspath(webapp.__file__))
        local = {f[:-3] for f in os.listdir(base) if f.endswith(".py")}
        stdlib_dir = os.path.realpath(sysconfig.get_paths()["stdlib"])

        def is_stdlib(name):
            if name in local:
                return True
            try:
                spec = importlib.util.find_spec(name)
            except (ImportError, ValueError):
                return False
            if spec is None:
                return False
            if spec.origin in (None, "built-in", "frozen"):
                return True
            origin = os.path.realpath(spec.origin)
            # Inside the stdlib directory, but not in site-packages.
            return (origin.startswith(stdlib_dir)
                    and "site-packages" not in origin)

        for module in ("main.py", "detector.py", "log_parser.py",
                       "evaluate.py", "storage.py", "watcher.py",
                       "generate_log.py", "config.py"):
            tree = ast.parse(open(os.path.join(base, module)).read())
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    names = [a.name.split(".")[0] for a in node.names]
                elif isinstance(node, ast.ImportFrom) and node.module:
                    names = [node.module.split(".")[0]]
                else:
                    continue
                for name in names:
                    self.assertTrue(is_stdlib(name),
                                    f"{module} imports non-stdlib {name!r} — "
                                    f"the CLI is meant to need nothing but "
                                    f"the standard library")


class TestGeoLookupIsOptIn(WebTestCase):
    """Asking a third party where an address is sends them that address."""

    def test_no_geo_source_when_not_requested(self):
        data = self.client.post("/api/analyze",
                                json={"sample": "auth_sample.log"}).get_json()
        for finding in data["findings"]:
            self.assertNotIn("geo_source", finding.get("enrichment", {}))

    def test_documentation_addresses_are_never_sent_offsite(self):
        # The bundled samples are all reserved ranges, so even with the option
        # on, nothing should leave the machine.
        data = self.client.post("/api/analyze",
                                json={"sample": "auth_sample.log",
                                      "geo_lookup": True}).get_json()
        for finding in data["findings"]:
            enrichment = finding.get("enrichment", {})
            if enrichment.get("routable") is False:
                self.assertNotEqual(enrichment.get("geo_source"), "online")
                self.assertNotIn("country", enrichment)


class TestSampleApi(WebTestCase):

    def test_lists_samples_with_live_computed_stats(self):
        payload = self.client.get("/api/samples").get_json()
        names = {s["name"] for s in payload["samples"]}
        for sample in webapp.SAMPLES:
            self.assertIn(sample["name"], names)
        for card in payload["samples"]:
            for field in ("lines", "events", "skipped", "findings", "high",
                          "group"):
                self.assertIn(field, card)

    def test_states_where_the_demo_data_came_from(self):
        # The first question anyone asks of a security finding is "what am I
        # looking at?" The answer ships with the data.
        payload = self.client.get("/api/samples").get_json()
        provenance = payload["provenance"].lower()
        self.assertIn("synthetic", provenance)
        self.assertIn("not captured from any real host", provenance)

    def test_the_two_headline_examples_are_selectable(self):
        # They are what the README, START-HERE and HOW-TO-USE all tell people
        # to try first, so the web app must offer them too.
        payload = self.client.get("/api/samples").get_json()
        names = {s["name"] for s in payload["samples"]}
        self.assertIn("EXAMPLE-1-attacks-present.log", names)
        self.assertIn("EXAMPLE-2-no-attacks.log", names)

    def test_the_examples_can_be_analysed_and_reported_by_name(self):
        for name in ("EXAMPLE-1-attacks-present.log", "EXAMPLE-2-no-attacks.log"):
            analysed = self.client.post("/api/analyze", json={"sample": name})
            self.assertEqual(analysed.status_code, 200, name)
            report = self.client.post("/api/report", json={"sample": name})
            self.assertEqual(report.status_code, 200, name)

    def test_the_attack_example_reports_a_breach_and_the_quiet_one_does_not(self):
        loud = self.client.post("/api/analyze",
                                json={"sample": "EXAMPLE-1-attacks-present.log",
                                      "threshold": 4, "window": 600}).get_json()
        quiet = self.client.post("/api/analyze",
                                 json={"sample": "EXAMPLE-2-no-attacks.log",
                                       "threshold": 4, "window": 600}).get_json()
        self.assertEqual(loud["stats"]["high"], 1)
        self.assertEqual(quiet["stats"]["findings"], 0)

    def test_lists_the_logs_folder(self):
        names = {s["name"] for s in
                 self.client.get("/api/samples").get_json()["samples"]}
        self.assertTrue(any(n.startswith("logs/clean/") for n in names))
        self.assertTrue(any(n.startswith("logs/attacks/") for n in names))

    def test_sample_stats_match_analysing_the_file_directly(self):
        # The card must not be able to claim anything the detector does not
        # actually produce.
        from detector import BruteForceDetector
        from config import config
        cards = {s["name"]: s
                 for s in self.client.get("/api/samples").get_json()["samples"]}
        detector = BruteForceDetector(allowlist=config.allowlist)
        for name, card in cards.items():
            result = detector.analyze_file(webapp.sample_path(name))
            self.assertEqual(card["events"], len(result.events), name)
            self.assertEqual(card["findings"], len(result.findings), name)
            self.assertEqual(card["high"], len(result.high_findings), name)

    def test_fetches_one_sample(self):
        payload = self.client.get("/api/samples/auth_sample.log").get_json()
        self.assertIn("Failed password", payload["text"])

    def test_unknown_sample_is_404(self):
        self.assertEqual(self.client.get("/api/samples/nope.log").status_code, 404)

    def test_path_traversal_is_refused(self):
        # The sample lookup is a whitelist membership test, not a path join,
        # so this can never escape the project directory.
        for attack in ("../app.py", "....//app.py", "/etc/passwd"):
            response = self.client.get(f"/api/samples/{attack}")
            self.assertIn(response.status_code, (404, 308),
                          f"{attack} returned {response.status_code}")
            if response.status_code == 404 and response.is_json:
                self.assertNotIn("Flask", response.get_json().get("error", ""))


class TestAnalyzeApi(WebTestCase):

    ATTACK = "\n".join(
        f"Jun 19 09:15:{i:02d} server sshd[1]: Failed password for invalid "
        f"user admin from 192.168.1.5 port 5123{i} ssh2" for i in range(0, 10, 2))

    def test_analyses_a_named_sample(self):
        response, data = self.post({"sample": "auth_sample.log"})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(data["stats"]["high"], 1)
        self.assertIn("203.0.113.5", [f["key"] for f in data["findings"]])

    def test_analyses_pasted_text(self):
        _, data = self.post({"text": self.ATTACK, "threshold": 5, "window": 120})
        self.assertIn("192.168.1.5", [f["key"] for f in data["findings"]])

    def test_analyses_an_uploaded_file(self):
        upload = (io.BytesIO(self.ATTACK.encode()), "auth.log")
        response = self.client.post("/api/analyze", content_type="multipart/form-data",
                                    data={"logfile": upload, "threshold": "5",
                                          "window": "120"})
        data = response.get_json()
        self.assertEqual(response.status_code, 200)
        self.assertEqual(data["source"], "auth.log")
        self.assertTrue(data["findings"])

    def test_clean_log_reports_no_findings(self):
        _, data = self.post({"sample": "clean_sample.log"})
        self.assertEqual(data["findings"], [])
        self.assertEqual(data["stats"]["high"], 0)

    def test_tuning_changes_the_outcome(self):
        _, default = self.post({"sample": "evasion_sample.log",
                                "threshold": 5, "window": 120})
        _, tuned = self.post({"sample": "evasion_sample.log",
                              "threshold": 3, "window": 1800})
        self.assertGreater(len(tuned["findings"]), len(default["findings"]))

    def test_compromise_detection_can_be_disabled(self):
        _, data = self.post({"sample": "auth_sample.log",
                             "detect_compromise": False})
        self.assertEqual(data["stats"]["high"], 0)

    def test_response_carries_the_chart_data(self):
        _, data = self.post({"sample": "auth_sample.log"})
        self.assertTrue(data["top_offenders"])
        self.assertTrue(data["timeline"])
        self.assertEqual(sum(b["failures"] for b in data["timeline"]),
                         data["stats"]["failures"])


class TestInputValidation(WebTestCase):
    """A web front end takes input from strangers. A CLI does not."""

    def test_empty_body_is_a_400_not_a_crash(self):
        response, data = self.post({"text": "   \n  "})
        self.assertEqual(response.status_code, 400)
        self.assertIn("error", data)

    def test_unknown_sample_name_is_a_404(self):
        response, _ = self.post({"sample": "../../etc/passwd"})
        self.assertEqual(response.status_code, 404)

    def test_garbage_tuning_values_fall_back_to_defaults(self):
        _, data = self.post({"sample": "auth_sample.log",
                             "threshold": "abc", "window": None})
        self.assertEqual(data["threshold"], webapp.DEFAULT_THRESHOLD)
        self.assertEqual(data["window"], webapp.DEFAULT_WINDOW)

    def test_out_of_range_tuning_is_clamped_not_rejected(self):
        _, data = self.post({"sample": "auth_sample.log",
                             "threshold": 999999, "window": -5})
        self.assertEqual(data["threshold"], webapp.LIMITS["threshold"][1])
        self.assertEqual(data["window"], webapp.LIMITS["window"][0])

    def test_zero_threshold_is_clamped_to_one(self):
        _, data = self.post({"sample": "auth_sample.log", "threshold": 0})
        self.assertEqual(data["threshold"], 1)

    def test_unparseable_log_text_returns_zero_events(self):
        _, data = self.post({"text": "this is not a log file at all"})
        self.assertEqual(data["stats"]["events"], 0)
        self.assertEqual(data["stats"]["skipped"], 1)
        self.assertEqual(data["findings"], [])

    def test_oversized_upload_is_rejected_with_413(self):
        big = io.BytesIO(b"x" * (webapp.config.max_upload_bytes + 1024))
        response = self.client.post("/api/analyze",
                                    content_type="multipart/form-data",
                                    data={"logfile": (big, "huge.log")})
        self.assertEqual(response.status_code, 413)

    def test_invalid_utf8_does_not_crash_the_parser(self):
        upload = (io.BytesIO(b"Jun 19 09:15:01 h sshd[1]: Failed password for "
                             b"invalid user \xff\xfe from 1.2.3.4 port 1 ssh2"),
                  "bad.log")
        response = self.client.post("/api/analyze",
                                    content_type="multipart/form-data",
                                    data={"logfile": upload})
        self.assertEqual(response.status_code, 200)


class TestTemplateWiring(WebTestCase):
    """Catches the classic front-end bug: app.js reaches for an element id
    the template does not define, so a handler silently binds to null and one
    control does nothing. Cheap to test, easy to miss by eye."""

    def js_source(self):
        import os
        path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            "static", "app.js")
        with open(path) as f:
            return f.read()

    def test_every_id_app_js_looks_up_exists_in_the_page(self):
        import re
        html = self.client.get("/").data.decode()
        wanted = set(re.findall(r'\$\("([^"]+)"\)', self.js_source()))
        self.assertTrue(wanted, "no element lookups found in app.js")
        for element_id in sorted(wanted):
            self.assertIn(f'id="{element_id}"', html,
                          f'app.js looks up #{element_id}, template lacks it')

    def test_every_css_class_app_js_queries_exists_in_the_page(self):
        import re
        html = self.client.get("/").data.decode()
        for selector in set(re.findall(r'querySelectorAll\("\.([a-z-]+)',
                                       self.js_source())):
            self.assertIn(f'class="{selector}', html,
                          f'app.js queries .{selector}, template lacks it')

    def test_sample_cards_carry_the_data_attribute_js_reads(self):
        # Rendered by loadSamples() rather than the template, so assert the
        # client writes the attribute the click handler reads back.
        source = self.js_source()
        self.assertIn('data-sample="${esc(s.name)}"', source)
        self.assertIn('button.dataset.sample', source)

    def test_page_references_no_external_hosts(self):
        # No CDN, no build step: everything is served from this app.
        html = self.client.get("/").data.decode()
        for scheme in ("http://", "https://"):
            for hit in html.split(scheme)[1:]:
                host = hit.split("/")[0].split('"')[0]
                self.assertIn(host, ("www.w3.org",), f"external host {host}")


class TestOutputSafety(WebTestCase):
    """Log content is attacker-controlled. A username can contain markup."""

    HOSTILE_USER = "<script>alert(1)</script>"

    def hostile_log(self):
        return "\n".join(
            f"Jun 19 09:15:{i:02d} server sshd[1]: Failed password for invalid "
            f"user {self.HOSTILE_USER} from 9.9.9.9 port 500{i} ssh2"
            for i in range(5))

    def test_markup_in_a_username_round_trips_as_data(self):
        # The API must neither mangle it nor interpret it: it is a username
        # that happens to contain angle brackets, and the analyst needs to see
        # exactly what the attacker sent.
        _, data = self.post({"text": self.hostile_log(),
                             "threshold": 5, "window": 120})
        user_findings = [f for f in data["findings"] if f["pivot"] == "user"]
        self.assertEqual(user_findings[0]["key"], self.HOSTILE_USER)

    def test_api_response_is_json_not_html(self):
        # Content type matters: a browser must never parse this as a document.
        response = self.client.post("/api/analyze",
                                    json={"text": self.hostile_log()})
        self.assertEqual(response.mimetype, "application/json")

    def test_every_html_interpolation_in_the_client_escapes_its_input(self):
        # Guard rail on the browser layer: the JSON is safe on the wire, so
        # the only place markup could execute is an unescaped interpolation
        # inside a template literal that is written to innerHTML.
        #
        # A literal with no markup in it is not HTML — it goes to textContent,
        # which escapes by definition. Calling esc() there would be a BUG: the
        # user would see a literal &lt; instead of a less-than sign. So the
        # rule is applied only to literals that actually contain a tag.
        import os
        import re
        path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            "static", "app.js")
        with open(path) as f:
            source = f.read()

        # Every backtick-delimited template literal in the file.
        literals = re.findall(r"`(?:[^`\\]|\\.)*`", source, re.DOTALL)
        html_literals = [lit for lit in literals if re.search(r"<[a-zA-Z/]", lit)]
        self.assertTrue(html_literals, "no HTML template literals found in app.js")

        # Fields carrying attacker-controlled text out of the log.
        risky = ("f.key", "f.detail", "f.severity", "f.pivot", "o.ip",
                 "data.source", "s.name", "s.label", "a.name", "a.channel",
                 "o.key", "o.worst", "o.pivot", "r.source", "r.mode",
                 "a.key", "a.severity", "m.variable", "m.feature", "ch.name")

        def emitted_part(expression):
            """Drop a ternary's condition — only the branches reach the page.

            `flagged.has(o.ip) ? "flagged" : ""` emits a string literal. The
            field is a lookup key, not output, so it needs no escaping.
            """
            depth = 0
            for index, character in enumerate(expression):
                if character in "([{":
                    depth += 1
                elif character in ")]}":
                    depth -= 1
                elif character == "?" and depth == 0:
                    return expression[index + 1:]
            return expression

        offences = []
        for literal in html_literals:
            for expression in re.findall(r"\$\{([^{}]*)\}", literal):
                output = emitted_part(expression)
                if "esc(" in output:
                    continue
                for field in risky:
                    if re.search(r"\b" + re.escape(field) + r"\b", output):
                        offences.append(expression.strip())
                        break
        self.assertEqual(offences, [],
                         f"unescaped log data in HTML: {offences}")

    def test_the_escape_helper_covers_every_dangerous_character(self):
        import os
        path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            "static", "app.js")
        with open(path) as f:
            source = f.read()
        self.assertIn("const esc =", source)
        for entity in ("&amp;", "&lt;", "&gt;", "&quot;", "&#39;"):
            self.assertIn(entity, source, f"esc() does not produce {entity}")



class TestGeneratorApi(WebTestCase):
    """The generator makes a fresh log; the detector must find its attacks."""

    def test_generates_a_log_and_reports_what_it_planted(self):
        data = self.client.post("/api/generate",
                                json={"hours": 6, "seed": 1}).get_json()
        self.assertGreater(data["lines"], 100)
        self.assertTrue(data["planted"])
        self.assertIn("Failed password", data["text"])

    def test_generation_is_reproducible_from_a_seed(self):
        first = self.client.post("/api/generate", json={"seed": 5}).get_json()
        second = self.client.post("/api/generate", json={"seed": 5}).get_json()
        self.assertEqual(first["text"], second["text"])

    def test_hours_is_clamped_to_a_sane_range(self):
        data = self.client.post("/api/generate",
                                json={"hours": 99999, "seed": 1}).get_json()
        self.assertLessEqual(data["hours"], webapp.LIMITS["hours"][1])

    def test_the_generated_log_becomes_a_loadable_sample(self):
        self.client.post("/api/generate", json={"hours": 4, "seed": 2})
        names = {s["name"] for s in
                 self.client.get("/api/samples").get_json()["samples"]}
        self.assertIn("generated.log", names)

    def test_verify_scores_the_detector_against_ground_truth(self):
        data = self.client.post("/api/verify",
                                json={"seed": 42, "hours": 24,
                                      "threshold": 4, "window": 600}).get_json()
        self.assertEqual(data["caught"], data["planted"])
        self.assertEqual(data["false_alarms"], [])
        self.assertEqual(data["recall"], 1.0)

    def test_verify_shows_the_default_missing_the_slow_attacks(self):
        data = self.client.post("/api/verify",
                                json={"seed": 42, "threshold": 5,
                                      "window": 120}).get_json()
        self.assertLess(data["caught"], data["planted"])
        self.assertTrue(any(not a["found"] for a in data["attacks"]))

    def test_verify_needs_a_seed(self):
        response = self.client.post("/api/verify", json={})
        self.assertEqual(response.status_code, 400)


class TestHistoryApi(WebTestCase):

    def test_history_reports_what_was_actually_recorded(self):
        before = self.client.get("/api/history").get_json()
        if not before.get("enabled"):
            self.skipTest("persistence disabled")
        self.client.post("/api/analyze", json={"sample": "auth_sample.log"})
        after = self.client.get("/api/history").get_json()
        self.assertGreater(after["summary"]["runs"], before["summary"]["runs"])

    def test_repeat_offenders_appear_after_analysing_twice(self):
        if not self.client.get("/api/history").get_json().get("enabled"):
            self.skipTest("persistence disabled")
        for _ in range(2):
            self.client.post("/api/analyze", json={"sample": "auth_sample.log"})
        keys = {o["key"] for o in
                self.client.get("/api/history").get_json()["repeat_offenders"]}
        self.assertIn("203.0.113.5", keys)

    def test_history_for_an_unseen_key_is_404(self):
        self.assertEqual(
            self.client.get("/api/history/never.seen.at.all").status_code, 404)

    def test_findings_carry_prior_sighting_counts(self):
        self.client.post("/api/analyze", json={"sample": "auth_sample.log"})
        data = self.client.post("/api/analyze",
                                json={"sample": "auth_sample.log"}).get_json()
        self.assertTrue(any(f.get("times_seen", 0) > 0 for f in data["findings"]))


class TestEnrichmentInResponses(WebTestCase):

    def test_ip_findings_carry_a_location_string(self):
        data = self.client.post("/api/analyze",
                                json={"sample": "auth_sample.log"}).get_json()
        ip_findings = [f for f in data["findings"] if f["pivot"] == "ip"]
        self.assertTrue(ip_findings)
        for finding in ip_findings:
            self.assertIn("location", finding)
            self.assertTrue(finding["location"])

    def test_no_country_is_invented_without_a_geoip_database(self):
        status = self.client.get("/api/config").get_json()["enrichment"]
        if status["geo"]:
            self.skipTest("a GeoIP database is configured")
        data = self.client.post("/api/analyze",
                                json={"sample": "auth_sample.log"}).get_json()
        for finding in data["findings"]:
            self.assertNotIn("country", finding.get("enrichment", {}))


class TestLiveApi(WebTestCase):

    def test_status_when_nothing_is_running(self):
        data = self.client.get("/api/live/status").get_json()
        self.assertFalse(data["running"])

    def test_starting_without_a_path_explains_what_is_needed(self):
        response = self.client.post("/api/live/start", json={"path": ""})
        self.assertEqual(response.status_code, 400)
        self.assertIn("BFLA_WATCH_PATH", response.get_json()["hint"])

    def test_snapshot_without_a_watcher_is_404(self):
        if webapp.watcher and webapp.watcher.running:
            self.skipTest("a watcher is running")
        self.assertEqual(self.client.get("/api/live/snapshot").status_code, 404)

    def test_start_follow_and_stop_a_real_file(self):
        import os
        import tempfile
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "auth.log")
            open(path, "w").close()
            started = self.client.post("/api/live/start",
                                       json={"path": path, "threshold": 4,
                                             "window": 600}).get_json()
            self.assertTrue(started["running"])
            self.assertEqual(started["path"], path)

            with open(path, "a") as f:
                for i in range(5):
                    f.write(f"Aug 24 10:00:0{i} h sshd[1]: Failed password "
                            f"for invalid user root from 203.0.113.9 "
                            f"port 1 ssh2\n")
            webapp.watcher.poll_once()

            snapshot = self.client.get("/api/live/snapshot").get_json()
            self.assertTrue(snapshot["findings"])

            stopped = self.client.post("/api/live/stop").get_json()
            self.assertFalse(stopped["running"])


class TestConfigApi(WebTestCase):

    def test_reports_capabilities_without_leaking_secrets(self):
        data = self.client.get("/api/config").get_json()
        body = json.dumps(data).lower()
        for secret in ("password", "webhook_url", "smtp_password"):
            self.assertNotIn(f'"{secret}":', body)
        self.assertIn("alerting", data)
        self.assertIn("missing", data["config"])

    def test_missing_entries_name_the_variable_that_fixes_them(self):
        for gap in self.client.get("/api/config").get_json()["config"]["missing"]:
            self.assertTrue(gap["variable"].startswith("BFLA_"))
            self.assertTrue(gap["hint"])

    def test_alert_test_refuses_when_nothing_is_configured(self):
        status = self.client.get("/api/alerts").get_json()["status"]
        if status["enabled"]:
            self.skipTest("an alert channel is configured")
        response = self.client.post("/api/alerts/test")
        self.assertEqual(response.status_code, 400)
        self.assertIn("no channel", response.get_json()["reason"])


class TestLookupApi(WebTestCase):
    """The operator chooses which sources to ask. Nothing leaves the machine
    unless they explicitly tick the online one."""

    def test_lists_the_available_methods(self):
        providers = self.client.get("/api/lookup/providers").get_json()
        names = {p["name"] for p in providers}
        self.assertEqual(names, {"builtin", "maxmind", "rdns", "online"})

    def test_each_method_declares_whether_it_leaves_the_machine(self):
        for provider in self.client.get("/api/lookup/providers").get_json():
            self.assertIn("sends_data_offsite", provider)
            self.assertIn("needs_network", provider)
        online = next(p for p in self.client.get("/api/lookup/providers").get_json()
                      if p["name"] == "online")
        self.assertTrue(online["sends_data_offsite"])

    def test_builtin_lookup_needs_no_network(self):
        data = self.client.post("/api/lookup",
                                json={"ip": "10.0.4.15",
                                      "methods": ["builtin"]}).get_json()
        self.assertEqual(data["classification"]["kind"], "private")
        self.assertIn("Private network", data["summary"])

    def test_a_reserved_range_is_flagged_as_having_no_location(self):
        data = self.client.post("/api/lookup",
                                json={"ip": "203.0.113.5",
                                      "methods": ["builtin", "rdns"]}).get_json()
        self.assertFalse(data["classification"]["routable"])
        merged = data["merged"]
        for field in ("country", "city", "network_operator"):
            self.assertNotIn(field, merged)

    def test_documentation_range_is_recognised(self):
        data = self.client.post("/api/lookup",
                                json={"ip": "203.0.113.5"}).get_json()
        self.assertEqual(data["classification"]["kind"], "documentation")

    def test_online_lookup_refuses_a_non_routable_address(self):
        # Sending a private address to a geolocation service would leak
        # internal addressing and learn nothing.
        data = self.client.post("/api/lookup",
                                json={"ip": "10.0.4.15",
                                      "methods": ["builtin", "online"]}).get_json()
        online = data["methods"]["online"]
        self.assertFalse(online["ok"])
        self.assertIn("not sent", online["error"])
        self.assertEqual(online["data"], {})

    def test_online_is_not_consulted_unless_asked_for(self):
        data = self.client.post("/api/lookup",
                                json={"ip": "8.8.8.8",
                                      "methods": ["builtin"]}).get_json()
        self.assertNotIn("online", data["methods"])

    def test_maxmind_reports_why_it_is_unavailable(self):
        data = self.client.post("/api/lookup",
                                json={"ip": "8.8.8.8",
                                      "methods": ["maxmind"]}).get_json()
        entry = data["methods"]["maxmind"]
        if not entry["ok"]:
            self.assertTrue(entry["error"])

    def test_an_unknown_method_is_ignored_not_fatal(self):
        data = self.client.post("/api/lookup",
                                json={"ip": "8.8.8.8",
                                      "methods": ["nonsense"]}).get_json()
        self.assertIn("builtin", data["methods"])

    def test_garbage_input_does_not_crash(self):
        data = self.client.post("/api/lookup", json={"ip": "not-an-ip"}).get_json()
        self.assertEqual(data["classification"]["kind"], "invalid")

    def test_empty_address_is_a_400(self):
        self.assertEqual(
            self.client.post("/api/lookup", json={"ip": ""}).status_code, 400)


class TestReportApi(WebTestCase):

    def test_builds_a_report_for_a_sample(self):
        response = self.client.post("/api/report",
                                    json={"sample": "auth_sample.log",
                                          "threshold": 4, "window": 600})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.mimetype, "text/html")
        self.assertIn(b"<!doctype html>", response.data[:40].lower())

    def test_builds_a_report_for_uploaded_text(self):
        text = open(webapp.sample_path("auth_sample.log")).read()
        response = self.client.post("/api/report",
                                    json={"text": text,
                                          "source": "my-server.log"})
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"my-server.log", response.data)
        self.assertIn(b"Supplied by the operator", response.data)

    def test_offers_a_filename_to_save_as(self):
        response = self.client.post("/api/report",
                                    json={"sample": "auth_sample.log"})
        self.assertIn("filename=", response.headers["Content-Disposition"])

    def test_report_reflects_the_tuning_it_was_given(self):
        strict = self.client.post("/api/report",
                                  json={"sample": "evasion_sample.log",
                                        "threshold": 20, "window": 60}).data
        loose = self.client.post("/api/report",
                                 json={"sample": "evasion_sample.log",
                                       "threshold": 3, "window": 1800}).data
        self.assertNotEqual(strict, loose)

    def test_empty_input_is_a_400(self):
        self.assertEqual(
            self.client.post("/api/report", json={"text": "  "}).status_code, 400)

    def test_unknown_sample_is_a_404(self):
        self.assertEqual(
            self.client.post("/api/report",
                             json={"sample": "nope.log"}).status_code, 404)


class TestAllowlistApi(WebTestCase):

    def test_allowlist_supplied_per_request_suppresses_findings(self):
        bare = self.client.post("/api/analyze",
                                json={"sample": "auth_sample.log",
                                      "threshold": 4, "window": 600}).get_json()
        allowed = self.client.post("/api/analyze",
                                   json={"sample": "auth_sample.log",
                                         "threshold": 4, "window": 600,
                                         "allowlist": "203.0.113.0/24"}).get_json()
        self.assertGreater(len(bare["findings"]), len(allowed["findings"]))
        self.assertTrue(allowed["suppressed"])

    def test_a_comma_separated_string_is_accepted(self):
        data = self.client.post("/api/analyze",
                                json={"sample": "auth_sample.log",
                                      "allowlist": "10.0.0.0/8, 203.0.113.0/24"}
                                ).get_json()
        self.assertEqual(data["allowlist"]["count"], 2)

    def test_suppressed_findings_are_returned_not_hidden(self):
        data = self.client.post("/api/analyze",
                                json={"sample": "auth_sample.log",
                                      "threshold": 4, "window": 600,
                                      "allowlist": "203.0.113.0/24"}).get_json()
        self.assertEqual(data["stats"]["suppressed"], len(data["suppressed"]))
        for finding in data["suppressed"]:
            self.assertIn("key", finding)


class TestHistoryReset(WebTestCase):

    def test_clearing_history_really_clears_it(self):
        self.client.post("/api/analyze", json={"sample": "auth_sample.log"})
        before = self.client.get("/api/history").get_json()
        if not before.get("enabled"):
            self.skipTest("persistence disabled")
        self.assertGreater(before["summary"]["runs"], 0)

        cleared = self.client.post("/api/history/reset").get_json()
        self.assertTrue(cleared["cleared"])

        after = self.client.get("/api/history").get_json()
        self.assertEqual(after["summary"]["runs"], 0)
        self.assertEqual(after["summary"]["distinct_offenders"], 0)
        self.assertEqual(after["repeat_offenders"], [])
        self.assertEqual(after["runs"], [])

    def test_reset_reports_what_it_removed(self):
        self.client.post("/api/analyze", json={"sample": "auth_sample.log"})
        removed = self.client.post("/api/history/reset").get_json()["removed"]
        self.assertGreaterEqual(removed["runs"], 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
