# test_enrich.py
# Tests for address enrichment.
#
# The important property under test is HONESTY: without a GeoIP database the
# enricher must say it does not know, never invent a plausible-looking country.

import unittest

from enrich import Enricher, MaxMindProvider, classify


class TestClassification(unittest.TestCase):
    """Derived from the address itself. Works with no database, no network."""

    def kind(self, ip):
        return classify(ip)["kind"]

    def test_rfc1918_ranges_are_private(self):
        for ip in ("10.0.4.15", "172.16.0.1", "192.168.1.5"):
            self.assertEqual(self.kind(ip), "private", ip)

    def test_rfc5737_ranges_are_documentation(self):
        for ip in ("192.0.2.1", "198.51.100.9", "203.0.113.5"):
            self.assertEqual(self.kind(ip), "documentation", ip)

    def test_loopback(self):
        self.assertEqual(self.kind("127.0.0.1"), "loopback")

    def test_carrier_grade_nat(self):
        self.assertEqual(self.kind("100.64.0.1"), "cgnat")

    def test_link_local(self):
        self.assertEqual(self.kind("169.254.1.1"), "link-local")

    def test_multicast(self):
        self.assertEqual(self.kind("239.1.1.1"), "multicast")

    def test_ordinary_public_address(self):
        self.assertEqual(self.kind("8.8.8.8"), "public")

    def test_ipv6_documentation_range(self):
        self.assertEqual(self.kind("2001:db8::1"), "documentation")

    def test_ipv6_public_address(self):
        self.assertEqual(self.kind("2606:4700::1111"), "public")

    def test_garbage_is_reported_as_invalid_not_crashed_on(self):
        record = classify("not-an-ip")
        self.assertEqual(record["kind"], "invalid")
        self.assertFalse(record["routable"])

    def test_a_username_accidentally_passed_in_does_not_raise(self):
        self.assertEqual(classify("admin")["kind"], "invalid")

    def test_only_public_addresses_are_marked_routable(self):
        self.assertTrue(classify("8.8.8.8")["routable"])
        for ip in ("10.0.0.1", "127.0.0.1", "203.0.113.1", "169.254.1.1"):
            self.assertFalse(classify(ip)["routable"], ip)

    def test_version_is_reported(self):
        self.assertEqual(classify("8.8.8.8")["version"], 4)
        self.assertEqual(classify("2606:4700::1111")["version"], 6)


class TestProviderWithoutDatabase(unittest.TestCase):

    def test_no_database_configured_is_reported_not_hidden(self):
        provider = MaxMindProvider("", "")
        self.assertFalse(provider.available)
        self.assertIn("no database", provider.error)

    def test_a_bad_path_reports_the_reason(self):
        provider = MaxMindProvider("/nonexistent/GeoLite2-City.mmdb", "")
        self.assertFalse(provider.available)
        self.assertTrue(provider.error)

    def test_lookup_returns_nothing_rather_than_guessing(self):
        self.assertEqual(MaxMindProvider("", "").lookup("8.8.8.8"), {})


class TestEnricher(unittest.TestCase):

    def setUp(self):
        # Explicitly no database and no DNS, so the test does not depend on
        # the developer's environment or touch the network.
        self.enricher = Enricher(city_db="", asn_db="", reverse_dns=False)

    def test_status_reports_what_is_available(self):
        status = self.enricher.status
        self.assertTrue(status["classification"])
        self.assertFalse(status["geo"])
        self.assertTrue(status["geo_error"])

    def test_classification_is_always_present(self):
        record = self.enricher.lookup("203.0.113.5")
        self.assertEqual(record["kind"], "documentation")
        self.assertEqual(record["ip"], "203.0.113.5")

    def test_no_country_is_invented_without_a_database(self):
        record = self.enricher.lookup("8.8.8.8")
        for invented in ("country", "city", "latitude", "asn",
                         "network_operator"):
            self.assertNotIn(invented, record)

    def test_describe_says_what_is_known_rather_than_unknown_nonsense(self):
        self.assertEqual(self.enricher.describe(self.enricher.lookup("10.0.0.1")),
                         "Private network (RFC 1918)")

    def test_describe_handles_an_empty_record(self):
        self.assertEqual(self.enricher.describe({}), "")

    def test_describe_prefers_city_and_country_when_present(self):
        text = Enricher.describe({"kind": "public", "city": "Bengaluru",
                                  "country": "India", "asn": 4755,
                                  "network_operator": "TATA"})
        self.assertIn("Bengaluru, India", text)
        self.assertIn("AS4755 TATA", text)

    def test_results_are_cached(self):
        first = self.enricher.lookup("8.8.8.8")
        second = self.enricher.lookup("8.8.8.8")
        self.assertIs(first, second)

    def test_enrich_findings_covers_only_ip_pivots(self):
        from detector import Finding, MEDIUM
        findings = [
            Finding("burst", "ip", "203.0.113.5", MEDIUM, ""),
            Finding("burst", "user", "root", MEDIUM, ""),
            Finding("burst", "subnet", "203.0.113.0/24", MEDIUM, ""),
        ]
        enriched = self.enricher.enrich_findings(findings)
        self.assertEqual(set(enriched), {"203.0.113.5"})

    def test_non_routable_addresses_skip_the_lookup_path(self):
        # Private addresses have no geography worth asking about.
        record = self.enricher.lookup("192.168.1.1")
        self.assertFalse(record["routable"])
        self.assertNotIn("hostname", record)


if __name__ == "__main__":
    unittest.main(verbosity=2)
