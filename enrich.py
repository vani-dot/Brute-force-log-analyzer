# enrich.py
# ONE JOB: say something useful about an IP address beyond its digits.
#
# Two layers, and the distinction matters:
#
#   1. CLASSIFICATION — derived from the address itself using the IANA special
#      registries. Always available, needs no database and no network, and is
#      not a guess: 10.0.4.15 IS private, 203.0.113.5 IS a documentation
#      address. This layer never invents anything.
#
#   2. GEO / ASN — country, city and network operator. Requires MaxMind
#      GeoLite2 databases, which are free but must be downloaded and are
#      deliberately NOT bundled. Without them these fields are absent, not
#      faked. An unknown location is reported as unknown.
#
# Set BFLA_GEOIP_CITY_DB and BFLA_GEOIP_ASN_DB to enable layer 2.

import ipaddress
import json
import socket
import urllib.error
import urllib.parse
import urllib.request

from config import config

try:
    import geoip2.database
    GEOIP2_AVAILABLE = True
except ImportError:
    GEOIP2_AVAILABLE = False


# Special-purpose ranges worth naming, from the IANA registries.
# Checked before the generic private/global tests because they are more
# specific and more informative.
SPECIAL_RANGES = [
    ("192.0.2.0/24", "documentation", "TEST-NET-1 (RFC 5737)"),
    ("198.51.100.0/24", "documentation", "TEST-NET-2 (RFC 5737)"),
    ("203.0.113.0/24", "documentation", "TEST-NET-3 (RFC 5737)"),
    ("2001:db8::/32", "documentation", "IPv6 documentation (RFC 3849)"),
    ("100.64.0.0/10", "cgnat", "Carrier-grade NAT (RFC 6598)"),
    ("169.254.0.0/16", "link-local", "Link-local (RFC 3927)"),
    ("192.88.99.0/24", "special", "6to4 relay anycast (RFC 7526)"),
    ("198.18.0.0/15", "benchmark", "Benchmarking (RFC 2544)"),
    ("224.0.0.0/4", "multicast", "Multicast (RFC 5771)"),
]

_COMPILED = [(ipaddress.ip_network(cidr), kind, label)
             for cidr, kind, label in SPECIAL_RANGES]


def classify(ip_text):
    """What kind of address is this? Derived, never guessed."""
    try:
        address = ipaddress.ip_address(ip_text)
    except ValueError:
        return {"kind": "invalid", "label": "not an IP address",
                "version": None, "routable": False}

    for network, kind, label in _COMPILED:
        if address.version == network.version and address in network:
            return {"kind": kind, "label": label,
                    "version": address.version, "routable": False}

    if address.is_loopback:
        return {"kind": "loopback", "label": "Loopback",
                "version": address.version, "routable": False}
    if address.is_private:
        return {"kind": "private", "label": "Private network (RFC 1918)",
                "version": address.version, "routable": False}
    if address.is_reserved:
        return {"kind": "reserved", "label": "Reserved",
                "version": address.version, "routable": False}

    return {"kind": "public", "label": "Public internet",
            "version": address.version, "routable": True}


class MaxMindProvider:
    """Geo and ASN from GeoLite2 .mmdb files, if the user supplied them."""

    def __init__(self, city_db="", asn_db=""):
        self.city_reader = None
        self.asn_reader = None
        self.error = None

        if not (city_db or asn_db):
            self.error = "no database configured"
            return
        if not GEOIP2_AVAILABLE:
            self.error = "geoip2 not installed (pip install geoip2)"
            return

        try:
            if city_db:
                self.city_reader = geoip2.database.Reader(city_db)
            if asn_db:
                self.asn_reader = geoip2.database.Reader(asn_db)
        except (OSError, ValueError) as exc:
            self.error = f"could not open database: {exc}"

    @property
    def available(self):
        return self.city_reader is not None or self.asn_reader is not None

    def lookup(self, ip_text):
        record = {}
        if self.city_reader is not None:
            try:
                city = self.city_reader.city(ip_text)
                record["country"] = city.country.name
                record["country_code"] = city.country.iso_code
                record["city"] = city.city.name
                if city.location.latitude is not None:
                    record["latitude"] = city.location.latitude
                    record["longitude"] = city.location.longitude
            except Exception:
                # Address genuinely not in the database. Absent, not faked.
                pass
        if self.asn_reader is not None:
            try:
                asn = self.asn_reader.asn(ip_text)
                record["asn"] = asn.autonomous_system_number
                record["network_operator"] = asn.autonomous_system_organization
            except Exception:
                pass
        return record

    def close(self):
        for reader in (self.city_reader, self.asn_reader):
            if reader is not None:
                reader.close()


class ReverseDNSProvider:
    """Asks your resolver what name an address claims. No third party."""

    name = "rdns"
    label = "Reverse DNS"
    description = ("Asks your own DNS resolver for the PTR record. The query "
                   "goes to whichever resolver this machine uses.")
    needs_network = True
    sends_data_offsite = False

    def __init__(self, timeout=None):
        self.timeout = (config.reverse_dns_timeout if timeout is None
                        else timeout)

    @property
    def available(self):
        return True

    @property
    def error(self):
        return ""

    def lookup(self, ip_text):
        previous = socket.getdefaulttimeout()
        try:
            socket.setdefaulttimeout(self.timeout)
            hostname, aliases, _ = socket.gethostbyaddr(ip_text)
            record = {"hostname": hostname}
            if aliases:
                record["aliases"] = aliases
            return record
        except (OSError, socket.herror, socket.gaierror):
            # No PTR record is the normal case for most addresses.
            return {}
        finally:
            socket.setdefaulttimeout(previous)


class OnlineProvider:
    """Country, city and network operator from a free public API.

    OFF BY DEFAULT AND OPT-IN PER REQUEST. Looking an address up here tells a
    third party which addresses you are investigating, which is itself
    information worth protecting. Nothing is sent unless the operator asks for
    this provider by name.

    Uses ip-api.com, which needs no key. Private and documentation ranges are
    never sent — they mean nothing to a geolocation service and sending them
    would leak your internal addressing for no benefit.
    """

    name = "online"
    label = "Online lookup (ip-api.com)"
    description = ("Queries a free public geolocation API. Sends the address "
                   "to a third party — off unless you pick it.")
    needs_network = True
    sends_data_offsite = True
    ENDPOINT = "http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,city,regionName,lat,lon,isp,org,as,asname,reverse,proxy,hosting"

    def __init__(self, timeout=4.0):
        self.timeout = timeout

    @property
    def available(self):
        return True

    @property
    def error(self):
        return ""

    def lookup(self, ip_text):
        url = self.ENDPOINT.format(ip=urllib.parse.quote(ip_text, safe=""))
        request = urllib.request.Request(
            url, headers={"User-Agent": "brute-force-log-analyzer"})
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                payload = json.loads(response.read().decode("utf-8"))
        except (urllib.error.URLError, OSError, ValueError, TimeoutError) as exc:
            return {"lookup_error": f"{type(exc).__name__}: {exc}"}

        if payload.get("status") != "success":
            return {"lookup_error": payload.get("message", "lookup failed")}

        record = {}
        mapping = {
            "country": "country", "countryCode": "country_code",
            "city": "city", "regionName": "region",
            "lat": "latitude", "lon": "longitude",
            "isp": "isp", "org": "organisation",
            "asname": "network_operator", "reverse": "hostname",
        }
        for source_key, target_key in mapping.items():
            value = payload.get(source_key)
            if value not in (None, ""):
                record[target_key] = value

        # "AS15169 Google LLC" -> 15169
        as_field = payload.get("as") or ""
        if as_field.startswith("AS"):
            number = as_field[2:].split()[0] if len(as_field) > 2 else ""
            if number.isdigit():
                record["asn"] = int(number)

        for flag in ("proxy", "hosting"):
            if payload.get(flag):
                record[flag] = True
        return record


class Enricher:
    """Adds what is known about an address, and nothing that is not.

    Results are cached: a burst of 400 failures from one IP is one lookup.
    """

    def __init__(self, city_db=None, asn_db=None, reverse_dns=None,
                 rdns_timeout=None):
        self.provider = MaxMindProvider(
            city_db if city_db is not None else config.geoip_city_db,
            asn_db if asn_db is not None else config.geoip_asn_db)
        self.reverse_dns = (config.reverse_dns if reverse_dns is None
                            else reverse_dns)
        self.rdns_timeout = (config.reverse_dns_timeout
                             if rdns_timeout is None else rdns_timeout)
        self._cache = {}
        self._rdns_provider = ReverseDNSProvider(self.rdns_timeout)
        self._online_provider = OnlineProvider()

    # ---- explicit, operator-chosen lookups ---------------------------

    def providers(self):
        """The lookup methods on offer, and whether each can run."""
        return [
            {"name": "builtin", "label": "Built in (offline)",
             "description": ("Derived from the address itself using the IANA "
                             "registries. Instant, no network, always correct "
                             "about what kind of address it is."),
             "available": True, "error": "",
             "needs_network": False, "sends_data_offsite": False},
            {"name": "maxmind", "label": "MaxMind GeoLite2 (offline database)",
             "description": ("Country, city and network operator from local "
                             ".mmdb files. Nothing leaves this machine."),
             "available": self.provider.available,
             "error": "" if self.provider.available else self.provider.error,
             "needs_network": False, "sends_data_offsite": False},
            {"name": "rdns", "label": self._rdns_provider.label,
             "description": self._rdns_provider.description,
             "available": True, "error": "",
             "needs_network": True, "sends_data_offsite": False},
            {"name": "online", "label": self._online_provider.label,
             "description": self._online_provider.description,
             "available": True, "error": "",
             "needs_network": True, "sends_data_offsite": True},
        ]

    def investigate(self, ip_text, methods=("builtin",)):
        """Look one address up with exactly the methods asked for.

        Returns what each method said separately, so the operator can see
        which source a claim came from rather than a merged blob of
        unattributed facts.
        """
        methods = [m for m in methods if m in
                   {"builtin", "maxmind", "rdns", "online"}] or ["builtin"]

        base = dict(classify(ip_text))
        base["ip"] = ip_text
        results = {"ip": ip_text, "classification": base, "methods": {}}

        for method in methods:
            if method == "builtin":
                results["methods"]["builtin"] = {"ok": True, "data": base}

            elif method == "maxmind":
                if not self.provider.available:
                    results["methods"]["maxmind"] = {
                        "ok": False, "error": self.provider.error, "data": {}}
                else:
                    results["methods"]["maxmind"] = {
                        "ok": True, "data": self.provider.lookup(ip_text)}

            elif method == "rdns":
                data = self._rdns_provider.lookup(ip_text)
                results["methods"]["rdns"] = {
                    "ok": bool(data), "data": data,
                    "error": "" if data else "no PTR record"}

            elif method == "online":
                # Refuse to send anything that is not routable. A private or
                # documentation address means nothing to a geolocation service,
                # and sending it would leak internal addressing for no benefit.
                if not base.get("routable"):
                    results["methods"]["online"] = {
                        "ok": False, "data": {},
                        "error": (f"not sent — {base.get('label', 'this address')} "
                                  f"is not routable on the internet")}
                else:
                    data = self._online_provider.lookup(ip_text)
                    error = data.pop("lookup_error", "")
                    results["methods"]["online"] = {
                        "ok": not error and bool(data), "data": data,
                        "error": error or ("" if data else "no data returned")}

        merged = {}
        for method in ("builtin", "maxmind", "rdns", "online"):
            entry = results["methods"].get(method)
            if entry and entry.get("ok"):
                merged.update(entry["data"])
        results["merged"] = merged
        results["summary"] = self.describe(merged) or base.get("label", "")
        return results

    @property
    def geo_available(self):
        return self.provider.available

    @property
    def status(self):
        return {
            "classification": True,          # always works
            "geo": self.provider.available,
            "geo_error": self.provider.error,
            "reverse_dns": self.reverse_dns,
        }

    def _rdns(self, ip_text):
        previous = socket.getdefaulttimeout()
        try:
            socket.setdefaulttimeout(self.rdns_timeout)
            return socket.gethostbyaddr(ip_text)[0]
        except (OSError, socket.herror, socket.gaierror):
            return None
        finally:
            socket.setdefaulttimeout(previous)

    def lookup(self, ip_text):
        if ip_text in self._cache:
            return self._cache[ip_text]

        record = {"ip": ip_text}
        record.update(classify(ip_text))

        # Only look up addresses that could actually be on the internet.
        # A private or documentation address has no meaningful geography, and
        # asking a database about one wastes a lookup to learn nothing.
        if record["routable"]:
            record.update(self.provider.lookup(ip_text))
            if self.reverse_dns:
                hostname = self._rdns(ip_text)
                if hostname:
                    record["hostname"] = hostname

        self._cache[ip_text] = record
        return record

    def enrich_findings(self, findings):
        """{key: enrichment} for every IP-pivoted finding.

        Username and subnet findings are skipped: a username has no geography,
        and a /24 would need its own aggregate lookup to mean anything.
        """
        out = {}
        for finding in findings:
            if finding.pivot == "ip":
                out[finding.key] = self.lookup(finding.key)
        return out

    @staticmethod
    def describe(record):
        """One short human-readable line. Says 'unknown' when it is."""
        if not record:
            return ""
        if record.get("kind") == "invalid":
            return "not an IP address"

        parts = []
        if record.get("city") and record.get("country"):
            parts.append(f"{record['city']}, {record['country']}")
        elif record.get("country"):
            parts.append(record["country"])

        if record.get("network_operator"):
            asn = f"AS{record['asn']}" if record.get("asn") else ""
            parts.append(f"{asn} {record['network_operator']}".strip())

        if record.get("hostname"):
            parts.append(record["hostname"])

        if not parts:
            # No geo data. Say what IS known rather than inventing a location.
            return record.get("label", "unknown")
        return " · ".join(parts)
