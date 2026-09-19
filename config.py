# config.py
# Every setting in one place, read from the environment.
#
# Nothing secret is stored in this file. Values you have not supplied stay
# empty, and the feature that needs them reports itself as "not configured"
# rather than failing or, worse, pretending to work.
#
# Supply them by exporting environment variables, or by copying
# .env.example to .env and filling it in.

import os

# .env is optional. Parsed here rather than pulling in python-dotenv, since
# the format we need is KEY=value and nothing more.
ENV_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")


def _load_env_file(path=ENV_FILE):
    if not os.path.exists(path):
        return
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            key, value = key.strip(), value.strip().strip('"').strip("'")
            # A real environment variable always wins over the file.
            os.environ.setdefault(key, value)


_load_env_file()


def _str(name, default=""):
    return os.environ.get(name, default).strip()


def _int(name, default):
    try:
        return int(os.environ.get(name, default))
    except (TypeError, ValueError):
        return default


def _bool(name, default=False):
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in ("1", "true", "yes", "on")


class Config:
    """Reads the environment once, then answers questions about itself."""

    def __init__(self):
        self.reload()

    def reload(self):
        _load_env_file()

        # ---- detection defaults -------------------------------------
        # Empty means "use the detector's own defaults".
        self.threshold = _int("BFLA_THRESHOLD", 0) or None
        self.window = _int("BFLA_WINDOW", 0) or None

        # Sources that must never alert. Comma separated: CIDRs, single
        # addresses, or usernames. Your own office range belongs here.
        self.allowlist = [e.strip() for e in _str("BFLA_ALLOWLIST").split(",")
                          if e.strip()]

        # ---- persistence --------------------------------------------
        self.db_path = _str("BFLA_DB_PATH") or os.path.join(
            os.path.dirname(os.path.abspath(__file__)), "bfla.db")
        self.persist = _bool("BFLA_PERSIST", True)

        # ---- live monitoring ----------------------------------------
        # YOU SUPPLY: the log file to follow, e.g. /var/log/auth.log
        self.watch_path = _str("BFLA_WATCH_PATH")
        self.watch_poll_seconds = float(_str("BFLA_WATCH_POLL", "1.0") or 1.0)
        # How much history the live detector keeps in memory.
        self.watch_retention_seconds = _int("BFLA_WATCH_RETENTION", 7200)

        # ---- geo / ASN enrichment -----------------------------------
        # YOU SUPPLY: paths to MaxMind GeoLite2 .mmdb files.
        # Free after registering at maxmind.com; nothing is bundled here.
        self.geoip_city_db = _str("BFLA_GEOIP_CITY_DB")
        self.geoip_asn_db = _str("BFLA_GEOIP_ASN_DB")
        self.reverse_dns = _bool("BFLA_REVERSE_DNS", False)
        self.reverse_dns_timeout = float(_str("BFLA_RDNS_TIMEOUT", "0.5") or 0.5)

        # ---- alert delivery -----------------------------------------
        # YOU SUPPLY: whichever of these you want to use. All blank = no
        # alerts are sent, and the UI says so plainly.
        self.alert_min_severity = _str("BFLA_ALERT_MIN_SEVERITY", "HIGH").upper()
        self.alert_cooldown_seconds = _int("BFLA_ALERT_COOLDOWN", 900)

        self.slack_webhook_url = _str("BFLA_SLACK_WEBHOOK_URL")
        self.webhook_url = _str("BFLA_WEBHOOK_URL")
        self.webhook_timeout = float(_str("BFLA_WEBHOOK_TIMEOUT", "5") or 5)

        self.smtp_host = _str("BFLA_SMTP_HOST")
        self.smtp_port = _int("BFLA_SMTP_PORT", 587)
        self.smtp_user = _str("BFLA_SMTP_USER")
        self.smtp_password = _str("BFLA_SMTP_PASSWORD")
        self.smtp_use_tls = _bool("BFLA_SMTP_TLS", True)
        self.mail_from = _str("BFLA_MAIL_FROM")
        self.mail_to = [a.strip() for a in _str("BFLA_MAIL_TO").split(",")
                        if a.strip()]

        # ---- web ----------------------------------------------------
        self.port = _int("PORT", 5000)
        self.debug = _bool("BFLA_DEBUG", True)
        self.max_upload_bytes = _int("BFLA_MAX_UPLOAD", 5 * 1024 * 1024)

    # ---- capability questions ---------------------------------------
    # Each returns why a feature is unavailable, so the UI can say
    # "not configured: set BFLA_SLACK_WEBHOOK_URL" instead of silently
    # doing nothing.

    @property
    def slack_ready(self):
        return bool(self.slack_webhook_url)

    @property
    def webhook_ready(self):
        return bool(self.webhook_url)

    @property
    def email_ready(self):
        return bool(self.smtp_host and self.mail_from and self.mail_to)

    @property
    def any_alerting(self):
        return self.slack_ready or self.webhook_ready or self.email_ready

    @property
    def geoip_ready(self):
        return bool(self.geoip_city_db or self.geoip_asn_db)

    @property
    def watch_ready(self):
        return bool(self.watch_path)

    def missing(self):
        """What is not configured, and the variable that would configure it."""
        gaps = []
        if not self.watch_path:
            gaps.append(("Live log monitoring", "BFLA_WATCH_PATH",
                         "path to the log to follow, e.g. /var/log/auth.log"))
        if not self.geoip_city_db:
            gaps.append(("Geo lookup", "BFLA_GEOIP_CITY_DB",
                         "path to GeoLite2-City.mmdb"))
        if not self.geoip_asn_db:
            gaps.append(("ASN lookup", "BFLA_GEOIP_ASN_DB",
                         "path to GeoLite2-ASN.mmdb"))
        if not self.slack_webhook_url:
            gaps.append(("Slack alerts", "BFLA_SLACK_WEBHOOK_URL",
                         "incoming webhook URL from your Slack app"))
        if not self.webhook_url:
            gaps.append(("Webhook alerts", "BFLA_WEBHOOK_URL",
                         "any URL to POST findings to"))
        if not self.email_ready:
            gaps.append(("Email alerts", "BFLA_SMTP_HOST + BFLA_MAIL_FROM + BFLA_MAIL_TO",
                         "your mail server and addresses"))
        return gaps

    def to_dict(self):
        """Safe to serialise: reports readiness, never the secrets."""
        return {
            "allowlist": self.allowlist,
            "persist": self.persist,
            "db_path": os.path.basename(self.db_path),
            "watch_path": self.watch_path,
            "watch_ready": self.watch_ready,
            "geoip_ready": self.geoip_ready,
            "reverse_dns": self.reverse_dns,
            "alerting": {
                "slack": self.slack_ready,
                "webhook": self.webhook_ready,
                "email": self.email_ready,
                "any": self.any_alerting,
                "min_severity": self.alert_min_severity,
                "cooldown_seconds": self.alert_cooldown_seconds,
            },
            "missing": [{"feature": f, "variable": v, "hint": h}
                        for f, v, h in self.missing()],
        }


config = Config()
