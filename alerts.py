# alerts.py
# ONE JOB: get a finding in front of a human, now.
#
# Three channels, all optional. A channel with no credentials reports itself
# as not ready and is skipped — it never silently swallows an alert, and the
# UI can say exactly which variable would switch it on.
#
# Standard library only: urllib for HTTP, smtplib for mail. No new packages.
#
# Two things stop this becoming a nuisance:
#   severity floor - MEDIUM bursts are constant on an exposed host; by default
#                    only HIGH (an actual compromise) is worth waking someone.
#   cooldown       - the same offender does not alert twice within the window,
#                    so a persistent attacker produces one message, not four
#                    hundred.

import json
import smtplib
import ssl
import time
import urllib.error
import urllib.request
from email.message import EmailMessage

from config import config

SEVERITY_ORDER = {"MEDIUM": 1, "HIGH": 2}


class AlertResult:
    """What happened when we tried to send. Never raises at the caller."""

    __slots__ = ("channel", "ok", "skipped", "reason")

    def __init__(self, channel, ok=False, skipped=False, reason=""):
        self.channel = channel
        self.ok = ok
        self.skipped = skipped
        self.reason = reason

    def to_dict(self):
        return {"channel": self.channel, "ok": self.ok,
                "skipped": self.skipped, "reason": self.reason}

    def __repr__(self):
        state = "sent" if self.ok else ("skipped" if self.skipped else "failed")
        return f"AlertResult({self.channel} {state}: {self.reason})"


class AlertChannel:
    """Base class. Subclasses implement ready, missing_setting and deliver."""

    name = "channel"

    @property
    def ready(self):
        raise NotImplementedError

    @property
    def missing_setting(self):
        return ""

    def deliver(self, finding, context):
        raise NotImplementedError

    def send(self, finding, context=None):
        if not self.ready:
            return AlertResult(self.name, skipped=True,
                               reason=f"not configured — set {self.missing_setting}")
        try:
            self.deliver(finding, context or {})
            return AlertResult(self.name, ok=True, reason="delivered")
        except Exception as exc:
            # A failing alert channel must never take down the detector.
            return AlertResult(self.name, reason=f"{type(exc).__name__}: {exc}")


def _post_json(url, payload, timeout):
    body = json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(
        url, data=body, method="POST",
        headers={"Content-Type": "application/json",
                 "User-Agent": "brute-force-log-analyzer"})
    context = ssl.create_default_context()
    with urllib.request.urlopen(request, timeout=timeout,
                                context=context) as response:
        return response.status


class SlackChannel(AlertChannel):
    name = "slack"

    def __init__(self, webhook_url=None, timeout=None):
        self.webhook_url = (config.slack_webhook_url if webhook_url is None
                            else webhook_url)
        self.timeout = config.webhook_timeout if timeout is None else timeout

    @property
    def ready(self):
        return bool(self.webhook_url)

    @property
    def missing_setting(self):
        return "BFLA_SLACK_WEBHOOK_URL"

    def deliver(self, finding, context):
        icon = ":rotating_light:" if finding.severity == "HIGH" else ":warning:"
        source = context.get("source", "log")
        where = context.get("location", "")

        lines = [f"*{finding.pivot}* `{finding.key}`", finding.detail]
        if where:
            lines.append(f"_{where}_")
        if context.get("times_seen", 0) > 1:
            lines.append(f"Seen in {context['times_seen']} previous analyses.")

        _post_json(self.webhook_url, {
            "text": f"{icon} {finding.severity}: {finding.key} — {finding.detail}",
            "blocks": [
                {"type": "header",
                 "text": {"type": "plain_text",
                          "emoji": True,
                          "text": f"{icon} {finding.severity} — SSH {finding.type}"}},
                {"type": "section",
                 "text": {"type": "mrkdwn", "text": "\n".join(lines)}},
                {"type": "context",
                 "elements": [{"type": "mrkdwn", "text": f"source: `{source}`"}]},
            ],
        }, self.timeout)


class WebhookChannel(AlertChannel):
    """POSTs the finding as JSON anywhere — SIEM, n8n, a Lambda, whatever."""

    name = "webhook"

    def __init__(self, url=None, timeout=None):
        self.url = config.webhook_url if url is None else url
        self.timeout = config.webhook_timeout if timeout is None else timeout

    @property
    def ready(self):
        return bool(self.url)

    @property
    def missing_setting(self):
        return "BFLA_WEBHOOK_URL"

    def deliver(self, finding, context):
        _post_json(self.url, {
            "tool": "brute-force-log-analyzer",
            "sent_at": time.time(),
            "finding": finding.to_dict(),
            "context": context,
        }, self.timeout)


class EmailChannel(AlertChannel):
    name = "email"

    def __init__(self, host=None, port=None, user=None, password=None,
                 use_tls=None, sender=None, recipients=None):
        self.host = config.smtp_host if host is None else host
        self.port = config.smtp_port if port is None else port
        self.user = config.smtp_user if user is None else user
        self.password = config.smtp_password if password is None else password
        self.use_tls = config.smtp_use_tls if use_tls is None else use_tls
        self.sender = config.mail_from if sender is None else sender
        self.recipients = (list(config.mail_to) if recipients is None
                           else list(recipients))

    @property
    def ready(self):
        return bool(self.host and self.sender and self.recipients)

    @property
    def missing_setting(self):
        return "BFLA_SMTP_HOST, BFLA_MAIL_FROM and BFLA_MAIL_TO"

    def build_message(self, finding, context):
        message = EmailMessage()
        message["Subject"] = (f"[{finding.severity}] SSH {finding.type} — "
                              f"{finding.key}")
        message["From"] = self.sender
        message["To"] = ", ".join(self.recipients)

        body = [
            f"Severity : {finding.severity}",
            f"Type     : {finding.type}",
            f"Pivot    : {finding.pivot}",
            f"Key      : {finding.key}",
            f"Detail   : {finding.detail}",
            f"Source   : {context.get('source', 'log')}",
        ]
        if context.get("location"):
            body.append(f"Location : {context['location']}")
        if context.get("times_seen", 0) > 1:
            body.append(f"History  : seen in {context['times_seen']} "
                        f"previous analyses")
        body.append("")
        body.append("-- brute-force-log-analyzer")
        message.set_content("\n".join(body))
        return message

    def deliver(self, finding, context):
        message = self.build_message(finding, context)
        with smtplib.SMTP(self.host, self.port, timeout=10) as server:
            if self.use_tls:
                server.starttls(context=ssl.create_default_context())
            if self.user:
                server.login(self.user, self.password)
            server.send_message(message)


class AlertDispatcher:
    """Decides what deserves an alert, then sends it everywhere configured."""

    def __init__(self, channels=None, storage=None, min_severity=None,
                 cooldown_seconds=None):
        self.channels = (channels if channels is not None
                         else [SlackChannel(), WebhookChannel(), EmailChannel()])
        self.storage = storage
        self.min_severity = (config.alert_min_severity if min_severity is None
                             else min_severity).upper()
        self.cooldown = (config.alert_cooldown_seconds
                         if cooldown_seconds is None else cooldown_seconds)
        # Fallback when no storage is attached, so cooldown still works.
        self._last_sent = {}

    @property
    def ready_channels(self):
        return [c for c in self.channels if c.ready]

    @property
    def enabled(self):
        return bool(self.ready_channels)

    def status(self):
        return {
            "enabled": self.enabled,
            "min_severity": self.min_severity,
            "cooldown_seconds": self.cooldown,
            "channels": [
                {"name": c.name, "ready": c.ready,
                 "missing": "" if c.ready else c.missing_setting}
                for c in self.channels
            ],
        }

    def meets_severity(self, finding):
        return (SEVERITY_ORDER.get(finding.severity, 0)
                >= SEVERITY_ORDER.get(self.min_severity, 2))

    def in_cooldown(self, key, now):
        if self.cooldown <= 0:
            return False
        last = None
        if self.storage is not None:
            last = self.storage.last_alert_time(key)
        if last is None:
            last = self._last_sent.get(key)
        return last is not None and (now - last) < self.cooldown

    def dispatch(self, finding, context=None, now=None):
        """Returns a list of AlertResult, one per channel that was tried."""
        now = time.time() if now is None else now

        if not self.meets_severity(finding):
            return [AlertResult("dispatcher", skipped=True,
                                reason=f"{finding.severity} below "
                                       f"{self.min_severity}")]
        if self.in_cooldown(finding.key, now):
            return [AlertResult("dispatcher", skipped=True,
                                reason=f"cooldown — {finding.key} alerted "
                                       f"within {self.cooldown}s")]
        if not self.ready_channels:
            return [AlertResult("dispatcher", skipped=True,
                                reason="no channel configured")]

        results = []
        for channel in self.ready_channels:
            result = channel.send(finding, context)
            results.append(result)
            if self.storage is not None:
                self.storage.record_alert(finding.key, finding.severity,
                                          channel.name, result.ok,
                                          result.reason, now)

        if any(r.ok for r in results):
            self._last_sent[finding.key] = now
        return results

    def dispatch_many(self, findings, context=None, now=None):
        return {f.key: self.dispatch(f, context, now) for f in findings}
