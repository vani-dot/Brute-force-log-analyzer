# test_alerts.py
# Tests for alert delivery.
#
# A real HTTP server is stood up on a loopback port for the webhook tests, so
# "it sends" is demonstrated rather than mocked. Email is tested by inspecting
# the message that would be sent, without an SMTP server.

import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer

from alerts import (AlertDispatcher, AlertResult, EmailChannel, SlackChannel,
                    WebhookChannel)
from detector import Finding, HIGH, MEDIUM
from storage import Storage


class Receiver:
    """A throwaway HTTP server that records what it was sent."""

    def __init__(self, status=200):
        self.received = []
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                length = int(self.headers.get("Content-Length", 0))
                outer.received.append({
                    "path": self.path,
                    "body": json.loads(self.rfile.read(length) or b"{}"),
                })
                self.send_response(status)
                self.end_headers()

            def log_message(self, *args):
                pass

        self.server = HTTPServer(("127.0.0.1", 0), Handler)
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever,
                                       daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *exc):
        self.server.shutdown()

    def url(self, path="/hook"):
        return f"http://127.0.0.1:{self.port}{path}"


HIGH_FINDING = Finding("compromise", "ip", "198.51.100.31", HIGH,
                       "4 failure(s) across 4 usernames then SUCCESS")
MEDIUM_FINDING = Finding("burst", "ip", "192.0.2.7", MEDIUM,
                         "25 failures in 60s")


class TestChannelReadiness(unittest.TestCase):
    """An unconfigured channel must say so, never silently drop an alert."""

    def test_slack_without_a_url_is_not_ready(self):
        channel = SlackChannel(webhook_url="")
        self.assertFalse(channel.ready)
        self.assertIn("BFLA_SLACK_WEBHOOK_URL", channel.missing_setting)

    def test_webhook_without_a_url_is_not_ready(self):
        self.assertFalse(WebhookChannel(url="").ready)

    def test_email_needs_host_sender_and_recipients(self):
        self.assertFalse(EmailChannel(host="", sender="a@b.c",
                                      recipients=["d@e.f"]).ready)
        self.assertFalse(EmailChannel(host="mail", sender="",
                                      recipients=["d@e.f"]).ready)
        self.assertFalse(EmailChannel(host="mail", sender="a@b.c",
                                      recipients=[]).ready)
        self.assertTrue(EmailChannel(host="mail", sender="a@b.c",
                                     recipients=["d@e.f"]).ready)

    def test_sending_on_an_unready_channel_is_skipped_with_a_reason(self):
        result = SlackChannel(webhook_url="").send(HIGH_FINDING)
        self.assertTrue(result.skipped)
        self.assertFalse(result.ok)
        self.assertIn("BFLA_SLACK_WEBHOOK_URL", result.reason)


class TestWebhookDelivery(unittest.TestCase):

    def test_webhook_actually_posts_the_finding(self):
        with Receiver() as receiver:
            result = WebhookChannel(url=receiver.url()).send(
                HIGH_FINDING, {"source": "test.log"})
            self.assertTrue(result.ok, result.reason)
            self.assertEqual(len(receiver.received), 1)
            body = receiver.received[0]["body"]
            self.assertEqual(body["finding"]["key"], "198.51.100.31")
            self.assertEqual(body["finding"]["severity"], HIGH)
            self.assertEqual(body["context"]["source"], "test.log")

    def test_slack_payload_has_text_and_blocks(self):
        with Receiver() as receiver:
            SlackChannel(webhook_url=receiver.url("/slack")).send(
                HIGH_FINDING, {"source": "test.log", "location": "Testland"})
            body = receiver.received[0]["body"]
            self.assertIn("198.51.100.31", body["text"])
            self.assertTrue(body["blocks"])

    def test_slack_mentions_prior_sightings_when_there_are_any(self):
        with Receiver() as receiver:
            SlackChannel(webhook_url=receiver.url()).send(
                HIGH_FINDING, {"times_seen": 6})
            text = json.dumps(receiver.received[0]["body"])
            self.assertIn("6 previous", text)

    def test_a_server_error_is_reported_not_raised(self):
        with Receiver(status=500) as receiver:
            result = WebhookChannel(url=receiver.url()).send(HIGH_FINDING)
            self.assertFalse(result.ok)
            self.assertFalse(result.skipped)
            self.assertTrue(result.reason)

    def test_an_unreachable_host_is_reported_not_raised(self):
        result = WebhookChannel(url="http://127.0.0.1:1/hook",
                                timeout=0.5).send(HIGH_FINDING)
        self.assertFalse(result.ok)
        self.assertIn("Error", result.reason)


class TestEmailMessage(unittest.TestCase):

    def channel(self):
        return EmailChannel(host="mail.example.com", sender="bfla@example.com",
                            recipients=["soc@example.com", "ops@example.com"])

    def test_subject_carries_severity_and_key(self):
        message = self.channel().build_message(HIGH_FINDING, {})
        self.assertIn("HIGH", message["Subject"])
        self.assertIn("198.51.100.31", message["Subject"])

    def test_all_recipients_are_addressed(self):
        message = self.channel().build_message(HIGH_FINDING, {})
        self.assertIn("soc@example.com", message["To"])
        self.assertIn("ops@example.com", message["To"])

    def test_body_includes_the_detail_and_context(self):
        message = self.channel().build_message(
            HIGH_FINDING, {"source": "auth.log", "location": "Testland",
                           "times_seen": 3})
        body = message.get_content()
        self.assertIn("4 failure(s)", body)
        self.assertIn("auth.log", body)
        self.assertIn("Testland", body)
        self.assertIn("3 previous", body)


class TestDispatcher(unittest.TestCase):

    def dispatcher(self, receiver, **kwargs):
        return AlertDispatcher(
            channels=[WebhookChannel(url=receiver.url())], **kwargs)

    def test_severity_floor_blocks_medium_by_default(self):
        with Receiver() as receiver:
            results = self.dispatcher(receiver, min_severity=HIGH).dispatch(
                MEDIUM_FINDING)
            self.assertTrue(results[0].skipped)
            self.assertEqual(receiver.received, [])

    def test_lowering_the_floor_lets_medium_through(self):
        with Receiver() as receiver:
            results = self.dispatcher(receiver, min_severity=MEDIUM,
                                      cooldown_seconds=0).dispatch(MEDIUM_FINDING)
            self.assertTrue(results[0].ok, results[0].reason)
            self.assertEqual(len(receiver.received), 1)

    def test_cooldown_suppresses_a_repeat_of_the_same_key(self):
        with Receiver() as receiver:
            dispatcher = self.dispatcher(receiver, cooldown_seconds=600)
            first = dispatcher.dispatch(HIGH_FINDING, now=1000)
            second = dispatcher.dispatch(HIGH_FINDING, now=1100)
            self.assertTrue(first[0].ok)
            self.assertTrue(second[0].skipped)
            self.assertIn("cooldown", second[0].reason)
            self.assertEqual(len(receiver.received), 1)

    def test_cooldown_expires(self):
        with Receiver() as receiver:
            dispatcher = self.dispatcher(receiver, cooldown_seconds=600)
            dispatcher.dispatch(HIGH_FINDING, now=1000)
            again = dispatcher.dispatch(HIGH_FINDING, now=2000)
            self.assertTrue(again[0].ok, again[0].reason)
            self.assertEqual(len(receiver.received), 2)

    def test_a_different_key_is_not_suppressed(self):
        with Receiver() as receiver:
            dispatcher = self.dispatcher(receiver, cooldown_seconds=600)
            dispatcher.dispatch(HIGH_FINDING, now=1000)
            other = Finding("compromise", "ip", "1.2.3.4", HIGH, "x")
            self.assertTrue(dispatcher.dispatch(other, now=1001)[0].ok)
            self.assertEqual(len(receiver.received), 2)

    def test_no_configured_channel_is_reported_clearly(self):
        results = AlertDispatcher(channels=[SlackChannel(webhook_url="")]
                                  ).dispatch(HIGH_FINDING)
        self.assertTrue(results[0].skipped)
        self.assertIn("no channel", results[0].reason)

    def test_status_lists_every_channel_and_what_it_needs(self):
        status = AlertDispatcher(channels=[SlackChannel(webhook_url=""),
                                           WebhookChannel(url="")]).status()
        self.assertFalse(status["enabled"])
        self.assertEqual(len(status["channels"]), 2)
        self.assertTrue(all(c["missing"] for c in status["channels"]))

    def test_delivery_is_recorded_in_storage(self):
        store = Storage(":memory:")
        with Receiver() as receiver:
            self.dispatcher(receiver, storage=store,
                            cooldown_seconds=0).dispatch(HIGH_FINDING)
        recent = store.recent_alerts()
        self.assertEqual(len(recent), 1)
        self.assertTrue(recent[0]["ok"])
        store.close()

    def test_cooldown_survives_a_new_dispatcher_via_storage(self):
        # A restarted process must not re-alert on everything it already sent.
        store = Storage(":memory:")
        with Receiver() as receiver:
            first = AlertDispatcher(channels=[WebhookChannel(url=receiver.url())],
                                    storage=store, cooldown_seconds=600)
            first.dispatch(HIGH_FINDING, now=1000)

            fresh = AlertDispatcher(channels=[WebhookChannel(url=receiver.url())],
                                    storage=store, cooldown_seconds=600)
            second = fresh.dispatch(HIGH_FINDING, now=1100)
            self.assertTrue(second[0].skipped)
            self.assertEqual(len(receiver.received), 1)
        store.close()

    def test_one_failing_channel_does_not_stop_the_others(self):
        with Receiver() as receiver:
            dispatcher = AlertDispatcher(
                channels=[WebhookChannel(url="http://127.0.0.1:1/dead",
                                         timeout=0.5),
                          WebhookChannel(url=receiver.url())],
                cooldown_seconds=0)
            results = dispatcher.dispatch(HIGH_FINDING)
            self.assertEqual(len(results), 2)
            self.assertTrue(any(r.ok for r in results))
            self.assertEqual(len(receiver.received), 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
