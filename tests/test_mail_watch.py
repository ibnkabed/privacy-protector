import json
import tempfile
import unittest
from datetime import datetime
from pathlib import Path
from unittest import mock

from mail_watch import MailWatch, assess_mail, body_markers, bulk_markers

BLOCKED = {"tracker.example", "spam-sender.example"}


def verdict(domain):
    return "red" if domain in BLOCKED else "green"


def mail(**fields):
    return {"id": "m1", "at": datetime.now().astimezone().isoformat(), "subject": "Hello",
            "sender": "friend@good.example", "links": [], "attachments": [], **fields}


class AssessMailTests(unittest.TestCase):
    def test_clean(self):
        self.assertEqual(assess_mail(mail(links=["good.example", "docs.example"]), verdict)["verdict"], "clean")

    def test_tracking_links_are_promo_not_danger(self):
        got = assess_mail(mail(links=["tracker.example", "good.example"]), verdict)
        self.assertEqual(got["verdict"], "promo")
        self.assertEqual(got["trackers"], ["tracker.example"])

    def test_runnable_attachment_is_danger(self):
        for name in ("invoice.exe", "Scan.PDF.js", "report.docm", "photo.iso"):
            self.assertEqual(assess_mail(mail(attachments=[name]), verdict)["verdict"], "danger", name)
        self.assertEqual(assess_mail(mail(attachments=["report.pdf", "photo.jpg"]), verdict)["verdict"], "clean")

    def test_blocked_sender_domain_is_danger(self):
        got = assess_mail(mail(sender="x@spam-sender.example"), verdict)
        self.assertEqual(got["verdict"], "danger")
        self.assertIn("spam-sender.example", got["reasons"][0])

    def test_body_is_never_kept(self):
        got = assess_mail(mail(body="secret text", HTMLBody="<p>secret</p>"), verdict)
        self.assertNotIn("secret", json.dumps(got))


class BulkTests(unittest.TestCase):
    def test_newsletter_headers_are_promo(self):
        headers = "From: shop@x.example\r\nList-Unsubscribe: <mailto:u@x.example>\r\nPrecedence: bulk\r\n"
        self.assertEqual(bulk_markers(headers), ["list-unsubscribe", "precedence"])
        self.assertEqual(assess_mail(mail(bulk=bulk_markers(headers)), verdict)["verdict"], "promo")

    def test_sending_service_alone_is_not_promo(self):
        # Security alerts and invoices also pass through SendGrid and Google
        headers = "Feedback-ID: 1:2:google\r\nX-SG-EID: abc\r\nPrecedence: first-class\r\n"
        self.assertEqual(bulk_markers(headers), [])

    def test_headers_text_is_never_kept(self):
        got = assess_mail(mail(bulk=bulk_markers("List-Id: secret-list <x>\r\n")), verdict)
        self.assertNotIn("secret", json.dumps(got))


class KindTests(unittest.TestCase):
    """حالات حقيقية من سجل البريد (2026-10-29 إلى 2026-10-31)."""

    def kind(self, subject, sender="noreply@service.example", **fields):
        return assess_mail(mail(subject=subject, sender=sender, **fields), verdict)["verdict"]

    def test_account_mail_is_clean_even_when_bulk(self):
        bulk = {"bulk": ["list-unsubscribe"], "links": ["tracker.example"]}
        for subject in ("316118 is your one-time passcode", "Email verification code", "Box login from \"Claude\"",
                        "Hi Sam, we noticed a new sign in to your Dropbox account", "Password was changed successfully",
                        "Your receipt from Example", "Your order has shipped", "رمز التحقق الخاص بك"):
            self.assertEqual(self.kind(subject, **bulk), "clean", subject)

    def test_confirm_email_in_body_is_clean(self):
        self.assertEqual(self.kind("Welcome to Windscribe: Let's Get You Set Up", bulk=["list-unsubscribe"],
                                   body=body_markers("Confirm Your Email (Get 10 GB Free)")), "clean")
        self.assertEqual(body_markers("Read our latest product news"), [])

    def test_service_notices_are_clean(self):
        for subject in ("Insufficient Free Quota", "ZipGrade Account Expires Soon",
                        "[Notice] Cloudflare Observability pricing changes starting December 1",
                        "[Incident: 261027-003761] الطلبات أو الإرجاع"):
            self.assertEqual(self.kind(subject, bulk=["list-unsubscribe"], links=["tracker.example"]), "clean", subject)

    def test_marketing_is_promo_even_without_bulk_headers(self):
        self.assertEqual(self.kind("Runpod Weekly: GLM-5.3 at $0.77 per million input tokens", "team@runpod.io"), "promo")
        self.assertEqual(self.kind("All Things Agentic: Wrapped + 2 new hackathons"), "promo")
        self.assertEqual(self.kind("Mistral Large 4 is now open source, with lower pricing"), "promo")
        self.assertEqual(self.kind("We're flipping the script on November 1st", "newsletter@email.rumble.com"), "promo")
        self.assertEqual(self.kind("خصم 50% على كل الخطط"), "promo")

    def test_ci_notifications_are_clean_and_noreply_awareness_is_promo(self):
        # User note 2026-10-31: Verdicts reversed
        bulk = {"bulk": ["list-id", "precedence"]}
        for subject in ("[example/app] Run failed: CI - main (aff4979)", "deploy failed for cinema-taste"):
            self.assertEqual(self.kind(subject, "notifications@github.com", **bulk), "clean", subject)
        # User: Failures and task successes are unimportant; messages to self and Norton Family reports are important
        # User 2026-11-01: Kaggle notebook completion is important
        self.assertEqual(self.kind("Your notebook finished", "kaggle-noreply@google.com"), "clean")
        self.assertEqual(self.kind("Your notebook finished", "kaggle-noreply@google.com", **bulk), "clean")
        self.assertEqual(self.kind("[example/app] Run succeeded: CI - main", "notifications@github.com", **bulk), "promo")
        self.assertEqual(self.kind("Claude Incident - Elevated errors affecting the Gmail connector", "noreply@statuspage.io"), "promo")
        self.assertEqual(self.kind("Users may experience an increase in error rates", "no-reply@status.incident.io"), "promo")
        self.assertEqual(self.kind("Norton Family : Weekly Report - Metib"), "clean")
        self.assertEqual(self.kind("الجديد لك هذا الأسبوع — موسمان جديدان، 5 أعمال قادمة", "someone@example.com"), "clean")
        self.assertEqual(self.kind("كن واعياً", "noreply@alinma.com"), "promo")
        for subject in ("001 تنبيه: خصم مبلغ , حساب رقم", "669393 is your 6-digit code", "fal Payment Failure",
                        "$115.00 payment to Anthropic, PBC was unsuccessful again", "تم إنشاء كلمة سر خاصة بالتطبيق لحساب Apple"):
            self.assertEqual(self.kind(subject, "noreply@bank.example"), "clean", subject)

    def test_pin_and_temporary_codes_are_always_clean(self):
        # User 2026-10-31: PINs and temporary login codes are always important
        noisy = {"bulk": ["list-unsubscribe"], "links": ["tracker.example"]}
        for subject in ("669393 is your 6-digit code", "Use code 041045 to log in", "Your PIN for the weekly sale",
                        "Your Link verification code: 067 443", "Your Cloudflare login token: 9486864", "بنك البلاد كلمة المرور لمرة واحدة", "رمز التحقق في طويق"):
            self.assertEqual(self.kind(subject, "news@em.shop.example", **noisy), "clean", subject)
        self.assertEqual(self.kind("Weekly sale", "noreply@statuspage.io", body=body_markers("Your code is 482913")), "clean")
        self.assertEqual(self.kind("Use promo code SAVE20 for 20% off", "news@em.shop.example"), "promo")

    def test_account_body_and_transactional_subjects_are_clean(self):
        # From reviewing 6 months of texts with user permission
        noisy = {"bulk": ["list-unsubscribe"]}
        for text in ("Your account will be deleted in 5 days", "Download your memories before they are removed",
                     "Your monthly charges will resume at the beginning of your next billing cycle", "سيتم حذف حسابك"):
            self.assertEqual(self.kind("Hello from Snap", "team@e.snap.example", body=body_markers(text), **noisy), "clean", text)
        for subject in ("Online check-in reminder for EMSV6G", "Important Security Update for Plex Media Server",
                        "إشعار هام – تحسين تجربة خدمة العملاء"):
            self.assertEqual(self.kind(subject, "news@em.shop.example", **noisy), "clean", subject)
        # User: "If it wasn't you", policies, and repository comments are unimportant; failures and codes are important
        for subject in ("Re: [openai/codex] Missing rollout leaves a ghost thread", "We're updating our Anthropic Policies",
                        "Updates to our Terms of Service and Privacy Policy", "تحديثات شروط الاستخدام",
                        "Did you just log in near Riyadh on a new device?"):
            self.assertEqual(self.kind(subject, "noreply@service.example", **noisy), "promo", subject)
        self.assertEqual(self.kind("New sign-in to your account", body=body_markers("If this wasn't you, reset now")), "promo")
        self.assertEqual(self.kind("New sign-in", body=body_markers("Your code is 482913. If this wasn't you, ignore")), "clean")
        self.assertEqual(self.kind("[example/app] Run failed: CI - main", "notifications@github.com"), "clean")
        self.assertEqual(self.kind("Your Workers subscription will be canceled on November 7",
                                   body=body_markers("Your subscription will be canceled. If this wasn't you, contact us")), "clean")
        self.assertEqual(self.kind("Five ways to build efficiently", "no-reply@email.claude.com", **noisy), "promo")
        self.assertEqual(self.kind("علي and ع sent you new messages", "informational@email.snapchat.com",
                                   body=body_markers("You have unread messages waiting"), **noisy), "promo")

    def test_security_beats_promo_words(self):
        self.assertEqual(self.kind("Weekly security alert: new login from Chrome"), "clean")

    def test_matched_text_is_never_kept(self):
        got = assess_mail(mail(subject="Email verification code", body=body_markers("secret confirm your email")), verdict)
        self.assertNotIn("secret", json.dumps(got))
class MailWatchTests(unittest.TestCase):
    def test_rule_change_reassesses_unread_once(self):
        class Item:
            Class, SenderEmailAddress, SenderEmailType, Subject = 43, "noreply@windscribe.com", "SMTP", "Welcome to Windscribe"
            HTMLBody, Body, Attachments, UnRead, ReceivedTime = "", "Confirm your email", [], True, datetime.now()
            EntryID = "w1"
            PropertyAccessor = type("PA", (), {"GetProperty": lambda self, name: "List-Unsubscribe: <x>\r\n"})()

        namespace = type("NS", (), {"GetItemFromID": lambda self, entry_id: Item()})()
        with tempfile.TemporaryDirectory() as tmp:
            watch = MailWatch(Path(tmp), verdict)
            watch.unread = {"w1": "promo"}
            watch._reassess_unread(namespace)
            self.assertEqual(watch.unread, {"w1": "clean"})
            watch.unread["w1"] = "promo"
            watch._reassess_unread(namespace)
            self.assertEqual(watch.unread, {"w1": "promo"})


    def test_danger_removed_promo_and_clean_shown_and_logged_once(self):
        removed = []
        badges = []
        with tempfile.TemporaryDirectory() as tmp:
            watch = MailWatch(Path(tmp), verdict, badge=lambda level, tip: badges.append(level))
            watch.state["outlook"] = "running"
            mails = [mail(attachments=["a.exe"]), mail(id="m2", links=["tracker.example"]), mail(id="m3")]
            self.assertEqual(len(watch.handle(mails, removed.append)), 3)
            self.assertEqual(watch.handle(mails, removed.append), [])
            self.assertEqual(removed, ["m1"])
            self.assertEqual(watch.unread, {"m2": "promo", "m3": "clean"})
            watch.paint()
            self.assertEqual(watch.badge_state()[0], "tan")
            del watch.unread["m3"]
            watch.paint()
            del watch.unread["m2"]
            watch.paint()
            self.assertEqual(badges, ["tan", "white", None])
            lines = (Path(tmp) / "mail-watch-events.ndjson").read_text(encoding="utf-8").splitlines()
            self.assertEqual(len(lines), 3)
            self.assertTrue(json.loads(lines[0])["removed"])
            view = MailWatch(Path(tmp), verdict).view()
            self.assertEqual(view["today"], {"danger": 1, "promo": 1, "clean": 1})
            self.assertEqual(len(view["removed"]), 1)

    def test_click_opens_oldest_clean_mail_then_inbox(self):
        class Item:
            Subject, SenderEmailAddress, UnRead = "Your project x-1 has been shut down", "g@x", True

            def __init__(self, opened, entry_id):
                self.opened, self.entry_id = opened, entry_id

            def Display(self):  # noqa: N802
                self.opened.append(self.entry_id)

            def Save(self):  # noqa: N802
                pass

        opened = []
        namespace = type("NS", (), {"GetItemFromID": lambda self, entry_id: Item(opened, entry_id)})()
        with tempfile.TemporaryDirectory() as tmp:
            watch = MailWatch(Path(tmp), verdict)
            watch._show_explorer = lambda app, inbox: opened.append("inbox")
            watch.unread = {"p1": "promo", "c1": "clean", "c2": "clean"}
            # Opened items are marked as read so they don't reappear on the next click
            for _ in range(3):
                watch._open_inbox(None, None, namespace)
            self.assertEqual(opened, ["c1", "c2", "inbox"])
            rows = [json.loads(line) for line in (Path(tmp) / "mail-watch-clicks.ndjson").read_text(encoding="utf-8").splitlines()]
            self.assertEqual([r["opened"] for r in rows], ["message", "message", "inbox"])
            self.assertTrue(rows[1]["seriesWithLast"])

    def test_failed_removal_is_logged_and_never_shown(self):
        def fail(entry_id):
            raise OSError("locked")
        with tempfile.TemporaryDirectory() as tmp:
            watch = MailWatch(Path(tmp), verdict)
            got = watch.handle([mail(attachments=["a.scr"])], fail)[0]
            self.assertFalse(got["removed"])
            self.assertEqual(watch.unread, {})

    def test_read_mail_and_closed_outlook_show_no_envelope(self):
        with tempfile.TemporaryDirectory() as tmp:
            watch = MailWatch(Path(tmp), verdict)
            watch.state["outlook"] = "running"
            watch.handle([mail(unread=False)], lambda _: None)
            self.assertEqual(watch.badge_state(), (None, ""))
            watch.handle([mail(id="m9")], lambda _: None)
            watch.state["outlook"] = "closed"
            self.assertEqual(watch.badge_state(), (None, ""))
if __name__ == "__main__":
    unittest.main()


class ClickLogTests(unittest.TestCase):
    def test_click_log_marks_series_and_repeats(self):
        with tempfile.TemporaryDirectory() as folder:
            watch = MailWatch(Path(folder), verdict)
            first = watch.log_click({"id": "a", "subject": "Your project alpha-123 has been shut down", "sender": "g@x"}, None)
            second = watch.log_click({"id": "b", "subject": "Your project beta-456 has been shut down", "sender": "g@x"}, False)
            third = watch.log_click({"id": "b", "subject": "Your project beta-456 has been shut down", "sender": "g@x"}, True)
            self.assertFalse(first["sameAsLast"] or first["seriesWithLast"])
            self.assertTrue(second["seriesWithLast"])
            self.assertTrue(third["sameAsLast"] and third["lastStillUnread"])
            rows = (Path(folder) / "mail-watch-clicks.ndjson").read_text(encoding="utf-8").splitlines()
            self.assertEqual(len(rows), 3)
