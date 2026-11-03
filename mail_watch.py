"""Outlook Protection: Inspects every new message in classic Outlook the moment it arrives.

No 5-minute polling and no PowerShell: a single Python thread in the engine connects to Outlook via COM (pywin32) and sleeps
until Outlook notifies it of a NewMailEx event, consuming nothing between messages. It reads the sender domain, link domains,
attachment names, and bulk mailing headers from the message; the body is neither logged nor sent to any model,
and unknown network domains are not probed because visiting them could alert the sender that the message was opened.

The judgment has three categories:
  - danger: The message is forcefully removed from Outlook (moved to Deleted Items then permanently deleted) without notification, but remains in the log.
  - promo: Advertisement or promotion, so the tray icon remains white like other tray icons.
  - clean: Safe and worth reading, so the tray icon turns light brown, matching the Outlook envelope color.
The tray icon remains visible as long as there are inspected unread messages, and disappears if all are read or Outlook is closed.
Outlook is not launched from here: if it is not running, the thread waits until it starts.
"""

from __future__ import annotations

import json
import logging
import os
import re
import threading
import time
from collections import deque
from datetime import datetime
from pathlib import Path
from typing import Any, Callable

import mail_images

RECENT_LIMIT = 100
ATTACH_EVERY = 30  # Seconds between attempts to connect to Outlook while it is closed (COM table lookup is inexpensive)
UNREAD_EVERY = 60  # Seconds between checks for 'have messages been read?' while the tray icon is visible
IDLE_WAIT = 10 * 60  # With no tray icon visible, an Outlook event is sufficient to wake it up
CATCH_UP_LIMIT = 100
RULES_VERSION = 8  # Incremented with every change to classification rules, triggering re-evaluation of unread messages
# Attachment names that execute on click, which are the usual vector for email viruses.
RISKY_ATTACHMENT = re.compile(r"\.(exe|scr|bat|cmd|com|pif|js|jse|vbs|vbe|wsf|hta|ps1|msi|lnk|iso|img|jar|docm|xlsm|pptm)$", re.I)
# Newsletter and campaign markers in the message header. Only the marker name is stored, not the header text. Sending service markers
# alone (Feedback-ID and X-SG-EID) are insufficient, because security alerts and invoices pass through the same services.
BULK_HEADER = re.compile(r"^(list-unsubscribe|list-id|x-campaign\w*)\s*:"
                         r"|^precedence\s*:\s*(bulk|list|junk)", re.I | re.M)
# Message type is determined locally without a model. The markers have four layers, with the highest taking precedence:
#   1) Account, security, and finance (verification code, email confirmation, password, login, invoice, payment, request): Safe, even if bulk.
#   2) Promotional subject (discount, newsletter, weekly, webinar, hackathon, 'available now'), or a service outage from a status page, or a task completed
#      successfully: Promotional.
#   3) Service or account notification (expiration, quota, subscription, outage, price or term changes, build or run result): Safe.
#   4) Otherwise: If it has bulk sending markers, tracking links, or a marketing sender, it is promotional; otherwise, it is safe.
#
# Only the tag name is saved, not the matching text.
# Symbols first before all layers: A message containing a PIN, login code, or temporary verification is always important, even if it comes from
# a status page or with bulk sending tags. Discount codes and coupons are excluded.
CODE_TEXT = re.compile(
    r"(?<!promo )(?<!discount )(?<!coupon )(?<!referral )\b(pin|otp|passcode|one-time (pass)?code"
    r"|(verification|security|login|log-in|sign[- ]?in|access|temporary|auth\w*|confirmation|\d-digit) (code|token)|token:? \d{4,8}"
    r"|(your )?code (is|:)?\s*\d[\d -]{2,8}|\d{3,8} is your|use code \d{3,8})\b"
    r"|رمز (التحقق|التأكيد|الدخول|المرور|التفعيل|سري)|الرمز (المؤقت|السري)|كود (التحقق|التفعيل|الدخول)|الرقم السري"
    r"|كلمة (المرور|السر) (المؤقتة|لمرة واحدة)|(رمز|كود) [^ ]* ?لمرة واحدة", re.I)
# Also in the text, anything affecting the account itself, even if its address is public: Account or data deletion
# or memories, subscription cancellation or renewal, or 'If it wasn't you'. Ads do not contain these phrases.
ACCOUNT_BODY = re.compile(
    r"\b(your (account|subscription|data|memories|photos|files|storage)( and \w+)? (will|is going to|has been|was|is) (be )?"
    r"(deleted|removed|suspended|closed|canceled|cancelled|paused|disabled|locked|expired?)|billing cycle|re-?subscrib|download (my|your) (data|memories)|memories)\b"
    r"|سيتم حذف|على وشك الحذف|حذف حساب|ذكرياتك|تنزيل بياناتك", re.I)
# And three rules from the Owner preceding the layers after symbols and verification only: 'If it wasn't you' messages are not always important, changes to
# policies and terms for every site and app are unimportant, and repository messages '[Owner/Repository]' only matter if they indicate failure.
NOT_ME_TEXT = re.compile(r"\b((if )?(this|it) (wasn'?t|was not) you|was (this|it) you|did you just (log|sign))\b|إن لم تكن أنت|إذا لم تكن أنت|لم تكن أنت", re.I)
POLICY_SUBJECT = re.compile(
    r"\b(terms of (service|use)|privacy (policy|notice)|polic(y|ies)|user agreement|(updates?|changes) to our (terms|policies|policy|agreement))\b"
    r"|الشروط|شروط (الاستخدام|الخدمة)|سياسة الخصوصية|سياسات|بنود (الخدمة|الاستخدام)", re.I)
REPO_SUBJECT = re.compile(r"^(re: )?\[[\w.-]+/[\w.-]+\]", re.I)
FAILURE_SUBJECT = re.compile(r"\b(run failed|failed|failure|errored)\b", re.I)
VERIFY_BODY = re.compile(
    r"\b(confirm (your )?(e-?mail|email address|account|registration|sign[- ]?up)|verify (your )?(e-?mail|email address|account)"
    r"|activate (your )?account|verification code|one-time (pass)?code|reset (your )?password)\b"
    r"|تأكيد (البريد|الحساب|التسجيل)|تفعيل (الحساب|حسابك)|رمز (التحقق|التأكيد)", re.I)
VERIFY_TEXT = re.compile(
    r"\b(verif(y|ication)|confirm (your )?(e-?mail|email address|account|registration|sign[- ]?up)|activate (your )?account"
    r"|one-time (pass)?code|passcode|otp|security code|login code|sign[- ]?in code|reset (your )?password|password (reset|change|was changed|expir))"
    r"|رمز (التحقق|التأكيد|الدخول)|تأكيد (البريد|الحساب|التسجيل)|تفعيل (الحساب|حسابك)|كلمة (المرور|السر)", re.I)
SECURITY_SUBJECT = re.compile(
    r"\b(new (sign[- ]?in|login|device)|(sign[- ]?in|login) (from|attempt|activity|alert)|security (alert|notice)|two-(factor|step)|2fa"
    r"|norton family|family (report|link)|is your (verification |one-time |security |\d-digit )?(code|passcode)|your (new )?password|sign in by|code \d{4,8}|\d{4,8} is your"
    r"|recovery|log(ged)? ?(in|into) .{0,30}(near|with a code|new device)|security (update|issue|vulnerabilit\w*)|account (creation|details|deletion|status)|(oauth|third-party) app|app\(s\) connected|new (trusted )?device|passkey)\b"
    r"|تسجيل (الدخول|دخول)|تنبيه أمني|كلمة (السر|سر)|التحقق بخطوتين|بيانات حسابك|تم إنشاء حسابك|إنشاء الحساب", re.I)
MONEY_SUBJECT = re.compile(
    r"\b(receipt|invoice|payment (received|failed|declined|due|confirm)|your order|order (#|no\.?|number|confirm|shipped)"
    r"|has shipped|out for delivery|(has been|was) delivered|refund|payment (failure|.{0,30}unsuccessful)|purchase|letter"
    r"|check-?in|boarding pass|itinerary|e-?ticket|reservation|booking (confirm\w*|reference))\b"
    r"|فاتورة|إيصال|الدفع|طلبك|تم الشحن|استرداد|خصم مبلغ|شراء|حوالة|كشف (ال)?حساب|حجزك|الحجز|خطاب", re.I)
PROMO_SUBJECT = re.compile(
    r"\d+\s*%\s*off|\b(sale|deals?|discount|coupon|promo(tion)?|special offer|newsletter|weekly|monthly|digest|roundup|recap"
    r"|wrapped|webinar|hackathons?|livestream|don'?t miss|last chance|limited time|free trial|introducing|now available"
    r"|is now|new features?|what'?s new|tips)\b"
    r"|خصم|تخفيض|عرض (خاص|حصري)|نشرة|لفترة محدودة|جديدنا|كن واعي|توعية|نصيحة|نصائح|عروض|هدية|احصل على|(^|\s)جرّ?ب(\s|$)", re.I)
NOTICE_SUBJECT = re.compile(
    r"\b(expir(es|ed|ing|ation)|suspend(ed)?|quota|used up|limit reached|billing|renew(al|s)?|subscription|action required"
    r"|pricing changes?|changes to|notice|finish setting up"
    r"|run failed|(build|workflow|job|deploy(ment)?|pipeline|check|notebook) (failed|errored)"
    r"|(pull request|issue|review) (opened|closed|merged|requested)|action needed|turned off|(permanently )?deleted in \d|credits? (was|were) added"
    r"|(low|insufficient) balance|balance low|complaints?|ticket|updates? to .{0,40}your account)\b|\[incident:"
    r"|ينتهي|انتهاء|تعليق|الحصة|اشتراكك|إجراء مطلوب|عطل|تحديث هام|إشعار هام|إيقاف|الشكاوى|شكوى|تذكرة", re.I)
STATUS_SUBJECT = re.compile(
    r"\b(incident -|elevated errors|error rates|degraded|outage|downtime|(scheduled )?maintenance|service restoration"
    r"|run (succeeded|cancell?ed)|(build|workflow|job|deploy(ment)?|pipeline|check|notebook) (succeeded|passed|cancell?ed|completed|finished))\b", re.I)
KAGGLE_DONE = re.compile(r"\bnotebook\b.{0,40}\b(finished|completed|succeeded|failed|errored)\b|\b(kernel|notebook) (run|version)\b", re.I)
STATUS_SENDER = re.compile(r"(^|[.@])(statuspage\.io|incident\.io)$|@status\.", re.I)
MARKETING_SENDER = re.compile(r"^(newsletters?|news|marketing|promo(tions)?|offers?|deals|hello|team|community|events?|updates|info|digest)$", re.I)
MARKETING_SUBDOMAIN = re.compile(r"^(e|em|email|news|newsletter|marketing|info|go|promo|campaign)\d*\.", re.I)
HEADERS_PROP = "http://schemas.microsoft.com/mapi/proptag/0x007D001F"  # PR_TRANSPORT_MESSAGE_HEADERS
LINK_DOMAIN = re.compile(r"https?://([A-Za-z0-9.-]+)")
INBOX, DELETED = 6, 3
MAIL_CLASS = 43


def _now_iso() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


def _epoch(value: str) -> float:
    try:
        return datetime.fromisoformat(str(value)).timestamp()
    except (TypeError, ValueError):
        return 0.0


def _local(value: Any) -> datetime:
    """Outlook time is local time, sometimes tagged by pywin32 with a timezone; compared without timezone."""
    if isinstance(value, datetime):
        return value.replace(tzinfo=None)
    try:
        return datetime.fromisoformat(str(value)).replace(tzinfo=None)
    except (TypeError, ValueError):
        return datetime.min


def _template(subject: str) -> str:
    """Address without numbers and IDs: Single-thread messages ('Your project X closed') appear to the user as a single message."""
    return re.sub(r"[\w-]*\d[\w-]*", "#", str(subject or "")).strip().casefold()


def sender_domain(address: str) -> str:
    return address.rsplit("@", 1)[-1].strip().lower().rstrip(".") if "@" in address else ""


def bulk_markers(headers: str) -> list[str]:
    return sorted({m.group(0).split(":")[0].strip().lower() for m in BULK_HEADER.finditer(headers or "")})


def body_markers(text: str) -> list[str]:
    """'Verify' tag in the message body, like a 'Confirm Email' button under a 'Hello' subject. The text is read here then skipped."""
    text = text or ""
    return ([name for name, pattern in (("code", CODE_TEXT), ("verify", VERIFY_BODY), ("account", ACCOUNT_BODY), ("notme", NOT_ME_TEXT))
             if pattern.search(text)])


def mail_kind(mail: dict[str, Any]) -> tuple[str, str]:
    """Non-dangerous message type with its four layers: (clean or promo, the tag), and empty ones are decided by bulk sending tags."""
    subject = str(mail.get("subject") or "")
    address = str(mail.get("sender") or "").lower()
    if CODE_TEXT.search(subject) or "code" in (mail.get("body") or []):
        return "clean", "Login or verification code"
    if REPO_SUBJECT.search(subject):
        return ("clean", "Repository failure") if FAILURE_SUBJECT.search(subject) else ("promo", "Repository notification")
    if VERIFY_TEXT.search(subject):
        return "clean", "verification subject"
    if "verify" in (mail.get("body") or []):
        return "clean", "verification text"
    if NOT_ME_TEXT.search(subject):
        return "promo", "if this wasn't you"
    if POLICY_SUBJECT.search(subject):
        return "promo", "policy or terms change"
    # An invoice, cancelled subscription, or service notice remains important even if the sender tags it with 'if this wasn't you'
    if MONEY_SUBJECT.search(subject):
        return "clean", "ownership subject"
    if "account" in (mail.get("body") or []):
        return "clean", "account-related text"
    notice = bool(NOTICE_SUBJECT.search(subject)) and not PROMO_SUBJECT.search(subject)
    if "notme" in (mail.get("body") or []) and not notice:
        return "promo", "if this wasn't you"
    if SECURITY_SUBJECT.search(subject):
        return "clean", "security subject"
    # Kaggle notebook expiration is important, not promotional, while other task successes remain announcements
    if "kaggle" in address and KAGGLE_DONE.search(subject):
        return "clean", "Kaggle notebook expired"
    if STATUS_SENDER.search(address) or STATUS_SUBJECT.search(subject):
        return "promo", "service outage or completed task"
    if PROMO_SUBJECT.search(subject):
        return "promo", "promotional subject"
    if NOTICE_SUBJECT.search(subject):
        return "clean", "service notification"
    local, _, domain = address.partition("@")
    if MARKETING_SENDER.match(local) or MARKETING_SUBDOMAIN.match(domain):
        return "promo", "marketing sender"
    return "", ""


def assess_mail(mail: dict[str, Any], verdict: Callable[[str], str]) -> dict[str, Any]:
    """Assess the message and provide a reason:
    - danger: executable attachment, or sender domain blocked by the app (sender is a tracker or threat).
    - promo and clean: determined by mail_kind, then bulk send flag or blocked tracking links imply ads, otherwise clean.
    Malicious sites clicked are blocked by Defender via network protection; this app tracks tracking, not viruses."""
    sender = sender_domain(str(mail.get("sender") or ""))
    links = sorted({d for d in mail.get("links") or [] if d and d != sender})
    trackers = [d for d in links if verdict(d) == "red"]
    sender_bad = bool(sender) and verdict(sender) == "red"
    risky = [name for name in mail.get("attachments") or [] if RISKY_ATTACHMENT.search(str(name))]
    bulk = [str(m) for m in mail.get("bulk") or []]
    reasons = [f"Executable attachment: {name}" for name in risky] + ([f"Sender domain blocked: {sender}"] if sender_bad else [])
    kind, why = mail_kind(mail)
    level = "danger" if reasons else kind or ("promo" if trackers or bulk else "clean")
    if why and level != "danger":
        reasons.append(why)
    if bulk:
        reasons.append("Bulk send: " + ", ".join(bulk))
    if trackers:
        reasons.append(f"Blocked tracking links: {len(trackers)}")
    return {"at": mail.get("at", ""), "subject": str(mail.get("subject") or "")[:160], "sender": str(mail.get("sender") or ""),
            "domains": len(links) + (1 if sender else 0), "trackers": trackers[:20], "risky": risky, "verdict": level, "reasons": reasons}


def read_item(item: Any) -> dict[str, Any] | None:
    """Extracts data from an Outlook message. Body is read here to extract link domains, then discarded."""
    if getattr(item, "Class", 0) != MAIL_CLASS:
        return None
    sender = str(item.SenderEmailAddress or "")
    if item.SenderEmailType == "EX":
        try:
            user = item.Sender.GetExchangeUser()
            sender = str(user.PrimarySmtpAddress) if user else sender
        except Exception:  # noqa: BLE001 - Exchange sender without SMTP address remains as is
            pass
    try:
        headers = str(item.PropertyAccessor.GetProperty(HEADERS_PROP) or "")
    except Exception:  # noqa: BLE001 - some accounts do not save headers
        headers = ""
    html = str(item.HTMLBody or "")
    links = sorted({d.lower() for d in LINK_DOMAIN.findall(html)})
    return {"id": str(item.EntryID), "at": _local(item.ReceivedTime).isoformat(), "subject": str(item.Subject or ""),
            "sender": sender, "links": links, "attachments": [str(a.FileName) for a in item.Attachments],
            "bulk": bulk_markers(headers), "body": body_markers(str(item.Body or "")), "unread": bool(item.UnRead),
            "images": sorted(mail_images.content_hosts(html))}


def remove_item(namespace: Any, entry_id: str) -> None:
    """Removes the message as Norton used to quarantine it: to Deleted Items, then permanently deleted, so it doesn't remain in Outlook."""
    moved = namespace.GetItemFromID(entry_id).Move(namespace.GetDefaultFolder(DELETED))
    moved.Delete()


class _AppEvents:
    watch: "MailWatch"

    def OnNewMailEx(self, ids):  # noqa: N802 - Outlook event name
        self.watch.pending.extend(i for i in str(ids).split(",") if i)

    def OnQuit(self):  # noqa: N802
        self.watch.quit = True


class _InboxEvents:
    watch: "MailWatch"

    def OnItemChange(self, item):  # noqa: N802 - Read a changed message
        self.watch.dirty = True

    def OnItemRemove(self):  # noqa: N802
        self.watch.dirty = True


class MailWatch:
    def __init__(self, directory: Path, verdict: Callable[[str], str], badge: Callable[[str | None, str], None] | None = None,
                 on_images: Callable[[list[str]], None] | None = None):
        self.state_path = Path(directory) / "mail-watch.json"
        self.events_path = Path(directory) / "mail-watch-events.ndjson"
        # Envelope click log: what was opened, whether it
        # was the same message again (bug) or another message with the same subject after stripping numbers (series), and whether the previous one remained unread.
        self.clicks_path = Path(directory) / "mail-watch-clicks.ndjson"
        self._last_click: dict[str, str] = {}
        self.verdict = verdict
        self.badge = badge
        self.on_images = on_images  # New content image hosts: unblock them so images appear
        self.lock = threading.Lock()
        self.stop_event = threading.Event()
        self.since = ""
        self.state = {"outlook": "unknown", "lastRunAt": "", "error": "", "checked": 0}
        self.recent: deque[dict[str, Any]] = deque(maxlen=RECENT_LIMIT)
        self.seen: deque[str] = deque(maxlen=2000)
        self.unread: dict[str, str] = {}  # Checked unread messages: ID -> verdict
        self.pending: deque[str] = deque()
        self.dirty = False
        self.quit = False
        self.show = False
        self._painted: tuple | None = None
        self._wake = None
        self._load()

    def _load(self) -> None:
        try:
            payload = json.loads(self.state_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return
        self.since = payload.get("since", "")
        self.state.update(payload.get("state") or {})
        self.recent.extend(payload.get("recent") or [])
        self.seen.extend(payload.get("seen") or [])
        self.unread.update(payload.get("unread") or {})

    def save(self) -> None:
        with self.lock:
            text = json.dumps({"since": self.since, "state": self.state, "recent": list(self.recent), "seen": list(self.seen),
                               "unread": self.unread}, ensure_ascii=False, indent=1)
        temp = self.state_path.with_suffix(".tmp")
        temp.write_text(text + "\n", encoding="utf-8")
        os.replace(temp, self.state_path)

    def _keep_images(self, hosts: Any) -> None:
        """Images from safe messages appear: their hosts are recorded so they are not blocked."""
        try:
            new = mail_images.record(set(hosts))
            if new and self.on_images:
                self.on_images(new)
        except Exception as error:  # noqa: BLE001 - recording failure does not stop mail scanning
            logging.warning("mail images: %s", error)

    def handle(self, mails: list[dict[str, Any]], remove: Callable[[str], None]) -> list[dict[str, Any]]:
        """Assesses each unseen message, removes dangerous ones, and logs each verdict line by line. Returns assessed items."""
        found = []
        for mail in mails:
            if not mail or not mail.get("id") or mail["id"] in self.seen:
                continue
            self.seen.append(mail["id"])
            result = assess_mail(mail, self.verdict)
            if result["verdict"] == "danger":
                try:
                    remove(mail["id"])
                    result["removed"] = True
                except Exception as error:  # noqa: BLE001 - failed removal is logged and does not show envelope
                    result.update(removed=False, removeError=str(error)[:200])
            else:
                if mail.get("unread", True):
                    self.unread[mail["id"]] = result["verdict"]
                self._keep_images(mail.get("images") or ())
            found.append(result)
            with self.lock:
                self.recent.appendleft(result)
            with self.lock, self.events_path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps({"checkedAt": _now_iso(), **result}, ensure_ascii=False) + "\n")
            if str(mail.get("at") or "") > self.since:
                self.since = str(mail["at"])
        if found:
            self.state.update(lastRunAt=_now_iso(), checked=int(self.state.get("checked", 0)) + len(found))
            self.save()
        return found

    def badge_state(self) -> tuple[str | None, str]:
        """Light brown prevails: one clean message warrants entry even if accompanied by ads."""
        if self.state.get("outlook") != "running":
            return None, ""
        clean = sum(v == "clean" for v in self.unread.values())
        promo = len(self.unread) - clean
        parts = ([f"Clean mail: {clean}"] if clean else []) + ([f"Ads: {promo}"] if promo else [])
        return ("tan" if clean else "white" if promo else None), ", ".join(parts)

    def paint(self) -> None:
        painted = self.badge_state()
        if painted != self._painted and self.badge:
            self._painted = painted
            try:
                self.badge(*painted)
            except Exception as error:  # noqa: BLE001 - envelope does not crash scanning
                logging.debug("mail badge: %s", error)

    def request_show(self) -> None:
        """Envelope click: opens Inbox in Outlook from the Outlook thread itself."""
        self.show = True
        self._signal()

    def _signal(self) -> None:
        if self._wake is not None:
            import win32event

            win32event.SetEvent(self._wake)

    def _wait(self, seconds: float) -> None:
        """Sleeps until a Windows message (Outlook event), wake-up, or timeout, without consumption."""
        import pythoncom
        import win32event

        if win32event.MsgWaitForMultipleObjects([self._wake], False, int(seconds * 1000), win32event.QS_ALLINPUT) != win32event.WAIT_OBJECT_0:
            pythoncom.PumpWaitingMessages()

    def _set_outlook(self, value: str, error: str = "") -> None:
        if (self.state.get("outlook"), self.state.get("error")) != (value, error):
            self.state.update(outlook=value, error=error)
            self.save()
        self.paint()

    def _refresh_unread(self, namespace: Any) -> None:
        deleted = namespace.GetDefaultFolder(DELETED).EntryID
        for entry_id in list(self.unread):
            try:
                item = namespace.GetItemFromID(entry_id)
                keep = bool(item.UnRead) and item.Parent.EntryID != deleted
            except Exception:  # noqa: BLE001 - message deleted or moved out of store
                keep = False
            if not keep:
                self.unread.pop(entry_id, None)
        self.save()

    def _reassess_unread(self, namespace: Any) -> None:
        """If type rules change, reassess unread messages once, so the envelope doesn't stay on an old verdict."""
        if self.state.get("rules") == RULES_VERSION:
            return
        for entry_id, level in list(self.unread.items()):
            try:
                mail = read_item(namespace.GetItemFromID(entry_id))
            except Exception:  # noqa: BLE001 - message deleted or moved
                mail = None
            if mail and level != "danger":
                kind = assess_mail(mail, self.verdict)["verdict"]
                self.unread[entry_id] = kind if kind != "danger" else level
        self.state["rules"] = RULES_VERSION
        self.save()

    def _catch_up(self, namespace: Any, inbox: Any) -> None:
        """What arrived while the engine or Outlook was closed: from the last seen message, and on first run from a day ago."""
        since = _local(self.since) if self.since else _local(datetime.fromtimestamp(time.time() - 86400))
        items = inbox.Items
        items.Sort("[ReceivedTime]", True)
        mails = []
        for index, item in enumerate(items):
            if index >= CATCH_UP_LIMIT or _local(item.ReceivedTime) <= since:
                break
            if str(item.EntryID) not in self.seen:
                mails.append(read_item(item))
        self.handle(list(reversed(mails)), lambda entry_id: remove_item(namespace, entry_id))

    def click_targets(self) -> list[str]:
        """What the envelope click opens: light brown opens the oldest single clean unread message,
        so if read and closed, brown remains for the next; white opens nothing from ads, just the mail interface as is."""
        return [entry_id for entry_id, level in self.unread.items() if level == "clean"]

    def _show_explorer(self, app: Any, inbox: Any) -> None:
        """Shows Outlook on the Inbox as if opened from its icon next to the clock.

        Outlook minimized to the system tray has a hidden window, refusing state changes before showing, causing
        the click to fail with 'has not yet been made visible' and opening nothing."""
        explorer = app.ActiveExplorer()
        if explorer is None:
            inbox.Display()
            explorer = app.ActiveExplorer()
        else:
            explorer.CurrentFolder = inbox
            explorer.Display()
        if explorer is not None:
            try:
                if explorer.WindowState == 1:  # olMinimized
                    explorer.WindowState = 2
                explorer.Activate()
            except Exception as error:  # noqa: BLE001 - window visible even if not focused
                logging.debug("mail open: %s", error)

    def log_click(self, opened: dict[str, Any] | None, previous_unread: bool | None) -> dict[str, Any]:
        """One line per click. Subject and sender only as verdict log, no message body."""
        last = self._last_click
        row: dict[str, Any] = {"at": _now_iso(), "opened": "message" if opened else "inbox",
                               "cleanLeft": sum(v == "clean" for v in self.unread.values())}
        if opened:
            row.update(subject=opened["subject"][:160], sender=opened["sender"])
            row["sameAsLast"] = opened["id"] == last.get("id")
            row["seriesWithLast"] = not row["sameAsLast"] and (opened["sender"], _template(opened["subject"])) == (
                last.get("sender"), _template(last.get("subject", "")))
        if previous_unread is not None:
            row["lastStillUnread"] = previous_unread
        self._last_click = dict(opened) if opened else {}
        with self.lock, self.clicks_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")
        return row

    def _open_inbox(self, app: Any, inbox: Any, namespace: Any) -> None:
        previous = None
        if self._last_click.get("id"):
            try:
                previous = bool(namespace.GetItemFromID(self._last_click["id"]).UnRead)
            except Exception:  # noqa: BLE001 - previous deleted or moved
                previous = None
        for entry_id in self.click_targets():
            try:
                item = namespace.GetItemFromID(entry_id)
                item.Display()
            except Exception:  # noqa: BLE001 - message deleted or moved: try the next one
                self.unread.pop(entry_id, None)
                continue
            # Opened by the user via click, so it's read: won't reappear as itself on the next click even if Outlook didn't mark it
            try:
                item.UnRead = False
                item.Save()
            except Exception as error:  # noqa: BLE001 - marking remains on Outlook
                logging.debug("mail mark read: %s", error)
            self.unread.pop(entry_id, None)
            self.save()
            self.log_click({"id": entry_id, "subject": str(item.Subject or ""), "sender": str(item.SenderEmailAddress or "")}, previous)
            return
        self._show_explorer(app, inbox)
        self.log_click(None, previous)

    def _serve(self) -> None:
        import pythoncom
        import win32com.client

        try:
            active = win32com.client.GetActiveObject("Outlook.Application")
        except pythoncom.com_error:
            self._set_outlook("closed")
            self._wait(ATTACH_EVERY)
            return
        app = win32com.client.DispatchWithEvents(active, _AppEvents)
        app.watch = self
        namespace = app.GetNamespace("MAPI")
        inbox = namespace.GetDefaultFolder(INBOX)
        inbox_items = inbox.Items
        inbox_events = win32com.client.WithEvents(inbox_items, _InboxEvents)
        inbox_events.watch = self
        self.quit, self.dirty = False, True
        self.pending.clear()
        self._set_outlook("running")
        self._catch_up(namespace, inbox)
        self._reassess_unread(namespace)
        remove =lambda entry_id: remove_item(namespace, entry_id)  # noqa: E731
        last_refresh = 0.0
        try:
            while not self.stop_event.is_set() and not self.quit:
                while self.pending:
                    entry_id = self.pending.popleft()
                    if entry_id not in self.seen:
                        self.handle([read_item(namespace.GetItemFromID(entry_id))], remove)
                if self.dirty or (self.unread and time.monotonic() - last_refresh >= UNREAD_EVERY):
                    self.dirty, last_refresh = False, time.monotonic()
                    self._refresh_unread(namespace)
                if self.show:
                    self.show = False
                    try:
                        self._open_inbox(app, inbox, namespace)
                    except Exception as error:  # noqa: BLE001 - open failure does not stop mail scanning
                        logging.warning("mail open: %s", error)
                self.paint()
                self._wait(UNREAD_EVERY if self.unread else IDLE_WAIT)
        finally:
            inbox_events.close()
            app.close()
            del inbox_items, inbox, namespace, app, active
        self._set_outlook("closed")

    def _run(self) -> None:
        import pythoncom
        import win32event

        pythoncom.CoInitialize()
        self._wake = win32event.CreateEvent(None, False, False, None)
        try:
            while not self.stop_event.is_set():
                try:
                    self._serve()
                except Exception as error:  # noqa: BLE001 - mail does not crash the engine
                    logging.warning("mail watch: %s", error)
                    self._set_outlook("error", str(error)[:300])
                    self._wait(ATTACH_EVERY)
        finally:
            pythoncom.CoUninitialize()

    def start(self) -> None:
        threading.Thread(target=self._run, name="mail-watch", daemon=True).start()

    def view(self) -> dict[str, Any]:
        with self.lock:
            recent = list(self.recent)
        day = time.time() - 86400
        fresh = [m for m in recent if _epoch(m.get("at", "")) >= day]
        level, tip = self.badge_state()
        return {**self.state, "badge": level, "badgeTip": tip, "unread": len(self.unread),
                "removed": [m for m in recent if m["verdict"] == "danger"][:30], "recent": recent[:30],
                "today": {"danger": sum(m["verdict"] == "danger" for m in fresh),
                          "promo": sum(m["verdict"] in ("promo", "trackers") for m in fresh),
                          "clean": sum(m["verdict"] == "clean" for m in fresh)}}

    def shutdown(self) -> None:
        self.stop_event.set()
        self._signal()
