"""
omnimail.adapters.smtp_adapter
───────────────────────────────
SMTP transport adapter for OmniMail.

Translates OmniMessage ↔ RFC 5322 email messages and delivers them via
an SMTP relay (plain, STARTTLS, or SSL).  Receiving uses IMAP IDLE
polling (requires the ``imapclient`` package).

Dependencies (optional install):
    pip install aiosmtplib imapclient
"""

from __future__ import annotations

import asyncio
import email
import email.mime.multipart
import email.mime.text
import email.mime.base
import email.encoders
import email.utils
import imaplib
import logging
import quopri
import time
from typing import List, Optional

from omnimail.adapters.base import BaseAdapter
from omnimail.core.message import (
    OmniMessage,
    MessageType,
    Attachment,
    TransportStatus,
)

log = logging.getLogger(__name__)


class SMTPAdapter(BaseAdapter):
    """
    Full-featured SMTP/IMAP adapter.

    Parameters
    ----------
    smtp_host : SMTP relay hostname
    smtp_port : SMTP relay port (587 for STARTTLS, 465 for SSL)
    username  : SMTP/IMAP account username
    password  : SMTP/IMAP account password
    imap_host : IMAP server hostname (for receive())
    imap_port : IMAP port (default 993 for IMAPS)
    use_tls   : enable STARTTLS (default True)
    from_address : envelope FROM address (defaults to username)
    """

    adapter_id      = "smtp"
    priority_weight = 80          # SMTP is the most universally available

    def __init__(
        self,
        smtp_host: str,
        smtp_port: int = 587,
        username:  str = "",
        password:  str = "",
        imap_host: str = "",
        imap_port: int = 993,
        use_tls:   bool = True,
        from_address: Optional[str] = None,
    ) -> None:
        self.smtp_host    = smtp_host
        self.smtp_port    = smtp_port
        self.username     = username
        self.password     = password
        self.imap_host    = imap_host or smtp_host
        self.imap_port    = imap_port
        self.use_tls      = use_tls
        self.from_address = from_address or username
        self._seen_uids: set = set()

    # ── Send ──────────────────────────────────────────────────────────────────

    async def send(self, message: OmniMessage) -> None:
        """Convert OmniMessage to RFC 5322 and deliver via SMTP."""
        mime_msg = self._to_mime(message)

        try:
            import aiosmtplib
        except ImportError:
            # Fallback: use stdlib smtplib synchronously in a thread
            await asyncio.get_event_loop().run_in_executor(
                None, self._send_sync, mime_msg, message.recipients
            )
            return

        smtp = aiosmtplib.SMTP(
            hostname=self.smtp_host,
            port=self.smtp_port,
            use_tls=(self.smtp_port == 465),
        )
        await smtp.connect()
        if self.use_tls and self.smtp_port != 465:
            await smtp.starttls()
        if self.username:
            await smtp.login(self.username, self.password)

        await smtp.send_message(mime_msg)
        await smtp.quit()
        log.info("SMTP: sent %s to %s", message.id[:8], message.recipients)

    def _send_sync(self, mime_msg, recipients: List[str]) -> None:
        import smtplib
        with smtplib.SMTP(self.smtp_host, self.smtp_port) as s:
            if self.use_tls:
                s.starttls()
            if self.username:
                s.login(self.username, self.password)
            s.send_message(mime_msg)

    def _to_mime(self, msg: OmniMessage) -> email.mime.multipart.MIMEMultipart:
        """Build an RFC 5322 MIME message from an OmniMessage."""
        if msg.attachments or msg.body_html:
            mime = email.mime.multipart.MIMEMultipart("mixed")
        else:
            mime = email.mime.multipart.MIMEMultipart("alternative")

        mime["From"]    = self.from_address
        mime["To"]      = ", ".join(msg.recipients)
        mime["Subject"] = msg.subject
        mime["Date"]    = email.utils.formatdate(msg.timestamp, localtime=False)
        mime["Message-ID"] = f"<{msg.id}@omnimail>"

        # Embed OmniMail metadata in custom headers
        mime["X-OmniMail-ID"]       = msg.id
        mime["X-OmniMail-Priority"] = msg.priority.value
        if msg.thread_id:
            mime["X-OmniMail-Thread"] = msg.thread_id
        if msg.signature:
            mime["X-OmniMail-Signature"] = msg.signature[:64]  # truncated

        # Body
        if msg.message_type == MessageType.ENCRYPTED:
            mime.attach(email.mime.text.MIMEText(
                "[Encrypted OmniMail message]\n\n" + msg.body, "plain"
            ))
        else:
            mime.attach(email.mime.text.MIMEText(msg.body, "plain"))
            if msg.body_html:
                mime.attach(email.mime.text.MIMEText(msg.body_html, "html"))

        # Attachments
        for att in msg.attachments:
            part = email.mime.base.MIMEBase(*att.content_type.split("/", 1))
            part.set_payload(att.data)
            email.encoders.encode_base64(part)
            part.add_header(
                "Content-Disposition", "attachment", filename=att.filename
            )
            mime.attach(part)

        return mime

    # ── Receive ───────────────────────────────────────────────────────────────

    async def receive(self) -> List[OmniMessage]:
        """Fetch unseen messages from the IMAP inbox."""
        return await asyncio.get_event_loop().run_in_executor(
            None, self._receive_sync
        )

    def _receive_sync(self) -> List[OmniMessage]:
        """Blocking IMAP fetch (runs in threadpool)."""
        if not self.imap_host:
            return []

        messages: List[OmniMessage] = []
        try:
            with imaplib.IMAP4_SSL(self.imap_host, self.imap_port) as imap:
                imap.login(self.username, self.password)
                imap.select("INBOX")

                _, data = imap.search(None, "UNSEEN")
                uid_list = data[0].split() if data[0] else []

                for uid in uid_list:
                    if uid in self._seen_uids:
                        continue
                    _, msg_data = imap.fetch(uid, "(RFC822)")
                    raw = msg_data[0][1]
                    omni = self._from_mime(raw)
                    if omni:
                        messages.append(omni)
                    self._seen_uids.add(uid)

        except Exception as exc:
            log.error("SMTP receive error: %s", exc)

        return messages

    def _from_mime(self, raw: bytes) -> Optional[OmniMessage]:
        """Parse a raw RFC 5322 message into an OmniMessage."""
        try:
            msg = email.message_from_bytes(raw)
            body = ""
            body_html = ""
            attachments: List[Attachment] = []

            if msg.is_multipart():
                for part in msg.walk():
                    ct = part.get_content_type()
                    cd = str(part.get("Content-Disposition", ""))
                    if "attachment" in cd:
                        attachments.append(Attachment(
                            filename=part.get_filename() or "attachment",
                            content_type=ct,
                            data=part.get_payload(decode=True) or b"",
                        ))
                    elif ct == "text/plain":
                        body = (part.get_payload(decode=True) or b"").decode(
                            errors="replace"
                        )
                    elif ct == "text/html":
                        body_html = (part.get_payload(decode=True) or b"").decode(
                            errors="replace"
                        )
            else:
                body = (msg.get_payload(decode=True) or b"").decode(errors="replace")

            date_str = msg.get("Date", "")
            try:
                ts = email.utils.parsedate_to_datetime(date_str).timestamp()
            except Exception:
                ts = time.time()

            omni_id = msg.get("X-OmniMail-ID") or None

            return OmniMessage(
                id=omni_id or str(__import__("uuid").uuid4()),
                sender=msg.get("From", ""),
                recipients=[addr.strip() for addr in msg.get("To", "").split(",")],
                subject=msg.get("Subject", ""),
                body=body,
                body_html=body_html,
                attachments=attachments,
                timestamp=ts,
            )
        except Exception as exc:
            log.error("SMTP parse error: %s", exc)
            return None

    def can_deliver_to(self, address: str) -> bool:
        return "@" in address

    def address_scheme(self) -> str:
        return "mailto"
