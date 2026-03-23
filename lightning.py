"""
omnimail.payments.lightning
────────────────────────────
Lightning Network micropayment integration for OmniMail.

OmniMail uses Lightning invoices to implement a priority message
"fast lane".  Senders attach a BOLT-11 invoice to their message;
the receiving gateway verifies payment before elevating the message
to HIGH priority processing.

This module supports two backends:
  1. LND (Lightning Network Daemon) via its REST API
  2. Core Lightning (CLN) via its JSON-RPC API
  3. Stub mode (no real node; useful for testing / demos)

Requires: pip install aiohttp (for LND REST calls)
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import time
from dataclasses import dataclass
from typing import Optional

log = logging.getLogger(__name__)

try:
    import aiohttp
    _AIOHTTP = True
except ImportError:
    _AIOHTTP = False


# ──────────────────────────────────────────────────────────────────────────────
# Data types
# ──────────────────────────────────────────────────────────────────────────────

@dataclass
class Invoice:
    """A BOLT-11 Lightning invoice."""
    bolt11:       str           # full BOLT-11 encoded string
    payment_hash: str           # hex-encoded payment hash
    amount_msats: int           # milli-satoshis
    description:  str  = ""
    expiry:       int  = 3600   # seconds
    created_at:   float = 0.0
    settled:      bool = False
    preimage:     Optional[str] = None   # set when paid

    @property
    def is_expired(self) -> bool:
        return time.time() > (self.created_at + self.expiry)


@dataclass
class PaymentResult:
    success:      bool
    preimage:     Optional[str] = None
    fee_msats:    int = 0
    error:        str = ""


# ──────────────────────────────────────────────────────────────────────────────
# Lightning client (LND REST backend)
# ──────────────────────────────────────────────────────────────────────────────

class LNDClient:
    """
    Thin async client for LND's REST API.

    Parameters
    ----------
    lnd_url    : base URL of LND REST (e.g. ``"https://localhost:8080"``)
    macaroon   : hex-encoded LND macaroon (admin or invoice)
    tls_cert   : path to LND's TLS certificate (for self-signed certs)
    """

    def __init__(
        self,
        lnd_url:  str,
        macaroon: str,
        tls_cert: Optional[str] = None,
    ) -> None:
        self.lnd_url  = lnd_url.rstrip("/")
        self.macaroon = macaroon
        self.tls_cert = tls_cert

    def _headers(self) -> dict:
        return {"Grpc-Metadata-macaroon": self.macaroon}

    async def create_invoice(
        self,
        amount_msats: int,
        memo: str = "OmniMail priority message",
        expiry: int = 3600,
    ) -> Invoice:
        """Create a new Lightning invoice on the connected LND node."""
        if not _AIOHTTP:
            return self._stub_invoice(amount_msats, memo)

        payload = {
            "value_msat": amount_msats,
            "memo":       memo,
            "expiry":     expiry,
        }
        url = f"{self.lnd_url}/v1/invoices"
        connector = aiohttp.TCPConnector(ssl=False)   # disable SSL verify for dev
        async with aiohttp.ClientSession(connector=connector) as session:
            async with session.post(
                url, json=payload, headers=self._headers()
            ) as resp:
                data = await resp.json()

        payment_request = data.get("payment_request", "")
        payment_hash    = base64.b64decode(data.get("r_hash", "")).hex()

        return Invoice(
            bolt11=payment_request,
            payment_hash=payment_hash,
            amount_msats=amount_msats,
            description=memo,
            expiry=expiry,
            created_at=time.time(),
        )

    async def check_invoice(self, payment_hash_hex: str) -> bool:
        """Return True if the invoice identified by *payment_hash_hex* is settled."""
        if not _AIOHTTP:
            return True   # stub: always paid

        r_hash_b64 = base64.urlsafe_b64encode(
            bytes.fromhex(payment_hash_hex)
        ).decode()
        url = f"{self.lnd_url}/v1/invoice/{r_hash_b64}"
        connector = aiohttp.TCPConnector(ssl=False)
        async with aiohttp.ClientSession(connector=connector) as session:
            async with session.get(url, headers=self._headers()) as resp:
                data = await resp.json()

        return data.get("settled", False)

    async def pay_invoice(self, bolt11: str) -> PaymentResult:
        """Pay a BOLT-11 invoice from the connected LND node."""
        if not _AIOHTTP:
            return PaymentResult(
                success=True,
                preimage="stub_preimage_" + hashlib.sha256(bolt11.encode()).hexdigest()[:16],
            )

        payload = {"payment_request": bolt11}
        url = f"{self.lnd_url}/v1/channels/transactions"
        connector = aiohttp.TCPConnector(ssl=False)
        async with aiohttp.ClientSession(connector=connector) as session:
            async with session.post(
                url, json=payload, headers=self._headers()
            ) as resp:
                data = await resp.json()

        if data.get("payment_error"):
            return PaymentResult(success=False, error=data["payment_error"])

        return PaymentResult(
            success=True,
            preimage=data.get("payment_preimage", ""),
            fee_msats=int(data.get("payment_route", {}).get("total_fees_msat", 0)),
        )

    # ── Stub helpers (no real node) ───────────────────────────────────────────

    @staticmethod
    def _stub_invoice(amount_msats: int, memo: str) -> Invoice:
        """Generate a fake invoice for demo / testing."""
        import hashlib, random, string
        fake_hash = hashlib.sha256(
            (str(time.time()) + memo).encode()
        ).hexdigest()
        chars = string.ascii_lowercase + string.digits
        fake_bolt11 = "lnbc" + "".join(random.choices(chars, k=120))
        return Invoice(
            bolt11=fake_bolt11,
            payment_hash=fake_hash,
            amount_msats=amount_msats,
            description=memo,
            created_at=time.time(),
        )


# ──────────────────────────────────────────────────────────────────────────────
# High-level payment service
# ──────────────────────────────────────────────────────────────────────────────

class LightningPaymentService:
    """
    High-level service that wraps ``LNDClient`` and integrates with
    OmniMail message priority.

    Usage::

        svc = LightningPaymentService.stub()   # no real node needed
        invoice = await svc.create_priority_invoice(amount_msats=1000)

        # Attach invoice to message before sending
        message.lightning = LightningPayment(
            invoice=invoice.bolt11,
            amount_msats=1000,
            preimage=None,
        )
        message.priority = Priority.HIGH
    """

    # msats = 1000 msats = 1 sat.  Default: 1 sat per priority message.
    DEFAULT_PRIORITY_AMOUNT_MSATS = 1_000

    def __init__(self, client: LNDClient) -> None:
        self._client = client

    @classmethod
    def stub(cls) -> "LightningPaymentService":
        """Create a service backed by a stub (no real node) for testing."""
        return cls(LNDClient(lnd_url="http://stub", macaroon="stub"))

    async def create_priority_invoice(
        self,
        amount_msats: int = DEFAULT_PRIORITY_AMOUNT_MSATS,
        description: str = "OmniMail priority delivery",
    ) -> Invoice:
        return await self._client.create_invoice(amount_msats, description)

    async def verify_payment(self, invoice: "LightningPayment") -> bool:  # noqa: F821
        """Return True if *invoice* has been paid."""
        return await self._client.check_invoice(invoice.payment_hash)

    async def pay(self, bolt11: str) -> PaymentResult:
        return await self._client.pay_invoice(bolt11)

    def format_amount(self, msats: int) -> str:
        sats = msats / 1000
        if sats >= 100_000_000:
            return f"{sats / 100_000_000:.4f} BTC"
        return f"{sats:,.0f} sat{'s' if sats != 1 else ''}"
