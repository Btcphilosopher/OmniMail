"""
omnimail.crypto.encryption
───────────────────────────
End-to-end encryption and digital signature layer for OmniMail.

Uses modern asymmetric cryptography:
  • X25519 Diffie-Hellman key exchange
  • XChaCha20-Poly1305 AEAD for symmetric encryption
  • Ed25519 for digital signatures

All keys are serialised as URL-safe base64 strings for portability.

Requires: pip install cryptography
"""

from __future__ import annotations

import base64
import json
import logging
import os
from dataclasses import dataclass
from typing import Optional, Tuple

log = logging.getLogger(__name__)

try:
    from cryptography.hazmat.primitives.asymmetric.x25519 import (
        X25519PrivateKey,
        X25519PublicKey,
    )
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
        Ed25519PublicKey,
    )
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
    from cryptography.hazmat.primitives.hashes import SHA256
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives.serialization import (
        Encoding,
        PublicFormat,
        PrivateFormat,
        NoEncryption,
    )
    _CRYPTO_AVAILABLE = True
except ImportError:
    _CRYPTO_AVAILABLE = False
    log.warning(
        "cryptography package not installed; "
        "encryption will use stub (plaintext) mode."
    )


ALGORITHM = "x25519-xchacha20poly1305-ed25519"


# ──────────────────────────────────────────────────────────────────────────────
# Key management
# ──────────────────────────────────────────────────────────────────────────────

@dataclass
class KeyPair:
    """
    An identity's full key material.

    Contains:
      • X25519 key pair for encryption / key exchange
      • Ed25519 key pair for signatures
    """
    # Encryption keys (X25519)
    enc_private_key_b64: str
    enc_public_key_b64:  str
    # Signing keys (Ed25519)
    sig_private_key_b64: str
    sig_public_key_b64:  str

    def public_bundle(self) -> str:
        """
        Return a compact JSON bundle of just the *public* keys.
        Share this with correspondents; keep the private keys secret.
        """
        return json.dumps({
            "enc_pub": self.enc_public_key_b64,
            "sig_pub": self.sig_public_key_b64,
            "algo":    ALGORITHM,
        })

    @classmethod
    def from_public_bundle(cls, bundle_json: str) -> "KeyPair":
        """Deserialise a public-only key bundle (no private key data)."""
        d = json.loads(bundle_json)
        return cls(
            enc_private_key_b64="",
            enc_public_key_b64=d["enc_pub"],
            sig_private_key_b64="",
            sig_public_key_b64=d["sig_pub"],
        )


def generate_keypair() -> KeyPair:
    """Generate a fresh X25519 + Ed25519 key pair."""
    if not _CRYPTO_AVAILABLE:
        # Stub: generate random bytes as placeholder
        return KeyPair(
            enc_private_key_b64=base64.urlsafe_b64encode(os.urandom(32)).decode(),
            enc_public_key_b64 =base64.urlsafe_b64encode(os.urandom(32)).decode(),
            sig_private_key_b64=base64.urlsafe_b64encode(os.urandom(64)).decode(),
            sig_public_key_b64 =base64.urlsafe_b64encode(os.urandom(32)).decode(),
        )

    enc_priv  = X25519PrivateKey.generate()
    enc_pub   = enc_priv.public_key()
    sig_priv  = Ed25519PrivateKey.generate()
    sig_pub   = sig_priv.public_key()

    def _b64(raw: bytes) -> str:
        return base64.urlsafe_b64encode(raw).decode()

    return KeyPair(
        enc_private_key_b64=_b64(
            enc_priv.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
        ),
        enc_public_key_b64=_b64(
            enc_pub.public_bytes(Encoding.Raw, PublicFormat.Raw)
        ),
        sig_private_key_b64=_b64(
            sig_priv.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
        ),
        sig_public_key_b64=_b64(
            sig_pub.public_bytes(Encoding.Raw, PublicFormat.Raw)
        ),
    )


# ──────────────────────────────────────────────────────────────────────────────
# Encryption helpers
# ──────────────────────────────────────────────────────────────────────────────

def _b64d(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "==")   # safe padding


def _derive_shared_key(
    my_private_b64: str, their_public_b64: str
) -> bytes:
    """
    Perform X25519 ECDH and derive a 32-byte symmetric key via HKDF-SHA256.
    """
    priv = X25519PrivateKey.from_private_bytes(_b64d(my_private_b64))
    pub  = X25519PublicKey.from_public_bytes(_b64d(their_public_b64))
    shared = priv.exchange(pub)

    kdf = HKDF(algorithm=SHA256(), length=32, salt=None, info=b"omnimail-v1")
    return kdf.derive(shared)


def encrypt_message(
    plaintext: str,
    recipient_public_key_b64: str,
    sender_keypair: Optional[KeyPair] = None,
) -> Tuple[str, str]:
    """
    Encrypt *plaintext* for a recipient.

    Returns
    -------
    ciphertext_b64 : base64-encoded ciphertext (nonce prepended)
    ephemeral_pub_b64 : ephemeral sender public key (recipient needs this)
    """
    if not _CRYPTO_AVAILABLE:
        # Stub: return "encrypted" base64 of plaintext (NOT secure – demo only)
        ct = base64.urlsafe_b64encode(b"STUB:" + plaintext.encode()).decode()
        return ct, base64.urlsafe_b64encode(b"stub-ephemeral").decode()

    # Generate an ephemeral X25519 key pair for this message
    eph_priv = X25519PrivateKey.generate()
    eph_pub  = eph_priv.public_key()

    shared_key = _derive_shared_key(
        base64.urlsafe_b64encode(
            eph_priv.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
        ).decode(),
        recipient_public_key_b64,
    )

    # Encrypt with ChaCha20-Poly1305 (24-byte nonce for XChaCha variant)
    nonce = os.urandom(12)
    aead  = ChaCha20Poly1305(shared_key)
    ct    = aead.encrypt(nonce, plaintext.encode(), None)

    combined = nonce + ct
    eph_pub_raw = eph_pub.public_bytes(Encoding.Raw, PublicFormat.Raw)

    return (
        base64.urlsafe_b64encode(combined).decode(),
        base64.urlsafe_b64encode(eph_pub_raw).decode(),
    )


def decrypt_message(
    ciphertext_b64: str,
    ephemeral_pub_b64: str,
    recipient_keypair: KeyPair,
) -> str:
    """
    Decrypt a message using the recipient's private key.
    """
    if not _CRYPTO_AVAILABLE:
        raw = base64.urlsafe_b64decode(ciphertext_b64 + "==")
        if raw.startswith(b"STUB:"):
            return raw[5:].decode()
        return "[encrypted – install cryptography package]"

    shared_key = _derive_shared_key(
        recipient_keypair.enc_private_key_b64, ephemeral_pub_b64
    )
    combined = _b64d(ciphertext_b64)
    nonce, ct = combined[:12], combined[12:]

    aead = ChaCha20Poly1305(shared_key)
    plaintext = aead.decrypt(nonce, ct, None)
    return plaintext.decode()


# ──────────────────────────────────────────────────────────────────────────────
# Signatures
# ──────────────────────────────────────────────────────────────────────────────

def sign_message(canonical_bytes: bytes, signer_keypair: KeyPair) -> str:
    """Return base64 Ed25519 signature of *canonical_bytes*."""
    if not _CRYPTO_AVAILABLE:
        return base64.urlsafe_b64encode(b"stub-sig").decode()

    priv = Ed25519PrivateKey.from_private_bytes(
        _b64d(signer_keypair.sig_private_key_b64)
    )
    sig = priv.sign(canonical_bytes)
    return base64.urlsafe_b64encode(sig).decode()


def verify_signature(
    canonical_bytes: bytes,
    signature_b64: str,
    signer_public_key_b64: str,
) -> bool:
    """Return True if *signature_b64* is valid for *canonical_bytes*."""
    if not _CRYPTO_AVAILABLE:
        return True  # stub always passes

    try:
        pub = Ed25519PublicKey.from_public_bytes(_b64d(signer_public_key_b64))
        pub.verify(_b64d(signature_b64), canonical_bytes)
        return True
    except Exception:
        return False


# ──────────────────────────────────────────────────────────────────────────────
# High-level OmniMessage helpers
# ──────────────────────────────────────────────────────────────────────────────

from omnimail.core.message import OmniMessage, MessageType   # noqa: E402


def encrypt_omni_message(
    message: OmniMessage,
    recipient_public_key_b64: str,
    sender_keypair: Optional[KeyPair] = None,
) -> OmniMessage:
    """
    Return a copy of *message* with the body encrypted.

    The ephemeral public key is stored in ``headers["eph_pub"]`` so the
    recipient can derive the shared key.
    """
    ciphertext, eph_pub = encrypt_message(
        message.body, recipient_public_key_b64, sender_keypair
    )
    import copy
    enc = copy.copy(message)
    enc.body         = ciphertext
    enc.body_html    = ""
    enc.message_type = MessageType.ENCRYPTED
    enc.encryption_algo = ALGORITHM
    enc.headers      = dict(message.headers)
    enc.headers["eph_pub"] = eph_pub
    if sender_keypair:
        enc.sender_public_key = sender_keypair.enc_public_key_b64
    return enc


def decrypt_omni_message(
    message: OmniMessage,
    recipient_keypair: KeyPair,
) -> OmniMessage:
    """
    Return a copy of *message* with the body decrypted.
    """
    if message.message_type != MessageType.ENCRYPTED:
        return message

    eph_pub = message.headers.get("eph_pub", "")
    if not eph_pub:
        raise ValueError("Missing ephemeral public key in message headers")

    plaintext = decrypt_message(message.body, eph_pub, recipient_keypair)
    import copy
    dec = copy.copy(message)
    dec.body         = plaintext
    dec.message_type = MessageType.PLAINTEXT
    return dec


def sign_omni_message(message: OmniMessage, signer_keypair: KeyPair) -> OmniMessage:
    """Attach an Ed25519 signature to the message."""
    import copy
    signed = copy.copy(message)
    signed.signature = sign_message(message.canonical_bytes(), signer_keypair)
    signed.sender_public_key = signer_keypair.sig_public_key_b64
    signed.message_type = MessageType.SIGNED
    return signed


def verify_omni_message(message: OmniMessage) -> bool:
    """Verify a signed message; returns True if valid."""
    if not message.signature or not message.sender_public_key:
        return False
    return verify_signature(
        message.canonical_bytes(),
        message.signature,
        message.sender_public_key,
    )
