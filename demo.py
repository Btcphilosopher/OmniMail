"""
examples/demo.py
─────────────────
OmniMail reference demo – runs without any real SMTP/Matrix/LND nodes.

Demonstrates:
  1. Basic plaintext send/receive via the MemoryAdapter
  2. Multi-adapter routing with automatic fallback
  3. End-to-end encryption (X25519 + ChaCha20-Poly1305)
  4. Digital signatures (Ed25519)
  5. Message queue with retry simulation
  6. Lightning invoice attachment (stub mode)
  7. WebSocket server stub

Run:
    python examples/demo.py
"""

import asyncio
import json
import logging
import sys
import os

# Allow running from the repo root
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from omnimail import (
    OmniMailSDK,
    OmniMessage,
    Priority,
    DeliveryMode,
    MemoryAdapter,
    generate_keypair,
    LightningPaymentService,
)
from omnimail.adapters.memory_adapter import MemoryAdapter

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s – %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("demo")

SEP = "─" * 64


async def demo_basic_send_receive():
    """Send and receive a plain message via the MemoryAdapter."""
    print(f"\n{SEP}")
    print("  DEMO 1 · Basic send / receive (MemoryAdapter)")
    print(SEP)

    sdk = OmniMailSDK(enable_queue=False)
    mem = MemoryAdapter()
    sdk.register_adapter("memory", mem)
    await sdk.start()

    # Send
    msg_id = await sdk.send(
        sender="alice@omnimail.test",
        to=["bob@omnimail.test"],
        subject="Hello from OmniMail!",
        body="This is OmniMail's first test message.",
    )
    print(f"  ✓ Sent message  id={msg_id[:8]}…")
    print(f"  ✓ MemoryAdapter stored {len(mem.sent)} message(s)")

    stored = mem.sent[0]
    print(f"  ✓ Subject: {stored.subject!r}")
    print(f"  ✓ Fingerprint: {stored.fingerprint()[:16]}…")

    await sdk.stop()


async def demo_multi_adapter_fallback():
    """
    Register two adapters; the first deliberately fails.
    The Router should fall back to the second automatically.
    """
    print(f"\n{SEP}")
    print("  DEMO 2 · Multi-adapter routing with automatic fallback")
    print(SEP)

    sdk  = OmniMailSDK(enable_queue=False)
    bad  = MemoryAdapter(fail_first_n=1)   # fails on first send
    good = MemoryAdapter()
    bad.adapter_id      = "flaky-transport"
    bad.priority_weight = 90    # preferred – but will fail
    good.adapter_id     = "reliable-transport"
    good.priority_weight = 50

    sdk.register_adapter("flaky",    bad)
    sdk.register_adapter("reliable", good)
    await sdk.start()

    msg_id = await sdk.send(
        sender="alice@omnimail.test",
        to=["charlie@omnimail.test"],
        subject="Fallback test",
        body="If you read this, fallback worked!",
    )

    # Check delivery report via router internals
    inbox_msg = good.sent[0]
    hops = inbox_msg.routing_history
    print(f"  ✓ Message {msg_id[:8]}… delivered")
    print(f"  ✓ Routing hops: {len(hops)}")
    for hop in hops:
        status = "✓ SENT" if hop.status.value == "sent" else f"✗ {hop.status.value}"
        print(f"    [{status}] via {hop.adapter!r}  note={hop.note!r}")

    await sdk.stop()


async def demo_encryption():
    """
    Alice generates a key pair, Bob registers her public key, and
    Alice encrypts a message only Bob can read.
    """
    print(f"\n{SEP}")
    print("  DEMO 3 · End-to-end encryption (X25519 + XChaCha20-Poly1305)")
    print(SEP)

    # Alice
    alice_kp = generate_keypair()
    alice_sdk = OmniMailSDK(enable_queue=False)
    alice_mem = MemoryAdapter()
    alice_sdk.register_adapter("memory", alice_mem)
    alice_sdk.load_keypair(alice_kp)
    await alice_sdk.start()

    # Bob
    bob_kp = generate_keypair()
    bob_sdk = OmniMailSDK(enable_queue=False)
    bob_mem = MemoryAdapter()
    bob_sdk.register_adapter("memory", bob_mem)
    bob_sdk.load_keypair(bob_kp)
    await bob_sdk.start()

    # Exchange public keys (in real life via a key server or QR code)
    alice_sdk.register_peer_key("bob@omnimail.test", bob_kp.enc_public_key_b64)

    secret_text = "The private key to the kingdom is: hunter2"

    msg_id = await alice_sdk.send(
        sender="alice@omnimail.test",
        to=["bob@omnimail.test"],
        subject="Secret message",
        body=secret_text,
        encrypt=True,
    )

    enc_msg = alice_mem.sent[0]
    print(f"  ✓ Encrypted body (first 60 chars): {enc_msg.body[:60]}…")
    print(f"  ✓ Encryption algo: {enc_msg.encryption_algo!r}")
    print(f"  ✓ Message type: {enc_msg.message_type!r}")

    # Bob receives and decrypts
    bob_mem.inject(enc_msg)
    received = (await bob_sdk.fetch_inbox("memory"))[0]
    decrypted = bob_sdk.decrypt_message(received)
    print(f"  ✓ Bob decrypted body: {decrypted.body!r}")
    assert decrypted.body == secret_text, "Decryption mismatch!"
    print("  ✓ Decryption integrity check PASSED")

    await alice_sdk.stop()
    await bob_sdk.stop()


async def demo_signatures():
    """Alice signs a message; Bob verifies the signature."""
    print(f"\n{SEP}")
    print("  DEMO 4 · Digital signatures (Ed25519)")
    print(SEP)

    sdk = OmniMailSDK(enable_queue=False)
    mem = MemoryAdapter()
    sdk.register_adapter("memory", mem)
    kp = sdk.generate_identity()
    await sdk.start()

    msg_id = await sdk.send(
        sender="alice@omnimail.test",
        to=["bob@omnimail.test"],
        subject="Signed announcement",
        body="This message is cryptographically signed by Alice.",
        sign=True,
    )

    signed_msg = mem.sent[0]
    print(f"  ✓ Signature (first 40 chars): {signed_msg.signature[:40]}…")
    print(f"  ✓ Sender public key (first 20): {signed_msg.sender_public_key[:20]}…")

    valid = sdk.verify_message(signed_msg)
    print(f"  ✓ Signature valid: {valid}")
    assert valid, "Signature verification failed!"

    # Tamper and re-verify
    from copy import copy
    tampered = copy(signed_msg)
    tampered.body = "I am definitely Alice... or am I?"
    invalid = sdk.verify_message(tampered)
    print(f"  ✓ Tampered message signature valid: {invalid}  (expected False)")
    assert not invalid, "Tampered message should NOT verify!"
    print("  ✓ Tampering detected correctly ✓")

    await sdk.stop()


async def demo_message_queue():
    """Enqueue several messages; observe retry and dead-letter behaviour."""
    print(f"\n{SEP}")
    print("  DEMO 5 · Message queue with retries and dead-letter")
    print(SEP)

    # Adapter fails the first 5 sends → message must retry
    bad_mem  = MemoryAdapter(fail_first_n=5)
    good_mem = MemoryAdapter()
    bad_mem.adapter_id      = "unreliable"
    bad_mem.priority_weight = 90
    good_mem.adapter_id     = "backup"
    good_mem.priority_weight = 20

    sdk = OmniMailSDK(enable_queue=True, max_retries=3)
    sdk.register_adapter("unreliable", bad_mem)
    sdk.register_adapter("backup",     good_mem)
    await sdk.start()

    results = {}

    def on_done(msg, report):
        results[msg.id] = report.success
        print(
            f"  Callback: {msg.subject!r} → "
            f"{'✓ delivered' if report.success else '✗ failed'}"
        )

    # Message that will succeed via backup adapter
    id1 = await sdk.send(
        sender="system@omnimail.test",
        to=["users@omnimail.test"],
        subject="Weekly digest",
        body="Here is your weekly digest.",
        on_complete=on_done,
    )

    # A message to the dead-letter queue (needs its own retry counter)
    very_bad = MemoryAdapter(fail_first_n=999)
    very_bad.adapter_id = "black-hole"
    very_bad.priority_weight = 5
    sdk.register_adapter("black-hole", very_bad)

    id2 = await sdk.send(
        sender="system@omnimail.test",
        to=["lost@nowhere"],
        subject="This will fail",
        body="Nobody will read this.",
        preferred_adapters=["black-hole"],
        on_complete=on_done,
    )

    # Wait for the queue to process
    await asyncio.sleep(3)
    await sdk.stop()

    stats = sdk.queue_stats
    print(f"  ✓ Queue stats: {stats}")
    print(f"  ✓ Dead-letter count: {len(sdk.dead_letter_queue())}")


async def demo_lightning():
    """Attach a Lightning invoice to a priority message."""
    print(f"\n{SEP}")
    print("  DEMO 6 · Lightning Network micropayment (stub mode)")
    print(SEP)

    lightning = LightningPaymentService.stub()
    sdk = OmniMailSDK(enable_queue=False, lightning_service=lightning)
    mem = MemoryAdapter()
    sdk.register_adapter("memory", mem)
    await sdk.start()

    msg_id = await sdk.send(
        sender="merchant@omnimail.test",
        to=["vip@omnimail.test"],
        subject="Priority delivery (1 sat surcharge)",
        body="This message was delivered on the Lightning fast lane.",
        lightning_msats=1000,
    )

    sent = mem.sent[0]
    print(f"  ✓ Priority: {sent.priority}")
    print(f"  ✓ Lightning invoice: {sent.lightning.invoice[:40]}…")
    print(f"  ✓ Amount: {lightning.format_amount(sent.lightning.amount_msats)}")
    print(f"  ✓ Payment hash: {sent.lightning.payment_hash[:32]}…")

    # Verify payment (stub always returns True)
    settled = await lightning.verify_payment(sent.lightning)
    print(f"  ✓ Payment settled: {settled}")

    await sdk.stop()


async def demo_broadcast():
    """Broadcast a message via all registered adapters simultaneously."""
    print(f"\n{SEP}")
    print("  DEMO 7 · Broadcast delivery mode")
    print(SEP)

    sdk  = OmniMailSDK(enable_queue=False)
    mem1 = MemoryAdapter(); mem1.adapter_id = "channel-1"
    mem2 = MemoryAdapter(); mem2.adapter_id = "channel-2"
    mem3 = MemoryAdapter(); mem3.adapter_id = "channel-3"
    for a in (mem1, mem2, mem3):
        sdk.register_adapter(a.adapter_id, a)
    await sdk.start()

    msg_id = await sdk.send(
        sender="news@omnimail.test",
        to=[],   # broadcast doesn't need explicit recipients
        subject="Breaking news",
        body="OmniMail now supports broadcast delivery!",
        delivery_mode=DeliveryMode.BROADCAST,
    )

    print(f"  ✓ Broadcast sent (id={msg_id[:8]}…)")
    for adapter in (mem1, mem2, mem3):
        count = len(adapter.sent)
        print(f"    {adapter.adapter_id}: received {count} message(s)")

    await sdk.stop()


async def demo_message_serialisation():
    """Show JSON serialisation round-trip."""
    print(f"\n{SEP}")
    print("  DEMO 8 · Message JSON serialisation round-trip")
    print(SEP)

    original = OmniMessage(
        sender="alice@omnimail.test",
        recipients=["bob@omnimail.test"],
        subject="Serialisation test",
        body="Does JSON round-tripping work?",
        headers={"custom": "value", "priority_reason": "demo"},
    )

    serialised = original.to_json(indent=2)
    recovered  = OmniMessage.from_json(serialised)

    print(f"  ✓ Original  id: {original.id[:8]}…")
    print(f"  ✓ Recovered id: {recovered.id[:8]}…")
    assert original.id == recovered.id
    assert original.fingerprint() == recovered.fingerprint()
    print("  ✓ Round-trip integrity check PASSED")
    print(f"\n  Sample packet (truncated):\n")
    lines = serialised.splitlines()[:18]
    for line in lines:
        print(f"    {line}")
    print("    …")


# ──────────────────────────────────────────────────────────────────────────────
# Main
# ──────────────────────────────────────────────────────────────────────────────

async def main():
    print()
    print("╔══════════════════════════════════════════════════════════════╗")
    print("║       OmniMail Protocol – Reference Implementation Demo       ║")
    print("╚══════════════════════════════════════════════════════════════╝")

    await demo_basic_send_receive()
    await demo_multi_adapter_fallback()
    await demo_encryption()
    await demo_signatures()
    await demo_message_queue()
    await demo_lightning()
    await demo_broadcast()
    await demo_message_serialisation()

    print(f"\n{SEP}")
    print("  All demos completed successfully. 🎉")
    print(SEP)


if __name__ == "__main__":
    asyncio.run(main())
