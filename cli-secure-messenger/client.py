#!/usr/bin/env python3
import asyncio
import argparse
import base64
import json
import os
import sys
import time
import hashlib

import websockets

from nacl.secret import SecretBox
from nacl.utils import random as nacl_random
from argon2.low_level import hash_secret_raw, Type

def derive_key(passcode: str, conversation_id: str) -> bytes:
    """
    Derive a 32-byte key from passcode + conversation_id using Argon2id.
    conversation_id is a deterministic salt (e.g., sorted usernames "alice|bob").
    """
    salt = hashlib.blake2b(conversation_id.encode('utf-8'), digest_size=16).digest()
    key = hash_secret_raw(
        secret=passcode.encode('utf-8'),
        salt=salt,
        time_cost=2,
        memory_cost=64 * 1024,  # 64 MB
        parallelism=2,
        hash_len=32,
        type=Type.ID
    )
    return key

def encrypt_message(key: bytes, plaintext: str) -> dict:
    box = SecretBox(key)
    nonce = nacl_random(SecretBox.NONCE_SIZE)  # 24 bytes
    ct = box.encrypt(plaintext.encode('utf-8'), nonce)
    # ct contains nonce + ciphertext; but we'll send nonce separately for clarity
    # SecretBox.encrypt returns nonce+ciphertext+mac; we already supplied nonce, so ct.ciphertext includes MAC.
    # Extract ciphertext portion (skip first 24 bytes)
    ciphertext = ct.ciphertext
    return {
        "nonce": base64.b64encode(nonce).decode('ascii'),
        "ciphertext": base64.b64encode(ciphertext).decode('ascii'),
        "alg": "xsalsa20poly1305"
    }

def decrypt_message(key: bytes, payload: dict) -> str:
    box = SecretBox(key)
    nonce = base64.b64decode(payload["nonce"])
    ciphertext = base64.b64decode(payload["ciphertext"])
    # SecretBox expects nonce + ciphertext
    combined = nonce + ciphertext
    pt = box.decrypt(combined)
    return pt.decode('utf-8')

async def receiver(ws, key):
    async for raw in ws:
        try:
            obj = json.loads(raw)
        except Exception:
            continue
        if obj.get("type") == "message":
            try:
                text = decrypt_message(key, obj["payload"])
                # Simple local self-destruct on print (content isn't stored)
                exp = obj.get("expires_at")
                ttl_left = max(0, int(exp - time.time())) if exp else None
                print(f"\n[From {obj.get('from')} | TTL ~{ttl_left}s] {text}\n> ", end="", flush=True)
            except Exception:
                print("\n[!] Received message but failed to decrypt (wrong passcode?).\n> ", end="", flush=True)
        elif obj.get("type") == "pong":
            pass

async def sender(ws, key, me, peer, ttl):
    loop = asyncio.get_event_loop()
    while True:
        # Readline blocking wrapped in executor
        msg = await loop.run_in_executor(None, lambda: input("> "))
        if not msg:
            continue
        payload = encrypt_message(key, msg)
        await ws.send(json.dumps({"type":"send","to":peer,"payload":payload,"ttl":ttl}))

async def main():
    ap = argparse.ArgumentParser(description="CLI E2E Messenger (PoC)")
    ap.add_argument("--server", default="ws://localhost:8765", help="ws://host:port or wss://host:port")
    ap.add_argument("--user", required=True, help="Your username")
    ap.add_argument("--peer", required=True, help="Recipient username")
    ap.add_argument("--passcode", required=True, help="Shared passcode")
    ap.add_argument("--ttl", type=int, default=30, help="Message time-to-live seconds (server-enforced 5-60s)")
    args = ap.parse_args()

    conversation_id = "|".join(sorted([args.user, args.peer]))
    key = derive_key(args.passcode, conversation_id)

    # Optional TLS: if using self-signed cert, you may need to disable verify (NOT recommended for prod).
    ssl_context = None
    if args.server.startswith("wss://"):
        import ssl
        ssl_context = ssl.create_default_context()
        # For demo with self-signed certs, uncomment next line (insecure):
        # ssl_context.check_hostname = False; ssl_context.verify_mode = ssl.CERT_NONE

    async with websockets.connect(args.server, ssl=ssl_context) as ws:
        # Send hello
        await ws.send(json.dumps({"type":"hello","user": args.user}))

        # Start tasks
        recv_task = asyncio.create_task(receiver(ws, key))
        send_task = asyncio.create_task(sender(ws, key, args.user, args.peer, args.ttl))

        # Keepalive pings
        async def pinger():
            while True:
                try:
                    await ws.send(json.dumps({"type":"ping"}))
                except Exception:
                    break
                await asyncio.sleep(10)
        ping_task = asyncio.create_task(pinger())

        done, pending = await asyncio.wait([recv_task, send_task, ping_task], return_when=asyncio.FIRST_COMPLETED)
        for t in pending:
            t.cancel()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
