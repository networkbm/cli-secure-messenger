#!/usr/bin/env python3
import asyncio
import json
import time
from collections import defaultdict, deque
from typing import Dict, Deque, Any, Optional

import websockets

# Optional TLS support:
# To enable TLS, create cert.pem and key.pem alongside this file and set USE_TLS=True.
USE_TLS = False
CERT_FILE = "cert.pem"
KEY_FILE = "key.pem"

# In-memory mailbox with TTL (seconds)
TTL_SECONDS = 30

# Structure: inbox[recipient] = deque([ (expires_at, message_json_str), ... ])
inbox: Dict[str, Deque] = defaultdict(deque)

connected = {}  # username -> websocket


async def cleanup_loop():
    while True:
        now = time.time()
        for user, dq in list(inbox.items()):
            # Remove expired messages
            while dq and dq[0][0] <= now:
                dq.popleft()
        await asyncio.sleep(1.0)


async def deliver_queued(user: str):
    ws = connected.get(user)
    if not ws:
        return
    dq = inbox.get(user)
    if not dq:
        return
    # deliver all non-expired now
    now = time.time()
    remaining = deque()
    while dq:
        exp, msg = dq.popleft()
        if exp > now:
            try:
                await ws.send(msg)
            except Exception:
                # If send fails, keep it for later
                remaining.append((exp, msg))
    if remaining:
        inbox[user] = remaining


async def handle_client(websocket):
    # First message from client must be {"type":"hello","user":"alice"}
    try:
        hello = await asyncio.wait_for(websocket.recv(), timeout=10)
        hello_obj = json.loads(hello)
        if hello_obj.get("type") != "hello" or "user" not in hello_obj:
            await websocket.close(code=4000, reason="Bad hello")
            return
        user = hello_obj["user"]
    except Exception:
        await websocket.close(code=4001, reason="Hello timeout")
        return

    # Register connection
    connected[user] = websocket
    try:
        # Immediately deliver queued messages
        await deliver_queued(user)

        async for raw in websocket:
            try:
                obj = json.loads(raw)
            except Exception:
                continue

            if obj.get("type") == "send":
                # Expected fields: to, payload (opaque), ttl (seconds, optional)
                to_user = obj.get("to")
                ttl = int(obj.get("ttl", TTL_SECONDS))
                if not to_user or "payload" not in obj:
                    continue
                # Enforce ttl bounds (between 5 and 60s)
                ttl = max(5, min(60, ttl))
                expires_at = time.time() + ttl
                msg = json.dumps({
                    "type": "message",
                    "from": user,
                    "to": to_user,
                    "payload": obj["payload"],
                    "expires_at": expires_at
                })
                # If recipient is online, attempt to deliver immediately
                rcpt_ws = connected.get(to_user)
                delivered = False
                if rcpt_ws:
                    try:
                        await rcpt_ws.send(msg)
                        delivered = True
                    except Exception:
                        delivered = False

                if not delivered:
                    inbox[to_user].append((expires_at, msg))

            elif obj.get("type") == "ping":
                await websocket.send(json.dumps({"type": "pong"}))

    finally:
        # Unregister
        if connected.get(user) is websocket:
            del connected[user]


async def main():
    ssl_context = None
    if USE_TLS:
        import ssl
        ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ssl_context.load_cert_chain(CERT_FILE, KEY_FILE)

    port = 8765
    async with websockets.serve(handle_client, "0.0.0.0", port, ssl=ssl_context):
        print(f"Server listening on {'wss' if USE_TLS else 'ws'}://0.0.0.0:{port}")
        await cleanup_loop()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
