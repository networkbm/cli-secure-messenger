# CLI Secure Messenger (PoC)

A minimal, end-to-end encrypted CLI messenger with ephemeral (self-destructing) messages.

- **E2E crypto**: XSalsa20-Poly1305 (`PyNaCl.SecretBox`) with a key derived from a shared passcode via **Argon2id**.
- **Transport**: WebSocket relay server. Optional TLS (`wss://`) if you provide `cert.pem` and `key.pem`.
- **Ephemeral**: Messages expire server-side after **TTL** (default 30s). Client does not persist plaintext.
- **Passcode-gated reading**: Without the correct passcode, ciphertext cannot be decrypted (server never sees plaintext).

> This is a teaching/demo project, **not** a production-ready secure messenger. See Security Notes below.

## Quick Start

### 1) Install
```bash
python3 -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

### 2) Run the relay server
```bash
python server.py
```
The server listens on `ws://0.0.0.0:8765` by default.

**Enable TLS (optional):**
- Create `cert.pem` and `key.pem` next to `server.py` and set `USE_TLS = True` at the top of `server.py`.
- Then run the server and connect via `wss://HOST:8765`.

### 3) Open two terminals as users

**Terminal A (Alice):**
```bash
python client.py --server ws://localhost:8765 --user alice --peer bob --passcode "correct horse battery staple"
```

**Terminal B (Bob):**
```bash
python client.py --server ws://localhost:8765 --user bob --peer alice --passcode "correct horse battery staple"
```

Now type messages in either terminal. They will be end-to-end encrypted with the passcode key.

### TTL (Self-Destruct)
- Default TTL is **30 seconds** (server-enforced between 5–60s).
- Set a custom TTL:
```bash
python client.py --server ws://localhost:8765 --user alice --peer bob --passcode "secret" --ttl 20
```

## Security Notes (Read Me)

- This PoC uses a **shared passcode** and a deterministic salt derived from usernames to derive the symmetric key (Argon2id). Choose a strong passcode.
- Messages are end-to-end encrypted; the relay server cannot read their contents.
- **Forward secrecy** is limited. For production, add an **X25519** ephemeral key exchange per session or implement the **Double Ratchet** (Signal protocol).
- **Authentication** is minimal (usernames are not verified). In production, add proper identity verification and out-of-band key verification (e.g., safety numbers/QR).
- Transport security: enabling **TLS (wss://)** protects metadata and prevents passive interception at the transport layer. E2E already protects message content.
- The server stores only ciphertext and deletes messages after TTL. This is **in-memory** and ephemeral in this PoC.
- Client does **not** persist plaintext messages; once printed, they're gone unless your terminal scrollback saves them.

## License
MIT
