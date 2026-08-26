#!/usr/bin/env python3
"""Interactsh collaborator driver — blind SSRF / OOB interaction detection.

Implements the projectdiscovery/interactsh client protocol natively so no
extra binary is needed (the wrapper execs this file via ``sys.executable``,
argv-list only — consistent with the platform's zero-shell invariant).

Protocol flow (per run):
  1. RSA-2048 keygen; registration payload = MAGIC + aesKey(16) + hmacKey(32)
     + PKIX-DER public key, base64-encoded.
  2. ``POST https://<server>/register`` with
     ``{"public-key": <payload>, "secret-key": <random>}``;
     the server must answer 200 with "registration successful".
  3. For every candidate parameter-URL, each query-parameter value is
     replaced by a unique callback host ``<cid><nonce>.<server>`` and the
     URL is fetched once (bounded).
  4. Poll ``GET /poll?id=<cid>`` (Authorization: <secret>) until the budget
     expires; responses are RSA-OAEP(SHA-256) wrapped AES, ciphertext
     prefixed by a 16-byte IV (CFB on stable server releases, CTR on newer
     ones — both are attempted).
  5. Interactions whose unique-id carries one of our nonces are emitted as
     JSONL rows for the wrapper to parse.

Exit codes: 0 = ran (findings or none), 3 = nothing to probe,
4 = collaborator registration failure (retryable upstream).
"""

from __future__ import annotations

import argparse
import base64
import json
import secrets
import ssl
import sys
import time
import urllib.parse
import urllib.request

MAGIC = b"Clkg"                       # interactsh client magic header
CORRELATION_ID_LENGTH = 20            # matches CorrelationIdLengthDefault
NONCE_LENGTH = 20                     # per-payload unique component
AES_KEY_LEN = 16
HMAC_KEY_LEN = 32

_UNVERIFIED_SSL = ssl._create_unverified_context()  # noqa: S323 - target certs


class InteractshError(RuntimeError):
    """Fatal driver error (registration/protocol failure)."""


def random_id(length: int) -> str:
    """DNS-safe lowercase random identifier ([a-z0-9], length chars)."""
    alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
    return "".join(secrets.choice(alphabet) for _ in range(length))


# --------------------------------------------------------------------- #
# Crypto                                                                 #
# --------------------------------------------------------------------- #
def generate_keys():
    """Return (rsa_private_key, public_key_der_pkix)."""
    from cryptography.hazmat.primitives.serialization import (
        Encoding, PublicFormat,
    )
    from cryptography.hazmat.primitives.asymmetric import rsa

    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pub_der = priv.public_key().public_bytes(
        encoding=Encoding.DER, format=PublicFormat.SubjectPublicKeyInfo)
    return priv, pub_der


def build_registration_payload(pub_der: bytes, aes_key: bytes,
                               hmac_key: bytes) -> str:
    """MAGIC || aes || hmac || pubDER, base64 (interactsh register spec)."""
    if len(aes_key) != AES_KEY_LEN or len(hmac_key) != HMAC_KEY_LEN:
        raise InteractshError("bad key material lengths")
    payload = MAGIC + aes_key + hmac_key + pub_der
    return base64.b64encode(payload).decode("ascii")


def decrypt_poll_response(priv, aes_key_b64: str, data_b64: str) -> bytes:
    """Decrypt one poll response body.

    Server returns {"aes_key": <RSA-OAEP-SHA256 wrapped, b64>,
                    "data": <b64 ciphertext with 16-byte IV prefix>}.
    Newer servers use AES-CTR, stable releases used CFB; try both and keep
    the mode whose plaintext validates as JSON.
    """
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    wrapped = base64.b64decode(aes_key_b64)
    try:
        aes_key = priv.decrypt(wrapped, padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(), label=None))
    except ValueError as exc:
        raise InteractshError(f"aes key unwrap failed: {exc}") from exc
    if len(aes_key) not in (16, 24, 32):
        raise InteractshError(f"unexpected aes key size {len(aes_key)}")
    blob = base64.b64decode(data_b64)
    if len(blob) <= 16:
        raise InteractshError("ciphertext too short")
    iv, ct = blob[:16], blob[16:]

    last_error: Exception | None = None
    for mode in (_supported_modes()):
        try:
            dec = Cipher(algorithms.AES(aes_key), mode(iv)).decryptor()
            out = dec.update(ct) + dec.finalize()
            json.loads(out.decode("utf-8"))     # integrity check picks the mode
            return out
        except Exception as exc:                # noqa: BLE001 - try next mode
            last_error = exc
    raise InteractshError(f"poll decryption failed: {last_error}")


def _supported_modes() -> list:
    """CTR everywhere; CFB lives in `decrepit` on newer cryptography."""
    from cryptography.hazmat.primitives.ciphers import modes

    classes = [modes.CTR]
    try:                                        # cryptography >= 43
        from cryptography.hazmat.decrepit.ciphers.modes import CFB
        classes.append(CFB)
    except ImportError:                         # older releases
        classes.append(modes.CFB)
    return classes


# --------------------------------------------------------------------- #
# HTTP helpers (module-level so tests can stub them)                     #
# --------------------------------------------------------------------- #
def _post_json(url: str, body: dict, timeout: float) -> tuple[int, dict]:
    req = urllib.request.Request(
        url, data=json.dumps(body).encode(), method="POST",
        headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout, context=_UNVERIFIED_SSL) as r:
        return r.status, json.loads(r.read().decode() or "{}")


def _get(url: str, headers: dict | None = None,
         timeout: float = 10.0) -> tuple[int, str]:
    req = urllib.request.Request(url, headers=headers or {}, method="GET")
    with urllib.request.urlopen(req, timeout=timeout, context=_UNVERIFIED_SSL) as r:
        return r.status, r.read(512_000).decode(errors="replace")


def _fetch_no_raise(url: str, timeout: float) -> int | None:
    """Fire one GET at a candidate URL; status code or None on any failure."""
    try:
        status, _ = _get(url, timeout=timeout)
        return status
    except Exception:                       # noqa: BLE001 - probes must not crash
        return None


# --------------------------------------------------------------------- #
# Payload crafting                                                       #
# --------------------------------------------------------------------- #
def inject_callback(candidate_url: str, callback_host: str) -> str | None:
    """Replace every query-parameter value with the callback URL.

    Returns None when there is nothing injectable (no query string).
    Original parameter names are preserved to maximise sink coverage.
    """
    parsed = urllib.parse.urlsplit(candidate_url)
    if not parsed.query:
        return None
    callback = f"http://{callback_host}/probe"
    pairs = [
        (name, callback if value else value)
        for name, value in urllib.parse.parse_qsl(parsed.query,
                                                  keep_blank_values=True)
    ]
    return urllib.parse.urlunsplit(
        parsed._replace(query=urllib.parse.urlencode(pairs)))


def build_probe_plan(candidates: list[str], correlation_id: str,
                     server_host: str,
                     max_urls: int) -> list[tuple[str, str, str]]:
    """[(original_url, nonce_token, injected_url), ...] — capped, deduped."""
    plan: list[tuple[str, str, str]] = []
    seen: set[str] = set()
    for url in candidates:
        url = url.strip()
        if not url or url in seen:
            continue
        seen.add(url)
        token = random_id(NONCE_LENGTH)
        injected = inject_callback(url, f"{correlation_id}{token}.{server_host}")
        if injected is None:
            continue
        plan.append((url, token, injected))
        if len(plan) >= max_urls:
            break
    return plan


def match_interactions(interactions: list[dict], tokens: set[str],
                       token_to_url: dict[str, str]) -> list[dict]:
    """Keep only interactions that carry one of OUR nonce tokens."""
    matched: list[dict] = []
    for rec in interactions or []:
        if not isinstance(rec, dict):
            continue
        uid = str(rec.get("unique-id") or "")
        full_id = str(rec.get("full-id") or "")
        hit = next((t for t in tokens if t in uid or t in full_id), None)
        if hit is None:
            continue
        matched.append({
            "found": True,
            "url": token_to_url.get(hit, ""),
            "token": hit,
            "protocol": str(rec.get("protocol") or "?"),
            "remote": str(rec.get("remote-address") or ""),
            "unique-id": uid,
            "timestamp": str(rec.get("timestamp") or ""),
        })
    return matched


# --------------------------------------------------------------------- #
# Orchestration                                                          #
# --------------------------------------------------------------------- #
EXIT_OK, EXIT_NO_INPUT, EXIT_REGISTER_FAILED = 0, 3, 4


def run(input_file: str, *, server: str, duration_secs: int, max_urls: int,
        request_timeout: int, poll_interval: float = 3.0,
        _clock=time.monotonic, _sleep=time.sleep) -> int:
    """Full driver flow. Returns the process exit code."""
    with open(input_file, encoding="utf-8") as fh:
        candidates = [line.strip() for line in fh if line.strip()]
    if not candidates:
        print("no candidate urls", file=sys.stderr)
        return EXIT_NO_INPUT

    host = server.split("://", 1)[-1].rstrip("/")
    base = f"https://{host}"

    # 1-2. register a fresh collaborator session --------------------------
    try:
        priv, pub_der = generate_keys()
        aes_key = secrets.token_bytes(AES_KEY_LEN)
        hmac_key = secrets.token_bytes(HMAC_KEY_LEN)
        secret_key = random_id(32)
        cid = random_id(CORRELATION_ID_LENGTH)
        status, body = _post_json(f"{base}/register", {
            "public-key": build_registration_payload(pub_der, aes_key, hmac_key),
            "secret-key": secret_key,
        }, timeout=15)
        if status != 200 or str(body.get("message")) != "registration successful":
            raise InteractshError(f"register rejected: {status} {body}")
    except InteractshError:
        raise
    except Exception as exc:                # noqa: BLE001
        raise InteractshError(f"register failed: {exc}") from exc

    # 3. inject callbacks and fire the probes -----------------------------
    plan = build_probe_plan(candidates, cid, host, max_urls)
    if not plan:
        print("no injectable parameter urls", file=sys.stderr)
        return EXIT_NO_INPUT
    token_to_url = {token: original for original, token, _ in plan}
    tokens = set(token_to_url)
    for _, _, injected in plan:
        _fetch_no_raise(injected, timeout=request_timeout)

    # 4-5. poll until the interaction budget is spent ----------------------
    deadline = _clock() + duration_secs
    reported: set[str] = set()
    while _clock() < deadline:
        try:
            status, payload = _get(f"{base}/poll?id={cid}",
                                   headers={"Authorization": secret_key},
                                   timeout=15)
            if status == 200:
                doc = json.loads(payload)
                content = decrypt_poll_response(priv, str(doc.get("aes_key", "")),
                                                str(doc.get("data", "")))
                rows = match_interactions(json.loads(content.decode()),
                                          tokens, token_to_url)
                fresh = [r for r in rows if r["token"] not in reported]
                for row in fresh:
                    print(json.dumps(row, separators=(",", ":")))
                    reported.add(row["token"])
                if fresh:
                    sys.stdout.flush()
        except InteractshError as exc:
            print(f"poll error: {exc}", file=sys.stderr)
            return EXIT_OK                  # findings already printed survive
        except Exception:                   # noqa: BLE001 - transient poll issues
            pass
        remaining = deadline - _clock()
        if remaining > 0:
            _sleep(min(poll_interval, remaining))
    return EXIT_OK


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="interactsh OOB prober")
    parser.add_argument("input_file")
    parser.add_argument("--server", default="oast.pro")
    parser.add_argument("--duration-secs", type=int, default=30)
    parser.add_argument("--max-urls", type=int, default=25)
    parser.add_argument("--request-timeout", type=int, default=10)
    parser.add_argument("--poll-interval", type=float, default=3.0)
    args = parser.parse_args(argv)
    try:
        return run(args.input_file, server=args.server,
                   duration_secs=args.duration_secs, max_urls=args.max_urls,
                   request_timeout=args.request_timeout,
                   poll_interval=args.poll_interval)
    except InteractshError as exc:
        print(f"interactsh driver: {exc}", file=sys.stderr)
        return EXIT_REGISTER_FAILED


if __name__ == "__main__":
    sys.exit(main())
