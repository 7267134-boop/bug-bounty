"""Stage 4 OOB tests: interactsh wrapper + collaborator driver (offline).

The driver's HTTP layer is stubbed at module level; cryptography is real,
so register → inject → poll → decrypt is exercised end to end without
touching the network.
"""

import base64
import json
import os
from pathlib import Path

import pytest

from master.orchestrator import ALLOWED_TOOLS, load_workflow

from worker.tools.base import ExecResult, ToolExecutionError
from worker.tools.drivers import interactsh as drv
from worker.tools.registry import known_tools, resolve_tool

from _helpers import _ctx, _res

WORKFLOWS = Path(__file__).resolve().parent.parent / "workflows"


# --------------------------------------------------------------------- #
# Wrapper contract                                                       #
# --------------------------------------------------------------------- #
class TestWrapperContract:
    def test_registered_and_allowed(self):
        assert "interactsh" in known_tools()
        assert "interactsh" in ALLOWED_TOOLS

    def test_dataflow_contract(self):
        tool = resolve_tool("interactsh", ["interactsh"])
        assert tool.consumes == ["url_param"]
        assert tool.produces == ["vulnerability"]
        assert tool.needs_input_file is True

    def test_argv_contains_driver_and_params(self, tmp_path):
        tool = resolve_tool("interactsh", ["interactsh"])
        ctx = _ctx(tmp_path, input_file=str(tmp_path / "in.txt"),
                   params={"server": "oast.fun", "duration_secs": 60,
                           "max_urls": 10})
        argv = tool.build_argv(ctx)
        assert argv[1].endswith("drivers" + os.sep + "interactsh.py")
        assert "--server" in argv and "oast.fun" in argv
        assert "--duration-secs" in argv and "60" in argv

    def test_param_clamping(self, tmp_path):
        tool = resolve_tool("interactsh", ["interactsh"])
        ctx = _ctx(tmp_path, input_file="x", params={"duration_secs": 99999,
                                                     "max_urls": 0})
        argv = tool.build_argv(ctx)
        assert argv[argv.index("--duration-secs") + 1] == str(tool.DURATION_MAX)
        assert argv[argv.index("--max-urls") + 1] == str(tool.URLS_MIN)

    def test_illegal_server_charset_rejected(self, tmp_path):
        tool = resolve_tool("interactsh", ["interactsh"])
        ctx = _ctx(tmp_path, input_file="x",
                   params={"server": "bad host; rm -rf"})
        with pytest.raises(ToolExecutionError):
            tool.build_argv(ctx)

    def test_parse_findings(self, tmp_path):
        tool = resolve_tool("interactsh", ["interactsh"])
        row = json.dumps({"found": True, "url": "https://x.com/?u=1",
                          "protocol": "dns", "remote": "1.2.3.4",
                          "unique-id": "cid123tok"})
        findings = tool.parse(_res(row + "\ngarbage\n"), _ctx(tmp_path))
        (f,) = findings
        assert f["id"] == "interactsh-oob"
        assert f["severity"] == "high"
        assert f["evidence"]["protocol"] == "dns"

    def test_parse_garbage_is_empty(self, tmp_path):
        tool = resolve_tool("interactsh", ["interactsh"])
        assert tool.parse(_res("not {json\n[]\n"), _ctx(tmp_path)) == []


# --------------------------------------------------------------------- #
# Driver units                                                           #
# --------------------------------------------------------------------- #
class TestDriverUnits:
    def test_random_id_dns_safe(self):
        for _ in range(20):
            rid = drv.random_id(20)
            assert len(rid) == 20
            assert rid.isalnum() and rid.islower()

    def test_registration_payload_shape(self):
        aes, hmac_key = b"A" * 16, b"H" * 32
        payload = drv.build_registration_payload(b"PUBDER", aes, hmac_key)
        raw = base64.b64decode(payload)
        assert raw[:4] == drv.MAGIC
        assert raw[4:20] == aes and raw[20:52] == hmac_key
        assert raw[52:] == b"PUBDER"

    def test_registration_payload_bad_lengths(self):
        with pytest.raises(drv.InteractshError):
            drv.build_registration_payload(b"P", b"short", b"H" * 32)

    def test_inject_callback_replaces_values_keeps_names(self):
        out = drv.inject_callback("https://x.com/a?user=bob&debug=1",
                                  "cid.tok.oast.pro")
        q = out.split("?", 1)[1]
        assert "user=http%3A%2F%2Fcid.tok.oast.pro%2Fprobe" in q
        assert "debug=http" in q and "bob" not in q

    def test_inject_callback_no_query_returns_none(self):
        assert drv.inject_callback("https://x.com/path", "c.oast.pro") is None

    def test_probe_plan_caps_and_skips_uninjectable(self):
        urls = [f"https://x.com/?p={i}" for i in range(30)] + \
               ["https://x.com/noquery"]
        plan = drv.build_probe_plan(urls, "cid", "oast.pro", max_urls=5)
        assert len(plan) == 5
        tokens = {t for _, t, _ in plan}
        assert len(tokens) == 5                      # unique nonces
        assert all(".oast.pro" in injected for _, _, injected in plan)

    def test_match_interactions_filters_foreign_ids(self):
        plan_tokens = {"tokaaa", "tokbbb"}
        t2u = {"tokaaa": "https://a.com/?p=1", "tokbbb": "https://b.com/?p=2"}
        interactions = [
            {"unique-id": "cidtokaaa", "protocol": "http",
             "remote-address": "9.9.9.9"},
            {"unique-id": "someoneelse", "full-id": "someoneelse.oast.pro"},
            "garbage-not-a-dict",
        ]
        rows = drv.match_interactions(interactions, plan_tokens, t2u)
        (row,) = rows
        assert row["url"] == "https://a.com/?p=1"
        assert row["found"] and row["remote"] == "9.9.9.9"


# --------------------------------------------------------------------- #
# Decrypt dual-mode (CTR on newer servers, CFB on stable ones)           #
# --------------------------------------------------------------------- #
def _encrypt_sample(priv, mode, plaintext: bytes):
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding
    from cryptography.hazmat.primitives.ciphers import (
        Cipher, algorithms,
    )

    aes_key, iv = os.urandom(16), os.urandom(16)
    enc = Cipher(algorithms.AES(aes_key), mode(iv)).encryptor()
    ct = enc.update(plaintext) + enc.finalize()
    wrapped = priv.public_key().encrypt(
        aes_key, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                              algorithm=hashes.SHA256(), label=None))
    return (base64.b64encode(wrapped).decode(),
            base64.b64encode(iv + ct).decode())


def _mode_class(name: str):
    """Resolve a cipher-mode class without tripping deprecation warnings:
    CTR comes from primitives; CFB via the driver's own decrepit-aware
    resolver (_supported_modes), mirroring production behavior."""
    if name == "CTR":
        from cryptography.hazmat.primitives.ciphers import modes
        return modes.CTR
    return drv._supported_modes()[1]            # [0] is CTR


class TestDecryptDualMode:
    @pytest.mark.parametrize("mode_name", ["CTR", "CFB"])
    def test_both_modes(self, mode_name):
        priv, _ = drv.generate_keys()
        interactions = [{"unique-id": "cidtok", "protocol": "dns"}]
        key_b64, data_b64 = _encrypt_sample(
            priv, _mode_class(mode_name),
            json.dumps(interactions).encode())
        out = drv.decrypt_poll_response(priv, key_b64, data_b64)
        assert json.loads(out.decode()) == interactions

    def test_garbage_ciphertext_raises(self):
        priv, _ = drv.generate_keys()
        wrapped = base64.b64encode(os.urandom(256)).decode()
        with pytest.raises(drv.InteractshError):
            drv.decrypt_poll_response(priv, wrapped,
                                      base64.b64encode(os.urandom(64)).decode())


# --------------------------------------------------------------------- #
# Driver end-to-end (stubbed HTTP, real crypto)                          #
# --------------------------------------------------------------------- #
class TestDriverEndToEnd:
    def test_full_flow_emits_matching_interactions(self, tmp_path, monkeypatch,
                                                   capsys):
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding
        from cryptography.hazmat.primitives.ciphers import (
            Cipher, algorithms, modes,
        )

        infile = tmp_path / "urls.txt"
        infile.write_text("https://t.com/?q=abc\nhttps://t.com/noquery\n")

        state: dict = {}
        register_calls: list[dict] = []
        probe_urls: list[str] = []

        def fake_post(url, body, timeout):
            register_calls.append({"url": url, "body": body})
            raw = base64.b64decode(body["public-key"])
            assert raw[:4] == drv.MAGIC                       # magic header
            assert len(raw) > 4 + 16 + 32                     # keys + DER
            assert body["secret-key"] and len(body["secret-key"]) == 32
            return 200, {"message": "registration successful"}

        orig_plan = drv.build_probe_plan      # capture BEFORE patching

        def spy_plan(candidates, cid, host, max_urls):
            plan = orig_plan(candidates, cid, host, max_urls)
            state.update(cid=cid, host=host,
                         token_to_url={t: u for u, t, _ in plan})
            return plan

        orig_get = drv._get

        def fake_get(url, headers=None, timeout=10.0):
            if "/poll?" not in url:
                probe_urls.append(url)
                return 200, ""                                # probe GETs
            priv = state["priv"]
            token = next(iter(state["token_to_url"]))
            interactions = [{"unique-id": f"{state['cid']}{token}",
                             "protocol": "http", "remote-address": "8.8.8.8"}]
            aes_key, iv = os.urandom(16), os.urandom(16)
            enc = Cipher(algorithms.AES(aes_key), modes.CTR(iv)).encryptor()
            ct = enc.update(json.dumps(interactions).encode()) + enc.finalize()
            wrapped = priv.public_key().encrypt(
                aes_key, padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(), label=None))
            return 200, json.dumps({
                "aes_key": base64.b64encode(wrapped).decode(),
                "data": base64.b64encode(iv + ct).decode(),
            })

        monkeypatch.setattr(drv, "_post_json", fake_post)
        monkeypatch.setattr(drv, "_get", fake_get)
        monkeypatch.setattr(drv, "build_probe_plan", spy_plan)

        # capture the private key generated inside run()
        orig_keys = drv.generate_keys

        def spy_keys():
            priv, pub = orig_keys()
            state["priv"] = priv
            return priv, pub

        monkeypatch.setattr(drv, "generate_keys", spy_keys)

        clock = {"t": 0.0}

        def advance(seconds):
            clock["t"] += seconds

        rc = drv.run(str(infile), server="collab.example.internal",
                     duration_secs=6, max_urls=10, request_timeout=5,
                     poll_interval=3.0, _clock=lambda: clock["t"],
                     _sleep=advance)

        assert rc == drv.EXIT_OK
        assert len(register_calls) == 1
        assert register_calls[0]["url"] == \
            "https://collab.example.internal/register"
        # exactly one injectable URL was probed with our callback host
        assert len(probe_urls) == 1
        assert f"{state['cid']}" in probe_urls[0]
        assert ".collab.example.internal" in probe_urls[0]

        out = capsys.readouterr().out.strip().splitlines()
        assert len(out) == 1                            # one matching row
        row = json.loads(out[0])
        assert row["found"] is True
        assert row["url"] == "https://t.com/?q=abc"
        assert row["protocol"] == "http" and row["remote"] == "8.8.8.8"

    def test_empty_input_exit_3(self, tmp_path):
        infile = tmp_path / "empty.txt"
        infile.write_text("\n")
        clock = {"t": 0.0}
        rc = drv.run(str(infile), server="s.local", duration_secs=10,
                     max_urls=5, request_timeout=5,
                     _clock=lambda: clock["t"],
                     _sleep=lambda s: None)
        assert rc == drv.EXIT_NO_INPUT

    def test_register_failure_maps_to_exit_4(self, tmp_path, monkeypatch):
        infile = tmp_path / "urls.txt"
        infile.write_text("https://t.com/?a=1\n")

        def boom(*a, **kw):
            raise OSError("unreachable")

        monkeypatch.setattr(drv, "_post_json", boom)
        with pytest.raises(drv.InteractshError):
            drv.run(str(infile), server="s.local", duration_secs=10,
                    max_urls=5, request_timeout=5)


# --------------------------------------------------------------------- #
# Workflow integration                                                   #
# --------------------------------------------------------------------- #
class TestFocusedWorkflowOob:
    @pytest.fixture(scope="class")
    @classmethod
    def wf(cls):
        return load_workflow(WORKFLOWS / "focused.yaml")

    def test_oob_step_gate(self, wf):
        step = next(s for s in wf["steps"]
                    if s["name"] == "oob_ssrf_probe")
        assert step["tool"] == "interactsh"
        assert step["when"]["has_finding_type"] == "url_param"
        assert "crawl_urls" in step["depends_on"]

    def test_tool_allowed_on_master(self, wf):
        for s in wf["steps"]:
            assert s["tool"] in ALLOWED_TOOLS
