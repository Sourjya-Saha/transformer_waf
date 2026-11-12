"""Unit and integration test suite for the Transformer WAF (waf/ package)."""
import json
import os
import sys
import tempfile
from pathlib import Path
import pytest

# Add waf folder to sys.path
WAF_DIR = Path(__file__).resolve().parent.parent / "waf"
if str(WAF_DIR) not in sys.path:
    sys.path.insert(0, str(WAF_DIR))

import data
import chain
from model import Scorer
from waf import Waf


@pytest.fixture(scope="session")
def model_dir():
    return str(WAF_DIR / "model")


@pytest.fixture
def temp_chain_file():
    with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as f:
        path = f.name
    yield path
    if os.path.exists(path):
        os.remove(path)


def test_scorer_loading(model_dir):
    """Ensure transformer scorer loads weights and config correctly."""
    scorer = Scorer(model_dir)
    assert scorer.threshold > 0
    assert "thresholds" in scorer.cfg
    assert scorer.tok is not None


def test_normalization_rules():
    """Verify normalization decodes multi-level url encoding and collapses parameters."""
    norm = data.normalize("GET", "/rest/products/search?q=apple", "Mozilla/5.0")
    assert norm == "GET /rest/products/search?q=apple UA=mozilla REF=NONE"

    # Multi-pass decoding test
    norm_encoded = data.normalize("GET", "/rest/products/search?q=%2527%2520OR%25201%253D1--")
    assert "' or 1=1--" in norm_encoded


def test_benign_vs_attack_scoring(model_dir, temp_chain_file):
    """Test that benign juice shop queries pass while SQL injection is flagged."""
    waf = Waf(model_dir=model_dir, chain_path=temp_chain_file, threshold=1.0)

    # Benign query
    r_benign = waf.inspect("GET", "/rest/products/search?q=apple", "Mozilla/5.0", record=False)
    assert r_benign["flagged"] is False
    assert r_benign["score"] < 1.0

    # SQL Injection query
    r_attack = waf.inspect("GET", "/rest/products/search?q=' OR 1=1--", "Mozilla/5.0", record=False)
    assert r_attack["flagged"] is True
    assert r_attack["score"] >= 1.0


def test_hash_chain_integrity(temp_chain_file):
    """Test cryptographic SHA-256 tamper-evident log chaining and verification."""
    c = chain.Chain(temp_chain_file)
    c.append("127.0.0.1", "GET /test", 0.15, "ALLOWED")
    c.append("127.0.0.1", "GET /attack", 2.50, "FLAGGED")

    # Verify intact chain
    ok, count, head_hash = chain.verify(temp_chain_file)
    assert ok is True
    assert count == 2
    assert len(head_hash) == 64

    # Tamper with the chain file
    with open(temp_chain_file, "r") as f:
        content = f.readlines()

    # Modify line 0 payload
    tampered_entry = json.loads(content[0])
    tampered_entry["score"] = 9.99
    content[0] = json.dumps(tampered_entry) + "\n"

    with open(temp_chain_file, "w") as f:
        f.writelines(content)

    # Verification must fail
    ok, count, head_hash = chain.verify(temp_chain_file)
    assert ok is False
    assert count == 0


def test_flask_endpoints(model_dir, temp_chain_file):
    """Test Flask server /health, /check, and /score endpoints."""
    from flask import Flask, Response, request

    waf = Waf(model_dir=model_dir, chain_path=temp_chain_file, threshold=1.0)
    app = Flask("test_waf")

    @app.get("/health")
    def health():
        return {"status": "healthy", "service": "transformer-waf"}, 200

    @app.post("/score")
    def score():
        j = request.get_json(force=True)
        r = waf.inspect(j.get("method", "GET"), j["uri"], j.get("user_agent"), j.get("referer"), j.get("client_ip", "-"))
        r["tokens"] = sorted(r["tokens"], key=lambda t: -t[1])[:8]
        return r

    @app.route("/check", methods=["GET", "POST"])
    def check():
        h = request.headers
        r = waf.inspect(h.get("X-Original-Method", "GET"), h.get("X-Original-URI", "/"), h.get("User-Agent"),
                        h.get("Referer"), h.get("X-Real-IP", "-"))
        return ("", 403 if r["flagged"] else 204)

    client = app.test_client()

    # 1. Health endpoint
    h_resp = client.get("/health")
    assert h_resp.status_code == 200
    assert h_resp.get_json()["status"] == "healthy"

    # 2. Score endpoint
    s_resp = client.post("/score", json={"method": "GET", "uri": "/rest/products/search?q=apple", "user_agent": "Mozilla/5.0"})
    assert s_resp.status_code == 200
    res_data = s_resp.get_json()
    assert "score" in res_data
    assert res_data["flagged"] is False

    # 3. Check endpoint (benign)
    c_benign = client.get("/check", headers={
        "X-Original-Method": "GET",
        "X-Original-URI": "/rest/products/search?q=apple",
        "User-Agent": "Mozilla/5.0"
    })
    assert c_benign.status_code == 204

    # 4. Check endpoint (malicious attack)
    c_attack = client.get("/check", headers={
        "X-Original-Method": "GET",
        "X-Original-URI": "/rest/products/search?q=' OR 1=1--",
        "User-Agent": "Mozilla/5.0"
    })
    assert c_attack.status_code == 403
