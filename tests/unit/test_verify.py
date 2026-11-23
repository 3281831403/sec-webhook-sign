"""契约测试：10 条，每条对应题面中的一个缺陷。"""

import hashlib
import hmac

from hook.verify import (
    canonical_request,
    hook_batch,
    nonce_seen,
    sign,
    timestamp_ok,
    validate_policy,
    verify_request,
    verify_signature,
)

SECRET = "whsec_test_secret"
NOW = 1_700_000_000


def _policy(**overrides):
    policy = {
        "window": 300,
        "replay": True,
        "algorithm": "sha256",
        "nonce_store": {},
    }
    policy.update(overrides)
    return policy


def _signed_request(
    secret,
    now,
    nonce,
    body=b'{"amount": 100}',
    event="payment",
    tamper_body=None,
):
    timestamp = str(now)
    headers = {
        "X-Timestamp": timestamp,
        "X-Nonce": nonce,
        "X-Event": event,
    }
    canonical = canonical_request(body, headers, timestamp)
    headers["X-Signature"] = sign(secret, canonical)
    sent_body = body if tamper_body is None else tamper_body
    return {"body": sent_body, "headers": headers}


def test_canonical_request_sorts_headers_and_ignores_insertion_order():
    body = b'{"amount": 100}'
    timestamp = "1700000000"
    headers_a = {
        "X-Event": "payment",
        "X-Nonce": "n-1",
        "X-Timestamp": timestamp,
        "X-Signature": "00",
        "X-Empty": "",
    }
    headers_b = {
        "X-Empty": None,
        "X-Signature": "00",
        "X-Timestamp": timestamp,
        "X-Nonce": "n-1",
        "X-Event": "payment",
    }
    expected = (
        "v1\n"
        + timestamp
        + "\n"
        + hashlib.sha256(body).hexdigest()
        + "\nx-event:payment\nx-nonce:n-1"
    )
    assert canonical_request(body, headers_a, timestamp) == expected
    assert canonical_request(body, headers_b, timestamp) == expected


def test_canonical_request_changes_when_body_changes():
    headers = {"X-Nonce": "n-2"}
    timestamp = "1700000000"
    first = canonical_request(b'{"amount": 100}', headers, timestamp)
    second = canonical_request(b'{"amount": 999}', headers, timestamp)
    assert first != second
    assert hashlib.sha256(b'{"amount": 999}').hexdigest() in second


def test_verify_signature_uses_constant_time_compare(monkeypatch):
    secret = "Jefe"
    payload = "what do ya want for nothing?"
    expected = "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
    observed = []
    real_compare = hmac.compare_digest

    def spy(left, right):
        observed.append((left, right))
        return real_compare(left, right)

    monkeypatch.setattr(hmac, "compare_digest", spy)
    assert sign(secret, payload) == expected
    assert verify_signature(secret, payload, expected) is True
    assert observed
    assert verify_signature(secret, payload + "!", expected) is False
    altered = ("1" if expected[0] == "0" else "0") + expected[1:]
    assert verify_signature(secret, payload, altered) is False
    assert verify_signature(secret, payload, expected[:-1]) is False
    assert verify_signature(secret, payload, None) is False


def test_verify_request_verifies_raw_body_before_json_parse():
    body = b"not-json-{"
    timestamp = str(NOW)
    headers = {"X-Timestamp": timestamp, "X-Nonce": "n-4"}
    canonical = canonical_request(body, headers, timestamp)
    headers["X-Signature"] = sign(SECRET, canonical)
    result = verify_request(
        {"body": body, "headers": headers}, SECRET, _policy(), NOW
    )
    assert result["checks"]["signature"] is True
    assert result["checks"]["body"] is False
    assert result["ok"] is False
    assert "body_invalid_json" in result["reasons"]


def test_timestamp_ok_rejects_future_and_includes_both_ends():
    window = 300
    assert timestamp_ok(NOW, NOW, window) is True
    assert timestamp_ok(NOW - window, NOW, window) is True
    assert timestamp_ok(NOW - window - 1, NOW, window) is False
    assert timestamp_ok(NOW + 1, NOW, window) is False


def test_timestamp_ok_uses_policy_window():
    assert timestamp_ok(NOW - 120, NOW, 60) is False
    assert timestamp_ok(NOW - 120, NOW, 600) is True
    problems = validate_policy(
        {"window": None, "replay": True, "algorithm": "sha256"}
    )
    assert problems == ["window_missing"]


def test_nonce_seen_detects_replay():
    store = {}
    assert nonce_seen(store, "nonce-7", NOW) is False
    assert "nonce-7" in store
    assert nonce_seen(store, "nonce-7", NOW + 1) is True


def test_nonce_seen_purges_expired_entries():
    store = {"expired": NOW - 1, "live": NOW + 100}
    assert nonce_seen(store, "fresh", NOW) is False
    assert "expired" not in store
    assert "live" in store
    assert store["fresh"] == NOW + 600
    assert nonce_seen(store, "fresh", NOW + 599) is True
    assert nonce_seen(store, "fresh-2", NOW + 601) is False
    assert "fresh" not in store


def test_validate_policy_flags_weak_algorithm():
    assert validate_policy(_policy()) == []
    assert "algorithm_weak" in validate_policy(_policy(algorithm="md5"))
    assert "algorithm_weak" in validate_policy(_policy(algorithm="sha1"))
    assert "algorithm_weak" not in validate_policy(_policy(algorithm="sha256"))
    problems = validate_policy({"window": 300, "algorithm": "sha256"})
    assert "replay_disabled" in problems


def test_hook_batch_does_not_reuse_previous_request_state():
    first = _signed_request(SECRET, NOW, "n-10a", body=b'{"id": 1}')
    tampered = _signed_request(
        SECRET,
        NOW,
        "n-10b",
        body=b'{"id": 2}',
        tamper_body=b'{"id": 3}',
    )
    third = _signed_request(SECRET, NOW, "n-10c", body=b'{"id": 4}')
    result = hook_batch([first, tampered, third], SECRET, _policy(), NOW)
    assert [item["ok"] for item in result["results"]] == [True, False, True]
    assert result["results"][1]["checks"]["signature"] is False
    assert result["results"][2]["checks"]["signature"] is True
    assert result["ok"] is False
