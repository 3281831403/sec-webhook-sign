"""边界行为测试：5 条，覆盖合法、篡改、过期、重放与批量一致性。"""

from hook.verify import (
    canonical_request,
    hook_batch,
    sign,
    verify_request,
)

SECRET = "whsec_behaviour_secret"
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


def test_valid_request_passes_all_checks():
    request = _signed_request(SECRET, NOW, "valid-1")
    result = verify_request(request, SECRET, _policy(), NOW)
    assert result["ok"] is True
    assert result["checks"] == {
        "policy": True,
        "timestamp": True,
        "signature": True,
        "body": True,
        "replay": True,
    }
    assert result["reasons"] == []


def test_tampered_body_is_rejected():
    request = _signed_request(
        SECRET, NOW, "tamper-1", tamper_body=b'{"amount": 999}'
    )
    result = verify_request(request, SECRET, _policy(), NOW)
    assert result["ok"] is False
    assert result["checks"]["signature"] is False
    assert "signature_mismatch" in result["reasons"]


def test_expired_timestamp_is_rejected():
    request = _signed_request(SECRET, NOW - 301, "expired-1")
    result = verify_request(request, SECRET, _policy(), NOW)
    assert result["ok"] is False
    assert result["checks"]["timestamp"] is False
    assert "timestamp_out_of_window" in result["reasons"]


def test_reused_nonce_is_rejected():
    policy = _policy()
    first = _signed_request(SECRET, NOW, "replay-1")
    second = _signed_request(SECRET, NOW, "replay-1")
    assert verify_request(first, SECRET, policy, NOW)["ok"] is True
    result = verify_request(second, SECRET, policy, NOW)
    assert result["ok"] is False
    assert result["checks"]["replay"] is False
    assert "replay_duplicate" in result["reasons"]


def test_batch_matches_individual_validations():
    requests = [
        _signed_request(SECRET, NOW, "batch-1", body=b'{"id": 1}'),
        _signed_request(
            SECRET,
            NOW,
            "batch-2",
            body=b'{"id": 2}',
            tamper_body=b'{"id": 3}',
        ),
        _signed_request(SECRET, NOW, "batch-3", body=b'{"id": 4}'),
    ]
    batch_one = hook_batch(requests, SECRET, _policy(), NOW)
    batch_two = hook_batch(requests, SECRET, _policy(), NOW)
    individual = [
        verify_request(item, SECRET, _policy(), NOW) for item in requests
    ]
    expected_ok = [item["ok"] for item in individual]
    assert expected_ok == [True, False, True]
    assert [item["ok"] for item in batch_one["results"]] == expected_ok
    assert [item["ok"] for item in batch_two["results"]] == expected_ok
    assert [item["checks"] for item in batch_one["results"]] == [
        item["checks"] for item in individual
    ]
    assert batch_one["ok"] is False
