"""支付回调 webhook 签名校验的核心实现。

实现严格遵守各函数 docstring 中的契约，尤其是：

* 规范化串使用 v1 格式，字段排序，空值省略，请求体参与签名；
* 签名比较使用 hmac.compare_digest；
* 时间窗为 [now - window, now]，两端包含，容差 0；
* 先对原始 body 验签，再解析 JSON；
* nonce 先查后登记，并清理过期项。
"""

import hashlib
import hmac
import json
import re
from urllib.parse import quote

_NONCE_TTL_SECONDS = 600
_INTEGER_RE = re.compile(r"^-?\d+$")


def _as_bytes(value):
    """str 按 UTF-8 编码，bytes 原样返回。"""
    if isinstance(value, bytes):
        return value
    if isinstance(value, str):
        return value.encode("utf-8")
    raise TypeError("expected str or bytes")


def _to_epoch_seconds(value):
    """接受 int 或纯十进制整数字符串，返回 int；bool 与其他类型一律非法。"""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str) and _INTEGER_RE.match(value):
        return int(value)
    return None


def canonical_request(body, headers, timestamp) -> str:
    """构造待签名的规范化字符串。

    参数:
        body: 原始请求体，bytes；str 按 UTF-8 编码。
        headers: 请求头映射，键和值通常为 str。
        timestamp: epoch 秒字符串，原样写入第二行。

    v1 格式（各行用单个换行符连接，末尾不加换行）:
        第 1 行: v1
        第 2 行: timestamp
        第 3 行: SHA-256(body) 的小写十六进制摘要
        第 4 行起: 按小写头名排序的请求头行

    请求头规则:
        * 只纳入小写后以 x- 开头的头；
        * x-signature 与 x-timestamp 不纳入（签名本身和已单独传入的时间戳）；
        * 头名转小写并去除首尾空白；
        * 值为 None 或去空白后为空串的头整行省略；
        * 值去除首尾空白后按 UTF-8 做百分号编码（quote(value, safe="")）；
        * 行格式为 小写头名:编码后的值，按 (头名, 值) 排序。

    相同字段集合无论字典插入顺序如何，结果必须相同；body 任一字节变化，
    结果必须变化。
    """
    body_bytes = _as_bytes(body)
    body_digest = hashlib.sha256(body_bytes).hexdigest()

    lines = ["v1", str(timestamp), body_digest]

    # 收集后统一按 (头名, 编码值) 排序，消除字典插入顺序对签名的影响。
    header_rows = []
    for name, value in headers.items():
        lower_name = str(name).lower().strip()
        if not lower_name.startswith("x-"):
            continue
        if lower_name in ("x-signature", "x-timestamp"):
            continue
        if value is None:
            continue
        trimmed = str(value).strip()
        if trimmed == "":
            continue
        encoded = quote(trimmed, safe="")
        header_rows.append((lower_name, encoded))

    header_rows.sort(key=lambda item: (item[0], item[1]))
    lines.extend(f"{name}:{value}" for name, value in header_rows)
    return "\n".join(lines)


def sign(secret, payload) -> str:
    """用 HMAC-SHA256 计算签名，返回小写十六进制字符串。

    secret 与 payload 为 str 时按 UTF-8 编码，为 bytes 时原样使用。
    输出固定为 64 个十六进制字符。
    """
    return hmac.new(_as_bytes(secret), _as_bytes(payload), hashlib.sha256).hexdigest()


def verify_signature(secret, payload, provided) -> bool:
    """校验 provided 是否等于 payload 的 HMAC-SHA256 签名。

    必须使用 hmac.compare_digest 做恒定时间比较，禁止使用 ==。
    provided 必须是 str；None、非 str、长度不是 64 或非十六进制时返回 False，
    不得抛出异常。只接受 sign 输出的小写十六进制形式。
    """
    if not isinstance(provided, str):
        return False
    if len(provided) != 64:
        return False
    try:
        int(provided, 16)
    except ValueError:
        return False
    if provided != provided.lower():
        return False

    expected = sign(secret, payload)
    # 通过模块属性访问，保证测试对 hmac.compare_digest 的 monkeypatch 生效，
    # 同时比较本身是恒定时间的，不泄漏签名前缀。
    return hmac.compare_digest(expected, provided)


def timestamp_ok(timestamp, now, window) -> bool:
    """判断时间戳是否落在允许窗口内。

    有效区间为 [now - window, now]，两端都包含；容差为 0，
    未来时间戳（timestamp > now）一律拒绝。
    timestamp 与 now 为 epoch 秒，接受 int 或纯十进制整数字符串；
    window 必须为正整数秒。任一参数非法时返回 False。
    """
    ts = _to_epoch_seconds(timestamp)
    current = _to_epoch_seconds(now)
    if ts is None or current is None:
        return False
    if isinstance(window, bool) or not isinstance(window, int) or window <= 0:
        return False
    # 闭区间 [now - window, now]：未来时间戳与超出窗口的历史时间戳都拒绝。
    return current - window <= ts <= current


def nonce_seen(store, nonce, now) -> bool:
    """查询 nonce 是否已出现，未出现则登记，并清理过期项。

    store 为 dict，键是 nonce，值是该 nonce 的过期时刻（epoch 秒）。
    每次调用先删除所有 value <= now 的项，防止长时间运行内存无界增长。
    清理后 nonce 仍在 store 中则返回 True（命中重放）；否则写入
    store[nonce] = now + 600 并返回 False。空 nonce 视为已见并返回 True。
    TTL 固定为 600 秒。
    """
    # 先清理过期项，保证台账不会随运行时间无界增长。
    expired = [key for key, deadline in store.items() if deadline <= now]
    for key in expired:
        del store[key]

    if nonce is None or (isinstance(nonce, str) and nonce.strip() == ""):
        return True

    # 先查询后登记：同一个 nonce 第二次出现即判重放。
    if nonce in store:
        return True

    store[nonce] = now + _NONCE_TTL_SECONDS
    return False


def validate_policy(policy) -> list[str]:
    """返回策略问题代码列表，空列表表示策略可用。

    检查项（按此顺序返回）:
        * window 缺失或不是正整数: window_missing / window_invalid；
        * replay 不为 True: replay_disabled；
        * algorithm 不是 sha256: algorithm_weak（md5、sha1 等均视为过弱）。
    """
    problems = []

    window = policy.get("window")
    if "window" not in policy or window is None:
        problems.append("window_missing")
    elif isinstance(window, bool) or not isinstance(window, int) or window <= 0:
        problems.append("window_invalid")

    if policy.get("replay") is not True:
        problems.append("replay_disabled")

    if policy.get("algorithm") != "sha256":
        problems.append("algorithm_weak")

    return problems


def _header(headers, name):
    """大小写不敏感地取请求头，缺失返回 None。"""
    target = name.lower()
    for key, value in headers.items():
        if str(key).lower() == target:
            return value
    return None


def verify_request(request, secret, policy, now) -> dict:
    """校验单个 webhook 请求，返回逐项结果。

    参数:
        request: dict，包含 body（bytes 或 str）与 headers（dict）。
        headers 中 X-Signature 为待校验签名，X-Timestamp 为 epoch 秒字符串，
            X-Nonce 为一次性随机串。
        policy: dict，包含 window（正整数秒）、replay（必须为 True）、
            algorithm（必须为 sha256），可选 nonce_store（dict，运行期重放台账）。
        now: 当前 epoch 秒，显式传入，函数内不得调用 time。

    返回:
        {
          "ok": bool,
          "checks": {
              "policy": bool 或 None,
              "timestamp": bool 或 None,
              "signature": bool 或 None,
              "body": bool 或 None,
              "replay": bool 或 None,
          },
          "reasons": list[str],
        }

    执行顺序（安全关键）:
        1. 校验 policy；
        2. 校验时间窗；
        3. 用原始 body 字节构造规范化串并验签；
        4. 验签通过后才解析 JSON；
        5. 策略、时间窗、签名、body 全部通过后才查询并登记 nonce，
           避免未认证请求消耗 nonce。
    reasons 使用以下代码: window_missing、window_invalid、replay_disabled、
        algorithm_weak、timestamp_out_of_window、signature_mismatch、
        body_invalid_json、nonce_missing、replay_duplicate。
    未执行到的检查记为 None。
    """
    checks = {
        "policy": None,
        "timestamp": None,
        "signature": None,
        "body": None,
        "replay": None,
    }
    reasons = []
    headers = request.get("headers", {})
    body = request.get("body")

    # 1. 策略校验：窗口必须来自配置且为正整数，重放必须开启，算法必须够强。
    policy_problems = validate_policy(policy)
    checks["policy"] = not policy_problems
    if policy_problems:
        reasons.extend(policy_problems)
        return {"ok": False, "checks": checks, "reasons": reasons}

    # 2. 时间窗校验：窗口取配置值，未来时间戳与过期时间戳一律拒绝。
    raw_timestamp = _header(headers, "X-Timestamp")
    timestamp = _to_epoch_seconds(raw_timestamp)
    if timestamp is None or not timestamp_ok(timestamp, now, policy["window"]):
        checks["timestamp"] = False
        reasons.append("timestamp_out_of_window")
        return {"ok": False, "checks": checks, "reasons": reasons}
    checks["timestamp"] = True

    # 3. 用原始 body 字节构造规范化串并验签：body 参与签名，恒定时间比较。
    canonical = canonical_request(body, headers, raw_timestamp)
    provided_signature = _header(headers, "X-Signature")
    if not verify_signature(secret, canonical, provided_signature):
        checks["signature"] = False
        reasons.append("signature_mismatch")
        return {"ok": False, "checks": checks, "reasons": reasons}
    checks["signature"] = True

    # 4. 验签通过之后才解析 JSON，避免未认证请求在解析阶段触发危险逻辑。
    try:
        body_bytes = _as_bytes(body)
        json.loads(body_bytes.decode("utf-8"))
    except (ValueError, UnicodeError, TypeError):
        checks["body"] = False
        reasons.append("body_invalid_json")
        return {"ok": False, "checks": checks, "reasons": reasons}
    checks["body"] = True

    # 5. 前面全部通过后才触碰 nonce 台账：先查后登记，过期项同步清理。
    nonce = _header(headers, "X-Nonce")
    if nonce is None or (isinstance(nonce, str) and nonce.strip() == ""):
        checks["replay"] = False
        reasons.append("nonce_missing")
        return {"ok": False, "checks": checks, "reasons": reasons}

    store = policy.get("nonce_store")
    if not isinstance(store, dict):
        store = {}
    if nonce_seen(store, nonce, now):
        checks["replay"] = False
        reasons.append("replay_duplicate")
        return {"ok": False, "checks": checks, "reasons": reasons}

    checks["replay"] = True
    return {"ok": True, "checks": checks, "reasons": reasons}


def hook_batch(requests, secret, policy, now) -> dict:
    """批量校验，各请求独立计算，返回批量结果。

    每个请求都用自己的 body 与 headers 重新构造规范化串并单独验签，
    不得缓存或复用上一个请求的规范化串、签名或结果。
    共享 policy 中的 nonce_store，同一批次内重复的 nonce 仍判为重放。
    返回 {"ok": 所有请求均 ok, "results": [verify_request 结果, ...]}。
    """
    results = [verify_request(request, secret, policy, now) for request in requests]
    return {"ok": all(result["ok"] for result in results), "results": results}
