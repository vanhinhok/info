import os
import time
import traceback
from datetime import datetime, timezone, timedelta

import httpx
from flask import Flask, jsonify, request
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

app = Flask(__name__)

# ============================================================
# CẤU HÌNH (Chỉnh qua Environment Variables trên Vercel hoặc sửa trực tiếp)
# ============================================================
INFO_UID = os.environ.get("INFO_UID", "8049781707").strip()
INFO_PASS = os.environ.get(
    "INFO_PASS",
    "8E0D1AC299B6FC5954B644DCBABFB981C2FF2511219336B2286E25C478368EBF",
).strip()
API_SECRET_KEY = os.environ.get("API_SECRET_KEY", "").strip()

AES_KEY = b"Yg&tc%DEuh6%Zc^8"
AES_IV = b"6oyZDr22E3ychjM%"
VN_TZ = timezone(timedelta(hours=7))
GARENA_BAN_URL = "https://ff.garena.com/api/antihack/check_banned"

_TOKEN_CACHE = {"token": None, "expires_at": 0.0}


# ============================================================
# PROTOBUF THUẦN PYTHON & MÃ HÓA AES
# ============================================================
def encode_varint(value: int) -> bytes:
    out = []
    while True:
        b = value & 0x7F
        value >>= 7
        if value:
            out.append(b | 0x80)
        else:
            out.append(b)
            break
    return bytes(out)


def encode_length_delimited(field_num: int, data) -> bytes:
    if isinstance(data, str):
        data = data.encode("utf-8")
    tag = (field_num << 3) | 2
    return encode_varint(tag) + encode_varint(len(data)) + data


def encode_varint_field(field_num: int, value: int) -> bytes:
    tag = (field_num << 3) | 0
    return encode_varint(tag) + encode_varint(value)


def create_protobuf_packet(fields: dict) -> bytes:
    packet = bytearray()
    for field, value in fields.items():
        if isinstance(value, dict):
            packet.extend(encode_length_delimited(field, create_protobuf_packet(value)))
        elif isinstance(value, list):
            for item in value:
                if isinstance(item, int):
                    packet.extend(encode_varint_field(field, item))
                elif isinstance(item, (str, bytes)):
                    packet.extend(encode_length_delimited(field, item))
                elif isinstance(item, dict):
                    packet.extend(encode_length_delimited(field, create_protobuf_packet(item)))
        elif isinstance(value, int):
            packet.extend(encode_varint_field(field, value))
        elif isinstance(value, (str, bytes)):
            packet.extend(encode_length_delimited(field, value))
    return bytes(packet)


def decode_protobuf(data: bytes) -> dict:
    pos = 0
    length = len(data)
    fields = {}
    while pos < length:
        try:
            val, shift = 0, 0
            while True:
                if pos >= length:
                    break
                b = data[pos]
                pos += 1
                val |= (b & 0x7F) << shift
                if not (b & 0x80):
                    break
                shift += 7
            field_num = val >> 3
            wire_type = val & 0x07
            if wire_type == 0:
                v, s = 0, 0
                while True:
                    if pos >= length:
                        break
                    b = data[pos]
                    pos += 1
                    v |= (b & 0x7F) << s
                    if not (b & 0x80):
                        break
                    s += 7
                fields[field_num] = v
            elif wire_type == 2:
                l, s = 0, 0
                while True:
                    if pos >= length:
                        break
                    b = data[pos]
                    pos += 1
                    l |= (b & 0x7F) << s
                    if not (b & 0x80):
                        break
                    s += 7
                fields[field_num] = data[pos : pos + l]
                pos += l
            elif wire_type == 1:
                fields[field_num] = data[pos : pos + 8]
                pos += 8
            elif wire_type == 5:
                fields[field_num] = data[pos : pos + 4]
                pos += 4
            else:
                break
        except Exception:
            break
    return fields


def _pb_str(d: dict, k: int, default: str = "") -> str:
    val = d.get(k)
    if isinstance(val, bytes):
        return val.decode("utf-8", errors="ignore")
    return str(val) if val is not None else default


def _pb_int(d: dict, k: int, default: int = 0) -> int:
    val = d.get(k)
    return int(val) if isinstance(val, int) else default


def _pb_msg(d: dict, k: int) -> dict:
    val = d.get(k)
    return decode_protobuf(val) if isinstance(val, bytes) else {}


def parse_account_show_info(raw_bytes: bytes) -> dict:
    """Giải mã trực tiếp gói AccountPersonalShowInfo theo schema data.proto."""
    root = decode_protobuf(raw_bytes)
    b = _pb_msg(root, 1)    # basic_info
    c = _pb_msg(root, 6)    # clan_basic_info
    pet = _pb_msg(root, 8)  # pet_info
    soc = _pb_msg(root, 9)  # social_info
    cr = _pb_msg(root, 11)  # credit_score_info

    account_id = _pb_int(b, 1)
    if not account_id:
        return {}

    clan_id = _pb_int(c, 1)
    pet_id = _pb_int(pet, 1)
    score = _pb_int(cr, 1)

    return {
        "uid": account_id,
        "nickname": _pb_str(b, 3),
        "region": _pb_str(b, 5),
        "level": _pb_int(b, 6),
        "exp": _pb_int(b, 7),
        "br_rank": _pb_int(b, 14),
        "br_points": _pb_int(b, 15),
        "has_elite_pass": bool(_pb_int(b, 17)),
        "badges": _pb_int(b, 18),
        "likes": _pb_int(b, 21),
        "last_login_at": _fmt_vn_ts(_pb_int(b, 24)),
        "cs_rank": _pb_int(b, 30),
        "cs_points": _pb_int(b, 31),
        "create_at": _fmt_vn_ts(_pb_int(b, 44)),
        "release_version": _pb_str(b, 50),
        "clan_name": _pb_str(c, 2) if clan_id else "",
        "clan_id": clan_id,
        "clan_level": _pb_int(c, 4) if clan_id else 0,
        "clan_members": f"{_pb_int(c, 6)}/{_pb_int(c, 5)}" if clan_id else "",
        "credit_score": score if score else 100,
        "signature": _pb_str(soc, 9),
        "pet_name": _pb_str(pet, 2) if pet_id else "",
        "pet_level": _pb_int(pet, 3) if pet_id else 0,
    }


def aes_encrypt(data: bytes) -> bytes:
    cipher = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
    return cipher.encrypt(pad(data, AES.block_size))


def _fmt_vn_ts(ts_val) -> str:
    try:
        ts_int = int(ts_val or 0)
        if ts_int <= 0:
            return ""
        return datetime.fromtimestamp(ts_int, VN_TZ).strftime("%d/%m/%Y %H:%M")
    except Exception:
        return ""


# ============================================================
# ĐĂNG NHẬP LẤY TOKEN TỪ 1 TÀI KHOẢN
# ============================================================
def request_garena_access(uid: str, password: str, client: httpx.Client):
    payload = {
        "uid": str(uid),
        "password": str(password),
        "response_type": "token",
        "client_type": "2",
        "client_id": "100067",
        "client_secret": "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3",
    }
    headers = {
        "User-Agent": "GarenaMSDK/4.0.42(M2004J7AC ;Android 12;vi;VN;app 1.132.3 2019121229;)",
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "application/json",
    }
    urls = [
        "https://100067.connect.garena.com/oauth/guest/token/grant",
        "https://auth.garena.com/oauth/guest/token/grant",
    ]
    for url in urls:
        try:
            r = client.post(url, data=payload, headers=headers)
            if r.status_code == 200:
                data = r.json()
                if "access_token" in data and "open_id" in data:
                    return data["access_token"], data["open_id"]
        except Exception:
            continue
    return None, None


def request_game_jwt(access_token: str, open_id: str, client: httpx.Client):
    fields = {
        3: datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        4: "free fire",
        5: 1,
        7: "1.132.3",
        8: "Android OS 12 / API-31 (SP1A.210812.016/V13.0.8.0.SJHCNXM)",
        9: "Handheld",
        11: "WIFI",
        12: 1666,
        13: 750,
        14: "440",
        15: "ARM64 FP ASIMD AES | 2600 | 8",
        16: 5479,
        17: "Mali-G57 MC5",
        18: "OpenGL ES 3.2 v1.r32p1-00bet5.e94274a04d1e4e37d3804a00cb1f4074",
        19: "Google|21cd1993-491c-45f0-9aee-f4bf86b9245b",
        20: "123.26.135.179",
        21: "vn",
        22: str(open_id),
        23: "4",
        24: "Handheld",
        25: "Xiaomi M2004J7AC",
        26: "VN",
        29: str(access_token),
        30: 1,
        42: "WIFI",
        57: "7428b253defc164018c604a1ebbfebdf",
        60: 48520,
        61: 23518,
        62: 4498,
        64: 23662,
        65: 48520,
        66: 23662,
        67: 48520,
        73: 2,
        74: "/data/app/~~5Oyng5_R0TorqNAyEwZX8A==/com.dts.freefireth-jiQ7sG-AMNwBe9bzqhdluA==/lib/arm64",
        76: 1,
        77: "b8e0cd5e295eee42f5860d3c86e483dd|/data/app/~~5Oyng5_R0TorqNAyEwZX8A==/com.dts.freefireth-jiQ7sG-AMNwBe9bzqhdluA==/base.apk",
        78: 3,
        79: 2,
        81: "64",
        83: "2019121229",
        85: 3,
        86: "OpenGLES2",
        87: 4095,
        88: 4,
        92: 21473,
        93: "android",
        94: "KqsHT0ZDw2VRkOchxPu26AP2douhbLpyxAKQ4DlHphBHkJEbs+ga1Ut7OesVOBYNJ49Ipj2Dbr3iycet+FHmTyZfQ2I=",
        95: 111107,
        96: '{"cur_rate":null,"support_etc2":false}',
        97: 1,
        99: "4",
        100: "4",
        102: bytes.fromhex("425d4743005f085230"),
        104: 50900,
        105: 1,
        106: "https://dl.ak.freefiremobile.com/live/ABHotUpdates/|https://core-ak.freefiremobile.com/live/ABHotUpdates/|1c2462939e53942fc995400436a3dc7b",
        107: "c8e41b7a93f02d56e1a94c7b8203f5d1",
    }
    enc_data = aes_encrypt(create_protobuf_packet(fields))
    headers = {
        "User-Agent": "UnityPlayer/2018.4.12f1 (UnityWebRequest/1.0, libcurl/8.5.0-DEV)",
        "Accept-Encoding": "gzip",
        "Content-Type": "application/x-www-form-urlencoded",
        "X-Unity-Version": "2018.4.12f1",
        "X-GA-SV": str(int(time.time())),
        "X-GA": "v1 1",
        "ReleaseVersion": "OB55",
    }
    try:
        r = client.post("https://loginbp.ppmainecoonghj.com/MajorLogin", content=enc_data, headers=headers)
        if r.status_code == 200:
            raw_bytes = r.content
            decoded = decode_protobuf(raw_bytes[64:] if len(raw_bytes) >= 64 else raw_bytes)
            tok = decoded.get(8)
            if tok:
                return tok.decode("utf-8", errors="ignore") if isinstance(tok, bytes) else str(tok)
    except Exception:
        pass
    return None


def get_valid_info_token(client: httpx.Client, force_refresh: bool = False):
    now = time.time()
    if not force_refresh and _TOKEN_CACHE["token"] and now < _TOKEN_CACHE["expires_at"]:
        return _TOKEN_CACHE["token"]

    at, oid = request_garena_access(INFO_UID, INFO_PASS, client)
    if not at or not oid:
        return None
    jwt = request_game_jwt(at, oid, client)
    if jwt:
        _TOKEN_CACHE["token"] = jwt
        _TOKEN_CACHE["expires_at"] = now + 3000
        return jwt
    return None


# ============================================================
# LẤY INFO & CHECK BAN
# ============================================================
def check_garena_ban(uid_str: str, client: httpx.Client) -> dict:
    headers = {
        "User-Agent": "Mozilla/5.0 (Linux; Android 12) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
        "Accept": "application/json, text/plain, */*",
        "Referer": "https://ff.garena.com/en/support/",
        "Origin": "https://ff.garena.com",
        "X-Requested-With": "B6FksShzIgjfrYImLpTsadjS86sddhFH",
    }
    try:
        r = client.get(GARENA_BAN_URL, params={"lang": "en", "uid": str(uid_str).strip()}, headers=headers)
        if r.status_code == 200:
            info = (r.json() or {}).get("data") or {}
            if isinstance(info, dict) and "is_banned" in info:
                banned = bool(int(info.get("is_banned") or 0))
                period = int(info.get("period") or 0)
                return {
                    "status": "Banned" if banned else "Not Banned",
                    "is_banned": banned,
                    "period": period,
                }
    except Exception:
        pass
    return {"status": "Unknown", "is_banned": None, "period": 0}


def _call_get_player_show(uid_num: int, token: str, client: httpx.Client):
    proto_show = b"\x08" + encode_varint(uid_num) + b"\x10\x09\x18\x01\x20\x01"
    enc_payload = aes_encrypt(proto_show)
    headers = {
        "Host": "clientbp.ppmainecoonghj.com",
        "ReleaseVersion": "OB55",
        "X-Unity-Version": "2018.4.12f1",
        "X-GA": "v1 1",
        "X-GA-SV": str(int(time.time())),
        "Authorization": f"Bearer {token}",
        "User-Agent": "UnityPlayer/2018.4.12f1 (UnityWebRequest/1.0, libcurl/8.5.0-DEV)",
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept-Encoding": "gzip",
    }
    r = client.post("https://clientbp.ppmainecoonghj.com/GetPlayerPersonalShow", headers=headers, content=enc_payload)
    if r.status_code == 200:
        return r.content, 200
    return None, r.status_code


def fetch_full_info(uid_num: int):
    with httpx.Client(timeout=15.0) as client:
        token = get_valid_info_token(client)
        if not token:
            return None, "Không thể đăng nhập tài khoản lấy info (kiểm tra INFO_UID / INFO_PASS)"

        raw_bytes, status = _call_get_player_show(uid_num, token, client)
        if status in (401, 403) or not raw_bytes:
            token = get_valid_info_token(client, force_refresh=True)
            if token:
                raw_bytes, status = _call_get_player_show(uid_num, token, client)

        if not raw_bytes:
            return None, f"Không lấy được dữ liệu từ Garena (HTTP {status})"

        try:
            data = parse_account_show_info(raw_bytes)
            if not data:
                return None, "UID không tồn tại"

            ban_res = check_garena_ban(str(uid_num), client)
            data["ban_status"] = ban_res["status"]
            data["is_banned"] = ban_res["is_banned"]
            data["ban_period"] = ban_res["period"]
            return data, None
        except Exception as e:
            return None, f"Lỗi giải mã dữ liệu: {e}"


# ============================================================
# ROUTES (Hỗ trợ cả đường dẫn gốc và đường dẫn /api/index.py của Vercel)
# ============================================================
@app.after_request
def add_cors(response):
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Methods"] = "GET, OPTIONS"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type"
    return response


@app.route("/", methods=["GET"])
@app.route("/api/index.py", methods=["GET"])
def home():
    return jsonify({
        "status": "online",
        "service": "Free Fire Info API (Vercel)",
        "endpoints": {
            "info": "/info?uid=123456789",
            "checkban": "/checkban?uid=123456789",
        },
    }), 200


@app.route("/info", methods=["GET"])
@app.route("/api/index.py/info", methods=["GET"])
def route_info():
    try:
        if API_SECRET_KEY:
            key = str(request.args.get("key") or "").strip()
            if key != API_SECRET_KEY:
                return jsonify({"status": "error", "err": "API Key không hợp lệ hoặc thiếu key"}), 403

        uid = str(request.args.get("uid") or request.args.get("id") or "").strip()
        if not uid:
            return jsonify({"status": "error", "err": "Thiếu tham số uid"}), 400
        if not uid.isdigit():
            return jsonify({"status": "error", "err": "UID phải là số"}), 400

        data, err = fetch_full_info(int(uid))
        if data:
            return jsonify({"status": "success", "data": data}), 200
        return jsonify({"status": "error", "err": err or "Không thể lấy thông tin"}), 404
    except Exception:
        return jsonify({"status": "error", "trace": traceback.format_exc()}), 500


@app.route("/checkban", methods=["GET"])
@app.route("/api/index.py/checkban", methods=["GET"])
def route_checkban():
    uid = str(request.args.get("uid") or request.args.get("id") or "").strip()
    if not uid or not uid.isdigit():
        return jsonify({"status": "error", "err": "Thiếu hoặc sai định dạng UID"}), 400

    with httpx.Client(timeout=10.0) as client:
        res = check_garena_ban(uid, client)
    return jsonify({"status": "success", "uid": uid, **res}), 200
