#!/usr/bin/python
# -*- coding: utf-8 -*-
# @Author   : Zebedy
# @Time     : 2025-10-27 11:30

# pip install dnslib cryptography

import argparse
import base64
import binascii
import hashlib
import struct
import threading
import time
from collections import deque

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from dnslib import RR, QTYPE, TXT
from dnslib.server import DNSServer, DNSLogger, BaseResolver


def b32d(s):
    s = s.replace("-", "").upper()
    s += "=" * ((8 - len(s) % 8) % 8)
    return base64.b32decode(s)


def b64ud(s):
    s += "=" * ((4 - len(s) % 4) % 4)
    return base64.urlsafe_b64decode(s)


def b64ue(data):
    return base64.urlsafe_b64encode(data).decode()


def aese(key, nonce, data, aad=b""):
    return AESGCM(key).encrypt(nonce, data, aad)


def aesd(key, nonce, data, aad=b""):
    return AESGCM(key).decrypt(nonce, data, aad)


def derive_key(group):
    return hashlib.sha256(group).digest()


def parse_qname(qname):
    labels = qname.strip(".").split(".")

    if len(labels) < 5:
        return None
    body = labels

    if len(body) < 5:
        return None

    try:
        grp = b32d(body[0])
        sid = b32d(body[1])
        direction = body[2]
        seq = int(body[3], 10)
        nonce = b32d(body[4])
        payload_labels = body[5:]

        if payload_labels:
            payload = b64ud("".join(payload_labels))
        else:
            payload = b""

        return {
            "grp": grp,
            "sid": sid,
            "dir": direction,
            "seq": seq,
            "nonce": nonce,
            "payload": payload,
        }
    except (ValueError, binascii.Error):
        return None


class SessionManager:
    def __init__(self, timeout):
        self.sessions = {}
        self.timeout = timeout
        self.lock = threading.Lock()

    def touch(self, sid, grp=None):
        with self.lock:
            if sid not in self.sessions:
                self.sessions[sid] = {
                    "grp": grp,
                    "downq": deque(),
                    "last": int(time.time())
                }
            else:
                self.sessions[sid]["last"] = int(time.time())
                if grp is not None:
                    self.sessions[sid]["grp"] = grp

    def get(self, sid):
        with self.lock:
            return self.sessions.get(sid)

    def cleanup(self):
        now = int(time.time())
        with self.lock:
            expired = [sid for sid, sess in self.sessions.items()
                       if now - sess["last"] > self.timeout]
            for sid in expired:
                del self.sessions[sid]
            return len(expired)

    def broadcast(self, grp, sender_sid, message):
        with self.lock:
            for sid, sess in self.sessions.items():
                if sess.get("grp") == grp and sid != sender_sid:
                    sess["downq"].append(message)


class ChatResolver(BaseResolver):
    def __init__(self, session_mgr, max_length):
        self.session_mgr = session_mgr
        self.max_length = max_length

    @staticmethod
    def _make_response(request, text):
        reply = request.reply()
        reply.add_answer(RR(reply.q.qname, QTYPE.TXT, rdata=TXT(text), ttl=0))
        return reply

    def _make_encrypted_response(self, request, key, nonce, data, sid):
        reply = request.reply()
        ciphertext = aese(key, nonce, data, aad=sid)
        encoded = b64ue(ciphertext)

        for i in range(0, len(encoded), self.max_length):
            chunk = encoded[i:i + self.max_length]
            reply.add_answer(RR(reply.q.qname, QTYPE.TXT, rdata=TXT(chunk), ttl=0))

        return reply

    def resolve(self, request, handler):
        qname = str(request.q.qname)
        qtype = QTYPE[request.q.qtype]

        if qtype != "TXT":
            return self._make_response(request, "ok")

        info = parse_qname(qname)
        if not info:
            return self._make_response(request, "ok")

        grp = info["grp"]
        sid = info["sid"]
        key = derive_key(grp)

        self.session_mgr.touch(sid, grp)

        if info["dir"] == "u":
            try:
                plaintext = aesd(key, info["nonce"], info["payload"], aad=sid)
                self.session_mgr.broadcast(grp, sid, plaintext)
                ack = b"ok" + struct.pack("!I", info["seq"])
                return self._make_encrypted_response(request, key, info["nonce"], ack, sid)
            except Exception:
                return self._make_response(request, "bad")

        if info["dir"] == "p":
            sess = self.session_mgr.get(sid)
            if sess and sess["downq"]:
                message = sess["downq"].popleft()
            else:
                message = b""
            return self._make_encrypted_response(request, key, info["nonce"], message, sid)
        return self._make_response(request, "noop")


def cleanup_loop(session_mgr, interval):
    while True:
        time.sleep(interval)
        session_mgr.cleanup()


def main():
    ap = argparse.ArgumentParser(description="DNS 聊天服务器")
    ap.add_argument("--bind", default="0.0.0.0", help="绑定地址")
    ap.add_argument("--port", type=int, default=5335, help="监听端口")
    ap.add_argument("--max-length", type=int, default=200, help="TXT 记录最大长度")
    ap.add_argument("--timeout", type=int, default=300, help="会话空闲超时 (秒)")
    args = ap.parse_args()

    session_mgr = SessionManager(args.timeout)

    cleanup_thread = threading.Thread(
        target=cleanup_loop,
        args=(session_mgr, 10),
        daemon=True
    )
    cleanup_thread.start()

    logger = DNSLogger("-recv,-send,-request,-reply")

    resolver = ChatResolver(session_mgr, args.max_length)

    udp_server = DNSServer(resolver, port=args.port, address=args.bind, logger=logger)
    tcp_server = DNSServer(resolver, port=args.port, address=args.bind, tcp=True, logger=logger)

    udp_server.start_thread()
    tcp_server.start_thread()

    print(f"DNS 服务运行中\n{args.bind}:{args.port} (UDP/TCP)")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n服务关闭")


if __name__ == "__main__":
    main()
