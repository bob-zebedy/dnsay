#!/usr/bin/python
# -*- coding: utf-8 -*-
# @Author   : Zebedy
# @Time     : 2025-10-27 11:37

# pip install dnspython cryptography

import argparse
import base64
import hashlib
import os
import secrets
import sys
import threading
import time

import dns.resolver
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def nickname():
    adjs = ["飞翔", "逐风", "无畏", "低调", "温柔", "清醒", "闪电", "暴走", "潇洒", "沉默",
            "热血", "冷静", "追光", "孤独", "迷途", "滚烫", "平静", "勇敢", "机智", "自在",
            "飘逸", "执着", "温暖", "高冷", "炽热", "清澈", "朴素", "恬淡", "灵动", "轻盈",
            "狂野", "优雅", "神秘", "纯真", "深沉", "活泼", "安静", "张扬", "内敛", "奔放",
            "细腻", "粗犷", "精致", "豪放", "温润", "锐利", "柔和", "刚烈", "清新", "浓郁"]
    nouns = ["小哥", "姑娘", "船长", "骑士", "旅人", "诗人", "画师", "黑客", "捕风者", "观星者",
             "远行者", "逐梦者", "程序员", "航海家", "筑梦者", "修行者", "开拓者", "探路者",
             "听风者", "赶路人", "追梦人", "夜行者", "晨光者", "月光者", "星光者", "阳光者",
             "风语者", "雨行者", "雪舞者", "花语者", "鸟语者", "鱼游者", "蝶舞者", "蜂鸣者",
             "书虫", "码农", "设计师", "艺术家", "音乐家", "舞蹈家", "摄影师", "导演", "编剧",
             "探险家", "科学家", "发明家", "思想家", "哲学家", "教育家", "医生", "律师", "记者"]
    return f"{secrets.choice(adjs)}的{secrets.choice(nouns)}"


def b32e(data):
    return base64.b32encode(data).decode().rstrip("=").lower()


def b64ue(data):
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def b64ud(s):
    s += "=" * ((4 - len(s) % 4) % 4)
    return base64.urlsafe_b64decode(s)


def derive_key(group):
    return hashlib.sha256(group).digest()


def aese(key, nonce, data, aad=b""):
    return AESGCM(key).encrypt(nonce, data, aad)


def aesd(key, nonce, data, aad=b""):
    return AESGCM(key).decrypt(nonce, data, aad)


class DNSChat:
    def __init__(self, dns_host, dns_port, group, name):
        self.group = group.encode()
        self.name = name
        self.sid = os.urandom(4)
        self.key = derive_key(self.group)

        self.resolver = dns.resolver.Resolver(configure=False)
        self.resolver.nameservers = [dns_host]
        self.resolver.port = dns_port
        self.resolver.lifetime = 5.0
        self.resolver.timeout = 2.0
        self.resolver.search = []

    @staticmethod
    def _build_qname(labels):
        return ".".join(labels).rstrip(".") + "."

    def _query_txt(self, qname):
        try:
            ans = self.resolver.resolve(qname, 'TXT', raise_on_no_answer=False)
            if not ans.response or not ans.response.answer:
                return b""

            parts = []
            for rr in ans.response.answer:
                for item in rr.items:
                    try:
                        for s in item.strings:
                            text = s.decode() if isinstance(s, (bytes, bytearray)) else str(s)
                            parts.append(text)
                    except AttributeError:
                        parts.append(item.to_text().strip('"'))

            return "".join(parts).encode()
        except Exception:
            return b""

    def send_message(self, message):
        data = self.name.encode() + b"\x00" + message.encode()

        seq = 0
        for i in range(0, len(data), 80):
            chunk = data[i:i + 80]
            nonce = os.urandom(12)

            ciphertext = aese(self.key, nonce, chunk, aad=self.sid)
            payload = b64ue(ciphertext)

            # 构造查询 grp.sid.u.seq.nonce.payload
            payload_labels = [payload[j:j + 30] for j in range(0, len(payload), 30)]
            labels = [b32e(self.group), b32e(self.sid), "u", str(seq), b32e(nonce)] + payload_labels
            qname = self._build_qname(labels)
            self._query_txt(qname)
            seq += 1

    def poll_message(self):
        nonce = os.urandom(12)
        labels = [b32e(self.group), b32e(self.sid), "p", "0", b32e(nonce)]
        qname = self._build_qname(labels)
        response = self._query_txt(qname)
        if not response:
            return None

        try:
            ciphertext = b64ud(response.decode())
            plaintext = aesd(self.key, nonce, ciphertext, aad=self.sid)

            if not plaintext:
                return None

            if b"\x00" in plaintext:
                name, text = plaintext.split(b"\x00", 1)
                return f"{name.decode(errors='ignore')}: {text.decode(errors='ignore')}"
            else:
                return plaintext.decode(errors='ignore')
        except Exception:
            return None

    def receive_loop(self, interval):
        while True:
            msg = self.poll_message()
            if msg:
                print(msg, flush=True)
            time.sleep(interval)


def main():
    ap = argparse.ArgumentParser(description="DNS 聊天客户端")
    ap.add_argument("--name", default=nickname(), help="昵称")
    ap.add_argument("--group", default="default", help="分组ID")
    ap.add_argument("--dns-host", default="127.0.0.1", help="DNS 服务器地址")
    ap.add_argument("--dns-port", type=int, default=5335, help="DNS 服务器端口")
    ap.add_argument("--interval", type=float, default=0.25, help="轮询间隔（秒）")
    args = ap.parse_args()

    group = args.group or "default"
    name = args.name or nickname()
    
    client = DNSChat(args.dns_host, args.dns_port, group, name)

    print(f"[你是 '{name}']")
    print(f"[连接到 {args.dns_host}:{args.dns_port}, 分组 '{group}']")

    recv_thread = threading.Thread(
        target=client.receive_loop,
        args=(args.interval,),
        daemon=True
    )
    recv_thread.start()

    try:
        for line in sys.stdin:
            line = line.rstrip("\n")
            if line:
                client.send_message(line)
    except KeyboardInterrupt:
        print("\n再见!")


if __name__ == "__main__":
    main()
