#!/usr/bin/env python3
"""
demo_pubkey_encryption.py
示范流程：
1. 解密 keystore，打印用户公钥；
2. “设备”生成一次性私钥，使用用户公钥做 ECDH -> 派生 AES 密钥；
3. 设备用 AES-GCM 加密数据，附带一次性公钥返回；
4. “用户”用自己的私钥 + 设备公钥复算共享密钥，解密数据。
"""
import sys
import os
import time
import secrets
import ctypes


import argparse
import json
from dataclasses import dataclass
from typing import Tuple
sys.path.append("./")
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
from ecdsa.ecdsa import curve_secp256k1
from eth_account.account import Account
from eth_keys import keys
from ecdsa import SECP256k1, SigningKey, curves, ellipticcurve


@dataclass
class EncryptedPackage:
    device_pub_hex: str  # 64 字节未压缩公钥（不含 0x04 前缀）
    nonce: bytes
    tag: bytes
    ciphertext: bytes


def load_user_account(keyfile: str, password: str) -> Tuple[bytes, str]:
    with open(keyfile) as f:
        key_json = json.load(f)
    priv_bytes = Account.decrypt(key_json, password)
    pub_hex = keys.PrivateKey(priv_bytes).public_key.to_hex()  # 0x04 + X + Y
    return priv_bytes, pub_hex[4:] if pub_hex.startswith("0x04") else pub_hex[2:]


def hex_pub_to_point(raw_hex: str):
    raw = bytes.fromhex(raw_hex)
    if len(raw) != 64:
        raise ValueError("需要 64 字节未压缩公钥 (X||Y)")
    x = int.from_bytes(raw[:32], "big")
    y = int.from_bytes(raw[32:], "big")
    curve = curves.SECP256k1.curve
    point = ellipticcurve.Point(curve, x, y)
    # 可选: 验证点是否在曲线上
    if not curve.contains_point(x, y):
        raise ValueError("公钥不在 secp256k1 曲线上")
    return point

def derive_aes_key(priv_scalar: int, peer_point) -> bytes:
    shared_point = peer_point * priv_scalar
    shared_x = int(shared_point.x())
    # 通过 SHA256(shared_x) 生成 32 字节对称密钥
    return SHA256.new(shared_x.to_bytes(32, "big")).digest()


def device_encrypt_for_user(user_pub_hex: str, plaintext: bytes) -> EncryptedPackage:
    device_sk = SigningKey.generate(curve=SECP256k1)  # 一次性设备私钥
    device_scalar = device_sk.privkey.secret_multiplier
    user_point = hex_pub_to_point(user_pub_hex)
    aes_key = derive_aes_key(device_scalar, user_point)

    nonce = get_random_bytes(12)
    cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)

    device_pub = device_sk.verifying_key.to_string("uncompressed")[1:]  # 去掉 0x04
    return EncryptedPackage(device_pub.hex(), nonce, tag, ciphertext)


def user_decrypt_with_private_key(priv_bytes: bytes, package: EncryptedPackage) -> bytes:
    priv_scalar = int.from_bytes(priv_bytes, "big")
    device_point = hex_pub_to_point(package.device_pub_hex)
    aes_key = derive_aes_key(priv_scalar, device_point)

    cipher = AES.new(aes_key, AES.MODE_GCM, nonce=package.nonce)
    return cipher.decrypt_and_verify(package.ciphertext, package.tag)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--keystore", required=True)
    parser.add_argument("--password", required=True)
    parser.add_argument("--message", default="hello edge data")
    args = parser.parse_args()

    priv_bytes, user_pub_hex = load_user_account(args.keystore, args.password)
    print(f"用户公钥（64B Hex）：{user_pub_hex}")

    package = device_encrypt_for_user(user_pub_hex, args.message.encode())
    print(f"设备临时公钥：{package.device_pub_hex}")
    print(f"密文(hex)：{package.ciphertext.hex()}")

    recovered = user_decrypt_with_private_key(priv_bytes, package)
    print(f"解密结果：{recovered.decode()}")


if __name__ == "__main__":
    main()
