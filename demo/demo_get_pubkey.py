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
from eth_utils import keccak
from ecdsa import SECP256k1, SigningKey, curves, ellipticcurve


@dataclass
class EncryptedPackage:
    device_pub_hex: str  # 64 字节未压缩公钥（不含 0x04 前缀）
    nonce: bytes
    tag: bytes
    ciphertext: bytes


def normalize_pub_hex(raw_hex: str) -> str:
    """转换为 64 字节未压缩公钥的十六进制表示 (不含 0x04 前缀)"""
    clean = raw_hex[2:] if raw_hex.startswith("0x") else raw_hex
    if clean.startswith("04") and len(clean) == 130:
        clean = clean[2:]
    if len(clean) != 128:
        raise ValueError("需要 64 字节未压缩公钥 (X||Y)")
    return clean


def derive_fisco_address(raw_pub_hex: str) -> str:
    """按照 FISCO-BCOS/EVM 规则：Keccak256(pubkey)[12:]"""
    pub_bytes = bytes.fromhex(normalize_pub_hex(raw_pub_hex))
    return "0x" + keccak(pub_bytes)[-20:].hex()


def load_user_account(keyfile: str, password: str) -> Tuple[bytes, str]:
    with open(keyfile) as f:
        key_json = json.load(f)
    priv_bytes = Account.decrypt(key_json, password)
    pub_hex = keys.PrivateKey(priv_bytes).public_key.to_hex()  # 0x04 + X + Y
    return priv_bytes, pub_hex


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


def device_encrypt_for_user(user_raw_pub_hex: str, plaintext: bytes) -> Tuple[EncryptedPackage, str]:
    """
    设备端加密函数：使用 ECDH 密钥交换 + AES-GCM 加密数据
    
    参数:
        user_raw_pub_hex: 用户的原始公钥（一般为 0x04 + X + Y）
        plaintext: 需要加密的明文数据（字节串）
    
    返回:
        Tuple[EncryptedPackage, str]: 加密包和派生的 FISCO-BCOS 地址
    """
    normalized_pub_hex = normalize_pub_hex(user_raw_pub_hex)
    user_address = derive_fisco_address(user_raw_pub_hex)

    # 步骤1: 生成一次性的 SECP256k1 椭圆曲线密钥对
    # 这是设备端的临时私钥，用于本次加密会话，用完即弃，提高安全性
    device_sk = SigningKey.generate(curve=SECP256k1)
    
    # 步骤2: 提取设备私钥的标量值（大整数）
    # 在椭圆曲线密码学中，私钥本质上是一个大整数（标量）
    device_scalar = device_sk.privkey.secret_multiplier
    
    # 步骤3: 将用户公钥的十六进制字符串转换为椭圆曲线上的点
    # 公钥在椭圆曲线上表示为一个点 (x, y)
    user_point = hex_pub_to_point(normalized_pub_hex)
    
    # 步骤4: 使用 ECDH 协议派生共享的 AES 密钥
    # ECDH 原理: shared_secret = device_private_key × user_public_key_point
    # 用户端可以用同样的方法计算: shared_secret = user_private_key × device_public_key_point
    # 由于椭圆曲线的数学性质，双方会得到相同的共享密钥
    aes_key = derive_aes_key(device_scalar, user_point)

    # 步骤5: 生成 12 字节的随机 nonce（Number used ONCE）
    # GCM 模式需要 nonce 来确保相同明文在不同加密中产生不同密文
    # 12 字节是 AES-GCM 推荐的 nonce 长度
    nonce = get_random_bytes(12)
    
    # 步骤6: 创建 AES-GCM 加密器
    # GCM (Galois/Counter Mode) 是一种认证加密模式，同时提供机密性和完整性保护
    cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
    
    # 步骤7: 加密明文并生成认证标签
    # ciphertext: 加密后的数据
    # tag: 消息认证码(MAC)，用于验证数据在传输过程中未被篡改
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)

    # 步骤8: 提取设备公钥并转换为十六进制字符串
    # to_string("uncompressed") 返回格式: 0x04 + X坐标(32字节) + Y坐标(32字节)
    # [1:] 切片操作去掉开头的 0x04 前缀，只保留 64 字节的 X||Y 坐标
    device_pub = device_sk.verifying_key.to_string("uncompressed")[1:]
    
    # 步骤9: 返回加密包
    # 接收方需要: 设备公钥(用于ECDH)、nonce(用于解密)、tag(用于验证)、密文(加密数据)
    return EncryptedPackage(device_pub.hex(), nonce, tag, ciphertext), user_address


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
    print(f"用户公钥（原始 Hex）：{user_pub_hex}")

    package, user_address = device_encrypt_for_user(user_pub_hex, args.message.encode())
    print(f"FISCO BCOS 地址：{user_address}")
    print(f"设备临时公钥：{package.device_pub_hex}")
    print(f"密文(hex)：{package.ciphertext.hex()}")

    recovered = user_decrypt_with_private_key(priv_bytes, package)
    print(f"解密结果：{recovered.decode()}")


if __name__ == "__main__":
    main()
