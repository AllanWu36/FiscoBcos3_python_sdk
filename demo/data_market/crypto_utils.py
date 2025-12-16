"""抽离 demo_get_pubkey 的核心加密逻辑，供三个端点复用。"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Tuple

from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
from ecdsa import SECP256k1, SigningKey, curves, ellipticcurve


@dataclass
class EncryptedPackage:
    """封装设备侧返回给平台/用户的密文包。"""

    device_pub_hex: str  # 64 字节未压缩公钥，不含 0x04
    nonce: bytes
    tag: bytes
    ciphertext: bytes

    def to_message(self) -> Dict[str, str]:
        """序列化为可放入 MQ/HTTP 的纯十六进制字符串。"""
        return {
            "device_pub_hex": self.device_pub_hex,
            "nonce": self.nonce.hex(),
            "tag": self.tag.hex(),
            "ciphertext": self.ciphertext.hex(),
        }

    @staticmethod
    def from_message(message: Dict[str, str]) -> "EncryptedPackage":
        """从 MQ/HTTP 消息还原密文包。"""
        return EncryptedPackage(
            device_pub_hex=message["device_pub_hex"],
            nonce=bytes.fromhex(message["nonce"]),
            tag=bytes.fromhex(message["tag"]),
            ciphertext=bytes.fromhex(message["ciphertext"]),
        )


def _normalize_pub_hex(raw_hex: str) -> str:
    clean = raw_hex[2:] if raw_hex.startswith("0x") else raw_hex
    if clean.startswith("04") and len(clean) == 130:
        clean = clean[2:]
    if len(clean) != 128:
        raise ValueError("需要 64 字节未压缩公钥 (X||Y)")
    return clean


def _hex_pub_to_point(raw_hex: str):
    raw = bytes.fromhex(raw_hex)
    if len(raw) != 64:
        raise ValueError("需要 64 字节未压缩公钥 (X||Y)")
    x = int.from_bytes(raw[:32], "big")
    y = int.from_bytes(raw[32:], "big")
    curve = curves.SECP256k1.curve
    point = ellipticcurve.Point(curve, x, y)
    if not curve.contains_point(x, y):
        raise ValueError("公钥不在 secp256k1 曲线上")
    return point


def _derive_aes_key(priv_scalar: int, peer_point) -> bytes:
    shared_point = peer_point * priv_scalar
    shared_x = int(shared_point.x())
    return SHA256.new(shared_x.to_bytes(32, "big")).digest()


def encrypt_for_user(user_pub_hex: str, plaintext: bytes) -> EncryptedPackage:
    """
    使用 ECDH + AES-GCM 对 plaintext 进行加密。

    Args:
        user_pub_hex: 用户端提供的 0x04 + X + Y 或 64 字节未压缩公钥。
        plaintext: 需要保护的数据。

    Returns:
        EncryptedPackage: 序列化后的密文对象。
    """
    normalized_pub_hex = _normalize_pub_hex(user_pub_hex)
    device_sk = SigningKey.generate(curve=SECP256k1)
    device_scalar = device_sk.privkey.secret_multiplier
    user_point = _hex_pub_to_point(normalized_pub_hex)
    aes_key = _derive_aes_key(device_scalar, user_point)
    nonce = get_random_bytes(12)
    cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    device_pub = device_sk.verifying_key.to_string("uncompressed")[1:]
    return EncryptedPackage(device_pub.hex(), nonce, tag, ciphertext)


def decrypt_with_private_key(priv_bytes: bytes, package: EncryptedPackage) -> bytes:
    """便于单元测试/后续用户端复用的解密函数。"""
    priv_scalar = int.from_bytes(priv_bytes, "big")
    device_point = _hex_pub_to_point(package.device_pub_hex)
    aes_key = _derive_aes_key(priv_scalar, device_point)
    cipher = AES.new(aes_key, AES.MODE_GCM, nonce=package.nonce)
    return cipher.decrypt_and_verify(package.ciphertext, package.tag)
