import subprocess
import tempfile
from pathlib import Path

from app.security.ed25519 import generate_keypair, public_from_secret, sign, verify


def _openssl_available():
    try:
        subprocess.run(["openssl", "version"], capture_output=True, check=True)
        return True
    except (FileNotFoundError, subprocess.CalledProcessError):
        return False


def _tlv(tag, content):
    length = len(content)
    if length < 0x80:
        head = bytes([tag, length])
    else:
        n = length.to_bytes((length.bit_length() + 7) // 8, "big")
        head = bytes([tag, 0x80 | len(n)]) + n
    return head + content


def _private_pem(seed, path):
    import base64
    alg = b"\x30\x05\x06\x03\x2b\x65\x70"  # Ed25519 OID 1.3.101.112
    der = _tlv(0x30, b"\x02\x01\x00" + alg + _tlv(0x04, b"\x04\x20" + seed))
    pem = (b"-----BEGIN PRIVATE KEY-----\n" + b"\n".join(base64.encodebytes(der).split())
           + b"\n-----END PRIVATE KEY-----\n")
    path.write_bytes(pem)


def test_self_consistency_basic():
    seed, pub = generate_keypair()
    assert public_from_secret(seed) == pub
    assert len(pub) == 32
    message = b"refund batch O-12321 amount 4500 cents"
    signature = sign(seed, message)
    assert len(signature) == 64
    assert verify(pub, message, signature)
    assert not verify(pub, message + b"x", signature)
    assert not verify(pub, message, b"\x00" * 64)
    _, other_pub = generate_keypair()
    assert not verify(other_pub, message, signature)


def test_signature_is_deterministic():
    seed, _ = generate_keypair()
    assert sign(seed, b"same message") == sign(seed, b"same message")


def test_malformed_inputs_never_raise():
    seed, pub = generate_keypair()
    signature = sign(seed, b"abc")
    assert verify(b"short", b"abc", signature) is False
    assert verify(pub, b"abc", b"short") is False
    assert verify(pub, b"abc", b"") is False
    assert verify(b"", b"abc", signature) is False


def test_openssl_signatures_verify_in_pure_python():
    if not _openssl_available():
        return
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        pem = tmp / "key.pem"
        subprocess.run(["openssl", "genpkey", "-algorithm", "ED25519", "-out", str(pem)],
                       check=True, capture_output=True)
        seed = _seed_from_pem(pem)
        pub = public_from_secret(seed)
        # openssl 对多条消息签名，纯 Python verify 必须全部通过
        for message in [b"a", b"order=O1;refund_cents=4500", bytes(range(256)), b"\x00" * 1024]:
            msg_path = tmp / "msg"
            sig_path = tmp / "sig"
            msg_path.write_bytes(message)
            subprocess.run(["openssl", "pkeyutl", "-sign", "-rawin", "-inkey", str(pem),
                            "-in", str(msg_path), "-out", str(sig_path)],
                           check=True, capture_output=True)
            signature = sig_path.read_bytes()
            assert verify(pub, message, signature)
            assert sign(seed, message) == signature  # 确定性签名应逐字节一致


def test_pure_python_signatures_verify_in_openssl():
    if not _openssl_available():
        return
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        for _ in range(5):
            seed, pub = generate_keypair()
            pem = tmp / "key.pem"
            _private_pem(seed, pem)
            message = b"batch=B42;order=O7;refund_cents=9000"
            (tmp / "msg").write_bytes(message)
            (tmp / "sig").write_bytes(sign(seed, message))
            result = subprocess.run(
                ["openssl", "pkeyutl", "-verify", "-rawin", "-inkey", str(pem),
                 "-in", str(tmp / "msg"), "-sigfile", str(tmp / "sig")],
                capture_output=True, text=True,
            )
            assert result.returncode == 0, result.stderr
            # 篡改一个字节后 openssl 必须拒绝
            tampered = bytearray(message)
            tampered[-1] ^= 0x01
            (tmp / "msg2").write_bytes(bytes(tampered))
            bad = subprocess.run(
                ["openssl", "pkeyutl", "-verify", "-rawin", "-inkey", str(pem),
                 "-in", str(tmp / "msg2"), "-sigfile", str(tmp / "sig")],
                capture_output=True, text=True,
            )
            assert bad.returncode != 0


def _seed_from_pem(pem_path):
    import base64
    lines = [line for line in pem_path.read_text().splitlines() if "KEY" not in line]
    der = base64.b64decode("".join(lines))
    # PKCS#8 Ed25519 固定 48 字节，末尾 32 字节即 seed
    assert der[-34:-32] == b"\x04\x20"
    return der[-32:]
