"""批次签名密钥管理。

私钥只保存在工作台本地的密钥文件中（默认在数据卷里，不进仓库、不出网），
对外只暴露公钥与公钥指纹 ``key_id``。复核方离线持有的信任锚是公钥，
凭证文件里不内嵌公钥，因此连凭证自带的验真材料一起替换也无法伪造。
"""
import hashlib
import os
from pathlib import Path

from app.config import SIGNING_KEY_PATH
from app.security import ed25519


class SigningKey:
    def __init__(self, seed: bytes):
        if len(seed) != 32:
            raise ValueError("BAD_SIGNING_KEY")
        self.seed = seed
        self.public = ed25519.public_from_secret(seed)
        self.key_id = hashlib.sha256(self.public).hexdigest()

    def sign(self, message: bytes) -> bytes:
        return ed25519.sign(self.seed, message)

    def verify(self, message: bytes, signature: bytes) -> bool:
        return ed25519.verify(self.public, message, signature)


def load_signing_key(path: str | os.PathLike | None = None) -> SigningKey:
    """读取签名密钥；文件不存在时在本机生成一把并固定下来。

    生成只发生一次，之后所有批次共用同一把密钥，复核方只需保存一次公钥。
    """
    key_path = Path(path or SIGNING_KEY_PATH)
    key_path.parent.mkdir(parents=True, exist_ok=True)
    if key_path.is_file():
        seed = key_path.read_bytes().strip()
        return SigningKey(seed)
    seed, _ = ed25519.generate_keypair()
    # 先写临时文件再原子替换，避免并发下写出半截密钥
    tmp = key_path.with_suffix(key_path.suffix + ".tmp")
    tmp.write_bytes(seed)
    tmp.chmod(0o600)
    tmp.replace(key_path)
    return SigningKey(seed)
