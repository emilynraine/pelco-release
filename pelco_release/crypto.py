"""Payload encryption, recipient key wrapping and manifest signatures (spec sections 4 to 6)."""
from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.keywrap import InvalidUnwrap, aes_key_unwrap, aes_key_wrap

from .codes import Rejected

ENCRYPTION_ALG = "aes-256-gcm-chunked"
RECIPIENT_ALG = "x25519-hkdf-sha256-aes-kw"
SIGNATURE_ALG = "ed25519"
TAG = 16
KEK_INFO = b"pelco-release v1 kek"


def chunk_count(plain_size, chunk_size):
    return -(-plain_size // chunk_size)


def encrypted_size(plain_size, chunk_size):
    return plain_size + TAG * chunk_count(plain_size, chunk_size)


def _nonce(prefix, index):
    return prefix + index.to_bytes(4, "big")


def encrypt(content_key, nonce_prefix, chunk_size, plain):
    aes = AESGCM(content_key)
    count = chunk_count(len(plain), chunk_size)
    return b"".join(
        aes.encrypt(_nonce(nonce_prefix, i), plain[i * chunk_size:(i + 1) * chunk_size],
                    b"\x01" if i == count - 1 else b"\x00")
        for i in range(count))


class Decryptor:
    """Decrypts and authenticates a payload chunk by chunk as its stored bytes arrive."""

    def __init__(self, content_key, nonce_prefix, chunk_size, plain_size):
        self._aes = AESGCM(content_key)
        self._prefix = nonce_prefix
        self._stored_chunk = chunk_size + TAG
        self._count = chunk_count(plain_size, chunk_size)
        self._index = 0
        self._buffer = bytearray()

    def _open(self, data, last):
        try:
            plain = self._aes.decrypt(_nonce(self._prefix, self._index), bytes(data),
                                      b"\x01" if last else b"\x00")
        except InvalidTag:
            raise Rejected("DECRYPT_FAILED", f"chunk {self._index} doesn't authenticate") from None
        self._index += 1
        return plain

    def update(self, data):
        self._buffer += data
        out = []
        while self._index < self._count - 1 and len(self._buffer) >= self._stored_chunk:
            out.append(self._open(self._buffer[:self._stored_chunk], last=False))
            del self._buffer[:self._stored_chunk]
        return b"".join(out)

    def finish(self):
        if self._index != self._count - 1:
            raise Rejected("DECRYPT_FAILED", "payload ends before its last chunk")
        return self._open(self._buffer, last=True)


def _kek(shared, ephemeral_pub, recipient_pub, key_id):
    if shared == bytes(32):
        raise ValueError("all-zero shared secret")
    return HKDF(hashes.SHA256(), 32, salt=ephemeral_pub + recipient_pub,
                info=KEK_INFO + key_id.encode("utf-8")).derive(shared)


def x25519_public(private):
    return X25519PrivateKey.from_private_bytes(private).public_key().public_bytes_raw()


def ed25519_public(private):
    return Ed25519PrivateKey.from_private_bytes(private).public_key().public_bytes_raw()


def wrap(content_key, key_id, recipient_pub, random_bytes):
    ephemeral = X25519PrivateKey.from_private_bytes(random_bytes(32))
    ephemeral_pub = ephemeral.public_key().public_bytes_raw()
    shared = ephemeral.exchange(X25519PublicKey.from_public_bytes(recipient_pub))
    kek = _kek(shared, ephemeral_pub, recipient_pub, key_id)
    return {
        "key_id": key_id,
        "alg": RECIPIENT_ALG,
        "ephemeral_pub": ephemeral_pub.hex(),
        "wrapped_key": aes_key_wrap(kek, content_key).hex(),
    }


def unwrap(recipient, private):
    """The content key from one `recipients` entry, using the matching X25519 private key."""
    key = X25519PrivateKey.from_private_bytes(private)
    ephemeral_pub = bytes.fromhex(recipient["ephemeral_pub"])
    try:
        shared = key.exchange(X25519PublicKey.from_public_bytes(ephemeral_pub))
        kek = _kek(shared, ephemeral_pub, key.public_key().public_bytes_raw(), recipient["key_id"])
        return aes_key_unwrap(kek, bytes.fromhex(recipient["wrapped_key"]))
    except (ValueError, InvalidUnwrap) as e:
        raise Rejected("KEY_UNWRAP_FAILED", str(e) or type(e).__name__) from None


def sign(manifest_bytes, private):
    return Ed25519PrivateKey.from_private_bytes(private).sign(manifest_bytes)


def verify(manifest_bytes, signature, public):
    try:
        Ed25519PublicKey.from_public_bytes(public).verify(signature, manifest_bytes)
        return True
    except InvalidSignature:
        return False
