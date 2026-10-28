"""Ed25519 signatures for the simulator.

Seed-derived keys are for deterministic tests only, not for real deployments.
"""

from dataclasses import dataclass, fields, is_dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from l1sim.encoding import EncodingError, domain_prefix, encode, hash_with_domain
from l1sim.models import CHAIN_ID, SIG_RE, Domain

__all__ = ["CHAIN_ID", "KeyPair", "keypair_from_seed", "sign", "verify"]


@dataclass(frozen=True)
class KeyPair:
    private_key: Ed25519PrivateKey
    public_key: Ed25519PublicKey

    @property
    def public_bytes(self) -> bytes:
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )


def keypair_from_seed(seed: int, name: str) -> KeyPair:
    if type(seed) is not int:
        raise TypeError("seed must be an integer")

    if not isinstance(name, str) or not name:
        raise ValueError("name must be a non-empty string")

    seed_bytes = bytes.fromhex(hash_with_domain("KEYGEN", {"seed": seed, "name": name}))
    private_key = Ed25519PrivateKey.from_private_bytes(seed_bytes)

    return KeyPair(private_key, private_key.public_key())


def _signing_bytes(domain: Domain | str, value: object) -> bytes:
    domain = Domain(domain)
    if is_dataclass(value) and not isinstance(value, type):
        value = {
            field.name: getattr(value, field.name)
            for field in fields(value)
            if field.name != "signature"
        }
    elif isinstance(value, dict) and "signature" in value:
        value = {key: item for key, item in value.items() if key != "signature"}

    return domain_prefix(domain.value) + encode(value)


def sign(sk: Ed25519PrivateKey, domain: Domain | str, value: object) -> str:
    if not isinstance(sk, Ed25519PrivateKey):
        raise TypeError("sk must be an Ed25519 private key")

    return sk.sign(_signing_bytes(domain, value)).hex()


def verify(pk: Ed25519PublicKey, domain: Domain | str, value: object, signature: str) -> bool:
    if not isinstance(pk, Ed25519PublicKey):
        raise TypeError("pk must be an Ed25519 public key")

    domain = Domain(domain)
    if not isinstance(signature, str) or not SIG_RE.fullmatch(signature):
        return False
    try:
        pk.verify(bytes.fromhex(signature), _signing_bytes(domain, value))
    except (InvalidSignature, EncodingError):
        return False

    return True
