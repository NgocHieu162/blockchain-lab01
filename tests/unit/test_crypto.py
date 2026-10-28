from dataclasses import replace

import pytest

from l1sim.crypto import keypair_from_seed, sign, verify
from l1sim.models import CHAIN_ID, GENESIS_HASH, BlockHeader, Hello, Phase, Tx, Vote

HASH = "a" * 64


def test_seeded_keypair_and_signature_are_deterministic():
    first = keypair_from_seed(42, "V0")
    second = keypair_from_seed(42, "V0")

    tx = Tx("Alice", "Alice/name", "Ada", 0)
    signature = sign(first.private_key, "TX", tx)

    assert first.public_bytes == second.public_bytes
    assert verify(second.public_key, "TX", tx, signature)


def test_signature_rejects_modified_fields_and_wrong_domain():
    keypair = keypair_from_seed(42, "V0")
    tx = Tx("Alice", "Alice/name", "Ada", 0)
    signature = sign(keypair.private_key, "TX", tx)

    assert not verify(keypair.public_key, "TX", replace(tx, value="Grace"), signature)
    assert not verify(keypair.public_key, "VOTE", tx, signature)
    assert not verify(keypair.public_key, "TX", tx, "not-hex")


def test_vote_height_and_round_are_signed():
    keypair = keypair_from_seed(7, "V1")
    vote = Vote(Phase.PREVOTE, 5, 0, HASH, "V1")
    signature = sign(keypair.private_key, "VOTE", vote)

    assert verify(keypair.public_key, "VOTE", vote, signature)
    assert not verify(keypair.public_key, "VOTE", replace(vote, height=6), signature)
    assert not verify(keypair.public_key, "VOTE", replace(vote, round=1), signature)


def test_domain_names_are_checked():
    keypair = keypair_from_seed(1, "V0")

    with pytest.raises(ValueError, match="valid Domain"):
        sign(keypair.private_key, "UNKNOWN", {})

    with pytest.raises(ValueError, match="valid Domain"):
        verify(keypair.public_key, "UNKNOWN", {}, "00" * 64)


def test_signing_ignores_the_signature_field_it_populates():
    keypair = keypair_from_seed(17, "V2")
    header = BlockHeader(1, 0, GENESIS_HASH, HASH, HASH, "V2")
    signature = sign(keypair.private_key, "HEADER", header)
    signed_header = replace(header, signature=signature)

    assert verify(keypair.public_key, "HEADER", signed_header, signature)


def test_hello_signature_covers_identity_address_chain_and_height():
    keypair = keypair_from_seed(23, "V3")
    hello = Hello("V3", "127.0.0.1:9003", CHAIN_ID, 4)
    signature = sign(keypair.private_key, "HELLO", hello)

    assert verify(keypair.public_key, "HELLO", replace(hello, signature=signature), signature)
    assert not verify(
        keypair.public_key,
        "HELLO",
        replace(hello, advertise_addr="127.0.0.1:9004", signature=signature),
        signature,
    )
