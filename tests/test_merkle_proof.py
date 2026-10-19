import hashlib

import pytest

from merkle_proof import (
    DefaultHasher,
    RootMismatchError,
    compute_leaf_hash,
    verify_consistency,
    verify_inclusion,
)


def leaf(data):
    return DefaultHasher.hash_leaf(data)


def node(left, right):
    return DefaultHasher.hash_children(left, right)


def test_hash_leaf_uses_rfc6962_prefix():
    assert leaf(b"a") == hashlib.sha256(b"\x00a").digest()


def test_hash_children_uses_rfc6962_prefix():
    assert node(b"l", b"r") == hashlib.sha256(b"\x01lr").digest()


def test_hasher_size_and_empty_root():
    assert DefaultHasher.size() == 32
    assert DefaultHasher.empty_root() == hashlib.sha256().digest()


def test_compute_leaf_hash_matches_hasher():
    import base64

    body = base64.b64encode(b"entry").decode()
    assert compute_leaf_hash(body) == leaf(b"entry").hex()


def test_verify_inclusion_valid_two_leaf_tree():
    a, b = leaf(b"a"), leaf(b"b")
    root = node(a, b)
    verify_inclusion(DefaultHasher, 0, 2, a.hex(), [b.hex()], root.hex(), debug=True)
    verify_inclusion(DefaultHasher, 1, 2, b.hex(), [a.hex()], root.hex())


def test_verify_inclusion_wrong_root_raises():
    a, b = leaf(b"a"), leaf(b"b")
    with pytest.raises(RootMismatchError) as err:
        verify_inclusion(DefaultHasher, 0, 2, a.hex(), [b.hex()], a.hex())
    assert "does not match" in str(err.value)


def test_verify_inclusion_index_beyond_size_raises():
    a = leaf(b"a")
    with pytest.raises(ValueError):
        verify_inclusion(DefaultHasher, 5, 2, a.hex(), [], a.hex())


def test_verify_inclusion_wrong_proof_size_raises():
    a = leaf(b"a")
    with pytest.raises(ValueError):
        verify_inclusion(DefaultHasher, 0, 2, a.hex(), [], a.hex())


def test_verify_inclusion_bad_leaf_size_raises():
    with pytest.raises(ValueError):
        verify_inclusion(DefaultHasher, 0, 1, "abcd", [], "abcd")


def test_verify_consistency_valid():
    a, b, c, d = (leaf(x) for x in (b"a", b"b", b"c", b"d"))
    ab, cd = node(a, b), node(c, d)
    root4 = node(ab, cd)
    # power-of-two first tree: proof is just the sibling subtree
    verify_consistency(DefaultHasher, 2, 4, [cd.hex()], ab.hex(), root4.hex())
    # size 3 -> 4
    root3 = node(ab, c)
    verify_consistency(
        DefaultHasher, 3, 4, [c.hex(), d.hex(), ab.hex()], root3.hex(), root4.hex()
    )


def test_verify_consistency_same_size():
    r = leaf(b"a").hex()
    verify_consistency(DefaultHasher, 1, 1, [], r, r)
    with pytest.raises(ValueError):
        verify_consistency(DefaultHasher, 1, 1, [r], r, r)


def test_verify_consistency_error_cases():
    r = leaf(b"a").hex()
    with pytest.raises(ValueError):
        verify_consistency(DefaultHasher, 4, 2, [], r, r)  # shrinking tree
    verify_consistency(DefaultHasher, 0, 2, [], r, r)  # empty first tree
    with pytest.raises(ValueError):
        verify_consistency(DefaultHasher, 0, 2, [r], r, r)
    with pytest.raises(ValueError):
        verify_consistency(DefaultHasher, 1, 2, [], r, r)  # empty proof
    with pytest.raises(ValueError):
        verify_consistency(DefaultHasher, 1, 2, [r, r, r], r, r)  # wrong size


def test_verify_consistency_wrong_root_raises():
    a, b = leaf(b"a"), leaf(b"b")
    with pytest.raises(RootMismatchError):
        verify_consistency(DefaultHasher, 1, 2, [b.hex()], a.hex(), a.hex())
