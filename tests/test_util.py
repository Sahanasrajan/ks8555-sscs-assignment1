from cryptography.hazmat.primitives.serialization import load_pem_public_key

from util import extract_public_key


def test_extract_public_key_returns_pem(signed_artifact):
    pem = extract_public_key(signed_artifact["cert_pem"])
    assert pem.startswith(b"-----BEGIN PUBLIC KEY-----")
    load_pem_public_key(pem)  # must be a loadable key
