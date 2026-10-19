import base64
import datetime
import hashlib
import json

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID


@pytest.fixture
def signed_artifact(tmp_path):
    """Create an artifact, sign it, and build a fake Rekor entry for it."""
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test")])
    now = datetime.datetime.now(datetime.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)

    artifact = tmp_path / "artifact.md"
    artifact.write_bytes(b"hello rekor\n")
    signature = key.sign(artifact.read_bytes(), ec.ECDSA(hashes.SHA256()))

    body = {
        "spec": {
            "signature": {
                "content": base64.b64encode(signature).decode(),
                "publicKey": {"content": base64.b64encode(cert_pem).decode()},
            }
        }
    }
    body_b64 = base64.b64encode(json.dumps(body).encode()).decode()
    # a tree with a single leaf: the root hash is the leaf hash, proof is empty
    leaf = hashlib.sha256(b"\x00" + base64.b64decode(body_b64)).hexdigest()
    entry = {
        "body": body_b64,
        "verification": {
            "inclusionProof": {
                "logIndex": 0,
                "treeSize": 1,
                "hashes": [],
                "rootHash": leaf,
            }
        },
    }
    return {
        "artifact": str(artifact),
        "cert_pem": cert_pem,
        "signature": signature,
        "entry": entry,
        "leaf": leaf,
    }
