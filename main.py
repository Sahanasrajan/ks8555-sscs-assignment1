import argparse
import base64
import json
import os
import requests
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from util import extract_public_key, verify_artifact_signature
from merkle_proof import DefaultHasher, verify_consistency, verify_inclusion, compute_leaf_hash

REKOR_URL = "https://rekor.sigstore.dev/api/v1"


def get_log_entry(log_index, debug=False):
    # sanity check: must be a non-negative integer
    if not isinstance(log_index, int) or log_index < 0:
        raise ValueError("log index must be a non-negative integer")

    resp = requests.get(f"{REKOR_URL}/log/entries",
                        params={"logIndex": log_index}, timeout=30)
    resp.raise_for_status()
    data = resp.json()

    # response looks like {"<uuid>": {...entry...}}; take the single entry
    entry = next(iter(data.values()))
    if debug:
        print(json.dumps(entry, indent=4))
    return entry


def get_verification_proof(log_index, debug=False):
    if not isinstance(log_index, int) or log_index < 0:
        raise ValueError("log index must be a non-negative integer")

    entry = get_log_entry(log_index, debug)
    proof = entry["verification"]["inclusionProof"]
    # the leaf hash is computed from the entry body
    leaf_hash = compute_leaf_hash(entry["body"])
    return proof, leaf_hash


def signature_is_valid(signature, public_key, artifact_filepath):
    # same check as util.verify_artifact_signature, but returns True/False
    key = load_pem_public_key(public_key)
    with open(artifact_filepath, "rb") as f:
        data = f.read()
    try:
        key.verify(signature, data, ec.ECDSA(hashes.SHA256()))
    except InvalidSignature:
        return False
    return True


def inclusion(log_index, artifact_filepath, debug=False):
    if not isinstance(log_index, int) or log_index < 0:
        print("log index must be a non-negative integer")
        return
    if not artifact_filepath or not os.path.isfile(artifact_filepath):
        print("please provide a valid artifact filepath with --artifact")
        return

    entry = get_log_entry(log_index, debug)

    # body is base64-encoded JSON
    body = json.loads(base64.b64decode(entry["body"]))
    sig_block = body["spec"]["signature"]

    # both are base64-encoded: signature -> raw bytes, cert -> PEM bytes
    signature = base64.b64decode(sig_block["content"])
    certificate = base64.b64decode(sig_block["publicKey"]["content"])

    public_key = extract_public_key(certificate)
    verify_artifact_signature(signature, public_key, artifact_filepath)
    # the util function only prints on failure, so check again and stop here
    if not signature_is_valid(signature, public_key, artifact_filepath):
        print("Verification failed: signature does not match artifact")
        return

    proof, leaf_hash = get_verification_proof(log_index, debug)
    verify_inclusion(DefaultHasher, proof["logIndex"], proof["treeSize"],
                     leaf_hash, proof["hashes"], proof["rootHash"])
    print("Offline verification successful")


def get_latest_checkpoint(debug=False):
    # GET /log returns the current tree: treeID, treeSize, rootHash, signedTreeHead
    resp = requests.get(f"{REKOR_URL}/log", timeout=30)
    resp.raise_for_status()
    checkpoint = resp.json()

    if debug:
        with open("checkpoint.json", "w", encoding="utf-8") as f:
            json.dump(checkpoint, f, indent=4)
    return checkpoint


def consistency(prev_checkpoint, debug=False):
    # verify that prev checkpoint is not empty
    if not prev_checkpoint:
        print("please specify previous checkpoint")
        return
    for key in ("treeID", "treeSize", "rootHash"):
        if not prev_checkpoint.get(key):
            print(f"previous checkpoint is missing {key}")
            return

    latest = get_latest_checkpoint(debug)

    # ask Rekor for the proof that the old tree is a prefix of the new one
    resp = requests.get(f"{REKOR_URL}/log/proof",
                        params={"firstSize": prev_checkpoint["treeSize"],
                                "lastSize": latest["treeSize"],
                                "treeID": prev_checkpoint["treeID"]},
                        timeout=30)
    resp.raise_for_status()
    proof = resp.json()
    if debug:
        print(json.dumps(proof, indent=4))

    verify_consistency(DefaultHasher,
                       prev_checkpoint["treeSize"], latest["treeSize"],
                       proof["hashes"],
                       prev_checkpoint["rootHash"], latest["rootHash"])
    print("Consistency verification successful")


def main():
    debug = False
    parser = argparse.ArgumentParser(description="Rekor Verifier")
    parser.add_argument('-d', '--debug', help='Debug mode',
                        required=False, action='store_true') # Default false
    parser.add_argument('-c', '--checkpoint', help='Obtain latest checkpoint\
                        from Rekor Server public instance',
                        required=False, action='store_true')
    parser.add_argument('--inclusion', help='Verify inclusion of an\
                        entry in the Rekor Transparency Log using log index\
                        and artifact filename.\
                        Usage: --inclusion 126574567',
                        required=False, type=int)
    parser.add_argument('--artifact', help='Artifact filepath for verifying\
                        signature',
                        required=False)
    parser.add_argument('--consistency', help='Verify consistency of a given\
                        checkpoint with the latest checkpoint.',
                        action='store_true')
    parser.add_argument('--tree-id', help='Tree ID for consistency proof',
                        required=False)
    parser.add_argument('--tree-size', help='Tree size for consistency proof',
                        required=False, type=int)
    parser.add_argument('--root-hash', help='Root hash for consistency proof',
                        required=False)
    args = parser.parse_args()
    if args.debug:
        debug = True
        print("enabled debug mode")
    if args.checkpoint:
        # get and print latest checkpoint from server
        # if debug is enabled, store it in a file checkpoint.json
        checkpoint = get_latest_checkpoint(debug)
        print(json.dumps(checkpoint, indent=4))
    if args.inclusion:
        inclusion(args.inclusion, args.artifact, debug)
    if args.consistency:
        if not args.tree_id:
            print("please specify tree id for prev checkpoint")
            return
        if not args.tree_size:
            print("please specify tree size for prev checkpoint")
            return
        if not args.root_hash:
            print("please specify root hash for prev checkpoint")
            return

        prev_checkpoint = {}
        prev_checkpoint["treeID"] = args.tree_id
        prev_checkpoint["treeSize"] = args.tree_size
        prev_checkpoint["rootHash"] = args.root_hash

        consistency(prev_checkpoint, debug)


if __name__ == "__main__":
    main()
