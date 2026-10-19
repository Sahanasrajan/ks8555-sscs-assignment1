import json
from unittest.mock import MagicMock, patch

import pytest

import main
from util import extract_public_key


def fake_response(data):
    resp = MagicMock()
    resp.json.return_value = data
    return resp


# ---------- signature ----------


def test_signature_valid(signed_artifact):
    key = extract_public_key(signed_artifact["cert_pem"])
    assert main.signature_is_valid(
        signed_artifact["signature"], key, signed_artifact["artifact"]
    )


def test_signature_invalid_for_tampered_file(signed_artifact):
    key = extract_public_key(signed_artifact["cert_pem"])
    with open(signed_artifact["artifact"], "ab") as f:
        f.write(b"tampered")
    assert not main.signature_is_valid(
        signed_artifact["signature"], key, signed_artifact["artifact"]
    )


# ---------- log entries ----------


def test_get_log_entry_rejects_bad_index():
    with pytest.raises(ValueError):
        main.get_log_entry(-1)
    with pytest.raises(ValueError):
        main.get_verification_proof("abc")


def test_get_log_entry_and_proof(signed_artifact, capsys):
    entry = signed_artifact["entry"]
    with patch("main.requests.get", return_value=fake_response({"uuid": entry})):
        assert main.get_log_entry(0, debug=True) == entry
        proof, leaf_hash = main.get_verification_proof(0)
    assert proof["treeSize"] == 1
    assert leaf_hash == signed_artifact["leaf"]
    assert "verification" in capsys.readouterr().out


# ---------- inclusion ----------


def test_inclusion_success(signed_artifact, capsys):
    resp = fake_response({"uuid": signed_artifact["entry"]})
    with patch("main.requests.get", return_value=resp):
        main.inclusion(0, signed_artifact["artifact"])
    assert "Offline verification successful" in capsys.readouterr().out


def test_inclusion_tampered_artifact_exits(signed_artifact, capsys):
    with open(signed_artifact["artifact"], "ab") as f:
        f.write(b"tampered")
    resp = fake_response({"uuid": signed_artifact["entry"]})
    with patch("main.requests.get", return_value=resp), pytest.raises(SystemExit) as e:
        main.inclusion(0, signed_artifact["artifact"])
    assert e.value.code == 1
    assert "Verification failed" in capsys.readouterr().out


def test_inclusion_bad_proof_exits(signed_artifact, capsys):
    entry = signed_artifact["entry"]
    entry["verification"]["inclusionProof"]["rootHash"] = "00" * 32
    resp = fake_response({"uuid": entry})
    with patch("main.requests.get", return_value=resp), pytest.raises(SystemExit) as e:
        main.inclusion(0, signed_artifact["artifact"])
    assert e.value.code == 1
    assert "Inclusion verification failed" in capsys.readouterr().out


def test_inclusion_input_validation(capsys):
    main.inclusion(-1, "artifact.md")
    main.inclusion(0, None)
    main.inclusion(0, "does-not-exist.txt")
    out = capsys.readouterr().out
    assert "non-negative integer" in out
    assert out.count("valid artifact filepath") == 2


# ---------- checkpoint & consistency ----------

CHECKPOINT = {"treeID": "1", "treeSize": 2, "rootHash": "", "inactiveShards": []}


def test_get_latest_checkpoint_debug_writes_file(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    with patch("main.requests.get", return_value=fake_response(CHECKPOINT)):
        assert main.get_latest_checkpoint(debug=True) == CHECKPOINT
    assert json.loads((tmp_path / "checkpoint.json").read_text()) == CHECKPOINT


def _two_leaf_tree():
    from merkle_proof import DefaultHasher

    a = DefaultHasher.hash_leaf(b"a")
    b = DefaultHasher.hash_leaf(b"b")
    return a.hex(), b.hex(), DefaultHasher.hash_children(a, b).hex()


def test_consistency_success(capsys):
    a, b, root = _two_leaf_tree()
    latest = dict(CHECKPOINT, rootHash=root)
    responses = [fake_response(latest), fake_response({"hashes": [b]})]
    with patch("main.requests.get", side_effect=responses):
        main.consistency({"treeID": "1", "treeSize": 1, "rootHash": a}, debug=True)
    assert "Consistency verification successful" in capsys.readouterr().out


def test_consistency_bad_proof_exits(capsys):
    a, _b, root = _two_leaf_tree()
    latest = dict(CHECKPOINT, rootHash=root)
    responses = [fake_response(latest), fake_response({"hashes": [a]})]
    with (
        patch("main.requests.get", side_effect=responses),
        pytest.raises(SystemExit) as e,
    ):
        main.consistency({"treeID": "1", "treeSize": 1, "rootHash": a})
    assert e.value.code == 1
    assert "Consistency verification failed" in capsys.readouterr().out


def test_consistency_missing_fields(capsys):
    main.consistency({})
    main.consistency({"treeID": "1", "treeSize": 1})
    out = capsys.readouterr().out
    assert "please specify previous checkpoint" in out
    assert "missing rootHash" in out


# ---------- command line ----------


def test_cli_checkpoint(capsys, monkeypatch):
    monkeypatch.setattr("sys.argv", ["main.py", "-c", "-d"])
    with patch("main.get_latest_checkpoint", return_value=CHECKPOINT):
        main.main()
    out = capsys.readouterr().out
    assert "enabled debug mode" in out
    assert '"treeID": "1"' in out


def test_cli_inclusion_and_consistency(monkeypatch):
    monkeypatch.setattr(
        "sys.argv",
        [
            "main.py",
            "--inclusion",
            "5",
            "--artifact",
            "a.md",
            "--consistency",
            "--tree-id",
            "1",
            "--tree-size",
            "3",
            "--root-hash",
            "ab",
        ],
    )
    with patch("main.inclusion") as inc, patch("main.consistency") as con:
        main.main()
    inc.assert_called_once_with(5, "a.md", False)
    con.assert_called_once_with({"treeID": "1", "treeSize": 3, "rootHash": "ab"}, False)


@pytest.mark.parametrize(
    "args, message",
    [
        ([], "tree id"),
        (["--tree-id", "1"], "tree size"),
        (["--tree-id", "1", "--tree-size", "3"], "root hash"),
    ],
)
def test_cli_consistency_missing_args(args, message, capsys, monkeypatch):
    monkeypatch.setattr("sys.argv", ["main.py", "--consistency", *args])
    main.main()
    assert message in capsys.readouterr().out
