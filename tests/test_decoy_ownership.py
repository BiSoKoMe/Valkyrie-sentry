"""Decoys must never claim real user files or lose their identity on restart."""
import json
import pathlib

import pytest

from valkyrie.decoys import DecoyManager


def _lock_reads_of(monkeypatch, target):
    """Deny reads of one planted decoy the way Windows denies a file that is
    being scanned, synced or backed up: the file is there, we just cannot
    open it this pass."""
    real_open = pathlib.Path.open

    def flaky_open(self, *args, **kwargs):
        mode = args[0] if args else kwargs.get("mode", "r")
        if self == target and "x" not in mode:
            raise PermissionError(13, "The process cannot access the file")
        return real_open(self, *args, **kwargs)

    monkeypatch.setattr(pathlib.Path, "open", flaky_open)


def test_existing_user_files_are_preserved_and_never_become_tripwires(tmp_path):
    personal = tmp_path / "passwords.txt"
    personal.write_text("my real notes", encoding="utf-8")
    binary = tmp_path / "id_rsa"
    binary.write_bytes(b"\xff\xfe user key")
    manager = DecoyManager(dirs=[tmp_path])
    assert manager.deploy() == 3
    assert personal.read_text(encoding="utf-8") == "my real notes"
    assert binary.read_bytes() == b"\xff\xfe user key"
    assert manager.references_decoy(str(personal), str(binary)) is None


def test_repeated_deployment_and_restart_preserve_on_disk_tokens(tmp_path):
    manifest = tmp_path / "manifest.json"
    manager = DecoyManager(manifest_path=manifest, dirs=[tmp_path / "decoys"])
    assert manager.deploy() == 5
    tokens, paths = manager.tokens(), manager.paths()
    assert manager.deploy() == 5
    assert manager.tokens() == tokens
    assert manager.paths() == paths
    restarted = DecoyManager(manifest_path=manifest, dirs=[tmp_path / "decoys"])
    restarted.load()
    assert restarted.deploy() == 5
    assert restarted.tokens() == tokens
    assert restarted.paths() == paths
    assert all(restarted.references_decoy(token) == token for token in tokens)


def test_replaced_decoy_is_no_longer_a_tripwire(tmp_path):
    manager = DecoyManager(dirs=[tmp_path])
    manager.deploy()
    personal = tmp_path / "passwords.txt"
    personal.write_text("replaced with real notes", encoding="utf-8")
    assert manager.deploy() == 4
    assert manager.references_decoy(str(personal)) is None
    assert len(manager.tokens()) == 4


def test_explicit_empty_targets_do_not_fall_back_to_user_profiles(tmp_path):
    manager = DecoyManager(manifest_path=tmp_path / "manifest.json", dirs=[])
    assert manager.target_dirs() == []
    assert manager.deploy() == 0
    assert not manager.tokens()


@pytest.mark.parametrize("carries_pairs", [True, False])
def test_an_unreadable_decoy_is_retained_not_silently_disarmed(
    tmp_path, monkeypatch, carries_pairs,
):
    """A tripwire we could not read is not a tripwire we know is gone. Dropping
    it leaves the bait on disk with nothing watching it, and the manifest save
    makes that loss permanent. `carries_pairs` False is a manifest written by a
    release before path->token pairs were persisted."""
    manifest = tmp_path / "manifest.json"
    decoys = tmp_path / "decoys"
    DecoyManager(manifest_path=manifest, dirs=[decoys]).deploy()
    planted = decoys / "passwords.txt"
    token = planted.read_text(encoding="utf-8").split("# ref:")[1].strip()

    if not carries_pairs:
        legacy = json.loads(manifest.read_text(encoding="utf-8"))
        legacy.pop("pairs", None)
        manifest.write_text(json.dumps(legacy), encoding="utf-8")

    _lock_reads_of(monkeypatch, planted)
    restarted = DecoyManager(manifest_path=manifest, dirs=[decoys])
    restarted.load()
    assert restarted.deploy() == 5

    assert restarted.references_decoy(f"type x # {token}") == token.lower()
    assert restarted.references_decoy(f"cmd /c type {planted}") is not None
    assert token.lower() in json.loads(manifest.read_text(encoding="utf-8"))["tokens"]


def test_an_unreachable_directory_does_not_disarm_its_tripwires(
    tmp_path, monkeypatch,
):
    manifest = tmp_path / "manifest.json"
    decoys = tmp_path / "decoys"
    manager = DecoyManager(manifest_path=manifest, dirs=[decoys])
    assert manager.deploy() == 5
    tokens = manager.tokens()

    def denied(self, *args, **kwargs):
        raise PermissionError(13, "Access is denied")

    monkeypatch.setattr(pathlib.Path, "mkdir", denied)
    assert manager.deploy() == 5
    assert manager.tokens() == tokens
