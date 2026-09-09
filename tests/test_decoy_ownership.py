"""Decoys must never claim real user files or lose their identity on restart."""
from valkyrie.decoys import DecoyManager


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
