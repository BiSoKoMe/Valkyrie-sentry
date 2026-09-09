"""Credential publication ordering, using temporary files and mocked ACL calls."""
from valkyrie import control_credentials


def test_secret_is_written_only_after_both_access_checks(tmp_path, monkeypatch):
    checks = []

    def harden(path, is_dir=False):
        checks.append(is_dir)
        if not is_dir:
            assert path.read_bytes() == b""
        return True, "restricted"

    monkeypatch.setattr(control_credentials.secure_file, "harden", harden)
    assert control_credentials.publish(tmp_path, "sensitive-token")[0]
    assert checks == [True, False]
    assert (tmp_path / "control" / "token").read_text() == "sensitive-token"
    assert list((tmp_path / "control").iterdir()) == [tmp_path / "control" / "token"]


def test_failed_directory_protection_never_publishes(tmp_path, monkeypatch):
    monkeypatch.setattr(control_credentials.secure_file, "harden", lambda *a, **kw: (False, "ACL failure"))
    assert not control_credentials.publish(tmp_path, "must-not-write")[0]
    assert list((tmp_path / "control").iterdir()) == []


def test_failed_file_protection_removes_empty_staging_file(tmp_path, monkeypatch):
    monkeypatch.setattr(control_credentials.secure_file, "harden", lambda p, is_dir=False: (is_dir, "ACL failure"))
    assert not control_credentials.publish(tmp_path, "must-not-write")[0]
    assert list((tmp_path / "control").iterdir()) == []
