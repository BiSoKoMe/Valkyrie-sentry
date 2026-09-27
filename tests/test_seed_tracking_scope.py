"""Known tracking hosts must not expand into blocking consumer sites."""
import pytest

from valkyrie import blocklist
from valkyrie.site_scanner import SiteScanner


@pytest.fixture
def offline_blocklist(tmp_path, monkeypatch):
    monkeypatch.setattr(blocklist, "BLOCKLIST_PATH", tmp_path / "absent.txt")
    manager = blocklist.BlocklistManager()
    manager.load(allow_download=False)
    return manager


@pytest.mark.parametrize("domain", ["tr.snapchat.com", "ct.pinterest.com"])
def test_documented_tracking_hosts_are_covered_offline(offline_blocklist, domain):
    assert offline_blocklist.is_blocked(domain)
    assert offline_blocklist.is_blocked(domain.upper() + ".")
    assert offline_blocklist.is_blocked("collect." + domain)


@pytest.mark.parametrize("domain", [
    "snapchat.com", "www.snapchat.com", "accounts.snapchat.com",
    "pinterest.com", "www.pinterest.com", "help.pinterest.com",
    "events.linuxfoundation.org", "events.microsoft.com", "events.google.com",
    "tr.example.com", "ct.example.com",
    "tr.snapchat.com.example.org", "ct.pinterest.com.example.org",
])
def test_tracking_rules_do_not_block_parent_sibling_or_ambiguous_hosts(
    offline_blocklist, domain,
):
    assert not offline_blocklist.is_blocked(domain)
    assert SiteScanner(store=None).analyze(domain, process="browser").decision == "allow"
