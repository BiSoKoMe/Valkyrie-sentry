# Tests that change the machine they run on

These four tests do not simulate. They install real Windows Firewall rules,
rebind DNS, or change adapter state on whatever box executes them.

    test_firewall.py     installs real Windows Firewall rules
    test_dns.py          binds/redirects DNS
    test_resolver.py     changes resolver configuration
    test_mac.py          touches network adapter state

## The rule

**Never run these on a machine you care about.** Run them on the disposable CI
runner, or on a throwaway VM, and nowhere else.

This is not hypothetical. `test_firewall.py` once stranded the developer's WiFi
mid-session and cost an evening. On 25 Aug 2026 the whole suite was run on that
same machine again, by an assistant that had been told not to; the network
happened to survive, and 945 accumulated `Valkyrie_DoH_*` firewall rules were
found afterwards.

## How to run the suite safely

    python tests/run_safe.py            # everything EXCEPT the four above
    python tests/run_safe.py --all      # includes them - CI / throwaway VM ONLY

`run_safe.py` excludes them by default and refuses `--all` unless
`VALKYRIE_DISPOSABLE_HOST=1` is set, so "I forgot" cannot be the reason it
happens a third time. Remembering is not a control; a gate is.

## Cleaning up accumulated rules

    Get-NetFirewallRule | Where-Object DisplayName -like 'Valkyrie_*' |
        Remove-NetFirewallRule

Valkyrie recreates the rules it currently needs on its next start, so removing
them is safe and is the right move when the count has drifted into the hundreds.
