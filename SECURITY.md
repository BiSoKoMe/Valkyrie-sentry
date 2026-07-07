# Security and Privacy Guarantees

## What Valkyrie protects against
- Background app tracking and telemetry
- 572,000+ known tracker domains (DNS sinkhole)
- 12,000+ malicious IP ranges (kernel firewall)
- Zero-day trackers (behavioral AI engine)
- DNS leaks to Google/Cloudflare (local Unbound)
- OS telemetry (16 Windows tracking systems)
- DoH bypass attempts
- TLS tracking scripts (content inspection)
- Network identity tracking (MAC randomization)

## What Valkyrie cannot protect against
- Cell tower triangulation by mobile carriers
- Baseband chip communication (below OS level)
- Certificate-pinned apps (DNS/FW still active)
- ISP metadata visibility (fixable with VPN)

## Zero knowledge architecture
- Zero log mode is available (RAM only)
- No central server receives any client data
- No telemetry sent from Valkyrie itself
- Device contains no identity-linked data
- All processing happens locally on device

## Reporting security issues
Contact via the repository owner on GitHub.
