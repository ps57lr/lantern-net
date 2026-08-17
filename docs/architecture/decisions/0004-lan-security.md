# ADR 0004: LAN responder security boundary

Status: accepted as a gated prototype

Lantern LAN is read-only initially and binds exactly one approved private interface. It refuses wildcard, public, loopback, bridge, VPN, and ambiguous bindings. It uses TLS, a locally displayed single-use pairing code, short-lived secure sessions, rate limits, Host/Origin/CSRF enforcement, revocation, bounded requests, and an audit trail without secrets.

There is no plaintext fallback, generic target, upload, filesystem, terminal, command, or remediation endpoint. mDNS discovery is not authentication. A self-signed development certificate requires visible fingerprint confirmation and is not described as frictionless production trust.

Non-loopback listening remains blocked until its threat-model tests pass independent review.
