# ADR 0002: Privilege separation

Status: accepted for contracts; helper deferred

The diagnostic core and UI remain unprivileged. Read-only checks report permission-denied or unsupported states honestly. Remediation planning may describe an administrator requirement but does not collect credentials.

Any future elevated helper must expose one versioned message per allowlisted action, validate typed parameters, use fixed native APIs or absolute executable paths with a sanitized environment, and reject executable paths, shell text, scripts, URLs, and unknown fields. It will be designed and audited separately before a real remediation is registered.
