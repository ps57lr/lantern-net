# ADR 0003: Report schema and structural redaction

Status: accepted

Lantern evolves the report additively from schema 1.0 to 1.1. Existing keys retain their meanings. New evidence, coverage, finding-code, confidence, access-prerequisite, and action-plan fields are derived by the core rather than JavaScript.

Every typed value has a sensitivity classification. Share-safe serialization transforms fields before prose rendering, keeps documented diagnostic network addresses, tokenizes device and user identifiers, removes potential secrets, and treats unknown legacy fields conservatively. Global substring replacement is deprecated because it can corrupt unrelated text.
