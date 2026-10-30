# Forgejo Actions: intentionally empty

This repository's CI is GitHub Actions (`.github/workflows/`). The rack Forgejo
keeps a git mirror only and runs no CI.

This file exists to keep the `.forgejo/workflows/` directory in the tree.
**Do not delete it.** When this directory is missing, Forgejo falls back to
`.github/workflows/` and queues every GitHub workflow, scheduled ones included,
for runners it does not have. Forgejo only reads `.yml` and `.yaml` files here,
so this README starts no runs.

That fallback has already happened on the rack. GarnetLedger/finance-controls has
no `.forgejo/` directory, and Forgejo still queued its `.github/workflows/*.yml`
jobs. They waited for an `ubuntu-latest` runner and were then cancelled. Source:
`forgejo.db`, backup capture 20261030T073323Z.

This file can be removed once Actions is turned off for this repository in
Forgejo's settings.
