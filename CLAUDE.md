# CLAUDE.md

This repository is the client for **GRASP-P**, SovTech's private-repository extension to the
ngit-grasp server: `cord-core` (the library), `cord-git` (the CLI) and `inbox-relay` (a test
relay). Everything is encrypted on the client; the server only ever stores ciphertext.

## Start here

The plan, the state of the work and the system overview live in the **server** repository
(`grasp-p`), under `docs/grasp-p/`: `CLOUD-HANDOFF.md`, `PLAN.md`, `OVERVIEW.md` and the full
convention `CORD-git-v0-spec.md`. Read those before changing protocol behaviour here.

`README.md` lists every command and the known gaps.

## Rules

- **Commit identity:** `git -c user.name=sovtech -c user.email=git@sovtech.pro commit ...`.
  Pass it on every commit; do not rely on ambient git config.
- **No AI attribution anywhere:** no `Co-Authored-By`, no "Generated with", no session links, in
  commits, pull requests or files.
- Commit subjects start with `sovtech:`. Never squash, never rebase or amend a pushed commit;
  fix forward. Never push to `main`; work on a branch.
- Run `git status` immediately before every `git commit`.
- Stage files by path. Never `git add -A` or `git add .`: the end-to-end script and the CLI write
  key files and keystores into working directories.
- **Never commit or print secrets.** No nsec, keystore, token or password in files, logs, test
  output or commit messages. Test keys are generated at run time or are obvious throwaway
  constants inside test code. Never add a code path that takes a secret key on the command line.
- The protocol is about to change (owner model, key list, rotation: milestone M4 in the plan).
  Do not start that work without reading the decisions in `PLAN.md`.

## Building and testing

- `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets --locked -- -D warnings`,
  `cargo test --workspace --locked`.
- `scripts/e2e.sh` runs the full scenario suite against a real server binary. It needs
  `SERVER_BIN` (the server built from the `grasp-p` commit named in `ci/SERVER_REF`), `CORD_BIN`
  and `INBOX_BIN`, and loopback ports 7361 to 7363.
- Builds and tests belong in a cloud sandbox or in CI. Never run them on a SovTech host.

## Out of scope for a cloud session

Deployment, the GitLab project, CI runners and anything on SovTech hosts. GitLab is the canonical
remote and GitHub is a working mirror: push branches here, and they are carried to GitLab from
the maintainer's machine.
