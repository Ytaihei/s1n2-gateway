# Codex development guide

## Project scope

This repository contains the S1AP/EPS-to-NGAP/5GS protocol converter used to
connect a 4G eNB to a 5G Core. Treat protocol, authentication, networking, and
subscriber-data changes as high-risk changes that require focused review.

## Integration environment

- The complete system runs with the designated integration repository derived
  from `open5gs-compose`. This repository is normally checked out at the
  submodule commit selected by that parent repository.
- Do not assume that this repository's `main` branch is compatible with the
  latest branch of the integration repository. Before integration work, record
  both exact commit SHAs and preserve the parent's submodule pin.
- The real integration stack is permitted only on the authorized remote host while it is
  connected to RG-VPN and the real base station is available.
- Never run the real integration Compose stack, attach to the physical eNB,
  or change live subscriber state on a developer machine or in GitHub Actions.
- The synthetic `lab/` environment is a separate, opt-in Linux test fixture.
  Run it only when the user requests virtual integration testing. Use
  `python3 lab/run.py`, which isolates the network and tears down its services;
  never copy deployment credentials into it. Unit tests run with `--network none`.
- GitHub Actions is build-only. A successful CI build does not establish
  end-to-end compatibility with the remote host, core network, eNB, UE, or VPN.

### Verified deployment topology

- The local SSH alias for the authorized integration host is
  `taihei-nuc-ubuntu`. Its configured jump host is `taihei-rgcpu`; use the SSH
  aliases instead of copying addresses or key paths into commands or docs.
- On the integration host, the parent repository is
  `/home/taihei/open5gs-compose` and this repository is its submodule at
  `/home/taihei/open5gs-compose/s1n2-gateway`.
- The parent integration branch is currently `master`. Always verify the actual
  branch, worktree state, and submodule pin at the start of a task rather than
  assuming that these details are unchanged.
- `scripts/check-remote-status.sh` is the approved read-only starting point for
  remote inspection. It does not establish that an end-to-end UE data session
  works.

## Safety boundaries

- Never commit, print, paste into logs, or otherwise expose `.env`,
  `config/auth_keys.yaml`, Ki, OPc, subscriber identifiers, VPN credentials, or
  other deployment secrets. Use only the committed example files as references.
- Do not change VPN settings, routes, interfaces, firewall/iptables rules,
  Docker privileged settings, physical NIC selection, eNB configuration, or
  remote-host services without explicit user approval.
- Do not deploy, restart the live stack, update the parent submodule pin, or
  push directly to `main` unless the user explicitly requests that exact action.
- Keep changes on a dedicated branch and submit them through a pull request.

## Repository layout

- `src/`: handwritten converter implementation.
- `include/`: public/internal headers and generated S1AP sources.
- `include/s1ap/`: generated/vendor protocol sources; avoid broad mechanical
  edits unless regeneration is the explicit task.
- `config/auth_keys.example.yaml`: non-secret configuration template.
- `Dockerfile`: supported, reproducible Ubuntu 22.04 build environment.
- `docker-compose.yml`: integration topology; it references files in the parent
  `open5gs-compose`-derived repository and is not a standalone local stack.

## Development workflow

1. Read `README.md`, the affected modules, and the parent-repository assumptions
   before editing.
2. Make the smallest change that satisfies the task. Preserve C11 compatibility
   and the existing warning settings in `Makefile`.
3. For protocol changes, identify the direction (4G-to-5G or 5G-to-4G), message
   type, state transition, and expected failure behavior in the PR description.
4. Build with the repository Dockerfile:

   ```bash
   docker build --tag s1n2-gateway:dev .
   ```

5. Run focused unit tests when they exist. The current `Makefile` exposes a
   `test` target, but do not claim tests passed when the repository contains no
   corresponding test sources.
6. Do not run the real integration Compose stack as part of routine validation. If an
   authorized remote integration test is required, first provide the exact
   commands, affected services, rollback plan, and expected evidence, then wait
   for explicit approval.
7. Before requesting an integration test, run `scripts/check-remote-status.sh`
   to verify reachability, clean worktrees, the submodule pin, expected
   containers, and the number of SCTP associations without retrieving logs or
   secrets.

## Completion report

Every PR or task summary must distinguish among:

- source review completed;
- build completed;
- unit tests completed;
- opt-in synthetic virtual integration test completed (report profile and scope);
- real integration test not run; or
- authorized remote-host/eNB integration test completed.

When the remote integration test was not run, state that limitation plainly and
do not describe the change as production-validated.
