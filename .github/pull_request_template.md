## Summary

<!-- What changed and why? -->

## Protocol impact

<!-- Direction, message type, state transition, and failure behavior; or "None". -->

## Validation

- [ ] Source review completed
- [ ] Docker build completed
- [ ] Unit tests completed (or no applicable test sources exist)
- [ ] `scripts/check-remote-status.sh` completed, if remote context was needed
- [ ] Integration test completed with explicit approval

Integration status: <!-- Not run / Completed with approval -->

## Safety review

- [ ] No `.env`, authentication keys, subscriber identifiers, VPN credentials,
      private addresses, or other deployment secrets are included
- [ ] No unapproved live-service, eNB, VPN, route, interface, firewall, or
      subscriber-state changes were made
- [ ] Parent `open5gs-compose` commit and `s1n2-gateway` submodule pin are
      recorded when compatibility is affected

## Rollback

<!-- State the rollback procedure for behavior changes; or "Revert this PR". -->
