# Agent Guidance

## Review Scope Discipline

- Require a concrete, reachable failure before expanding a change. If a proposed remedy adds persistent state, a schema or migration, retries or background work, validation or attestation, a new service, or another subsystem, present it as a scope decision instead of an automatic review fix.
- Do not invent guarantees, coverage claims, or attestations the user did not request. If review shows an unrequested promise cannot be justified, withdraw or narrow the promise before adding machinery to make it true; reviewers should question whether the promise belongs, not only whether it is proven.
- On rereview, distinguish defects in the original change from defects introduced by earlier review fixes. If another fix would add another layer, stop the loop and prefer deletion, narrowing, reuse of an existing chokepoint, or an explicitly accepted bounded residual unless the owner authorizes the expanded design.

