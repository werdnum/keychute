-- A request that matched a standing policy row carries that row's expiry, so a
-- later *human* approval can cap the grant at it — the auto-approve path
-- already applies min(TTL, policy_not_after), and approving minutes before a
-- policy lapses must not mint a grant that outlives it (DESIGN §5, grants).
ALTER TABLE access_requests ADD COLUMN policy_not_after timestamptz;
