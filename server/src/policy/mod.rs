//! Policy engine: pure decision logic. Contract in docs/IMPLEMENTATION.md §policy.
//! STUB — implemented by the policy task.

pub mod paths {
    /// Canonicalize a request path per DESIGN §4: percent-decode once, reject
    /// ambiguity (encoded separators, dot segments, backslash, non-UTF8).
    /// Returns the canonical decoded path starting with '/'.
    pub fn canonicalize(_raw: &str) -> Result<String, &'static str> {
        unimplemented!("policy task")
    }

    /// Prefix match at '/' segment boundaries only.
    pub fn prefix_matches(_prefix: &str, _path: &str) -> bool {
        unimplemented!("policy task")
    }
}
