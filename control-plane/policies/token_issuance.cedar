// token_issuance.cedar
// Service-level authorization for token issuance.
// The runtime source of truth is platform.cedar_policies; this file is a
// reference copy used for CI tests and offline review. The control plane
// loads policies from the DB table at startup and on /admin/policies/reload.
//
// Entities (loaded by entity_builder at boot):
//   User    { role: String, scopes: Set<String> }
//   Agent   { is_delegatable: Bool, default_scopes: Set<String>, allowed_scopes: Set<String> }
//   TokenRequest { grant_type, requested_scopes, subject_scopes, client_type }
//
// Actions: IssueToken (token issuance), ViewMaskingComparison (in masking_compare.cedar)

// --- Authorization Code + Refresh Token (humans) ---
permit(
  principal is User,
  action == Action::"IssueToken",
  resource is TokenRequest
)
when {
  (resource.grant_type == "authorization_code" || resource.grant_type == "refresh_token") &&
  (resource.requested_scopes.isEmpty() ||
   resource.requested_scopes.containsAny(principal.scopes))
};

// --- RFC 8693 Token Exchange (delegated agent) ---
//   - Agent must be delegatable
//   - subject_scopes (from human's JWT) must intersect with agent.default_scopes
permit(
  principal is Agent,
  action == Action::"IssueToken",
  resource is TokenRequest
)
when {
  resource.grant_type == "token_exchange" &&
  principal.is_delegatable &&
  resource.subject_scopes.containsAny(principal.default_scopes)
};

// --- Client Credentials (headless agent) ---
//   - allowed_scopes (from platform.clients) must match requested (or empty = all)
permit(
  principal is Agent,
  action == Action::"IssueToken",
  resource is TokenRequest
)
when {
  resource.grant_type == "client_credentials" &&
  (resource.requested_scopes.isEmpty() ||
   resource.requested_scopes.containsAny(principal.allowed_scopes))
};