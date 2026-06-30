// masking_compare.cedar
// Gates the web-app's /action/masking-comparison route, which forces umask='raw'
// on behalf of the human to produce a side-by-side raw-vs-masked diff. Only
// senior_analyst is allowed (matches the existing hard-coded role check that
// this policy replaces at web-app/app/routes/actions.py:160).
permit(
  principal is User,
  action == Action::"ViewMaskingComparison",
  resource is User
)
when {
  principal.role == "senior_analyst"
};