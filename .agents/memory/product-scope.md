---
name: ZeroTrust product scope
description: Approved purpose, demo priorities, and design constraints that should guide future implementation.
---

This is a college project/demo, not intended as production enterprise identity infrastructure. The attached brief is the primary checklist; there is no additional course rubric. Complete all modules in phases, with actual backend functionality rather than a frontend prototype.

**Why:** The user explicitly selected the college-demo purpose and confirmed these scope requirements.

**How to apply:** Prioritize demonstrable RBAC, MFA, device verification, session monitoring, and security auditing. The most important live scenario is an employee attempting unauthorized administrator access, being denied, and the incident appearing in the admin security audit dashboard.

For this app, the user said: "make the UI nice .. not generic blue,purple or yellow".

**Why:** The user added this constraint when approving the build plan.

**How to apply:** Keep the interface distinctive and avoid replacing it with a generic blue, purple, or yellow SaaS theme.

The AI risk-analysis feature is for the bootstrap administrator only and covers both organization-wide and individual-account risk. It must not introduce a separate SUPER_ADMIN role or let AI change scores, permissions, or accounts.

**Why:** The user selected bootstrap-admin-only access and both scoring scopes, then approved an explainable server score with advisory AI analysis.

**How to apply:** For this feature, the user approved sending redacted aggregate/pseudonymous risk signals to a Replit-managed AI provider. This does not authorize sending names, emails, IP addresses, raw audit descriptions, credentials, or secrets. Keep analysis on demand; do not send data merely because a dashboard opens.
