---
name: GitHub authorization
description: Source-control integration status can disagree with usable workspace authentication.
---

Do not treat a healthy GitHub connection response as proof that repository creation or pushing is authenticated.

**Why:** The connection reported healthy/already attached while the GitHub CLI had no authenticated session. Reauthorization and first-time connection prompts also returned contradictory validation errors.

**How to apply:** Verify a real, non-secret authentication result. If the integration flow remains inconsistent, stop retrying it, clearly state that nothing was pushed, and use a user-created repository URL or the standard Git pane. Never request a token in chat or invent connector identifiers.
