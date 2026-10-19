---
name: Query schema defaults
description: Zod 4 parsing behavior to preserve when modifying validated query parameters.
---

For query values transformed from strings into numbers, use a pre-parse default rather than a string output default.

**Why:** Zod 4 output defaults short-circuit transformations. A string default can escape the numeric validation and remain a string even though explicitly provided values become numbers.

**How to apply:** When extending query schemas, check both omitted parameters and explicit parameters for the same final types; preserve this distinction when upgrading Zod.
