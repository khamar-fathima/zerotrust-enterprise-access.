---
name: Atlas test database limits
description: Environment-specific database-name limits and reliable teardown for isolated tests.
---

Keep disposable database names within 38 bytes in this Atlas environment, including the longest possible random suffix.

**Why:** Atlas rejected a 39-byte test database name. A variable-length sanitized random suffix made the failure intermittent. Cleanup then attempted to drop that invalid database and skipped disconnecting, leaving the test process running. Earlier suspicion of browser/screenshot contention was not the actual diagnosis.

**How to apply:** Use short prefixes and fixed-length suffixes for test databases. Enforce the maximum before connecting and disconnect in a finally block even if dropping the test database fails. Do not replace the uniquely named test database with the application's database.

MongoDB-backed integration and browser tests can be blocked when the workspace cannot reach the configured Atlas cluster. Confirm Atlas connectivity or its network access rules before treating a server-selection timeout as an application regression.

**Why:** On 2026-10-19, both acceptance suites failed before test setup because Atlas reported no reachable primary and identified IP allowlisting as a common cause.

**How to apply:** Separate infrastructure connection failures from application assertions; continue with syntax, build, and non-database tests, and report that database-backed behavior remains unverified until connectivity is restored.
