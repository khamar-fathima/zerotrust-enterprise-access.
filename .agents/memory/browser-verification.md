---
name: Atlas test database limits
description: Environment-specific database-name limits and reliable teardown for isolated tests.
---

Keep disposable database names within 38 bytes in this Atlas environment, including the longest possible random suffix.

**Why:** Atlas rejected a 39-byte test database name. A variable-length sanitized random suffix made the failure intermittent. Cleanup then attempted to drop that invalid database and skipped disconnecting, leaving the test process running. Earlier suspicion of browser/screenshot contention was not the actual diagnosis.

**How to apply:** Use short prefixes and fixed-length suffixes for test databases. Enforce the maximum before connecting and disconnect in a finally block even if dropping the test database fails. Do not replace the uniquely named test database with the application's database.
