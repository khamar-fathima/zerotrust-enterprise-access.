---
name: Test suite isolation
description: Keep browser and UI test runs from racing Vite caches or throttling test fixtures.
---

Run the project test files serially. The browser acceptance test and mocked UI tests start separate Vite servers that can race while optimizing dependencies when the Node test runner runs files in parallel. Test requests also share a loopback address, so production sign-in throttles can block fixture users.

**Why:** A parallel full-suite run produced Vite `504 Outdated Optimize Dep` errors and fixture sign-ins were rate limited. Serial execution with elevated test-only auth throttles passed the complete suite.

**How to apply:** Preserve `--test-concurrency=1` in the test command and keep the higher login/challenge limits restricted to `NODE_ENV=test`. Production and development limits should remain unchanged.
