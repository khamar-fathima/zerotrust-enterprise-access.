---
name: Browser verification scheduling
description: Conservative scheduling for live browser acceptance and screenshot capture.
---

Run live browser acceptance tests separately from screenshot capture in this workspace.

**Why:** A concurrent browser-test/capture run failed early and stalled; the same browser flow passed when run alone. Contention was not conclusively diagnosed, so serialization is a conservative operational choice.

**How to apply:** Finish the browser acceptance command before starting a screenshot capture, or vice versa. Do not interpret this as evidence of an application authentication defect.
