# ZeroTrust project

## Run
- JavaScript MERN application. Preserve the existing `client/` and `server/` layout.
- Root command: `npm run dev`.
- Vite listens on `0.0.0.0:5000`, allows the preview proxy host, and proxies `/api` to Express on port 3001.
- Production: `npm run build`, then `npm start` (serves the built client and API).
- Required environment secrets: `MONGODB_URI`, `SESSION_SECRET`, `BOOTSTRAP_ADMIN_EMAIL`, and `BOOTSTRAP_ADMIN_PASSWORD`. Do not inspect or print their values.
- MongoDB Atlas is the persistent data source. Do not replace it with PostgreSQL or silently substitute a local/mock database.
- Missing/unreachable MongoDB makes data APIs return an explicit 503; public pages remain visible.

## Verification
- `npm test`: utility checks; database acceptance scenarios run only when `MONGODB_URI` exists, using a uniquely named disposable test database.
- `npm run build`: production frontend build.
- `/api/health`: reports database connection/configuration status without exposing credentials.
- See README.md for API routes, setup, bootstrap behavior, and security limitations.
