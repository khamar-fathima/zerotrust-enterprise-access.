# ZeroTrust — Enterprise Access Management

A full-stack **college cybersecurity demonstration**, built with JavaScript, React/Vite, Express, Mongoose, and MongoDB Atlas. This is an educational IAM implementation, not a certified or independently reviewed production identity provider.

## Run on Replit

1. Configure these values through the project's **Secrets** tool. Never commit real credentials:
   - `MONGODB_URI`: the Atlas connection string for a dedicated application database.
   - `SESSION_SECRET`: a random secret of at least 32 characters. Replit has already provisioned this secret in this project.
   - `BOOTSTRAP_ADMIN_EMAIL`: the initial administrator's email.
   - `BOOTSTRAP_ADMIN_PASSWORD`: a unique password with at least 12 characters, uppercase, lowercase, and a digit.
2. Configure Atlas Network Access and a database user permitted to read/write the application database.
3. Run the **Start application** workflow, or `npm run dev`.
4. Open the preview. The React development server runs on port 5000 and proxies `/api` to Express on port 3001.
5. Sign in through the administrator portal, enroll an authenticator, save the one-time recovery codes, and change the bootstrap password.

The first administrator is created only when no active administrator exists and bootstrap configuration is supplied. No public administrator registration exists. The initial administrator's first device is bootstrap-approved once, after password and MFA verification, and this exception is recorded in the audit log. Later devices need an administrator's approval.

If MongoDB is not configured or cannot connect, the public UI can still render, but database-backed APIs explicitly return `503 DATABASE_UNAVAILABLE`. There is no mock authentication or substitute database.

## Scripts

| Command | Purpose |
| --- | --- |
| `npm run dev` | Express with watch mode and Vite on port 5000 |
| `npm run build` | Build the React frontend and enforce bundle budgets |
| `npm start` | Serve the built frontend and API in production mode |
| `npm test` | Frontend render, cryptographic utility, and MongoDB security tests |
| `npm run check:bundle` | Check startup/chunk size budgets after a production build |

Dependencies are managed in the root `package.json`. Source stays in `client/` and `server/`.

## Architecture

- `client/src/`: React portals, protected layouts, dashboards, management views, and Axios API client.
- `server/routes/`: authentication, identity/device/session management, dashboard analytics, and protected resources.
- `server/middleware/`: database availability and continuous session/device/account/role authorization.
- `server/models/`: User, Role, Permission, Department, Device, Session, AuditLog, Resource, and short-lived PreAuth schemas.
- `server/lib/`: audit recording and cryptographic utilities.
- `server/services/`: baseline role/permission/resource initialization.
- `server/tests/`: cryptographic utility and integrated security acceptance scenarios.

### Authentication and authorization

1. The selected portal and password are validated server-side.
2. A short-lived preauthentication challenge permits only MFA enrollment/verification.
3. TOTP or a single-use recovery code is verified.
4. The browser must present an approved random device credential; new devices are pending until approval.
5. Only then is a signed, HTTP-only session cookie issued.
6. Protected requests revalidate the session record, account status, MFA status, device credential and approval, and current role.

Sessions expire after 30 minutes idle or 12 hours absolute. Revoking a session, device, or account takes effect on the next protected request. Role changes revoke existing sessions. Manager data access is department-scoped; employees cannot retrieve other identities' private records.

Passwords use bcrypt. MFA secrets use AES-256-GCM with a domain-separated key derived from `SESSION_SECRET`; changing this secret invalidates existing MFA encryption and sessions, so retain it securely. Recovery codes and device credentials are stored only as hashes. Cookie-authenticated writes require a double-submit CSRF token. Authentication and verification endpoints are rate-limited.

### Primary demo scenario

1. Administrator signs in and creates or approves an employee.
2. Employee completes MFA enrollment and receives a pending device state.
3. Administrator approves the employee's device.
4. Employee completes sign-in and accesses their authorized resources.
5. Employee attempts to sign in through `/admin/login` using their employee credentials.
6. The backend returns `403 PORTAL_ROLE_MISMATCH`.
7. The administrator opens Audit logs and finds the critical portal-role mismatch, including actor, timestamp, and attempted portal.
8. Demonstrate direct administrator-API denial and immediate session revocation as additional controls.

## API reference

All routes are under `/api`. Error bodies use `{ error, code? }`. List endpoints return named collections, such as `{ users }` or `{ logs }`. Unauthorized accesses are denied by backend checks, not just hidden in the UI.

| Module | Endpoints |
| --- | --- |
| Health | `GET /health` |
| Auth | `GET /auth/csrf`, `GET /auth/departments`, `POST /auth/register`, `POST /auth/login`, `GET /auth/me`, `POST /auth/logout` |
| MFA | `POST /auth/mfa/setup`, `POST /auth/mfa/confirm`, `POST /auth/mfa/verify`, `POST /auth/mfa/disable` |
| Device login | `GET /auth/device-status`, `POST /auth/device/complete` |
| Credentials | `POST /auth/change-password` |
| Users | `GET /users`, `GET /users/:id`, `POST /users`, `PATCH /users/:id`, `POST /users/:id/review` |
| Roles | `GET /roles`, `GET /departments` |
| Devices | `GET /devices`, `PATCH /devices/:id` |
| Sessions | `GET /sessions`, `DELETE /sessions/:id`, `POST /sessions/revoke-all` |
| Auditing | `GET /audit-logs` with status, event type, user, date, and text filters |
| Resources | `GET /resources`, `POST /resources`, `PATCH /resources/:id`, `GET /resources/:id/content` |
| Dashboard | `GET /dashboard/summary`, `GET /dashboard/activity` |
| Profile | `GET /profile`, `PATCH /profile`, `GET /profile/login-history` |

Administrative writes are administrator-only. Users can revoke their own sessions/devices. MFA disable requires password and TOTP reauthentication, revokes sessions, and requires enrollment again on the next sign-in. Audit records have no application edit/delete endpoints.

## Testing

`npm test` always runs the cryptographic utility tests. If `MONGODB_URI` is configured, the integration suite connects to a **uniquely named test-owned database**, creates temporary fixtures, runs the ten required security scenarios plus CSRF validation, and removes only that test database afterward. The database user needs permission to create/drop that separate test database. Without `MONGODB_URI`, the integration suite reports itself as skipped—this is not proof of end-to-end behavior.

Never point this educational project at a production identity database. Use a dedicated Atlas project/database and non-sensitive demonstration accounts.

The frontend render smoke tests load each extracted page module without running effects or bypassing authentication. They catch broken component imports and initial rendering regressions; they do not replace interactive browser verification of sign-in or MFA. Protected routes still verify the session and role before rendering their lazy-loaded page.

Every `npm run build` automatically runs `check:bundle` and fails if a budget is exceeded or dashboard/management modules enter the initial static import graph. The budgets are 400 KB raw / 150 KB gzip for initial JavaScript and 500 KB raw per chunk. `npm run check:bundle` can also recheck an existing build independently.

## Production limitations

No independent penetration test, compliance certification, enterprise SSO/SCIM, mail delivery, password-recovery email service, or high-availability infrastructure is included. Audit records are append-only through this app, not immutable against a database administrator. A production deployment requires independent security review, operational monitoring, backup/recovery planning, and stronger deployment controls.
