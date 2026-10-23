# TrustVault Threat Model

## Assets

- Confidential document contents and metadata
- Account credentials and authenticated sessions
- Workspace membership and roles
- Per-document permissions and revocation state
- Audit history and evidence of security-relevant events
- Private uploaded files and their storage paths

## Security boundaries

- Browser/client to Flask API
- Authenticated user to selected workspace
- Workspace member to a specific document
- Workspace administrator to audit metadata (not document contents)
- Application process to database and private file storage

## Threats and mitigations

| Threat | Example | Mitigation | Residual risk |
|---|---|---|---|
| Broken object-level authorization | A user guesses another document ID | Every document route checks active workspace, membership, ownership or explicit grant | Must keep tests for every new endpoint |
| Cross-workspace data leakage | User belongs to Company A and B, but requests B's document while A is active | Active workspace is stored in session; direct document access requires document company to match active workspace | Session theft can expose the workspaces the user is entitled to |
| Privilege escalation | Viewer calls update/delete/permission routes | Backend role/owner/grant checks; admin role does not automatically reveal content | Application bugs may bypass checks if new routes omit helpers |
| Stale permission after revocation | Previously granted user keeps requesting document | Every request reads current database grants | Already downloaded files cannot be recalled |
| CSRF | Attacker causes browser to submit a state-changing request | Flask-WTF CSRF protection and `X-CSRFToken` header | XSS or leaked tokens can undermine browser protections |
| Session theft | Stolen session cookie is reused | HttpOnly, SameSite=Lax, Secure in HTTPS deployments; logout | HTTPS and secure host configuration are required |
| Password compromise | Weak or reused password | Password hashing and minimum 12-character rule | No MFA or rate limiting in current backend |
| Unsafe upload/path traversal | Crafted filename tries to escape storage | `secure_filename`, extension allowlist, random server-generated storage name, resolved path check, 10 MB limit | Extension allowlist is not malware scanning or content inspection |
| Audit tampering | Database rows are changed | SHA-256 hash chain with previous hash links and verification tests | A privileged attacker can rewrite the entire database chain; external signed checkpoints are needed for stronger guarantees |
| Audit information leakage | Admin sees other company's events | Audit records snapshot workspace ID; query filters by selected workspace | Legacy events that cannot be unambiguously assigned during migration may have a null workspace and are not broadly exposed |
| Denial of service | Oversized upload or excessive requests | 10 MB upload/request limit | Rate limiting, quotas and monitoring are not yet implemented |
| Database/file inconsistency | File removed before DB commit or stale file remains | File deletion after successful DB commit; rollback cleanup on upload failure | Process crash can still leave orphan files; periodic cleanup is advisable |

## Trust assumptions

- The server, secret key, database credentials and private upload directory are controlled by the deployment operator.
- Workspace admins are trusted to manage membership and view audit metadata, but are not automatically trusted with every document.
- Email addresses identify accounts; invitation verification/acceptance flow is not implemented in this backend. Adding an account by email currently requires that account to be registered.
- The application is not production-ready until HTTPS, backups, rate limiting, operational alerting, file scanning and deployment secrets are configured.

## Security test priorities

- Cross-user and cross-workspace reads/downloads are denied.
- Read grants cannot edit or delete.
- Revocation blocks the next request.
- Non-owners cannot grant/revoke permissions or delete.
- Workspace switching rejects non-members.
- Audit logs remain scoped to a workspace and retain document deletion events.
- Tampered audit event data breaks chain verification.
