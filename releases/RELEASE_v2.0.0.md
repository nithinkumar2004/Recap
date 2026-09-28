# Release v2.0.0
**Baseline Version:** `v1.2.0` -> **Target Version:** `v2.0.0`  
**Risk Rating:** `HIGH` (Score: 14)  

### New Features
- [auth] add OAuth2 login and JWT session handling
- [billing] require currency parameter in charge API

### Bug Fixes
- [payments] resolve timeout in payment processing gateway

### Breaking Changes
- **Commit Log** (`9b0c1d2`): Commit marked breaking: [billing] require currency parameter in charge API
- **src/payments/processor.py** (`charge`): Function 'charge' added new required parameter(s). Callers without them will break.
  - Old: `def charge(user_id, amount)`
  - New: `def charge(user_id, amount, currency)`

### Maintenance & Chores
- [chore] update requirements.txt with latest packages

### Quality & Verification Health
- **Automated Tests:** 147/147 passed (0 failed, 0 skipped) in 18.4s
- **Secrets Detected:** 0
- **SAST High/Critical:** 0
- **Dependency CVEs (High/Critical):** 1

### Explainable Risk Factors
- **+3**: Database Schema / Migration Modified (Changes detected in migration files: migrations/003_add_currency.sql)
- **+3**: Authentication / Security Middleware Modified (Security-sensitive files changed: src/auth/oauth.py)
- **+6**: Breaking Public API Changes Detected (2 breaking change(s) in API/function contracts)
- **+2**: Dependency Manifest Modified (Package manifests updated: requirements.txt)
