# Contributing to nmap-web

Thanks for your interest! A few ground rules before you open a PR.

## Branch model

- `main` is the protected release branch.
- All work happens on feature branches cut from `main` (or `develop`).
- Every change lands via a Pull Request — **direct pushes to `main` are disabled**.

## Required checks

CI (`.github/workflows/ci.yml`) must be green before a PR can merge. It runs:

1. Syntax check (`node --check` on `server.js`, `lib/*.js`, `public/app.js`)
2. Unit tests (`npm run test:unit`) on Node 20 and 22
3. Frontend XSS harness (`npm run test:frontend`)
4. Docker build + smoke test (container boots and `/api/health` responds)

### Enabling branch protection (repo admins)

GitHub → Settings → Branches → Add rule for `main`:

- ✅ Require a pull request before merging
- ✅ Require approvals (1)
- ✅ Require status checks to pass before merging
  - `Test (Node 20)`
  - `Test (Node 22)`
  - `Docker build`
- ✅ Require branches to be up to date before merging
- ✅ Do not allow bypassing the above settings
- ✅ Restrict who can push to matching branches (admins only, for emergencies)

## Local development

```bash
npm install
npm start          # http://127.0.0.1:8787  (needs nmap on PATH)
npm run dev        # auto-restart on changes
npm test           # unit + frontend harness
```

`nmap` is not required to run the test suite — the scanner tests use a fake
binary. To exercise the real pipeline, run in Podman/Docker (see README).

## Code style

- ES modules (`"type": "module"`), Node ≥ 20.
- No build step, no external assets in `public/` — keep it offline-capable.
- Security: every scan-derived or user-supplied string rendered into HTML
  must go through `esc()` / `escAttr()`. The frontend harness will fail
  otherwise.

## Reporting security issues

Please do not open public issues for vulnerabilities. Email the maintainer
instead (see `package.json` author field).
