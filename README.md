# VulnShop — an Application Security lab

A small Flask web app that started **deliberately vulnerable**, a CI/CD security
pipeline that runs **SAST, DAST and SCA** on every push, and the commit history
of finding and fixing every flaw — the same loop an AppSec team runs every day.

![Security Pipeline](https://github.com/Oussamakhodr95/vulnshop/actions/workflows/security.yml/badge.svg)

> The current code is the **fixed** version. To see the original vulnerable app,
> open the [first commit](https://github.com/Oussamakhodr95/vulnshop/commit/ce9c5da).
> Each fix after it is a separate commit, so the history reads as before → after.

---

## The security pipeline

`.github/workflows/security.yml` runs three jobs on every push and pull request to `main`:

| Job | Type | Tool | What it checks |
|-----|------|------|----------------|
| **SAST** | Static analysis | Semgrep (`p/python`, `p/flask`, `p/secrets`) | The source code, for vulnerable patterns |
| **DAST** | Dynamic analysis | OWASP ZAP baseline | The running app, from the outside |
| **SCA** | Dependency scanning | pip-audit | Third-party packages, for known CVEs |

SAST and SCA are **blocking gates**: any finding fails the job and turns the pipeline red.
DAST runs in report mode (`-I`): warnings such as missing security headers are recorded
in the ZAP report artifact without blocking, because blocking every low-risk header
warning teaches developers to ignore the pipeline.

The app's secret key is stored as a **GitHub Actions secret** and injected at runtime;
it is never in the repository.

---

## What was found, and by what

The app started with six vulnerabilities. The pipeline caught some; others needed a human.

| # | Vulnerability | Found by | Fix |
|---|---------------|----------|-----|
| 1 | SQL injection in `/login` | **Semgrep** + manual | Parameterized query |
| 2 | Flask `debug=True` | **Semgrep** | Debug only when `FLASK_DEBUG=1` is set |
| 3 | Bound to `0.0.0.0` | **Semgrep** | Bound to `127.0.0.1` (see triage note) |
| 4 | IDOR on `/profile?id=` | **Manual testing** — missed by tools | User id taken from the session, never the URL |
| 5 | Reflected XSS on `/search` | **Manual testing** — missed by tools | Removed `\|safe`; Jinja2 autoescaping |
| 6 | Hardcoded secret key | **Code review** — missed by tools | Read from environment / GitHub Secrets |
| 7 | Plaintext passwords | **Code review** — missed by tools | Stored and verified as hashes |
| 8 | Vulnerable Flask & Werkzeug versions | **pip-audit** | Upgraded to `Flask 3.1.3`, `Werkzeug 3.1.9` |

**Triage note on #3:** binding to `0.0.0.0` is required when an app runs inside a
container, so the same Semgrep finding can be a false positive in one deployment and a
real issue in another. Here the app runs directly on the host, so it was fixed.

---

## What I learned

- **Green does not mean secure.** After the pipeline went green, IDOR and XSS were
  still exploitable. Access control and logic flaws need manual testing.
- **Red does not always mean a vulnerability.** Two early red runs were caused by the
  pipeline itself (a ZAP action that tried to open issues without permission, and an
  outdated version whose artifact upload no longer worked). You have to read *why* a
  job failed.
- **A scanner that never fails is worse than none.** The first Semgrep setup reported
  findings but still passed. Adding `--error` is what turned it into a real gate.
- **Fix the cause, not the instance.** For dependencies, one upgrade to the highest
  fixed version closed every CVE at once. For XSS, the unsafe template branch was
  removed entirely instead of just avoided.
- **Verify both directions.** Every fix was tested to confirm the attack fails *and*
  normal use still works.

---

## Run it locally

```bash
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt

export SECRET_KEY="local-dev-only" # Windows PowerShell: $env:SECRET_KEY="local-dev-only"
python init_db.py
python app.py                      # http://localhost:5000
```

Demo users: `admin` / `SuperSecret123`, `oussama` / `hunter2`.

## Run the scans locally

```bash
# SAST
semgrep scan --config p/python --config p/flask --config p/secrets --error .

# SCA
pip-audit -r requirements.txt

# DAST (with the app running on :5000)
docker run --rm -t ghcr.io/zaproxy/zaproxy:stable \
  zap-baseline.py -t http://host.docker.internal:5000
```

---

> ⚠️ This is a learning project. The first commit contains intentionally vulnerable
> code. Don't deploy any version of it to the public internet.
