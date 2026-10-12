# VulnShop — an Application Security lab

A small, deliberately vulnerable Flask web app, its secure counterpart, and a
CI/CD security pipeline (SAST + DAST) that runs on every push.

> ⚠️ **VulnShop is insecure on purpose.** Run it only on your own machine.
> Never deploy it to the public internet.

Built to demonstrate, end to end, how application security works in practice:
write code → a scanner finds the flaw → fix it → re-scan → automate the whole
thing so it happens on every commit.

---

## What's inside

| File | What it is |
|------|------------|
| `app.py` | The **vulnerable** app (SQLi, IDOR, XSS, hardcoded secret, debug on) |
| `app_fixed.py` | The **secure** version — every flaw fixed, with a comment on each fix |
| `init_db.py` | Creates the demo database (plaintext passwords, for the vulnerable app) |
| `init_db_fixed.py` | Same database but with **hashed** passwords, for the fixed app |
| `templates/` | The HTML pages |
| `.github/workflows/security.yml` | The CI/CD pipeline: Semgrep (SAST) + OWASP ZAP (DAST) |
| `requirements.txt` | Python dependencies |

---

## The vulnerabilities (and how they're fixed)

| # | Vulnerability | Where | Fix |
|---|---------------|-------|-----|
| 1 | **SQL Injection** | `/login` | Parameterized query instead of string concatenation |
| 2 | **IDOR** | `/profile?id=` | Use the id from the session, ignore the URL |
| 3 | **Reflected XSS** | `/search?q=` | Let Jinja2 autoescape the output (`|safe` removed) |
| 4 | **Hardcoded secret** | `app.secret_key` | Read it from an environment variable |
| 5 | **Debug mode in prod** | `app.run(debug=True)` | `debug=False` |
| 6 | **Plaintext passwords** | the database | Store and verify password **hashes** |

---

## Run it locally

```bash
# 1. set up
python -m venv .venv
source .venv/bin/activate         # Windows: .venv\Scripts\activate
pip install -r requirements.txt

# 2. the VULNERABLE app
python init_db.py
python app.py                     # http://localhost:5000
```

Now try the attacks by hand:

- **SQL injection** — log in with username `admin' --` and any password. You're in.
- **IDOR** — once logged in, open `/profile?id=1`, then `/profile?id=2`. You can
  read another user's email and credit card.
- **XSS** — open `/search?q=<script>alert(1)</script>`. The script runs.

Then run the **fixed** app and try the same attacks — they all fail:

```bash
python init_db_fixed.py
SECRET_KEY=change-me python app_fixed.py    # Windows: set SECRET_KEY first
```

---

## Scan it yourself (what the pipeline automates)

**SAST — read the code:**
```bash
pip install semgrep
semgrep --config p/python --config p/flask --config p/owasp-top-ten --config p/secrets app.py
```

**DAST — attack the running app:**
```bash
# with the app running on :5000
docker run --rm -t ghcr.io/zaproxy/zaproxy:stable \
  zap-baseline.py -t http://host.docker.internal:5000
```

---

## The CI/CD pipeline

`.github/workflows/security.yml` runs on every push and pull request to `main`:

1. **SAST job** — checks out the code and runs Semgrep over it.
2. **DAST job** — installs the app, starts it, and runs an OWASP ZAP baseline
   scan against the live instance.

Push the vulnerable `app.py` and the SAST job goes **red**. Fix it, push again,
and it goes **green**. That red/green gate is the whole point of "shifting
security left" — problems are caught automatically, before code reaches
production, instead of months later in a pentest.

---

## What this demonstrates

- The full AppSec loop: **find → verify → fix → re-scan → automate**
- Hands-on SAST (Semgrep) and DAST (OWASP ZAP)
- Secure coding fixes for the most common web vulnerabilities (OWASP Top 10)
- Integrating security into CI/CD with GitHub Actions
