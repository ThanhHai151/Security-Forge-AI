"""Built-in sandboxed labs.

Each emulates one class against in-memory fake data. The SQLi lab uses a tiny, quote-aware
WHERE-clause evaluator so a real injection (``administrator'--`` / ``' OR '1'='1`) bypasses
auth exactly as it would against a vulnerable app — but nothing touches a real database.
"""

from __future__ import annotations

import html
import re

from labs.base import BaseLab, Lab, LabRequest, LabResponse

# ── a toy, quote-aware SQL predicate evaluator (the SQLi lab's "engine") ──


def _strip_sql_comment(sql: str) -> str:
    """Cut an inline ``--`` comment that begins outside a string literal."""
    in_quote = False
    i = 0
    while i < len(sql):
        c = sql[i]
        if c == "'":
            in_quote = not in_quote
        elif not in_quote and sql.startswith("--", i):
            return sql[:i]
        i += 1
    return sql


def _split_top(expr: str, op: str) -> list[str]:
    """Split on a boolean ``op`` token that sits outside quotes (case-insensitive)."""
    parts: list[str] = []
    in_quote = False
    last = 0
    i = 0
    token = op.lower()
    while i < len(expr):
        if expr[i] == "'":
            in_quote = not in_quote
            i += 1
            continue
        if not in_quote and expr[i] in " \t":
            # try to match " op " at this whitespace boundary
            m = re.match(rf"\s+{token}\s+", expr[i:], re.IGNORECASE)
            if m:
                parts.append(expr[last:i])
                i += m.end()
                last = i
                continue
        i += 1
    parts.append(expr[last:])
    return [p.strip() for p in parts if p.strip()]


def _value(tok: str, row: dict[str, str]) -> str | None:
    tok = tok.strip()
    if len(tok) >= 2 and tok[0] == "'" and tok[-1] == "'":
        return tok[1:-1]
    if tok.isdigit():
        return tok
    return row.get(tok.lower())  # column reference


def _eval_cmp(expr: str, row: dict[str, str]) -> bool:
    m = re.match(r"(.+?)\s*=\s*(.+)", expr)
    if not m:
        return bool(_value(expr, row))
    return _value(m.group(1), row) == _value(m.group(2), row)


def eval_predicate(predicate: str, row: dict[str, str]) -> bool:
    """Evaluate a SQL WHERE predicate (OR over ANDs over comparisons) against one row."""
    predicate = _strip_sql_comment(predicate).strip()
    if not predicate:
        return True  # WHERE removed by a comment → unconditional match
    return any(
        all(_eval_cmp(cmp, row) for cmp in _split_top(or_part, "and"))
        for or_part in _split_top(predicate, "or")
    )


# ── labs ──


class SqliLoginBypassLab(BaseLab):
    slug = "sqli-login-bypass"
    title = "SQL injection — login bypass"
    category = "Injection"
    kb_id = "sql_injection"
    skill = "ai_framework/skills/exploiting-sql-injection"
    difficulty = "apprentice"
    description = "Authenticate as administrator without valid credentials. Goal: an admin session."

    def reset(self) -> None:
        self.solved = False
        self.users = [
            {"username": "wiener", "password": "peter", "role": "user"},
            {"username": "administrator", "password": "s3cr3t-9f2a", "role": "admin"},
        ]

    def handle(self, req: LabRequest) -> LabResponse:
        if req.method != "POST" or req.path.rstrip("/") not in ("", "/login"):
            return LabResponse(
                body="<h1>Login</h1><form method=post action=/login>"
                "<input name=username><input name=password type=password>"
                "<button>Log in</button></form>",
                note="POST username & password to /login. Try a classic auth bypass.",
            )
        u = req.body.get("username", "")
        p = req.body.get("password", "")
        # The vulnerability: credentials concatenated straight into the query string.
        predicate = f"username = '{u}' AND password = '{p}'"
        query = f"SELECT * FROM users WHERE {predicate}"
        matched = [row for row in self.users if eval_predicate(predicate, row)]
        if not matched:
            return LabResponse(status=401, body="<p>Invalid credentials.</p>", note=f"ran: {query}")
        row = matched[0]
        authentic = any(r["username"] == u and r["password"] == p for r in matched)
        if not authentic:
            self.solved = True  # got in without valid creds
            note = "Solved — authentication bypassed via SQL injection."
        else:
            note = "Logged in with valid credentials (no injection)."
        return LabResponse(
            body=f"<h1>Welcome, {html.escape(row['username'])}</h1>"
            f"<p>Role: {html.escape(row['role'])}</p>",
            solved=self.solved,
            note=note,
        )


class ReflectedXssLab(BaseLab):
    slug = "reflected-xss"
    title = "Reflected XSS in search"
    category = "Client-side"
    kb_id = "xss"
    skill = "ai_framework/skills/"
    difficulty = "apprentice"
    description = "The search box reflects your query unencoded. Goal: inject executing markup."

    def reset(self) -> None:
        self.solved = False

    def handle(self, req: LabRequest) -> LabResponse:
        q = req.query.get("q", req.body.get("q", ""))
        # The vulnerability: the query is interpolated into HTML with no escaping.
        body = f"<h1>Search</h1><p>0 results for: {q}</p>"
        executes = bool(re.search(r"<script|onerror\s*=|onload\s*=|<img[^>]+src", q, re.IGNORECASE))
        if executes:
            self.solved = True
        note = (
            "Solved — payload reflected unescaped." if self.solved else "Reflect a script payload."
        )
        return LabResponse(body=body, solved=self.solved, note=note)


class IdorLab(BaseLab):
    slug = "idor"
    title = "IDOR — access another user's account"
    category = "Access control"
    kb_id = "broken_access_control"
    skill = "ai_framework/skills/"
    difficulty = "apprentice"
    description = "You are logged in as user #1. Goal: read another account by changing the id."

    def reset(self) -> None:
        self.solved = False
        self.session_uid = "1"
        self.accounts = {
            "1": {"user": "wiener", "balance": "120", "apikey": "live_w_8821"},
            "2": {"user": "administrator", "balance": "999999", "apikey": "live_admin_root"},
        }

    def handle(self, req: LabRequest) -> LabResponse:
        if req.path.rstrip("/") not in ("", "/account"):
            return LabResponse(status=404, body="<p>Not found.</p>")
        # The vulnerability: the record is keyed by ?id with no ownership check.
        wanted = req.query.get("id", self.session_uid)
        acct = self.accounts.get(wanted)
        if acct is None:
            return LabResponse(status=404, body="<p>No such account.</p>")
        if wanted != self.session_uid:
            self.solved = True
        note = (
            "Solved — read another user's account (IDOR)."
            if self.solved
            else "You see your own account."
        )
        return LabResponse(
            body=f"<h1>Account #{wanted}</h1><p>User: {html.escape(acct['user'])}</p>"
            f"<p>API key: {html.escape(acct['apikey'])}</p>",
            solved=self.solved,
            note=note,
        )


def builtin_labs() -> list[Lab]:
    return [SqliLoginBypassLab(), ReflectedXssLab(), IdorLab()]
