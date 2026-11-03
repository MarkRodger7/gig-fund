#!/usr/bin/env python3
"""Fetch an E*TRADE portfolio and publish an encrypted snapshot to the site.

Run once per trading day after the US market close (16:00 US Eastern).

    python fetch/fetch_portfolio.py                  # fetch and encrypt locally
    python fetch/fetch_portfolio.py --publish        # fetch, encrypt, commit, push
    python fetch/fetch_portfolio.py --reencrypt      # no E*TRADE login: re-encrypt
                                                     # existing data, e.g. after
                                                     # changing SITE_PASSWORD

The script opens the E*TRADE authorisation page, asks for the verification
code shown after you log in, then writes:

    fetch/private/portfolio.json   plaintext snapshot   (git-ignored)
    fetch/private/history.json     plaintext history    (git-ignored)
    docs/data/vault.json           AES-256-GCM ciphertext of both (public)

Only vault.json is published. Without SITE_PASSWORD it is unreadable.
Consumer keys, access tokens and account numbers are never written to disk.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import secrets
import subprocess
import sys
import webbrowser
from datetime import datetime
from pathlib import Path
from urllib.parse import parse_qs, quote
from zoneinfo import ZoneInfo

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from dotenv import load_dotenv
from requests_oauthlib import OAuth1Session

ROOT = Path(__file__).resolve().parent.parent
PRIVATE_DIR = ROOT / "fetch" / "private"
PORTFOLIO_FILE = PRIVATE_DIR / "portfolio.json"
HISTORY_FILE = PRIVATE_DIR / "history.json"
SALT_FILE = PRIVATE_DIR / "salt.bin"
VAULT_FILE = ROOT / "docs" / "data" / "vault.json"

PBKDF2_ITERATIONS = 600_000

# OAuth endpoints are the same host for sandbox and production keys.
OAUTH_BASE = "https://api.etrade.com/oauth"
AUTHORIZE_URL = "https://us.etrade.com/e/t/etws/authorize?key={key}&token={token}"
API_BASE = {
    "sandbox": "https://apisb.etrade.com",
    "production": "https://api.etrade.com",
}
EASTERN = ZoneInfo("America/New_York")


# --------------------------------------------------------------------------
# Authorisation (OAuth 1.0a, out-of-band verifier)
# --------------------------------------------------------------------------

def _token_pair(resp) -> tuple[str, str]:
    if resp.status_code != 200:
        sys.exit(f"E*TRADE OAuth error {resp.status_code}: {resp.text[:300]}")
    fields = parse_qs(resp.text)
    return fields["oauth_token"][0], fields["oauth_token_secret"][0]


def authorise(key: str, secret: str) -> OAuth1Session:
    """Run the daily login and return a signed session for API calls."""
    session = OAuth1Session(key, client_secret=secret, callback_uri="oob")
    req_token, req_secret = _token_pair(session.get(f"{OAUTH_BASE}/request_token", timeout=30))

    url = AUTHORIZE_URL.format(key=quote(key, safe=""), token=quote(req_token, safe=""))
    print("\nLog in to E*TRADE and accept the request at:\n")
    print(f"  {url}\n")
    try:
        webbrowser.open(url)
    except Exception:
        pass
    verifier = input("Paste the verification code: ").strip()
    if not verifier:
        sys.exit("No verification code entered.")

    session = OAuth1Session(
        key,
        client_secret=secret,
        resource_owner_key=req_token,
        resource_owner_secret=req_secret,
        verifier=verifier,
    )
    acc_token, acc_secret = _token_pair(session.get(f"{OAUTH_BASE}/access_token", timeout=30))
    return OAuth1Session(
        key,
        client_secret=secret,
        resource_owner_key=acc_token,
        resource_owner_secret=acc_secret,
    )


# --------------------------------------------------------------------------
# API calls
# --------------------------------------------------------------------------

def get_json(session: OAuth1Session, url: str, **params) -> dict:
    resp = session.get(url, params=params, headers={"Accept": "application/json"}, timeout=30)
    if resp.status_code == 204:  # e.g. an account with no positions
        return {}
    if resp.status_code != 200:
        sys.exit(f"E*TRADE API error {resp.status_code} on {url}: {resp.text[:300]}")
    return resp.json()


def as_list(value) -> list:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def mask(account_id: str) -> str:
    return f"••••{str(account_id)[-4:]}"


def choose_account(session: OAuth1Session, base: str) -> dict:
    data = get_json(session, f"{base}/v1/accounts/list.json")
    accounts = as_list(
        data.get("AccountListResponse", {}).get("Accounts", {}).get("Account")
    )
    accounts = [a for a in accounts if a.get("accountStatus", "ACTIVE") != "CLOSED"]
    if not accounts:
        sys.exit("No open accounts were returned for these credentials.")

    wanted = os.getenv("ETRADE_ACCOUNT_ID", "").strip()
    if wanted:
        for acct in accounts:
            if str(acct.get("accountId", "")).endswith(wanted):
                return acct
        sys.exit(f"No account ending in {wanted} was found.")

    if len(accounts) == 1:
        return accounts[0]

    print("\nAccounts:")
    for i, acct in enumerate(accounts, 1):
        label = acct.get("accountDesc") or acct.get("accountName") or acct.get("accountType", "")
        print(f"  {i}. {mask(acct.get('accountId', ''))}  {label}")
    choice = input("Which account holds the portfolio? ").strip()
    try:
        return accounts[int(choice) - 1]
    except (ValueError, IndexError):
        sys.exit("Invalid choice. Set ETRADE_ACCOUNT_ID in .env to skip this prompt.")


def fetch_positions(session: OAuth1Session, base: str, account_key: str) -> list[dict]:
    positions: list[dict] = []
    page = 1
    while True:
        data = get_json(
            session,
            f"{base}/v1/accounts/{account_key}/portfolio.json",
            view="COMPLETE",
            count=100,
            pageNumber=page,
        )
        portfolios = as_list(data.get("PortfolioResponse", {}).get("AccountPortfolio"))
        for portfolio in portfolios:
            positions.extend(as_list(portfolio.get("Position")))
        total_pages = int(portfolios[0].get("totalPages", 1)) if portfolios else 1
        if page >= total_pages:
            return positions
        page += 1


def fetch_account_value(session: OAuth1Session, base: str, account_key: str) -> float | None:
    data = get_json(
        session,
        f"{base}/v1/accounts/{account_key}/balance.json",
        instType="BROKERAGE",
        realTimeNAV="true",
    )
    computed = data.get("BalanceResponse", {}).get("Computed", {})
    return num(computed.get("RealTimeValues", {}).get("totalAccountValue"), None)


# --------------------------------------------------------------------------
# Snapshot construction
# --------------------------------------------------------------------------

def num(value, default: float | None = 0.0):
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def normalise(position: dict) -> dict:
    product = position.get("Product", {}) or {}
    quote_data = position.get("Complete") or position.get("Quick") or {}
    security_type = product.get("securityType", "EQ")
    quantity = num(position.get("quantity"))
    market_value = num(position.get("marketValue"))
    cost_basis = num(position.get("totalCost"))
    gain = num(position.get("totalGain"), market_value - cost_basis)
    price = num(quote_data.get("lastTrade"), None)
    if price is None and quantity:
        price = market_value / quantity

    symbol = product.get("symbol") or position.get("symbolDescription", "")
    label = position.get("symbolDescription", symbol) if security_type == "OPTN" else symbol

    return {
        "symbol": label,
        "type": security_type,
        "side": position.get("positionType", "LONG"),
        "quantity": quantity,
        "price": round(price or 0.0, 4),
        "dayChange": round(num(position.get("daysGain")), 2),
        "dayChangePct": round(num(position.get("daysGainPct")), 4),
        "marketValue": round(market_value, 2),
        "costBasis": round(cost_basis, 2),
        "gain": round(gain, 2),
        "gainPct": round(num(position.get("totalGainPct"), (gain / cost_basis * 100) if cost_basis else 0.0), 4),
    }


def build_snapshot(raw_positions: list[dict], account_value: float | None, env: str) -> dict:
    positions = [normalise(p) for p in raw_positions]
    invested = sum(p["marketValue"] for p in positions)
    total = account_value if account_value else invested
    cash = total - invested
    cost = sum(p["costBasis"] for p in positions)
    day_change = sum(p["dayChange"] for p in positions)
    gain = sum(p["gain"] for p in positions)
    opening = total - day_change

    for p in positions:
        p["weight"] = round(p["marketValue"] / total * 100, 4) if total else 0.0
    positions.sort(key=lambda p: p["marketValue"], reverse=True)

    return {
        "name": os.getenv("PORTFOLIO_NAME", "Managed Portfolio"),
        "asOf": datetime.now(EASTERN).isoformat(timespec="seconds"),
        "environment": env,
        "currency": "USD",
        "sample": False,
        "totals": {
            "totalValue": round(total, 2),
            "invested": round(invested, 2),
            "cash": round(cash, 2),
            "cashPct": round(cash / total * 100, 4) if total else 0.0,
            "dayChange": round(day_change, 2),
            "dayChangePct": round(day_change / opening * 100, 4) if opening else 0.0,
            "costBasis": round(cost, 2),
            "unrealisedGain": round(gain, 2),
            "unrealisedGainPct": round(gain / cost * 100, 4) if cost else 0.0,
            "positions": len(positions),
        },
        "positions": positions,
    }


def update_history(snapshot: dict) -> dict:
    history = {"sample": False, "points": []}
    if HISTORY_FILE.exists():
        existing = json.loads(HISTORY_FILE.read_text())
        if not existing.get("sample"):
            history = existing

    today = snapshot["asOf"][:10]
    points = [p for p in history.get("points", []) if p["date"] != today]
    points.append({"date": today, "value": snapshot["totals"]["totalValue"]})
    points.sort(key=lambda p: p["date"])
    return {"sample": False, "points": points}


# --------------------------------------------------------------------------
# Encryption (matches the Web Crypto code in docs/index.html)
# --------------------------------------------------------------------------

def b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def load_salt() -> bytes:
    """A stable per-site salt, so 'keep me signed in' survives daily updates."""
    if SALT_FILE.exists():
        return SALT_FILE.read_bytes()
    salt = secrets.token_bytes(16)
    SALT_FILE.write_bytes(salt)
    return salt


def encrypt_vault(payload: dict, password: str, salt: bytes) -> dict:
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=PBKDF2_ITERATIONS)
    key = kdf.derive(password.encode("utf-8"))
    iv = secrets.token_bytes(12)
    plaintext = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    ciphertext = AESGCM(key).encrypt(iv, plaintext, None)  # ciphertext || 16-byte tag
    return {
        "v": 1,
        "kdf": "PBKDF2-SHA256",
        "iterations": PBKDF2_ITERATIONS,
        "salt": b64(salt),
        "iv": b64(iv),
        "ciphertext": b64(ciphertext),
    }


def site_password() -> str:
    password = os.getenv("SITE_PASSWORD", "")
    if len(password) < 12:
        sys.exit("Set SITE_PASSWORD in fetch/.env (at least 12 characters; longer is safer).")
    return password


def write_vault(snapshot: dict, history: dict, password: str) -> None:
    vault = encrypt_vault({"portfolio": snapshot, "history": history}, password, load_salt())
    VAULT_FILE.parent.mkdir(parents=True, exist_ok=True)
    VAULT_FILE.write_text(json.dumps(vault))


def publish(message: str) -> None:
    git = ["git", "-C", str(ROOT)]
    subprocess.run(git + ["add", "docs/data/vault.json"], check=True)
    if subprocess.run(git + ["diff", "--cached", "--quiet"]).returncode == 0:
        print("No changes to publish.")
        return
    subprocess.run(git + ["commit", "-m", message], check=True)
    subprocess.run(git + ["push"], check=True)
    print("Pushed. GitHub Pages usually updates within a minute or two.")


# --------------------------------------------------------------------------

def main() -> None:
    load_dotenv(Path(__file__).resolve().parent / ".env")
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--publish", action="store_true", help="commit and push the encrypted vault")
    parser.add_argument("--reencrypt", action="store_true", help="re-encrypt existing data without fetching")
    parser.add_argument("--env", choices=["sandbox", "production"], help="override ETRADE_ENV")
    args = parser.parse_args()

    password = site_password()
    PRIVATE_DIR.mkdir(parents=True, exist_ok=True)

    if args.reencrypt:
        if not PORTFOLIO_FILE.exists():
            sys.exit("No saved snapshot yet. Run once without --reencrypt first.")
        snapshot = json.loads(PORTFOLIO_FILE.read_text())
        history = json.loads(HISTORY_FILE.read_text()) if HISTORY_FILE.exists() else {"sample": False, "points": []}
        write_vault(snapshot, history, password)
        print("Re-encrypted docs/data/vault.json with the current SITE_PASSWORD.")
        if args.publish:
            publish("Re-encrypt portfolio data")
        return

    env = args.env or os.getenv("ETRADE_ENV", "sandbox")
    key = os.getenv("ETRADE_CONSUMER_KEY")
    secret = os.getenv("ETRADE_CONSUMER_SECRET")
    if not key or not secret:
        sys.exit("Set ETRADE_CONSUMER_KEY and ETRADE_CONSUMER_SECRET in fetch/.env")
    base = API_BASE[env]
    print(f"Environment: {env}")

    session = authorise(key, secret)
    account = choose_account(session, base)
    account_key = account["accountIdKey"]
    print(f"Account: {mask(account.get('accountId', ''))}")

    snapshot = build_snapshot(
        fetch_positions(session, base, account_key),
        fetch_account_value(session, base, account_key),
        env,
    )
    history = update_history(snapshot)

    PORTFOLIO_FILE.write_text(json.dumps(snapshot, indent=2))
    HISTORY_FILE.write_text(json.dumps(history, indent=2))
    write_vault(snapshot, history, password)

    t = snapshot["totals"]
    print(f"\nWrote {t['positions']} positions, total value ${t['totalValue']:,.2f} "
          f"(day {t['dayChange']:+,.2f}). Encrypted to docs/data/vault.json.")

    if args.publish:
        publish(f"Portfolio snapshot {snapshot['asOf'][:10]}")


if __name__ == "__main__":
    main()
