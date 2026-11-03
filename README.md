# Portfolio Holdings Site

A password-protected website showing the holdings and performance of a portfolio held at E*TRADE. It is hosted publicly on GitHub Pages, but the portfolio data is encrypted, so only people with the members' password can read it.

```
portfolio-site/
├── fetch/                    PRIVATE – runs on your machine only
│   ├── fetch_portfolio.py    daily E*TRADE login, pulls positions, encrypts, publishes
│   ├── requirements.txt
│   ├── .env.example          copy to .env and add keys + site password (git-ignored)
│   └── private/              plaintext snapshot and history (git-ignored, created on first run)
└── docs/                     PUBLIC – served by GitHub Pages
    ├── index.html            login screen and portfolio view
    └── data/vault.json       encrypted portfolio + history (sample until first run)
```

## How it works

E*TRADE access tokens expire at midnight US Eastern and go inactive after two hours without use, so the site cannot hold a live connection. Once per trading day you run `fetch_portfolio.py`, log in to E*TRADE in your browser and paste the verification code. The script pulls the account's positions and balance, keeps a plaintext copy in `fetch/private/`, and writes `docs/data/vault.json`: the snapshot and value history encrypted with AES-256-GCM, using a key derived from `SITE_PASSWORD` (PBKDF2-SHA256, 600,000 iterations). It then pushes the vault to GitHub.

Visitors see a login screen. The password is checked in their browser by decrypting the vault; nothing readable is ever served, so the public repository and site expose only ciphertext. Your E*TRADE keys, tokens and account number never leave your machine.

## 1. Get E*TRADE API keys

1. You need an E*TRADE brokerage account with access to the portfolio.
2. Go to the E*TRADE Developer Platform (developer.etrade.com) and follow **Getting Started**. You will be asked to complete the API user intent survey and the API agreement.
3. Request a **sandbox** key first. Sandbox returns canned test data and is ideal for checking the pipeline end to end.
4. Request a **production** key once sandbox works. Production approval can take some days.

## 2. Install the fetch script

```bash
cd portfolio-site
python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r fetch/requirements.txt
cp fetch/.env.example fetch/.env   # then fill in your keys and SITE_PASSWORD
```

Choose a long `SITE_PASSWORD`, such as four or five random words. Anyone holding the encrypted file can try passwords offline, so length is what protects the data.

## 3. Preview the site locally

```bash
python3 -m http.server 8000 --directory docs
# open http://localhost:8000
```

The bundled sample vault opens with the password `sample-password-change-me` and shows a banner saying it is sample data. Your first real run replaces it.

## 4. Test against sandbox

```bash
python fetch/fetch_portfolio.py
```

A browser window opens at the E*TRADE authorisation page. Log in, accept, and paste the code shown into the terminal. The script writes the plaintext copy to `fetch/private/` and a new `docs/data/vault.json` encrypted with your `SITE_PASSWORD`.

## 5. Publish with GitHub Pages

1. Create a new repository on GitHub. It can be public, because only ciphertext is committed.
2. Push this folder:
   ```bash
   git init && git add . && git commit -m "Initial site"
   git branch -M main
   git remote add origin https://github.com/<you>/<repo>.git
   git push -u origin main
   ```
3. In the repository: **Settings → Pages → Build and deployment → Deploy from a branch**, branch `main`, folder `/docs`.
4. The site goes live at `https://<you>.github.io/<repo>/`. A custom domain can be added on the same settings page.

Before the first push, run `git status` and confirm neither `fetch/.env` nor `fetch/private/` is listed.

## 6. Daily routine

After the US close (16:00 Eastern, which is 21:00 UK time for most of the year):

```bash
source .venv/bin/activate
python fetch/fetch_portfolio.py --publish
```

This logs in, writes and encrypts the snapshot, commits `docs/data/vault.json` and pushes. The live site updates within a couple of minutes. Switch `ETRADE_ENV=production` in `fetch/.env` once live keys are approved.

## Managing the password

- **Share it** with members privately, not in a public channel.
- **Change it** when someone leaves: edit `SITE_PASSWORD` in `fetch/.env`, then run
  ```bash
  python fetch/fetch_portfolio.py --reencrypt --publish
  ```
  This re-encrypts the existing data without an E*TRADE login. Members who ticked "Keep me signed in" are signed out automatically and must enter the new password.
- Older encrypted versions stay in the git history, readable with the old password. If that matters after removing a member, start a fresh repository or rewrite history.

## What members can see

Symbols, quantities, prices, market values, cost basis, gains, cash, total value and the daily value history. The value history is total account value, so deposits and withdrawals appear as moves in the chart. The page asks search engines not to index it.

## Customising

- `PORTFOLIO_NAME` in `fetch/.env` sets the name shown after login.
- Colours and fonts are CSS variables at the top of `docs/index.html`; dark mode follows the visitor's system setting.
