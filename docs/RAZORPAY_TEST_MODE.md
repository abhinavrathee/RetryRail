# Razorpay Test Mode access and safe execution

RetryRail uses only Razorpay Test Mode for M5. Test Mode does not move real
money, but its API key is still a credential and must be handled as a secret.

## Getting the keys

An account Owner or Administrator can open the Razorpay Dashboard, switch the
mode toggle to **Test**, then open **Account & Settings → API Keys** and generate
a key. The downloaded CSV contains two rows: the Test key ID and the key secret.
The key ID must begin with `rzp_test_`. Razorpay shows the secret only when the
key is generated, so keep the downloaded file outside the repository.

Official references:

- [Razorpay API key setup](https://razorpay.com/docs/payments/dashboard/account-settings/api-keys/)
- [Test and Live modes](https://razorpay.com/docs/payments/dashboard/test-live-modes/)
- [Create a Standard Payment Link](https://razorpay.com/docs/api/payments/payment-links/create-standard/)
- [Fetch Payment Links by reference](https://razorpay.com/docs/api/payments/payment-links/fetch-all-standard/)

## RetryRail handling rules

- Do not paste key values into source files, `.env.example`, Compose, test data,
  screenshots, issues or chat messages.
- Do not rename a key to a `VITE_` variable; browser bundles must never receive
  provider credentials.
- Load the two CSV values only into the API process that performs the approved
  action. RetryRail masks them in configuration representations.
- Never commit a local `.env`; repository ignore and security scans enforce
  this, but the operator remains responsible for keeping the downloaded CSV
  private.
- Rotate the key immediately in the Razorpay Dashboard if its value is exposed.

## What the M5 action does

The approved action creates one Standard Payment Link for a synthetic failed
payment. It sends an integer Test Mode amount, currency, expiry and stable
reference. It does not send a customer object, SMS, email or reminder. RetryRail
stores only a sanitized receipt.

A timeout never triggers another create. RetryRail first looks up the stable
reference and records either the existing link or confirmed absence. Replaying
the execute request also returns the original durable action without a second
POST.

The API key does not replace merchant approval. The final Test Mode POST remains
behind RetryRail's external approval token and should be performed only once.

## One-link reviewer evidence workflow

This workflow intentionally separates preparation from authority. `prepare`
builds a fresh synthetic incident, rules-only analysis and eligible plan in a
disposable SQLite database outside the repository. It prints the exact amount,
reference, expiry and notification state, but creates no approval, dispatch or
provider call.

On Windows PowerShell, choose a fresh path and run:

```powershell
uv run retryrail-m5-demo prepare --database-path "$env:TEMP\retryrail-m5-review.sqlite3"
```

Review the printed fields. Then run `execute` with that same database and the
downloaded Razorpay CSV:

```powershell
uv run retryrail-m5-demo execute --database-path "$env:TEMP\retryrail-m5-review.sqlite3" --credential-csv "C:\path\outside\the\repo\razorpay_test_api_keys.csv"
```

The command requires an interactive terminal and prints a plan-specific phrase.
A human merchant operator must type that phrase exactly. It cannot be piped or
approximated, and the model cannot perform the approving terminal keystroke.
Only after the match does RetryRail issue and atomically consume its short-lived
approval credential, persist the provider dispatch, and make the one POST.

On verified success, the command writes the sanitized, schema-validated audit
artifact to `evals/reports/razorpay_test_mode_receipt.v1.json`. The artifact has
no API key, authorization header, customer data or raw provider response.

If the process stops after dispatch or reports an ambiguous provider outcome,
run lookup-only recovery with the same files:

```powershell
uv run retryrail-m5-demo reconcile --database-path "$env:TEMP\retryrail-m5-review.sqlite3" --credential-csv "C:\path\outside\the\repo\razorpay_test_api_keys.csv"
```

`reconcile` issues a GET by the already-durable reference. It never issues a
replacement POST. Do not delete the disposable database until the sanitized
evidence is committed and verified.

## Completed M5 evidence

On September 5, 2026, the human-approved command created one synthetic INR
1,499.00 Test Mode link. Razorpay returned HTTP 200 to the sole POST. Its
second-resolution creation timestamp was about 2.5 seconds ahead of the local
host, so the strict initial result validator stopped before storing a receipt.
The already-committed dispatch remained in `executing`; RetryRail did not retry
the POST. The dedicated command performed one GET by reference, found the same
provider entity and appended a complete `reference_lookup` receipt and terminal
`succeeded` transition.

The committed evidence is
`evals/reports/razorpay_test_mode_receipt.v1.json`. It is explicitly synthetic,
Test Mode-only and no-real-money; it records notifications off, complete audit,
`credentials_persisted=false` and `raw_provider_response_persisted=false`.
Regression coverage now admits at most five minutes of positive provider-clock
skew by preserving provider creation time and normalizing verification ordering;
larger skew remains a typed failure and a create response remains lookup-only
ambiguous.
