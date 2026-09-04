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
