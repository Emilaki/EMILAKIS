# EA EarnHub pilot

## What this bundle does

- Keeps reward tasks and the member ledger sponsor-funded.
- Collects a Kenyan M-Pesa number with a withdrawal request.
- Lets an authenticated operator submit an individual B2C request to Safaricom **sandbox only**.
- Uses Daraja's result and timeout callbacks to settle the request; confirmed failures are refunded once.
- Stops duplicate submissions and marks uncertain network outcomes for reconciliation instead of retrying.
- Does not contain a live-money endpoint. This bundle is not ready for production payouts or public financial use.

The sandbox simulator does not transfer real money. Do not promise earnings; credits are payable only when supported by cleared funds and reviewed activity.

## Upload the bundle to GitHub

Extract `ea-earnhub-mpesa-sandbox-bundle.zip`. In the root of the connected GitHub repository, replace `app.py`, `index.html`, `requirements.txt`, and `README.md` with the files from the archive, then commit the changes. Do **not** upload a database file or any `.env` file. Render will build the new commit automatically if auto-deploy is enabled; otherwise choose **Manual Deploy → Deploy latest commit**.

## Render environment variables

Set these in the Render service Environment page. Keep all key/credential values private:

| Name | Value |
| --- | --- |
| `MPESA_ENV` | `sandbox` |
| `MPESA_B2C_ENABLED` | `true` only when ready to run simulator tests; otherwise `false` |
| `MPESA_PUBLIC_BASE_URL` | `https://ea-earnhubs.onrender.com` (or your own public HTTPS host) |
| `MPESA_CONSUMER_KEY` | Consumer key for the Daraja sandbox app |
| `MPESA_CONSUMER_SECRET` | Consumer secret for the Daraja sandbox app |
| `MPESA_B2C_SHORTCODE` | B2C sandbox shortcode from Daraja test credentials |
| `MPESA_INITIATOR_NAME` | Sandbox B2C initiator name |
| `MPESA_SECURITY_CREDENTIAL` | Encrypted sandbox initiator credential (not the plain password) |

The callback URLs are formed automatically from `MPESA_PUBLIC_BASE_URL`:

- `/api/mpesa/b2c/result`
- `/api/mpesa/b2c/timeout`

Use the sandbox app's B2C test credentials. Generate the encrypted SecurityCredential with Daraja's sandbox certificate and RSA PKCS #1 v1.5/Base64 method, or use Daraja's credential tool. The `174379` shortcode is for Lipa na M-Pesa Online, not B2C. This code accepts `MPESA_B2C_SECURITY_CREDENTIAL` as an alias for `MPESA_SECURITY_CREDENTIAL`. It does not read plaintext initiator passwords. Never put credentials in GitHub or paste them into chat.

After changing Render variables, save and redeploy. The operator console will report `SANDBOX ONLY` only when the required variables and public HTTPS base URL are present. The `MPESA_ENV` must remain `sandbox`; the API host is hard-coded to Safaricom sandbox.

## Sandbox flow

1. A member requests a withdrawal and enters their M-Pesa number. The amount is reserved from their balance and placed in the review queue.
2. An operator signs into the console with `EA_ADMIN_TOKEN`, reviews the request and explicitly selects **Send sandbox test**.
3. Daraja acknowledges the request asynchronously. A result callback records success or failure. Confirmed failure returns the reserved amount once.
4. A timeout or network ambiguity is marked `unknown`. Do not retry until you reconcile it in Daraja; this prevents duplicate submissions.

The sandbox test button is a simulation and cannot pay users. `paid` in this pilot means only that Daraja returned a successful sandbox result.

## Existing deployment and data

The app migrates the payouts table on startup to add the M-Pesa tracking fields. Keep a verified database backup before replacing code. Do not use Render's expiring free database for real member or balance records. This app is a starter pilot and still needs production-grade security review, rate limiting, account verification, support and appeals, finalized privacy/payout terms, and Safaricom's live B2C business onboarding before public payout use.

Never collect or store M-Pesa PINs or OTPs. Do not enable public access to the operator console. Configure a strong, unique `EA_ADMIN_TOKEN` and rotate any credential that has been exposed.
