# Testing for free

Everything here costs nothing. Free tiers and their terms change: check them when you sign up.

## 1. On your own Android phone, against your PC (no account needed)

1. Download the debug APK: on the CI mirror's latest successful **CI** run, open *Artifacts* and
   download `guardian-registry-debug-apk`. Unzip it and copy `app-debug.apk` to the phone.
2. On the phone, allow installing apps from your file manager, then open the APK.
3. On the PC (same Wi-Fi as the phone):

   ```
   python scripts/dev_server.py 8010 --lan
   ```

   It prints the address to use, like `http://172.17.48.46:8010`. Allow Python through the
   Windows firewall when asked (private networks only). Office or campus Wi-Fi often blocks
   devices from reaching each other; a phone hotspot with the PC connected to it works.
4. In the app, type that address into **Server address (testing)**, enter your mobile number and
   tap *Send code*. In development mode the code is filled in for you.

What this proves on a real phone: the device key is created in the phone's secure hardware
(StrongBox or TEE), sign-in signs the server's challenge with it, a second sign-in is a proven
device, and the Keystore attestation chain is real. `scripts/check_attestation.py` can check the
chain the phone produced.

## 2. Real SMS codes and push notifications (free Twilio trial + free Firebase)

Both work on free plans; set up once, then run the test server in real mode.

1. **Firebase:** create a project (Analytics not needed) and add an Android app with package name
   `in.guardianregistry.app`. CI builds the APK with push when the repository has the secrets
   `GR_FCM_PROJECT_ID`, `GR_FCM_APP_ID`, `GR_FCM_API_KEY` and `GR_FCM_SENDER_ID` (from *Project
   settings*; the API key is the auto-created "Android key" in Google Cloud *Credentials*). For the
   server: *Project settings -> Service accounts -> Generate new private key*, saved as
   `local-secrets/firebase-service-account.json`.
2. **Twilio:** sign up for the free *Limited trial* (no card) and verify your own mobile number.
   A trial only sends Twilio's own wording, so sign-in codes go through **Twilio Verify** (Twilio
   makes, sends and checks the code; the registry keeps its own limits). Create a Verify service
   (console, or `POST https://verify.twilio.com/v2/Services`) and save its `VA...` id as
   `local-secrets/twilio_verify_service`; save your Auth Token as `local-secrets/twilio_auth_token`.
   Alert SMS can't be sent on a trial: alerts arrive in the app and by push.
3. `local-secrets/real.env` (the folder is git-ignored):

   ```
   GR_SMS_PROVIDER=twilio_verify
   GR_TWILIO_ACCOUNT_SID=AC...
   GR_TWILIO_AUTH_TOKEN_FILE=local-secrets/twilio_auth_token
   GR_TWILIO_VERIFY_SERVICE_FILE=local-secrets/twilio_verify_service
   GR_PUSH_PROVIDER=direct
   GR_FCM_SERVICE_ACCOUNT_FILE=local-secrets/firebase-service-account.json
   ```

4. `python scripts/dev_server.py 8010 --lan --real`: codes now arrive by SMS (not on screen), and
   urgent alerts as push notifications.

Real users need a paid account and, in India, DLT registration of the sender and templates;
with that, `GR_SMS_PROVIDER=twilio` or `msg91` sends our own wording, alerts included.

## 3. A public staging server (free cloud VM)

1. Create an Ubuntu VM on a free tier: Oracle Cloud "Always Free" (an Ampere A1 VM with several
   GB of RAM is the comfortable choice) or Google Cloud's free-tier e2-micro.
2. Copy the repository onto it and run:

   ```
   sudo bash deploy/bootstrap.sh --tunnel
   ```

   It installs Docker, creates secrets and trial certificates, starts Postgres, two API nodes,
   nginx and backups, and prints a free `https://<random>.trycloudflare.com` address for the
   people's app and the operator console.
3. Point the phone's **Server address (testing)** at that address to test away from your Wi-Fi.

## 4. Free security scanning

* **CodeQL** runs on every push once the repository is public (`.github/workflows/codeql.yml`);
  results appear under *Security -> Code scanning*.
* **OWASP ZAP** scans the running deployment in CI (the `deploy` job); its report is kept as the
  `zap-report` artifact.
* **pip-audit** and **bandit** run in the `security` job.

None of these replaces an independent penetration test before launch.
