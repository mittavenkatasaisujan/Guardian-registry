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

## 2. Push notifications (free Firebase account)

1. Create a Firebase project at console.firebase.google.com and add an Android app with package
   name `in.guardianregistry.app`.
2. From *Project settings*, note the project id, app id, web API key and sender id; build with
   `gradle -p android :app:assembleDebug -PgrFcmProjectId=... -PgrFcmAppId=... -PgrFcmApiKey=...
   -PgrFcmSenderId=...` (or ask for these to be wired into the CI build as repository secrets).
3. For the server: *Project settings -> Service accounts -> Generate new private key*, then set
   `GR_PUSH_PROVIDER=direct` and `GR_FCM_SERVICE_ACCOUNT_FILE=/path/to/key.json`. Keep that file
   out of the repository.

## 3. Real SMS codes to your own phone (Twilio free trial)

1. Sign up for a Twilio trial and verify your own mobile number in the console.
2. Set `GR_SMS_PROVIDER=twilio`, `GR_TWILIO_ACCOUNT_SID`, `GR_TWILIO_AUTH_TOKEN_FILE` (a file with
   the token) and `GR_TWILIO_FROM` (the trial number). Trial accounts only send to numbers you
   verified, and add a "Sent from a Twilio trial account" prefix.
3. Run without `GR_OTP_DEV_ECHO`: the code now arrives by SMS.

Real users need a paid account and, in India, DLT registration of the sender and templates.

## 4. A public staging server (free cloud VM)

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

## 5. Free security scanning

* **CodeQL** runs on every push once the repository is public (`.github/workflows/codeql.yml`);
  results appear under *Security -> Code scanning*.
* **OWASP ZAP** scans the running deployment in CI (the `deploy` job); its report is kept as the
  `zap-report` artifact.
* **pip-audit** and **bandit** run in the `security` job.

None of these replaces an independent penetration test before launch.
