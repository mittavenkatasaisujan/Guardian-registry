# Translation review (25 November 2026)

Reviewed by the model that wrote the translations, so **this is not a native-speaker review**.
It checks consistency, completeness and the meaning of safety-critical messages, and it fixes
what it finds; a native speaker for each language must still sign off before that language is
switched on (Hindi is on; Tamil, Telugu, Bengali and Marathi are drafts, off).

## Checked across all 426 Hindi strings (server, web, Android, iOS)

- **One term per concept:** guardian = गार्डियन (53 uses), payee = प्राप्तकर्ता, approve = मंज़ूर,
  sign in = साइन इन, restricted = सीमित, device = डिवाइस. No mixed synonyms.
- **No leftover English** apart from deliberate terms (UPI, SIM, OTP, KYC, RBI, Guardian Registry).
- **Every placeholder kept** ({name}, %1$s, %@) in every string; the test suite enforces this for all
  five languages.

## Fixed

| Text | Before | After | Why |
|---|---|---|---|
| "Only approve if you have spoken to them yourself, on a call YOU placed or in person" (web, Android, iOS, recovery alert) | अपनी की हुई कॉल पर | ऐसी कॉल पर जो आपने ख़ुद की हो | The English stresses that **you** made the call, because scammers are the ones who call. The old Hindi could be read as "on your own call". The four drafts already carry the emphasis. |
| Ready-made rule set names | Always English | Translated by the server (`GET /v1/presets` with the app's language) in Hindi and the drafts | Hindi readers saw English names in the rules picker. |

New texts from today's changes (RBI rules, security, privacy) were translated into Hindi and the
four drafts.

## For each native reviewer

1. Read the safety messages first: sign-in code SMS, "never share", "call them on a number you know",
   recovery vouching, SIM change, lost phone, "pause everything if someone is pressuring you".
   They must be unmistakable to an older reader.
2. Check register: respectful forms (आप, நீங்கள், మీరు, আপনি, तुम्ही/आपण) throughout.
3. Check numbers and dates as shown in each app (₹ grouping 1,00,000; dates in the phone's locale).
4. Hindi and regional SMS also need DLT templates registered in that language.
5. Switch a draft on by setting `"enabled": true` in `guardian_registry/i18n/languages.json` and
   running `python scripts/i18n.py generate`.
