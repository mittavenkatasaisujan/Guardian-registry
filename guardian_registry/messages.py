"""Server-written text in the person's language: alerts (in-app, SMS, WhatsApp, push), the
sign-in code SMS, and error messages shown to people.

The code composes English, as before. Just before an alert is queued for someone whose
language is Hindi, translate() matches it against TEMPLATES (English templates taken from
the source by textscan.py, with {0}, {1}... where the code inserts values), translates
the inserted values that are themselves English phrases (FRAGMENTS: reasons, change
descriptions, verbs), and fills the Hindi template. Names, amounts, payees, numbers and
times pass through unchanged. Anything that doesn't match stays English rather than being
guessed at.

tests/test_messages.py parses the source and fails if an alert or a person-facing error
has no Hindi here (or isn't listed in NOT_FOR_PEOPLE), so new text can't slip through.
"""

from __future__ import annotations

import json
import os
import re
from functools import lru_cache
from pathlib import Path


# --------------------------------------------------------------------------- alerts
ALERTS_HI = {
    "Open Guardian Registry to see the details.": "पूरी जानकारी के लिए Guardian Registry खोलें।",
    "A recovery to the number {0} was started. If this isn't you, cancel it here.":
        "नंबर {0} पर खाता वापसी शुरू की गई है। अगर यह आप नहीं हैं, तो इसे यहाँ रद्द करें।",
    "Account deletion requested": "खाता हटाने का अनुरोध",
    "Your complaint was answered": "आपकी शिकायत का जवाब आ गया",
    "Our grievance officer has answered your complaint. Open the app to read the answer.":
        "हमारे शिकायत अधिकारी ने आपकी शिकायत का जवाब दिया है। जवाब पढ़ने के लिए ऐप खोलें।",
    "Account recovered": "खाता वापस मिल गया",
    "Account recovery request": "खाता वापसी का अनुरोध",
    "Account recovery stopped": "खाता वापसी रोकी गई",
    "Account recovery will complete": "खाता वापसी पूरी होने वाली है",
    "Approve payment?": "भुगतान मंज़ूर करें?",
    "Bank verification ended": "बैंक सत्यापन समाप्त",
    "Bank verification expired": "बैंक सत्यापन की अवधि समाप्त",
    "Bank verification removed": "बैंक सत्यापन हटाया गया",
    "Banks disagree on your date of birth": "बैंकों में आपकी जन्मतिथि को लेकर मतभेद है",
    "Change on hold": "बदलाव रोका गया",
    "Change stopped": "बदलाव रोक दिया गया",
    "Confirm your identity?": "अपनी पहचान की पुष्टि करें?",
    "For your safety this takes effect in {0} hours. Your guardians have been told.":
        "आपकी सुरक्षा के लिए यह {0} घंटे बाद लागू होगा। आपके गार्डियन को बता दिया गया है।",
    "Guardian request": "गार्डियन अनुरोध",
    "Guardian accepted": "गार्डियन ने स्वीकार किया",
    "Guardian declined": "गार्डियन ने अस्वीकार किया",
    "Guardian stepped down": "गार्डियन ने भूमिका छोड़ दी",
    "New device signed in": "नए डिवाइस पर साइन इन",
    "No guardian approved {0} to {1}, so it was not sent.": "किसी गार्डियन ने {1} को {0} मंज़ूर नहीं किया, इसलिए यह नहीं भेजा गया।",
    "Number disconnected": "नंबर बंद हो गया",
    "Payment blocked": "भुगतान रोका गया",
    "Payment can go ahead": "भुगतान हो सकता है",
    "Payment not approved in time": "भुगतान समय पर मंज़ूर नहीं हुआ",
    "Payment on hold": "भुगतान रुका हुआ है",
    "Payment {0}": "भुगतान {0}",
    "Payments paused": "भुगतान रोके गए",
    "Payments resumed": "भुगतान फिर से चालू",
    "Protection change applied": "सुरक्षा बदलाव लागू हुआ",
    "Protection change requested": "सुरक्षा बदलाव का अनुरोध",
    "Protection ending": "सुरक्षा समाप्त हो रही है",
    "SIM change alert": "सिम बदलने की चेतावनी",
    "SIM change confirmed": "सिम बदलने की पुष्टि",
    "SIM change detected": "सिम बदला गया",
    "Someone is recovering your account": "कोई आपका खाता वापस पाने की कोशिश कर रहा है",
    "Someone is trying to recover {0}'s account on a new number {1}. Only approve if you have spoken to {2} "
    "yourself, on a call YOU placed or in person. If in doubt, deny.":
        "कोई {0} का खाता नए नंबर {1} पर वापस पाने की कोशिश कर रहा है। तभी मंज़ूर करें जब आपने खुद {2} से बात की हो, "
        "ऐसी कॉल पर जो आपने ख़ुद की हो, या आमने-सामने। शक हो तो अस्वीकार करें।",
    "The requested change ({0}) for {1} is now in effect.": "{1} के लिए माँगा गया बदलाव ({0}) अब लागू है।",
    "The waiting period for {0} to {1} is over.": "{1} को {0} के भुगतान की प्रतीक्षा अवधि पूरी हो गई है।",
    "Two banks reported different dates of birth, so we can't confirm your age. Ask one of them to correct their record.":
        "दो बैंकों ने अलग-अलग जन्मतिथि बताई है, इसलिए हम आपकी उम्र की पुष्टि नहीं कर सकते। उनमें से किसी एक से अपना रिकॉर्ड ठीक करवाएँ।",
    "Waiting for your guardian": "आपके गार्डियन की प्रतीक्षा",
    "We were told your SIM card changed. If you did this, confirm it from your old phone or ask a guardian to "
    "confirm. If you didn't, contact your mobile operator now.":
        "हमें बताया गया है कि आपका सिम कार्ड बदला गया है। अगर यह आपने किया है, तो अपने पुराने फ़ोन से पुष्टि करें या किसी "
        "गार्डियन से पुष्टि करवाएँ। अगर नहीं, तो अभी अपने मोबाइल ऑपरेटर से संपर्क करें।",
    "You are being removed as guardian": "आपको गार्डियन पद से हटाया जा रहा है",
    "Your Guardian Registry account will be deleted on {0}, and your guardians will stop protecting your payments. "
    "If you didn't ask for this, or someone told you to, cancel it in the app.":
        "आपका Guardian Registry खाता {0} को हटा दिया जाएगा, और आपके गार्डियन आपके भुगतानों की सुरक्षा बंद कर देंगे। अगर "
        "आपने यह नहीं माँगा, या किसी ने आपसे ऐसा करने को कहा, तो ऐप में इसे रद्द करें।",
    "Your account is being recovered": "आपका खाता वापस पाया जा रहा है",
    "Your account moves to {0} at {1}. If this isn't you, cancel it now.":
        "आपका खाता {1} पर {0} पर चला जाएगा। अगर यह आप नहीं हैं, तो अभी रद्द करें।",
    "Your account now uses {0}. Sign in with it to continue.": "आपका खाता अब {0} इस्तेमाल करता है। आगे बढ़ने के लिए इससे साइन इन करें।",
    "Your account was signed in on a new device. For 24 hours that device can't approve payments or loosen "
    "protection. If this wasn't you, report a lost phone.":
        "आपके खाते में एक नए डिवाइस से साइन इन हुआ है। 24 घंटे तक वह डिवाइस भुगतान मंज़ूर या सुरक्षा ढीली नहीं कर सकता। "
        "अगर यह आप नहीं थे, तो फ़ोन खोने की सूचना दें।",
    "Your bank's identity confirmation is more than a year old. Ask your bank to confirm it again.":
        "आपके बैंक की पहचान पुष्टि एक साल से ज़्यादा पुरानी है। अपने बैंक से फिर से पुष्टि करवाएँ।",
    "Your guardian's SIM changed": "आपके गार्डियन का सिम बदला",
    "Your guardian's number changed": "आपके गार्डियन का नंबर बदला",
    "Your mobile operator says {0} was disconnected. It is no longer linked to your account, so sign-in codes "
    "can't reach you. From this app, add your new number under Change number. No phone signed in? Recover your "
    "account from your new number.":
        "आपके मोबाइल ऑपरेटर के अनुसार {0} बंद कर दिया गया है। यह अब आपके खाते से जुड़ा नहीं है, इसलिए साइन-इन कोड आप तक नहीं "
        "पहुँचेंगे। इस ऐप में 'नंबर बदलें' से अपना नया नंबर जोड़ें। कोई फ़ोन साइन इन नहीं है? अपने नए नंबर से खाता वापस पाएँ।",
    "Your number changed, so your bank needs to confirm your identity again.":
        "आपका नंबर बदल गया है, इसलिए आपके बैंक को आपकी पहचान फिर से पुष्टि करनी होगी।",
    "Your number was disconnected": "आपका नंबर बंद कर दिया गया",
    "{0} asked to delete their account on {1}. If someone may be pressuring them, call them now.":
        "{0} ने {1} को अपना खाता हटाने को कहा है। अगर कोई उन पर दबाव डाल रहा हो सकता है, तो अभी उन्हें कॉल करें।",
    "{0} asked to remove you as guardian. It takes effect in {1} hours. If this sounds like pressure from someone "
    "else, call them.":
        "{0} ने आपको गार्डियन पद से हटाने को कहा है। यह {1} घंटे बाद लागू होगा। अगर लगे कि कोई और दबाव डाल रहा है, तो उन्हें कॉल करें।",
    "{0} asked to {1}. It takes effect in {2} hours unless you veto it. If they are on a call with a stranger, veto.":
        "{0} ने यह माँगा है: {1}। यह {2} घंटे बाद लागू होगा, जब तक आप इसे न रोकें। अगर वे किसी अजनबी से कॉल पर हैं, तो रोक दें।",
    "{0} asked you to be their payment guardian. Accept or decline in the app.":
        "{0} ने आपसे उनका भुगतान गार्डियन बनने को कहा है। ऐप में स्वीकार या अस्वीकार करें।",
    "{0} confirmed the SIM change for {1}. Normal protection applies again.":
        "{0} ने {1} के सिम बदलने की पुष्टि की। सामान्य सुरक्षा फिर से लागू है।",
    "{0} has left Guardian Registry, so its confirmation of your identity no longer counts.":
        "{0} Guardian Registry से अलग हो गया है, इसलिए उसकी पहचान पुष्टि अब मान्य नहीं है।",
    "{0} is no longer your guardian.": "{0} अब आपके गार्डियन नहीं हैं।",
    "{0} is paying {1} to {2}. It goes through in {3} min unless you or they cancel it. Reason: {4}.":
        "{0} {2} को {1} भेज रहे हैं। यह {3} मिनट में हो जाएगा, जब तक आप या वे इसे रद्द न करें। कारण: {4}।",
    "{0} paused all outgoing payments for {1}.": "{0} ने {1} के सभी भुगतान रोक दिए।",
    "{0} stopped your requested change. Your protection stays as it was.":
        "{0} ने आपका माँगा गया बदलाव रोक दिया। आपकी सुरक्षा पहले जैसी बनी रहेगी।",
    "{0} switched payments back on for {1}.": "{0} ने {1} के भुगतान फिर से चालू किए।",
    "{0} to {1} needs a guardian's approval. They have been alerted.":
        "{1} को {0} के लिए गार्डियन की मंज़ूरी चाहिए। उन्हें सूचना भेज दी गई है।",
    "{0} to {1} was blocked: {2}.": "{1} को {0} का भुगतान रोका गया: {2}।",
    "{0} to {1} will go through in {2} min. You can cancel it until then.":
        "{1} को {0} का भुगतान {2} मिनट में हो जाएगा। तब तक आप इसे रद्द कर सकते हैं।",
    "{0} wants to confirm to Guardian Registry that you are their KYC-verified customer{1}. Approve only if you bank with them.":
        "{0} Guardian Registry को पुष्टि करना चाहता है कि आप उसके KYC-सत्यापित ग्राहक हैं{1}। तभी मंज़ूर करें जब आपका उनके पास खाता हो।",
    "{0} wants to pay {1} to {2}. Approve or deny within {3} min. Reason held: {4}.":
        "{0} {2} को {1} भेजना चाहते हैं। {3} मिनट के अंदर मंज़ूर या अस्वीकार करें। रोकने का कारण: {4}।",
    "{0} withdrew its identity confirmation.": "{0} ने अपनी पहचान पुष्टि वापस ले ली।",
    "{0} {1} {2} to {3}.": "{0} ने {3} को {2} का भुगतान {1}।",
    "{0} {1}.": "{0} {1}।",
    "{0} {1}. For {2} h, new sign-ins can't approve or loosen anything and larger payments are held. Call {3} on "
    "another number. If it wasn't them, switch on the kill switch.":
        "{0} {1}। {2} घंटे तक नए साइन-इन कुछ भी मंज़ूर या ढीला नहीं कर सकते और बड़े भुगतान रोके जाएँगे। {3} को किसी दूसरे "
        "नंबर पर कॉल करें। अगर यह उन्होंने नहीं किया, तो सभी भुगतान रोकें।",
    "{0}'s SIM card changed. Approvals from their new sign-ins are paused for {1} h.":
        "{0} का सिम कार्ड बदला है। उनके नए साइन-इन से मंज़ूरियाँ {1} घंटे के लिए रुकी हैं।",
    "{0}'s account now uses {1}.": "{0} का खाता अब {1} इस्तेमाल करता है।",
    "{0}'s mobile number was disconnected. They can still act from the phone they are signed in on, but can't "
    "sign in anywhere new until they add a new number.":
        "{0} का मोबाइल नंबर बंद कर दिया गया है। वे अभी भी अपने साइन-इन फ़ोन से काम कर सकते हैं, लेकिन नया नंबर जोड़ने तक "
        "कहीं नया साइन इन नहीं कर सकते।",
    "{0}'s mobile number {1} was disconnected by the operator and removed from their account. Their protection "
    "still applies. Help {2} add their new number.":
        "{0} का मोबाइल नंबर {1} ऑपरेटर ने बंद कर दिया है और उनके खाते से हटा दिया गया है। उनकी सुरक्षा अभी भी लागू है। "
        "{2} को नया नंबर जोड़ने में मदद करें।",
    "{0}. {1}'s account moves to {2} at {3} unless someone stops it.":
        "{0}। {1} का खाता {3} पर {2} पर चला जाएगा, जब तक कोई इसे न रोके।",
    "A security incident may affect your data": "एक सुरक्षा घटना से आपका डेटा प्रभावित हो सकता है",
    "On {0} we found a security incident that may have exposed {1}. What you can do: {2}. Your protection rules "
    "and guardians are not affected. Questions: {3}.":
        "{0} को हमें एक सुरक्षा घटना का पता चला, जिससे {1} उजागर हो सकते हैं। आप क्या कर सकते हैं: {2}। आपके सुरक्षा "
        "नियम और गार्डियन प्रभावित नहीं हैं। सवालों के लिए: {3}।",
    "Guardian Registry code: {0}. Valid {1} min. Never share it with anyone, not even a guardian or a bank.":
        "Guardian Registry कोड: {0}। {1} मिनट तक मान्य। इसे किसी से साझा न करें, गार्डियन या बैंक से भी नहीं।",
}

# English phrases the code inserts into the templates above
FRAGMENTS_HI = {
    # payment decisions (policy.py)
    "the SIM card for this number was changed recently, so this payment needs extra checks":
        "इस नंबर का सिम कार्ड हाल ही में बदला गया, इसलिए इस भुगतान की अतिरिक्त जाँच ज़रूरी है",
    "amount {0} is at or above the approval threshold {1}": "राशि {0} मंज़ूरी सीमा {1} के बराबर या उससे ज़्यादा है",
    "first payment of {0} to a new payee": "नए प्राप्तकर्ता को {0} का पहला भुगतान",
    "no active guardian to approve, so a cooling-off delay applies instead":
        "मंज़ूरी देने के लिए कोई सक्रिय गार्डियन नहीं, इसलिए इसकी जगह प्रतीक्षा अवधि लागू है",
    "amount must be positive": "राशि शून्य से ज़्यादा होनी चाहिए",
    "banks have confirmed fraud involving this payee": "बैंकों ने इस प्राप्तकर्ता से जुड़ी धोखाधड़ी की पुष्टि की है",
    "a bank has reported fraud involving this payee": "एक बैंक ने इस प्राप्तकर्ता से जुड़ी धोखाधड़ी की सूचना दी है",
    "much larger than this person's usual payments (largest in 90 days: {0})":
        "इस व्यक्ति के सामान्य भुगतानों से बहुत बड़ा (90 दिनों में सबसे बड़ा: {0})",
    "{0} new payees in 24 hours": "24 घंटों में {0} नए प्राप्तकर्ता",
    "a request to loosen protection is waiting": "सुरक्षा ढीली करने का एक अनुरोध प्रतीक्षा में है",
    "a large payment at night ({0}:00 to {1}:00)": "रात में बड़ा भुगतान ({0}:00 से {1}:00 के बीच)",
    "kill switch is on: all outgoing payments are paused": "सभी भुगतान रोकने वाला बटन चालू है: सभी भुगतान रुके हुए हैं",
    "payments to this payee today would go over the limit {0} ({1} left today)":
        "आज इस प्राप्तकर्ता को भुगतान सीमा {0} से ज़्यादा हो जाएँगे (आज {1} बाकी)",
    "daily limit {0} for {1} would be exceeded ({2} left today)": "{1} की दैनिक सीमा {0} पार हो जाएगी (आज {2} बाकी)",
    "channel '{0}' is switched off": "माध्यम '{0}' बंद है",
    "channel '{0}' is switched off from {1} to {2}": "माध्यम '{0}' {1} से {2} तक बंद रहता है",
    "amount {0} is over the per-payment limit {1}": "राशि {0} एक भुगतान की सीमा {1} से ज़्यादा है",
    "daily limit {0} would be exceeded ({1} left today)": "दैनिक सीमा {0} पार हो जाएगी (आज {1} बाकी)",
    # ready-made rule sets (presets.py), shown in the apps
    "1-hour wait on high-value payments to new payees": "नए प्राप्तकर्ताओं को बड़े भुगतान पर 1 घंटे की प्रतीक्षा",
    "Trusted person approves large transfers (RBI draft rules)": "भरोसेमंद व्यक्ति बड़े ट्रांसफ़र मंज़ूर करे (RBI के मसौदा नियम)",
    "Trusted person approves large payments": "भरोसेमंद व्यक्ति बड़े भुगतान मंज़ूर करे",
    "Strict: low limits, no RTGS": "सख़्त: कम सीमाएँ, RTGS बंद",
    # protection changes (service.py)
    "loosen their payment limits ({0})": "अपनी भुगतान सीमाएँ ढीली करना ({0})",
    "switch payments back on": "भुगतान फिर से चालू करना",
    "remove a guardian": "एक गार्डियन को हटाना",
    "move their account to a new number ({0})": "अपना खाता नए नंबर ({0}) पर ले जाना",
    "approved": "मंज़ूर किया", "denied": "अस्वीकार किया", "cancelled": "रद्द किया",
    "is now your guardian": "अब आपके गार्डियन हैं", "declined your request": "ने आपका अनुरोध अस्वीकार किया",
    # breach notices (breach.py)
    "your mobile number": "आपका मोबाइल नंबर", "your name": "आपका नाम", "your date of birth": "आपकी जन्मतिथि",
    "your payment history": "आपके भुगतानों का इतिहास", "your sign-in sessions": "आपके साइन-इन सत्र",
    "data about your phone": "आपके फ़ोन से जुड़ी जानकारी",
    "be careful with calls and messages that claim to be from us or your bank":
        "हमारी या आपके बैंक की ओर से होने का दावा करने वाली कॉल और संदेशों से सावधान रहें",
    "expect scam calls that use your name to sound genuine": "आपका नाम लेकर असली लगने वाली धोखाधड़ी कॉल आ सकती हैं",
    "never confirm your date of birth to a caller": "किसी कॉल करने वाले को अपनी जन्मतिथि की पुष्टि कभी न करें",
    "check your recent payments in the app": "ऐप में अपने हाल के भुगतान जाँचें",
    "sign out everywhere in the app and sign in again": "ऐप में हर जगह से साइन आउट करें और फिर से साइन इन करें",
    "ignore unexpected messages asking you to install apps or share codes":
        "ऐप इंस्टॉल करने या कोड साझा करने के लिए कहने वाले अनचाहे संदेशों को अनदेखा करें",
    # SIM and number events (simswap.py, simfeed.py, recovery.py)
    "reported a lost or stolen phone": "ने फ़ोन खोने या चोरी होने की सूचना दी",
    "had their SIM card changed": "का सिम कार्ड बदला गया",
    "had their SIM card changed (reported by their mobile operator)": "का सिम कार्ड बदला गया (मोबाइल ऑपरेटर ने बताया)",
    "had their SIM card changed (found when we checked with their operator)":
        "का सिम कार्ड बदला गया (ऑपरेटर से जाँच में पता चला)",
    "moved their number to another mobile operator": "ने अपना नंबर दूसरे मोबाइल ऑपरेटर पर पोर्ट कराया",
    "recovered their account on a new number": "ने नए नंबर पर अपना खाता वापस पाया",
    "{0} people who know {1} vouched": "{1} को जानने वाले {0} लोगों ने पुष्टि की",
    "{0} confirmed who they are": "{0} ने उनकी पहचान की पुष्टि की",
    "{0} did a full KYC check in person": "{0} ने आमने-सामने पूरी KYC जाँच की",
    " and your date of birth (used only to tell banks if you are 70 or over)":
        " और आपकी जन्मतिथि (केवल बैंकों को यह बताने के लिए कि आप 70 या उससे ज़्यादा उम्र के हैं)",
}

# --------------------------------------------------------------------------- errors
ERRORS_HI = {
    "an erasure is already waiting; cancel it or wait": "खाता हटाने का एक अनुरोध पहले से प्रतीक्षा में है; उसे रद्द करें या प्रतीक्षा करें",
    "approval_timeout_minutes must be between 1 and 1440": "गार्डियन के जवाब का समय 1 से 1440 मिनट के बीच होना चाहिए",
    "at most {0} devices; remove one first": "ज़्यादा से ज़्यादा {0} डिवाइस; पहले एक हटाएँ",
    "at most {0} guardians (invited + active)": "ज़्यादा से ज़्यादा {0} गार्डियन (आमंत्रित + सक्रिय)",
    "attestation is already {0}": "यह पुष्टि पहले से {0} है",
    "attestation not found": "पुष्टि नहीं मिली",
    "change is already {0}": "बदलाव पहले से {0} है",
    "change not found": "बदलाव नहीं मिला",
    "check not found": "भुगतान नहीं मिला",
    "code expired or not requested": "कोड की अवधि समाप्त हो गई या कोड माँगा नहीं गया",
    "cooling_off_minutes must be between 0 and 10080": "प्रतीक्षा समय 0 से 10080 मिनट के बीच होना चाहिए",
    "device challenge is unknown, used or expired; ask for a new one": "डिवाइस चुनौती अमान्य, इस्तेमाल हो चुकी या पुरानी है; नई माँगें",
    "device key not found": "डिवाइस कुंजी नहीं मिली",
    "device signature does not verify": "डिवाइस का हस्ताक्षर सही नहीं है",
    "display_name is required": "नाम ज़रूरी है",
    "guardianship is not active": "गार्डियनशिप सक्रिय नहीं है",
    "guardianship not found": "गार्डियनशिप नहीं मिली",
    "invitation is already {0}": "निमंत्रण पहले से {0} है",
    "invitation not found": "निमंत्रण नहीं मिला",
    "no erasure is waiting": "खाता हटाने का कोई अनुरोध प्रतीक्षा में नहीं है",
    "no open SIM-change window": "सिम बदलने की कोई खुली अवधि नहीं है",
    "only this person's guardians, or people they guard, can vouch": "केवल इस व्यक्ति के गार्डियन, या जिनकी वे सुरक्षा करते हैं, पुष्टि कर सकते हैं",
    "payment is {0}; it can no longer be changed": "भुगतान {0} है; अब इसे बदला नहीं जा सकता",
    "platform must be one of {0}": "प्लेटफ़ॉर्म इनमें से एक होना चाहिए: {0}",
    "push device not found": "पुश डिवाइस नहीं मिला",
    "recovery already has enough vouches": "खाता वापसी के लिए पर्याप्त पुष्टियाँ पहले ही मिल चुकी हैं",
    "recovery changed meanwhile; reload and try again": "इस बीच खाता वापसी बदल गई; फिर से लोड करके कोशिश करें",
    "recovery is already {0}": "खाता वापसी पहले से {0} है",
    "recovery not found": "खाता वापसी नहीं मिली",
    "require_verified_guardian must be true or false": "'केवल बैंक-सत्यापित गार्डियन' हाँ या नहीं होना चाहिए",
    "your name must be 1 to 80 characters": "आपका नाम 1 से 80 अक्षरों का होना चाहिए",
    "the nominee needs a name (up to 80 characters) and a relation (up to 40)":
        "नामित व्यक्ति का नाम (80 अक्षरों तक) और रिश्ता (40 अक्षरों तक) ज़रूरी है",
    "the nominee's mobile must be a valid Indian mobile number": "नामित व्यक्ति का मोबाइल एक सही भारतीय मोबाइल नंबर होना चाहिए",
    "a new guardian can approve payments only after the waiting period set in this person's rules":
        "नया गार्डियन इस व्यक्ति के नियमों में तय प्रतीक्षा अवधि के बाद ही भुगतान मंज़ूर कर सकता है",
    "approval_scope must be all or rbi": "मंज़ूरी का दायरा 'सभी' या 'RBI' होना चाहिए",
    "write your complaint in 10 to 2000 characters": "अपनी शिकायत 10 से 2000 अक्षरों में लिखें",
    "you already have 5 complaints waiting; we answer each within 90 days":
        "आपकी 5 शिकायतें पहले से जवाब के इंतज़ार में हैं; हम हर शिकायत का जवाब 90 दिनों के भीतर देते हैं",
    "confirm you are 18 or older to create an account": "खाता बनाने के लिए पुष्टि करें कि आपकी उम्र 18 वर्ष या उससे ज़्यादा है",
    "narration must be at most 140 characters": "भुगतान का विवरण 140 अक्षरों से ज़्यादा नहीं हो सकता",
    "quiet_hours needs one or more channels and a start and end hour (0 to 23) that differ":
        "बंद रहने के समय के लिए कम से कम एक माध्यम और शुरू व खत्म होने का अलग-अलग घंटा (0 से 23) चाहिए",
    "channel_daily_limits must map channels to positive whole numbers of paise":
        "हर माध्यम की दैनिक सीमा पैसे में शून्य से बड़ी पूर्ण संख्या होनी चाहिए",
    "new_guardian_wait_hours must be between 0 and 168": "नए गार्डियन की प्रतीक्षा 0 से 168 घंटे के बीच होनी चाहिए",
    "per_payee_daily_limit must be a positive whole number of paise or null":
        "हर प्राप्तकर्ता की दैनिक सीमा पैसे में शून्य से बड़ी पूर्ण संख्या या खाली होनी चाहिए",
    "send device_key, challenge and device_proof together": "डिवाइस कुंजी, चुनौती और प्रमाण एक साथ भेजें",
    "that new number is already enrolled; recover with a number that isn't": "वह नया नंबर पहले से पंजीकृत है; किसी ऐसे नंबर से खाता वापस पाएँ जो पंजीकृत न हो",
    "that number is already enrolled": "वह नंबर पहले से पंजीकृत है",
    "that person must enrol before they can be invited as a guardian": "गार्डियन के रूप में आमंत्रित होने से पहले उस व्यक्ति को पंजीकरण करना होगा",
    "the current notice is version {0}; read it and accept that version": "मौजूदा सूचना संस्करण {0} है; उसे पढ़ें और वही संस्करण स्वीकार करें",
    "the guardian being removed cannot decide on their own removal": "हटाए जा रहे गार्डियन अपने हटाए जाने पर फ़ैसला नहीं कर सकते",
    "the new number was enrolled by someone else in the meantime": "इस बीच नया नंबर किसी और ने पंजीकृत कर लिया",
    "this change was already decided": "इस बदलाव पर पहले ही फ़ैसला हो चुका है",
    "this device key was revoked; reinstall the app to create a new one": "यह डिवाइस कुंजी रद्द कर दी गई है; नई बनाने के लिए ऐप फिर से इंस्टॉल करें",
    "this mobile number is already enrolled": "यह मोबाइल नंबर पहले से पंजीकृत है",
    "this number is not enrolled yet: send display_name to enrol": "यह नंबर अभी पंजीकृत नहीं है: पंजीकरण के लिए अपना नाम भेजें",
    "this person is already invited or active as your guardian": "यह व्यक्ति पहले से आपके गार्डियन के रूप में आमंत्रित या सक्रिय है",
    "this person's rules require a bank-verified guardian to approve payments": "इस व्यक्ति के नियमों के अनुसार भुगतान की मंज़ूरी बैंक-सत्यापित गार्डियन ही दे सकते हैं",
    "too many wrong codes; request a new one": "बहुत ज़्यादा गलत कोड; नया कोड माँगें",
    "unknown channels: {0}": "अज्ञात माध्यम: {0}",
    "unknown preset; choose one of {0}": "अज्ञात सेट; इनमें से चुनें: {0}",
    "urgent_channel must be one of {0}": "ज़रूरी सूचनाओं का माध्यम इनमें से एक होना चाहिए: {0}",
    "use the kill-switch endpoints to turn payments on or off": "भुगतान चालू या बंद करने के लिए 'सभी भुगतान रोकें' बटन इस्तेमाल करें",
    "user not found": "उपयोगकर्ता नहीं मिला",
    "vouching opens at {0}. Use the time to call them yourself on a number you know; you can deny at any time":
        "पुष्टि {0} से खुलेगी। इस समय में उन्हें खुद किसी जाने-पहचाने नंबर पर कॉल करें; अस्वीकार आप कभी भी कर सकते हैं",
    "wrong code": "गलत कोड",
    "wait {0} seconds before asking for another code": "दूसरा कोड माँगने से पहले {0} सेकंड रुकें",
    "too many codes requested; try again in {0} minutes": "बहुत ज़्यादा कोड माँगे गए; {0} मिनट बाद फिर कोशिश करें",
    "language must be one of {0}": "भाषा इनमें से एक होनी चाहिए: {0}",
    "scam_signals and sim_swap_hold must be true or false": "धोखाधड़ी के संकेत और सिम-बदलाव रोक हाँ या नहीं होने चाहिए",
    "you are not an active guardian of this person": "आप इस व्यक्ति के सक्रिय गार्डियन नहीं हैं",
    "you cannot be your own guardian": "आप खुद अपने गार्डियन नहीं हो सकते",
    "{0} must be a positive whole number of paise or null": "{0} पैसों में धनात्मक पूर्ण संख्या या खाली होना चाहिए",
    # api.py
    "missing, invalid or expired bearer token": "साइन इन नहीं है या सत्र समाप्त हो गया; फिर से साइन इन करें",
    "rate limit exceeded": "बहुत ज़्यादा कोशिशें; थोड़ी देर बाद फिर कोशिश करें",
    "this sign-in can't do that yet: {0}": "यह साइन-इन अभी ऐसा नहीं कर सकता: {0}",
    "not a valid Indian mobile number": "यह मान्य भारतीय मोबाइल नंबर नहीं है",
}
ERROR_FRAGMENTS_HI = {
    "new device: restricted until {0}": "नया डिवाइस: {0} तक सीमित",
    "signed in after a SIM change: restricted until {0} or until confirmed from a trusted device or by a guardian":
        "सिम बदलने के बाद साइन इन: {0} तक, या किसी भरोसेमंद डिवाइस या गार्डियन से पुष्टि होने तक सीमित",
    "approved": "मंज़ूर", "denied": "अस्वीकृत", "cancelled": "रद्द", "expired": "समय समाप्त", "released": "जारी",
    "pending_approval": "मंज़ूरी की प्रतीक्षा में", "cooling_off": "रुका हुआ", "blocked": "अवरुद्ध", "allowed": "अनुमत",
    "active": "सक्रिय", "declined": "अस्वीकृत", "ended": "समाप्त", "rejected": "अस्वीकृत", "withdrawn": "वापस लिया गया",
    "revoked": "रद्द", "pending": "प्रतीक्षा में", "held": "रुका हुआ", "completed": "पूरा", "vetoed": "रोका गया",
    "applied": "लागू",
}

# Errors only banks, operators or developers see; they stay English (API field names, formats).
NOT_FOR_PEOPLE = {
    "complaint not found", "this complaint was already answered", "write an answer of 1 to 4000 characters",
    "status must be open, answered or all",
    "KYC record is too old; re-verify the customer first", "amount must be a whole number of paise",
    "assisted recovery needs KYC done in the last 30 days",
    "assisted recovery needs verified_on (the in-person KYC you just did)", "at most {0} events per batch",
    "changed_at cannot be in the future", "changed_at must be an ISO 8601 timestamp",
    "changed_at must include a timezone, e.g. 2026-11-23T09:15:00+05:30", "channel must be one of {0}",
    "customer is not enrolled in the registry", "customer_ref is required (max 100 characters)",
    "date_of_birth is not plausible", "device_key must be a DER SubjectPublicKeyInfo",
    "device_key must be an EC P-256 key", "events must be a non-empty list", "kyc_level must be one of {0}",
    "no pending recovery for that number is eligible for assisted recovery (it is only for people with no "
    "contacts and no earlier bank KYC)",
    "no pending recovery for that number matches a customer you verified before",
    "occurred_at cannot be in the future", "occurred_at is required", "occurred_at must be an ISO 8601 timestamp",
    "occurred_at must include a timezone", "outcome already reported as completed", "participant_txn_id is required",
    "participant_txn_id was already used for a different payment", "payee is required",
    "payment was not cleared to execute (status: {0})", "kind must be one of {0}", "token is required", "unknown rule fields: {0}",
    "verified_on cannot be in the future",
    "webhook url must be https:// (http://localhost allowed outside production)",
    "webhook url must point to a public address, not a private or internal one", "{0} must be a date like 1951-04-23",
    "{0} must be base64",
}


# --------------------------------------------------------------------------- languages
I18N_DIR = Path(__file__).parent / "i18n"
_KINDS = {1: "server:alert", 2: "server:phrase", 3: "server:error", 4: "server:error-phrase"}


@lru_cache(maxsize=1)
def language_meta() -> dict:
    return json.loads((I18N_DIR / "languages.json").read_text(encoding="utf-8"))


def enabled_languages() -> tuple[str, ...]:
    """English plus the languages switched on in i18n/languages.json, or exactly those in
    GR_LANGUAGES (e.g. "en,hi,ta") when set. Draft languages stay off until reviewed."""
    env = os.environ.get("GR_LANGUAGES")
    meta = language_meta()
    if env:
        codes = [c.strip() for c in env.split(",") if c.strip() in meta]
    else:
        codes = [c for c, m in meta.items() if m.get("enabled")]
    return tuple(dict.fromkeys(["en", *codes]))


def _known(lang: str | None) -> bool:
    return bool(lang) and lang in enabled_languages()


@lru_cache(maxsize=None)
def _catalog_table(lang: str, table_id: int) -> dict[str, str]:
    """English -> translation for one server table, from i18n/catalog.json + i18n/<lang>.json."""
    if lang == "hi":
        return {1: ALERTS_HI, 2: FRAGMENTS_HI, 3: ERRORS_HI, 4: ERROR_FRAGMENTS_HI}[table_id]
    known = next((code for code in language_meta() if code == lang), None)   # never the caller's string
    if known is None:
        return {}
    path = I18N_DIR / f"{known}.json"
    if not path.exists():
        return {}
    catalog = json.loads((I18N_DIR / "catalog.json").read_text(encoding="utf-8"))
    tr = json.loads(path.read_text(encoding="utf-8"))
    kind = _KINDS[table_id]
    return {e["en"]: tr[k] for k, e in catalog.items() if kind in e["where"] and k in tr}


# --------------------------------------------------------------------------- engine
def _regex(template: str) -> re.Pattern:
    parts = re.split(r"(\{\d+\})", template)
    out = []
    for p in parts:
        m = re.fullmatch(r"\{(\d+)\}", p)
        out.append(f"(?P<g{m.group(1)}>.+?)" if m else re.escape(p.replace("{{", "{").replace("}}", "}")))
    return re.compile("".join(out), re.S)


@lru_cache(maxsize=None)
def _compiled(table_id: int, lang: str = "hi") -> list[tuple[re.Pattern, str, int]]:
    table = _catalog_table(lang, table_id)
    rows = [(_regex(en), tr, len(re.sub(r"\{\d+\}", "", en))) for en, tr in table.items()]
    rows.sort(key=lambda r: -r[2])  # most specific (most literal text) first
    return rows


def _fill(rx: re.Pattern, tr: str, m: re.Match, fragments: int, lang: str) -> str:
    values = {k: _value(v, fragments, lang=lang) for k, v in m.groupdict().items()}
    return re.sub(r"\{(\d+)\}", lambda x: values.get(f"g{x.group(1)}", x.group(0)), tr)


def _value(v: str, fragments: int, depth: int = 0, lang: str = "hi") -> str:
    if depth > 3:
        return v
    if "; " in v:  # several reasons: translate each (before matching, or one template swallows all)
        return "; ".join(_value(p, fragments, depth + 1, lang) for p in v.split("; "))
    for rx, tr, _ in _compiled(fragments, lang):
        m = rx.fullmatch(v)
        if m:
            return _fill(rx, tr, m, fragments, lang)
    if ", " in v and v.count(", ") < 6:
        parts = v.split(", ")
        out = [_value(p, fragments, depth + 1, lang) for p in parts]
        if out != parts:
            return ", ".join(out)
    return v


def _translate(text: str, lang: str, table: int, fragments: int) -> str:
    if not text or lang == "en" or not _known(lang):
        return text
    for rx, tr, _ in _compiled(table, lang):
        m = rx.fullmatch(text)
        if m:
            return _fill(rx, tr, m, fragments, lang)
    return text


def phrase(text: str, lang: str) -> str:
    """A phrase the code inserts (a payment's reasons) in `lang`, for the screens that list
    payments; English when there is no translation."""
    if not text or lang == "en" or not _known(lang):
        return text
    return _value(text, 2, lang=lang)


def preset_labels(presets: dict, lang: str) -> dict:
    """The ready-made rule sets with their labels in `lang` (the rules themselves unchanged)."""
    if lang == "en" or not _known(lang):
        return presets
    return {k: {**p, "label": phrase(p["label"], lang)} for k, p in presets.items()}


def restriction(text: str, lang: str) -> str:
    """Why a sign-in is restricted ("new device: restricted until ...") in `lang`."""
    if not text or lang == "en" or not _known(lang):
        return text
    return _value(text, 4, lang=lang)


def alert(text: str, lang: str) -> str:
    return _translate(text, lang, 1, 2)


def error(text: str, lang: str) -> str:
    return _translate(text, lang, 3, 4)


def language_from_header(accept_language: str | None) -> str:
    """'hi-IN,hi;q=0.9,en;q=0.8' -> 'hi'. Only enabled languages; English otherwise."""
    for part in (accept_language or "").split(","):
        code = part.split(";")[0].strip().lower()[:2]
        if _known(code):
            return code
    return "en"


def normalise(lang: str | None) -> str | None:
    """A language code from an app ('ta-IN', 'TA') if it is enabled, else None."""
    code = (lang or "").strip().lower()[:2]
    return code if _known(code) else None
