"use strict";
// Interface languages. The English text is the key; a missing translation falls back to
// English, so nothing ever shows a raw key. Placeholders: {name}.
// The language is a per-browser preference (localStorage), chosen with the header button
// and defaulting to the browser's language. Alerts and error messages written by the server
// are still English (see README: Still open).

const LANG_KEY = "gr.lang";
const LANGS = { en: "English", hi: "हिंदी" };

const STRINGS = {
  hi: {
    // navigation and chrome
    "My protection": "मेरी सुरक्षा", "I protect": "मेरे द्वारा सुरक्षित", "Alerts": "सूचनाएँ", "Devices": "डिवाइस",
    "Loading…": "लोड हो रहा है…", "No limit": "कोई सीमा नहीं", "Something went wrong": "कुछ गड़बड़ हो गई",
    "This sign-in is restricted for now: {reasons}. You can still pause payments, deny or stop payments, and make rules stricter.":
      "यह साइन-इन अभी सीमित है: {reasons}। आप फिर भी भुगतान रोक सकते हैं, उन्हें अस्वीकार कर सकते हैं और नियम सख़्त कर सकते हैं।",
    // rules
    "Most per payment": "एक भुगतान में अधिकतम", "Most per day (all banks)": "एक दिन में अधिकतम (सभी बैंक)",
    "Guardian approves from": "इतनी राशि से गार्डियन की मंज़ूरी", "Wait on new payees from": "नए प्राप्तकर्ता पर इतनी राशि से प्रतीक्षा",
    "Wait time": "प्रतीक्षा समय", "Time for guardian to answer": "गार्डियन के जवाब का समय", "Blocked channels": "बंद किए गए माध्यम",
    "Only bank-verified guardians approve": "केवल बैंक-सत्यापित गार्डियन मंज़ूरी दें",
    "Hold payments after a SIM change": "सिम बदलने के बाद भुगतान रोकें",
    "None": "कोई नहीं", "Yes": "हाँ", "No": "नहीं", "{m} min": "{m} मिनट",
    "Loosen payment limits": "भुगतान सीमाएँ ढीली करना", "Switch payments back on": "भुगतान फिर से चालू करें",
    "Remove a guardian": "एक गार्डियन को हटाना", "Move to a new number": "नए नंबर पर जाना",
    // statuses
    "Allowed": "अनुमत", "Approved": "मंज़ूर", "Released": "जारी", "Waiting for approval": "मंज़ूरी की प्रतीक्षा",
    "On hold": "रोका गया", "Blocked": "अवरुद्ध", "Denied": "अस्वीकृत", "Expired": "समय समाप्त", "Cancelled": "रद्द",
    "Failed": "विफल", "active": "सक्रिय", "invited": "आमंत्रित", "declined": "अस्वीकृत", "ended": "समाप्त",
    "trusted": "भरोसेमंद", "probation": "परखा जा रहा", "revoked": "रद्द",
    // sign-in
    "Sign in": "साइन इन करें", "We'll send a 6-digit code to your mobile number.": "हम आपके मोबाइल नंबर पर 6 अंकों का कोड भेजेंगे।",
    "Mobile number": "मोबाइल नंबर", "Send code": "कोड भेजें", "Enter the code": "कोड डालें",
    "Sent to {mobile}. It works for 5 minutes.": "{mobile} पर भेजा गया। यह 5 मिनट तक मान्य है।",
    "Development mode code: {code}": "डेवलपमेंट मोड कोड: {code}",
    "Welcome! Your account is set up.": "स्वागत है! आपका खाता बन गया है।",
    "Signed in. This device is restricted for now; see the note at the top.": "साइन इन हो गया। यह डिवाइस अभी सीमित है; ऊपर दी गई सूचना देखें।",
    "This number is new here. Add your name to create your account.": "यह नंबर यहाँ नया है। खाता बनाने के लिए अपना नाम जोड़ें।",
    "6-digit code": "6 अंकों का कोड", "Your name": "आपका नाम", "Create account": "खाता बनाएँ",
    "Use another number": "दूसरा नंबर इस्तेमाल करें",
    "Protect payments for the people you care about": "अपनों के भुगतान सुरक्षित रखें",
    "Set limits once and every bank checks them. Ask someone you trust to approve large payments.":
      "एक बार सीमाएँ तय करें, हर बैंक उन्हें जाँचेगा। बड़े भुगतानों की मंज़ूरी के लिए किसी भरोसेमंद व्यक्ति से कहें।",
    // my protection
    "Payments are back on.": "भुगतान फिर से चालू हैं।",
    "Your request is held for 24 hours. Your guardians can approve it sooner.": "आपका अनुरोध 24 घंटे के लिए रोका गया है। आपके गार्डियन इसे पहले मंज़ूर कर सकते हैं।",
    "All payments are paused.": "सभी भुगतान रोक दिए गए हैं।", "Pause all payments": "सभी भुगतान रोकें", "Preset": "तैयार सेट",
    "Invitation sent. They need to accept it in their app.": "निमंत्रण भेजा गया। उन्हें अपने ऐप में इसे स्वीकार करना होगा।",
    "Invite a guardian by mobile number": "मोबाइल नंबर से गार्डियन को आमंत्रित करें", "Invite": "आमंत्रित करें",
    "Hello, {name}": "नमस्ते, {name}", "Identity: {level}": "पहचान: {level}",
    "Payments are paused": "भुगतान रुके हुए हैं", "Payments are on": "भुगतान चालू हैं",
    "No bank will send money from your accounts until payments are switched back on.": "भुगतान फिर से चालू होने तक कोई भी बैंक आपके खातों से पैसे नहीं भेजेगा।",
    "If someone is pressuring you to pay, pause everything. You can switch back on later.": "अगर कोई आप पर भुगतान का दबाव डाल रहा है, तो सब कुछ रोक दें। बाद में फिर से चालू कर सकते हैं।",
    "Your SIM card was reported changed": "आपका सिम कार्ड बदले जाने की सूचना मिली है",
    "Until {time}, larger payments are held and new sign-ins can't approve anything.": "{time} तक बड़े भुगतान रोके जाएँगे और नए साइन-इन कुछ भी मंज़ूर नहीं कर सकते।",
    "If you changed your SIM yourself, confirm it from this phone. If you didn't, call your mobile operator now.":
      "अगर सिम आपने खुद बदला है, तो इस फ़ोन से पुष्टि करें। अगर नहीं, तो अभी अपने मोबाइल ऑपरेटर को कॉल करें।",
    "Thanks. Normal protection applies again.": "धन्यवाद। सामान्य सुरक्षा फिर से लागू है।", "Yes, I changed my SIM": "हाँ, मैंने सिम बदला है",
    "Changes waiting": "प्रतीक्षा में बदलाव", "Takes effect {time} unless a guardian stops it.": "{time} पर लागू होगा, जब तक कोई गार्डियन इसे न रोके।",
    "My rules": "मेरे नियम", "Use a ready-made set": "तैयार सेट इस्तेमाल करें",
    "Stricter parts apply now; looser parts wait 24 hours.": "सख़्त हिस्से अभी लागू हैं; ढीले हिस्से 24 घंटे बाद लागू होंगे।",
    "Applied.": "लागू किया गया।", "Apply": "लागू करें",
    "Making rules stricter works at once. Loosening them waits 24 hours, and your guardians can stop it.":
      "नियम सख़्त करना तुरंत लागू होता है। ढीला करने में 24 घंटे लगते हैं, और आपके गार्डियन इसे रोक सकते हैं।",
    "My guardians": "मेरे गार्डियन",
    "No guardians yet. A guardian can approve large payments and pause payments for you.": "अभी कोई गार्डियन नहीं है। गार्डियन बड़े भुगतानों को मंज़ूरी दे सकते हैं और आपके भुगतान रोक सकते हैं।",
    "Recent payments": "हाल के भुगतान", "No payments checked yet.": "अभी तक कोई भुगतान जाँचा नहीं गया।",
    "Lost your phone?": "फ़ोन खो गया?",
    "This signs you out everywhere and holds larger payments for 72 hours.": "इससे आप हर जगह से साइन आउट हो जाएँगे और बड़े भुगतान 72 घंटे के लिए रुक जाएँगे।",
    "Sign out of every device and hold larger payments for 72 hours?": "हर डिवाइस से साइन आउट करें और बड़े भुगतान 72 घंटे रोकें?",
    "Done. Every device is signed out.": "हो गया। हर डिवाइस से साइन आउट कर दिया गया है।", "Report lost phone": "फ़ोन खोने की सूचना दें",
    "verified by a bank": "बैंक द्वारा सत्यापित", "basic bank check": "बैंक की बुनियादी जाँच", "phone number only": "केवल फ़ोन नंबर",
    "To {payee}": "{payee} को",
    // guardian
    "People I protect": "मेरे द्वारा सुरक्षित लोग", "Guardian requests": "गार्डियन अनुरोध",
    "{name} asked you to be their payment guardian.": "{name} ने आपसे उनका भुगतान गार्डियन बनने को कहा है।",
    "You now protect {name}.": "अब आप {name} की सुरक्षा कर रहे हैं।", "Accept": "स्वीकार करें", "Declined.": "अस्वीकार किया।",
    "Decline": "अस्वीकार करें", "Payments waiting": "प्रतीक्षा में भुगतान", "from {name}": "{name} से",
    "Approved.": "मंज़ूर किया।", "Approve": "मंज़ूर करें", "Denied. The payment will not go through.": "अस्वीकार किया। यह भुगतान नहीं होगा।",
    "Deny": "अस्वीकार करें", "Cancelled.": "रद्द किया।", "Stop this payment": "यह भुगतान रोकें",
    "Answer by {time}": "{time} तक जवाब दें", "Goes through at {time} unless stopped": "{time} पर हो जाएगा, जब तक रोका न जाए",
    "Not sure? Call them on a number you know before approving.": "पक्का नहीं? मंज़ूरी से पहले उन्हें किसी जाने-पहचाने नंबर पर कॉल करें।",
    "Nothing is waiting for you.": "आपके लिए कुछ भी प्रतीक्षा में नहीं है।", "Protection changes waiting": "प्रतीक्षा में सुरक्षा बदलाव",
    "Someone": "कोई", "{name} wants to: {what}": "{name} यह करना चाहते हैं: {what}",
    "Happens {time} unless you stop it. Scammers often ask people to do this.": "{time} पर होगा, जब तक आप इसे न रोकें। धोखेबाज़ अक्सर लोगों से ऐसा करवाते हैं।",
    "Stopped.": "रोक दिया।", "Stop it": "इसे रोकें", "Approve now": "अभी मंज़ूर करें",
    "Account recovery requests": "खाता वापसी के अनुरोध",
    "{name} wants to move their account to {number}.": "{name} अपना खाता {number} पर ले जाना चाहते हैं।",
    "Only approve if you have spoken to them yourself, on a call YOU placed or in person. If in doubt, deny.":
      "तभी मंज़ूर करें जब आपने खुद उनसे बात की हो, अपनी की हुई कॉल पर या आमने-सामने। शक हो तो अस्वीकार करें।",
    "You can approve from {time}.": "आप {time} से मंज़ूर कर सकते हैं।", "Thank you. Your vouch is recorded.": "धन्यवाद। आपकी पुष्टि दर्ज कर ली गई है।",
    "I spoke to them: approve": "मैंने उनसे बात की: मंज़ूर करें", "Pause all payments for {name}?": "{name} के सभी भुगतान रोकें?",
    "Payments paused for {name}.": "{name} के भुगतान रोक दिए गए।", "Pause their payments": "उनके भुगतान रोकें",
    "You don't protect anyone yet. Someone has to invite you from their app.": "आप अभी किसी की सुरक्षा नहीं कर रहे। किसी को अपने ऐप से आपको आमंत्रित करना होगा।",
    // alerts and devices
    "All marked as read.": "सभी पढ़ी हुई मान ली गईं।", "Mark all read": "सभी को पढ़ा हुआ मानें", "New": "नई", "No alerts yet.": "अभी कोई सूचना नहीं।",
    "Each phone or browser you sign in on has its own key. A new one can't approve payments for 24 hours.":
      "जिस भी फ़ोन या ब्राउज़र पर आप साइन इन करते हैं, उसकी अपनी कुंजी होती है। नया डिवाइस 24 घंटे तक भुगतान मंज़ूर नहीं कर सकता।",
    "This device": "यह डिवाइस", "Device {id}": "डिवाइस {id}", "Added {time}": "{time} को जोड़ा गया",
    " · last used {time}": " · आख़िरी बार {time} को इस्तेमाल", "Removed and signed out.": "हटाया गया और साइन आउट किया गया।",
    "Remove": "हटाएँ", "No device keys yet.": "अभी कोई डिवाइस कुंजी नहीं।", "Sign out": "साइन आउट",
    "Sign out here": "यहाँ साइन आउट करें", "Sign out everywhere": "हर जगह साइन आउट करें",
  },
};

function currentLang() {
  let saved = null;
  try { saved = localStorage.getItem(LANG_KEY); } catch (e) { /* storage blocked: use the browser's language */ }
  if (saved && LANGS[saved]) return saved;
  return (navigator.language || "en").toLowerCase().startsWith("hi") ? "hi" : "en";
}

const LANG = currentLang();

function t(text, vars) {
  const table = STRINGS[LANG] || {};
  let out = table[text] !== undefined ? table[text] : text;
  for (const [k, v] of Object.entries(vars || {})) out = out.split(`{${k}}`).join(String(v));
  return out;
}

function setLang(lang) {
  try { localStorage.setItem(LANG_KEY, lang); } catch (e) { /* fine: this visit only */ }
  location.reload();
}

document.addEventListener("DOMContentLoaded", () => {
  document.documentElement.lang = LANG;
  for (const el of document.querySelectorAll("[data-i18n]")) el.textContent = t(el.dataset.i18n);
  const btn = document.getElementById("lang");
  if (btn) {
    const other = LANG === "hi" ? "en" : "hi";
    btn.textContent = LANGS[other];
    btn.setAttribute("lang", other);
    btn.addEventListener("click", () => setLang(other));
  }
});
