# WebIntoApp Custom Keystore Guide
### 🛡️ Secure Your Developer Signature for Crewmate Rush

Aap jo online tools (jaise **WebIntoApp**) use karte hain, unme by-default custom signing enabled nahi hoti. Is wajah se app reject ho jata hai. Niche di gayi steps follow karke aap WebIntoApp par apni custom signature upload kar sakte hain:

---

## 🛑 Rejection Ka Asli Reason:
Jab aap WebIntoApp par simple convert karte hain, toh wo game ko ek **Debug Key** ya unki **Default Key** se sign kar deta hai. 
Google Play Store ya koi bhi badi publishing platform debug/generic signatures ko reject kar deti hai kyunki unhe security ke liye **Aapka Apna Unique Developer Keystore** chahiye hota hai.

---

## 🛠️ Solution: WebIntoApp Me Custom Keystore Kaise Dalein?

WebIntoApp ke paas aek feature hai jahan aap apna **Custom Keystore** upload kar sakte hain taaki APK aapke naam se sign ho.

### Step 1: Apna Keystore File Banayein (Permanent Developer Signature)
Sabse pehle apne computer (CMD ya Terminal) par ye command chalakar apni personal `.keystore` file generate karein:

```bash
keytool -genkey -v -keystore eachone_signature.keystore -alias eachone_alias -keyalg RSA -keysize 2048 -validity 10000 -dname "CN=Eachone Info, OU=Gaming, O=Eachone Information Channel, L=Delhi, S=Delhi, C=IN"
```
* **Keystore Password:** (Eg: `eachone123`)
* **Key Alias:** `eachone_alias`
* **Key Password:** (Eg: `eachone123`)

Isse aapke computer par `eachone_signature.keystore` naam ki file save ho jayegi.

---

### Step 2: WebIntoApp Par Upload Karein
1. **WebIntoApp.com** par login karein aur apna project setup karein.
2. App settings ke andar **"Android Certificate"** ya **"Keystore / Signing"** tab par jayein.
3. Wahan par select karein: **"Use My Own Keystore / Custom Certificate"** (Default keystore ki jagah).
4. Ab apni generate ki hui `eachone_signature.keystore` file ko wahan upload karein.
5. Form mein wahi passwords aur alias fill karein jo aapne Step 1 mein rakhe the:
   * **Keystore Password:** `eachone123`
   * **Key Alias:** `eachone_alias`
   * **Key Password:** `eachone123`
6. Ab **Generate APK** par click karein.

---

## 🎉 Result:
Ab jo APK download hoga, uske andar **Eachone Information Channel** ka verified developer signature lag chuka hoga. Is signed APK ko jab aap publish karenge, toh store use instantly accept kar lega aur signature verification error **kabhi nahi** aayega!
