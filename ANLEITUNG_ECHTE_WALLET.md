# Echte EUDI Wallet Anbindung — Schritt für Schritt

## Was wir haben (Demo-Modus)
- Frontend, Backend, Wallet-Simulator: alles läuft
- Daten kommen aus Testdaten im Code

## Was wir wollen (Echter Modus)
- Echte EUDI Test-Wallet App auf dem Handy scannt QR-Code
- Nutzer bestätigt in der App
- Echte (Test-)Daten kommen ans Backend

---

## Schritt 1 – Pakete installieren (5 Minuten)

```bash
cd eudi-poc/backend
npm install @sphereon/siop-oid4vp @sphereon/oid4vc-common jose qrcode
```

## Schritt 2 – ngrok installieren (10 Minuten)

ngrok macht euren lokalen Server kurz über das Internet erreichbar.
Die Wallet-App braucht eine echte HTTPS-Adresse um zurückzurufen.

1. Auf https://ngrok.com kostenlos registrieren
2. ngrok herunterladen und installieren
3. Im Terminal: `ngrok http 3001`
4. ngrok zeigt dann sowas: `https://abc123.ngrok.io`
5. Diese URL merken!

## Schritt 3 – Backend mit echter URL starten

```bash
PUBLIC_URL=https://abc123.ngrok.io node server_real.js
```

(abc123.ngrok.io durch eure echte ngrok-URL ersetzen)

Der Server sagt dann:
  Modus: ECHT (Sphereon OpenID4VP)

## Schritt 4 – EUDI Test-Wallet App aufs Handy

Die offizielle deutsche EUDI Test-Wallet:
→ https://bmi.usercontent.opencode.de/eudi-wallet/developer-guide/Wallet_Use_Instructions/

Die App ist für Android und iOS verfügbar.
In der App: Test-PID (Personalausweis) aktivieren.

## Schritt 5 – Demo im Browser öffnen

Browser: http://localhost:3001

Auf "Mit EUDI Wallet abschließen" klicken.
Jetzt erscheint ein echter, scanbarer QR-Code.
Handy nehmen, Wallet-App öffnen, QR-Code scannen.
In der App auf "Freigeben" tippen.
Im Browser erscheint automatisch die Police.

---

## Sandbox-Registrierung (Relying-Party-Zertifikat)

→ https://bmi.usercontent.opencode.de/eudi-wallet/developer-guide/onboarding/joining/

**Update nach echtem Test (24./25.08.2026):** Entgegen der ursprünglichen Annahme unten
ist dieser Schritt **doch zwingend nötig**, sobald die echte Sandbox-Wallet-App
(nicht der Browser-Simulator) einen Nachweis abgeben soll:

- Die App lehnt unser selbstsigniertes Request Object ab:
  `Invalid resolution: No certificate in header` — sie behandelt unsere `client_id`
  als `preRegistered` und erwartet ein Zertifikat aus dem
  **German EUDI Ecosystem Sandbox Registrar**.
- Dieses Zertifikat gibt es nur nach dem offiziellen Onboarding-Prozess:
  Intent-Formular ausfüllen → monatlicher Kick-off-Call → Zugang zum Registrar →
  Zertifikat ausstellen. Kostenlos, aber dauert (Kick-offs sind monatlich).
- Die reine **Ausstellung** eines Test-PID an die Wallet-App (Schritt 4 oben)
  funktioniert dagegen bereits ohne Registrierung — das läuft über den offiziellen
  PID-Provider (Bundesdruckerei preprod) und ist unabhängig von unserem RP-Zertifikat.

Für die Demo mit dem **Browser-Wallet-Simulator** ist die Registrierung weiterhin
NICHT nötig — nur für die echte App als Verifier-Gegenstelle.

## Bekannte Lücke: mDL/IBAN in der Sandbox

Die offizielle Sandbox-Wallet kann aktuell nur ein Test-**PID** ausstellen.
Führerschein (mDL) und Bankverbindung (IBAN/EAA) sind fiktive Credential-Typen
dieses Projekts und dort (noch) nicht implementierbar.

→ Für Tests mit dem echten Handy: Server mit `PID_ONLY=1` starten
(`PID_ONLY=1 PUBLIC_URL=... node server_v4.js`). Das reduziert die
Presentation Definition und die fachliche Prüfung auf "Alter ≥ 18" aus dem PID.
Ohne `PID_ONLY=1` bleibt der volle 3-Credential-Flow (PID + mDL + IBAN) nur im
Browser-Simulator testbar.

⚠️ `PID_ONLY=1` gilt für den ganzen Serverprozess — beim normalen Browser-Demo
(Szenario "kein Führerschein" etc.) darf der Server NICHT mit `PID_ONLY=1` laufen,
sonst wird die Führerschein-Prüfung fälschlich übersprungen und der Test besteht
immer, egal welches Szenario gewählt wird.

---

## Was ändert sich in der Demo wenn es echt ist?

- QR-Code ist echt scanbar (statt visueller Mock)
- Wallet-Simulator-Fenster wird NICHT mehr geöffnet
- Nutzer bestätigt direkt auf seinem Handy
- Im Backend: "Modus: ECHT" statt "DEMO"
- In der Police: "EUDI Wallet verifiziert (echt)"

Alles andere — Screens, Checks, Police, Design — bleibt 100% gleich.
