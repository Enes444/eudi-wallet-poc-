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

## Optional: Sandbox-Registrierung

Für eine vollständige Integration (inkl. Trust Framework):
→ https://bmi.usercontent.opencode.de/eudi-wallet/developer-guide/onboarding/joining/

Kostenlos. Dauert ein paar Tage bis zur Freischaltung.
Für die Demo mit Test-Wallet ist das NICHT zwingend nötig.

---

## Was ändert sich in der Demo wenn es echt ist?

- QR-Code ist echt scanbar (statt visueller Mock)
- Wallet-Simulator-Fenster wird NICHT mehr geöffnet
- Nutzer bestätigt direkt auf seinem Handy
- Im Backend: "Modus: ECHT" statt "DEMO"
- In der Police: "EUDI Wallet verifiziert (echt)"

Alles andere — Screens, Checks, Police, Design — bleibt 100% gleich.
