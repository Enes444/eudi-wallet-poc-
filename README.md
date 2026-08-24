# EUDI Wallet POC — Echte Kryptographie (v4)

KFZ-Versicherungsabschluss via EUDI Wallet. **Kein Mock mehr:** vollständige
OpenID4VP + SD-JWT Implementierung mit echter ES256-Kryptographie.

## Was ist echt?
- ES256-signierte SD-JWT Credentials (PID, mDL, IBAN) mit Selective Disclosure
- Signierte OpenID4VP Request Objects, echt scanbare QR-Codes
- Vollständige Verifikation: Issuer-Signatur · Disclosure-Hashes (SHA-256) · Nonce (Replay-Schutz) · Key Binding JWT
- Sicherheitstests beweisen: Manipulation, Replay und fremde Issuer werden erkannt und abgelehnt

## Schnellstart
```bash
cd backend
npm install        # jose + qrcode
npm run setup      # Issuer erstellt 4 signierte Credentials + Trust Registry
npm start          # Server auf http://localhost:3001
```
Browser: http://localhost:3001 → Demo durchklicken (Wallet-Simulator nutzt echte Krypto)

## Standardkonformer Wallet-Client (statt Handy-App)
```bash
node test-wallet.js present <sessionId>              # Freigeben (alles OK)
node test-wallet.js present <sessionId> no_license   # ohne Führerschein
node test-wallet.js present <sessionId> underage     # minderjährig
```

## Tests (12 Stück, inkl. Sicherheit)
```bash
npm start          # Terminal 1
npm test           # Terminal 2 → 12/12 bestanden
```

## Struktur
```
backend/
├── sdjwt.js        SD-JWT Kern: Issue · Present · Verify (IETF-Draft-konform)
├── server_v4.js    OpenID4VP Relying Party mit echter Verifikation
├── test-wallet.js  Standardkonformer Wallet-Client (tut was die Handy-App tut)
├── e2e-test.js     12 automatisierte Tests inkl. Angriffs-Szenarien
└── server.js       (Alt: reiner Demo-Modus ohne Krypto)
frontend/
├── index.html            Demo-Webseite
└── wallet-simulator.html Browser-Wallet (triggert echten Krypto-Flow)
```

## Verbleibende Lücke zur Produktion
Einzig der Scan mit der **physischen EUDI Wallet App** fehlt — dafür: ngrok-Tunnel
+ offizielle Test-App (bmi.usercontent.opencode.de/eudi-wallet/developer-guide/).
Protokoll, Token-Formate und Verifikation sind bereits identisch implementiert.
