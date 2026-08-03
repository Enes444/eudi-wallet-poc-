/**
 * EUDI Test-Wallet — standardkonformer Wallet-Client
 * Tut exakt das, was die echte Handy-App tut:
 *   1. Request Object von der RP holen und Signatur prüfen
 *   2. Presentation Definition lesen
 *   3. Echte SD-JWT Credentials präsentieren (mit Key Binding, Nonce)
 *   4. VP Tokens an die RP zurücksenden
 *
 * Nutzung:
 *   node test-wallet.js setup                  → Issuer-Keys + Credentials erzeugen
 *   node test-wallet.js present <sessionId>    → Freigeben (alle Credentials)
 *   node test-wallet.js present <id> no_license → ohne Führerschein
 *   node test-wallet.js present <id> underage   → minderjährig
 */
const fs = require('fs');
const path = require('path');
const jose = require('jose');
const { issueCredential, createPresentation } = require('./sdjwt');

const API = process.env.API || 'http://localhost:3001';
const WALLET_FILE = path.join(__dirname, 'wallet-storage.json');
const TRUST_FILE  = path.join(__dirname, 'trust-registry.json');

// ── SETUP: Issuer erstellt Credentials, Wallet speichert sie ─────────────────
async function setup() {
  console.log('— Issuer-Setup (simuliert PID-Provider / Führerscheinstelle / Bank) —');
  const issuer = await jose.generateKeyPair('ES256', { extractable: true });
  const holder = await jose.generateKeyPair('ES256', { extractable: true });
  const issuerPublicJwk = await jose.exportJWK(issuer.publicKey);
  const holderPublicJwk = await jose.exportJWK(holder.publicKey);
  const holderPrivateJwk = await jose.exportJWK(holder.privateKey);

  // Drei echte, signierte SD-JWT Credentials ausstellen
  const pid = await issueCredential(issuer.privateKey, 'issuer-key-1', holderPublicJwk,
    'urn:eu.europa.ec.eudi:pid:1',
    { given_name:'Max', family_name:'Mustermann', birth_date:'1990-05-14', age_over_18:true });
  const pidUnderage = await issueCredential(issuer.privateKey, 'issuer-key-1', holderPublicJwk,
    'urn:eu.europa.ec.eudi:pid:1',
    { given_name:'Tom', family_name:'Schmidt', birth_date:'2009-07-11', age_over_18:false });
  const mdl = await issueCredential(issuer.privateKey, 'issuer-key-1', holderPublicJwk,
    'urn:eu.europa.ec.eudi:mdl:1',
    { document_number:'A1234567', driving_privileges:['B','AM'], expiry_date:'2030-05-14' });
  const iban = await issueCredential(issuer.privateKey, 'issuer-key-1', holderPublicJwk,
    'urn:eu.europa.ec.eudi:iban:1',
    { iban:'DE89370400440532013000', bank_name:'Commerzbank', verified:true });

  fs.writeFileSync(WALLET_FILE, JSON.stringify({ holderPrivateJwk, credentials:{ pid, pidUnderage, mdl, iban } }, null, 2));
  fs.writeFileSync(TRUST_FILE, JSON.stringify({ issuerPublicJwk }, null, 2));
  console.log('✅ 4 SD-JWT Credentials ausgestellt (ES256-signiert)');
  console.log('✅ wallet-storage.json  (Wallet des Nutzers)');
  console.log('✅ trust-registry.json  (Vertrauensanker für die RP)');
}

// ── PRESENT: Der "Freigeben"-Klick der echten App ────────────────────────────
async function present(sessionId, scenario = 'success') {
  const store = JSON.parse(fs.readFileSync(WALLET_FILE));
  const holderKey = await jose.importJWK(store.holderPrivateJwk, 'ES256');

  // 1. Request Object holen (wie beim QR-Scan)
  const reqUri = `${API}/api/wallet/request/${sessionId}`;
  console.log(`[Wallet] Hole Request Object: ${reqUri}`);
  const reqJwt = await (await fetch(reqUri)).text();

  // 2. RP-Signatur prüfen (echte Wallet prüft gegen Trust Registry)
  const jwks = await (await fetch(`${API}/api/rp-jwks`)).json();
  const rpKey = await jose.importJWK(jwks.keys[0], 'ES256');
  const { payload: reqObj } = await jose.jwtVerify(reqJwt, rpKey);
  console.log(`[Wallet] RP-Signatur ✓  | client_id: ${reqObj.client_id}`);
  console.log(`[Wallet] Angefragt: ${reqObj.presentation_definition.input_descriptors.map(d=>d.name).join(', ')}`);

  // 3. VP Tokens erzeugen — echte Kryptographie mit Nonce + Key Binding
  const c = store.credentials;
  const vp_tokens = {};
  const pidCred = scenario === 'underage' ? c.pidUnderage : c.pid;
  vp_tokens.pid = await createPresentation(pidCred, ['given_name','family_name','age_over_18'], holderKey, reqObj.nonce, reqObj.client_id);
  if (scenario !== 'no_license' && scenario !== 'underage') {
    vp_tokens.mdl = await createPresentation(c.mdl, ['driving_privileges','expiry_date'], holderKey, reqObj.nonce, reqObj.client_id);
  }
  vp_tokens.iban = await createPresentation(c.iban, ['iban','verified'], holderKey, reqObj.nonce, reqObj.client_id);
  console.log(`[Wallet] ${Object.keys(vp_tokens).length} VP Tokens erstellt (Szenario: ${scenario})`);

  // 4. Zurücksenden (direct_post)
  const r = await fetch(reqObj.response_uri, {
    method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({ state: reqObj.state, vp_tokens }),
  });
  const result = await r.json();
  console.log('[Wallet] Antwort der RP:', JSON.stringify(result.verificationLog || result, null, 2));
}

const [,, cmd, arg1, arg2] = process.argv;
if (cmd === 'setup') setup();
else if (cmd === 'present' && arg1) present(arg1, arg2 || 'success');
else console.log('Nutzung: node test-wallet.js setup | present <sessionId> [success|no_license|underage]');
