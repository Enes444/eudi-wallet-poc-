/**
 * End-to-End-Test: Vollständiger OpenID4VP-Flow mit echter Kryptographie
 * + Sicherheitstests (Manipulation, Replay-Angriff)
 */
const jose = require('jose');
const fs = require('fs');
const { createPresentation, verifyPresentation } = require('./sdjwt');
const API = 'http://localhost:3001';

const results = [];
const test = (name, ok, detail='') => { results.push({name, ok, detail}); console.log(`  ${ok?'✅':'❌'} ${name}${detail?' — '+detail:''}`); };

async function startSession(scenario) {
  const r = await (await fetch(`${API}/api/wallet/start-auth`, { method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({ vehicleData:{plate:'B-XY 1234',make:'VW',model:'Golf 8'}, scenario }) })).json();
  return r;
}
async function walletPresent(sessionId, scenario) {
  const store = JSON.parse(fs.readFileSync('./wallet-storage.json'));
  const holderKey = await jose.importJWK(store.holderPrivateJwk, 'ES256');
  const reqJwt = await (await fetch(`${API}/api/wallet/request/${sessionId}`)).text();
  const jwks = await (await fetch(`${API}/api/rp-jwks`)).json();
  const rpKey = await jose.importJWK(jwks.keys[0], 'ES256');
  const { payload: reqObj } = await jose.jwtVerify(reqJwt, rpKey);
  const c = store.credentials;
  const vp_tokens = {};
  const pidCred = scenario==='underage' ? c.pidUnderage : c.pid;
  vp_tokens.pid = await createPresentation(pidCred, ['given_name','family_name','age_over_18'], holderKey, reqObj.nonce, reqObj.client_id);
  if (scenario!=='no_license' && scenario!=='underage')
    vp_tokens.mdl = await createPresentation(c.mdl, ['driving_privileges','expiry_date'], holderKey, reqObj.nonce, reqObj.client_id);
  vp_tokens.iban = await createPresentation(c.iban, ['iban','verified'], holderKey, reqObj.nonce, reqObj.client_id);
  await fetch(reqObj.response_uri, { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ state: reqObj.state, vp_tokens }) });
  return { reqObj, vp_tokens };
}
async function getStatus(id) { return await (await fetch(`${API}/api/wallet/status/${id}`)).json(); }

(async () => {
  console.log('\n══════ E2E-TESTS: Echter OpenID4VP + SD-JWT Flow ══════\n');

  // TEST 1: Erfolgsfall — alle Credentials, Police wird ausgestellt
  console.log('TEST 1 — Erfolgsfall (alle Credentials gültig)');
  let s = await startSession('success');
  test('QR-Code generiert (echt scanbar)', !!s.qrCodeDataUrl && s.qrCodeDataUrl.startsWith('data:image/png'));
  test('OpenID4VP-URI standardkonform', s.openid4vpUri.startsWith('openid4vp://authorize?client_id='));
  await walletPresent(s.sessionId, 'success');
  let st = await getStatus(s.sessionId);
  test('Alle 3 Checks kryptographisch bestanden', st.status==='success');
  test('Police ausgestellt', !!st.policy?.policyNumber, st.policy?.policyNumber);
  test('Verifikationslog: 3× verified', st.verificationLog?.filter(v=>v.verified).length===3);

  // TEST 2: Kein Führerschein
  console.log('\nTEST 2 — Szenario: Kein Führerschein');
  s = await startSession('no_license');
  await walletPresent(s.sessionId, 'no_license');
  st = await getStatus(s.sessionId);
  test('Abschluss abgelehnt', st.status==='failed');
  test('mDL-Check fehlgeschlagen, andere OK', !st.checks.driversLicense.passed && st.checks.ageOver18.passed && st.checks.ibanValid.passed);

  // TEST 3: Minderjährig
  console.log('\nTEST 3 — Szenario: Minderjährig');
  s = await startSession('underage');
  await walletPresent(s.sessionId, 'underage');
  st = await getStatus(s.sessionId);
  test('Abschluss abgelehnt', st.status==='failed');
  test('Alters-Check fehlgeschlagen (age_over_18=false, echt signiert)', !st.checks.ageOver18.passed);

  // TEST 4: SICHERHEIT — Manipulierte Disclosure muss erkannt werden
  console.log('\nTEST 4 — SICHERHEIT: Manipulationserkennung');
  const store = JSON.parse(fs.readFileSync('./wallet-storage.json'));
  const trust = JSON.parse(fs.readFileSync('./trust-registry.json'));
  const issuerPub = await jose.importJWK(trust.issuerPublicJwk, 'ES256');
  const holderKey = await jose.importJWK(store.holderPrivateJwk, 'ES256');
  // Gültige Präsentation bauen, dann eine Disclosure fälschen (age_over_18: false → true)
  const fakeDisc = Buffer.from(JSON.stringify(['fakesalt','age_over_18',true])).toString('base64url');
  const validVp = await createPresentation(store.credentials.pidUnderage, ['age_over_18'], holderKey, 'test-nonce', 'test-aud');
  const parts = validVp.split('~');
  const tampered = [parts[0], fakeDisc, parts[parts.length-1]].join('~');
  let caught = false;
  try { await verifyPresentation(tampered, issuerPub, 'test-nonce', 'test-aud'); }
  catch(e) { caught = true; test('Gefälschte Disclosure erkannt & abgelehnt', true, e.message); }
  if (!caught) test('Gefälschte Disclosure erkannt & abgelehnt', false, 'MANIPULATION NICHT ERKANNT!');

  // TEST 5: SICHERHEIT — Replay-Angriff (falsche Nonce)
  console.log('\nTEST 5 — SICHERHEIT: Replay-Schutz');
  let replayCaught = false;
  try { await verifyPresentation(validVp, issuerPub, 'ANDERE-nonce', 'test-aud'); }
  catch(e) { replayCaught = true; test('Replay-Angriff (Nonce-Mismatch) abgewehrt', true, e.message); }
  if (!replayCaught) test('Replay-Angriff abgewehrt', false, 'REPLAY NICHT ERKANNT!');

  // TEST 6: SICHERHEIT — Fremder Issuer wird abgelehnt
  console.log('\nTEST 6 — SICHERHEIT: Unbekannter Aussteller');
  const fakeIssuer = await jose.generateKeyPair('ES256');
  const { issueCredential } = require('./sdjwt');
  const holderJwk = await jose.exportJWK(await jose.importJWK(store.holderPrivateJwk,'ES256')).catch(()=>store.holderPrivateJwk);
  const fakeCred = await issueCredential(fakeIssuer.privateKey, 'fake-key', {kty:store.holderPrivateJwk.kty,crv:store.holderPrivateJwk.crv,x:store.holderPrivateJwk.x,y:store.holderPrivateJwk.y}, 'urn:fake', { age_over_18:true });
  const fakeVp = await createPresentation(fakeCred, ['age_over_18'], holderKey, 'test-nonce', 'test-aud');
  let fakeCaught = false;
  try { await verifyPresentation(fakeVp, issuerPub, 'test-nonce', 'test-aud'); }
  catch(e) { fakeCaught = true; test('Credential von fremdem Issuer abgelehnt', true, 'Signaturprüfung schlägt fehl'); }
  if (!fakeCaught) test('Credential von fremdem Issuer abgelehnt', false, 'FREMDER ISSUER AKZEPTIERT!');

  // Zusammenfassung
  const passed = results.filter(r=>r.ok).length;
  console.log(`\n══════ ERGEBNIS: ${passed}/${results.length} Tests bestanden ══════\n`);
  process.exit(passed === results.length ? 0 : 1);
})().catch(e => { console.error('Test-Fehler:', e); process.exit(1); });
