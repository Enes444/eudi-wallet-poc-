/**
 * EUDI Wallet POC – Backend v4 (ECHTE Kryptographie)
 * OpenID4VP Relying Party mit vollständiger SD-JWT-Verifikation.
 * Start: node server_v4.js  →  http://localhost:3001
 */
const http = require('http');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const url = require('url');
const jose = require('jose');
const QRCode = require('qrcode');
const { verifyPresentation } = require('./sdjwt');
const { createWalletPass, isConfigured: passcreatorConfigured } = require('./passcreator');

// .env laden (kein Paket nötig — Werte wie der Passcreator-API-Key können & und . enthalten,
// daher hier selbst geparst statt über die Shell einzulesen)
function loadEnvFile(fp) {
  if (!fs.existsSync(fp)) return;
  for (const line of fs.readFileSync(fp, 'utf8').split('\n')) {
    const m = line.match(/^\s*([\w.-]+)\s*=\s*(.*)$/);
    if (!m || !m[1]) continue;
    if (!(m[1] in process.env)) process.env[m[1]] = m[2].trim();
  }
}
loadEnvFile(path.join(__dirname, '.env'));

const PORT = process.env.PORT || 3001;
const PUBLIC_URL = process.env.PUBLIC_URL || `http://localhost:${PORT}`;
let CLIENT_ID = PUBLIC_URL; // wird bei geladenem Registrar-Zertifikat auf das x509_hash-Schema umgestellt

const sessions = new Map();
setInterval(() => { const n = Date.now(); for (const [id,s] of sessions) if (s.expires < n) sessions.delete(id); }, 300000);

// ── Schlüssel: RP (signiert Requests) + Issuer-Vertrauensanker ────────────────
// Registrierter RP-Key (echtes Zertifikat) hat Vorrang vor dem selbstsignierten Test-Key.
// Pfade über Env-Variablen konfigurierbar, Default: ~/Desktop/eudi-rp-cert/
const RP_KEY_DIR = process.env.RP_KEY_DIR || path.join(require('os').homedir(), 'Desktop', 'eudi-rp-cert');
const RP_PRIVATE_KEY_FILE = process.env.RP_PRIVATE_KEY_FILE || path.join(RP_KEY_DIR, 'key_private.pem');
const RP_CERT_FILE = process.env.RP_CERT_FILE || path.join(RP_KEY_DIR, 'certificate-b23bf4273a1e1d03df191d02e0d783a8.crt');

let rpPrivateKey, rpPublicKey, rpCertDer, issuerPublicKey, issuerPublicJwk;
async function initKeys() {
  const envCert = process.env.RP_CERT_PEM, envKey = process.env.RP_PRIVATE_KEY_PEM;
  const certPem = envCert || (fs.existsSync(RP_CERT_FILE) ? fs.readFileSync(RP_CERT_FILE,'utf8') : null);
  const keyPem  = envKey  || (fs.existsSync(RP_PRIVATE_KEY_FILE) ? fs.readFileSync(RP_PRIVATE_KEY_FILE,'utf8') : null);
  if (certPem && keyPem) {
    rpPrivateKey = crypto.createPrivateKey(keyPem);
    rpPublicKey = crypto.createPublicKey(rpPrivateKey);
    rpCertDer = certPem.replace(/-----(BEGIN|END) CERTIFICATE-----/g, '').replace(/\s+/g, '');
    // OpenID4VP x509_hash-Schema: client_id = base64url(SHA-256 über das DER-Zertifikat)
    CLIENT_ID = 'x509_hash:' + crypto.createHash('sha256').update(Buffer.from(rpCertDer,'base64')).digest('base64url');
    console.log(`✅ Registriertes RP-Zertifikat geladen (${envCert?'ENV':'Datei'}) — client_id: ${CLIENT_ID.slice(0,32)}…`);
  } else {
    const kp = await jose.generateKeyPair('ES256');
    rpPrivateKey = kp.privateKey; rpPublicKey = kp.publicKey; rpCertDer = null;
    console.log('⚠️  Kein RP-Zertifikat gefunden — selbstsignierter Test-Key (nur für Browser-Simulator, echte Wallets lehnen ihn ab)');
  }
  // Issuer-Public-Key aus Datei (wird vom Test-Wallet / Issuer-Setup erzeugt)
  const trustFile = path.join(__dirname, 'trust-registry.json');
  if (fs.existsSync(trustFile)) {
    issuerPublicJwk = JSON.parse(fs.readFileSync(trustFile)).issuerPublicJwk;
    issuerPublicKey = await jose.importJWK(issuerPublicJwk, 'ES256');
    console.log('✅ Trust Registry geladen (Issuer-Key)');
  } else {
    console.log('⚠️  trust-registry.json fehlt — erst "node test-wallet.js setup" ausführen');
  }
}

// PID_ONLY=1: für Tests mit einer echten Sandbox-Wallet, die nur ein Test-PID
// ausstellt (Führerschein/IBAN sind fiktive Credential-Typen dieses Projekts).
const PID_ONLY = process.env.PID_ONLY === '1';

function buildPresentationDefinition(pidOnly) {
  return {
  id: 'kfz-versicherung-check',
  input_descriptors: [
    { id: 'pid',  name: 'Identität (PID)', format: { 'vc+sd-jwt': {} },
      constraints: { limit_disclosure: 'required', fields: [{ path: ['$.given_name'] }, { path: ['$.family_name'] }, { path: ['$.age_over_18'] }] } },
    ...(pidOnly ? [] : [
      { id: 'mdl',  name: 'Führerschein',    format: { 'vc+sd-jwt': {} },
        constraints: { limit_disclosure: 'required', fields: [{ path: ['$.driving_privileges'] }] } },
      { id: 'iban', name: 'Bankverbindung',  format: { 'vc+sd-jwt': {} },
        constraints: { limit_disclosure: 'required', fields: [{ path: ['$.iban'] }] } },
    ]),
  ],
  };
}
// DCQL-Query nach Developer Guide — für Anfragen an die echte Sandbox-Wallet (deutsche Test-PID)
const PID_VCT = process.env.PID_VCT || 'urn:eudi:pid:1';
const PID_VCTS = [...new Set([PID_VCT, 'urn:eudi:pid:1', 'urn:eudi:pid:de:1', 'urn:eu.europa.ec.eudi:pid:1'])];
const DCQL_PID = { credentials: [ { id:'pid', format:'dc+sd-jwt', meta:{ vct_values: PID_VCTS },
  claims: [ { path:['age_equal_or_over','18'] }, { path:['given_name'] }, { path:['family_name'] } ] } ] };
const VP_FORMATS = { 'dc+sd-jwt': { 'sd-jwt_alg_values':['ES256'], 'kb-jwt_alg_values':['ES256'] },
                     'vc+sd-jwt': { 'sd-jwt_alg_values':['ES256'], 'kb-jwt_alg_values':['ES256'] } };

const setCors = r => { r.setHeader('Access-Control-Allow-Origin','*'); r.setHeader('Access-Control-Allow-Methods','GET,POST,OPTIONS'); r.setHeader('Access-Control-Allow-Headers','Content-Type'); };
const json = (r,s,d) => { setCors(r); r.writeHead(s,{'Content-Type':'application/json'}); r.end(JSON.stringify(d,null,2)); };
const readBody = req => new Promise(res => { let b=''; req.on('data',d=>b+=d); req.on('end',()=>{
  const ct = (req.headers['content-type']||'');
  if (ct.includes('urlencoded')) return res(Object.fromEntries(new URLSearchParams(b)));
  try { res(JSON.parse(b)) } catch { try { res(Object.fromEntries(new URLSearchParams(b))) } catch { res({}) } }
}); });

function validateClaims(all, pidOnly = PID_ONLY) {
  const pid = all.pid || {}, mdl = all.mdl || {}, iban = all.iban || {};
  // Deutsche Sandbox-PID nutzt age_equal_or_over.{18}; unser Simulator age_over_18 — beide akzeptieren
  const aeo = pid.age_equal_or_over || {};
  const ageOK = pid.age_over_18 === true || aeo['18'] === true || aeo[18] === true || pid['18'] === true;
  const checks = {
    ageOver18: { passed: ageOK, label:'Alter ≥ 18', source:'PID (kryptographisch verifiziert)' },
  };
  if (!pidOnly) {
    checks.driversLicense = { passed: Array.isArray(mdl.driving_privileges) && mdl.driving_privileges.includes('B'), label:'Führerschein Klasse B', source:'mDL (kryptographisch verifiziert)' };
    checks.ibanValid = { passed: typeof iban.iban === 'string' && /^[A-Z]{2}\d{2}/.test(iban.iban.replace(/\s/g,'')), label:'Valide IBAN', source:'EAA (kryptographisch verifiziert)' };
  }
  return checks;
}

const server = http.createServer(async (req, res) => {
  const { pathname } = url.parse(req.url, true);
  if (req.method === 'OPTIONS') { setCors(res); res.writeHead(204); return res.end(); }

  // Statische Dateien
  if (req.method === 'GET' && !pathname.startsWith('/api/')) {
    const fp = path.join(__dirname, '../frontend', pathname === '/' ? 'index.html' : pathname.slice(1));
    const types = { '.html':'text/html; charset=utf-8', '.js':'application/javascript', '.css':'text/css', '.svg':'image/svg+xml', '.png':'image/png', '.ico':'image/x-icon' };
    try {
      const data = fs.readFileSync(fp);                     // erst lesen …
      setCors(res);
      res.writeHead(200, {'Content-Type': types[path.extname(fp)] || 'text/plain'});  // … dann Header
      return res.end(data);
    } catch {
      setCors(res); res.writeHead(404); return res.end('Not found');
    }
  }

  // POST /api/wallet/start-auth — Session + echter QR-Code
  if (req.method === 'POST' && pathname === '/api/wallet/start-auth') {
    const body = await readBody(req);
    const sessionId = crypto.randomUUID();
    const nonce = crypto.randomBytes(16).toString('hex');
    const pidOnly = body.pidOnly !== undefined ? !!body.pidOnly : PID_ONLY;
    let encKey = null, encPubJwk = null;
    if (pidOnly) { // echte Wallet: verschlüsselte Antwort (direct_post.jwt, ECDH-ES)
      const eph = await jose.generateKeyPair('ECDH-ES', { crv:'P-256', extractable:true });
      encKey = eph.privateKey;
      encPubJwk = { ...(await jose.exportJWK(eph.publicKey)), use:'enc', alg:'ECDH-ES', kid:'enc-'+sessionId.slice(0,8) };
    }
    sessions.set(sessionId, { status:'pending', nonce, pidOnly, encKey, encPubJwk, vehicleData: body.vehicleData||{}, walletOptIn: !!body.walletOptIn, claims:null, expires: Date.now()+600000 });

    const requestUri = `${PUBLIC_URL}/api/wallet/request/${sessionId}`;
    const openid4vpUri = `openid4vp://authorize?client_id=${encodeURIComponent(CLIENT_ID)}&request_uri=${encodeURIComponent(requestUri)}&request_uri_method=get`;
    const qrCodeDataUrl = await QRCode.toDataURL(openid4vpUri, { width: 300, margin: 2 });

    console.log(`[START] ${sessionId}`);
    return json(res, 200, { sessionId, nonce, requestUri, openid4vpUri, qrCodeDataUrl, mode:'real-crypto',
      walletSimulatorUrl: `${PUBLIC_URL}/wallet-simulator.html?session=${sessionId}` });
  }

  // GET /api/wallet/request/:id — signiertes Request Object (holt die Wallet ab)
  if (req.method === 'GET' && pathname.startsWith('/api/wallet/request/')) {
    const id = pathname.split('/').pop();
    const s = sessions.get(id);
    if (!s) return json(res, 404, { error:'Session nicht gefunden' });
    const header = { alg:'ES256', typ:'oauth-authz-req+jwt' };
    if (rpCertDer) header.x5c = [rpCertDer];
    const useDcql = s.pidOnly && !!rpCertDer; // echte Sandbox-Wallet: DCQL + x509_hash + verschlüsselte Antwort
    const query = useDcql ? { dcql_query: DCQL_PID } : { presentation_definition: buildPresentationDefinition(s.pidOnly) };
    const extra = useDcql ? {
      aud: 'https://self-issued.me/v2',
      client_metadata: {
        jwks: { keys: [s.encPubJwk] },
        vp_formats: VP_FORMATS, vp_formats_supported: VP_FORMATS,
        authorization_encrypted_response_alg:'ECDH-ES', authorization_encrypted_response_enc:'A128GCM',
      },
    } : {};
    const requestObject = await new jose.SignJWT({
      response_type:'vp_token', response_mode: useDcql ? 'direct_post.jwt' : 'direct_post',
      client_id: CLIENT_ID, response_uri: `${PUBLIC_URL}/api/wallet/callback`,
      nonce: s.nonce, state: id, ...query, ...extra,
    }).setProtectedHeader(header).setIssuedAt().setExpirationTime('10m').sign(rpPrivateKey);
    if (useDcql) console.log(`[REQUEST] DCQL-Modus (echte Wallet) für ${id}`);
    setCors(res); res.writeHead(200, {'Content-Type':'application/oauth-authz-req+jwt'});
    console.log(`[REQUEST] Signiertes Request Object für ${id} ausgeliefert`);
    return res.end(requestObject);
  }

  // GET /api/rp-jwks — Public Key der RP (damit Wallet die Signatur prüfen kann)
  if (req.method === 'GET' && pathname === '/api/rp-jwks') {
    const jwk = await jose.exportJWK(rpPublicKey);
    return json(res, 200, { keys: [ { ...jwk, alg:'ES256', use:'sig' } ] });
  }

  // POST /api/wallet/callback — VP Tokens empfangen & KRYPTOGRAPHISCH VERIFIZIEREN
  if (req.method === 'POST' && pathname === '/api/wallet/callback') {
    const body = await readBody(req);
    // direct_post.jwt: verschlüsselte Antwort entschlüsseln (JWE im Feld 'response')
    if (body.response && typeof body.response === 'string' && body.response.split('.').length === 5) {
      for (const [sid, sess] of sessions) {
        if (!sess.encKey) continue;
        try {
          const { plaintext } = await jose.compactDecrypt(body.response, sess.encKey);
          const payload = JSON.parse(Buffer.from(plaintext).toString());
          Object.assign(body, payload);
          if (!body.state) body.state = payload.state || sid;
          console.log(`[CALLBACK] Verschlüsselte Antwort entschlüsselt (Session ${sid.slice(0,8)}…)`);
          break;
        } catch { /* nächste Session probieren */ }
      }
    }
    let { state, vp_tokens, action } = body;
    const s = sessions.get(state);
    if (!s) return json(res, 400, { error:'Session nicht gefunden' });

    if (action === 'reject') { s.status='rejected'; return json(res,200,{ok:true,status:'rejected'}); }
    if (!issuerPublicKey) return json(res, 500, { error:'Trust Registry fehlt — node test-wallet.js setup' });

    // Echte Wallet (direct_post): vp_token als String / JSON-Objekt / Array (DCQL: {pid:[token]})
    let tokens = vp_tokens;
    if (!tokens && body.vp_token) {
      let vt = body.vp_token;
      if (typeof vt === 'string') { try { vt = JSON.parse(vt); } catch { /* roher SD-JWT-String */ } }
      if (typeof vt === 'string') tokens = { pid: vt };
      else if (Array.isArray(vt)) tokens = { pid: vt[0] };
      else if (vt && typeof vt === 'object') tokens = vt;
      console.log(`[CALLBACK] Echte Wallet-Antwort empfangen (${req.headers['content-type']||'?'})`);
    }
    if (tokens) for (const k of Object.keys(tokens)) if (Array.isArray(tokens[k])) tokens[k] = tokens[k][0];

    if (!tokens && action === 'approve') {
      const { createPresentation } = require('./sdjwt');
      const store = JSON.parse(fs.readFileSync(path.join(__dirname,'wallet-storage.json')));
      const holderKey = await jose.importJWK(store.holderPrivateJwk, 'ES256');
      const sc = body.scenario || 'success';
      const c = store.credentials;
      tokens = {};
      const pidCred = sc==='underage' ? c.pidUnderage : c.pid;
      tokens.pid = await createPresentation(pidCred, ['given_name','family_name','age_over_18'], holderKey, s.nonce, CLIENT_ID);
      if (sc!=='no_license' && sc!=='underage')
        tokens.mdl = await createPresentation(c.mdl, ['driving_privileges','expiry_date'], holderKey, s.nonce, CLIENT_ID);
      tokens.iban = await createPresentation(c.iban, ['iban','verified'], holderKey, s.nonce, CLIENT_ID);
      console.log(`[SIMULATOR] Echte VP Tokens erzeugt (Szenario: ${sc})`);
    }
    if (!tokens || typeof tokens !== 'object') return json(res, 400, { error:'vp_tokens fehlt' });
    const vp_tokens_final = tokens;

    // Jeden VP Token einzeln kryptographisch verifizieren
    const all = {}; const verificationLog = [];
    for (const [credType, token] of Object.entries(vp_tokens_final)) {
      try {
        const { claims } = await verifyPresentation(token, issuerPublicKey, s.nonce, CLIENT_ID);
        all[credType] = claims;
        verificationLog.push({ credType, verified: true, tokenPreview: String(token).slice(0, 28), disclosed: Object.keys(claims) });
        console.log(`[VERIFY] ${credType}: Signatur ✓ Disclosures ✓ Nonce ✓ KeyBinding ✓`);
      } catch (e) {
        verificationLog.push({ credType, verified: false, error: e.message });
        console.log(`[VERIFY] ${credType}: FEHLGESCHLAGEN — ${e.message}`);
      }
    }
    s.claims = all; s.verificationLog = verificationLog; s.status = 'approved';
    return json(res, 200, { ok:true, status:'approved', verificationLog });
  }

  // GET /api/wallet/status/:id
  if (req.method === 'GET' && pathname.startsWith('/api/wallet/status/')) {
    const id = pathname.split('/').pop();
    const s = sessions.get(id);
    if (!s) return json(res, 404, { error:'Session nicht gefunden' });
    if (s.status === 'pending')  return json(res, 200, { status:'pending' });
    if (s.status === 'rejected') { sessions.delete(id); return json(res, 200, { status:'rejected' }); }
    if (s.status === 'approved') {
      s.status = 'verified';
      const checks = validateClaims(s.claims || {}, s.pidOnly);
      const ok = Object.values(checks).every(c => c.passed);
      const policy = ok ? {
        policyNumber:`OEV-${new Date().getFullYear()}-${Math.floor(10000+Math.random()*90000)}`,
        holder:`${s.claims.pid?.given_name||''} ${s.claims.pid?.family_name||''}`.trim()||'—',
        vehicle:s.vehicleData, coverage:'Teilkasko', annualPremium:348,
        validFrom:new Date().toISOString().split('T')[0],
        paymentMethod:s.claims.iban?.iban ? s.claims.iban.iban.slice(0,4)+'****'+s.claims.iban.iban.slice(-4) : '—',
        walletVerified:true, cryptographicallyVerified:true,
      } : null;

      if (ok && passcreatorConfigured()) {
        try {
          const pass = await createWalletPass({
            optIn: s.walletOptIn,
            kennzeichen: s.vehicleData.plate || '',
            versicherungsnummer: policy.policyNumber,
            vorname: s.claims.pid?.given_name || '',
            nachname: s.claims.pid?.family_name || '',
          });
          policy.walletPass = { downloadPage: pass.downloadPage, iPhoneUri: pass.iPhoneUri };
        } catch (e) {
          console.log(`[PASSCREATOR] Fehler: ${e.message}`);
        }
      }
      return json(res, 200, { status: ok?'success':'failed', checks, policy, verificationLog: s.verificationLog });
    }
    return json(res, 200, { status:s.status });
  }

  // GET /api/health
  if (req.method === 'GET' && pathname === '/api/health') {
    return json(res, 200, { status:'ok', version:'4.0', mode:'REAL CRYPTO',
      crypto:'ES256 · SD-JWT · Disclosure-Hashes · Key Binding · Nonce',
      trustRegistry: !!issuerPublicKey, activeSessions: sessions.size });
  }

  res.writeHead(404); res.end('Not found');
});

initKeys().then(() => server.listen(PORT, () => {
  console.log(`\n  EUDI Wallet POC v4 — ECHTE KRYPTOGRAPHIE\n  http://localhost:${PORT}\n  Modus: OpenID4VP + SD-JWT Verifikation (ES256)\n`);
}));
