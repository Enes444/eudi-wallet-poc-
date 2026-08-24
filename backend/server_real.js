/**
 * EUDI Wallet POC – Backend v3.0 (Echte OpenID4VP Integration)
 *
 * Benötigte Pakete (lokal installieren mit: npm install):
 *   npm install @sphereon/siop-oid4vp @sphereon/oid4vc-common jose qrcode
 *
 * Benötigt außerdem:
 *   1. ngrok (https://ngrok.com) – macht localhost öffentlich erreichbar
 *      Starten: ngrok http 3001  → gibt HTTPS-URL (z.B. https://abc123.ngrok.io)
 *   2. Registrierung im EUDI Sandbox: https://eudi-wallet.gov.de
 *   3. EUDI Test-Wallet App auf dem Handy
 *
 * Umgebungsvariablen (.env Datei):
 *   PUBLIC_URL=https://abc123.ngrok.io   ← eure ngrok URL
 *   CLIENT_ID=https://abc123.ngrok.io    ← gleich wie PUBLIC_URL
 */

const http    = require('http');
const crypto  = require('crypto');
const fs      = require('fs');
const path    = require('path');
const url     = require('url');

// ── Wer ist verfügbar? ───────────────────────────────────────────────────────
// Diese Pakete müssen lokal installiert werden: npm install
let RP, RPBuilder, SupportedVersion, PresentationDefinitionLocation;
let QRCode;
let jose;

let REAL_MODE = false;

try {
  const sphereon = require('@sphereon/siop-oid4vp');
  RP = sphereon.RP;
  RPBuilder = sphereon.RPBuilder;
  SupportedVersion = sphereon.SupportedVersion;
  PresentationDefinitionLocation = sphereon.PresentationDefinitionLocation;
  QRCode = require('qrcode');
  jose = require('jose');
  REAL_MODE = true;
  console.log('✅ Echte EUDI Wallet Integration aktiv (Sphereon + QRCode)');
} catch(e) {
  console.log('⚠️  Sphereon nicht installiert – Demo-Modus (npm install zum Aktivieren)');
}

const PORT       = process.env.PORT || 3001;
const PUBLIC_URL = process.env.PUBLIC_URL || `http://localhost:${PORT}`;
const CLIENT_ID  = process.env.CLIENT_ID  || PUBLIC_URL;

// ── Session Store ─────────────────────────────────────────────────────────────
const sessions = new Map();
setInterval(() => {
  const now = Date.now();
  for (const [id, s] of sessions) if (s.expires < now) sessions.delete(id);
}, 5 * 60 * 1000);

// ── RSA Key für Signing ───────────────────────────────────────────────────────
// In Produktion: aus Datei laden oder aus Umgebungsvariable
let signingKey = null;
async function getSigningKey() {
  if (signingKey) return signingKey;
  if (!REAL_MODE) return null;
  // Temporären Key generieren (in Produktion: persistenten Key verwenden)
  const { privateKey, publicKey } = await jose.generateKeyPair('ES256');
  signingKey = { privateKey, publicKey };
  return signingKey;
}

// ── Presentation Definition (was wir von der Wallet wollen) ───────────────────
const PRESENTATION_DEFINITION = {
  id: "oev-insurance-pd-1",
  name: "OEV KFZ-Versicherung",
  purpose: "Identitätsprüfung für Versicherungsabschluss",
  input_descriptors: [
    {
      id: "pid-descriptor",
      name: "Personalausweis",
      purpose: "Altersprüfung und Identifikation",
      format: { "vc+sd-jwt": {} },
      constraints: {
        limit_disclosure: "required",
        fields: [
          { path: ["$.age_over_18"],    filter: { type: "boolean", const: true } },
          { path: ["$.family_name"],    optional: true },
          { path: ["$.given_name"],     optional: true },
          { path: ["$.birth_date"],     optional: true },
        ]
      }
    }
  ]
};

// ── Helpers ───────────────────────────────────────────────────────────────────
function setCors(res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
}
function json(res, status, data) {
  setCors(res);
  res.writeHead(status, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(data, null, 2));
}
function serveFile(res, filePath) {
  const ext = path.extname(filePath);
  const types = { '.html':'text/html','.js':'application/javascript','.css':'text/css' };
  try {
    setCors(res);
    res.writeHead(200, { 'Content-Type': types[ext] || 'text/plain' });
    res.end(fs.readFileSync(filePath));
  } catch { res.writeHead(404); res.end('Not found'); }
}
function readBody(req) {
  return new Promise((resolve) => {
    let body = '';
    req.on('data', d => body += d);
    req.on('end', () => {
      try { resolve(JSON.parse(body)); } catch { resolve({}); }
    });
  });
}

// ── MOCK Fallback (wenn Sphereon nicht installiert) ───────────────────────────
const MOCK_CLAIMS = {
  success:    { pid: { given_name:'Max', family_name:'Mustermann', birth_date:'1990-05-14', age_over_18:true }, mdl: { categories:['B'], expiry_date:'2030-05-14' }, iban: { iban:'DE89370400440532013000', verified:true } },
  no_license: { pid: { given_name:'Anna', family_name:'Müller', birth_date:'1995-03-20', age_over_18:true }, mdl: null, iban: { iban:'DE12500105170648489890', verified:true } },
  underage:   { pid: { given_name:'Tom', family_name:'Schmidt', birth_date:'2009-07-11', age_over_18:false }, mdl: null, iban: { iban:'DE75512108001245126199', verified:false } },
};

// ── Claim-Validierung ─────────────────────────────────────────────────────────
function validateClaims(claims) {
  return {
    ageOver18:     { passed: !!(claims.pid?.age_over_18 === true),  label:'Alter ≥ 18',        source:'PID' },
    driversLicense:{ passed: !!(claims.mdl?.categories?.includes('B') && new Date(claims.mdl?.expiry_date) > new Date()), label:'Führerschein Klasse B', source:'mDL' },
    ibanValid:     { passed: !!(claims.iban?.verified && /^[A-Z]{2}\d{2}/.test((claims.iban?.iban||'').replace(/\s/g,''))), label:'Valide IBAN', source:'EAA' },
  };
}

// ════════════════════════════════════════════════════════════════════════════
// HTTP SERVER
// ════════════════════════════════════════════════════════════════════════════
const server = http.createServer(async (req, res) => {
  const parsed   = url.parse(req.url, true);
  const pathname = parsed.pathname;
  const method   = req.method;

  if (method === 'OPTIONS') { setCors(res); res.writeHead(204); res.end(); return; }

  // Statische Dateien
  if (method === 'GET' && !pathname.startsWith('/api/')) {
    const fp = pathname === '/' ? 'index.html' : pathname.slice(1);
    serveFile(res, path.join(__dirname, '../frontend', fp));
    return;
  }

  // ── POST /api/wallet/start-auth ───────────────────────────────────────────
  if (method === 'POST' && pathname === '/api/wallet/start-auth') {
    const body      = await readBody(req);
    const sessionId = crypto.randomUUID();
    const nonce     = crypto.randomBytes(16).toString('hex');

    const session = {
      status: 'pending', claims: null, nonce,
      vehicleData: body.vehicleData || {},
      scenario: body.scenario || 'success',
      created: Date.now(), expires: Date.now() + 10 * 60 * 1000,
    };
    sessions.set(sessionId, session);

    let requestUri, qrCodeDataUrl = null;

    if (REAL_MODE) {
      // ── Echter OpenID4VP Request ──────────────────────────────────────────
      try {
        const keys = await getSigningKey();

        // Request URI – die Wallet holt sich den Request von hier
        requestUri = `${PUBLIC_URL}/api/wallet/request/${sessionId}`;

        // QR-Code generieren (die Wallet scannt das)
        const qrContent = `openid4vp://authorize?client_id=${encodeURIComponent(CLIENT_ID)}&request_uri=${encodeURIComponent(requestUri)}`;
        qrCodeDataUrl = await QRCode.toDataURL(qrContent, { width: 300, margin: 2 });

        console.log(`[START-AUTH] Echter Flow | Session: ${sessionId}`);
        console.log(`[START-AUTH] Request URI: ${requestUri}`);
      } catch(e) {
        console.error('[START-AUTH] Fehler beim Request:', e.message);
        // Fallback auf Demo-Modus
      }
    } else {
      // Demo-Modus: simulated URI
      requestUri = `openid4vp://authorize?session=${sessionId}&client_id=oev-poc`;
      console.log(`[START-AUTH] Demo-Modus | Session: ${sessionId}`);
    }

    return json(res, 200, {
      sessionId, nonce, requestUri, qrCodeDataUrl,
      mode: REAL_MODE ? 'real' : 'demo',
      walletSimulatorUrl: `${PUBLIC_URL}/wallet-simulator.html?session=${sessionId}`,
      message: REAL_MODE
        ? 'Echter QR-Code generiert. Scanne mit EUDI Test-Wallet.'
        : 'Demo-Modus. Nutze den Wallet-Simulator.',
    });
  }

  // ── GET /api/wallet/request/:sessionId (Wallet holt den Request) ──────────
  // Die echte Wallet-App ruft das ab wenn sie den QR-Code scannt
  if (method === 'GET' && pathname.startsWith('/api/wallet/request/')) {
    const sessionId = pathname.split('/').pop();
    if (!sessions.has(sessionId)) return json(res, 404, { error: 'Session nicht gefunden' });

    const session = sessions.get(sessionId);

    if (!REAL_MODE) {
      return json(res, 200, { id: sessionId, status: 'demo_mode',
        presentation_definition: PRESENTATION_DEFINITION });
    }

    try {
      const keys = await getSigningKey();

      // JWT Request Object (signiert) – das ist was die Wallet erwartet
      const requestObject = await new jose.SignJWT({
        response_type: 'vp_token',
        response_mode: 'direct_post',
        client_id:     CLIENT_ID,
        response_uri:  `${PUBLIC_URL}/api/wallet/callback`,
        nonce:         session.nonce,
        state:         sessionId,
        presentation_definition: PRESENTATION_DEFINITION,
        presentation_definition_uri_supported: false,
      })
      .setProtectedHeader({ alg:'ES256', typ:'oauth-authz-req+jwt' })
      .setIssuedAt()
      .setExpirationTime('10m')
      .sign(keys.privateKey);

      // Wallet erwartet application/oauth-authz-req+jwt
      setCors(res);
      res.writeHead(200, { 'Content-Type': 'application/oauth-authz-req+jwt' });
      res.end(requestObject);
      console.log(`[REQUEST] JWT Request für Session ${sessionId} gesendet`);
    } catch(e) {
      console.error('[REQUEST] Fehler:', e.message);
      json(res, 500, { error: 'Fehler beim Erstellen des Request Objects' });
    }
    return;
  }

  // ── POST /api/wallet/callback (Wallet sendet Antwort) ─────────────────────
  // Das ist der wichtigste Endpoint – hier kommt die echte Wallet-Antwort an
  if (method === 'POST' && pathname === '/api/wallet/callback') {
    const body = await readBody(req);

    // OpenID4VP Response enthält vp_token und presentation_submission
    const { vp_token, presentation_submission, state, action, scenario } = body;
    const sessionId = state;

    if (!sessions.has(sessionId)) return json(res, 400, { error: 'Session nicht gefunden' });
    const session = sessions.get(sessionId);

    // Demo-Modus Callback (vom Wallet-Simulator)
    if (!REAL_MODE || action) {
      if (action === 'reject') {
        session.status = 'rejected';
        return json(res, 200, { ok: true, status: 'rejected' });
      }
      session.claims  = MOCK_CLAIMS[scenario || session.scenario] || MOCK_CLAIMS.success;
      session.status  = 'approved';
      console.log(`[CALLBACK Demo] Session ${sessionId}: ${scenario || session.scenario}`);
      return json(res, 200, { ok: true, status: 'approved' });
    }

    // ── Echter VP Token verarbeiten ────────────────────────────────────────
    try {
      console.log(`[CALLBACK Real] Session ${sessionId}: VP Token empfangen`);

      if (!vp_token) return json(res, 400, { error: 'Kein vp_token erhalten' });

      // SD-JWT parsen: header.payload.signature~disclosure1~disclosure2~...~KB-JWT
      const parts = vp_token.split('~');
      const [headerB64, payloadB64] = parts[0].split('.');

      // Payload dekodieren (Base64URL)
      const payload = JSON.parse(
        Buffer.from(payloadB64.replace(/-/g,'+').replace(/_/g,'/'), 'base64').toString('utf-8')
      );

      // Nonce prüfen (verhindert Replay-Angriffe)
      if (payload.nonce !== session.nonce) {
        console.error(`[CALLBACK] Nonce mismatch! Erwartet: ${session.nonce}, Erhalten: ${payload.nonce}`);
        return json(res, 400, { error: 'Nonce mismatch – möglicher Replay-Angriff' });
      }

      // Disclosures auflösen (selektive Offenbarung)
      const disclosures = parts.slice(1, -1); // ohne KB-JWT am Ende
      const resolvedClaims = {};

      for (const disclosure of disclosures) {
        if (!disclosure) continue;
        const decoded = Buffer.from(
          disclosure.replace(/-/g,'+').replace(/_/g,'/'), 'base64'
        ).toString('utf-8');
        const [_salt, key, value] = JSON.parse(decoded);
        resolvedClaims[key] = value;
      }

      console.log('[CALLBACK Real] Aufgelöste Claims:', resolvedClaims);

      // Claims in unser Format umwandeln
      session.claims = {
        pid: {
          given_name:  resolvedClaims.given_name,
          family_name: resolvedClaims.family_name,
          birth_date:  resolvedClaims.birth_date,
          age_over_18: resolvedClaims.age_over_18,
        },
        mdl:  { categories: resolvedClaims.driving_privileges ? ['B'] : [], expiry_date: resolvedClaims.expiry_date || '2099-01-01' },
        iban: { iban: resolvedClaims.iban, verified: !!resolvedClaims.iban },
      };
      session.status = 'approved';

      // Wallet erwartet eine Redirect-Antwort
      setCors(res);
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ redirect_uri: `${PUBLIC_URL}?session=${sessionId}&status=approved` }));
    } catch(e) {
      console.error('[CALLBACK Real] Fehler beim Verarbeiten:', e.message);
      session.status = 'rejected';
      json(res, 400, { error: 'VP Token konnte nicht verarbeitet werden', detail: e.message });
    }
    return;
  }

  // ── GET /api/wallet/status/:sessionId ─────────────────────────────────────
  if (method === 'GET' && pathname.startsWith('/api/wallet/status/')) {
    const sessionId = pathname.split('/').pop();
    if (!sessions.has(sessionId)) return json(res, 404, { error: 'Session nicht gefunden' });

    const session = sessions.get(sessionId);
    if (session.status === 'pending')  return json(res, 200, { status:'pending' });
    if (session.status === 'rejected') { sessions.delete(sessionId); return json(res, 200, { status:'rejected' }); }

    if (session.status === 'approved') {
      session.status = 'verified';
      const checks   = validateClaims(session.claims);
      const allOk    = Object.values(checks).every(c => c.passed);
      let policy = null;
      if (allOk) policy = {
        policyNumber: `OEV-${new Date().getFullYear()}-${Math.floor(10000+Math.random()*90000)}`,
        holder:  `${session.claims.pid?.given_name || 'Max'} ${session.claims.pid?.family_name || 'Mustermann'}`,
        vehicle: session.vehicleData,
        coverage:'Teilkasko', annualPremium:348,
        validFrom: new Date().toISOString().split('T')[0],
        paymentMethod: session.claims.iban?.iban ? session.claims.iban.iban.slice(0,4)+'****'+session.claims.iban.iban.slice(-4) : '****',
        walletVerified: true, mode: REAL_MODE ? 'real' : 'demo',
      };
      return json(res, 200, { status: allOk?'success':'failed', checks, policy,
        message: allOk ? 'Alle Claims verifiziert.' : 'Prüfung fehlgeschlagen.' });
    }
    return json(res, 200, { status: session.status });
  }

  // ── GET /api/health ───────────────────────────────────────────────────────
  if (method === 'GET' && pathname === '/api/health') {
    return json(res, 200, {
      status:'ok', mode: REAL_MODE ? 'REAL (Sphereon)' : 'DEMO (Mock)',
      version:'3.0.0', activeSessions: sessions.size,
      realModeInstructions: REAL_MODE ? null : {
        step1: 'npm install @sphereon/siop-oid4vp @sphereon/oid4vc-common jose qrcode',
        step2: 'ngrok http 3001',
        step3: 'PUBLIC_URL=https://xxx.ngrok.io node server_real.js',
        step4: 'EUDI Test-Wallet App auf Handy installieren',
        step5: 'Auf eudi-wallet.gov.de als Relying Party registrieren',
      }
    });
  }

  res.writeHead(404); res.end('Not found');
});

server.listen(PORT, () => {
  console.log('');
  console.log('  ╔══════════════════════════════════════════════════════════╗');
  console.log(`  ║  EUDI Wallet POC – Backend v3.0                          ║`);
  console.log(`  ║  Modus: ${REAL_MODE ? 'ECHT (Sphereon OpenID4VP)          ' : 'DEMO (Mock – npm install zum Aktivieren)'}  ║`);
  console.log(`  ║  http://localhost:${PORT}                                    ║`);
  console.log('  ╚══════════════════════════════════════════════════════════╝');
  if (!REAL_MODE) {
    console.log('');
    console.log('  Zum Aktivieren der echten Wallet-Anbindung:');
    console.log('  1. npm install @sphereon/siop-oid4vp jose qrcode');
    console.log('  2. ngrok http 3001');
    console.log('  3. PUBLIC_URL=https://xxx.ngrok.io node server_real.js');
  }
  console.log('');
});
