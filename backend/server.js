/**
 * EUDI Wallet POC – Backend (Pure Node.js, keine externen Dependencies)
 * Simuliert vollständigen OpenID4VP Flow:
 *   1. Frontend startet Session  → erhält RequestURI + QR-Code-Daten
 *   2. Wallet-Simulator scannt   → bestätigt oder lehnt ab
 *   3. Frontend pollt Status     → erhält Ergebnis sobald Wallet geantwortet hat
 *   4. Backend validiert Claims  → gibt Versicherungsentscheid zurück
 */

const http  = require('http');
const https = require('https');
const crypto = require('crypto');
const fs    = require('fs');
const path  = require('path');
const url   = require('url');

const PORT = 3001;

// ── In-Memory Session Store ───────────────────────────────────────────────────
// { sessionId: { status, claims, vehicleData, created, expires } }
const sessions = new Map();

// Session-Cleanup alle 5 Minuten
setInterval(() => {
  const now = Date.now();
  for (const [id, s] of sessions) {
    if (s.expires < now) sessions.delete(id);
  }
}, 5 * 60 * 1000);

// ── Mock EUDI Wallet Claims (SD-JWT simuliert) ────────────────────────────────
const MOCK_CLAIMS = {
  success: {
    pid: { given_name:'Max', family_name:'Mustermann', birth_date:'1990-05-14',
           age_over_18:true, issuing_country:'DE', doc_number:'DE-PID-88234711' },
    mdl: { doc_number:'A1234567', expiry_date:'2030-05-14',
           categories:['B','AM'], issuing_country:'DE' },
    iban: { iban:'DE89370400440532013000', bic:'COBADEFFXXX',
            bank_name:'Commerzbank', verified:true },
  },
  no_license: {
    pid: { given_name:'Anna', family_name:'Müller', birth_date:'1995-03-20',
           age_over_18:true, issuing_country:'DE', doc_number:'DE-PID-77123456' },
    mdl: null,
    iban: { iban:'DE12500105170648489890', bic:'INGDDEFFXXX',
            bank_name:'ING', verified:true },
  },
  underage: {
    pid: { given_name:'Tom', family_name:'Schmidt', birth_date:'2009-07-11',
           age_over_18:false, issuing_country:'DE', doc_number:'DE-PID-66789012' },
    mdl: null,
    iban: { iban:'DE75512108001245126199', verified:false },
  },
};

// ── CORS-Helper ───────────────────────────────────────────────────────────────
function setCors(res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
}

// ── JSON Response Helper ──────────────────────────────────────────────────────
function json(res, status, data) {
  setCors(res);
  res.writeHead(status, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(data, null, 2));
}

// ── Static File Helper ────────────────────────────────────────────────────────
function serveStatic(res, filePath) {
  const ext = path.extname(filePath);
  const types = { '.html':'text/html', '.js':'application/javascript',
                  '.css':'text/css', '.json':'application/json' };
  const ct = types[ext] || 'text/plain';
  try {
    const content = fs.readFileSync(filePath);
    setCors(res);
    res.writeHead(200, { 'Content-Type': ct });
    res.end(content);
  } catch {
    res.writeHead(404); res.end('Not found');
  }
}

// ── Body Reader ───────────────────────────────────────────────────────────────
function readBody(req) {
  return new Promise((resolve, reject) => {
    let body = '';
    req.on('data', d => body += d);
    req.on('end', () => {
      try { resolve(body ? JSON.parse(body) : {}); }
      catch { resolve({}); }
    });
    req.on('error', reject);
  });
}

// ── Claim-Validierung ─────────────────────────────────────────────────────────
function validateClaims(claims) {
  const checks = {};

  // Alter >= 18
  checks.ageOver18 = {
    passed: !!(claims.pid && claims.pid.age_over_18 === true),
    value:  claims.pid?.birth_date || null,
    source: 'PID (Personalausweis)',
    label:  'Alter ≥ 18 Jahre',
  };

  // Führerschein Klasse B
  const licValid = claims.mdl &&
                   claims.mdl.categories?.includes('B') &&
                   new Date(claims.mdl.expiry_date) > new Date();
  checks.driversLicense = {
    passed: !!licValid,
    value:  claims.mdl?.categories?.join(', ') || 'Kein Führerschein',
    source: 'mDL (Mobile Driving Licence)',
    label:  'Führerschein Klasse B',
  };

  // IBAN valide
  const ibanOk = claims.iban?.verified === true &&
                 /^[A-Z]{2}\d{2}/.test((claims.iban?.iban || '').replace(/\s/g,''));
  checks.ibanValid = {
    passed: !!ibanOk,
    value:  claims.iban?.iban ? maskIban(claims.iban.iban) : 'Keine IBAN',
    source: 'EAA (European Account Attestation)',
    label:  'Valide IBAN',
  };

  return checks;
}

function maskIban(iban) {
  const c = iban.replace(/\s/g,'');
  return c.substring(0,4) + '****' + c.substring(c.length-4);
}

// ══════════════════════════════════════════════════════════════════════════════
// HTTP SERVER
// ══════════════════════════════════════════════════════════════════════════════
const server = http.createServer(async (req, res) => {
  const parsed = url.parse(req.url, true);
  const pathname = parsed.pathname;
  const method = req.method;

  // Preflight
  if (method === 'OPTIONS') { setCors(res); res.writeHead(204); res.end(); return; }

  // ── Statische Dateien ─────────────────────────────────────────────────────
  if (method === 'GET' && !pathname.startsWith('/api/')) {
    const fp = pathname === '/' ? 'index.html' : pathname.slice(1);
    const full = path.join(__dirname, '../frontend', fp);
    serveStatic(res, full);
    return;
  }

  // ── API: POST /api/wallet/start-auth ──────────────────────────────────────
  if (method === 'POST' && pathname === '/api/wallet/start-auth') {
    const body = await readBody(req);
    const sessionId = crypto.randomUUID();
    const nonce     = crypto.randomBytes(16).toString('hex');
    const expires   = Date.now() + 10 * 60 * 1000; // 10 Minuten

    sessions.set(sessionId, {
      status:      'pending',   // pending | approved | rejected | verified
      claims:      null,
      vehicleData: body.vehicleData || {},
      scenario:    body.scenario || 'success',
      nonce,
      created:     Date.now(),
      expires,
    });

    // OpenID4VP Request URI (wie es in Produktion aussähe)
    const requestUri = `openid4vp://authorize?` +
      `response_type=vp_token` +
      `&client_id=oev-insurance-poc` +
      `&response_uri=http://localhost:${PORT}/api/wallet/callback` +
      `&presentation_definition_uri=http://localhost:${PORT}/api/presentation-definition/${sessionId}` +
      `&nonce=${nonce}` +
      `&state=${sessionId}`;

    console.log(`[START-AUTH] Session: ${sessionId} | Scenario: ${body.scenario || 'success'}`);

    return json(res, 200, {
      sessionId,
      nonce,
      requestUri,
      walletSimulatorUrl: `http://localhost:${PORT}/wallet-simulator.html?session=${sessionId}`,
      requestedClaims: ['pid.age_over_18', 'pid.birth_date', 'mdl.categories', 'mdl.expiry_date', 'iban.verified'],
    });
  }

  // ── API: GET /api/presentation-definition/:sessionId ──────────────────────
  // (Wie Relying Party in Produktion die Presentation Definition bereitstellt)
  if (method === 'GET' && pathname.startsWith('/api/presentation-definition/')) {
    const sessionId = pathname.split('/').pop();
    if (!sessions.has(sessionId)) return json(res, 404, { error: 'Session not found' });

    return json(res, 200, {
      id: `pd-${sessionId}`,
      input_descriptors: [
        { id: 'pid', name: 'Personalausweis', format: { 'vc+sd-jwt': {} },
          constraints: { fields: [{ path: ['$.age_over_18'], filter: { type: 'boolean', const: true } }] } },
        { id: 'mdl', name: 'Führerschein', format: { 'vc+sd-jwt': {} },
          constraints: { fields: [{ path: ['$.document_type'], filter: { type: 'string', const: 'mDL' } }] } },
        { id: 'iban', name: 'Bankverbindung', format: { 'vc+sd-jwt': {} },
          constraints: { fields: [{ path: ['$.verified'], filter: { type: 'boolean', const: true } }] } },
      ],
    });
  }

  // ── API: POST /api/wallet/callback ────────────────────────────────────────
  // Wallet-Simulator schickt die Claims hierher (simuliert VP Token Response)
  if (method === 'POST' && pathname === '/api/wallet/callback') {
    const body = await readBody(req);
    const { state: sessionId, action, scenario } = body;

    if (!sessions.has(sessionId)) return json(res, 404, { error: 'Session not found' });

    const session = sessions.get(sessionId);

    if (action === 'reject') {
      session.status = 'rejected';
      console.log(`[CALLBACK] Session ${sessionId}: REJECTED by user`);
      return json(res, 200, { ok: true, status: 'rejected' });
    }

    // Claims aus gewähltem Szenario injizieren (simuliert VP Token)
    const sc = scenario || session.scenario || 'success';
    session.claims  = MOCK_CLAIMS[sc] || MOCK_CLAIMS.success;
    session.status  = 'approved';
    session.scenario = sc;
    console.log(`[CALLBACK] Session ${sessionId}: APPROVED | Scenario: ${sc}`);

    return json(res, 200, { ok: true, status: 'approved' });
  }

  // ── API: GET /api/wallet/status/:sessionId ────────────────────────────────
  if (method === 'GET' && pathname.startsWith('/api/wallet/status/')) {
    const sessionId = pathname.split('/').pop();
    if (!sessions.has(sessionId)) return json(res, 404, { error: 'Session not found' });

    const session = sessions.get(sessionId);

    if (session.status === 'pending') {
      return json(res, 200, { status: 'pending', message: 'Warte auf Wallet-Bestätigung...' });
    }

    if (session.status === 'rejected') {
      sessions.delete(sessionId);
      return json(res, 200, { status: 'rejected', message: 'Nutzer hat Freigabe abgelehnt.' });
    }

    if (session.status === 'approved') {
      // Claims validieren
      session.status = 'verified';
      const checks = validateClaims(session.claims);
      const allPassed = Object.values(checks).every(c => c.passed);

      let policy = null;
      if (allPassed) {
        policy = {
          policyNumber: `OEV-${new Date().getFullYear()}-${Math.floor(10000 + Math.random() * 90000)}`,
          holder: `${session.claims.pid.given_name} ${session.claims.pid.family_name}`,
          vehicle: session.vehicleData,
          coverage: 'Teilkasko',
          annualPremium: 348,
          selfRetention: 300,
          validFrom: new Date().toISOString().split('T')[0],
          paymentMethod: maskIban(session.claims.iban?.iban || 'DE00000000000000000000'),
          walletVerified: true,
          issuedAt: new Date().toISOString(),
        };
      }

      return json(res, 200, {
        status: allPassed ? 'success' : 'failed',
        checks,
        policy,
        holder: session.claims.pid ? {
          name: `${session.claims.pid.given_name} ${session.claims.pid.family_name}`,
        } : null,
        message: allPassed
          ? 'Alle Claims verifiziert. Versicherungsabschluss genehmigt.'
          : 'Prüfung fehlgeschlagen. Versicherung kann nicht abgeschlossen werden.',
      });
    }

    return json(res, 200, { status: session.status });
  }

  // ── API: GET /api/health ──────────────────────────────────────────────────
  if (method === 'GET' && pathname === '/api/health') {
    return json(res, 200, {
      status: 'ok',
      service: 'EUDI Wallet POC Backend',
      version: '2.0.0',
      engine: 'Pure Node.js (no dependencies)',
      activeSessions: sessions.size,
      timestamp: new Date().toISOString(),
      flow: 'OpenID4VP (simulated)',
      tokenFormat: 'SD-JWT (simulated)',
    });
  }

  // 404
  res.writeHead(404); res.end('Not found');
});

server.listen(PORT, () => {
  console.log('');
  console.log('  ╔═══════════════════════════════════════════════╗');
  console.log('  ║  EUDI Wallet POC – Backend v2.0               ║');
  console.log(`  ║  http://localhost:${PORT}                          ║`);
  console.log('  ║  Pure Node.js – keine externen Dependencies   ║');
  console.log('  ╚═══════════════════════════════════════════════╝');
  console.log('');
  console.log('  Demo:             http://localhost:3001/');
  console.log('  Wallet Simulator: http://localhost:3001/wallet-simulator.html');
  console.log('  Health:           http://localhost:3001/api/health');
  console.log('');
});
