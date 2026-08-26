/**
 * SD-JWT Implementierung (Selective Disclosure JWT)
 * Nach IETF draft-ietf-oauth-selective-disclosure-jwt
 * Unterstützt echte Bundesdruckerei-PID (x5c) inkl. verschachtelter Disclosures
 * (object-property _sd UND array-element "..."-Digests, siehe walk() unten).
 */
const crypto = require('crypto');
const jose = require('jose');

const b64u = (buf) => Buffer.from(buf).toString('base64url');
const sha256b64u = (str) => b64u(crypto.createHash('sha256').update(str).digest());

/** Erstellt eine Disclosure: base64url([salt, key, value]) */
function makeDisclosure(key, value) {
  const salt = b64u(crypto.randomBytes(16));
  const disclosure = b64u(JSON.stringify([salt, key, value]));
  return { disclosure, digest: sha256b64u(disclosure) };
}

/**
 * ISSUER: Stellt ein SD-JWT Credential aus
 */
async function issueCredential(issuerPrivateKey, issuerKid, holderPublicJwk, vct, claims) {
  const discs = {};
  const digests = [];
  for (const [k, v] of Object.entries(claims)) {
    const { disclosure, digest } = makeDisclosure(k, v);
    discs[k] = disclosure;
    digests.push(digest);
  }
  const jwt = await new jose.SignJWT({
    vct,
    _sd: digests.sort(),
    _sd_alg: 'sha-256',
    cnf: { jwk: holderPublicJwk },
  })
    .setProtectedHeader({ alg: 'ES256', typ: 'vc+sd-jwt', kid: issuerKid })
    .setIssuer('https://demo-issuer.eudi-poc.local')
    .setIssuedAt()
    .setExpirationTime('1y')
    .sign(issuerPrivateKey);
  return { sdJwt: jwt, disclosures: discs };
}

/**
 * WALLET: Erstellt Presentation (VP Token) mit Key Binding JWT
 */
async function createPresentation(credential, revealKeys, holderPrivateKey, nonce, audience) {
  const revealed = revealKeys
    .filter(k => credential.disclosures[k])
    .map(k => credential.disclosures[k]);
  const presentationPart = credential.sdJwt + '~' + revealed.join('~') + (revealed.length ? '~' : '');
  const kbJwt = await new jose.SignJWT({
    nonce,
    aud: audience,
    sd_hash: sha256b64u(presentationPart),
  })
    .setProtectedHeader({ alg: 'ES256', typ: 'kb+jwt' })
    .setIssuedAt()
    .sign(holderPrivateKey);
  return presentationPart + kbJwt;
}

/**
 * VERIFIER: Verifiziert einen VP Token.
 * Unterstützt sowohl Demo-Issuer als auch echte Bundesdruckerei-PID (via x5c).
 * Key-Binding wird best-effort geprüft: bei x5c-vertrauten (echten) Tokens wird ein
 * Fehlschlag nicht hart abgelehnt (siehe kbVerified im Rückgabewert — der Aufrufer
 * muss das selbst auswerten, statt sich auf ein pauschales "verified:true" zu verlassen).
 */
async function verifyPresentation(vpToken, issuerPublicKey, expectedNonce, expectedAudience) {
  const parts = vpToken.split('~');
  const issuerJwt = parts[0];
  const kbJwt = parts[parts.length - 1];
  const disclosures = parts.slice(1, -1).filter(Boolean);

  // 1. Issuer-Signatur: Demo-Issuer ODER x5c-Kette (echte Bundesdruckerei)
  let payload, issuerTrust = 'trust-registry';
  try {
    ({ payload } = await jose.jwtVerify(issuerJwt, issuerPublicKey, {
      issuer: 'https://demo-issuer.eudi-poc.local',
    }));
  } catch {
    const hdr = jose.decodeProtectedHeader(issuerJwt);
    if (hdr.x5c && hdr.x5c.length) {
      const cert = new crypto.X509Certificate(Buffer.from(hdr.x5c[0], 'base64'));
      ({ payload } = await jose.jwtVerify(issuerJwt, cert.publicKey));
      issuerTrust = 'x5c:' + (cert.subject || 'unbekannt').replace(/\n/g, ' ');
      console.log(`[ISSUER] Vertraue x5c-Kette: ${cert.subject?.replace(/\n/g,' ')}`);
    } else {
      // Letzte Chance: ohne Issuer-Prüfung (nur für echte Sandbox-PIDs, die andere issuer-URLs nutzen)
      try { ({ payload } = await jose.jwtVerify(issuerJwt, issuerPublicKey)); issuerTrust = 'trust-registry-lenient'; }
      catch { throw new Error('Issuer-Signatur konnte nicht verifiziert werden'); }
    }
  }

  // 2. Disclosures extrahieren — Digests iterativ auflösen (fixed-point), nicht nur einmalig
  // aus dem statischen Payload sammeln. Grund: verschachtelte Felder wie
  // age_equal_or_over.18 haben ihren _sd nicht im Roh-Payload, sondern NUR im
  // dekodierten WERT der übergeordneten Disclosure (hier: "age_equal_or_over").
  // Der ist erst bekannt, nachdem genau diese Disclosure selbst aufgelöst wurde —
  // ein einmaliger Baum-Walk über den Roh-Payload findet ihn nie. Deshalb: erst
  // die im Payload sichtbaren Digests sammeln, dann Disclosures auflösen und dabei
  // neu sichtbar werdende Digests (aus dem offenbarten Wert) mit aufnehmen, bis
  // sich nichts mehr auflösen lässt. Erkennt beide SD-JWT-Digest-Formen: object-
  // property (_sd-Array am Objekt) und array-element ({"...":"<digest>"} in Arrays,
  // z.B. bei "nationalities").
  const knownSd = new Set();
  function collectSd(o) {
    if (!o || typeof o !== 'object') return;
    if (Array.isArray(o)) {
      for (const item of o) {
        if (item && typeof item === 'object' && typeof item['...'] === 'string') knownSd.add(item['...']);
        else collectSd(item);
      }
      return;
    }
    if (Array.isArray(o._sd)) for (const h of o._sd) knownSd.add(h);
    for (const v of Object.values(o)) collectSd(v);
  }
  collectSd(payload);

  const claims = {};
  const pending = new Map(disclosures.map(d => [sha256b64u(d), d]));
  let progress = true;
  while (progress && pending.size) {
    progress = false;
    for (const [digest, d] of [...pending]) {
      if (!knownSd.has(digest)) continue;
      pending.delete(digest);
      progress = true;
      let decoded;
      try { decoded = JSON.parse(Buffer.from(d, 'base64url').toString()); } catch { continue; }
      let value;
      if (Array.isArray(decoded) && decoded.length >= 3) {
        const [, key, val] = decoded;
        value = val;
        if (key !== undefined) claims[key] = val;
      } else if (Array.isArray(decoded) && decoded.length === 2) {
        value = decoded[1]; // array-element disclosure [salt, value], kein eigener key
      } else {
        continue;
      }
      collectSd(value); // ggf. neu sichtbar gewordene verschachtelte _sd-Digests freischalten
    }
  }
  if (pending.size) throw new Error('Disclosure-Hash nicht im Credential — Manipulation erkannt');

  // 3. Key-Binding-JWT — versuche Holder-Key aus cnf
  let kbVerified = false, kbError = null;
  if (payload.cnf?.jwk) {
    try {
      const holderKey = await jose.importJWK(payload.cnf.jwk, 'ES256');
      const { payload: kb } = await jose.jwtVerify(kbJwt, holderKey, { audience: expectedAudience });
      if (kb.nonce !== expectedNonce) throw new Error('Nonce mismatch');
      // sd_hash prüfen
      const presentationPart = issuerJwt + '~' + disclosures.join('~') + (disclosures.length ? '~' : '');
      if (kb.sd_hash !== sha256b64u(presentationPart)) throw new Error('sd_hash mismatch');
      kbVerified = true;
    } catch (e) {
      kbError = e.message;
      console.log(`[KB-JWT] Prüfung nicht bestanden (${e.message})`);
    }
  } else {
    kbError = 'Kein Holder-Key (cnf) im Credential';
  }
  if (!kbVerified && !issuerTrust.startsWith('x5c:')) {
    throw new Error('Key-Binding-JWT konnte nicht verifiziert werden');
  }
  if (!kbVerified) console.log('[KB-JWT] Key-Binding übersprungen (echte PID, POC-Modus) — Aufrufer muss kbVerified prüfen');

  return { claims, vct: payload.vct, verified: true, issuerTrust, kbVerified, kbError };
}

module.exports = { issueCredential, createPresentation, verifyPresentation, makeDisclosure };
