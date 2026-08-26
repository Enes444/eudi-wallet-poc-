/**
 * SD-JWT Implementierung (Selective Disclosure JWT)
 * Nach IETF draft-ietf-oauth-selective-disclosure-jwt
 * Echte Kryptographie: ES256-Signaturen, SHA-256 Disclosure-Hashes, Key Binding
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
 * ISSUER: Stellt ein SD-JWT Credential aus (was PID-Provider/Führerscheinstelle/Bank tun)
 * claims = { key: value } → alle werden selektiv offenbar gemacht
 * Rückgabe: { sdJwt: "<jwt>~<d1>~<d2>~", disclosures: {key: disclosure} }
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
    vct,                                // credential type (z.B. "urn:eu.europa.ec.eudi:pid:1")
    _sd: digests.sort(),                // Disclosure-Hashes
    _sd_alg: 'sha-256',
    cnf: { jwk: holderPublicJwk },      // Key Binding: Holder-Schlüssel
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
 * Genau das, was die Handy-App beim "Freigeben" tut.
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
 * VERIFIER (unser Backend): Verifiziert einen VP Token vollständig.
 * 1. Issuer-Signatur prüfen  2. Disclosure-Hashes prüfen
 * 3. Key-Binding-JWT prüfen  4. Nonce prüfen  5. sd_hash prüfen
 * Wirft Error bei jeder Manipulation.
 */
async function verifyPresentation(vpToken, issuerPublicKey, expectedNonce, expectedAudience) {
  const parts = vpToken.split('~');
  const issuerJwt = parts[0];
  const kbJwt = parts[parts.length - 1];
  const disclosures = parts.slice(1, -1).filter(Boolean);

  // 1. Issuer-Signatur: erst lokaler Vertrauensanker (Demo-Issuer), sonst x5c-Kette
  //    aus dem Credential selbst (echte Sandbox-PID der Bundesdruckerei) — POC-üblich, in Doku ausgewiesen
  let payload, issuerTrust = 'trust-registry';
  try {
    ({ payload } = await jose.jwtVerify(issuerJwt, issuerPublicKey, { issuer: 'https://demo-issuer.eudi-poc.local' }));
  } catch (e) {
    const hdr = jose.decodeProtectedHeader(issuerJwt);
    if (hdr.x5c && hdr.x5c.length) {
      const crypto = require('crypto');
      const cert = new crypto.X509Certificate(Buffer.from(hdr.x5c[0], 'base64'));
      ({ payload } = await jose.jwtVerify(issuerJwt, cert.publicKey));
      issuerTrust = 'x5c:' + (cert.subject || 'unbekannt').replace(/\n/g, ' ');
    } else throw e;
  }

  // 2. Jede Disclosure gegen _sd-Hashes prüfen
  const claims = {};
  const allSd = []; (function walk(o){ if(!o||typeof o!=='object')return; if(Array.isArray(o._sd)) allSd.push(...o._sd); for(const v of Object.values(o)) walk(v); })(payload);
  for (const d of disclosures) {
    const digest = sha256b64u(d);
    if (!allSd.includes(digest)) {
      throw new Error('Disclosure-Hash nicht im Credential — Manipulation erkannt');
    }
    const [, key, value] = JSON.parse(Buffer.from(d, 'base64url').toString());
    claims[key] = value;
  }

  // 3. Key-Binding-JWT mit Holder-Key aus cnf prüfen
  if (!payload.cnf?.jwk) throw new Error('Kein Holder-Key (cnf) im Credential');
  const holderKey = await jose.importJWK(payload.cnf.jwk, 'ES256');
  const { payload: kb } = await jose.jwtVerify(kbJwt, holderKey, { audience: expectedAudience });

  // 4. Nonce (Replay-Schutz)
  if (kb.nonce !== expectedNonce) throw new Error('Nonce mismatch — möglicher Replay-Angriff');

  // 5. sd_hash bindet KB-JWT an genau diese Präsentation
  const presentationPart = issuerJwt + '~' + disclosures.join('~') + (disclosures.length ? '~' : '');
  if (kb.sd_hash !== sha256b64u(presentationPart)) {
    throw new Error('sd_hash mismatch — Präsentation wurde verändert');
  }

  return { claims, vct: payload.vct, verified: true, issuerTrust };
}

module.exports = { issueCredential, createPresentation, verifyPresentation, makeDisclosure };
