/**
 * Passcreator-Anbindung: erzeugt eine Apple/Google-Wallet-Karte zur Police.
 * https://developer.passcreator.com/en/api/v3/pass
 */
const FIELD_KENNZEICHEN = '6a2a6a80adb7a7.95340218';
const FIELD_VERSICHERUNGSNR = '6a2a6a80adb860.94634519';
const FIELD_VORNAME = '6a2a6a80adb899.11243033';
const FIELD_NACHNAME = '6a2a6a80adb8b4.30308411';

const isConfigured = () => !!process.env.PASSCREATOR_API_KEY;

async function createWalletPass({ optIn, kennzeichen, versicherungsnummer, vorname, nachname }) {
  const apiKey = process.env.PASSCREATOR_API_KEY;
  if (!apiKey) throw new Error('PASSCREATOR_API_KEY fehlt (.env)');
  const templateId = optIn ? process.env.PASSCREATOR_OPTIN_TEMPLATE_ID : process.env.PASSCREATOR_OPTOUT_TEMPLATE_ID;
  if (!templateId) throw new Error(`Passcreator ${optIn ? 'Optin' : 'Optout'}-Template-ID fehlt (.env)`);
  const baseUrl = process.env.PASSCREATOR_BASE_URL || 'https://app-de.passcreator.com';

  const res = await fetch(`${baseUrl}/api/v3/pass`, {
    method: 'POST',
    headers: { Authorization: apiKey, 'Content-Type': 'application/json' },
    body: JSON.stringify({
      data: {
        templateId,
        [FIELD_KENNZEICHEN]: kennzeichen,
        [FIELD_VERSICHERUNGSNR]: versicherungsnummer,
        [FIELD_VORNAME]: vorname,
        [FIELD_NACHNAME]: nachname,
      },
    }),
  });

  const out = await res.json().catch(() => ({}));
  if (!res.ok || !out.success) throw new Error(out.description || `Passcreator HTTP ${res.status}`);
  return out.data; // { identifier, downloadPage, iPhoneUri, ... }
}

module.exports = { createWalletPass, isConfigured };
