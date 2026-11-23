
const cookieSignature = require('cookie-signature');

const BASE_URL = 'http://localhost:3001';
const OLD_LEAKED_SECRET = 'super-secret-key'; // secret - no longer valid here
const GUESS_START = 1000;
const GUESS_END = 1050;

function forgeCookie(id) {
  const signed = cookieSignature.sign(id, OLD_LEAKED_SECRET);
  return `connect.sid=s%3A${encodeURIComponent(signed)}`;
}

async function tryId(id) {
  const cookie = forgeCookie(id);
  const res = await fetch(`${BASE_URL}/whoami`, { headers: { Cookie: cookie } });
  const data = await res.json();
  return data;
}

(async () => {
  console.log('Attempting the Phase 2 attack against the HARDENED app...');
  console.log(`Trying sess_${GUESS_START}..sess_${GUESS_END} signed with the old leaked secret.\n`);

  let hijacked = false;
  for (let i = GUESS_START; i <= GUESS_END; i++) {
    const id = `sess_${i}`;
    const data = await tryId(id);
    if (data.session && data.session.user) {
      console.log(`UNEXPECTED: hijacked session ${id} -> ${data.session.user.username}`);
      hijacked = true;
    }
  }

  if (!hijacked) {
    console.log(' Attack FAILED as expected: no sequential IDs exist, and the old secret');
    console.log('   does not match the server\'s (randomly generated, unknown) secret, so');
    console.log('   every forged cookie is rejected as an invalid signature.');
  }
})();
