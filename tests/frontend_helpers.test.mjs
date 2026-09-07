// Self-check per gli helper puri di frontend/index.html (esito autenticazione e
// wired/wireless). Le funzioni vengono estratte dal sorgente reale, non copiate,
// così il test fallisce se la logica nel file cambia.
// Uso: node tests/frontend_helpers.test.mjs
import assert from 'node:assert';
import { readFileSync } from 'node:fs';

const src = readFileSync(new URL('../frontend/index.html', import.meta.url), 'utf-8');

function grab(pattern) {
  const m = src.match(pattern);
  assert.ok(m, 'helper non trovato in index.html: ' + pattern);
  return m[0];
}

const helpers = [
  grab(/function isTrue\(v\) \{[^}]*\}/),
  grab(/const SESSION_OK_STATES = \[[^\]]*\];/),
  grab(/function sessionOutcome\(s\) \{[\s\S]*?\n\}/),
  grab(/function isWireless\(s\) \{[\s\S]*?\n\}/),
  grab(/function authStatusOf\(rec\) \{[\s\S]*?\n\}/),
].join('\n');

const { sessionOutcome, isWireless, authStatusOf } =
  new Function(helpers + '\nreturn { sessionOutcome, isWireless, authStatusOf };')();

// L'XML MNT arriva appiattito in stringhe: "false" non deve passare per vero.
assert.equal(sessionOutcome({ passed: 'true', failed: 'false' }), 'ok');
assert.equal(sessionOutcome({ passed: 'false', failed: 'true' }), 'err');
assert.equal(sessionOutcome({ passed: true }), 'ok');
assert.equal(sessionOutcome({ session_status: 'AUTHENTICATED' }), 'ok');
assert.equal(sessionOutcome({ session_status: 'DISCONNECTED' }), 'err');
// Session/ActiveList non espone l'esito: indeterminato, non fallito.
assert.equal(sessionOutcome({ user_name: 'x' }), 'unknown');

assert.equal(isWireless({ nas_port_type: 'Wireless - IEEE 802.11' }), true);
assert.equal(isWireless({ nas_port_type: 'Ethernet' }), false);
assert.equal(isWireless({ cisco_av_pair: 'ssid=CorpWiFi' }), true);
assert.equal(isWireless({ user_name: 'x' }), null);

assert.equal(authStatusOf({ passed: 'false' }), 'failed');
assert.equal(authStatusOf({ passed: 'true' }), 'passed');
assert.equal(authStatusOf({ status: 'Failed' }), 'failed');

console.log('frontend helpers self-check ok');
