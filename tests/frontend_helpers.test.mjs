// Self-check per gli helper puri di frontend/index.html (esito autenticazione e
// wired/wireless). Le funzioni vengono estratte dal sorgente reale, non copiate,
// così il test fallisce se la logica nel file cambia.
// Uso: node tests/frontend_helpers.test.mjs
import assert from 'node:assert';
import { readFileSync } from 'node:fs';

const src = readFileSync(new URL('../frontend/index.html', import.meta.url), 'utf-8');

// Estrae una dichiarazione bilanciando le graffe: le regex si fermano alla prima
// '}' annidata e producono sorgente troncato.
function grab(header) {
  const start = src.indexOf(header);
  assert.notEqual(start, -1, 'helper non trovato in index.html: ' + header);
  let i = src.indexOf('{', start), depth = 0;
  for (; i < src.length; i++) {
    if (src[i] === '{') depth++;
    else if (src[i] === '}' && --depth === 0) return src.slice(start, i + 1);
  }
  throw new Error('graffe non bilanciate per ' + header);
}

const helpers = [
  grab('function isTrue(v)'),
  'const SESSION_OK_STATES = ' + src.match(/const SESSION_OK_STATES = (\[[^\]]*\]);/)[1] + ';',
  grab('function sessionOutcome(s)'),
  grab('function isWireless(s)'),
  grab('function authStatusOf(rec)'),
  'const NOT_AVAILABLE = null;',  // asserito sotto contro il sorgente
  grab('function otherAttrs(s)'),
  grab('function firstValue('),
  grab('function matchKey('),
  grab('function policyOf(s)'),
  grab('function authMethodOf(s)'),
  grab('function authProtocolOf(s)'),
  grab('function profilesOf(s)'),
  grab('function indexCatalog(catalog)'),
  grab('let policyCatalog = ') + ';',
  grab('function configuredRule('),
].join('\n');

assert.ok(src.includes('const NOT_AVAILABLE = null;'), 'NOT_AVAILABLE non e piu null in index.html');

const api = new Function(helpers + `
  return { sessionOutcome, isWireless, authStatusOf, policyOf, profilesOf, authMethodOf, authProtocolOf, indexCatalog, configuredRule,
           setCatalog: c => { policyCatalog = c; } };`)();
const { sessionOutcome, isWireless, authStatusOf, policyOf, profilesOf, authMethodOf, authProtocolOf,
        indexCatalog, configuredRule } = api;

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

// Policy: tag XML dedicato quando c'è, altrimenti il blob other_attributes.
assert.deepEqual(
  policyOf({ identity_policy_matched_rule: 'Dot1X', authorization_policy: 'Corp' }),
  { policySet: null, authn: 'Dot1X', authz: 'Corp', serviceSelection: null });
assert.deepEqual(
  policyOf({ other_attributes_parsed: { IdentityPolicyMatchedRule: 'Default', AuthorizationPolicyMatchedRule: 'CWA', ISEPolicySetName: 'Wired' } }),
  { policySet: 'Wired', authn: 'Default', authz: 'CWA', serviceSelection: null });
// Campo assente != "nessuna policy": deve restare distinguibile.
assert.equal(policyOf({ user_name: 'x' }).authz, null);
// Stringa vuota dall'XML vale come assente, non come nome di regola.
assert.equal(policyOf({ authorization_policy: '   ' }).authz, null);

// Nomi non previsti dalla whitelist ma inequivocabili nella forma: ISE cambia i tag
// tra endpoint e versioni, quindi vanno letti lo stesso.
assert.equal(policyOf({ authorization_policy_matched_rule: 'Corp' }).authz, 'Corp');
assert.equal(policyOf({ AuthenticationPolicyMatchedRule: 'Dot1X' }).authn, 'Dot1X');
assert.equal(policyOf({ other_attributes_parsed: { PolicySetName: 'Wired' } }).policySet, 'Wired');
// La ricerca per forma non deve rubare il campo sbagliato.
assert.equal(policyOf({ authorization_policy_matched_rule: 'Corp' }).authn, null);
assert.equal(policyOf({ identity_store: 'AD', identity_group: 'Corp' }).authn, null);

// Payload reale riportato dall'utente: i nomi delle regole arrivano dentro
// other_attributes e contengono spazi e trattini.
const REALE = {
  other_attributes_parsed: {
    IdentityPolicyMatchedRule: 'WiFi PEAP - SDA Mobile-Workstation - AuthC',
    AuthorizationPolicyMatchedRule: 'WiFi_Dipendenti_PEAP_Mobile',
  },
  authentication_method: 'dot1x',
  authentication_protocol: 'PEAP (EAP-MSCHAPv2)',
};
assert.equal(policyOf(REALE).authn, 'WiFi PEAP - SDA Mobile-Workstation - AuthC');
assert.equal(policyOf(REALE).authz, 'WiFi_Dipendenti_PEAP_Mobile');
assert.equal(authMethodOf(REALE), 'dot1x');
assert.equal(authProtocolOf(REALE), 'PEAP (EAP-MSCHAPv2)');
// Nomi alternativi secondo endpoint/versione.
assert.equal(authProtocolOf({ authen_protocol: 'PEAP (EAP-MSCHAPv2)' }), 'PEAP (EAP-MSCHAPv2)');
assert.equal(authProtocolOf({ eap_authentication: 'EAP-MSCHAPv2' }), 'EAP-MSCHAPv2');
assert.equal(authMethodOf({ user_name: 'x' }), null);
assert.equal(authProtocolOf({ user_name: 'x' }), null);

assert.deepEqual(profilesOf({ selected_azn_profiles: 'PermitAccess, Corp_VLAN' }), ['PermitAccess', 'Corp_VLAN']);
assert.equal(profilesOf({ dacl: 'ACL-X', vlan: '10' }), null, 'dacl/vlan non sono un profilo di autorizzazione');

// Correlazione con la configurazione: solo per nome, disambiguata dal policy set.
const catalog = {
  policy_sets: [
    { name: 'Wired', state: 'enabled', authentication: [{ name: 'Dot1X', state: 'enabled' }], authorization: [{ name: 'Corp', state: 'disabled' }] },
    { name: 'Wireless', state: 'enabled', authentication: [{ name: 'Dot1X', state: 'disabled' }], authorization: [] },
  ],
};
api.setCatalog({ state: 'ready', index: indexCatalog(catalog) });
assert.equal(configuredRule('authz', 'Corp', 'Wired').rule.state, 'disabled');
assert.equal(configuredRule('authn', 'Dot1X', 'Wireless').rule.state, 'disabled');
assert.equal(configuredRule('authn', 'Dot1X', null).status, 'ambiguous');
assert.equal(configuredRule('authz', 'Sparita', 'Wired').status, 'missing');
// Uno stato di configurazione non va mai dedotto senza catalogo pronto.
api.setCatalog({ state: 'error', index: null });
assert.equal(configuredRule('authz', 'Corp', 'Wired'), null);

console.log('frontend helpers self-check ok');
