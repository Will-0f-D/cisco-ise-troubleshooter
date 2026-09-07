// Self-check per il modello evento ISE di frontend/index.html (esito, attributi,
// redirect, MAC, check rapidi). Il blocco condiviso viene estratto dal sorgente
// reale e non copiato, così il test fallisce se la logica nel file cambia.
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

// Il modello evento è un blocco marcato: si esegue tutto intero, così ogni funzione
// nuova che ci finisce dentro è automaticamente sotto test senza toccare questa lista.
const REGION_START = '// ===== MODELLO EVENTO ISE (inizio) =====';
const REGION_END = '// ===== MODELLO EVENTO ISE (fine) =====';
const a = src.indexOf(REGION_START), b = src.indexOf(REGION_END);
assert.ok(a !== -1 && b > a, 'blocco "MODELLO EVENTO ISE" non trovato in index.html');
const region = src.slice(a, b + REGION_END.length);
assert.ok(!/\$\(|document\.|fetch\(|localStorage/.test(region),
  'il modello evento deve restare puro: niente DOM, rete o storage nel blocco condiviso');
assert.ok(region.includes('const NOT_AVAILABLE = null;'), 'NOT_AVAILABLE non e piu null in index.html');

const helpers = [
  region,
  grab('function isWireless(s)'),
  grab('function authStatusOf(rec)'),
  grab('function indexCatalog(catalog)'),
  grab('let policyCatalog = ') + ';',
  grab('function configuredRule('),
].join('\n');

const api = new Function(helpers + `
  return { sessionOutcome, isWireless, authStatusOf, policyOf, profilesOf, authMethodOf, authProtocolOf,
           identityStoreOf, iseNodeOf, responseTimeOf, parseAttrString, attrModel, otherAttrs,
           parseResponseAttrs, responseAttrs, responseValues, requestAttrEntries, normMac, maskToken,
           redirectInfo, stepLatencies, eventChecks, checkSummary, indexCatalog, configuredRule,
           setCatalog: c => { policyCatalog = c; } };`)();
const { sessionOutcome, isWireless, authStatusOf, policyOf, profilesOf, authMethodOf, authProtocolOf,
        identityStoreOf, iseNodeOf, responseTimeOf, parseAttrString, attrModel, otherAttrs,
        parseResponseAttrs, responseAttrs, responseValues, requestAttrEntries, normMac, maskToken,
        redirectInfo, stepLatencies, eventChecks, checkSummary, indexCatalog, configuredRule } = api;

const checkById = (checks, id) => checks.find(c => c.id === id);

// ---- Esito ----
// Tabella dell'esito: solo passed/failed, stringhe o booleani reali.
// L'XML MNT arriva appiattito in stringhe: "false" non deve passare per vero.
assert.equal(sessionOutcome({ passed: 'true', failed: 'false' }), 'ok');
assert.equal(sessionOutcome({ passed: 'false', failed: 'true' }), 'err');
assert.equal(sessionOutcome({ passed: 'false', failed: 'false' }), 'unknown');
assert.equal(sessionOutcome({ passed: 'true', failed: 'true' }), 'conflict');
assert.equal(sessionOutcome({ passed: true, failed: false }), 'ok');
assert.equal(sessionOutcome({ passed: false, failed: true }), 'err');
assert.equal(sessionOutcome({ passed: false, failed: false }), 'unknown');
assert.equal(sessionOutcome({ passed: true, failed: true }), 'conflict');
// Spazi e maiuscole non contano.
assert.equal(sessionOutcome({ passed: ' TRUE ', failed: '\tFalse' }), 'ok');
// Campo assente, nullo o non booleano: indeterminato, mai un successo presunto.
assert.equal(sessionOutcome({ passed: 'true' }), 'unknown');
assert.equal(sessionOutcome({ passed: 'true', failed: null }), 'unknown');
assert.equal(sessionOutcome({ passed: 'true', failed: '' }), 'unknown');
assert.equal(sessionOutcome({ passed: '1', failed: '0' }), 'unknown');
assert.equal(sessionOutcome({ passed: 'yes', failed: 'no' }), 'unknown');
// Session/ActiveList non espone l'esito: indeterminato, non fallito.
assert.equal(sessionOutcome({ user_name: 'x' }), 'unknown');
// L'esito non si deduce da altri campi: session_status, il blob degli attributi
// o i profili di autorizzazione descrivono altro.
assert.equal(sessionOutcome({ session_status: 'AUTHENTICATED' }), 'unknown');
assert.equal(sessionOutcome({ session_status: 'DISCONNECTED' }), 'unknown');
assert.equal(sessionOutcome({ other_attributes_parsed: { AuthenticationStatus: 'AuthenticationPassed' } }), 'unknown');
assert.equal(sessionOutcome({ selected_azn_profiles: 'PermitAccess', message_code: '5200' }), 'unknown');

assert.equal(isWireless({ nas_port_type: 'Wireless - IEEE 802.11' }), true);
assert.equal(isWireless({ nas_port_type: 'Ethernet' }), false);
assert.equal(isWireless({ cisco_av_pair: 'ssid=CorpWiFi' }), true);
assert.equal(isWireless({ user_name: 'x' }), null);

assert.equal(authStatusOf({ passed: 'false' }), 'failed');
assert.equal(authStatusOf({ passed: 'true' }), 'passed');
assert.equal(authStatusOf({ status: 'Failed' }), 'failed');

// ---- other_attr_string: delimitatore ":!:" e primo "=" ----
const attrs = parseAttrString('A=1:!:B=x=y:!:C=ore 10:30:!:D=:!:senza uguale:!:=nokey');
assert.equal(attrs.A, '1');
assert.equal(attrs.B, 'x=y', 'si spezza solo al primo =');
assert.equal(attrs.C, 'ore 10:30', 'i due punti dentro il valore restano');
assert.equal(attrs.D, '', 'un valore vuoto e un dato, non un attributo assente');
assert.ok(!('senza uguale' in attrs));
assert.equal(Object.keys(attrs).length, 4, 'nessuna chiave vuota');
assert.deepEqual(parseAttrString(undefined), {});
assert.equal(parseAttrString('Rule=  spazi interni  e coda ').Rule, '  spazi interni  e coda ',
  'il valore non viene tagliato: gli spazi interni fanno parte del dato');

// ---- Modello attributi: strutturato, chiavi piatte, blob, provenienza ----
assert.equal(policyOf({ other_attributes: { ISEPolicySetName: 'Wired' } }).policySet, 'Wired',
  'other_attributes puo arrivare come oggetto');
assert.equal(policyOf({ 'other_attributes.ISEPolicySetName': 'Wired' }).policySet, 'Wired',
  'other_attributes puo arrivare come chiavi piatte');
assert.equal(policyOf({ other_attr_string: 'ISEPolicySetName=Wired' }).policySet, 'Wired',
  'fallback sul blob quando manca la forma strutturata');

// Due rappresentazioni discordi: vince quella strutturata e la discrepanza resta visibile.
const CONFLICT = {
  other_attributes_parsed: { AuthorizationPolicyMatchedRule: 'Corp' },
  other_attributes_sources: { AuthorizationPolicyMatchedRule: 'other_attributes' },
  other_attr_string: 'AuthorizationPolicyMatchedRule=Guest',
};
assert.equal(policyOf(CONFLICT).authz, 'Corp');
assert.deepEqual(attrModel(CONFLICT).conflicts,
  [{ key: 'AuthorizationPolicyMatchedRule', structured: 'Corp', blob: 'Guest' }]);
// Discrepanza gia' rilevata dal backend: non viene persa ne duplicata.
const BACKEND_CONFLICT = {
  other_attributes_parsed: { UseCase: 'Host Lookup' },
  other_attributes_conflicts: [{ key: 'UseCase', other_attributes: 'Host Lookup', other_attr_string: 'Framed' }],
};
assert.deepEqual(attrModel(BACKEND_CONFLICT).conflicts,
  [{ key: 'UseCase', structured: 'Host Lookup', blob: 'Framed' }]);
// Stesso valore nelle due rappresentazioni: nessuna discrepanza da segnalare.
assert.deepEqual(attrModel({
  other_attributes_parsed: { UseCase: 'Host Lookup' },
  other_attr_string: 'UseCase=Host Lookup',
}).conflicts, []);
// La provenienza accompagna ogni attributo.
const PROV = { other_attributes_parsed: { A: '1' }, other_attributes_sources: { A: 'other_attributes' }, other_attr_string: 'B=2' };
assert.deepEqual(requestAttrEntries(PROV), [['A', '1', 'other_attributes'], ['B', '2', 'other_attr_string']]);

// ---- Attributi della risposta: i ripetuti non si perdono ----
const RESP = '{UserName=guest; Class=CACS:abc:ISE/1/2; cisco-av-pair=url-redirect-acl=CWA_ACL; '
  + 'cisco-av-pair=url-redirect=https://psn.example.local:8443/portal/gateway?sessionId=abc&token=SEGRETO123; }';
const pairs = parseResponseAttrs(RESP);
assert.equal(pairs.filter(([k]) => k === 'cisco-av-pair').length, 2,
  'due cisco-av-pair distinti: un dizionario a valore singolo ne perderebbe uno');
assert.deepEqual(pairs[1], ['Class', 'CACS:abc:ISE/1/2'], 'il valore conserva i due punti interni');
assert.equal(pairs[2][1], 'url-redirect-acl=CWA_ACL', 'il valore conserva gli = interni');
assert.deepEqual(parseResponseAttrs(''), []);
assert.deepEqual(parseResponseAttrs(undefined), []);
assert.equal(responseValues({ response: RESP }, 'username')[0], 'guest');

// ---- MAC: forma diversa non e identita diversa ----
assert.equal(normMac('00:0c:29:46:f3:b8'), '00:0C:29:46:F3:B8');
assert.equal(normMac('00-0C-29-46-F3-B8'), '00:0C:29:46:F3:B8');
assert.equal(normMac('000c.2946.f3b8'), '00:0C:29:46:F3:B8');
assert.equal(normMac('000C2946F3B8'), '00:0C:29:46:F3:B8');
assert.equal(normMac('guest01'), null);
assert.equal(normMac('00:0C:29:46:F3'), null, 'MAC incompleto non e un MAC');
assert.equal(normMac('0a2b3c4d0000012A5F6E7D8C'), null, 'un session id non e un MAC');
assert.equal(normMac(''), null);
assert.equal(normMac(undefined), null);

// ---- Token mascherato ovunque venga mostrato o esportato ----
assert.equal(maskToken('https://p/gw?sessionId=1&token=SEGRETO123'), 'https://p/gw?sessionId=1&token=***');
assert.equal(maskToken('https://p/gw?token=SEGRETO&next=1'), 'https://p/gw?token=***&next=1');
assert.equal(maskToken('nessun token qui'), 'nessun token qui');

// ---- Evento guest ----
// ATTENZIONE: il payload grezzo dell'esempio non era disponibile, questa fixture e'
// RICOSTRUITA dai risultati attesi indicati dall'utente usando i nomi di campo
// documentati dello schema MNT. Va riallineata sul payload originale anonimizzato.
const GUEST_RESPONSE = '{UserName=00:0C:29:46:F3:B8; State=ReauthSession:0a2b3c4d; Class=CACS:0a2b3c4d:ISE-PSN-DMZ-2/123/456; '
  + 'cisco-av-pair=url-redirect-acl=CWA_REDIRECT_ENTRATE_02; '
  + 'cisco-av-pair=url-redirect=https://ise-psn-dmz-2.example.local:8443/portal/gateway?sessionId=0a2b3c4d&portal=abcd&token=SEGRETOPORTALE; }';
const GUEST_EVENT = {
  passed: 'true', failed: 'false',
  user_name: '00:0C:29:46:F3:B8',
  calling_station_id: '00:0C:29:46:F3:B8',
  orig_calling_station_id: '00-0c-29-46-f3-b8',
  authentication_method: 'mab',
  authentication_protocol: 'Lookup',
  identity_store: 'Internal Endpoints',
  acs_server: 'ISE-PSN-DMZ-2',
  selected_azn_profiles: 'GuestDem-Redirect-Pol-2',
  response_time: '13',
  other_attr_string: [
    'AuthenticationStatus=AuthenticationPassed',
    'IdentityPolicyMatchedRule=Wireless MAB',
    'AuthorizationPolicyMatchedRule=GuestDemanio-Auth-ISE02',
    'ISEPolicySetName=SSID Guest Agenzie',
    'IdentitySelectionMatchedRule=Wireless MAB',
    'EndPointMACAddress=00-0C-29-46-F3-B8',
    'EndPointPolicy=Unknown',
    'IdentityGroup=GuestEndpoints',
    'UseCase=Host Lookup',
    'StepLatency=3=12,5=40',
    'TotalAuthenLatency=55',
    'ClientLatency=0',
    'CPMSessionID=0a2b3c4d0000012A5F6E7D8C',
    'Response=' + GUEST_RESPONSE,
  ].join(':!:'),
};

// I dieci campi mappati, uno per riga della tabella richiesta.
assert.equal(sessionOutcome(GUEST_EVENT), 'ok');
assert.equal(policyOf(GUEST_EVENT).authn, 'Wireless MAB');
assert.equal(policyOf(GUEST_EVENT).authz, 'GuestDemanio-Auth-ISE02');
assert.equal(authMethodOf(GUEST_EVENT), 'mab');
assert.equal(authProtocolOf(GUEST_EVENT), 'Lookup');
assert.equal(policyOf(GUEST_EVENT).policySet, 'SSID Guest Agenzie');
assert.deepEqual(profilesOf(GUEST_EVENT), ['GuestDem-Redirect-Pol-2']);
assert.equal(identityStoreOf(GUEST_EVENT), 'Internal Endpoints');
assert.equal(iseNodeOf(GUEST_EVENT), 'ISE-PSN-DMZ-2');
assert.equal(responseTimeOf(GUEST_EVENT), '13');
// Nodo ISE: acs_server, con fallback a server dello schema ridotto.
assert.equal(iseNodeOf({ server: 'ISE-PSN-DMZ-1' }), 'ISE-PSN-DMZ-1');
assert.equal(iseNodeOf({ acs_server: 'A', server: 'B' }), 'A');
assert.equal(iseNodeOf({ user_name: 'x' }), null);

// Il profilo non e la regola, e IdentitySelectionMatchedRule non e la regola di
// autenticazione: coincidono spesso, ma non sono lo stesso dato.
assert.equal(policyOf({ other_attributes_parsed: { IdentitySelectionMatchedRule: 'Wireless MAB' } }).authn, null);
assert.equal(policyOf({ selected_azn_profiles: 'GuestDem-Redirect-Pol-2' }).authz, null);
assert.equal(policyOf({ other_attributes_parsed: { ISEPolicySetName: 'SSID Guest Agenzie' } }).authz, null);

// Redirect: URL e ACL vengono dalla risposta, il token non compare mai in chiaro.
const rd = redirectInfo(GUEST_EVENT);
assert.equal(rd.source, 'risposta');
assert.equal(rd.acl, 'CWA_REDIRECT_ENTRATE_02');
assert.equal(rd.host, 'ise-psn-dmz-2.example.local');
assert.equal(rd.port, '8443');
assert.ok(rd.masked.includes('token=***'));
assert.ok(!rd.masked.includes('SEGRETOPORTALE'));
assert.equal(responseValues(GUEST_EVENT, 'cisco-av-pair').length, 2);

// StepLatency: indici e durate, ordinati dal piu lento.
assert.deepEqual(stepLatencies(GUEST_EVENT), [{ step: '5', value: 40 }, { step: '3', value: 12 }]);
assert.deepEqual(stepLatencies({ user_name: 'x' }), []);

// ---- Check rapidi sull'evento guest ----
const guestChecks = eventChecks(GUEST_EVENT);
assert.equal(guestChecks.length, 13);
for (const c of guestChecks) {
  assert.ok(['info', 'warn', 'insufficient'].includes(c.level), 'livello inatteso: ' + c.level);
  assert.ok(c.title && c.result, 'ogni check ha titolo e risultato');
  assert.ok(Array.isArray(c.evidence) && c.evidence.length, 'ogni check porta gli attributi che lo giustificano');
  assert.ok(!JSON.stringify(c).includes('SEGRETOPORTALE'), 'il token non deve comparire nelle evidenze');
}
assert.equal(checkSummary(GUEST_EVENT).warnings, 0, 'evento guest coerente: nessuna anomalia');
assert.equal(checkById(guestChecks, 'outcome').level, 'info');
assert.equal(checkById(guestChecks, 'redirect').result, 'Redirect al portale restituito.');
assert.ok(!/login|navigaz/i.test(checkById(guestChecks, 'redirect').result),
  'il redirect restituito non significa login guest completato');
assert.equal(checkById(guestChecks, 'redirect-partial').level, 'info');
assert.ok(/coerenti dopo normalizzazione/.test(checkById(guestChecks, 'identity').result));
assert.equal(checkById(guestChecks, 'identity').level, 'info', 'maiuscole e separatori diversi non sono un anomalia');
assert.equal(checkById(guestChecks, 'profiling').level, 'info');
assert.ok(/informazione/.test(checkById(guestChecks, 'profiling').result), 'Unknown e informativo, non un errore');
assert.equal(checkById(guestChecks, 'timing').level, 'info', 'senza soglia configurata nessun tempo e "alto"');
assert.ok(/non verificabile/i.test(checkById(guestChecks, 'steps').evidence.map(e => e[1]).join(' ')),
  'senza corrispondenza verificata gli indici non si traducono in passaggi');
assert.equal(checkById(guestChecks, 'repetition').level, 'insufficient', 'senza storico non si deducono ripetizioni');
assert.equal(checkById(guestChecks, 'not-verifiable').level, 'insufficient');
assert.ok(/ACL|CoA|DNS/.test(checkById(guestChecks, 'not-verifiable').result));

// Redirect a meta: da verificare, non "configurazione errata".
const HALF = { response: '{cisco-av-pair=url-redirect=https://p:8443/gw?token=X; }' };
const halfChecks = eventChecks(HALF);
assert.equal(checkById(halfChecks, 'redirect-partial').level, 'warn');
assert.ok(/da verificare/.test(checkById(halfChecks, 'redirect-partial').result));
assert.ok(/non è detto/i.test(checkById(halfChecks, 'redirect-partial').next),
  'il controllo suggerito non deve affermare che la configurazione sia errata');

// Esito dichiarato in contraddizione con passed/failed: avviso, esito invariato.
const CONTRA = { passed: 'true', failed: 'false', other_attr_string: 'AuthenticationStatus=AuthenticationFailed' };
assert.equal(sessionOutcome(CONTRA), 'ok', 'il check non cambia l esito');
assert.equal(checkById(eventChecks(CONTRA), 'outcome').level, 'warn');

// Scostamento dalla policy solo se un atteso e configurato.
assert.equal(checkById(eventChecks(GUEST_EVENT, { expected: { authz: 'Altra-Regola' } }), 'policy').level, 'warn');
assert.equal(checkById(eventChecks(GUEST_EVENT, { expected: {} }), 'policy').level, 'info');
// MAB al posto di 802.1X: anomalia solo dove dot1x e l'atteso configurato.
assert.equal(checkById(eventChecks(GUEST_EVENT, { expected: { method: 'dot1x' } }), 'method').level, 'warn');
assert.equal(checkById(eventChecks(GUEST_EVENT), 'method').level, 'info');
// Soglia sui tempi: nessun limite inventato, solo quello configurato.
assert.equal(checkById(eventChecks(GUEST_EVENT, { responseTimeWarn: 10 }), 'timing').level, 'warn');

// Identificativi di sessione: differenza evidenziata, causa non presunta.
const IDS = { ...GUEST_EVENT, audit_session_id: '0A2B3C4D0000099ABCDEF012' };
const corr = checkById(eventChecks(IDS), 'correlation');
assert.equal(corr.level, 'warn');
assert.ok(/da verificare/.test(corr.result));
assert.ok(!/errat|sbagliat/i.test(corr.result), 'mai dichiarare automaticamente la sessione sbagliata');
assert.ok(corr.evidence.some(([k]) => k === 'other_attributes.CPMSessionID'));
assert.ok(corr.evidence.some(([k]) => k === 'audit_session_id'));

// Storico: alternanza successo/fallimento vicina nel tempo e' un indizio, non una causa.
const t = '2026-09-07 10:00:00';
const HIST = [
  { acs_timestamp: '2026-09-07 10:01:00', passed: 'false', failed: 'true' },
  { acs_timestamp: '2026-09-07 10:02:00', passed: 'true', failed: 'false' },
  { acs_timestamp: '2026-09-07 10:03:00', passed: 'false', failed: 'true' },
];
const rep = checkById(eventChecks({ ...GUEST_EVENT, acs_timestamp: t }, null, HIST), 'repetition');
assert.equal(rep.level, 'warn');
assert.ok(/Indizi/.test(rep.result));

// Dati mancanti: nessun check inventa un fallimento.
const emptyChecks = eventChecks({});
assert.equal(emptyChecks.length, 13);
assert.equal(emptyChecks.filter(c => c.level === 'warn').length, 0,
  'un evento senza dati non produce anomalie, produce "dati insufficienti"');

// ---- Payload reale gia' verificato (WiFi PEAP) ----
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

assert.deepEqual(profilesOf({ selected_azn_profiles: 'PermitAccess, Corp_VLAN' }), ['PermitAccess', 'Corp_VLAN']);
assert.equal(profilesOf({ dacl: 'ACL-X', vlan: '10' }), null, 'dacl/vlan non sono un profilo di autorizzazione');

// ---- Correlazione con la configurazione: solo per nome, disambiguata dal policy set ----
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
