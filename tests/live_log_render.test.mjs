// Render di Live Log e Diagnostica con un DOM finto: verifica che le colonne
// mappate, il dettaglio evento, i controlli rapidi e gli export vedano lo stesso
// evento e diano gli stessi numeri. Nessuna rete: il fetch iniettato solleva.
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import assert from 'node:assert';

const html_path = fileURLToPath(new URL('../frontend/index.html', import.meta.url));
const src = readFileSync(html_path, 'utf-8');
const script = src.slice(src.indexOf('<script>') + 8, src.lastIndexOf('</script>'));

const els = new Map();
const makeEl = id => ({
  id, value: '', textContent: '', innerHTML: '', className: '', style: {},
  addEventListener() {}, dispatchEvent() {}, appendChild() {}, click() {}, querySelectorAll: () => [],
});
const document = {
  getElementById: id => { if (!els.has(id)) els.set(id, makeEl(id)); return els.get(id); },
  querySelectorAll: () => [],
  createElement: () => makeEl('tmp'),
};
const store = new Map();
const localStorage = {
  getItem: k => (store.has(k) ? store.get(k) : null),
  setItem: (k, v) => store.set(k, String(v)),
  removeItem: k => store.delete(k),
};
const sessionStorage = { getItem: () => null, setItem() {}, removeItem() {} };
const window = { location: { href: '' } };

const run = new Function('document', 'localStorage', 'sessionStorage', 'window', 'setInterval', 'clearInterval', 'fetch', 'confirm', 'alert',
  script + '\nreturn { renderSessions, renderDiagnosis, EVENT_COLUMNS, toggleColumn, lastChecks, checkSummary, diagConfig };');
const app = run(document, localStorage, sessionStorage, window, () => 0, () => {},
  async () => { throw new Error('nessuna rete nei test'); }, () => true, () => {});

// Evento RICOSTRUITO dai valori attesi dichiarati dall'utente: non è il payload
// originale di ISE. Se i nomi dei campi reali differiscono, va aggiornato qui.
const GUEST = {
  passed: 'true', failed: 'false', user_name: '00:0C:29:46:F3:B8',
  calling_station_id: '00:0C:29:46:F3:B8', nas_ip_address: '10.1.1.1', nas_port_id: 'Gi1/0/1',
  authentication_method: 'mab', authentication_protocol: 'Lookup',
  identity_store: 'Internal Endpoints', acs_server: 'ISE-PSN-DMZ-2',
  selected_azn_profiles: 'GuestDem-Redirect-Pol-2', response_time: '13',
  other_attr_string: [
    'AuthenticationStatus=AuthenticationPassed',
    'IdentityPolicyMatchedRule=Wireless MAB',
    'AuthorizationPolicyMatchedRule=GuestDemanio-Auth-ISE02',
    'ISEPolicySetName=SSID Guest Agenzie',
    'EndPointPolicy=Unknown',
    'Response={cisco-av-pair=url-redirect-acl=CWA_REDIRECT_ENTRATE_02; '
      + 'cisco-av-pair=url-redirect=https://psn.example.local:8443/portal/gateway?sessionId=1&token=SEGRETO; }',
  ].join(':!:'),
};

app.renderSessions([GUEST]);
const html = document.getElementById('ll-results').innerHTML;
for (const expected of ['Successo', 'Wireless MAB', 'GuestDemanio-Auth-ISE02', 'mab', 'Lookup',
                        'Diagnostica', '0 avvisi', 'CWA_REDIRECT_ENTRATE_02', 'token=***']) {
  assert.ok(html.includes(expected), 'manca nella tabella Live Log: ' + expected);
}
assert.ok(!html.includes('token=SEGRETO'), 'il token non deve comparire in chiaro');

// Le colonne opzionali non sono nell'intestazione finché non le si attiva, ma
// restano sempre tutte e dieci nel dettaglio evento.
const thead = h => h.slice(h.indexOf('<thead>'), h.indexOf('</thead>'));
assert.ok(!thead(html).includes('Identity Store'), 'Identity Store non è fra le prime cinque colonne');
assert.ok(html.includes('Identity Store'), 'Identity Store deve restare nel dettaglio evento');

app.toggleColumn('store', true);
const html2 = document.getElementById('ll-results').innerHTML;
assert.ok(thead(html2).includes('Identity Store'), 'la colonna attivata deve comparire dopo il refresh');
assert.ok(html2.includes('Internal Endpoints'), 'la colonna attivata deve mostrare il valore');
app.toggleColumn('store', false);

// Un evento senza attributi non deve rompere il render né inventare un esito.
app.renderSessions([{ user_name: 'ignoto' }]);
const empty = document.getElementById('ll-results').innerHTML;
assert.ok(empty.includes('Indeterminato'), 'senza passed/failed l’esito resta Indeterminato');
assert.ok(!/Successo|Fallimento/.test(empty), 'un evento senza dati non deve mostrare un esito');

// Live Log e Diagnostica leggono lo stesso riepilogo: stesso numero di avvisi.
app.renderSessions([GUEST]);
const warnings = app.checkSummary(GUEST, app.diagConfig(), [GUEST]).warnings;
assert.ok(document.getElementById('ll-results').innerHTML.includes(`${warnings} avvisi`),
  'il badge del Live Log deve riportare gli stessi avvisi del riepilogo');

app.renderDiagnosis('00:0C:29:46:F3:B8',
  { sessions: [GUEST], authRecords: [], endpointCtx: null, switchOutput: null, switchError: null });
const diag = document.getElementById('diag-result').innerHTML;
for (const expected of [`Controlli rapidi (${warnings} anomalie`, 'Redirect al portale restituito.',
                        'Internal Endpoints', 'ISE-PSN-DMZ-2', 'GuestDem-Redirect-Pol-2',
                        'SSID Guest Agenzie', 'token=***']) {
  assert.ok(diag.includes(expected), 'manca in Diagnostica: ' + expected);
}
assert.ok(!diag.includes('token=SEGRETO'), 'il token non deve comparire in Diagnostica');

console.log('live log + diagnostica render ok');
