# Development Workflow

For every coding, debugging, refactoring, or code-analysis task:

- Use Ponytail as the default development workflow.
- Use Graphify proactively to understand the codebase, relationships, dependencies, symbols, and relevant files before performing broad searches.
- Prefer Graphify over unnecessary Glob/Grep/Read exploration when the information is available from the code graph.
- Follow the Ponytail workflow throughout implementation and verification.
- Do not wait for the user to explicitly request Ponytail or Graphify.

# Riferimenti Cisco ISE (permanenti)

Documentazione di riferimento per tutte le integrazioni Cisco ISE del programma:

- **ERS / OpenAPI**: https://developer.cisco.com/docs/identity-services-engine/latest/ers-open-api-ers-open-api/
- **Recupero policy set e regole via OpenAPI**: https://www.cisco.com/c/en/us/support/docs/security/identity-services-engine-33/222404-use-openapi-to-retrieve-ise-policy-infor.html
- **MNT / troubleshooting (Session, AuthStatus, CoA)**: https://developer.cisco.com/docs/identity-services-engine/latest/using-api-calls-for-troubleshooting/

Regole per ogni nuova integrazione:

- Verificare endpoint, schema della risposta e compatibilità con la **versione ISE effettivamente in uso**. La documentazione "latest" non garantisce compatibilità con la versione installata: endpoint e campi cambiano tra major/patch.
- Non dare per scontato che un campo esista: se lo schema dell'endpoint non lo prevede, il dato è *assente*, non vuoto o negativo. Rappresentarlo come "non disponibile", mai come `disabilitato`, `negato` o `fallito`.
- Tenere separati tre piani di informazione che è facile confondere:
  1. **configurazione** delle policy (OpenAPI `policy/*`, campi `state` sul policy set e `rule.state` sulle regole);
  2. **evento** di autenticazione/sessione (MNT `Session/*`, `AuthStatus/*`) con le regole effettivamente applicate;
  3. **esito** della singola sessione (`passed`/`failed`).
  Lo stato `enabled` di una regola non significa autenticazione riuscita né accesso autorizzato, e la configurazione corrente non descrive necessariamente un evento passato.
- Le API MNT restituiscono XML con annidamenti diversi per endpoint: verificare la profondità reale dei record prima di appiattirli.