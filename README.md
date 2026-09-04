# Cisco ISE Troubleshooter

Web app per il troubleshooting live di autenticazioni 802.1X/MAB su Cisco ISE: ricerca sessioni per MAC/username via API MNT, contesto endpoint via API ERS, CoA (Reauth/Disconnect) e comandi diagnostici via SSH sugli switch (Netmiko). Backend FastAPI + frontend HTML/JS a file singolo, nessuna build richiesta.

## Funzionalità

- **Live Log**: ricerca sessioni per MAC address, username o elenco sessioni attive; storico pass/fail delle ultime 24h con motivo di fallimento; contesto endpoint (ERS); cronologia ricerche recenti; export CSV.
- **CoA**: Reauth e Disconnect delle sessioni direttamente dai risultati, con conferma esplicita prima dell'invio.
- **Switch Console**: esecuzione comandi SSH su switch (Netmiko) con comandi rapidi predefiniti; solo comandi `show` sono permessi di default (guardrail anti config-mode), attivabile una "modalità avanzata" per gli altri comandi.
- **Diagnostica completa**: verdetto automatico che incrocia sessione ISE, storico autenticazioni, contesto ERS e output switch; export in Markdown per allegare a un ticket.
- **Log di audit locale**: ogni CoA e comando switch eseguito viene registrato su file (`backend/audit.log`) con timestamp, host/utente e comando — le password non vengono mai salvate né loggate.
- **Profili salvati**: credenziali ISE/switch salvabili in locale (browser) per riuso rapido.
- **Auto-refresh** configurabile della Live Log.

## Requisiti

- Python 3.11+
- Accesso di rete a ISE (API MNT/ERS) e agli switch (SSH)

## Avvio (da sorgente)

```bash
cd backend
python -m venv venv
venv\Scripts\activate      # Windows
pip install -r requirements.txt
python -m uvicorn main:app --port 8000
```

Poi apri http://127.0.0.1:8000. Su Windows puoi anche lanciare `avvia.bat` dalla root del progetto.

## Eseguibile standalone (Windows)

Il progetto include uno spec PyInstaller (`backend/IseTroubleshooter.spec`) per generare un `.exe` autonomo (nessun Python richiesto sulla macchina di destinazione):

```bash
cd backend
pip install pyinstaller
pyinstaller IseTroubleshooter.spec
```

L'eseguibile viene creato in `backend/dist/IseTroubleshooter.exe` e apre automaticamente il browser all'avvio.

## Struttura

```
backend/
  main.py            # route FastAPI
  ise_client.py       # client API MNT/ERS (ISE)
  switch_client.py    # client SSH switch (Netmiko)
  audit_log.py         # log di audit locale (mai password)
  run.py               # entry point per l'eseguibile PyInstaller
  tests/               # test del parsing XML
frontend/
  index.html           # UI single-page (no build step)
```

## Sicurezza

- Le password ISE/switch non vengono mai scritte su disco (log o profili): solo host e username vengono persistiti/loggati.
- I comandi switch eseguibili da console sono limitati ai comandi `show` a meno di attivare esplicitamente la modalità avanzata.
- Ogni azione CoA e ogni comando switch vengono tracciati in `backend/audit.log`.
