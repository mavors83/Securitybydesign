# Template — Security Evidence (descrizione del PR)

Copia il blocco nella descrizione del PR e compila ogni voce. Scrivi "non applicabile" con il motivo quando una
voce non si applica; non cancellare le voci.

```markdown
## Security Evidence

### Contesto
- Cambiamento: <una frase>
- Dati toccati e classificazione: <entità — C0/C1/C2/C3 — etichette PII, PCI-PAN, CREDENTIAL, ...>
- Superficie esposta: <nessuna nuova | endpoint/porta/integrazione nuova: ...>
- Trust boundary attraversati: <...>

### Threat model
- Light: <minacce principali → contromisure (ID regola) → verifica>
- Full richiesto (SBD-TM-02): <no | sì → link a docs/security/threat-models/...>

### Controlli applicati
| Regola SBD | Come è applicata | Verifica |
|---|---|---|
| SBD-CODE-09 | query filtrata per tenant nel repository | test `OrderAccessTest.otherTenantIsDenied` |
| SBD-DATA-12 | campo `iban` escluso dal logger | test `LogRedactionTest` |

### Dipendenze
- Nuove o aggiornate: <nessuna | tabella da sbd-supply-chain>

### Security gate
<incolla il summary.md prodotto da run_gate.sh>

- Finding corretti: <elenco sintetico>
- Soppressioni aggiunte: <nessuna | ID, file:riga, motivazione>

### Verifiche non eseguite e rischi residui
- Non verificato: <es. scansione dei segreti in locale, delegata al job di CI>
- Rischi residui: <nessuno | descrizione, owner, eccezione SBD-EXC-..., scadenza>

### Escalation
- Security Champion / Security Engineering / DPO coinvolti: <no | chi e perché>
```
