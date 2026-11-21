---
name: sbd-ai-security
description: >
  Sicurezza delle funzionalità basate su AI Security by Design: applicazioni che usano LLM, chatbot e assistenti,
  agenti con tool, RAG e vector database, server e client MCP, modelli di machine learning, classificatori e
  scoring. Usare ogni volta che si integra un modello (Claude, GPT, Gemini, Llama, Mistral o modelli locali),
  si scrive un system prompt, si espongono tool o funzioni a un modello, si indicizzano documenti per il
  retrieval, si caricano pesi di modelli o si automatizzano decisioni su persone. Copre OWASP Top 10 for LLM
  Applications 2025: prompt injection, output non validato, agency eccessiva, leakage, supply chain dei modelli,
  consumo illimitato. Trigger: "LLM", "chatbot", "agente", "RAG", "embedding", "vector", "MCP", "prompt",
  "tool calling", "function calling", "fine-tuning", "modello ML".
---

# Sicurezza delle funzionalità AI

Un modello linguistico non distingue in modo affidabile le istruzioni dai dati: qualsiasi testo che entra nel
suo contesto (una email, una pagina web, un documento recuperato, l'output di un tool) può cambiarne il
comportamento. Per questo la sicurezza di una funzionalità LLM non si ottiene "scrivendo bene il prompt", ma
**progettando il sistema intorno al modello** come se il modello fosse un componente che può essere
convinto a fare qualsiasi cosa gli sia permesso fare. La domanda di design diventa: *se il modello venisse
completamente manipolato, quale danno potrebbe fare?* Le regole sotto servono a rendere quel danno piccolo.

Queste regole si aggiungono a quelle delle altre skill: il codice intorno al modello segue `sbd-secure-coding`,
i dati inviati al modello seguono `sbd-data-protection`, i modelli e i server MCP seguono `sbd-supply-chain`.

## Regole

**SBD-AI-01 — L'output del modello è input non fidato.** Prima di usarlo validalo come qualsiasi input
esterno (SBD-CODE-01): output strutturato con schema JSON verificato, allowlist dei valori ammessi, codifica
per il contesto prima di renderizzarlo in HTML o Markdown (link e immagini nel Markdown generato possono
esfiltrare dati via URL). Mai passare l'output a `eval`, shell, query SQL, template, deserializzatori o
chiamate HTTP senza la stessa validazione richiesta per l'input di un utente.

**SBD-AI-02 — Assumi che la prompt injection riesca, e contienila.** Separa nel prompt istruzioni e dati
(delimitatori, ruoli, campi strutturati) e indica al modello che i dati non contengono istruzioni, ma non
considerarlo un controllo di sicurezza. Il contenimento è architetturale: privilegi minimi (SBD-AI-03),
conferma umana per azioni ad alto impatto, nessuna combinazione pericolosa di capacità (SBD-AI-04), filtri
sull'output. Le injection indirette arrivano da documenti recuperati, pagine web, email, ticket, nomi di file,
risultati di tool e da altri agenti.

**SBD-AI-03 — Agency minima.** Esponi al modello solo i tool necessari al caso d'uso, ciascuno con lo scopo più
stretto possibile (`get_order_status(order_id)` invece di `run_sql(query)`). I tool agiscono con l'identità e i
permessi dell'utente finale, non con un account di servizio privilegiato, e applicano l'autorizzazione
server-side a ogni chiamata (SBD-CODE-09). Le azioni irreversibili o ad alto impatto (pagamenti, rimborsi,
modifiche di dati di contatto, invio di comunicazioni esterne, cancellazioni, cambi di permessi) richiedono una
conferma esplicita dell'utente con un riepilogo generato dal sistema, non dal modello. Limita il numero di
passi e di chiamate per sessione.

**SBD-AI-04 — Mai la combinazione "dati privati + contenuto non fidato + canale di uscita" senza controlli.**
Se un agente può leggere dati riservati, riceve contenuti da fonti non fidate e può comunicare verso l'esterno
(chiamate HTTP, email, creazione di link o immagini, scrittura in sistemi condivisi), un'injection può
esfiltrare i dati. Elimina almeno uno dei tre elementi nel singolo contesto: separa gli agenti, blocca l'egress
verso destinazioni non in allowlist, richiedi conferma umana per ogni comunicazione esterna, non renderizzare
URL e immagini generati dal modello.

**SBD-AI-05 — Il system prompt non è un segreto né un controllo.** Non inserire nel prompt credenziali, chiavi,
URL interni sensibili, logica di autorizzazione o dati di altri utenti: va considerato divulgabile. Le regole
che contano (chi può vedere cosa, quali azioni sono permesse) si applicano nel codice, fuori dal modello.

**SBD-AI-06 — Controlla quali dati arrivano al modello.** Classifica i dati inviati (SBD-DATA-01). Dati C2-C3 e
dati personali solo verso provider e modelli approvati dal CISO e dal DPO, con contratto che escluda
l'addestramento sui dati, retention limitata, elaborazione in regioni UE dove richiesto. Applica redazione o
pseudonimizzazione prima dell'invio quando il dato non serve al compito. Mai PAN, SAD o segreti nel contesto
di un modello. Le chiavi API del provider stanno nel secret manager e passano da un gateway che applica quote
e log.

**SBD-AI-07 — RAG con autorizzazione al momento del retrieval.** Ogni documento indicizzato porta con sé i
metadati di autorizzazione (tenant, owner, gruppi, classificazione) e la ricerca filtra per i permessi
dell'utente **prima** di passare i risultati al modello: il modello non deve mai ricevere documenti che
l'utente non potrebbe leggere direttamente. Isola i tenant (indici o namespace separati, o filtri obbligatori
imposti dal server). Controlla cosa entra nel corpus (fonti approvate, scansione, rimozione di contenuti
nascosti come testo invisibile o istruzioni nei metadati). Embedding e vector DB ereditano la classificazione
della sorgente (SBD-DATA-14).

**SBD-AI-08 — Supply chain di modelli e dataset.** Modelli e dataset solo da fonti approvate, a versione o
hash fissato, con verifica di integrità. Formati di pesi sicuri (`safetensors`, ONNX); mai caricare pickle o
checkpoint PyTorch di provenienza non verificata (`torch.load` con `weights_only=True` come minimo). Licenza e
model card verificate. Dataset di fine-tuning con provenienza documentata e controlli contro l'avvelenamento.

**SBD-AI-09 — Limiti di consumo.** Limiti per richiesta (token in ingresso e in uscita, dimensione dei
documenti), per utente e per tenant (rate limiting, quote), timeout, numero massimo di iterazioni degli agenti,
budget di costo con alert. Previene denial of service, abuso economico ed estrazione massiva del modello.

**SBD-AI-10 — Decisioni su persone: supervisione umana e compliance.** Un output del modello non produce da solo
decisioni con effetti giuridici o significativi su una persona (concessione di credito, blocco di un conto,
rifiuto di un servizio, valutazioni di dipendenti): serve un intervento umano qualificato e la possibilità di
contestare (GDPR art. 22). Sistemi che rientrano nelle categorie ad alto rischio dell'AI Act (ad esempio la
valutazione del merito creditizio di persone fisiche) hanno obblighi specifici: fermati ed escala a Compliance
e DPO. Presenta le risposte come generate da AI e cita le fonti per ridurre l'impatto delle risposte errate.

**SBD-AI-11 — Log e monitoraggio delle interazioni.** Registra prompt, contesto recuperato (riferimenti),
chiamate ai tool con parametri ed esito, conferme dell'utente e risposte, con redazione dei dati sensibili e
retention definita. Monitora segnali di abuso: tentativi di injection, rifiuti ripetuti, uso anomalo dei tool,
picchi di consumo.

**SBD-AI-12 — Test avversariali prima del rilascio.** Una funzionalità LLM esposta a utenti o a contenuti esterni
ha una suite di test di sicurezza eseguita in CI: injection dirette e indirette (anche nei documenti del
corpus), tentativi di ottenere il system prompt, di accedere a dati di altri utenti tramite il retrieval, di
invocare tool non previsti o con parametri malevoli, di esfiltrare dati tramite link o immagini. I casi che
hanno funzionato in passato diventano test di regressione.

**SBD-AI-13 — Server MCP, plugin e tool degli agenti sono dipendenze privilegiate.** Valutali come dipendenze
(SBD-SC-01, -02, -13): fonte verificata, codice ispezionabile, versione fissata. Concedi token con scope minimo
e dedicati al server; non esporre a uno stesso agente server che insieme realizzano la combinazione di
SBD-AI-04. Le descrizioni dei tool e le risposte dei server MCP sono contenuto non fidato (possono contenere
istruzioni nascoste). I server MCP che sviluppi autenticano i client, autorizzano ogni chiamata, validano i
parametri e non inoltrano token dell'utente a servizi terzi non previsti.

## Checklist di design per una funzionalità LLM

```markdown
### Funzionalità AI
- Modello e provider: <nome, regione, contratto approvato sì/no>
- Dati inviati al modello e classificazione: <...>; redazione applicata: <...>
- Fonti di contenuto non fidato nel contesto: <utente, documenti, web, email, tool>
- Tool esposti e permessi (identità usata): <...>
- Azioni con conferma umana: <...>
- Combinazione dati privati + contenuto non fidato + uscita: <assente | presente, mitigata con ...>
- Autorizzazione nel retrieval: <come>
- Validazione dell'output: <schema, encoding>
- Limiti di consumo: <token, rate, iterazioni, budget>
- Test avversariali: <suite, esito>
```
