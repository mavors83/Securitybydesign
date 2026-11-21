# Container e Kubernetes — configurazioni di riferimento

## Indice

1. Dockerfile hardened
2. Build senza segreti nei layer
3. Pod e Deployment in profilo restricted
4. Namespace con Pod Security Admission
5. NetworkPolicy default-deny
6. RBAC e ServiceAccount
7. Segreti
8. Admission control
9. Docker Compose per sviluppo locale
10. Scansione

## 1. Dockerfile hardened

```dockerfile
# syntax=docker/dockerfile:1
# Stage di build: toolchain completa, non arriva in produzione
FROM node:22-bookworm-slim@sha256:<digest> AS build
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --ignore-scripts
COPY . .
RUN npm run build && npm prune --omit=dev

# Stage finale: immagine minima, nessuna shell né package manager
FROM gcr.io/distroless/nodejs22-debian12:nonroot@sha256:<digest>
WORKDIR /app
COPY --from=build --chown=65532:65532 /app/dist ./dist
COPY --from=build --chown=65532:65532 /app/node_modules ./node_modules
USER 65532:65532
EXPOSE 8080
CMD ["dist/server.js"]
```

Regole:
- `FROM` sempre con digest `@sha256:`; il tag resta per leggibilità. Gli aggiornamenti del digest arrivano da
  Renovate/Dependabot.
- `USER` con UID numerico non zero nell'ultimo stage.
- Niente `ADD` da URL: scarica con `curl` e verifica il checksum, oppure usa `COPY`.
- Niente `ENV`/`ARG` con segreti (restano nella cronologia dell'immagine).
- `.dockerignore` esclude `.git`, `.env*`, chiavi, `node_modules` locali, file di test con dati.
- Per immagini con shell (es. basi `-slim`): installa solo i pacchetti necessari con versione fissata e pulisci
  le cache nello stesso `RUN`.
- Ricostruisci le immagini almeno settimanalmente anche senza modifiche al codice, per incorporare le patch.

## 2. Build senza segreti nei layer

```dockerfile
# Token del registry interno disponibile solo durante questo RUN, non salvato nell'immagine
RUN --mount=type=secret,id=npm_token,env=NPM_TOKEN \
    npm ci --ignore-scripts
```

```bash
docker buildx build --secret id=npm_token,env=NPM_TOKEN -t <registry>/payments-api:<sha> .
```

## 3. Pod e Deployment in profilo restricted

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: payments-api
  namespace: payments
  labels: { app.kubernetes.io/name: payments-api }
spec:
  replicas: 3
  selector:
    matchLabels: { app.kubernetes.io/name: payments-api }
  template:
    metadata:
      labels: { app.kubernetes.io/name: payments-api }
    spec:
      serviceAccountName: payments-api
      automountServiceAccountToken: false
      securityContext:
        runAsNonRoot: true
        runAsUser: 65532
        runAsGroup: 65532
        fsGroup: 65532
        seccompProfile: { type: RuntimeDefault }
      containers:
        - name: app
          image: <registry>/payments-api@sha256:<digest>
          ports: [{ containerPort: 8080 }]
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities: { drop: ["ALL"] }
          resources:
            requests: { cpu: 250m, memory: 256Mi }
            limits: { memory: 512Mi }
          readinessProbe: { httpGet: { path: /health/ready, port: 8080 } }
          livenessProbe: { httpGet: { path: /health/live, port: 8080 } }
          volumeMounts:
            - { name: tmp, mountPath: /tmp }
      volumes:
        - { name: tmp, emptyDir: { medium: Memory, sizeLimit: 64Mi } }
```

Vietati per i workload applicativi: `privileged: true`, `hostNetwork`, `hostPID`, `hostIPC`, `hostPath`,
`allowPrivilegeEscalation: true`, `runAsUser: 0`, aggiunta di capability (`SYS_ADMIN`, `NET_ADMIN`,
`NET_RAW`, `SYS_PTRACE`), immagini per tag mutabile (`:latest`).

## 4. Namespace con Pod Security Admission

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: payments
  labels:
    pod-security.kubernetes.io/enforce: restricted
    pod-security.kubernetes.io/enforce-version: latest
    pod-security.kubernetes.io/audit: restricted
    pod-security.kubernetes.io/warn: restricted
```

## 5. NetworkPolicy default-deny

```yaml
# Nega tutto il traffico in ingresso e in uscita per i pod del namespace
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-all
  namespace: payments
spec:
  podSelector: {}
  policyTypes: ["Ingress", "Egress"]
---
# Consente il DNS verso kube-dns
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-dns
  namespace: payments
spec:
  podSelector: {}
  policyTypes: ["Egress"]
  egress:
    - to:
        - namespaceSelector:
            matchLabels: { kubernetes.io/metadata.name: kube-system }
          podSelector:
            matchLabels: { k8s-app: kube-dns }
      ports:
        - { protocol: UDP, port: 53 }
        - { protocol: TCP, port: 53 }
---
# Consente il traffico dall'ingress controller verso l'API sulla porta applicativa
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-ingress-to-api
  namespace: payments
spec:
  podSelector:
    matchLabels: { app.kubernetes.io/name: payments-api }
  policyTypes: ["Ingress"]
  ingress:
    - from:
        - namespaceSelector:
            matchLabels: { kubernetes.io/metadata.name: ingress-nginx }
      ports:
        - { protocol: TCP, port: 8080 }
```

Aggiungi una policy di egress per ogni dipendenza (database, broker, API esterne tramite egress gateway).
Verifica che il CNI del cluster applichi davvero le NetworkPolicy.

## 6. RBAC e ServiceAccount

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: payments-api
  namespace: payments
automountServiceAccountToken: false
---
# Solo se l'applicazione deve leggere una ConfigMap specifica
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: payments-api-config-reader
  namespace: payments
rules:
  - apiGroups: [""]
    resources: ["configmaps"]
    resourceNames: ["payments-api-config"]
    verbs: ["get"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: payments-api-config-reader
  namespace: payments
subjects:
  - kind: ServiceAccount
    name: payments-api
    namespace: payments
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: payments-api-config-reader
```

- Mai `verbs: ["*"]`, `resources: ["*"]`, `ClusterRoleBinding` verso `cluster-admin` per workload o pipeline.
- Permessi `secrets`, `pods/exec`, `create pods`, `escalate`, `bind`, `impersonate` sono equivalenti a privilegi
  amministrativi: concedili solo a componenti di piattaforma revisionati.
- Il deploy dalla pipeline usa un'identità limitata al namespace dell'applicazione.

## 7. Segreti

- Il valore dei segreti vive nel secret manager; nel cluster arriva tramite External Secrets Operator o Secrets
  Store CSI Driver, con l'identità del workload.
- Cifratura dei Secret in etcd con provider KMS.
- Niente segreti in ConfigMap, nei values di Helm committati o in variabili `env` scritte nel manifest.
- Preferisci file montati a variabili d'ambiente (che finiscono più facilmente in dump e log di crash).

## 8. Admission control

Le policy di ammissione (Kyverno, OPA Gatekeeper o ValidatingAdmissionPolicy) devono almeno:
- imporre i controlli della sezione 3 anche dove PSA non arriva (registry ammessi, digest obbligatorio,
  limiti di risorse, label obbligatorie);
- verificare la firma delle immagini e l'attestazione di provenance emesse dalla pipeline attesa (cosign keyless
  con issuer e subject dell'identità OIDC della pipeline);
- girare in modalità `Enforce` in produzione, `Audit` solo durante l'introduzione di una nuova policy.

## 9. Docker Compose per sviluppo locale

- Porte pubblicate solo su loopback: `"127.0.0.1:5432:5432"`, non `"5432:5432"` (che espone su tutte le interfacce).
- Password dei servizi locali generate e in `.env` non versionato; `.env.example` con placeholder.
- Niente `privileged: true` né mount del socket Docker (`/var/run/docker.sock`) nei container applicativi.
- Le stesse immagini fissate per digest usate in produzione, dove possibile.

## 10. Scansione

- `hadolint` sui Dockerfile.
- `trivy image <immagine>` (vulnerabilità e segreti nei layer) e `trivy config` sui manifest.
- `kube-linter`, `kubescape` o `checkov` sui manifest e sui chart renderizzati (`helm template`).
- Scansione continua delle immagini nel registry: un'immagine sicura oggi può non esserlo tra un mese.
