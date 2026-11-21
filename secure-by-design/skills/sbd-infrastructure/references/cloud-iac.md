# Cloud e Infrastructure as Code — pattern sicuri

Gli esempi usano Terraform con provider AWS 6.x; per Azure e GCP sono indicate le impostazioni equivalenti.
I nomi degli attributi possono variare tra versioni dei provider: verifica sulla documentazione della versione
fissata nel lockfile `.terraform.lock.hcl`, che va sempre committato.

## Indice

1. Fondamenta del progetto Terraform
2. Storage a oggetti
3. Chiavi KMS
4. IAM a privilegio minimo
5. Rete
6. Database
7. Calcolo e metadata service
8. Guardrail di organizzazione
9. Equivalenti Azure e GCP
10. Scansione e policy as code

## 1. Fondamenta del progetto Terraform

```hcl
terraform {
  required_version = ">= 1.11"
  required_providers {
    aws = { source = "hashicorp/aws", version = "~> 6.0" }
  }
  backend "s3" {
    bucket       = "<org>-tfstate-prod"
    key          = "payments-api/terraform.tfstate"
    region       = "eu-south-1"
    encrypt      = true
    kms_key_id   = "<arn-cmk-tfstate>"
    use_lockfile = true                 # locking nativo S3
  }
}

provider "aws" {
  region = "eu-south-1"
  default_tags {
    tags = {
      owner               = "team-payments"
      service             = "payments-api"
      environment         = "prod"
      data-classification = "C3"
      criticality         = "critical"
    }
  }
}
```

- Il bucket dello state ha versioning, blocco dell'accesso pubblico, accesso limitato al ruolo della pipeline.
- Segreti: generali nel secret manager o con meccanismi gestiti (es. `manage_master_user_password` per RDS),
  usa risorse `ephemeral` e argomenti write-only dove disponibili, così non finiscono nello state.
- Moduli: versione esatta da registry interno (`source = "<registry>/<org>/s3-secure/aws"`, `version = "3.2.1"`).

## 2. Storage a oggetti

```hcl
resource "aws_s3_bucket" "reports" {
  bucket = "<org>-payments-reports-prod"
}

resource "aws_s3_bucket_public_access_block" "reports" {
  bucket                  = aws_s3_bucket.reports.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "reports" {
  bucket = aws_s3_bucket.reports.id
  rule {
    object_ownership = "BucketOwnerEnforced"   # disattiva le ACL
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "reports" {
  bucket = aws_s3_bucket.reports.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.data.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_versioning" "reports" {
  bucket = aws_s3_bucket.reports.id
  versioning_configuration {
    status = "Enabled"
  }
}

data "aws_iam_policy_document" "reports_tls_only" {
  statement {
    sid       = "DenyInsecureTransport"
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = [aws_s3_bucket.reports.arn, "${aws_s3_bucket.reports.arn}/*"]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
}

resource "aws_s3_bucket_policy" "reports" {
  bucket = aws_s3_bucket.reports.id
  policy = data.aws_iam_policy_document.reports_tls_only.json
}
```

Aggiungi lifecycle per la retention (SBD-DATA-08) e Object Lock in modalità compliance per log e backup
immutabili. Attiva anche il blocco dell'accesso pubblico a livello di account (`aws_s3_account_public_access_block`).

## 3. Chiavi KMS

```hcl
resource "aws_kms_key" "data" {
  description             = "CMK dati C3 payments-api prod"
  enable_key_rotation     = true
  deletion_window_in_days = 30
  policy                  = data.aws_iam_policy_document.kms_data.json
}
```

- Una chiave per servizio, ambiente e classe di dati; la key policy separa chi amministra la chiave da chi la usa.
- Nessun principal `*` nella key policy senza condizioni restrittive.

## 4. IAM a privilegio minimo

```hcl
# Insicuro
#   actions   = ["s3:*"]
#   resources = ["*"]

data "aws_iam_policy_document" "reports_reader" {
  statement {
    sid       = "ReadReports"
    actions   = ["s3:GetObject"]
    resources = ["${aws_s3_bucket.reports.arn}/reports/*"]
  }
  statement {
    sid       = "DecryptReports"
    actions   = ["kms:Decrypt"]
    resources = [aws_kms_key.data.arn]
  }
}
```

- I workload usano ruoli assunti tramite identità federata (EKS Pod Identity o IRSA, ruoli di istanza, ruoli
  di task ECS, OIDC dalla pipeline). Nessun `aws_iam_access_key`.
- Le trust policy dei ruoli federati vincolano `sub` e `aud` (es. per GitHub:
  `repo:<org>/<repo>:environment:prod`), mai wildcard sull'organizzazione intera.
- Usa IAM Access Analyzer per generare policy dal comportamento reale e per rilevare accessi esterni.

## 5. Rete

```hcl
# Il database accetta connessioni solo dal security group dell'applicazione
resource "aws_vpc_security_group_ingress_rule" "db_from_app" {
  security_group_id            = aws_security_group.db.id
  referenced_security_group_id = aws_security_group.app.id
  ip_protocol                  = "tcp"
  from_port                    = 5432
  to_port                      = 5432
}
```

- `0.0.0.0/0` e `::/0` ammessi in ingresso solo sul load balancer pubblico, porta 443.
- Subnet private per applicazioni e dati; VPC endpoint (gateway e interface) per S3, KMS, Secrets Manager,
  ECR, CloudWatch, così il traffico verso i servizi gestiti non esce su Internet.
- Egress dei workload C2-C3 tramite firewall o proxy con allowlist di domini.
- VPC Flow Logs attivi e inviati al SIEM.

## 6. Database

```hcl
resource "aws_db_instance" "payments" {
  identifier                          = "payments-prod"
  engine                              = "postgres"
  instance_class                      = "db.r6g.large"
  allocated_storage                   = 100
  storage_encrypted                   = true
  kms_key_id                          = aws_kms_key.data.arn
  publicly_accessible                 = false
  manage_master_user_password         = true        # password generata e custodita in Secrets Manager
  iam_database_authentication_enabled = true
  deletion_protection                 = true
  backup_retention_period             = 35
  copy_tags_to_snapshot               = true
  multi_az                            = true
  auto_minor_version_upgrade          = true
  db_subnet_group_name                = aws_db_subnet_group.data.name
  vpc_security_group_ids              = [aws_security_group.db.id]
  parameter_group_name                = aws_db_parameter_group.tls.name   # rds.force_ssl = 1
  enabled_cloudwatch_logs_exports     = ["postgresql"]
}
```

Account applicativi distinti per runtime (DML sulle sole tabelle necessarie), migrazioni (DDL) e reporting
(sola lettura), vedi SBD-DATA-09.

## 7. Calcolo e metadata service

```hcl
resource "aws_launch_template" "app" {
  # ...
  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"   # IMDSv2 obbligatorio
    http_put_response_hop_limit = 1            # i container non raggiungono il metadata service
  }
}
```

- Nessun IP pubblico sulle istanze applicative; accesso tramite SSM Session Manager.
- AMI da pipeline di immagini hardened con patch recenti; volumi EBS cifrati di default
  (`aws_ebs_encryption_by_default`).

## 8. Guardrail di organizzazione

Esempio di Service Control Policy che protegge l'audit trail:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "ProtectAuditTrail",
      "Effect": "Deny",
      "Action": [
        "cloudtrail:StopLogging",
        "cloudtrail:DeleteTrail",
        "cloudtrail:UpdateTrail",
        "cloudtrail:PutEventSelectors"
      ],
      "Resource": "*"
    }
  ]
}
```

Altri guardrail minimi: negare l'uso di regioni fuori da quelle ammesse (con eccezione per i servizi globali),
negare `iam:CreateAccessKey` e `iam:CreateUser` fuori dagli account di identità, negare la disattivazione di
GuardDuty, Security Hub e Config, negare la rimozione del blocco dell'accesso pubblico S3.

## 9. Equivalenti Azure e GCP

| Controllo | Azure (azurerm 4.x) | GCP (google 6.x) |
|---|---|---|
| Storage non pubblico | `allow_nested_items_to_be_public = false`, `public_network_access_enabled = false`, private endpoint | `public_access_prevention = "enforced"`, `uniform_bucket_level_access = true`, niente membri `allUsers` / `allAuthenticatedUsers` |
| Cifratura con chiave gestita | blocco `customer_managed_key` con Key Vault, `infrastructure_encryption_enabled = true` | blocco `encryption { default_kms_key_name = ... }` |
| TLS minimo | `min_tls_version = "TLS1_2"`, `https_traffic_only_enabled = true` | policy SSL del load balancer con `min_tls_version = "TLS_1_2"` e profilo `MODERN` o `RESTRICTED` |
| Niente chiavi condivise | `shared_access_key_enabled = false`, accesso con Entra ID | org policy `iam.disableServiceAccountKeyCreation` |
| Identità dei workload | Managed Identity, Workload Identity per AKS | Workload Identity per GKE, service account dedicati |
| Database privato | `public_network_access_enabled = false`, autenticazione solo Entra ID | Cloud SQL `ipv4_enabled = false`, `private_network`, `ssl_mode = "ENCRYPTED_ONLY"` |
| Segreti | Key Vault con RBAC, `purge_protection_enabled = true`, accesso pubblico disabilitato | Secret Manager con IAM per secret, replica in regioni UE |
| Guardrail | Azure Policy con effetto `Deny` assegnate al management group | Organization Policy: `gcp.resourceLocations`, `storage.publicAccessPrevention`, `compute.vmExternalIpAccess` |
| Audit | Activity Log e Diagnostic Settings verso Log Analytics/SIEM | Cloud Audit Logs (incluso Data Access per dati C3) verso SIEM |

## 10. Scansione e policy as code

- In CI: `trivy config .` (o Checkov/KICS) su ogni PR che tocca IaC; `terraform validate` e `tflint`.
- Esegui la scansione anche sul piano (`terraform show -json plan.out`), che vede i valori risolti.
- Policy aziendali in Rego (Conftest/OPA) o Sentinel per le regole non coperte dagli scanner: tag
  obbligatori, regioni ammesse, moduli approvati, divieto di risorse specifiche.
- Le soppressioni negli scanner (`#checkov:skip`, `#trivy:ignore`) richiedono motivazione e, per regole High,
  un'eccezione registrata.
