# Architecture: Centralised Resource Manager Cross-Environments
Data Sensitivity: Internal (contains High-sensitivity AD rotation logs, tokenized PII) | Pattern: Event-driven serverless with scheduled Fargate tasks for on-prem connectivity

## Solution Summary
The system discovers and inventories certificates (ACM, self-signed, on-prem) and AD accounts on a scheduled basis, storing lifecycle metadata (never plaintext secrets) in a unified DynamoDB inventory. Scheduled evaluators detect expiry thresholds and trigger Step Functions workflows for auto-renewal (ACM) or AD credential rotation (via Fargate tasks reaching on-prem AD over the existing Direct Connect/VPN), while alerts fan out asynchronously to a dashboard (SNS) and Jira (SQS-decoupled Lambda) without blocking. A Cognito-secured self-service UI (CloudFront + API Gateway + Lambda) lets resource owners query status and trigger manual renewal/rotation. All discovery, renewal, rotation, and access events are written to an immutable audit trail (DynamoDB hot store + S3 archive) satisfying compliance retention.

## AWS Services
| Service | Purpose | Config Notes |
|---------|---------|---------------|
| Amazon EventBridge | Scheduled triggers for discovery scans and expiry threshold checks | Daily discovery rule, hourly expiry-check rule |
| AWS Step Functions | Orchestrates discovery, auto-renewal, and rotation workflows | Standard workflows, retries/error branches |
| AWS Lambda | Discovery (ACM/Secrets Manager/IAM scan), expiry evaluation, renewal execution, Jira integration, UI API backend | Python/Node runtime, VPC-attached only where needed |
| Amazon ECS (Fargate) | On-prem AD discovery and credential rotation tasks (LDAP/ADWS) | Task-based (Step Functions RunTask), existing private subnets, no NAT/ALB |
| Amazon ECR | Container images for Fargate AD discovery/rotation tasks | Custom LDAP/ADWS client image |
| Amazon DynamoDB | Unified inventory (certs + AD accounts) and hot audit trail | On-demand capacity, GSIs for owner/expiry queries |
| Amazon S3 | Long-term audit log archive (7yr/3yr retention), static self-service UI assets | Lifecycle rules per retention tier |
| Amazon CloudFront | Delivers self-service UI | Origin: S3 static site |
| Amazon API Gateway | REST API for UI backend and manual trigger actions | Cognito authorizer |
| Amazon Cognito | User authentication, federated identity for internal users | SAML federation to corporate AD |
| Amazon SQS | Decouples alert delivery from Jira ticket creation (non-blocking, C-06) | DLQ for failed ticket creation |
| Amazon SNS | Fan-out alert notifications to dashboard/subscribers | Topic per severity threshold |
| AWS Secrets Manager | Jira API token, AD bind service-account credentials | Rotation enabled for service account creds |
| AWS Systems Manager Parameter Store | Expiry thresholds, renewal/rotation policy config | Environment-scoped parameters |
| Amazon CloudWatch | Logs, metrics, alarms across all compute | Dashboards per workflow |
| AWS X-Ray | Distributed tracing across Lambda/Step Functions | End-to-end workflow tracing |
| AWS IAM | Roles/permissions for all compute and cross-service access | Least-privilege per function |

## Data Flow
**Discovery (scheduled)**
1. EventBridge daily rule starts Step Functions discovery workflow.
2. Lambda queries AWS ACM, Secrets Manager, and IAM for certificate/key metadata; writes to DynamoDB inventory.
3. Step Functions runs an ECS Fargate task (existing private subnet, reachable via pre-provisioned Direct Connect/VPN) that queries on-prem AD over LDAP/ADWS using bind credentials from Secrets Manager; writes AD account metadata (hashed identifiers only) to DynamoDB.
4. All discovery outcomes written to audit trail (DynamoDB + async export to S3 archive).

**Expiry alerting (async, non-blocking)**
5. EventBridge hourly rule triggers Lambda to scan DynamoDB inventory for items within 30/14/7-day thresholds.
6. Matching items publish to SNS (dashboard/UI notification) and independently to SQS.
7. A separate Lambda consumes SQS and calls Jira REST API to create a ticket; failures go to DLQ and never block SNS alert delivery (C-06).
8. Alert and ticket events logged to audit trail.

**Auto-renewal / rotation**
9. Expiry Lambda or manual UI trigger starts a Step Functions execution: for ACM-eligible certs, Lambda calls ACM renewal API; for AD accounts, Fargate task performs rotation per organisational password policy (C-05), using Secrets Manager for privileged bind creds.
10. Result (success/failure, new expiry/rotation date — no plaintext secret stored) updates DynamoDB inventory and audit trail; SNS notifies subscribers.

**Self-service UI**
11. User authenticates via Cognito (federated AD identity) on CloudFront-served UI.
12. UI calls API Gateway → Lambda → DynamoDB for read queries (certs/AD accounts, owner-scoped) or to submit manual renewal/rotation requests, which start the same Step Functions workflows as #9.
13. Every UI action (query, manual trigger) is written to the audit trail.

## Design Decisions
| Decision | Choice | Rationale |
|----------|--------|-----------|
| Unified inventory store | Amazon DynamoDB | FR-13; low-latency owner/expiry queries, meets NFR-05 (≤3s) |
| On-prem AD access | ECS Fargate task in existing private subnets over pre-provisioned Direct Connect/VPN | FR-02/FR-12, C-01; no new networking created, reuses existing VPC/subnet IDs |
| Batch AD/discovery workload | Fargate task invoked via Step Functions RunTask (not a persistent service) | Avoids need for ALB; long-running LDAP/ADWS calls unsuited to Lambda timeout |
| Alert/ticket decoupling | SNS for alerts + separate SQS-backed Lambda for Jira | C-06; ticket creation failures never block alert delivery, NFR-03 (≤15min) |
| Auto-renewal scope | Step Functions + Lambda for ACM only; AD/on-prem/self-signed flagged for manual | C-04, FR-05/FR-10 |
| No plaintext secret storage | Only lifecycle metadata (expiry, owner, rotation status) persisted; secrets stay in Secrets Manager | C-02, FR-03 |
| Audit retention tiering | DynamoDB (hot, ≤5s retrieval, NFR-07) + S3 archive (7yr/3yr per data type) | FR-08, compliance retention table |
| Self-service UI hosting | S3 static site + CloudFront | FR-09; low-cost, scalable to 20-30 concurrent users |
| Federated identity | Cognito with SAML federation to AD | User Base table: "AWS IAM or federated AD identity" |
| Vector/RAG search | Not applicable — no semantic search requirement in BRD | Excluded to keep scope minimal |

## Security Design
| Concern | Approach |
|---------|----------|
| Authentication | Amazon Cognito user pool federated with corporate AD (SAML) for all internal user types |
| Authorisation | Cognito groups mapped to IAM-scoped API Gateway authorizers; resource-owner read-only scope enforced at Lambda query layer |
| Data at rest | DynamoDB and S3 default encryption (AWS managed keys); Secrets Manager encrypts stored bind credentials/Jira token |
| Data in transit | TLS 1.2+ enforced on CloudFront/API Gateway; on-prem AD traffic travels over existing encrypted Direct Connect/Site-to-Site VPN |
| Network boundary | Fargate tasks deployed only in existing pre-provisioned private subnets; security groups restrict egress to AD endpoints only; no public exposure of discovery/rotation compute |
| Secrets | AWS Secrets Manager holds AD bind service-account credentials and Jira API token; never store discovered plaintext secrets (C-02) |
| Audit trail | Every discovery/renewal/rotation/access event written to DynamoDB (hot) and archived to S3 (7yr/3yr per NFR/compliance table); CloudWatch Logs capture system-level events; X-Ray traces workflow execution |

## Integration Confirmation
| System | Direction | Endpoint Type | Auth | Notes |
|--------|-----------|---------------|------|-------|
| AWS Certificate Manager | Bidirectional | AWS API v4 (via Lambda) | IAM role | Matches BRD |
| AWS Secrets Manager | Bidirectional | AWS API v4 (via Lambda) | IAM role | Matches BRD; used for metadata + own service secrets |
| AWS IAM | Read | AWS API v4 (via Lambda) | IAM role | Matches BRD |
| Active Directory (on-prem) | Bidirectional | LDAP/ADWS via ECS Fargate | Service-account creds in Secrets Manager | Connectivity over existing Direct Connect/Site-to-Site VPN (pre-provisioned, no new networking) |
| Jira Cloud | Unidirectional (outbound ticket creation) | REST API via Lambda (SQS-decoupled) | API token in Secrets Manager | BRD listed Jira/ServiceNow; feedback scoped to Jira only — ServiceNow deferred, flagged as change from BRD |
| Internal audit/logging | Unidirectional | CloudWatch Logs + DynamoDB/S3 | IAM role | Matches BRD; Syslog target not implemented (no on-prem log collector in allowed services) — flagged as change from BRD |
