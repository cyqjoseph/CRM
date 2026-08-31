# Design: Centralised Resource Manager Cross-Environments

## Overview
The system uses two independent DynamoDB inventory tables (certs, AD accounts) fed by scheduled Step Functions workflows that invoke discovery Lambdas (ACM/Secrets Manager/IAM) and an ECS Fargate task for on-prem AD (LDAP/ADWS). Expiry evaluation runs hourly, fanning out non-blocking alerts to SNS and an SQS-decoupled Jira Lambda with a DLQ. A Cognito-secured API Gateway + Lambda backend serves the self-service UI with owner-scoped reads and asynchronous manual renewal/rotation triggers — the API returns a Step Functions execution reference immediately, and the UI polls a status endpoint or receives an SNS completion event. Every discovery, alert, renewal, rotation, and UI action is written to a dedicated append-only audit table with TTL-based export to S3 for long-term retention.

## Data Model
| Table / Store | Key Schema | Key Attributes | Notes |
|----------------|------------|-----------------|-------|
| `{env}-crm-cert-inventory` | PK: `CertId` | CertType, OwnerId, ExpiryDate, Status, Source | GSI1 `OwnerIndex` (PK OwnerId, SK ExpiryDate); GSI2 `ExpiryIndex` (PK Status, SK ExpiryDate) |
| `{env}-crm-ad-inventory` | PK: `AccountIdHash` | OwnerId, Domain, NextRotationDate, RotationStatus | GSI1 `OwnerIndex` (PK OwnerId, SK NextRotationDate); GSI2 `RotationIndex` (PK RotationStatus, SK NextRotationDate) |
| `{env}-crm-audit-hot` | PK: `EntityId`, SK: `EventTimestamp` | EventType, Actor, Outcome, Detail, TTL | Append-only; TTL ~90d before stream-triggered export |
| `{env}-crm-audit-archive` (S3) | Key: `{entityType}/{yyyy}/{mm}/{dd}/{entityId}-{eventTimestamp}.json` | entityType, entityId, eventTimestamp | Lifecycle: 7yr AD, 3yr cert per compliance table |

## API / Interface Contracts
| Endpoint or Interface | Method | Request | Response | Auth |
|------------------------|--------|---------|----------|------|
| `/certs` | GET | query: ownerId?, status? | 200 list of cert items | Cognito JWT |
| `/certs/{certId}` | GET | path: certId | 200 detail / 404 | Cognito JWT |
| `/certs/{certId}/renew` | POST | `{}` | 202 `{executionArn, requestId}` | Cognito JWT (owner/admin group) |
| `/ad-accounts` | GET | query: ownerId?, status? | 200 list of AD items | Cognito JWT |
| `/ad-accounts/{accountId}` | GET | path: accountId | 200 detail / 404 | Cognito JWT |
| `/ad-accounts/{accountId}/rotate` | POST | `{}` | 202 `{executionArn, requestId}` | Cognito JWT (owner/admin group) |
| `/executions/{executionId}` | GET | path: executionId | 200 `{status, output}` | Cognito JWT |
| `/audit` | GET | query: entityId, from, to | 200 list of audit events | Cognito JWT (admin group for cross-owner) |

## Sequence Detail

**Flow 1 — Scheduled discovery**
1. EventBridge daily rule starts the discovery Step Functions execution.
2. Step Functions invokes the discovery Lambda for ACM/Secrets Manager/IAM.
3. Discovery Lambda calls ACM DescribeCertificate for each certificate.
4. ACM returns metadata.
5. Discovery Lambda writes metadata to the cert inventory table.
6. Step Functions runs the Fargate task for on-prem AD discovery.
7. Fargate task queries the on-prem AD server via LDAP/ADWS.
8. AD server returns account metadata.
9. Fargate task writes hashed account metadata to the AD inventory table.
10. Fargate task reports completion back to Step Functions.
11. Step Functions writes the discovery event to the audit table.

**Flow 2 — Expiry alerting (non-blocking)**
1. EventBridge hourly rule triggers the expiry evaluator Lambda.
2. Lambda queries the cert/AD `ExpiryIndex` GSIs for threshold matches.
3. Matching items are returned.
4. Lambda publishes an alert to the relevant SNS severity topic.
5. Lambda independently (fire-and-forget) sends a ticket request to SQS.
6. Jira notifier Lambda polls the queue.
7. On success, it posts to the Jira REST API and receives an issue ID, then logs to the audit table.
8. On failure, the message moves to the DLQ without blocking the SNS alert already delivered (C-06).
9. Expiry evaluator logs the alert event to the audit table.

**Flow 3 — Self-service manual trigger (async)**
1. User submits a manual renewal request through the UI.
2. API Gateway authorizes via Cognito and invokes the API Lambda.
3. API Lambda starts the renewal Step Functions execution.
4. Step Functions returns the execution ARN immediately (async).
5. API Lambda logs the manual-trigger event to the audit table.
6. API Lambda responds 202 with execution ARN and request ID.
7. API Gateway relays the 202 response to the user.
8. Step Functions updates the cert inventory table once the workflow completes.
9. Step Functions fires an SNS completion notification (not awaited).
10. User (or dashboard) polls the execution status endpoint.
11. API Gateway authorizes and invokes the API Lambda for status.
12. API Lambda returns the current execution status to the user.

## IAM & Access Design
| Principal | Resource | Actions | Justification |
|-----------|----------|---------|----------------|
| `{env}-crm-discovery-acm-fn` role | ACM, Secrets Manager, IAM, cert-inventory table | `acm:ListCertificates`, `acm:DescribeCertificate`, `secretsmanager:ListSecrets`, `secretsmanager:DescribeSecret`, `iam:ListServerCertificates`, `dynamodb:PutItem`/`UpdateItem` | Metadata-only discovery scan (C-02) |
| `{env}-crm-ad-task-def` (Fargate task role) | AD bind secret, ad-inventory table | `secretsmanager:GetSecretValue` (scoped), `dynamodb:PutItem`/`UpdateItem` | On-prem AD discovery/rotation (FR-02/FR-12) |
| `{env}-crm-expiry-evaluator-fn` role | cert/AD inventory GSIs, SNS topics, SQS queue | `dynamodb:Query`, `sns:Publish`, `sqs:SendMessage` | Threshold scan, non-blocking fan-out (C-06) |
| `{env}-crm-jira-notifier-fn` role | jira-queue, jira-token secret | `sqs:ReceiveMessage`/`DeleteMessage`, `secretsmanager:GetSecretValue` | Decoupled ticket creation; DLQ on failure |
| `{env}-crm-renewal-executor-fn` role | ACM, inventory tables, Step Functions | `acm:RenewCertificate`, `states:StartExecution`, `dynamodb:UpdateItem` | Auto-renewal, ACM only (C-04) |
| `{env}-crm-api-*-fn` roles | inventory tables, audit-hot table, Step Functions | `dynamodb:Query`/`GetItem` (owner-scoped via Cognito claim), `states:StartExecution`, `dynamodb:PutItem` | Self-service read/manual trigger (FR-09) |
| `{env}-crm-audit-exporter-fn` role | audit-hot stream, audit-archive bucket | `dynamodb:GetRecords` (stream), `s3:PutObject` | Hot-to-archive export before TTL expiry |
| `{env}-crm-*-sfn` execution roles | discovery/renewal Lambdas, Fargate task | `lambda:InvokeFunction`, `ecs:RunTask`, `iam:PassRole` (task role only) | Per-workflow least-privilege orchestration |
| Cognito resource-owner group | API Gateway resources | `execute-api:Invoke` (owner-scoped only) | Self-service query/trigger (FR-09) |
| Cognito admin group | API Gateway resources incl. `/audit` | `execute-api:Invoke` (all resources) | Cross-owner visibility/audit access |

## Error Handling & Observability
| Concern | Approach |
|---------|----------|
| Retries/idempotency | Step Functions built-in retry/backoff on Lambda and ECS RunTask states; inventory writes use conditional `PutItem`/`UpdateItem` keyed on CertId/AccountIdHash + version attribute to prevent duplicate discovery writes |
| Failure alerting | CloudWatch Alarms on Lambda error rate, Step Functions failed executions, and `{env}-crm-jira-dlq` depth > 0, routed to an ops SNS topic |
| Logging | All Lambda/Fargate/Step Functions emit structured JSON logs to CloudWatch Logs, tagged with the Step Functions execution ARN as correlation ID |
| Tracing | AWS X-Ray enabled end-to-end across API Gateway → Lambda → Step Functions → Fargate task invocation |
| DLQ handling | Jira ticket failures land in `{env}-crm-jira-dlq`; a scheduled Lambda or manual runbook reprocesses/inspects DLQ messages without blocking SNS alert delivery |
