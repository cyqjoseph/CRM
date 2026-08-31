# Requirements: Centralised Resource Manager Cross-Environments

## Introduction
The system uses two independent DynamoDB inventory tables (certs, AD accounts) fed by scheduled Step Functions workflows that invoke discovery Lambdas (ACM/Secrets Manager/IAM) and an ECS Fargate task for on-prem AD (LDAP/ADWS). Expiry evaluation runs hourly, fanning out non-blocking alerts to SNS and an SQS-decoupled Jira Lambda with a DLQ. A Cognito-secured API Gateway + Lambda backend serves the self-service UI with owner-scoped reads and asynchronous manual renewal/rotation triggers, and every action is written to an append-only audit trail with S3 archival.

## Requirements

### Requirement 1: Certificate Inventory Storage
**User Story:** As a platform engineer, I want certificate lifecycle metadata stored in a dedicated inventory table, so that expiry and ownership can be queried quickly without exposing plaintext secrets.

#### Acceptance Criteria
1. WHEN a certificate discovery scan completes THE SYSTEM SHALL write cert metadata (CertId, CertType, OwnerId, ExpiryDate, Status, Source) to the `{env}-crm-cert-inventory` table.
2. WHEN a query is made by OwnerId THE SYSTEM SHALL return matching certs using the `OwnerIndex` GSI.
3. WHEN a query is made by expiry threshold and Status THE SYSTEM SHALL return matching certs using the `ExpiryIndex` GSI.
4. WHEN a discovery Lambda writes cert metadata THE SYSTEM SHALL never persist plaintext certificate/private key material.

### Requirement 2: AD Account Inventory Storage
**User Story:** As a platform engineer, I want AD account rotation metadata stored in a dedicated inventory table, so that rotation status can be tracked without storing raw identifiers.

#### Acceptance Criteria
1. WHEN an AD discovery task completes THE SYSTEM SHALL write account metadata (AccountIdHash, OwnerId, Domain, NextRotationDate, RotationStatus) to the `{env}-crm-ad-inventory` table.
2. WHEN a query is made by OwnerId THE SYSTEM SHALL return matching accounts using the `OwnerIndex` GSI.
3. WHEN a query is made by RotationStatus and NextRotationDate THE SYSTEM SHALL return matching accounts using the `RotationIndex` GSI.
4. WHEN account identifiers are written to the inventory THE SYSTEM SHALL store only hashed identifiers, never plaintext.

### Requirement 3: Scheduled Discovery Orchestration
**User Story:** As a compliance owner, I want certificate and AD discovery to run automatically on a schedule, so that the inventory stays current without manual effort.

#### Acceptance Criteria
1. WHEN the daily EventBridge rule fires THE SYSTEM SHALL start the `{env}-crm-discovery-sfn` Step Functions execution.
2. WHEN the discovery workflow runs THE SYSTEM SHALL invoke the ACM/Secrets Manager/IAM discovery Lambda and write results to the cert inventory table.
3. WHEN the discovery workflow runs THE SYSTEM SHALL invoke the Fargate AD discovery task via RunTask and write results to the AD inventory table.
4. WHEN a discovery step completes (success or failure) THE SYSTEM SHALL write an event record to the audit hot table.

### Requirement 4: Expiry Alerting and Ticketing
**User Story:** As a resource owner, I want to be alerted before certificates or AD accounts expire, so that I can act before an outage or compliance breach.

#### Acceptance Criteria
1. WHEN the hourly EventBridge rule fires THE SYSTEM SHALL invoke the expiry evaluator Lambda to query both `ExpiryIndex` GSIs for configured thresholds.
2. WHEN a resource matches a threshold THE SYSTEM SHALL publish an alert to the corresponding `{env}-crm-alerts-{severity}` SNS topic.
3. WHEN a resource matches a threshold THE SYSTEM SHALL independently send a ticket-creation message to `{env}-crm-jira-queue` without waiting on the Jira response.
4. IF Jira ticket creation fails THEN THE SYSTEM SHALL move the message to `{env}-crm-jira-dlq` without blocking or retracting the SNS alert already sent.
5. WHEN an alert or ticket event occurs THE SYSTEM SHALL write it to the audit hot table.

### Requirement 5: Auto-Renewal and Rotation Workflows
**User Story:** As a security engineer, I want ACM certificates auto-renewed and AD credentials rotated through controlled workflows, so that lifecycle actions are consistent and auditable.

#### Acceptance Criteria
1. WHEN an ACM-eligible certificate crosses its renewal threshold THE SYSTEM SHALL start the `{env}-crm-renewal-sfn` workflow and call the ACM renewal API.
2. WHEN an AD account rotation is triggered THE SYSTEM SHALL start the `{env}-crm-rotation-sfn` workflow and run the Fargate rotation task using bind credentials from Secrets Manager.
3. WHEN a renewal or rotation workflow completes THE SYSTEM SHALL update the corresponding inventory table with the new expiry/rotation date and status, without storing any plaintext secret.
4. WHEN a renewal or rotation workflow completes THE SYSTEM SHALL write the outcome to the audit hot table and publish an SNS notification.

### Requirement 6: Self-Service API and UI Access
**User Story:** As a resource owner, I want to query my certificates/AD accounts and trigger manual renewal or rotation from a self-service UI, so that I don't depend on the platform team for routine actions.

#### Acceptance Criteria
1. WHEN an authenticated user calls `GET /certs` or `GET /ad-accounts` THE SYSTEM SHALL return only items scoped to the user's OwnerId unless the caller is in the admin Cognito group.
2. WHEN an authenticated user calls `POST /certs/{certId}/renew` or `POST /ad-accounts/{accountId}/rotate` THE SYSTEM SHALL start the corresponding Step Functions execution and return a 202 response with the execution ARN and request ID without waiting for workflow completion.
3. WHEN a user calls `GET /executions/{executionId}` THE SYSTEM SHALL return the current status of the referenced Step Functions execution.
4. WHEN any UI-initiated query or manual trigger occurs THE SYSTEM SHALL write the action to the audit hot table.
5. IF a caller is not authenticated via Cognito THE SYSTEM SHALL reject the request with a 401/403 response.

### Requirement 7: Audit Trail and Retention
**User Story:** As a compliance officer, I want every discovery, alert, renewal, rotation, and access event recorded and retained, so that the system meets audit and regulatory requirements.

#### Acceptance Criteria
1. WHEN any discovery, alert, renewal, rotation, or UI event occurs THE SYSTEM SHALL write an append-only record (EntityId, EventTimestamp, EventType, Actor, Outcome, Detail) to the `{env}-crm-audit-hot` table.
2. WHEN a hot audit record approaches its TTL THE SYSTEM SHALL export it to the `{env}-crm-audit-archive` S3 bucket before expiry.
3. WHEN an archived record is written to S3 THE SYSTEM SHALL apply the retention lifecycle rule matching its entity type (7yr AD, 3yr cert).
4. WHEN an admin queries `GET /audit` THE SYSTEM SHALL return matching events scoped by entityId and time range.

### Requirement 8: IAM Least-Privilege Access
**User Story:** As a security engineer, I want every compute principal scoped to only the resources and actions it needs, so that a compromised function cannot access unrelated data.

#### Acceptance Criteria
1. WHEN a discovery, expiry, renewal, rotation, API, or exporter Lambda is deployed THE SYSTEM SHALL attach an IAM role granting only the actions listed in the IAM & Access Design table.
2. WHEN the Fargate task role is used THE SYSTEM SHALL restrict Secrets Manager access to only the AD bind credential secret.
3. WHEN a Step Functions execution role invokes Lambda or ECS RunTask THE SYSTEM SHALL use `iam:PassRole` only for the specific task role required, not a wildcard.
