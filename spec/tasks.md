# Implementation Tasks: Centralised Resource Manager Cross-Environments

- [ ] 1. Create `{env}-crm-cert-inventory` DynamoDB table
  - PK CertId, GSI1 OwnerIndex (OwnerId/ExpiryDate), GSI2 ExpiryIndex (Status/ExpiryDate)
  - _Requirements: 1_
  - _Verify: `sam validate` succeeds against the template defining this table_

- [ ] 2. Create `{env}-crm-ad-inventory` DynamoDB table
  - PK AccountIdHash, GSI1 OwnerIndex (OwnerId/NextRotationDate), GSI2 RotationIndex (RotationStatus/NextRotationDate)
  - _Requirements: 2_
  - _Verify: `sam validate` succeeds against the template defining this table_

- [ ] 3. Create `{env}-crm-audit-hot` DynamoDB table
  - PK EntityId, SK EventTimestamp, TTL attribute enabled for stream-triggered export
  - _Requirements: 7_
  - _Verify: `sam validate` succeeds against the template defining this table_

- [ ] 4. Create `{env}-crm-audit-archive` S3 bucket
  - Lifecycle rules for 7yr (AD) and 3yr (cert) retention tiers
  - _Requirements: 7_
  - _Verify: `sam validate` succeeds against the template defining this bucket_

- [ ] 5. Create `{env}-crm-ui-site` S3 bucket and `{env}-crm-ui-cdn` CloudFront distribution
  - Static site origin, TLS 1.2+ enforced
  - _Requirements: 6_
  - _Verify: `sam validate` succeeds against the template defining this bucket/distribution_

- [ ] 6. Create `{env}-crm-api` API Gateway REST API with Cognito authorizer
  - Routes: /certs, /certs/{certId}, /certs/{certId}/renew, /ad-accounts, /ad-accounts/{accountId}, /ad-accounts/{accountId}/rotate, /executions/{executionId}, /audit
  - _Requirements: 6_
  - _Verify: unit test asserts each route is defined in the OpenAPI/SAM spec_

- [ ] 7. Create `{env}-crm-userpool` Cognito user pool with SAML federation and owner/admin groups
  - _Requirements: 6, 8_
  - _Verify: `sam validate` succeeds against the template defining this user pool_

- [ ] 8. Create `{env}-crm-discovery-sfn` Step Functions state machine
  - Orchestrates ACM/Secrets/IAM discovery Lambda + Fargate RunTask for AD discovery
  - _Requirements: 3_
  - _Verify: state machine ASL JSON passes `sam validate` / ASL schema check_

- [ ] 9. Create `{env}-crm-renewal-sfn` Step Functions state machine
  - ACM auto-renewal workflow, updates cert inventory, publishes SNS
  - _Requirements: 5_
  - _Verify: state machine ASL JSON passes `sam validate` / ASL schema check_

- [ ] 10. Create `{env}-crm-rotation-sfn` Step Functions state machine
  - AD rotation workflow via Fargate task, updates AD inventory, publishes SNS
  - _Requirements: 5_
  - _Verify: state machine ASL JSON passes `sam validate` / ASL schema check_

- [ ] 11. Implement `{env}-crm-discovery-acm-fn` Lambda
  - Scans ACM/Secrets Manager/IAM, writes metadata-only records to cert inventory
  - _Requirements: 1, 3_
  - _Verify: unit test asserts function never writes a field named SecretValue/PrivateKey_

- [ ] 12. Implement `{env}-crm-discovery-ad-trigger-fn` Lambda
  - Starts Fargate RunTask for on-prem AD discovery
  - _Requirements: 2, 3_
  - _Verify: unit test mocks ECS client and asserts RunTask called with `{env}-crm-ad-task-def`_

- [ ] 13. Implement `{env}-crm-expiry-evaluator-fn` Lambda
  - Queries ExpiryIndex/RotationIndex GSIs, publishes SNS, sends SQS message
  - _Requirements: 4_
  - _Verify: unit test asserts SNS publish and SQS send are both called and independent (mocked)_

- [ ] 14. Implement `{env}-crm-renewal-executor-fn` Lambda
  - Calls ACM RenewCertificate, updates inventory, no plaintext secret storage
  - _Requirements: 5_
  - _Verify: unit test asserts no attribute named Secret/PrivateKey is passed to PutItem/UpdateItem_

- [ ] 15. Implement `{env}-crm-jira-notifier-fn` Lambda with `{env}-crm-jira-queue` and `{env}-crm-jira-dlq`
  - Consumes SQS, creates Jira ticket, routes failures to DLQ
  - _Requirements: 4_
  - _Verify: unit test simulates Jira API failure and asserts message is sent to DLQ, not raised as unhandled_

- [ ] 16. Implement `{env}-crm-api-certs-fn` and `{env}-crm-api-ad-fn` Lambdas
  - Owner-scoped GET queries, POST renew/rotate returning 202 + executionArn
  - _Requirements: 6_
  - _Verify: unit test asserts POST handler returns HTTP 202 with executionArn key present_

- [ ] 17. Implement `{env}-crm-api-audit-fn` Lambda
  - GET /audit and GET /executions/{executionId} handlers
  - _Requirements: 6, 7_
  - _Verify: unit test asserts handler enforces admin-group check for cross-owner audit queries_

- [ ] 18. Implement `{env}-crm-audit-exporter-fn` Lambda
  - Streams `{env}-crm-audit-hot` DynamoDB Stream to `{env}-crm-audit-archive` S3 before TTL expiry
  - _Requirements: 7_
  - _Verify: unit test asserts S3 key pattern matches `{entityType}/{yyyy}/{mm}/{dd}/{entityId}-{eventTimestamp}.json`_

- [ ] 19. Build `{env}-crm-ad-agent-repo` ECR image and `{env}-crm-ad-task-def` Fargate task definition
  - Custom LDAP/ADWS client for discovery and rotation, deployed in existing private subnets
  - _Requirements: 2, 5_
  - _Verify: `docker build` of the agent image succeeds locally in the build container_

- [ ] 20. Configure `{env}-crm-alerts-{severity}` SNS topics
  - One topic per severity threshold
  - _Requirements: 4_
  - _Verify: `sam validate` succeeds against the template defining these topics_

- [ ] 21. Configure `{env}-crm-ad-bind-creds` and `{env}-crm-jira-token` Secrets Manager secrets
  - Rotation enabled for AD bind credentials
  - _Requirements: 5, 8_
  - _Verify: `sam validate` succeeds against the template defining these secrets_

- [ ] 22. Configure SSM Parameter Store entries under `/{env}/crm/thresholds/*` and `/{env}/crm/policy/*`
  - _Requirements: 4, 5_
  - _Verify: `sam validate` succeeds against the template defining these parameters_

- [ ] 23. Configure `{env}-crm-dashboard` CloudWatch dashboard and alarms
  - Lambda error rate, Step Functions failures, `{env}-crm-jira-dlq` depth > 0
  - _Requirements: 4_
  - _Verify: `sam validate` succeeds against the template defining the dashboard/alarms_

- [ ] 24. Enable AWS X-Ray tracing across API Gateway, Lambda, Step Functions
  - _Requirements: 8_
  - _Verify: unit test / static check confirms `Tracing: Active` set in the SAM template for each function_

- [ ] 25. Wire IAM role for `{env}-crm-discovery-acm-fn`
  - Scope to ACM/Secrets Manager/IAM read + cert-inventory PutItem/UpdateItem only
  - _Requirements: 8_
  - _Verify: static IAM policy lint (e.g. `cfn-lint` / `iam-policy-validator`) confirms no wildcard resource_

- [ ] 26. Wire IAM role for `{env}-crm-ad-task-def` Fargate task role
  - Scope to AD bind secret GetSecretValue + ad-inventory PutItem/UpdateItem only
  - _Requirements: 8_
  - _Verify: static IAM policy lint confirms no wildcard resource_

- [ ] 27. Wire IAM role for `{env}-crm-expiry-evaluator-fn`
  - Scope to inventory GSIs Query, SNS Publish, SQS SendMessage only
  - _Requirements: 8_
  - _Verify: static IAM policy lint confirms no wildcard resource_

- [ ] 28. Wire IAM role for `{env}-crm-jira-notifier-fn`
  - Scope to jira-queue receive/delete + jira-token GetSecretValue only
  - _Requirements: 8_
  - _Verify: static IAM policy lint confirms no wildcard resource_

- [ ] 29. Wire IAM role for `{env}-crm-renewal-executor-fn`
  - Scope to ACM RenewCertificate, StartExecution, inventory UpdateItem only
  - _Requirements: 8_
  - _Verify: static IAM policy lint confirms no wildcard resource_

- [ ] 30. Wire IAM roles for `{env}-crm-api-*-fn` functions
  - Scope to owner-claim-conditioned inventory/audit access + StartExecution
  - _Requirements: 6, 8_
  - _Verify: static IAM policy lint confirms condition keys present on DynamoDB actions_

- [ ] 31. Wire IAM role for `{env}-crm-audit-exporter-fn`
  - Scope to audit-hot stream GetRecords + audit-archive PutObject only
  - _Requirements: 7, 8_
  - _Verify: static IAM policy lint confirms no wildcard resource_

- [ ] 32. Wire IAM execution roles for `{env}-crm-*-sfn` state machines
  - Scope PassRole to the specific Fargate task role only, not wildcard
  - _Requirements: 8_
  - _Verify: static IAM policy lint confirms PassRole resource is a named role ARN pattern, not `*`_

- [ ] 33. Wire Cognito group-to-API Gateway authorization mapping
  - Owner group scoped `execute-api:Invoke`; admin group full access incl. /audit
  - _Requirements: 6, 8_
  - _Verify: unit test asserts authorizer config maps both groups to expected resource scopes_
