# Resource Inventory
| Resource | AWS Service | Naming Pattern | Purpose |
|----------|-------------|-----------------|---------|
| Cert inventory table | DynamoDB | `{env}-crm-cert-inventory` | Certificate lifecycle metadata (ACM, self-signed, on-prem) |
| AD inventory table | DynamoDB | `{env}-crm-ad-inventory` | AD account rotation metadata (hashed identifiers only) |
| Audit hot table | DynamoDB | `{env}-crm-audit-hot` | Append-only recent audit events, TTL-bound |
| Audit archive bucket | S3 | `{env}-crm-audit-archive` | 7yr/3yr tiered audit retention |
| UI static site bucket | S3 | `{env}-crm-ui-site` | Self-service UI static assets |
| CloudFront distribution | CloudFront | `{env}-crm-ui-cdn` | Delivers self-service UI |
| API Gateway REST API | API Gateway | `{env}-crm-api` | UI backend + manual trigger endpoints |
| Cognito user pool | Cognito | `{env}-crm-userpool` | Federated AD authentication |
| Discovery state machine | Step Functions | `{env}-crm-discovery-sfn` | Orchestrates scheduled discovery |
| Renewal state machine | Step Functions | `{env}-crm-renewal-sfn` | ACM auto-renewal workflow |
| Rotation state machine | Step Functions | `{env}-crm-rotation-sfn` | AD credential rotation workflow |
| ACM discovery Lambda | Lambda | `{env}-crm-discovery-acm-fn` | Scans ACM/Secrets Manager/IAM |
| AD discovery trigger Lambda | Lambda | `{env}-crm-discovery-ad-trigger-fn` | Starts Fargate RunTask for AD scan |
| Expiry evaluator Lambda | Lambda | `{env}-crm-expiry-evaluator-fn` | Hourly threshold scan, alert fan-out |
| Renewal executor Lambda | Lambda | `{env}-crm-renewal-executor-fn` | Calls ACM renewal API |
| Jira notifier Lambda | Lambda | `{env}-crm-jira-notifier-fn` | SQS-consumed Jira ticket creation |
| API backend Lambda (certs) | Lambda | `{env}-crm-api-certs-fn` | Cert query/trigger endpoints |
| API backend Lambda (AD) | Lambda | `{env}-crm-api-ad-fn` | AD query/trigger endpoints |
| API backend Lambda (audit) | Lambda | `{env}-crm-api-audit-fn` | Audit query endpoint |
| Audit exporter Lambda | Lambda | `{env}-crm-audit-exporter-fn` | Streams hot table to S3 archive |
| ECS Fargate task definition | ECS (Fargate) | `{env}-crm-ad-task-def` | LDAP/ADWS discovery + rotation |
| ECR repository | ECR | `{env}-crm-ad-agent-repo` | AD agent container image |
| Jira queue | SQS | `{env}-crm-jira-queue` | Decouples ticket creation |
| Jira DLQ | SQS | `{env}-crm-jira-dlq` | Failed ticket creation |
| Alert topics | SNS | `{env}-crm-alerts-{severity}` | Severity-based fan-out |
| AD bind secret | Secrets Manager | `{env}-crm-ad-bind-creds` | Service-account creds |
| Jira token secret | Secrets Manager | `{env}-crm-jira-token` | Jira API token |
| Threshold params | SSM Parameter Store | `/{env}/crm/thresholds/*` | Expiry threshold config |
| Policy params | SSM Parameter Store | `/{env}/crm/policy/*` | Renewal/rotation policy config |
| Dashboard | CloudWatch | `{env}-crm-dashboard` | Cross-workflow observability |
