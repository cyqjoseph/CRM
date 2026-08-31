# BRD: Centralised Resource Manager Cross-Environments
Data Sensitivity: Internal | Date: 2025-01-16 | Owner: Platform/Infrastructure & Security Teams
approved_at: 2025-01-16T00:00:00Z

## Functional Scope
| ID    | Capability                                                                      | Source    | Priority |
|-------|---------------------------------------------------------------------------------|-----------|----------|
| FR-01 | Discover and inventory all certificates (AWS ACM, self-signed, on-prem) across environments | Explicit  | Must     |
| FR-02 | Discover and inventory all AD accounts and credentials across on-premises environments | Explicit  | Must     |
| FR-03 | Query resource metadata: expiry date, owner, renewal policy, rotation status    | Explicit  | Must     |
| FR-04 | Track and alert when resources are within configurable expiry thresholds (e.g., 30/14/7 days) | Explicit  | Must     |
| FR-05 | Automatically execute certificate renewal for platform-managed resources (AWS ACM, etc.) | Explicit  | Must     |
| FR-06 | Automatically execute AD credential rotation based on configured policies       | Explicit  | Must     |
| FR-07 | Send alerts to teams via UI dashboard and integrated ticketing system (Jira/ServiceNow) | Explicit  | Must     |
| FR-08 | Generate audit trails for all resource lifecycle events (discovery, renewal, rotation, access) | Explicit  | Must     |
| FR-09 | Provide self-service UI for resource owners to query their certificates and credentials | Explicit  | Should   |
| FR-10 | Support manual renewal/rotation triggers via UI for resources that cannot auto-renew | Explicit  | Should   |
| FR-11 | Direct API integration with AWS services (ACM, Secrets Manager, IAM)            | Explicit  | Must     |
| FR-12 | Direct API/LDAP integration with on-premises Active Directory                  | Explicit  | Must     |
| FR-13 | Consolidate data from AWS and on-premises sources into unified inventory       | Explicit  | Must     |
| FR-14 | Replace existing Excel tracking and platform-crawler scripts as single source of truth | Explicit  | Must     |

## User Base
| User Type                  | Internal/External | Est. Concurrent | Auth Method Expected                          |
|----------------------------|-------------------|-----------------|-----------------------------------------------|
| Platform/Infrastructure    | Internal          | 5–10            | AWS IAM or federated AD identity              |
| Security & Compliance      | Internal          | 3–5             | AWS IAM or federated AD identity              |
| Operations/SRE             | Internal          | 8–15            | AWS IAM or federated AD identity              |
| Resource Owners (App Teams)| Internal          | 20–50           | Self-service read-only via federated identity |

## Scale & Usage Patterns
| Metric                           | Baseline      | Peak         | Growth (12mo) |
|----------------------------------|---------------|--------------|---------------|
| Certificates managed (AWS + on-prem) | 100–200       | ~250         | +50%          |
| AD accounts managed              | ~50           | ~75          | +50%          |
| Discovery scan frequency         | Daily         | Daily        | No change     |
| Renewal events per month         | 10–20         | 30–50        | +100%         |
| Alert/notification events per day | 5–15          | 50–100       | +200%         |
| Concurrent dashboard users       | 5–10          | 20–30        | +50%          |

## Data Characteristics
| Data Type                          | Sensitivity | Volume (est)    | Retention        | PII? |
|------------------------------------|-------------|-----------------|------------------|------|
| Certificate metadata (expiry, issuer, subject) | Low         | ~500 KB         | 7 years (compliance) | No   |
| AD credential rotation logs        | High        | ~2–5 MB/month   | 3 years (audit)  | No*  |
| Renewal/rotation audit trails      | Medium      | ~1–3 MB/month   | 3 years          | No   |
| Resource owner contact info        | Low–Medium  | ~100 KB         | Current          | Yes* |

\* Hashed or tokenized; never store plaintext secrets or passwords.

## Integration Points
| System                    | Direction      | Protocol           | Hosted          | Data Exchanged                          |
|---------------------------|----------------|-------------------|-----------------|----------------------------------------|
| AWS Certificate Manager   | Bidirectional  | AWS API v4         | AWS             | Certificate metadata, renewal triggers |
| AWS Secrets Manager       | Bidirectional  | AWS API v4         | AWS             | Secret metadata, rotation events       |
| AWS IAM                   | Read           | AWS API v4         | AWS             | Access key age, rotation status        |
| Active Directory (on-prem)| Bidirectional  | LDAP/ADWS + custom | On-premises     | Account metadata, credential rotation  |
| Jira/ServiceNow           | Unidirectional | REST API           | Cloud/On-prem   | Create tickets for manual interventions|
| Internal audit/logging    | Unidirectional | Syslog/CloudWatch  | AWS or on-prem  | Audit trails, compliance events        |

## Non-Functional Requirements
| ID     | Requirement                                           | Target Metric                     | Priority |
|--------|-------------------------------------------------------|-----------------------------------|----------|
| NFR-01 | System availability during business hours            | 99.5% uptime (SLA: 4.5h downtime/month) | Must     |
| NFR-02 | Discovery and sync latency (certificate/AD inventory) | ≤1 hour from resource change to system awareness | Must     |
| NFR-03 | Alert notification delivery time                     | ≤15 minutes from threshold breach to alert sent | Must     |
| NFR-04 | Renewal execution latency for auto-renewal workflows | ≤30 minutes from trigger to renewal completion | Must     |
| NFR-05 | Dashboard query response time (UI load)              | ≤3 seconds for standard queries    | Should   |
| NFR-06 | Scalability: support 500+ certificates by Year 2     | Linear scaling without redesign    | Should   |
| NFR-07 | Audit log search and retrieval                       | ≤5 seconds to retrieve 1 year of logs | Should   |

## Compliance & Audit Requirements
- [x] Full audit trail required: YES — all discovery, renewal, rotation, and access events must be logged
- [ ] Data residency: AWS region(s) TBD by Cloud Architect; on-premises AD stays on-prem
- [ ] Regulation: None explicitly stated; assume SOC 2 / internal compliance best practices
- [ ] Log retention: 3 years for audit trails; 7 years for certificate lifecycle records

## Constraints
| ID   | Constraint                                                                 | Type         |
|------|----------------------------------------------------------------------------|--------------|
| C-01 | Must integrate with existing on-premises AD infrastructure without major migration | Technical   |
| C-02 | Cannot store plaintext credentials or secrets; only manage lifecycle metadata | Security     |
| C-03 | System must handle heterogeneous certificate sources (CSP-managed, self-signed, on-prem) | Operational |
| C-04 | Auto-renewal only for resources with confirmed platform/tooling support; others manual | Operational |
| C-05 | AD credential rotation must comply with organisational password policies   | Compliance   |
| C-06 | Ticketing system integration must be non-blocking (async); alert delivery never depends on ticket creation | Technical |

## Out of Scope
- Cloud infrastructure design and AWS service selection (Cloud Architect responsibility)
- Deployment topology, networking, or disaster recovery planning (separate architecture phase)
- Encryption key management (covered under separate secrets management initiative)
- Migration of existing manual processes or historical certificate data (separate change management)
- Multi-cloud support beyond AWS (future phase)
- Certificate issuance or signing (manager monitors only)