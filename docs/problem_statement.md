# Problem Statement: Centralised Resource Manager Cross-Environments
Data Sensitivity: Internal | Date: 2025-01-16
approved_at: 2025-01-16T00:00:00Z

## Problem Statement
Resources (certificates and Active Directory credentials) are expiring without warning across AWS and on-premises environments, causing unplanned service outages. Manual lifecycle management is error-prone, creates compliance/security risks, and lacks audit trails. Teams lack centralised visibility into resource expiry and rotation across environments.

## Business Objectives
| ID    | Objective                                                          | Priority |
|-------|--------------------------------------------------------------------|----------|
| OBJ-01 | Reduce operational overhead and manual effort in resource lifecycle management | Must     |
| OBJ-02 | Prevent service outages caused by resource expiry                   | Must     |
| OBJ-03 | Achieve full visibility and audit trails for credential and certificate lifecycle events | Should   |

## Success Criteria
| ID    | Criterion                                                         | Target Metric                              |
|-------|-------------------------------------------------------------------|--------------------------------------------|
| SC-01 | Eliminate unplanned outages caused by resource expiry             | Zero cert/credential-related outages in 6 months |
| SC-02 | Achieve full audit trail and compliance for resource lifecycle    | 100% of rotation and expiry events tracked and auditable |
| SC-03 | Reduce manual effort in resource lifecycle management             | Reduce resource renewal tickets/manual interventions by 80% |
| SC-04 | Centralised visibility across AWS and on-premises environments    | All certificates and AD credentials visible and monitored in single pane of glass |

## Primary Stakeholders
| Stakeholder | Role | Interest |
|-------------|------|----------|
| Platform/Infrastructure Teams | Resource management and deployment | Reduce manual overhead; prevent outages |
| Security and Compliance Teams | Security posture and audit requirements | Full lifecycle visibility; compliance tracking |
| Operations/SRE Teams | Production stability and incident response | Early warning of expiry; reduce on-call burden |