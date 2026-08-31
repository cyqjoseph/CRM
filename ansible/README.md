# Ansible stubs — on-prem AD / ADCS integration (future work)

This directory is **documentation only**. Nothing here runs today: it is not
installed, not invoked by `deploy.sh`/`destroy.sh`, and has no Python/Ansible
dependency anywhere in the repository. It exists to sketch the shape of the
on-prem half of the "one unified inventory dashboard" — Windows Active
Directory accounts and AD Certificate Services (ADCS) certificates — so a
future implementer has a concrete starting point instead of a blank page.

The AWS half of that dashboard (EC2, IAM, ACM/Secrets Manager/IAM server
certs) is real and deployed today; see the repo root `README.md`.

## Why Ansible, and why a stub

The platform this app is built for (see `CLAUDE.md`) cannot reach on-prem
infrastructure at all — it has no VPN, no Direct Connect, and no network path
out of the AWS account it deploys into. Discovering and rotating on-prem AD
accounts or ADCS certificates requires an agent that runs *inside* the
on-prem network, with its own credentials and its own execution schedule
(cron, AWX/Ansible Tower, a scheduled task — whatever the eventual operator
already runs). Ansible is a reasonable choice for that agent because most
Windows/AD estates already have `ansible.windows`/`community.windows`
tooling available.

None of this can be built, tested or run from inside this repository's build
environment, so every file below is a stub: real task names and structure,
`TODO` markers everywhere real logic would go, and no working credentials,
modules, or requirements.

## Layout

- `inventories/` — example (fake-data) inventory files for the on-prem
  Windows AD estate and the ADCS host. Replace the placeholder hostnames and
  wire up real credential lookups (Ansible Vault, or your own secrets
  manager) before ever running these for real.
- `roles/discover-ad-accounts/` — would enumerate AD user accounts and their
  password-last-set dates.
- `roles/rotate-ad-passwords/` — would reset a flagged AD account's password
  (the on-prem analogue of `functions/rotation_iam_key`, which only flags
  AWS IAM keys rather than mutating them — see the repo root README's
  Deviations section for why).
- `roles/discover-certificates/` — would enumerate certificates issued by an
  on-prem ADCS certificate authority.
- `roles/renew-certificates/` — would request/install a renewed certificate
  from ADCS.
- `roles/report-to-dynamodb/` — the one role that *would* touch AWS: it would
  call the deployed `POST /sync/on-prem-data` endpoint (see
  `functions/sync_on_prem/app.py`) to write discovered rows into the same
  `CertInventoryTable` / `IamAccountsTable` the AWS-side discovery Lambdas
  write to, tagging them `EnvironmentTag: on-prem` so the dashboard can tell
  them apart.
- `playbooks/` — top-level playbooks that would each include one or more of
  the roles above.
- `aws-iam-policy-template.json` — a template-only IAM policy document
  (never deployed, never referenced by `template.yaml`) showing the minimum
  DynamoDB permissions an on-prem-facing credential would need if a future
  implementer chose to call DynamoDB directly instead of going through
  `POST /sync/on-prem-data`.

## Making this real

At minimum, a real implementation would need:
1. A host inside the on-prem network able to run `ansible-playbook`, with
   network access to the AD domain controllers and the ADCS server.
2. Real Ansible collections (`ansible.windows`, `community.windows`,
   `community.crypto` or similar) added to a `requirements.yml` — not present
   here, since nothing in this repo installs or runs Ansible.
3. Credentials for that host to authenticate to AD/ADCS, stored in Ansible
   Vault or an equivalent secret store on that host — never in this repo.
4. Either network egress from that host to the deployed API Gateway URL (to
   call `POST /sync/on-prem-data`), or the direct-DynamoDB path implied by
   `aws-iam-policy-template.json`, with real AWS credentials scoped to that
   policy.
