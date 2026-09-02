"""ec2-discovery-fn: dispatches an SSM Run Command against the cert-scanner
EC2 instance (see Ec2CertScannerInstance in template.yaml) to enumerate
OS-level certificates under /etc/ssl/certs, and logs the outcome.

Triggered every 30 minutes by Ec2DiscoveryScheduleRule. Raises on a dispatch
failure rather than swallowing it, so EventBridge's default retry-once
behaviour applies — matching the other event-driven functions in this repo.
"""
import os

import boto3
import botocore.exceptions

from crm_common import structured_log

INSTANCE_ID_PARAM_NAME = os.environ["CERT_SCANNER_INSTANCE_ID_PARAM"]

# Best-effort enumeration of the OS certificate store. Ubuntu populates
# /etc/ssl/certs with per-certificate .pem symlinks, so this needs no
# knowledge of which CAs are installed.
CERT_SCAN_COMMAND = (
    "for f in /etc/ssl/certs/*.pem; do "
    '[ -f "$f" ] && openssl x509 -noout -subject -enddate -in "$f" 2>/dev/null; '
    "done"
)


def handler(event, context):
    request_id = getattr(context, "aws_request_id", "local")
    structured_log(request_id, "EC2_DISCOVERY_START")

    ssm = boto3.client("ssm")

    try:
        instance_id = ssm.get_parameter(Name=INSTANCE_ID_PARAM_NAME)["Parameter"]["Value"]
    except botocore.exceptions.ClientError as exc:
        structured_log(request_id, "EC2_DISCOVERY_NO_INSTANCE", level="ERROR", error=str(exc))
        return {"dispatched": False, "reason": "instance-id parameter not found"}

    try:
        response = ssm.send_command(
            InstanceIds=[instance_id],
            DocumentName="AWS-RunShellScript",
            Comment="app-d9fae51c-1929cc69 OS certificate discovery",
            Parameters={"commands": [CERT_SCAN_COMMAND]},
        )
    except botocore.exceptions.ClientError as exc:
        structured_log(
            request_id,
            "EC2_DISCOVERY_DISPATCH_FAILED",
            level="ERROR",
            instanceId=instance_id,
            error=str(exc),
        )
        raise

    command_id = response["Command"]["CommandId"]
    structured_log(
        request_id,
        "EC2_DISCOVERY_DISPATCHED",
        instanceId=instance_id,
        commandId=command_id,
    )
    return {"dispatched": True, "instanceId": instance_id, "commandId": command_id}
