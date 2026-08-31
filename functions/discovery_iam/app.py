"""discovery-iam-fn: scans IAM users and access keys for rotation-age metadata.

Writes ONLY lifecycle metadata to the IAM accounts table. Never persists a raw
AccessKeyId or secret material — AccountIdHash is a one-way hash, per
crm_common.hash_identifier (Requirement 1.4's AD analogue for AWS IAM).
"""
import os
import time
from datetime import datetime, timedelta, timezone

import boto3

from crm_common import hash_identifier

IAM_TABLE_NAME = os.environ["IAM_TABLE_NAME"]

WARNING_AGE_DAYS = 90
CRITICAL_AGE_DAYS = 180


def _status_for_age(age_days):
    if age_days >= CRITICAL_AGE_DAYS:
        return "critical"
    if age_days >= WARNING_AGE_DAYS:
        return "warning"
    return "active"


def _discover_iam_accounts(iam_client, now):
    items = []
    user_paginator = iam_client.get_paginator("list_users")
    for user_page in user_paginator.paginate():
        for user in user_page.get("Users", []):
            user_name = user["UserName"]
            key_paginator = iam_client.get_paginator("list_access_keys")
            for key_page in key_paginator.paginate(UserName=user_name):
                for key in key_page.get("AccessKeyMetadata", []):
                    if key.get("Status") != "Active":
                        continue
                    created = key["CreateDate"]
                    age_days = (now - created).days
                    items.append(
                        {
                            "AccountIdHash": hash_identifier(
                                f"{user_name}:{key['AccessKeyId']}"
                            ),
                            "UserName": user_name,
                            "OwnerId": user.get("Path", "/"),
                            "LastRotated": created.isoformat(),
                            "NextRotationDate": _next_rotation_date(created, now),
                            "KeyAge": age_days,
                            "Status": _status_for_age(age_days),
                        }
                    )
    return items


def _next_rotation_date(created, now):
    """The date the key next crosses the warning threshold, floored at now."""
    target = created + timedelta(days=WARNING_AGE_DAYS)
    if target < now:
        target = now
    return target.isoformat()


def handler(event, context):
    iam = boto3.client("iam")
    table = boto3.resource("dynamodb").Table(IAM_TABLE_NAME)
    now = datetime.now(timezone.utc)

    discovered = _discover_iam_accounts(iam, now)

    written = 0
    for item in discovered:
        item["Source"] = "AWS_IAM"
        item["EnvironmentTag"] = "aws"
        item["LastSyncedAt"] = now.isoformat()
        item["Version"] = int(time.time())
        table.put_item(Item=item)
        written += 1

    return {"discovered": len(discovered), "written": written}
