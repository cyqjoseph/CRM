"""discovery-ad-trigger-fn: starts the Fargate AD discovery task and waits for it to finish.

Invoked as a Step Functions Task state. The actual LDAP/ADWS work happens
on-prem-adjacent, inside the ad-agent Fargate container (see ad-agent/), which
writes hashed account metadata directly to the AD inventory table.
"""
import os

import boto3

CLUSTER_ARN = os.environ["ECS_CLUSTER_ARN"]
TASK_DEFINITION = os.environ["AD_TASK_DEFINITION"]
SUBNET_IDS = os.environ["SUBNET_IDS"].split(",")
SECURITY_GROUP_ID = os.environ["AD_TASK_SECURITY_GROUP_ID"]
CONTAINER_NAME = os.environ.get("AD_TASK_CONTAINER_NAME", "ad-agent")


def handler(event, context):
    ecs = boto3.client("ecs")

    run_response = ecs.run_task(
        cluster=CLUSTER_ARN,
        taskDefinition=TASK_DEFINITION,
        launchType="FARGATE",
        count=1,
        networkConfiguration={
            "awsvpcConfiguration": {
                "subnets": SUBNET_IDS,
                "securityGroups": [SECURITY_GROUP_ID],
                "assignPublicIp": "ENABLED",
            }
        },
        overrides={
            "containerOverrides": [
                {
                    "name": CONTAINER_NAME,
                    "environment": [{"name": "AD_TASK_MODE", "value": "DISCOVER"}],
                }
            ]
        },
    )

    failures = run_response.get("failures", [])
    if failures or not run_response.get("tasks"):
        raise RuntimeError(f"ecs.run_task for {TASK_DEFINITION} failed: {failures}")

    task_arn = run_response["tasks"][0]["taskArn"]

    waiter = ecs.get_waiter("tasks_stopped")
    waiter.wait(
        cluster=CLUSTER_ARN,
        tasks=[task_arn],
        WaiterConfig={"Delay": 15, "MaxAttempts": 60},
    )

    described = ecs.describe_tasks(cluster=CLUSTER_ARN, tasks=[task_arn])
    task = described["tasks"][0]
    exit_code = None
    for container in task.get("containers", []):
        if container.get("name") == CONTAINER_NAME:
            exit_code = container.get("exitCode")

    if exit_code != 0:
        raise RuntimeError(f"ad-agent discovery task {task_arn} exited with code {exit_code}")

    return {"taskArn": task_arn, "exitCode": exit_code}
