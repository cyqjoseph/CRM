"""api-certs-fn: GET /certs, GET /certs/{certId}, POST /certs/{certId}/renew."""
import os

import boto3
from crm_common import (
    api_response,
    get_claims,
    guard_api_handler,
    is_admin,
    new_request_id,
    owner_id_of,
    put_audit_event,
)

CERT_TABLE_NAME = os.environ["CERT_TABLE_NAME"]
RENEWAL_STATE_MACHINE_ARN = os.environ["RENEWAL_STATE_MACHINE_ARN"]


def _list_certs(table, claims, query_params):
    query_params = query_params or {}
    if is_admin(claims) and query_params.get("ownerId"):
        owner_id = query_params["ownerId"]
    else:
        owner_id = owner_id_of(claims)

    if not owner_id:
        # DynamoDB rejects an empty string for a key attribute, so an absent
        # `sub` would raise ValidationException here rather than return nothing —
        # another unhandled exception surfacing in the browser as a 502.
        return api_response(401, {"message": "unauthenticated"})

    response = table.query(
        IndexName="OwnerIndex",
        KeyConditionExpression="OwnerId = :owner",
        ExpressionAttributeValues={":owner": owner_id},
    )
    items = response.get("Items", [])
    if query_params.get("status"):
        items = [i for i in items if i.get("Status") == query_params["status"]]
    return api_response(200, {"items": items})


def _get_cert(table, claims, cert_id):
    response = table.get_item(Key={"CertId": cert_id})
    item = response.get("Item")
    if not item:
        return api_response(404, {"message": "not found"})
    if not is_admin(claims) and item.get("OwnerId") != owner_id_of(claims):
        return api_response(404, {"message": "not found"})
    return api_response(200, item)


def _renew_cert(table, claims, cert_id):
    response = table.get_item(Key={"CertId": cert_id})
    item = response.get("Item")
    if not item:
        return api_response(404, {"message": "not found"})
    if not is_admin(claims) and item.get("OwnerId") != owner_id_of(claims):
        return api_response(404, {"message": "not found"})

    sfn = boto3.client("stepfunctions")
    request_id = new_request_id()
    execution = sfn.start_execution(
        stateMachineArn=RENEWAL_STATE_MACHINE_ARN,
        name=request_id,
        input='{"certId": "%s", "certArn": "%s", "requestId": "%s"}'
        % (cert_id, item.get("CertId", cert_id), request_id),
    )

    put_audit_event(
        entity_id=cert_id,
        event_type="MANUAL_RENEWAL_TRIGGER",
        actor=owner_id_of(claims),
        outcome="STARTED",
        detail={"requestId": request_id, "executionArn": execution["executionArn"]},
    )

    return api_response(202, {"executionArn": execution["executionArn"], "requestId": request_id})


@guard_api_handler
def handler(event, context):
    claims = get_claims(event)
    table = boto3.resource("dynamodb").Table(CERT_TABLE_NAME)

    method = event.get("httpMethod")
    path_params = event.get("pathParameters") or {}
    cert_id = path_params.get("certId")
    resource_path = event.get("resource", "")

    if method == "GET" and cert_id is None:
        return _list_certs(table, claims, event.get("queryStringParameters"))
    if method == "GET" and cert_id is not None:
        return _get_cert(table, claims, cert_id)
    if method == "POST" and resource_path.endswith("/renew"):
        return _renew_cert(table, claims, cert_id)

    return api_response(404, {"message": "not found"})
