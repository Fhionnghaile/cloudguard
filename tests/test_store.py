import boto3
from moto import mock_aws
from cloudguard.model import Finding
from cloudguard.store import FindingStore

def _make_table():
    d = boto3.resource("dynamodb", region_name="us-east-1")
    d.create_table(TableName="cloudguard",
        KeySchema=[{"AttributeName": "PK", "KeyType": "HASH"}, {"AttributeName": "SK", "KeyType": "RANGE"}],
        AttributeDefinitions=[{"AttributeName": n, "AttributeType": "S"} for n in
                              ("PK", "SK", "GSI1PK", "GSI1SK", "GSI2PK", "GSI2SK")],
        GlobalSecondaryIndexes=[
            {"IndexName": "GSI1", "KeySchema": [{"AttributeName": "GSI1PK", "KeyType": "HASH"},
             {"AttributeName": "GSI1SK", "KeyType": "RANGE"}], "Projection": {"ProjectionType": "ALL"}},
            {"IndexName": "GSI2", "KeySchema": [{"AttributeName": "GSI2PK", "KeyType": "HASH"},
             {"AttributeName": "GSI2SK", "KeyType": "RANGE"}], "Projection": {"ProjectionType": "ALL"}}],
        BillingMode="PAY_PER_REQUEST")
    return d.Table("cloudguard")

@mock_aws
def test_reconcile_open_update_resolve():
    t = _make_table(); store = FindingStore(t)
    f1 = Finding("s3-public", "critical", "arn:aws:s3:::b1", "111122223333", "global", {})
    f2 = Finding("s3-public", "critical", "arn:aws:s3:::b2", "111122223333", "global", {})

    r1 = store.reconcile("111122223333", "s3-public", [f1, f2], now=1000)
    assert r1 == {"opened": 2, "updated": 0, "resolved": 0}

    # b2 fixed -> only f1 remains; f2 should be resolved with a ttl
    r2 = store.reconcile("111122223333", "s3-public", [f1], now=2000)
    assert r2["updated"] == 1 and r2["resolved"] == 1 and r2["opened"] == 0

    item2 = t.get_item(Key={"PK": "ACCT#111122223333", "SK": "FINDING#s3-public#arn:aws:s3:::b2"})["Item"]
    assert item2["status"] == "resolved" and "ttl" in item2
    item1 = t.get_item(Key={"PK": "ACCT#111122223333", "SK": "FINDING#s3-public#arn:aws:s3:::b1"})["Item"]
    assert item1["status"] == "open" and int(item1["first_seen"]) == 1000  # first_seen preserved
