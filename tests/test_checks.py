import json, boto3
from moto import mock_aws
from cloudguard.checks import S3Public, SgOpenAdmin, IamWildcard, EbsUnencrypted, RdsPublic

@mock_aws
def test_s3_public_detected_and_clean():
    s3 = boto3.client("s3", region_name="us-east-1")
    s3.create_bucket(Bucket="open-bucket")
    s3.put_bucket_policy(Bucket="open-bucket", Policy=json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject",
                       "Resource": "arn:aws:s3:::open-bucket/*"}]}))
    s3.create_bucket(Bucket="locked-bucket")
    s3.put_public_access_block(Bucket="locked-bucket", PublicAccessBlockConfiguration={
        "BlockPublicAcls": True, "IgnorePublicAcls": True, "BlockPublicPolicy": True, "RestrictPublicBuckets": True})
    findings = S3Public().run(boto3.Session())
    ids = {f.resource for f in findings}
    assert "arn:aws:s3:::open-bucket" in ids
    assert "arn:aws:s3:::locked-bucket" not in ids
    assert findings[0].severity == "critical"

@mock_aws
def test_sg_open_admin():
    ec2 = boto3.client("ec2", region_name="us-east-1")
    vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
    sg = ec2.create_security_group(GroupName="bad", Description="d", VpcId=vpc)["GroupId"]
    ec2.authorize_security_group_ingress(GroupId=sg, IpPermissions=[{
        "IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}])
    findings = SgOpenAdmin().run(boto3.Session())
    assert any(f.resource == sg and 22 in f.detail["open_ports"] for f in findings)

@mock_aws
def test_iam_wildcard():
    iam = boto3.client("iam", region_name="us-east-1")
    arn = iam.create_policy(PolicyName="godmode", PolicyDocument=json.dumps({
        "Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]
    }))["Policy"]["Arn"]
    findings = IamWildcard().run(boto3.Session())
    assert any(f.resource == arn for f in findings)

@mock_aws
def test_ebs_unencrypted():
    ec2 = boto3.client("ec2", region_name="us-east-1")
    v = ec2.create_volume(AvailabilityZone="us-east-1a", Size=8, Encrypted=False)["VolumeId"]
    ec2.create_volume(AvailabilityZone="us-east-1a", Size=8, Encrypted=True)
    findings = EbsUnencrypted().run(boto3.Session())
    res = {f.resource for f in findings}
    assert v in res

@mock_aws
def test_rds_public():
    rds = boto3.client("rds", region_name="us-east-1")
    rds.create_db_instance(DBInstanceIdentifier="pub", DBInstanceClass="db.t3.micro",
                           Engine="postgres", PubliclyAccessible=True,
                           MasterUsername="a", MasterUserPassword="password123", AllocatedStorage=20)
    findings = RdsPublic().run(boto3.Session())
    assert any("pub" in f.resource for f in findings)
