from app.policy_generator import (actions_for, generate_iam_policy, generate_access_point_policy,
                                  generate_bucket_policy)

AP = "arn:aws:s3:ap-south-1:618046392939:accesspoint/research-ap"


def test_permission_mapping():
    assert actions_for(["read", "write"]) == ["s3:GetObject", "s3:ListBucket", "s3:PutObject"]


def test_iam_policy_separates_bucket_and_object_resources():
    policy = generate_iam_policy("research", "research/", ["read", "write"], AP, "example-bucket")
    listed = next(s for s in policy["Statement"] if s["Action"] == "s3:ListBucket")
    objects = next(s for s in policy["Statement"] if isinstance(s["Action"], list))
    assert listed["Resource"] == "arn:aws:s3:::example-bucket"
    assert objects["Resource"] == f"{AP}/object/research/*"


def test_access_point_policy_uses_account_principal_and_ap_arns():
    policy = generate_access_point_policy("research", "research/", ["read"], AP, "618046392939")
    assert policy["Statement"][0]["Principal"]["AWS"] == "arn:aws:iam::618046392939:root"
    assert policy["Statement"][0]["Resource"] == AP
    assert policy["Statement"][1]["Resource"] == f"{AP}/object/research/*"


def test_bucket_policy_uses_bucket_arns_and_ap_constraint():
    policy = generate_bucket_policy("research", "research/", ["read", "write"], "example", AP)
    listing = next(s for s in policy["Statement"] if s["Action"] == "s3:ListBucket")
    objects = next(s for s in policy["Statement"] if isinstance(s["Action"], list))
    assert listing["Resource"] == "arn:aws:s3:::example"
    assert objects["Resource"] == "arn:aws:s3:::example/research/*"
    assert objects["Condition"]["StringEquals"]["s3:DataAccessPointArn"] == AP
