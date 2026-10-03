# S3 Access Manager

A FastAPI prototype that turns a small team access request into IAM, S3 Access Point, and bucket policy documents. A Team is an application-level logical access boundary, not an AWS resource. Its default mode is **dry run**: requests show the intended configuration and make no AWS calls.

## 1. Problem and abstraction

Administrators repeatedly translate team requirements into multiple interdependent AWS policies. This service accepts only a team, an S3 prefix, and one or more of `read`, `write`, and `delete`; it owns the policy translation. It never accepts arbitrary IAM actions or policy JSON.

```json
{"team":"research","prefix":"research/","permissions":["read","write"]}
```

## 2. Architecture

```text
Swagger / client
      |
      v
FastAPI router -> Pydantic validation -> TeamService
                                           |
                               central policy generator
                               /         |          \
                         IAM policy  AP policy  bucket delegation
                               \         |          /
                                dry-run JSON response
                                           |
                                   DRY_RUN=false
                                           v
                              boto3 IAM / S3 / S3 Control
```

`app/` is divided into configuration, API models, policy generation, AWS operations, service orchestration, and HTTP routes. `tests/` checks validation, policy shapes, and system endpoints without AWS.

## 3. Why S3 Access Points

An Access Point gives each team a named endpoint and a resource policy to pair with an IAM group policy. Each team's generated IAM policy scopes data operations to that team's Access Point and prefix. This design makes the intended route explicit and keeps team rules independently inspectable.

## 4. IAM, Access Point, and bucket policy

For an access request to succeed, the caller's identity policy must allow it, the Access Point policy must allow it, and the underlying bucket must permit the access point path. Generated bucket statements delegate only the listed actions through that team's exact Access Point ARN. The bucket policy uses `arn:aws:s3:::bucket` for `ListBucket`, and `arn:aws:s3:::bucket/prefix*` for object actions. Access Point object resources use `...:accesspoint/name/object/prefix*`.

The relationship is IAM Group → IAM Policy → Access Point ARN: the policy is attached to the group, and the policy Resource names the team Access Point. The Access Point is never attached to an IAM group. Its resource policy belongs to that Access Point and uses the account root principal for in-account delegation; IAM groups cannot be resource-policy principals. The bucket policy belongs to the bucket and uses `s3:DataAccessPointArn` to constrain delegation to the specific AP. Existing unrelated bucket policy statements are retained during reconciliation; only SIDs owned by this app/team are replaced.

An explicit `Deny` from any applicable identity, resource, permissions boundary, session, or organization policy overrides an `Allow`. Generated grants do not remove pre-existing broad IAM grants or bucket permissions. Production use should audit existing policies and consider organization-specific guardrails before relying on prefix isolation.

## 5. API and validation

- `GET /` and `GET /health`
- Team Operations: `POST /s3-access/add-team`, `PUT /s3-access/update-team`, `GET /s3-access/get-team/{team}`, `GET /s3-access/list-teams`, `GET /s3-access/get-team-access/{team}`, and `DELETE /s3-access/remove-team/{team}`. These reconcile or inspect team access. Removal leaves the Access Point itself in place.
- User Operations: `POST /s3-access/add-user`, `PUT /s3-access/update-user`, `GET /s3-access/get-user/{username}`, `GET /s3-access/list-users`, and `DELETE /s3-access/remove-user/{username}`. Add/update requests take a username and team and assign the IAM user to that team's IAM group. Remove-user removes the group assignment, not the IAM user identity.

The Swagger UI presents Team Operations, User Operations, and Access Verification inside the same application. `GET /s3-access/get-team/{team}` returns the high-level team definition only. `GET /s3-access/get-team-access/{team}` returns the access implementation: IAM group/policy, Access Point details and policy, and managed bucket-policy statements. `POST /s3-access/check-access` returns an explicit allow/deny decision after checking the user's team membership, prefix, and requested operation. In dry-run mode, it uses this process's simulated user/team assignments when available; for an existing AWS user, it only performs read-only IAM and Access Point configuration lookups. Users are assigned to the existing team IAM group and inherit its permissions; user operations do not create an Access Point or per-user policy. Removing a user removes only the group assignment. Team and user list records are process-local; restart clears that listing state.

Team names must be lowercase letters/digits/hyphens, begin with a letter, and fit the AWS naming convention. Prefixes must be relative and end in `/`. The permission vocabulary is exactly `read`, `write`, and `delete`.

## 6. boto3 and credentials

boto3 uses its standard credential provider chain. Optionally set `AWS_PROFILE` to a profile from `~/.aws/credentials` / `~/.aws/config`; when empty, the normal chain or an attached role is used. No credentials belong in source files or `.env`. The configured IAM principal needs suitable IAM, S3 Control, and S3 permissions to manage the named resources and bucket policy.

The AWS manager uses `iam` for groups and managed policies, `s3control` for Access Point creation and policies, and `s3` for bucket policy operations. boto3 `ClientError` details are reduced to operation/code messages; credentials are not logged.

## 7. Install and run

```sh
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
uvicorn app.main:app --reload
```

The server is at <http://127.0.0.1:8000>; Swagger is <http://127.0.0.1:8000/docs> and ReDoc is <http://127.0.0.1:8000/redoc>. Alternatively run `./run.sh`.

Set `AWS_PROFILE=my-profile` in `.env` (or export it in the shell) to select a profile. Set `AWS_REGION`, `AWS_ACCOUNT_ID`, and `S3_BUCKET` for another environment. The example values point at the supplied environment; the account and bucket must belong to the configured account.

## 8. Dry-run (default)

`.env.example` sets `DRY_RUN=true`. In this mode the service computes all policies and the AP configuration for inspection and does not construct a boto3 client or make AWS calls. Try `POST /s3-access/add-team` in Swagger:

```json
{
  "team": "research",
  "prefix": "research/",
  "permissions": ["read", "write"]
}
```

Example response (policy statement formatting abbreviated only by normal JSON whitespace):

```json
{
  "status": "dry_run",
  "team": "research",
  "prefix": "research/",
  "permissions": ["read", "write"],
  "resources": {
    "iam_group": "ResearchGroup",
    "iam_policy_name": "ResearchPolicy",
    "access_point": {
      "name": "research-ap",
      "bucket": "s3-access-manager-618046392939",
      "region": "ap-south-1",
      "arn": "arn:aws:s3:ap-south-1:618046392939:accesspoint/research-ap"
    },
    "iam_policy": {"Version":"2012-10-17","Statement":[{"Sid":"ListTeamPrefixThroughAccessPoint","Effect":"Allow","Action":"s3:ListBucket","Resource":"arn:aws:s3:ap-south-1:618046392939:accesspoint/research-ap","Condition":{"StringLike":{"s3:prefix":["research/","research/*"]}}},{"Sid":"TeamObjectsThroughAccessPoint","Effect":"Allow","Action":["s3:GetObject","s3:PutObject"],"Resource":"arn:aws:s3:ap-south-1:618046392939:accesspoint/research-ap/object/research/*"}]},
    "access_point_policy": {"Version":"2012-10-17","Statement":[{"Sid":"AllowAccountListTeamPrefix","Effect":"Allow","Principal":{"AWS":"arn:aws:iam::618046392939:root"},"Action":"s3:ListBucket","Resource":"arn:aws:s3:ap-south-1:618046392939:accesspoint/research-ap","Condition":{"StringLike":{"s3:prefix":["research/","research/*"]}}},{"Sid":"AllowAccountTeamObjects","Effect":"Allow","Principal":{"AWS":"arn:aws:iam::618046392939:root"},"Action":["s3:GetObject","s3:PutObject"],"Resource":"arn:aws:s3:ap-south-1:618046392939:accesspoint/research-ap/object/research/*"}]},
    "bucket_policy": {"Version":"2012-10-17","Statement":[{"Sid":"S3AccessManagerresearchList","Effect":"Allow","Principal":"*","Action":"s3:ListBucket","Resource":"arn:aws:s3:::s3-access-manager-618046392939","Condition":{"StringEquals":{"s3:DataAccessPointArn":"arn:aws:s3:ap-south-1:618046392939:accesspoint/research-ap"},"StringLike":{"s3:prefix":["research/","research/*"]}}},{"Sid":"S3AccessManagerresearchObjects","Effect":"Allow","Principal":"*","Action":["s3:GetObject","s3:PutObject"],"Resource":"arn:aws:s3:::s3-access-manager-618046392939/research/*","Condition":{"StringEquals":{"s3:DataAccessPointArn":"arn:aws:s3:ap-south-1:618046392939:accesspoint/research-ap"}}}]}
  }
}
```

Dry-run team and user assignments live in process memory; restart clears them. For already-existing AWS state, live `GET /s3-access/get-team/{team}` discovers a team from its Access Point policy where possible, and `GET /s3-access/get-team-access/{team}` retrieves the current IAM, Access Point, and managed bucket-policy documents.

## 9. Real AWS mode and idempotency

Keep `DRY_RUN=true` for this prototype. The live implementation remains available for later controlled use: `POST /s3-access/add-team` reuses or creates the group and Access Point, updates the predictable customer-managed IAM policy only when its document differs, sets the Access Point policy, and merges/replaces only generated team statements in the bucket policy. User operations require an existing team and IAM group. Team removal returns HTTP 409 while its group has members; it preserves the group and Access Point. User updates remove membership from other groups carrying this app's managed policy before adding the target team group. Repeating the same request reconciles those documents. The first live request can create resources and change bucket policy; use a non-production test account first and review current bucket policy.

The service will not delete an AP on `DELETE`; it removes this app's grants and deletes its managed IAM policy. It does not remove the group, which could contain users or other policies.

## 10. Tests

Run `python -m pytest` inside `.venv`. Tests use no real AWS credentials or AWS mutations. They cover team/user flows, Swagger grouping, idempotent dry-run configuration, policy mapping, and resource ARN forms.

## 11. Security and future work

Use least-privilege credentials for the service, protect `/docs` and API endpoints before network exposure, and review existing IAM/bucket grants because AWS combines multiple policy sources. Current team records in dry-run mode are in memory. Useful next steps include durable configuration storage, authn/authz for the API, policy simulation, automated policy drift detection, pagination for team discovery, and deployment health/metrics.

## Project tree

```text
app/
  __init__.py
  main.py
  config.py
  models.py
  policy_generator.py
  aws_manager.py
  services/team_service.py
  services/user_service.py
  routers/teams.py
  routers/users.py
  routers/access.py
tests/
  __init__.py
  test_health.py
  test_models.py
  test_policy_generator.py
  test_access_management.py
  test_aws_manager.py
requirements.txt
.env.example
.gitignore
README.md
run.sh
```
