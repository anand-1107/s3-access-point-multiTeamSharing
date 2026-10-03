import re
from typing import Literal
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

Permission = Literal["read", "write", "delete"]


class TeamConfig(BaseModel):
    model_config = ConfigDict(json_schema_extra={"example": {"team": "research", "prefix": "research/", "permissions": ["read", "write"]}})
    team: str = Field(..., min_length=1, description="Lowercase team key; used to derive AWS resource names.")
    prefix: str = Field(..., min_length=1, description="Object key prefix ending in slash.")
    permissions: list[Permission] = Field(..., min_length=1, description="Allowed high-level S3 permissions.")

    @field_validator("team")
    @classmethod
    def safe_team(cls, v: str) -> str:
        if not re.fullmatch(r"[a-z][a-z0-9-]{0,31}", v):
            raise ValueError("team must start with a lowercase letter and contain only lowercase letters, digits, or hyphens (max 32 characters)")
        return v

    @field_validator("prefix")
    @classmethod
    def safe_prefix(cls, v: str) -> str:
        if not v.strip() or not v.endswith("/") or v.startswith("/") or ".." in v or "*" in v:
            raise ValueError("prefix must be a non-empty relative S3 prefix ending in / and must not contain '..' or '*'")
        return v

    @model_validator(mode="after")
    def prefix_belongs_to_team(self):
        if not self.prefix.startswith(f"{self.team}/"):
            raise ValueError("prefix must be inside the named team namespace (team/...) ")
        return self


class TeamRecord(BaseModel):
    team: str
    prefix: str
    permissions: list[Permission]
    access_point_name: str
    access_point_arn: str
    iam_group_name: str
    status: str = "configured"


class UserConfig(BaseModel):
    model_config = ConfigDict(json_schema_extra={"example": {"username": "research-user", "team": "research"}})
    username: str = Field(..., min_length=1, description="IAM username to grant team access.")
    team: str = Field(..., min_length=1, description="Team whose IAM group grants this user S3 access.")

    @field_validator("username")
    @classmethod
    def safe_username(cls, v: str) -> str:
        if not re.fullmatch(r"[A-Za-z0-9+=,.@_-]{1,64}", v):
            raise ValueError("username contains unsupported IAM characters (max 64 characters)")
        return v

    @field_validator("team")
    @classmethod
    def safe_user_team(cls, v: str) -> str:
        if not re.fullmatch(r"[a-z][a-z0-9-]{0,31}", v):
            raise ValueError("team must start with a lowercase letter and contain only lowercase letters, digits, or hyphens")
        return v


class AccessCheckRequest(BaseModel):
    model_config = ConfigDict(json_schema_extra={"example": {"username": "finance-user", "prefix": "finance/", "operation": "read"}})
    username: str = Field(..., min_length=1, description="IAM username whose team membership will be checked.")
    prefix: str = Field(..., min_length=1, description="Requested S3 prefix, ending in slash.")
    operation: Permission = Field(..., description="Requested high-level operation: read, write, or delete.")

    @field_validator("username")
    @classmethod
    def safe_access_check_username(cls, v: str) -> str:
        if not re.fullmatch(r"[A-Za-z0-9+=,.@_-]{1,64}", v):
            raise ValueError("username contains unsupported IAM characters (max 64 characters)")
        return v

    @field_validator("prefix")
    @classmethod
    def safe_access_check_prefix(cls, v: str) -> str:
        if not v.strip() or not v.endswith("/") or v.startswith("/") or ".." in v or "*" in v:
            raise ValueError("prefix must be a non-empty relative S3 prefix ending in / and must not contain '..' or '*'")
        return v


class AccessCheckResponse(BaseModel):
    allowed: bool
    message: str
    username: str
    team: str | None = None
    requested_prefix: str
    configured_prefix: str | None = None
    operation: Permission
    access_point: str | None = None
    reason: str | None = None
