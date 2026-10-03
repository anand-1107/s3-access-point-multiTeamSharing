from functools import lru_cache
from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    aws_region: str = "ap-south-1"
    aws_profile: str | None = None
    s3_bucket: str = "s3-access-manager-618046392939"
    aws_account_id: str = "618046392939"
    dry_run: bool = True

    @field_validator("aws_profile", mode="before")
    @classmethod
    def empty_profile_is_none(cls, value):
        return value or None


@lru_cache
def get_settings() -> Settings:
    return Settings()
