# Copyright (c) 2025 CoReason, Inc.
#
# This software is proprietary and dual-licensed.
# Licensed under the Prosperity Public License 3.0 (the "License").
# A copy of the license is available at https://prosperitylicense.com/versions/3.0.0
# For details, see the LICENSE file.
# Commercial use beyond a 30-day trial requires a separate license.
#
# Source Code: https://github.com/CoReason-AI/coreason_auditor

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application configuration via environment variables.

    Loads configuration from environment variables and .env files using pydantic-settings.
    """

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")

    # App Info
    APP_ENV: str = "development"
    DEBUG: bool = False
    LOG_LEVEL: str = "INFO"

    # Compliance Thresholds
    RISK_THRESHOLD: str = "HIGH"  # Matches RiskLevel enum
    MAX_DEVIATIONS: int = 10

    # User Info (Default if not provided in CLI)
    DEFAULT_USER_ID: str = "system-auditor"


settings = Settings()
