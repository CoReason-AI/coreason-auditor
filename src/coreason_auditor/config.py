from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """
    Application configuration via environment variables.
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
