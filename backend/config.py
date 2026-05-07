from pydantic_settings import BaseSettings
from pathlib import Path

BASE_DIR = Path(__file__).parent.parent


class Settings(BaseSettings):
    db_path: str = str(BASE_DIR / "siem.db")
    secret_key: str = "changeme-in-production-use-env-var"
    algorithm: str = "HS256"
    access_token_expire_minutes: int = 480
    rules_dir: str = str(Path(__file__).parent / "rules")
    cors_origins: list[str] = ["http://localhost:5173", "http://127.0.0.1:5173"]
    log_retention_days: int = 90

    class Config:
        env_file = ".env"


settings = Settings()
