from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    DATABASE_URL: str
    JWT_SECRET_KEY: str
    ADMIN_USERNAME: str
    ADMIN_PASSWORD: str
    GOOGLE_SAFE_BROWSING_API_KEY: str = ""
    REDIS_URL: str = "redis://localhost:6379"
    DEBUG: bool = False
    ALLOWED_ORIGINS: list[str] = []
    TEST_MODE: bool = False

    class Config:
        env_file = ".env"


settings = Settings()