from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "ContextVuln API"
    app_env: str = "development"
    gemini_api_key: str = ""
    gemini_model: str = "gemini-2.5-flash"
    cors_origins: list[str] = ["http://localhost:5173", "http://127.0.0.1:5173"]

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")


settings = Settings()