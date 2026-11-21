from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    app_name: str = "ContextVuln API"
    app_env: str = "development"
    grok_api_key: str = ""
    grok_model: str = "grok-3-mini"
    grok_base_url: str = "https://api.x.ai/v1/chat/completions"
    cors_origins: list[str] = ["http://localhost:5173", "http://127.0.0.1:5173"]

    class Config:
        env_file = ".env"
        extra = "ignore"

settings = Settings()