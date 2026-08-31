import os
from typing import Optional
from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    # JWT security settings
    SECRET_KEY: str = "a_very_secret_jwt_signing_key_for_wachay_v2"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 1440  # 1 day expiration for easier deployment testing

    # Database Settings
    DATABASE_URL: str = "sqlite:///instance/wachay.db"

    # Custom WhatsApp Bot API settings (replacing Twilio)
    WHATSAPP_API_URL: str = "http://localhost:3000"
    WHATSAPP_API_KEY: Optional[str] = "clinic-secret-token-12345"

    # Twilio API credentials for WhatsApp
    TWILIO_ACCOUNT_SID: Optional[str] = None
    TWILIO_AUTH_TOKEN: Optional[str] = None
    TWILIO_PHONE_NUMBER: str = "whatsapp:+14155238886"  # Twilio sandbox number

    # Telegram Bot API credentials
    TELEGRAM_BOT_TOKEN: Optional[str] = None
    TELEGRAM_CHAT_ID: Optional[str] = None

    # OpenWeatherMap API credentials
    OPENWEATHER_API_KEY: Optional[str] = None

    # Gemini Generative AI credentials
    GEMINI_API_KEY: Optional[str] = None

    # App directories
    BASE_DIR: str = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

    model_config = SettingsConfigDict(
        env_file=os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), ".env"),
        env_file_encoding="utf-8",
        extra="ignore"
    )

settings = Settings()
