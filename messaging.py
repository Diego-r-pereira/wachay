import os
from twilio.rest import Client
import telegram
import asyncio

# Load environment variables from config.py
from config import Config

# Twilio
TWILIO_ACCOUNT_SID = Config.ACCOUNT_SID
TWILIO_AUTH_TOKEN = Config.AUTH_TOKEN
# IMPORTANT: Replace with your Twilio WhatsApp-enabled phone number
TWILIO_PHONE_NUMBER = os.getenv("TWILIO_PHONE_NUMBER", "+14155238886") # Default to Twilio sandbox number

# Telegram
TELEGRAM_BOT_TOKEN = Config.TELEGRAM_BOT_TOKEN
TELEGRAM_CHAT_ID = Config.TELEGRAM_CHAT_ID

def send_whatsapp_message(to_number, message_body):
    if not TWILIO_ACCOUNT_SID or not TWILIO_AUTH_TOKEN:
        print("Twilio credentials not set. Skipping WhatsApp message.")
        return

    client = Client(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN)
    try:
        message = client.messages.create(
            from_=f'whatsapp:{TWILIO_PHONE_NUMBER}',
            body=message_body,
            to=f'whatsapp:{to_number}'
        )
        print(f"WhatsApp message sent: {message.sid}")
    except Exception as e:
        print(f"Error sending WhatsApp message: {e}")

async def send_telegram_message(message_body):
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        print("Telegram credentials not set. Skipping Telegram message.")
        return

    bot = telegram.Bot(token=TELEGRAM_BOT_TOKEN)
    try:
        await bot.send_message(chat_id=TELEGRAM_CHAT_ID, text=message_body, parse_mode=telegram.constants.ParseMode.HTML)
        print("Telegram message sent.")
    except Exception as e:
        print(f"Error sending Telegram message: {e}")

if __name__ == '__main__':
    # Example usage (for testing)
    # Replace with actual numbers for testing
    test_whatsapp_number = "+1234567890" # Your WhatsApp number with country code
    test_telegram_chat_id = "YOUR_TELEGRAM_CHAT_ID" # Your Telegram chat ID

    # You can test these functions by uncommenting them and running this file directly
    # send_whatsapp_message(test_whatsapp_number, "ALERTA: Test WhatsApp message from Wachay!")
    # asyncio.run(send_telegram_message("<b>ALERTA:</b> Test Telegram message from Wachay!"))
    pass
