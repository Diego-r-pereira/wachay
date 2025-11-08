from twilio.rest import Client
import telebot

# Your Account SID and Auth Token from twilio.com/console
# and your Telegram Bot Token from BotFather
ACCOUNT_SID = 'YOUR_TWILIO_ACCOUNT_SID'
AUTH_TOKEN = 'YOUR_TWILIO_AUTH_TOKEN'
TELEGRAM_BOT_TOKEN = 'YOUR_TELEGRAM_BOT_TOKEN'
TELEGRAM_CHAT_ID = 'YOUR_TELEGRAM_CHAT_ID'

def send_whatsapp_message(body):
    """
    Sends a WhatsApp message using Twilio.
    """
    try:
        client = Client(ACCOUNT_SID, AUTH_TOKEN)
        message = client.messages.create(
            from_='whatsapp:+14155238886',  # Twilio sandbox number
            body=body,
            to='whatsapp:YOUR_WHATSAPP_NUMBER'
        )
        print(f"WhatsApp message sent: {message.sid}")
    except Exception as e:
        print(f"Error sending WhatsApp message: {e}")

def send_telegram_message(body):
    """
    Sends a Telegram message using Telebot.
    """
    try:
        bot = telebot.TeleBot(TELEGRAM_BOT_TOKEN)
        bot.send_message(TELEGRAM_CHAT_ID, body)
        print("Telegram message sent.")
    except Exception as e:
        print(f"Error sending Telegram message: {e}")
