import asyncio
import httpx
import telegram
from app.core.config import settings

def send_whatsapp_message(to_number: str, message_body: str) -> bool:
    """
    Sends a WhatsApp message via the custom Node.js WhatsApp Bot Server API.
    Returns:
        bool: True if sent successfully, False otherwise.
    """
    url = settings.WHATSAPP_API_URL
    api_key = settings.WHATSAPP_API_KEY
    
    if not url:
        print("Warning: WHATSAPP_API_URL not configured. Skipping WhatsApp alert.")
        return False

    try:
        # Format destination URL (appends /send-message to the base URL)
        send_url = f"{url.rstrip('/')}/send-message"
        
        # Clean up the phone number (remove any leading '+', spaces or non-digits)
        clean_number = "".join(filter(str.isdigit, to_number))
        
        # Build payload
        payload = {
            "phone": clean_number,
            "message": message_body
        }
        
        # Build headers
        headers = {}
        if api_key:
            headers["x-api-key"] = api_key

        print(f"WhatsApp Bot: Sending message to '{clean_number}' via Custom API at '{send_url}'...")
        
        # Call the Node.js API synchronously
        response = httpx.post(send_url, json=payload, headers=headers, timeout=10.0)
        
        if response.status_code == 200:
            print("WhatsApp Bot: Message successfully sent.")
            return True
        else:
            print(f"WhatsApp Bot: Failed to send message. HTTP Status: {response.status_code}, Response: {response.text}")
            raise Exception(f"WhatsApp Bot Server returned status {response.status_code}: {response.text}")
            
    except Exception as e:
        print(f"WhatsApp Bot: Error sending message via custom API: {e}")
        # Raise exception to propagate details to the database logging
        raise e

async def send_telegram_message(message_body: str, target_chat_id: str = None) -> bool:
    """
    Sends a Telegram alert via Telegram Bot API using HTML formatting.
    Returns:
        bool: True if sent successfully, False otherwise.
    """
    bot_token = settings.TELEGRAM_BOT_TOKEN
    chat_id = target_chat_id or settings.TELEGRAM_CHAT_ID
    
    if not bot_token or not chat_id:
        print("Warning: Telegram Bot credentials not configured. Skipping Telegram alert.")
        return False

    try:
        bot = telegram.Bot(token=bot_token)
        print(f"Telegram: Sending alert to chat ID '{chat_id}'...")
        
        # Send message asynchronously using the correct SDK method
        await bot.send_message(
            chat_id=chat_id,
            text=message_body,
            parse_mode=telegram.constants.ParseMode.HTML
        )
        print(f"Telegram: Alert message successfully sent to '{chat_id}'.")
        return True
    except Exception as e:
        print(f"Telegram: Error sending Telegram message to '{chat_id}': {e}")
        return False
