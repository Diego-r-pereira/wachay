import time
import httpx
from typing import Dict, Tuple, Any
from app.core.config import settings

# In-memory local cache for weather data to avoid excessive external API hits.
# Policy: Cache weather for a given (lat, lon) for 15 minutes (900 seconds).
# Schema: {(rounded_lat, rounded_lon): (weather_dict, cache_timestamp)}
weather_cache: Dict[Tuple[float, float], Tuple[Dict[str, Any], float]] = {}
CACHE_DURATION = 900  # 15 minutes in seconds

def get_weather_data(lat: float, lon: float) -> Dict[str, Any]:
    """
    Retrieves current weather (temp, humidity, wind speed, description) for coordinates.
    Employs a 15-minute in-memory cache.
    Returns:
        Dict: {
            "temp": float,           # in Celsius
            "humidity": float,       # in %
            "wind_speed": float,     # in km/h
            "description": str,      # weather description
            "raw_text": str          # compiled description for report saving
        }
    """
    # Round coordinates to 3 decimal places (~110m resolution) to group nearby cache entries
    r_lat = round(lat, 3)
    r_lon = round(lon, 3)
    coords = (r_lat, r_lon)
    
    current_time = time.time()
    
    # Check cache
    if coords in weather_cache:
        cached_data, timestamp = weather_cache[coords]
        if current_time - timestamp < CACHE_DURATION:
            print(f"Serving weather from cache for coordinates: {coords}")
            return cached_data

    # Check for API key
    api_key = settings.OPENWEATHER_API_KEY
    if not api_key:
        print("Warning: OPENWEATHER_API_KEY is not configured. Serving mock weather data.")
        # Provide reasonable Cochabamba weather simulation
        mock_data = {
            "temp": 24.5,
            "humidity": 45.0,
            "wind_speed": 12.5,
            "description": "Despejado (Simulado)",
            "raw_text": "Temperatura: 24.5°C, Humedad: 45%, Viento: 12.5 km/h, Cielo despejado"
        }
        # Cache the mock data as well to reduce logging spam
        weather_cache[coords] = (mock_data, current_time)
        return mock_data

    # Fetch from OpenWeatherMap API
    url = f"https://api.openweathermap.org/data/2.5/weather"
    params = {
        "lat": lat,
        "lon": lon,
        "appid": api_key,
        "units": "metric"  # Celsius for temp, m/s for wind
    }
    
    try:
        response = httpx.get(url, params=params, timeout=10.0)
        if response.status_code == 200:
            data = response.json()
            temp = data.get("main", {}).get("temp", 20.0)
            humidity = data.get("main", {}).get("humidity", 50.0)
            
            # Wind speed returned in m/s, convert to km/h (1 m/s = 3.6 km/h)
            wind_ms = data.get("wind", {}).get("speed", 3.0)
            wind_kmh = round(wind_ms * 3.6, 2)
            
            desc = data.get("weather", [{}])[0].get("description", "clear sky")
            
            weather_dict = {
                "temp": float(temp),
                "humidity": float(humidity),
                "wind_speed": float(wind_kmh),
                "description": desc.capitalize(),
                "raw_text": f"Temp: {temp}°C, Humedad: {humidity}%, Viento: {wind_kmh} km/h, Condición: {desc.capitalize()}"
            }
            
            # Update cache
            weather_cache[coords] = (weather_dict, current_time)
            return weather_dict
        else:
            print(f"Error fetching weather from OpenWeatherMap: HTTP {response.status_code}. Response: {response.text}")
    except Exception as e:
        print(f"Exception raised during weather API request: {e}")
        
    # Fallback in case of API failure
    return {
        "temp": 20.0,
        "humidity": 50.0,
        "wind_speed": 10.0,
        "description": "Información del clima no disponible",
        "raw_text": "Error al conectar con la API de clima. Valores por defecto aplicados."
    }
