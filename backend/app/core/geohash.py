# Simple Python Geohash Encoder (Pure Python)
# Base32 characters used in Geohash encoding
BASE32 = "0123456789bcdefghjkmnpqrstuvwxyz"
# Map characters to their index value for fast decoding
BASE32_MAP = {char: idx for idx, char in enumerate(BASE32)}

def encode_geohash(latitude: float, longitude: float, precision: int = 9) -> str:
    """
    Encodes coordinates to a Geohash string of the specified precision.
    """
    if latitude is None or longitude is None:
        return None

    # Lat/Lon bounding box limits
    lat_interval = (-90.0, 90.0)
    lon_interval = (-180.0, 180.0)
    
    geohash = []
    bits = 0
    ch = 0
    even_bit = True # even bit is longitude, odd is latitude

    while len(geohash) < precision:
        if even_bit:
            # Longitude partitioning
            mid = (lon_interval[0] + lon_interval[1]) / 2
            if longitude > mid:
                ch |= (1 << (4 - bits))
                lon_interval = (mid, lon_interval[1])
            else:
                lon_interval = (lon_interval[0], mid)
        else:
            # Latitude partitioning
            mid = (lat_interval[0] + lat_interval[1]) / 2
            if latitude > mid:
                ch |= (1 << (4 - bits))
                lat_interval = (mid, lat_interval[1])
            else:
                lat_interval = (lat_interval[0], mid)
        
        even_bit = not even_bit
        if bits < 4:
            bits += 1
        else:
            geohash.append(BASE32[ch])
            bits = 0
            ch = 0
            
    return "".join(geohash)
