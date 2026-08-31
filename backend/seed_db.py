import os
import random
from datetime import datetime, timedelta
from app.core.database import SessionLocal, Base, engine
from app.models.user import User
from app.models.report import Report
from app.models.bombero import Bombero

# Predefined realistic locations in Bolivian National Parks and Cochabamba region
BOLIVIA_LOCATIONS = [
    {
        "name": "Parque Nacional Tunari (Sector Taquiña)",
        "latitude": -17.2954,
        "longitude": -66.1832,
        "veg": "Matorral y Pastizal de Altura",
        "desc": "Foco de calor avistado en la ladera alta del Tunari. Se propaga rápidamente debido al viento cuesta arriba."
    },
    {
        "name": "Parque Nacional Tunari (Sector Andrada)",
        "latitude": -17.3120,
        "longitude": -66.1420,
        "veg": "Pinos y Eucaliptos",
        "desc": "Incendio de copas en zona forestada de pino. Brigadas comunitarias se movilizan para cortar línea de fuego."
    },
    {
        "name": "Parque Nacional Carrasco (Valle del Sajta)",
        "latitude": -17.4500,
        "longitude": -65.2500,
        "veg": "Bosque Húmedo de Montaña",
        "desc": "Quema de vegetación secundaria para cultivo (chaqueo) fuera de control cerca del límite del parque."
    },
    {
        "name": "TIPNIS (Zona Sur - Isiboro Sécure)",
        "latitude": -16.3500,
        "longitude": -66.1500,
        "veg": "Bosque Seco Tropical",
        "desc": "Quema descontrolada en pastizales secos. Humo visible desde comunidades del Sécure."
    },
    {
        "name": "Valle Alto Cochabamba (Tarata)",
        "latitude": -17.6100,
        "longitude": -66.0200,
        "veg": "Matorrales Espinosos",
        "desc": "Incendio forestal menor en arbustos secos. Riesgo moderado para viviendas periféricas cercanas."
    },
    {
        "name": "Sacaba (Lomas de Aranjuez)",
        "latitude": -17.3200,
        "longitude": -66.0400,
        "veg": "Pastizales",
        "desc": "Fuego de pastos secos iniciado presuntamente por negligencia (colilla de cigarrillo). Controlado rápidamente."
    },
    {
        "name": "Parque Nacional Madidi (Sector San Buenaventura)",
        "latitude": -14.2500,
        "longitude": -68.4500,
        "veg": "Bosque Amazónico",
        "desc": "Línea de fuego detectada por satélite. Bosque alto con vegetación densa de difícil acceso terrestre."
    },
    {
        "name": "Chiquitania (San Ignacio de Velasco)",
        "latitude": -16.3700,
        "longitude": -60.9600,
        "veg": "Bosque Seco Chiquitano",
        "desc": "Gran columna de humo detectada en predio privado. Amenaza activa al bosque seco chiquitano protegido."
    }
]

INCIDENT_TYPES = ["Incendio Forestal", "Quema Agrícola", "Fogata No Controlada", "Incendio de Vegetación", "Falsa Alarma"]
SEVERITY_LEVELS = ["Bajo", "Medio", "Alto", "Crítico"]
PROBABLE_CAUSES = ["Chaqueo Agrícola", "Colilla de Cigarrillo", "Intencional", "Desconocido", "Natural (Rayo)"]

# Users to create
ADMIN_USER = {
    "username": "admin",
    "name": "Administrador",
    "last_name": "General",
    "password": "adminpass",
    "role": "admin"
}

RANGER_DATA = [
    {"username": "ranger_ana", "name": "Ana María", "last_name": "Flores", "password": "rangerpass123", "role": "ranger", "whatsapp": "+59171234567"},
    {"username": "ranger_luis", "name": "Luis Alberto", "last_name": "Quispe", "password": "rangerpass123", "role": "ranger", "whatsapp": "+59172345678"},
    {"username": "ranger_sofia", "name": "Sofía", "last_name": "Mamani", "password": "rangerpass123", "role": "ranger", "whatsapp": "+59173456789"},
    {"username": "ranger_pedro", "name": "Pedro", "last_name": "Condori", "password": "rangerpass123", "role": "ranger", "whatsapp": "+59174567890"},
    {"username": "ranger_elena", "name": "Elena", "last_name": "Vargas", "password": "rangerpass123", "role": "ranger", "whatsapp": "+59175678901"},
    {"username": "ranger_marco", "name": "Marco Antonio", "last_name": "Choque", "password": "rangerpass123", "role": "ranger", "whatsapp": "+59176789012"},
    {"username": "ranger_clara", "name": "Clara", "last_name": "Apaza", "password": "rangerpass123", "role": "ranger", "whatsapp": "+59177890123"}
]

BOMBERO_DATA = [
    # SAR-Bolivia
    {"name": "Carlos", "last_name": "Mendoza", "whatsapp": "+59170011122", "unit": "SAR-Bolivia", "is_leader": True},
    {"name": "David", "last_name": "Rojas", "whatsapp": "+59170011123", "unit": "SAR-Bolivia", "is_leader": False},
    {"name": "Humberto", "last_name": "Pérez", "whatsapp": "+59170011124", "unit": "SAR-Bolivia", "is_leader": False},
    {"name": "Javier", "last_name": "Gutiérrez", "whatsapp": "+59170011125", "unit": "SAR-Bolivia", "is_leader": False},
    {"name": "Roberto", "last_name": "Ortiz", "whatsapp": "+59170011126", "unit": "SAR-Bolivia", "is_leader": False},
    {"name": "Raúl", "last_name": "Gómez", "whatsapp": "+59170011127", "unit": "SAR-Bolivia", "is_leader": False},

    # UGR
    {"name": "Eduardo", "last_name": "Torrico", "whatsapp": "+59170022233", "unit": "UGR", "is_leader": True},
    {"name": "Mario", "last_name": "Suárez", "whatsapp": "+59170022234", "unit": "UGR", "is_leader": False},
    {"name": "Ramiro", "last_name": "Morales", "whatsapp": "+59170022235", "unit": "UGR", "is_leader": False},
    {"name": "Daniel", "last_name": "López", "whatsapp": "+59170022236", "unit": "UGR", "is_leader": False},
    {"name": "Julio", "last_name": "Silva", "whatsapp": "+59170022237", "unit": "UGR", "is_leader": False},
    {"name": "Gualberto", "last_name": "Tapia", "whatsapp": "+59170022238", "unit": "UGR", "is_leader": False},

    # Bomberos Taquiña
    {"name": "Fernando", "last_name": "Vargas", "whatsapp": "+59170033344", "unit": "Bomberos Taquiña", "is_leader": True},
    {"name": "Hugo", "last_name": "Guerrero", "whatsapp": "+59170033345", "unit": "Bomberos Taquiña", "is_leader": False},
    {"name": "Santiago", "last_name": "Copa", "whatsapp": "+59170033346", "unit": "Bomberos Taquiña", "is_leader": False},
    {"name": "Juan", "last_name": "Beltrán", "whatsapp": "+59170033347", "unit": "Bomberos Taquiña", "is_leader": False},
    {"name": "Néstor", "last_name": "Cardozo", "whatsapp": "+59170033348", "unit": "Bomberos Taquiña", "is_leader": False},
    {"name": "Ignacio", "last_name": "Rada", "whatsapp": "+59170033349", "unit": "Bomberos Taquiña", "is_leader": False},
]

# Simple Python implementation of Geohash encoder to avoid dependency errors
def encode_geohash(latitude, longitude, precision=8):
    base32 = "0123456789bcdefghjkmnpqrstuvwxyz"
    lat_interval = (-90.0, 90.0)
    lon_interval = (-180.0, 180.0)
    geohash = []
    bits = [16, 8, 4, 2, 1]
    bit = 0
    ch = 0
    even = True
    while len(geohash) < precision:
        if even:
            mid = (lon_interval[0] + lon_interval[1]) / 2
            if longitude > mid:
                ch |= bits[bit]
                lon_interval = (mid, lon_interval[1])
            else:
                lon_interval = (lon_interval[0], mid)
        else:
            mid = (lat_interval[0] + lat_interval[1]) / 2
            if latitude > mid:
                ch |= bits[bit]
                lat_interval = (mid, lat_interval[1])
            else:
                lat_interval = (lat_interval[0], mid)
        even = not even
        if bit < 4:
            bit += 1
        else:
            geohash.append(base32[ch])
            bit = 0
            ch = 0
    return "".join(geohash)

def seed_database():
    db = SessionLocal()
    try:
        print("1. Creando tablas de la base de datos (si no existen)...")
        Base.metadata.create_all(bind=engine)

        print("2. Limpiando datos existentes...")
        db.query(Report).delete()
        db.query(User).delete()
        db.query(Bombero).delete()
        db.commit()

        print("3. Creando usuario administrador por defecto...")
        admin = User(
            username=ADMIN_USER["username"],
            name=ADMIN_USER["name"],
            last_name=ADMIN_USER["last_name"],
            role=ADMIN_USER["role"]
        )
        admin.set_password(ADMIN_USER["password"])
        db.add(admin)

        print("4. Creando usuarios con el rol de guardaparques...")
        rangers = []
        for r_info in RANGER_DATA:
            ranger = User(
                username=r_info["username"],
                name=r_info["name"],
                last_name=r_info["last_name"],
                role=r_info["role"],
                whatsapp_number=r_info["whatsapp"]
            )
            ranger.set_password(r_info["password"])
            db.add(ranger)
            rangers.append(ranger)
        db.commit()

        print("4b. Creando bomberos y líderes de brigadas...")
        for b_info in BOMBERO_DATA:
            bombero = Bombero(
                name=b_info["name"],
                last_name=b_info["last_name"],
                whatsapp_number=b_info["whatsapp"],
                fire_unit=b_info["unit"],
                is_leader=b_info["is_leader"]
            )
            db.add(bombero)
        db.commit()

        print("5. Creando reportes de incidentes reales e históricos en Bolivia...")
        base_date = datetime.now() - timedelta(days=60)
        reports_added = 0

        # Generate 25 reports distributed over the last two months
        for i in range(25):
            loc = random.choice(BOLIVIA_LOCATIONS)
            ranger = random.choice(rangers)
            
            # Formulate incident type and severity
            inc_type = random.choice(INCIDENT_TYPES)
            severity = random.choice(SEVERITY_LEVELS)
            cause = random.choice(PROBABLE_CAUSES)
            
            # Status distribution: Citizen_Pending, First_State, Second_State, Attended, Rejected
            status = random.choice(["Citizen_Pending", "First_State", "Second_State", "Attended", "Rejected"])
            source = "citizen" if status == "Citizen_Pending" else "ranger"
            
            det_time = base_date + timedelta(days=i * 2, hours=random.randint(1, 23))
            arr_time = det_time + timedelta(minutes=random.randint(20, 180)) if status != "Citizen_Pending" else None
            con_time = arr_time + timedelta(hours=random.randint(1, 48)) if status in ["Second_State", "Attended"] else None

            # Calculate mock metrics
            affected_area = round(random.uniform(0.5, 45.0), 2) if status in ["Second_State", "Attended"] else None
            est_cost = round(random.uniform(200.0, 5000.0), 2) if status in ["Second_State", "Attended"] else None

            # Notifications
            whatsapp_sent = random.choice([True, False])
            telegram_sent = random.choice([True, False])
            notif_status = "Sent" if (whatsapp_sent or telegram_sent) else "Pending"

            tracking_code = f"WCY{random.randint(10000, 99999)}" if source == "citizen" else None
            geohash_str = encode_geohash(loc["latitude"], loc["longitude"])

            report = Report(
                status=status,
                source=source,
                tracking_code=tracking_code,
                rejection_reason="Falsa alarma detectada por la patrulla de control" if status == "Rejected" else None,
                citizen_name=f"Denunciante {random.randint(1, 50)}" if source == "citizen" else None,
                citizen_email=f"contacto{random.randint(1, 50)}@gmail.com" if source == "citizen" else None,
                
                # First State
                ranger_name=None if source == "citizen" else f"{ranger.name} {ranger.last_name}",
                incident_type=inc_type,
                severity_level=severity,
                detection_time=det_time,
                arrival_time=arr_time,
                probable_cause=cause,
                latitude=loc["latitude"] + random.uniform(-0.02, 0.02),
                longitude=loc["longitude"] + random.uniform(-0.02, 0.02),
                google_maps_link=f"https://www.google.com/maps?q={loc['latitude']},{loc['longitude']}",
                weather_conditions=f"Temp: {random.randint(18, 33)}°C, Humedad: {random.randint(20, 60)}%, Viento: {random.randint(10, 35)}km/h",
                vegetation_type=loc["veg"],
                description=f"{loc['desc']} ({inc_type} nivel {severity})",
                geohash=geohash_str,

                # Second State
                control_time=con_time,
                affected_area=affected_area,
                deployed_resources="1 Brigada de guardaparques del SERNAP, 2 carros cisterna municipales" if status in ["Second_State", "Attended"] else None,
                materials_used="Mochilas extintoras, herramientas batefuegos y pulaski" if status in ["Second_State", "Attended"] else None,
                estimated_cost=est_cost,

                # Notifications
                whatsapp_sent=whatsapp_sent,
                telegram_sent=telegram_sent,
                notification_status=notif_status
            )
            db.add(report)
            reports_added += 1

        db.commit()
        print(f"6. Base de datos poblada exitosamente con {reports_added} reportes y {len(RANGER_DATA)} guardaparques.")
    
    except Exception as e:
        db.rollback()
        print(f"❌ Error en la siembra de la base de datos: {e}")
    finally:
        db.close()

if __name__ == "__main__":
    seed_database()
