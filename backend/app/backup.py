import os
import sqlite3
from app.core.config import settings

def perform_hot_backup() -> str:
    """
    Performs a consistent hot backup byte-by-byte of the active SQLite database file.
    Does not block active read/write transactions.
    Returns:
        str: Absolute path to the created backup database file, or raises Exception on failure.
    """
    db_url = settings.DATABASE_URL
    
    # Hot backup is only applicable for SQLite databases.
    if not db_url.startswith("sqlite"):
        raise ValueError("Hot Backup utility is only compatible with SQLite engine.")

    # Extract source file path from SQLite URI
    # standard format: sqlite:///instance/wachay.db or sqlite:///C:/path/to/db
    src_db_path = db_url.replace("sqlite:///", "")
    
    # Resolve relative paths relative to base folder
    if not os.path.isabs(src_db_path):
        src_db_path = os.path.join(settings.BASE_DIR, src_db_path)

    if not os.path.exists(src_db_path):
        raise FileNotFoundError(f"Source database file not found at: {src_db_path}")

    # Define destination backup file name
    backup_dir = os.path.join(settings.BASE_DIR, "backend", "instance", "backups")
    os.makedirs(backup_dir, exist_ok=True)
    
    from datetime import datetime
    backup_filename = f"backup_wachay_{datetime.now().strftime('%Y%m%d_%H%M%S')}.db"
    dest_db_path = os.path.join(backup_dir, backup_filename)

    print(f"Backup: Initializing hot backup from '{src_db_path}' -> '{dest_db_path}'...")
    
    src_conn = None
    dest_conn = None
    try:
        src_conn = sqlite3.connect(src_db_path)
        dest_conn = sqlite3.connect(dest_db_path)
        
        # Execute hot backup using python sqlite3 native backup method
        with dest_conn:
            src_conn.backup(dest_conn)
            
        print("Backup: Hot backup successfully completed.")
        return dest_db_path
    except Exception as e:
        print(f"Backup: Error executing hot backup: {e}")
        # Clean up failed backup file if created
        if os.path.exists(dest_db_path):
            os.remove(dest_db_path)
        raise e
    finally:
        if src_conn:
            src_conn.close()
        if dest_conn:
            dest_conn.close()
