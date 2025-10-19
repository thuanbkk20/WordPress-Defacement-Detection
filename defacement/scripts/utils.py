# defacement/scripts/utils.py
import os
from dotenv import load_dotenv
import pymysql
import phpserialize
import json

load_dotenv(dotenv_path=os.path.join(os.path.dirname(__file__), '..', '.env'))

def env(key, default=None):
    return os.getenv(key, default)

def get_db_conn():
    return pymysql.connect(
        host=env("DB_HOST","127.0.0.1"),
        port=int(env("DB_PORT", "3306")),
        user=env("DB_USER","root"),
        password=env("DB_PASS",""),
        database=env("DB_NAME","wordpress"),
        charset='utf8mb4',
        cursorclass=pymysql.cursors.DictCursor
    )

def parse_active_plugins(serialized):
    """
    Parse serialized PHP array value stored in wp_options.active_plugins
    Returns list of plugin entries or [] on error.
    """
    try:
        if not serialized:
            return []
        data = phpserialize.loads(serialized.encode() if isinstance(serialized, str) else serialized, decode_strings=True)
        if isinstance(data, dict):
            # data like {0: 'plugin/file.php', ...}
            return [v for k,v in data.items()]
        elif isinstance(data, list) or isinstance(data, tuple):
            return list(data)
        else:
            # fallback: search pattern
            import re
            return re.findall(r'([a-zA-Z0-9_\-]+/[a-zA-Z0-9_\-\.]+\.php)', str(serialized))
    except Exception:
        return []
