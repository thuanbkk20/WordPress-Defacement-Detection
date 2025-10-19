# defacement/scripts/create_baseline.py
import os, json, hashlib, time
from utils import get_db_conn, env, parse_active_plugins

BASELINE_PATH = env("BASELINE_PATH","./snapshots/baseline.json")

def sha256(text):
    return hashlib.sha256((text or "").encode('utf-8', errors='ignore')).hexdigest()

def snapshot_options(conn):
    keys = ['siteurl','home','blogname','admin_email','template','stylesheet','WPLANG','active_plugins']
    sql = "SELECT option_name, option_value FROM wp_options WHERE option_name IN (%s)" % ",".join(["%s"]*len(keys))
    with conn.cursor() as cur:
        cur.execute(sql, keys)
        rows = cur.fetchall()
    out = {}
    for r in rows:
        name = r['option_name']
        val = r['option_value']
        if name == 'active_plugins':
            out[name] = parse_active_plugins(val)
        else:
            out[name] = val
    return out

def snapshot_posts(conn):
    sql = "SELECT ID, post_title, post_content, post_status, post_type, post_modified FROM wp_posts WHERE post_type IN ('post','page')"
    out={}
    with conn.cursor() as cur:
        cur.execute(sql)
        rows = cur.fetchall()
    for r in rows:
        content = r.get('post_content') or ""
        out[str(r['ID'])] = {
            "post_title": r.get('post_title'),
            "sha256": sha256(content),
            "len": len(content),
            "snippet": content[:500],
            "post_status": r.get('post_status'),
            "post_type": r.get('post_type'),
            "post_modified": str(r.get('post_modified'))
        }
    return out

def snapshot_postmeta(conn, limit_keys=None):
    # we snapshot only meta that may contain header/footer or big text;
    sql = "SELECT meta_id, post_id, meta_key, meta_value FROM wp_postmeta"
    params = []
    if limit_keys:
        sql += " WHERE " + " OR ".join(["meta_key=%s"]*len(limit_keys))
        params = limit_keys
    out={}
    with conn.cursor() as cur:
        cur.execute(sql, params)
        rows = cur.fetchall()
    for r in rows:
        val = r.get('meta_value') or ""
        out[str(r['meta_id'])] = {
            "post_id": r['post_id'],
            "meta_key": r['meta_key'],
            "sha256": sha256(val),
            "snippet": val[:300]
        }
    return out

def snapshot_users(conn):
    sql = """SELECT u.ID, u.user_login, u.user_email,
                    (SELECT meta_value FROM wp_usermeta m WHERE m.user_id=u.ID AND m.meta_key='wp_capabilities' LIMIT 1) as caps
             FROM wp_users u"""
    out={}
    with conn.cursor() as cur:
        cur.execute(sql)
        rows = cur.fetchall()
    import phpserialize
    for r in rows:
        caps = r.get('caps')
        roles=[]
        try:
            if caps:
                parsed = phpserialize.loads(caps.encode() if isinstance(caps,str) else caps, decode_strings=True)
                if isinstance(parsed, dict):
                    roles = list(parsed.keys())
        except Exception:
            roles=[]
        out[str(r['ID'])] = {
            "user_login": r.get('user_login'),
            "user_email": r.get('user_email'),
            "roles": roles
        }
    return out

def create_baseline():
    conn = get_db_conn()
    try:
        baseline = {
            "ts": int(time.time()),
            "options": snapshot_options(conn),
            "posts": snapshot_posts(conn),
            "postmeta": snapshot_postmeta(conn, limit_keys=None),
            "users": snapshot_users(conn)
        }
        os.makedirs(os.path.dirname(BASELINE_PATH), exist_ok=True)
        with open(BASELINE_PATH,'w',encoding='utf-8') as f:
            json.dump(baseline,f,ensure_ascii=False,indent=2)
        print("Baseline saved to", BASELINE_PATH)
    finally:
        conn.close()

if __name__ == "__main__":
    create_baseline()
