# defacement/scripts/detector.py
import os, json, time, re, smtplib
from email.message import EmailMessage
from utils import get_db_conn, env, parse_active_plugins
import hashlib
from datetime import datetime

BASELINE_PATH = env("BASELINE_PATH","./snapshots/baseline.json")
ALERT_DIR = env("ALERT_DIR","./alerts")
LOG_FILE = env("LOG_FILE","./logs/detector.log")
ALERT_EMAIL_TO = env("ALERT_EMAIL_TO","admin@example.local")
SMTP_HOST = env("SMTP_HOST","127.0.0.1")
SMTP_PORT = int(env("SMTP_PORT","25"))
SMTP_USER = env("SMTP_USER","")
SMTP_PASS = env("SMTP_PASS","")
SLACK_WEBHOOK = env("SLACK_WEBHOOK","")
ADMIN_USER_IDS = [s.strip() for s in env("ADMIN_USER_IDS","1").split(",") if s.strip()]

SUSPICIOUS_RE = re.compile(r"(?i)(<script\b|<iframe\b|eval\(|base64_decode\(|onerror=|javascript:|hacked by|pwned|owned by|ransom)")

def log(msg):
    ts = datetime.now().isoformat()
    line = f"[{ts}] {msg}\n"
    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
    with open(LOG_FILE,'a',encoding='utf-8') as f:
        f.write(line)
    print(line, end="")

def sha256(text):
    return hashlib.sha256((text or "").encode('utf-8', errors='ignore')).hexdigest()

def load_baseline():
    if not os.path.exists(BASELINE_PATH):
        return None
    with open(BASELINE_PATH,'r',encoding='utf-8') as f:
        return json.load(f)

def snapshot_current(conn):
    # reuse code similar to create_baseline
    cur={}
    with conn.cursor() as c:
        # options
        keys = ['siteurl','home','blogname','admin_email','template','stylesheet','WPLANG','active_plugins']
        sql = "SELECT option_name, option_value FROM wp_options WHERE option_name IN (%s)" % ",".join(["%s"]*len(keys))
        c.execute(sql, keys)
        rows = c.fetchall()
        opts={}
        for r in rows:
            name = r['option_name']; val = r['option_value']
            if name=='active_plugins':
                opts[name]= parse_active_plugins(val)
            else:
                opts[name]= val
        # posts
        c.execute("SELECT ID, post_title, post_content, post_status, post_type, post_modified, post_author FROM wp_posts WHERE post_type IN ('post','page')")
        p_rows = c.fetchall()
        posts={}
        for r in p_rows:
            cid = str(r['ID'])
            content = r.get('post_content') or ""
            posts[cid] = {
                "post_title": r.get('post_title'),
                "sha256": sha256(content),
                "len": len(content),
                "snippet": content[:400],
                "post_status": r.get('post_status'),
                "post_type": r.get('post_type'),
                "post_modified": str(r.get('post_modified')),
                "post_author": str(r.get('post_author'))
            }
        # postmeta (scan for suspicious content only to avoid heavy IO)
        c.execute("SELECT meta_id, post_id, meta_key, LEFT(meta_value,300) AS snippet, meta_value FROM wp_postmeta")
        pm_rows = c.fetchall()
        postmeta = {}
        for r in pm_rows:
            meta_val = r.get('meta_value') or ""
            postmeta[str(r['meta_id'])] = {
                "post_id": r['post_id'],
                "meta_key": r['meta_key'],
                "snippet": r.get('snippet'),
                "sha256": sha256(meta_val)
            }
        # users
        c.execute("""SELECT u.ID, u.user_login, u.user_email,
                            (SELECT meta_value FROM wp_usermeta m WHERE m.user_id=u.ID AND m.meta_key='wp_capabilities' LIMIT 1) as caps
                     FROM wp_users u""")
        u_rows = c.fetchall()
        users={}
        import phpserialize
        for r in u_rows:
            caps = r.get('caps')
            roles=[]
            try:
                if caps:
                    parsed = phpserialize.loads(caps.encode() if isinstance(caps,str) else caps, decode_strings=True)
                    if isinstance(parsed, dict):
                        roles = list(parsed.keys())
            except Exception:
                roles=[]
            users[str(r['ID'])] = {"user_login": r['user_login'], "user_email": r['user_email'], "roles": roles}
    return {"options": opts, "posts": posts, "postmeta": postmeta, "users": users}

def send_email(subject, body):
    try:
        msg = EmailMessage()
        msg["From"] = "noreply@local"
        msg["To"] = ALERT_EMAIL_TO
        msg["Subject"] = subject
        msg.set_content(body)
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=10) as s:
            if SMTP_USER and SMTP_PASS:
                s.login(SMTP_USER, SMTP_PASS)
            s.send_message(msg)
        log("Email sent")
    except Exception as e:
        log(f"Failed to send email: {e}")

def create_alert(payload):
    os.makedirs(ALERT_DIR, exist_ok=True)
    fname = os.path.join(ALERT_DIR, f"alert_{int(time.time())}.json")
    with open(fname,'w',encoding='utf-8') as f:
        json.dump(payload,f,ensure_ascii=False,indent=2)
    log(f"Alert saved to {fname}")
    # send email
    subject = f"[DETECTOR] {payload.get('severity','INFO')} indicators on {env('DB_NAME')}"
    body = json.dumps(payload, indent=2, ensure_ascii=False)
    send_email(subject, body)
    # optional slack omitted for brevity

def detect(baseline, current):
    alerts=[]
    # 1) options change
    for key in ('siteurl','home','blogname','admin_email','template','stylesheet'):
        b = baseline.get('options',{}).get(key) if baseline else None
        c = current.get('options',{}).get(key)
        if b is not None and c is not None and b != c:
            severity = "CRITICAL" if key in ('siteurl','home') else "HIGH"
            alerts.append({"rule":"option_changed","severity":severity,"field":key,"old":b,"new":c})
    # active_plugins change
    base_plugins = set(baseline.get('options',{}).get('active_plugins') or []) if baseline else set()
    cur_plugins = set(current.get('options',{}).get('active_plugins') or [])
    if baseline and base_plugins != cur_plugins:
        added = list(cur_plugins - base_plugins)
        removed = list(base_plugins - cur_plugins)
        alerts.append({"rule":"plugins_changed","severity":"HIGH","added":added,"removed":removed})
    # 2) new admin?
    base_admins = {uid for uid,u in (baseline.get('users') or {}).items() if 'administrator' in (u.get('roles') or [])}
    cur_admins = {uid for uid,u in (current.get('users') or {}).items() if 'administrator' in (u.get('roles') or [])}
    new_admins = cur_admins - base_admins
    if new_admins:
        alerts.append({"rule":"new_admin","severity":"CRITICAL","new_admin_ids":list(new_admins)})
    # 3) posts changes & suspicious content
    for pid, pcur in current.get('posts',{}).items():
        pbase = (baseline.get('posts') or {}).get(pid) if baseline else None
        # suspicious regex
        if SUSPICIOUS_RE.search(pcur.get('snippet') or ""):
            alerts.append({"rule":"post_content_suspicious","severity":"HIGH","post_id":pid,"post_title":pcur.get('post_title'),"snippet":pcur.get('snippet')})
        if pbase and pbase.get('sha256') != pcur.get('sha256'):
            # len ratio
            try:
                ratio = (pcur.get('len') or 0) / (pbase.get('len') or 1)
            except Exception:
                ratio = 999
            severity = "HIGH" if (ratio>3 or ratio<0.3) else "MEDIUM"
            alerts.append({"rule":"post_changed","severity":severity,"post_id":pid,"post_title":pcur.get('post_title'),"old_hash":pbase.get('sha256'),"new_hash":pcur.get('sha256'),"len_ratio":ratio})
    
        if pbase.get('post_title') != pcur.get('post_title'):
            alerts.append({
                "rule": "post_title_changed",
                "severity": "MEDIUM",
                "post_id": pid,
                "old_title": pbase.get('post_title'),
                "new_title": pcur.get('post_title')
            })

    # 4) postmeta / options suspicious patterns
    # check options full values for suspicious patterns
    for k,v in (current.get('options') or {}).items():
        if isinstance(v, str) and SUSPICIOUS_RE.search(v):
            alerts.append({"rule":"option_contains_suspicious","severity":"HIGH","option":k,"snippet":v[:300]})
    for mid,m in (current.get('postmeta') or {}).items():
        if SUSPICIOUS_RE.search((m.get('snippet') or "")):
            alerts.append({"rule":"postmeta_suspicious","severity":"HIGH","meta_id":mid,"post_id":m.get('post_id'),"meta_key":m.get('meta_key'),"snippet":m.get('snippet')})
    return alerts

def run_once():
    baseline = None
    if os.path.exists(BASELINE_PATH):
        with open(BASELINE_PATH,'r',encoding='utf-8') as f:
            baseline = json.load(f)
    else:
        log("No baseline found - please run create_baseline.py first.")
        return

    conn = get_db_conn()
    try:
        current = snapshot_current(conn)
    finally:
        conn.close()

    alerts = detect(baseline, current)
    if alerts:
        payload = {
            "ts": datetime.utcnow().isoformat()+"Z",
            "site": env("DB_NAME"),
            "severity": max([a['severity'] for a in alerts], key=lambda s: ['INFO','MEDIUM','HIGH','CRITICAL'].index(s) if s in ['INFO','MEDIUM','HIGH','CRITICAL'] else 0),
            "alerts": alerts
        }
        create_alert(payload)
    else:
        log("No alerts found.")

if __name__ == "__main__":
    run_once()
