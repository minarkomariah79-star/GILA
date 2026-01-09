import asyncio
import socket
import random
import ipaddress
import time
import ssl
import os
import re
import httpx
from datetime import datetime, timezone
from supabase import create_client, Client

# --- IMPORTS FOR DEEP INSPECTOR ---
try:
    import ftplib
    import mysql.connector
    import psycopg2
except ImportError:
    pass # Will fail locally if not installed, but safe in CI

# --- CONFIGURATION ---
SUPABASE_URL = "https://kuvgwsqchmupoyavpuam.supabase.co"
SUPABASE_KEY = "sb_publishable_4MSByTjbGrM_7OH11rBCkQ_2Tfj4bg2"
TABLE_MAP = "internet_map"
TABLE_STATS = "scan_stats"

TARGET_PORTS = [80, 443, 8080, 21, 22, 3306, 5432]
# PRODUCTION MODE SETTINGS
BATCH_SIZE = 100
MAX_CONCURRENCY = 500
RUN_DURATION = 3600  # 1 hour safety limit

# Stats
TOTAL_SCANNED = 0
TOTAL_FOUND = 0
START_TIME = None
CIDR_RANGES = []

# --- STEALTH / BYPASS CONFIG ---
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:120.0) Gecko/20100101 Firefox/120.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/120.0.0.0 Safari/537.36"
]

# Initialize Supabase
supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

def clean_text(text):
    if not text: return text
    return text.replace('\x00', '').replace('\u0000', '')

async def fetch_country_cidrs(country_code):
    """Fetches CIDR list for a specific country from ipdeny.com."""
    url = f"http://www.ipdeny.com/ipblocks/data/countries/{country_code}.zone"
    print(f"[*] Downloading CIDR list for Country: {country_code.upper()}...")
    try:
        async with httpx.AsyncClient() as client:
            resp = await client.get(url, timeout=20)
            if resp.status_code == 200:
                cidrs = [line.strip() for line in resp.text.splitlines() if line.strip()]
                print(f"[*] Loaded {len(cidrs)} CIDRs for {country_code.upper()}")
                return cidrs
    except Exception as e:
        print(f"[!] Country CIDR Fetch Error: {e}")
    return []

def generate_target_ip():
    """Generates random IP from the loaded CIDR_RANGES."""
    global CIDR_RANGES
    while True:
        try:
            if not CIDR_RANGES:
                # Should not happen in prod if fetched correctly, but fallback safety
                return None

            cidr = random.choice(CIDR_RANGES)
            net = ipaddress.IPv4Network(cidr, strict=False)

            if net.num_addresses > 2:
                rand_idx = random.randint(1, net.num_addresses - 2)
                ip_obj = net[rand_idx]
                return str(ip_obj)
        except:
            continue

def get_random_headers():
    fake_ip = f"{random.randint(1,255)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(0,255)}"
    referer = random.choice(["https://www.google.com/", "https://www.bing.com/", "https://duckduckgo.com/"])

    return f"User-Agent: {random.choice(USER_AGENTS)}\r\n" \
           f"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n" \
           f"Accept-Language: en-US,en;q=0.5\r\n" \
           f"Referer: {referer}\r\n" \
           f"X-Forwarded-For: {fake_ip}\r\n" \
           f"Connection: close\r\n"

def detect_software(banner):
    if not banner: return None, None
    pattern = r'(?:Server: )?([a-zA-Z0-9\-\_]+)(?:/([0-9\.]+))?'
    match = re.search(pattern, banner, re.IGNORECASE)
    if match:
        software = match.group(1)
        version = match.group(2)
        return software, version
    return None, None

async def get_geo_info(ip, http_client):
    url = f"http://ip-api.com/json/{ip}"
    try:
        response = await http_client.get(url, timeout=5.0)
        if response.status_code == 429:
            return None, None
        data = response.json()
        if data.get('status') == 'success':
            return data.get('country'), data.get('isp')
    except Exception:
        pass
    return None, None

# --- AUTH CHECKERS ---
def check_ftp_anon(ip):
    try:
        ftp = ftplib.FTP()
        ftp.connect(ip, 21, timeout=3)
        ftp.login()
        ftp.quit()
        return True
    except:
        return False

def check_mysql_open(ip):
    try:
        conn = mysql.connector.connect(host=ip, user='root', password='', connection_timeout=3)
        conn.close()
        return True
    except:
        return False

def check_postgres_open(ip):
    try:
        conn = psycopg2.connect(host=ip, user='postgres', password='', connect_timeout=3)
        conn.close()
        return True
    except:
        return False

async def grab_banner(ip, port):
    conn_timeout = 2.0
    read_timeout = 2.0

    banner = ""
    title = ""
    ssl_info = {}
    raw_html = ""
    vuln_env = False
    vuln_auth = False

    loop = asyncio.get_running_loop()

    if port == 21:
        vuln_auth = await loop.run_in_executor(None, check_ftp_anon, ip)
    elif port == 3306:
        vuln_auth = await loop.run_in_executor(None, check_mysql_open, ip)
    elif port == 5432:
        vuln_auth = await loop.run_in_executor(None, check_postgres_open, ip)

    try:
        ssl_ctx = None
        if port == 443:
            ssl_ctx = ssl.create_default_context()
            ssl_ctx.check_hostname = False
            ssl_ctx.verify_mode = ssl.CERT_NONE

        future = asyncio.open_connection(ip, port, ssl=ssl_ctx)
        reader, writer = await asyncio.wait_for(future, timeout=conn_timeout)

        if port == 443:
            try:
                cert = writer.get_extra_info('peercert')
                if cert:
                    subject = dict(x[0] for x in cert['subject'])
                    common_name = subject.get('commonName', '')
                    issuer = dict(x[0] for x in cert['issuer'])
                    org_name = issuer.get('organizationName', '')
                    not_after = cert['notAfter']

                    ssl_info = {"ssl_subject": common_name, "ssl_issuer": org_name, "ssl_expiry": not_after}
            except Exception:
                pass

        try:
            if port in [80, 443, 8080]:
                headers = get_random_headers()
                request = f"GET / HTTP/1.1\r\nHost: {ip}\r\n{headers}\r\n"

                writer.write(request.encode())
                await writer.drain()

                data = await asyncio.wait_for(reader.read(4096), timeout=read_timeout)
                text = data.decode('utf-8', errors='ignore').strip()
                raw_html = text[:2000]

                for line in text.splitlines():
                    if line.lower().startswith("server:"):
                        banner = line.split(":", 1)[1].strip()
                        break

                title_match = re.search(r'<title>(.*?)</title>', text, re.IGNORECASE | re.DOTALL)
                if title_match:
                    title = title_match.group(1).strip()[:200]
                    # print(f"[INFO] Title found: {title}") # Too spammy for prod

            else:
                lines = text.splitlines()
                if lines:
                    banner = lines[0].strip()

        except Exception:
            pass
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

        if port in [80, 443, 8080]:
            try:
                probe_ctx = ssl.create_default_context() if port == 443 else None
                if probe_ctx:
                    probe_ctx.check_hostname = False
                    probe_ctx.verify_mode = ssl.CERT_NONE

                pfuture = asyncio.open_connection(ip, port, ssl=probe_ctx)
                preader, pwriter = await asyncio.wait_for(pfuture, timeout=2.0)

                headers = get_random_headers()
                req = f"GET /.env HTTP/1.1\r\nHost: {ip}\r\n{headers}\r\n"

                pwriter.write(req.encode())
                await pwriter.drain()

                pdata = await asyncio.wait_for(preader.read(2048), timeout=2.0)
                ptext = pdata.decode('utf-8', errors='ignore')

                if "APP_KEY=" in ptext or "DB_HOST=" in ptext or "DB_PASSWORD=" in ptext:
                    vuln_env = True

                pwriter.close()
                await pwriter.wait_closed()
            except Exception:
                pass

        return banner if banner else "", title, ssl_info, vuln_env, vuln_auth, raw_html

    except Exception:
        return None, None, {}, False, False, ""

async def scan_ip(ip, http_client):
    tasks = [grab_banner(ip, p) for p in TARGET_PORTS]
    results_raw = await asyncio.gather(*tasks)

    results = []
    open_ports = []

    for port, (banner, title, ssl_info, vuln_env, vuln_auth, raw_html) in zip(TARGET_PORTS, results_raw):
        if banner is not None:
            open_ports.append((port, banner, title, ssl_info, vuln_env, vuln_auth, raw_html))

    if open_ports:
        country, isp = await get_geo_info(ip, http_client)

        for port, banner, title, ssl_info, vuln_env, vuln_auth, raw_html in open_ports:
            service = "unknown"
            if port in [80, 443, 8080]: service = "http"
            elif port == 21: service = "ftp"
            elif port == 22: service = "ssh"
            elif port == 3306: service = "mysql"
            elif port == 5432: service = "postgres"

            software, version = detect_software(banner)

            payload = {
                "ip": ip,
                "port": port,
                "service": service,
                "banner": clean_text(banner),
                "software_name": software,
                "version": version,
                "title": clean_text(title),
                "country": country,
                "isp": isp,
                "vuln_env": vuln_env,
                "vuln_auth": vuln_auth,
                "raw_html": clean_text(raw_html)
            }
            if ssl_info: payload.update(ssl_info)
            results.append(payload)

    return results

async def scanner_worker(semaphore, http_client, queue, end_time, stop_event):
    global TOTAL_SCANNED, TOTAL_FOUND

    while time.time() < end_time and not stop_event.is_set():
        # Stop condition: 1000 Found IPs per worker
        if TOTAL_FOUND >= 1000:
            print("[*] Target Reached (1000 Found IPs). Stopping worker.")
            stop_event.set()
            break

        ip = generate_target_ip()
        if not ip:
            await asyncio.sleep(1) # Wait if CIDRs not ready
            continue

        async with semaphore:
            results = await scan_ip(ip, http_client)
            TOTAL_SCANNED += 1

            if TOTAL_SCANNED % 500 == 0:
                print(f"[*] Scanned: {TOTAL_SCANNED} | Found: {TOTAL_FOUND} | Queue: {queue.qsize()}")

            if results:
                for r in results:
                    await queue.put(r)

async def uploader_worker(queue):
    global TOTAL_FOUND
    batch = []

    async def flush():
        nonlocal batch
        global TOTAL_FOUND
        if not batch: return
        try:
            supabase.table(TABLE_MAP).insert(batch).execute()
            print(f"[SUCCESS] Uploaded batch: {len(batch)} | Total Found: {TOTAL_FOUND}")
        except Exception as e:
            if "duplicate" in str(e).lower() or "409" in str(e):
                pass
            else:
                print(f"[!] Upload Error: {e}")
        finally:
            batch = []

    while True:
        record = await queue.get()
        if record is None:
            await flush()
            queue.task_done()
            break

        # Optimization: Increment found count here for scanner visibility
        TOTAL_FOUND += 1

        batch.append(record)
        if len(batch) >= BATCH_SIZE:
            await flush()
        queue.task_done()

async def main():
    global START_TIME, CIDR_RANGES
    START_TIME = datetime.now(timezone.utc).isoformat()
    worker_id = os.getenv("WORKER_ID", "1")
    target_country = os.getenv("TARGET_COUNTRY", "id").lower() # Default to Indo

    print(f"[*] Starting PRODUCTION Scanner (Worker {worker_id})")
    print(f"[*] Target Country: {target_country.upper()}")

    CIDR_RANGES = await fetch_country_cidrs(target_country)
    if not CIDR_RANGES:
        print("[!] Critical: No CIDRs found. Exiting.")
        return

    end_time = time.time() + RUN_DURATION
    semaphore = asyncio.Semaphore(MAX_CONCURRENCY)
    queue = asyncio.Queue()
    stop_event = asyncio.Event()

    async with httpx.AsyncClient() as http_client:
        uploader = asyncio.create_task(uploader_worker(queue))
        scanners = [
            asyncio.create_task(scanner_worker(semaphore, http_client, queue, end_time, stop_event))
            for _ in range(MAX_CONCURRENCY)
        ]

        await asyncio.gather(*scanners)
        await queue.put(None)
        await queue.join()
        await uploader

    try:
        finished_at = datetime.now(timezone.utc).isoformat()
        stats = {
            "worker_id": worker_id,
            "total_scanned": TOTAL_SCANNED,
            "total_found": TOTAL_FOUND,
            "started_at": START_TIME,
            "finished_at": finished_at
        }
        supabase.table(TABLE_STATS).insert(stats).execute()
        print(f"[*] Stats uploaded: {stats}")
    except Exception as e:
        print(f"[!] Stats Upload Error: {e}")

    print("[*] Finished.")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
