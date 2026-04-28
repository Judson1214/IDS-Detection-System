import os
import re
import socket
from datetime import datetime
import requests
from database import insert_alert, insert_scan_log

# ---------------------------------------------------------------------------
# Log file writer
# ---------------------------------------------------------------------------

if os.environ.get('VERCEL') == '1':
    LOGS_DIR = '/tmp'
else:
    LOGS_DIR = r"C:\Users\HP\Documents\IDS report"

try:
    os.makedirs(LOGS_DIR, exist_ok=True)
except Exception:
    pass


def write_log_file(scan_type: str, target: str, resolved_ip: str | None,
                   open_ports: list, http_alerts: list,
                   port_alerts: list, summary: str) -> str:
    """Write a structured scan report to a .log file and return the filename."""
    ts      = datetime.now()
    ts_str  = ts.strftime('%Y-%m-%d %H:%M:%S')
    # Sanitise target for use in filename
    safe    = re.sub(r'[^\w\-.]', '_', target)
    fname   = f"scan_{ts.strftime('%Y%m%d_%H%M%S')}_{safe}.log"
    fpath   = os.path.join(LOGS_DIR, fname)

    lines = [
        '=' * 70,
        f'  SnortIDS – Scan Report',
        '=' * 70,
        f'  Timestamp  : {ts_str}',
        f'  Scan Type  : {scan_type}',
        f'  Target     : {target}',
    ]
    if resolved_ip:
        lines.append(f'  Resolved IP: {resolved_ip}')
    lines += [
        '=' * 70,
        '',
        '── Open Ports ──────────────────────────────────────────────────────',
    ]
    if open_ports:
        for p in open_ports:
            svc     = p.get('service', 'unknown')
            ver     = (p.get('product', '') + ' ' + p.get('version', '')).strip()
            ver_str = f' ({ver})' if ver else ''
            lines.append(f'  PORT {p["port"]:<6} {svc:<15}{ver_str}')
    else:
        lines.append('  No open ports found.')

    lines += [
        '',
        '── IDS Alerts (Port-Based) ─────────────────────────────────────────',
    ]
    if port_alerts:
        for a in port_alerts:
            lines.append(f'  [{a["severity"].upper():<8}] {a["message"]}')
            lines.append(f'             Rule: {a["rule"]}')
    else:
        lines.append('  No port-based alerts.')

    if http_alerts:
        lines += [
            '',
            '── IDS Alerts (HTTP Header Analysis) ───────────────────────────────',
        ]
        for a in http_alerts:
            lines.append(f'  [{a["severity"].upper():<8}] {a["message"]}')
            lines.append(f'             Rule: {a["rule"]}')

    total = len(port_alerts) + len(http_alerts)
    lines += [
        '',
        '── Summary ────────────────────────────────────────────────────────',
        f'  {summary}',
        f'  Total IDS Alerts : {total}',
        '',
        '=' * 70,
        f'  Log saved: {fpath}',
        '=' * 70,
    ]

    with open(fpath, 'w', encoding='utf-8') as f:
        f.write('\n'.join(lines) + '\n')

    return fname

# Try to import nmap; fall back to simulation if not available
try:
    import nmap
    NMAP_AVAILABLE = True
except ImportError:
    NMAP_AVAILABLE = False

# ---------------------------------------------------------------------------
# Snort-style rule definitions mapped to Nmap findings
# ---------------------------------------------------------------------------
SNORT_RULES = [
    {
        "port": 22,
        "service": "SSH",
        "severity": "High",
        "message": "SSH Port Open – Potential Brute Force Vector",
        "rule": 'alert tcp any any -> any 22 (msg:"SSH Scan Detected"; sid:1000001;)',
    },
    {
        "port": 21,
        "service": "FTP",
        "severity": "Critical",
        "message": "FTP Port Open – Unencrypted File Transfer Exposure",
        "rule": 'alert tcp any any -> any 21 (msg:"FTP Scan Detected"; sid:1000002;)',
    },
    {
        "port": 23,
        "service": "Telnet",
        "severity": "Critical",
        "message": "Telnet Port Open – Plaintext Remote Access Detected",
        "rule": 'alert tcp any any -> any 23 (msg:"Telnet Scan Detected"; sid:1000003;)',
    },
    {
        "port": 3306,
        "service": "MySQL",
        "severity": "Critical",
        "message": "MySQL Database Port Externally Exposed",
        "rule": 'alert tcp any any -> any 3306 (msg:"MySQL DB Exposed"; sid:1000004;)',
    },
    {
        "port": 5432,
        "service": "PostgreSQL",
        "severity": "Critical",
        "message": "PostgreSQL Database Port Externally Exposed",
        "rule": 'alert tcp any any -> any 5432 (msg:"PostgreSQL DB Exposed"; sid:1000005;)',
    },
    {
        "port": 1433,
        "service": "MSSQL",
        "severity": "Critical",
        "message": "MSSQL Server Port Externally Exposed",
        "rule": 'alert tcp any any -> any 1433 (msg:"MSSQL Exposed"; sid:1000006;)',
    },
    {
        "port": 3389,
        "service": "RDP",
        "severity": "Critical",
        "message": "RDP Port Open – Remote Desktop Exposure",
        "rule": 'alert tcp any any -> any 3389 (msg:"RDP Scan Detected"; sid:1000007;)',
    },
    {
        "port": 8080,
        "service": "HTTP-Alt",
        "severity": "Medium",
        "message": "Alternate HTTP Port Open – Possibly Unprotected Web Service",
        "rule": 'alert tcp any any -> any 8080 (msg:"Alt HTTP Port Open"; sid:1000008;)',
    },
    {
        "port": 8443,
        "service": "HTTPS-Alt",
        "severity": "Medium",
        "message": "Alternate HTTPS Port Open",
        "rule": 'alert tcp any any -> any 8443 (msg:"Alt HTTPS Port Open"; sid:1000009;)',
    },
    {
        "port": 25,
        "service": "SMTP",
        "severity": "High",
        "message": "SMTP Port Open – Potential Mail Relay / Spam Vector",
        "rule": 'alert tcp any any -> any 25 (msg:"SMTP Open"; sid:1000010;)',
    },
    {
        "port": 53,
        "service": "DNS",
        "severity": "Medium",
        "message": "DNS Port Open – Possible DNS Amplification Risk",
        "rule": 'alert udp any any -> any 53 (msg:"DNS Port Open"; sid:1000011;)',
    },
    {
        "port": 6379,
        "service": "Redis",
        "severity": "Critical",
        "message": "Redis Port Open – Unauthenticated Access Risk",
        "rule": 'alert tcp any any -> any 6379 (msg:"Redis Exposed"; sid:1000012;)',
    },
    {
        "port": 27017,
        "service": "MongoDB",
        "severity": "Critical",
        "message": "MongoDB Port Open – Unauthenticated Database Access Risk",
        "rule": 'alert tcp any any -> any 27017 (msg:"MongoDB Exposed"; sid:1000013;)',
    },
    {
        "port": 445,
        "service": "SMB",
        "severity": "Critical",
        "message": "SMB Port Open – EternalBlue / Ransomware Risk",
        "rule": 'alert tcp any any -> any 445 (msg:"SMB Port Open"; sid:1000014;)',
    },
    {
        "port": 139,
        "service": "NetBIOS",
        "severity": "High",
        "message": "NetBIOS Port Open – Windows Share Enumeration Risk",
        "rule": 'alert tcp any any -> any 139 (msg:"NetBIOS Open"; sid:1000015;)',
    },
]

RULE_MAP = {r["port"]: r for r in SNORT_RULES}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def resolve_domain(target: str) -> str | None:
    """Resolve a domain to its IP address."""
    target = target.strip().lower()
    # Strip scheme if present
    target = re.sub(r'^https?://', '', target).split('/')[0]
    try:
        ip = socket.gethostbyname(target)
        return ip
    except Exception:
        return None


def validate_ip(ip: str) -> bool:
    pattern = re.compile(
        r'^(\d{1,3}\.){3}\d{1,3}$'
    )
    if not pattern.match(ip):
        return False
    return all(0 <= int(p) <= 255 for p in ip.split('.'))


# ---------------------------------------------------------------------------
# Nmap-based scan
# ---------------------------------------------------------------------------

def _nmap_scan(ip: str) -> dict:
    """Run nmap scan and return parsed port data."""
    nm = nmap.PortScanner()
    nm.scan(ip, arguments='-sV -T4 --top-ports 1000 --open')
    open_ports = []
    for host in nm.all_hosts():
        for proto in nm[host].all_protocols():
            for port in nm[host][proto].keys():
                port_info = nm[host][proto][port]
                if port_info['state'] == 'open':
                    open_ports.append({
                        'port': port,
                        'service': port_info.get('name', 'unknown'),
                        'version': port_info.get('version', ''),
                        'product': port_info.get('product', ''),
                    })
    return {'ip': ip, 'open_ports': open_ports}


def _simulated_scan(ip: str) -> dict:
    """Simulate port scan using raw socket connections."""
    common_ports = [21, 22, 23, 25, 53, 80, 443, 445, 1433, 3306,
                    3389, 5432, 6379, 8080, 8443, 8888, 27017, 139]
    open_ports = []
    for port in common_ports:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.5)
            result = s.connect_ex((ip, port))
            s.close()
            if result == 0:
                service = RULE_MAP.get(port, {}).get('service', 'unknown')
                open_ports.append({'port': port, 'service': service,
                                   'version': '', 'product': ''})
        except Exception:
            pass
    return {'ip': ip, 'open_ports': open_ports}


# ---------------------------------------------------------------------------
# HTTP Header Analysis
# ---------------------------------------------------------------------------

def _check_http_headers(url: str) -> list:
    """Check a URL for security header misconfigurations."""
    alerts = []
    try:
        if not url.startswith('http'):
            url = 'http://' + url
        resp = requests.get(url, timeout=5, allow_redirects=True,
                            headers={'User-Agent': 'SnortIDS-Scanner/1.0'})
        headers = {k.lower(): v for k, v in resp.headers.items()}
        checks = [
            ('x-frame-options', 'Medium',
             'Missing X-Frame-Options – Clickjacking Risk',
             'alert http any any -> any any (msg:"Missing X-Frame-Options"; sid:2000001;)'),
            ('x-content-type-options', 'Low',
             'Missing X-Content-Type-Options – MIME Sniffing Risk',
             'alert http any any -> any any (msg:"Missing X-Content-Type-Options"; sid:2000002;)'),
            ('strict-transport-security', 'High',
             'Missing HSTS Header – Protocol Downgrade Risk',
             'alert http any any -> any any (msg:"Missing HSTS Header"; sid:2000003;)'),
            ('content-security-policy', 'High',
             'Missing Content-Security-Policy – XSS Risk',
             'alert http any any -> any any (msg:"Missing CSP Header"; sid:2000004;)'),
            ('x-xss-protection', 'Medium',
             'Missing X-XSS-Protection Header',
             'alert http any any -> any any (msg:"Missing X-XSS-Protection"; sid:2000005;)'),
        ]
        for header, severity, message, rule in checks:
            if header not in headers:
                alerts.append({
                    'severity': severity,
                    'message': message,
                    'rule': rule
                })

        # Check for server version disclosure
        if 'server' in headers:
            server = headers['server']
            if any(v in server for v in ['Apache/', 'nginx/', 'IIS/']):
                alerts.append({
                    'severity': 'Medium',
                    'message': f'Server Version Disclosed: {server}',
                    'rule': 'alert http any any -> any any (msg:"Server Version Disclosure"; sid:2000006;)'
                })

        # Check for HTTP (non-HTTPS)
        if resp.url.startswith('http://'):
            alerts.append({
                'severity': 'High',
                'message': 'Site served over HTTP – No TLS Encryption',
                'rule': 'alert http any any -> any 80 (msg:"Unencrypted HTTP Traffic"; sid:2000007;)'
            })

    except requests.exceptions.SSLError:
        alerts.append({
            'severity': 'Critical',
            'message': 'SSL Certificate Error – Invalid or Expired Certificate',
            'rule': 'alert tcp any any -> any 443 (msg:"SSL Certificate Invalid"; sid:2000008;)'
        })
    except requests.exceptions.ConnectionError:
        alerts.append({
            'severity': 'Low',
            'message': 'HTTP Connection Failed – Host may be unreachable or blocking connections',
            'rule': 'alert tcp any any -> any 80 (msg:"HTTP Connection Failed"; sid:2000009;)'
        })
    except Exception as e:
        pass

    return alerts


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def scan_ip(ip: str) -> dict:
    """Scan a single IP address. Returns scan results and generates alerts."""
    ip = ip.strip()
    if not validate_ip(ip):
        return {'error': f'Invalid IP address: {ip}'}

    # Perform port scan
    if NMAP_AVAILABLE:
        try:
            scan_data = _nmap_scan(ip)
        except Exception:
            scan_data = _simulated_scan(ip)
    else:
        scan_data = _simulated_scan(ip)

    open_ports = scan_data.get('open_ports', [])
    alert_count = 0
    port_alerts_generated = []

    # Match open ports against Snort rule map
    for port_info in open_ports:
        port_num = port_info['port']
        if port_num in RULE_MAP:
            rule = RULE_MAP[port_num]
            msg = rule['message'] + (f" ({port_info.get('product', '')} {port_info.get('version', '')})".strip())
            insert_alert(
                target=ip,
                severity=rule['severity'],
                message=msg,
                rule=rule['rule']
            )
            port_alerts_generated.append({
                'severity': rule['severity'],
                'message': msg,
                'rule': rule['rule']
            })
            alert_count += 1

    summary = (
        f"Scanned {ip}. Found {len(open_ports)} open port(s). "
        f"Generated {alert_count} IDS alert(s). "
        f"Open ports: {', '.join(str(p['port']) for p in open_ports) or 'None'}"
    )
    insert_scan_log(ip, 'IP Scan', summary, alert_count)

    log_file = write_log_file(
        scan_type='IP Scan',
        target=ip,
        resolved_ip=None,
        open_ports=open_ports,
        http_alerts=[],
        port_alerts=port_alerts_generated,
        summary=summary
    )

    return {
        'target': ip,
        'open_ports': open_ports,
        'alert_count': alert_count,
        'summary': summary,
        'log_file': log_file
    }


def scan_website(url: str) -> dict:
    """Scan a website (domain) by resolving its IP and checking HTTP headers."""
    original = url.strip()
    # Strip scheme for display
    display = re.sub(r'^https?://', '', original).split('/')[0]

    ip = resolve_domain(display)
    if not ip:
        return {'error': f'Could not resolve domain: {display}'}

    alert_count = 0
    all_alerts = []

    # 1. Port scan the resolved IP
    port_scan_result = scan_ip(ip)
    if 'error' not in port_scan_result:
        alert_count += port_scan_result.get('alert_count', 0)
        all_alerts.extend(port_scan_result.get('open_ports', []))

    # 2. HTTP header analysis
    http_alerts = _check_http_headers(display)
    for h_alert in http_alerts:
        insert_alert(
            target=display,
            severity=h_alert['severity'],
            message=h_alert['message'],
            rule=h_alert['rule']
        )
        alert_count += 1

    open_ports = port_scan_result.get('open_ports', []) if 'error' not in port_scan_result else []
    port_alerts_generated = []
    if 'error' not in port_scan_result:
        # Rebuild port alert list from the open ports for the log file
        for p in open_ports:
            if p['port'] in RULE_MAP:
                r = RULE_MAP[p['port']]
                port_alerts_generated.append({
                    'severity': r['severity'],
                    'message': r['message'],
                    'rule': r['rule']
                })

    summary = (
        f"Scanned {display} (resolved to {ip}). "
        f"Found {len(open_ports)} open port(s). "
        f"HTTP security issues: {len(http_alerts)}. "
        f"Total alerts: {alert_count}."
    )
    insert_scan_log(display, 'Website Scan', summary, alert_count)

    log_file = write_log_file(
        scan_type='Website Scan',
        target=display,
        resolved_ip=ip,
        open_ports=open_ports,
        http_alerts=http_alerts,
        port_alerts=port_alerts_generated,
        summary=summary
    )

    return {
        'target': display,
        'resolved_ip': ip,
        'open_ports': open_ports,
        'http_alerts': http_alerts,
        'alert_count': alert_count,
        'summary': summary,
        'log_file': log_file
    }
