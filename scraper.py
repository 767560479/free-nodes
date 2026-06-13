import requests
import base64
import os
import json
import random
import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from urllib.parse import quote

# ================= ⚙️ 核心配置区 ⚙️ =================

CUSTOM_REMARK_B64 = "56eR5oqA5YWx5LqrLeW8gOa6kOiKgueCuQ=="

# 2. 节点订阅源库（随时可在末尾追加新链接）
SOURCE_URLS = [
    "https://cdn.jsdelivr.net/gh/Pawdroid/Free-servers@main/sub",
    "https://cdn.jsdelivr.net/gh/mfuu/v2ray@master/v2ray",
    "https://raw.githubusercontent.com/ermaozi/get_subscribe/main/subscribe/v2ray.txt",
    "https://raw.githubusercontent.com/chengaopan/AutoMergePublicNodes/master/list.txt",
    "https://github.cmliussss.net/https://raw.githubusercontent.com/qmqv/jd07/refs/heads/main/v207-1010.txt",
    "https://ghfast.top/https://raw.githubusercontent.com/free18/v2ray/refs/heads/main/v.txt",
    "https://proxy.v2gh.com/https://raw.githubusercontent.com/Pawdroid/Free-servers/main/sub",
    "https://raw.githubusercontent.com/ts-sf/fly/main/v2",
    "https://sub.proxygo.org/v2ray.php?key=191c91f624a800e83942463fd667bba5",
    "https://raw.githubusercontent.com/roosterkid/openproxylist/main/V2RAY_BASE64.txt",
    "https://app.sublink.works/x/ZrVEXNV",
    "https://gcore.jsdelivr.net/gh/aews/jd/v20610.txt",
    "https://freev2ray.top/V2rayN061456NO.txt",
    "https://raw.githubusercontent.com/mahdibland/V2RayAggregator/master/sub/splitted/vmess.txt",
    "https://raw.githubusercontent.com/ebrasha/free-v2ray-public-list/main/V2Ray-Config-By-EbraSha-All-Type.txt",
    "https://raw.githubusercontent.com/mahdibland/V2RayAggregator/master/sub/splitted/trojan.txt",
    "https://raw.githubusercontent.com/hello-world-1989/cn-news/main/end-gfw-together",
]

# 3. 垃圾节点过滤黑名单
BLACKLIST_KEYWORDS = ['-1', '127.0.0.1', 'timeout', 'err', '错误', '剩余', '到期', '官网', 'mibei77', '别买']

# 4. 请求节奏（秒）
REQUEST_DELAY = (2.0, 5.0)
RETRY_DELAY = (3.0, 8.0)
MAX_RETRIES = 2
REQUEST_TIMEOUT = 20

# 5. 节点筛选
MAX_NODES = 1000
ENABLE_TCP_CHECK = True
TCP_TIMEOUT = 3
TCP_WORKERS = 64

# ====================================================

SUPPORTED_PROTOCOLS = ('vmess://', 'vless://', 'ss://', 'ssr://', 'trojan://', 'tuic://', 'hysteria2://')

BROWSER_HEADERS = {
    'User-Agent': (
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
        '(KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36'
    ),
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8',
    'Accept-Encoding': 'gzip, deflate, br',
    'Connection': 'keep-alive',
    'Cache-Control': 'no-cache',
}

try:
    CUSTOM_REMARK = base64.b64decode(CUSTOM_REMARK_B64).decode('utf-8')
except Exception:
    CUSTOM_REMARK = "Node"

_failed_sources = []


def _pad_base64(content):
    padding = 4 - (len(content) % 4)
    if padding != 4:
        content += "=" * padding
    return content


def _decode_content(content):
    try:
        decoded_bytes = base64.b64decode(_pad_base64(content))
        return decoded_bytes.decode('utf-8', errors='ignore').splitlines()
    except Exception:
        return content.splitlines()


def _sleep(delay_range):
    time.sleep(random.uniform(*delay_range))


def _short_url(url):
    return url.replace('https://', '').split('/', 1)[0]


def _split_host_port(hostport):
    hostport = hostport.strip()
    if hostport.startswith('['):
        host, _, port = hostport.rpartition(']')
        return host.strip('[]'), port.lstrip(':')
    if ':' in hostport:
        host, port = hostport.rsplit(':', 1)
        return host, port
    return hostport, ''


def _parse_auth_host(link, prefix_len):
    body = link.split('#', 1)[0]
    rest = body[prefix_len:]
    if '@' in rest:
        auth, hostport = rest.rsplit('@', 1)
    else:
        auth, hostport = '', rest
    hostport = hostport.split('?', 1)[0]
    host, port = _split_host_port(hostport)
    return host, port, auth


def _parse_ss(link):
    url_part = link[5:].split('#', 1)[0]
    if '@' in url_part:
        userinfo, hostport = url_part.rsplit('@', 1)
        if '://' not in userinfo and ':' not in userinfo.split('@')[-1]:
            try:
                userinfo = base64.b64decode(_pad_base64(userinfo)).decode('utf-8', errors='ignore')
            except Exception:
                pass
        if userinfo.startswith('ss://'):
            userinfo = userinfo[5:]
        host, port = _split_host_port(hostport.split('?', 1)[0])
        return host, port, userinfo
    try:
        decoded = base64.b64decode(_pad_base64(url_part)).decode('utf-8', errors='ignore')
        if decoded.startswith('ss://'):
            decoded = decoded[5:]
        if '@' in decoded:
            userinfo, hostport = decoded.rsplit('@', 1)
            host, port = _split_host_port(hostport.split('?', 1)[0])
            return host, port, userinfo
    except Exception:
        pass
    return None


def _parse_ssr(link):
    try:
        decoded = base64.b64decode(_pad_base64(link[6:])).decode('utf-8', errors='ignore')
        parts = decoded.split(':')
        if len(parts) >= 6:
            return parts[0], parts[1], parts[5]
    except Exception:
        pass
    return None


def node_fingerprint(link):
    try:
        if link.startswith('vmess://'):
            v_json = json.loads(base64.b64decode(_pad_base64(link[8:])).decode('utf-8'))
            host = str(v_json.get('add', '')).strip()
            port = str(v_json.get('port', '')).strip()
            identity = str(v_json.get('id', '')).strip()
            if host and port and identity:
                return host.lower(), port, identity

        if link.startswith('ss://'):
            parsed = _parse_ss(link)
            if parsed:
                host, port, identity = parsed
                if host and port:
                    return host.lower(), str(port), identity or link

        if link.startswith('ssr://'):
            parsed = _parse_ssr(link)
            if parsed:
                host, port, identity = parsed
                if host and port:
                    return host.lower(), str(port), identity or link

        for prefix, n in (
            ('vless://', 8), ('trojan://', 9), ('tuic://', 7), ('hysteria2://', 12),
        ):
            if link.startswith(prefix):
                host, port, identity = _parse_auth_host(link, n)
                if host and port:
                    return host.lower(), str(port), identity or link
    except Exception:
        pass
    return None


def tcp_alive(host, port):
    try:
        port_num = int(port)
    except (TypeError, ValueError):
        return False
    if not host or port_num <= 0 or port_num > 65535:
        return False
    try:
        with socket.create_connection((host, port_num), timeout=TCP_TIMEOUT):
            return True
    except OSError:
        return False


def filter_alive_nodes(nodes):
    if not ENABLE_TCP_CHECK or not nodes:
        return nodes

    alive = []
    with ThreadPoolExecutor(max_workers=TCP_WORKERS) as executor:
        futures = {}
        for node in nodes:
            fp = node_fingerprint(node)
            if not fp:
                alive.append(node)
                continue
            host, port, _ = fp
            futures[executor.submit(tcp_alive, host, port)] = node

        for future in as_completed(futures):
            if future.result():
                alive.append(futures[future])
    return alive


def fetch_and_decode(url, session):
    if not url or not url.strip():
        return []

    last_error = None
    for attempt in range(MAX_RETRIES + 1):
        try:
            response = session.get(url, timeout=REQUEST_TIMEOUT)
            response.raise_for_status()
            return _decode_content(response.text.strip())
        except requests.HTTPError as e:
            status = e.response.status_code if e.response is not None else 0
            last_error = f"HTTP {status}"
            if 400 <= status < 500:
                break
        except Exception as e:
            last_error = str(e).split('\n', 1)[0][:120]

        if attempt < MAX_RETRIES:
            _sleep(RETRY_DELAY)

    _failed_sources.append((_short_url(url), last_error or 'unknown'))
    return []


def rename_node(link, index):
    new_name = f"{CUSTOM_REMARK} {index:03d}"

    if link.startswith("vmess://"):
        try:
            b64_str = _pad_base64(link[8:])
            v_json = json.loads(base64.b64decode(b64_str).decode('utf-8'))
            v_json['ps'] = new_name
            new_b64 = base64.b64encode(json.dumps(v_json, ensure_ascii=False).encode('utf-8')).decode('utf-8')
            return f"vmess://{new_b64}"
        except Exception:
            return link

    elif any(link.startswith(p) for p in ['vless://', 'trojan://', 'ss://', 'ssr://', 'tuic://', 'hysteria2://']):
        try:
            base_link = link.split("#", 1)[0] if "#" in link else link
            return f"{base_link}#{quote(new_name)}"
        except Exception:
            return link

    return link


def main():
    started = time.time()
    print(f"=== 节点抓取 {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} ===")

    all_lines = []
    session = requests.Session()
    session.headers.update(BROWSER_HEADERS)
    source_total = len(SOURCE_URLS)

    for i, url in enumerate(SOURCE_URLS):
        if i > 0:
            _sleep(REQUEST_DELAY)
        all_lines.extend(fetch_and_decode(url, session))

    source_ok = source_total - len(_failed_sources)
    print(f"抓取: {source_ok}/{source_total} 源成功, {len(all_lines)} 行原始数据")

    valid_nodes = []
    seen_lines = set()
    seen_fingerprints = set()
    raw_count = 0

    for line in all_lines:
        line = line.strip()
        if not line.startswith(SUPPORTED_PROTOCOLS):
            continue
        raw_count += 1

        if any(keyword.lower() in line.lower() for keyword in BLACKLIST_KEYWORDS):
            continue
        if line in seen_lines:
            continue

        fp = node_fingerprint(line)
        if fp and fp in seen_fingerprints:
            continue

        seen_lines.add(line)
        if fp:
            seen_fingerprints.add(fp)
        valid_nodes.append(line)

    print(f"去重: {raw_count} -> {len(valid_nodes)} 节点")

    if ENABLE_TCP_CHECK:
        before_tcp = len(valid_nodes)
        valid_nodes = filter_alive_nodes(valid_nodes)
        print(f"TCP: {before_tcp} -> {len(valid_nodes)} 可达")

    if len(valid_nodes) > MAX_NODES:
        valid_nodes = valid_nodes[:MAX_NODES]
        print(f"限量: 保留前 {MAX_NODES} 个")

    final_nodes = [rename_node(node, i) for i, node in enumerate(valid_nodes, 1)]

    raw_text = "\n".join(final_nodes)
    sub_base64 = base64.b64encode(raw_text.encode('utf-8')).decode('utf-8')

    os.makedirs('output', exist_ok=True)
    with open('output/nodes.txt', 'w', encoding='utf-8') as f:
        f.write(raw_text)
    with open('output/sub.txt', 'w', encoding='utf-8') as f:
        f.write(sub_base64)

    elapsed = int(time.time() - started)
    print(f"完成: 输出 {len(final_nodes)} 节点, 耗时 {elapsed // 60}m{elapsed % 60:02d}s")

    if _failed_sources:
        failed = ', '.join(f"{host}({err})" for host, err in _failed_sources)
        print(f"失败源 ({len(_failed_sources)}): {failed}")


if __name__ == "__main__":
    main()
