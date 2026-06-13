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

BLACKLIST_KEYWORDS = [
    '-1', '127.0.0.1', 'timeout', 'err', '错误', '剩余', '到期', '官网', 'mibei77', '别买',
    't.me/', 'ripaojiedian', 'subscribe', '订阅', '流量', '过期', '失效', '已过期',
]

REQUEST_DELAY = (1.0, 2.0)
RETRY_DELAY = (3.0, 8.0)
MAX_RETRIES = 2
REQUEST_TIMEOUT = 20

TARGET_NODES = 200
# GitHub Actions 在美国跑，TCP 延迟≠国内可用；端口开放≠代理能连。默认关闭 TCP 筛选。
ENABLE_TCP_CHECK = False
TCP_TIMEOUT = 3
TCP_WORKERS = 128
MAX_LATENCY_MS = 2000

PROTOCOL_PRIORITY = {
    'vmess://': 0, 'vless://': 1, 'trojan://': 2,
    'tuic://': 3, 'hysteria2://': 4, 'ss://': 5, 'ssr://': 6,
}

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


def tcp_connect_latency_ms(host, port):
    try:
        port_num = int(port)
    except (TypeError, ValueError):
        return None
    if not host or port_num <= 0 or port_num > 65535:
        return None
    start = time.perf_counter()
    try:
        with socket.create_connection((host, port_num), timeout=TCP_TIMEOUT):
            return (time.perf_counter() - start) * 1000
    except OSError:
        return None


def filter_alive_nodes(nodes, limit):
    if not nodes or limit <= 0:
        return []

    if not ENABLE_TCP_CHECK:
        return nodes[:limit]

    alive = []
    executor = ThreadPoolExecutor(max_workers=TCP_WORKERS)
    try:
        futures = {
            executor.submit(tcp_connect_latency_ms, fp[0], fp[1]): node
            for node in nodes
            if (fp := node_fingerprint(node))
        }

        for future in as_completed(futures):
            if len(alive) >= limit:
                break
            try:
                latency_ms = future.result()
            except Exception:
                continue
            if latency_ms is not None and latency_ms <= MAX_LATENCY_MS:
                alive.append(futures[future])
    finally:
        executor.shutdown(wait=False, cancel_futures=True)

    return alive[:limit]


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

    if any(link.startswith(p) for p in ['vless://', 'trojan://', 'ss://', 'ssr://', 'tuic://', 'hysteria2://']):
        try:
            base_link = link.split("#", 1)[0] if "#" in link else link
            return f"{base_link}#{quote(new_name)}"
        except Exception:
            return link

    return link


def dedup_lines(lines, seen_lines, seen_fingerprints):
    new_nodes = []
    raw_count = 0

    for line in lines:
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
        new_nodes.append(line)

    return raw_count, new_nodes


def _protocol_rank(link):
    for prefix, rank in PROTOCOL_PRIORITY.items():
        if link.startswith(prefix):
            return rank
    return 99


def select_nodes(pool):
    if not pool:
        return []
    random.shuffle(pool)
    pool.sort(key=_protocol_rank)
    selected = pool[:TARGET_NODES]
    if ENABLE_TCP_CHECK:
        selected = filter_alive_nodes(selected, TARGET_NODES)
    return selected


def write_output(nodes):
    final_nodes = [rename_node(node, i) for i, node in enumerate(nodes, 1)]
    raw_text = "\n".join(final_nodes)
    sub_base64 = base64.b64encode(raw_text.encode('utf-8')).decode('utf-8')

    os.makedirs('output', exist_ok=True)
    with open('output/nodes.txt', 'w', encoding='utf-8') as f:
        f.write(raw_text)
    with open('output/sub.txt', 'w', encoding='utf-8') as f:
        f.write(sub_base64)
    return len(final_nodes)


def main():
    global _failed_sources
    _failed_sources = []

    started = time.time()
    print(f"=== 节点抓取 {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} ===")

    session = requests.Session()
    session.headers.update(BROWSER_HEADERS)

    seen_lines = set()
    seen_fingerprints = set()
    node_pool = []
    total_raw = 0
    sources_used = 0

    for i, url in enumerate(SOURCE_URLS):
        if len(node_pool) >= TARGET_NODES:
            break

        if i > 0:
            _sleep(REQUEST_DELAY)

        lines = fetch_and_decode(url, session)
        sources_used += 1
        raw_count, candidates = dedup_lines(lines, seen_lines, seen_fingerprints)
        total_raw += raw_count
        node_pool.extend(candidates)

        if len(node_pool) >= TARGET_NODES:
            print(f"已收集 {len(node_pool)} 个去重节点，停止抓取")
            break

    print(f"抓取: {sources_used}/{len(SOURCE_URLS)} 源, {total_raw} 行原始数据")
    print(f"去重池: {len(node_pool)} 节点")

    selected = select_nodes(node_pool)
    if ENABLE_TCP_CHECK:
        print(f"TCP: {len(selected)} 节点通过 (≤{MAX_LATENCY_MS}ms)")

    if not selected:
        print("无可用节点，跳过写入")
    else:
        count = write_output(selected)
        print(f"完成: 写入 nodes.txt + sub.txt ({count} 节点)")
        print("订阅请用 sub.txt（Base64），不要用 nodes.txt 当订阅链接")

    elapsed = int(time.time() - started)
    print(f"耗时 {elapsed // 60}m{elapsed % 60:02d}s")

    if _failed_sources:
        failed = ', '.join(f"{host}({err})" for host, err in _failed_sources)
        print(f"失败源 ({len(_failed_sources)}): {failed}")


if __name__ == "__main__":
    main()
