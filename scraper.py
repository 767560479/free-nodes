import requests
import base64
import os
import json
import random
import time
from datetime import datetime
from urllib.parse import quote

# ================= ⚙️ 核心配置区 ⚙️ =================

CUSTOM_REMARK_B64 = "56eR5oqA5YWx5LqrLeW8gOa6kOiKgueCuQ=="

# 2. 节点订阅源库（随时可在末尾追加新链接）
SOURCE_URLS = [
    "https://cdn.jsdelivr.net/gh/Pawdroid/Free-servers@main/sub",
    "https://cdn.jsdelivr.net/gh/mfuu/v2ray@master/v2ray",
    "https://raw.githubusercontent.com/ermaozi/get_subscribe/main/subscribe/v2ray.txt",
    "https://raw.githubusercontent.com/free-nodes/v2rayfree/main/v202605312",
    "https://raw.githubusercontent.com/chengaopan/AutoMergePublicNodes/master/list.txt",
    "https://github.cmliussss.net/https://raw.githubusercontent.com/qmqv/jd07/refs/heads/main/v207-1010.txt",
    "https://ghfast.top/https://raw.githubusercontent.com/free18/v2ray/refs/heads/main/v.txt",
    "https://proxy.v2gh.com/https://raw.githubusercontent.com/Pawdroid/Free-servers/main/sub",
    "https://raw.githubusercontent.com/ts-sf/fly/main/v2",
    "https://sub.proxygo.org/v2ray.php?key=191c91f624a800e83942463fd667bba5",
    "https://raw.githubusercontent.com/mahdibland/ShadowsocksAggregator/master/Eternity",
    "https://raw.githubusercontent.com/roosterkid/openproxylist/main/V2RAY_BASE64.txt",
    "https://app.sublink.works/x/ZrVEXNV",
    "https://gcore.jsdelivr.net/gh/aews/jd/v20610.txt",
    "https://freev2ray.top/V2rayN061456NO.txt",
    "https://mm.mibei77.com/202606/06.0764bacrt.txt",
    "https://mm.mibei77.com/202606/06.0864bacrt.txt",
    "https://raw.githubusercontent.com/mahdibland/V2RayAggregator/master/sub/splitted/vmess.txt",
    "https://raw.githubusercontent.com/ebrasha/free-v2ray-public-list/main/V2Ray-Config-By-EbraSha-All-Type.txt",
    "https://raw.githubusercontent.com/mahdibland/V2RayAggregator/master/sub/splitted/trojan.txt",
    "https://raw.githubusercontent.com/hello-world-1989/cn-news/main/end-gfw-together",
    "https://gt.1155555.xyz/https://raw.githubusercontent.com/shaoyouvip/free/refs/heads/main/base64.txt" 
]

# 3. 垃圾节点过滤黑名单（可自行添加别人节点里的广告词过滤掉）
BLACKLIST_KEYWORDS = ['-1', '127.0.0.1', 'timeout', 'err', '错误', '剩余', '到期', '官网', 'mibei77', '别买']

# 4. 请求节奏（秒）：随机间隔，降低被识别为爬虫的概率
REQUEST_DELAY = (2.0, 5.0)   # 相邻两次请求之间的等待范围
RETRY_DELAY = (3.0, 8.0)     # 失败后重试前的等待范围
MAX_RETRIES = 2
REQUEST_TIMEOUT = 20

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


def _random_sleep(delay_range, label=""):
    delay = random.uniform(*delay_range)
    suffix = f" ({label})" if label else ""
    print(f"[*] 等待 {delay:.1f}s{suffix}...")
    time.sleep(delay)


def fetch_and_decode(url, session):
    if not url or not url.strip():
        return []

    for attempt in range(MAX_RETRIES + 1):
        try:
            print(f"[*] 正在抓取: {url}")
            response = session.get(url, timeout=REQUEST_TIMEOUT)
            response.raise_for_status()
            content = response.text.strip()
            return _decode_content(content)
        except Exception as e:
            if attempt < MAX_RETRIES:
                print(f"[!] 抓取失败，准备重试 ({attempt + 1}/{MAX_RETRIES}): {e}")
                _random_sleep(RETRY_DELAY, "重试前")
            else:
                print(f"[!] 抓取失败 {url}: {e}")
                return []
    return []

def rename_node(link, index):
    new_name = f"{CUSTOM_REMARK} {index:03d}"

    if link.startswith("vmess://"):
        try:
            b64_str = _pad_base64(link[8:])
            v_json = json.loads(base64.b64decode(b64_str).decode('utf-8'))
            v_json['ps'] = new_name  # 强行覆盖 VMess 别名
            
            new_b64 = base64.b64encode(json.dumps(v_json, ensure_ascii=False).encode('utf-8')).decode('utf-8')
            return f"vmess://{new_b64}"
        except Exception:
            return link
            
    elif any(link.startswith(p) for p in ['vless://', 'trojan://', 'ss://', 'ssr://', 'tuic://', 'hysteria2://']):
        try:
            # 兼容处理：防范原本就不带 # 备注符号的特殊链接
            if "#" in link:
                base_link = link.split("#", 1)[0]
            else:
                base_link = link
            return f"{base_link}#{quote(new_name)}"
        except Exception:
            return link
            
    return link

def main():
    print(f"=== 开始执行高级抓取与清洗任务 {datetime.now()} ===")
    all_lines = []
    session = requests.Session()
    session.headers.update(BROWSER_HEADERS)

    for i, url in enumerate(SOURCE_URLS):
        if i > 0:
            _random_sleep(REQUEST_DELAY)
        all_lines.extend(fetch_and_decode(url, session))

    valid_nodes = []
    seen = set()

    for line in all_lines:
        line = line.strip()
        if not line.startswith(SUPPORTED_PROTOCOLS):
            continue

        is_bad = any(keyword.lower() in line.lower() for keyword in BLACKLIST_KEYWORDS)
        if is_bad:
            continue

        if line in seen:
            continue
        seen.add(line)
        valid_nodes.append(line)
    
    print(f"[*] 清洗完毕，正在进行全自动重命名...")
    
    final_nodes = []
    for i, node in enumerate(valid_nodes, 1):
        renamed_node = rename_node(node, i)
        final_nodes.append(renamed_node)
        
    print(f"[*] 成功生成 {len(final_nodes)} 个定制化节点！")
    
    raw_text = "\n".join(final_nodes)
    sub_base64 = base64.b64encode(raw_text.encode('utf-8')).decode('utf-8')
    
    os.makedirs('output', exist_ok=True)
    with open('output/nodes.txt', 'w', encoding='utf-8') as f:
        f.write(raw_text)
    with open('output/sub.txt', 'w', encoding='utf-8') as f:
        f.write(sub_base64)

if __name__ == "__main__":
    main()
