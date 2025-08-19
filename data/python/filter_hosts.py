import os
import requests
import re
import concurrent.futures
import time
import shutil
from glob import glob

# 高性能路径处理
WORKSPACE = os.getenv('WORKSPACE', os.getcwd())
TEMP_DIR = os.path.join(WORKSPACE, "tmp")
DATA_MOD_DIR = os.path.join(WORKSPACE, "data", "mod")  # 本地源目录

# 下载源配置
HOSTS_SOURCES = [
    "https://raw.githubusercontent.com/lingeringsound/10007_auto/master/10007.rule",
    "https://raw.githubusercontent.com/lingeringsound/10007_auto/master/reward",
    "https://raw.githubusercontent.com/TG-Twilight/AWAvenue-Ads-Rule/main/Filters/AWAvenue-Ads-Rule-hosts.txt",
    "https://raw.hellogithub.com/hosts"
]

# 白名单源配置
WHITE_LIST_SOURCES = [
    "https://raw.githubusercontent.com/lingeringsound/10007_auto/master/Adaway_white_list.prop"
]

def create_temp_dir():
    """确保临时目录存在"""
    os.makedirs(TEMP_DIR, exist_ok=True)
    print(f"[临时目录已创建] {TEMP_DIR}")

def download_file(url, filename, retries=3):
    """高性能下载函数（带智能重试）"""
    for attempt in range(retries):
        try:
            response = requests.get(
                url, 
                headers={'User-Agent': 'AdRulesFastDownloader/1.0'},
                timeout=(2, 4)  # 连接2秒, 读取4秒
            )
            response.raise_for_status()

            # 直接写入文件避免内存占用
            with open(filename, 'wb') as f:
                f.write(response.content)
                
            print(f"[下载成功] {url} → {filename}")
            return True
        except requests.RequestException as e:
            if attempt < retries - 1:
                time.sleep(1)
            else:
                print(f"[下载失败] {url} - {type(e).__name__}")
    return False

def download_hosts():
    """并发下载hosts文件"""
    create_temp_dir()
    print("\n[阶段1] 并发下载源文件")
    
    # 添加本地hosts.txt到临时目录（如果存在）
    local_hosts_path = os.path.join(DATA_MOD_DIR, "hosts.txt")
    if os.path.isfile(local_hosts_path):
        shutil.copy2(local_hosts_path, os.path.join(TEMP_DIR, "hosts_local.txt"))
        print(f"[添加本地文件] {local_hosts_path}")
    else:
        print(f"[跳过本地文件] {local_hosts_path} 不存在")
    
    # 创建下载任务列表
    tasks = []
    for index, url in enumerate(HOSTS_SOURCES):
        filename = f"hosts_{index}.txt"
        save_path = os.path.join(TEMP_DIR, filename)
        tasks.append((url, save_path))
    
    # 并发下载
    success_count = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(8, len(tasks))) as executor:
        futures = [executor.submit(download_file, url, path) for url, path in tasks]
        for future in concurrent.futures.as_completed(futures):
            if future.result():
                success_count += 1
                
    print(f"下载完成: {success_count}/{len(tasks)} 个源成功")
    return success_count > 0

def download_white_list():
    """并发下载白名单文件"""
    if not WHITE_LIST_SOURCES:
        return False
    
    print("\n[阶段4] 下载白名单文件")
    
    tasks = []
    for index, url in enumerate(WHITE_LIST_SOURCES):
        filename = f"whitelist_{index}.txt"
        save_path = os.path.join(TEMP_DIR, filename)
        tasks.append((url, save_path))
    
    # 并发下载
    success_count = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(4, len(tasks))) as executor:
        futures = [executor.submit(download_file, url, path) for url, path in tasks]
        for future in concurrent.futures.as_completed(futures):
            if future.result():
                success_count += 1
                
    print(f"白名单下载完成: {success_count}/{len(tasks)} 个源成功")
    return success_count > 0

def merge_hosts():
    """合并去重hosts逻辑（仅保留有效条目）"""
    entry_pattern = re.compile(r'^\s*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+(\S+)')
    domain_map = {}
    
    # 获取所有临时hosts文件
    hosts_files = glob(os.path.join(TEMP_DIR, "hosts_*.txt"))
    hosts_files += glob(os.path.join(TEMP_DIR, "hosts_local.txt"))
    
    if not hosts_files:
        print("错误: 未找到任何hosts文件")
        return None
        
    for file_path in hosts_files:
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    match = entry_pattern.match(line)
                    if match:
                        ip, domain = match.groups()
                        domain_map[domain.lower()] = ip
        except Exception as e:
            print(f"处理文件错误 {file_path}: {str(e)}")
            
    return domain_map

def merge_white_list():
    """合并去重白名单（仅保留有效域名）"""
    domain_set = set()
    entry_pattern = re.compile(r'^\s*([a-zA-Z0-9\-\.\*_?]+)\s*$')  # 允许通配符
    
    whitelist_files = glob(os.path.join(TEMP_DIR, "whitelist_*.txt"))
    
    if not whitelist_files:
        print("警告: 未找到任何白名单文件")
        return set()
        
    for file_path in whitelist_files:
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
               