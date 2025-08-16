#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
广告规则下载与处理脚本 - 完整保留版
包含所有原始黑白名单，优化GitHub CI性能
"""

import os
import glob
import shutil
import requests
import concurrent.futures
from pathlib import Path
import time

# ============== 配置参数 ==============
PATTERNS = ['*.txt', '*.mrs']  # 要删除的文件扩展名
MAX_WORKERS = 8                # 并发下载线程数
REQUEST_TIMEOUT = 60           # 请求超时(秒)
MAX_RETRIES = 3                # 最大重试次数
RETRY_DELAY = 2                # 重试间隔(秒)

# ============== 工具函数 ==============
def is_github_actions():
    """检查是否运行在GitHub Actions环境"""
    return os.getenv('GITHUB_ACTIONS') == 'true'

def clean_files():
    """清理旧文件"""
    root_dir = Path(__file__).parent.parent.parent.absolute()
    print(f"清理目录: {root_dir}")

    for pattern in PATTERNS:
        for file_path in glob.glob(str(root_dir / pattern)):
            try:
                if os.path.isfile(file_path):
                    os.unlink(file_path)
                    print(f"已删除: {file_path}")
            except Exception as e:
                print(f"删除失败: {file_path} - {e}")

def prepare_temp_dir():
    """准备临时目录并复制本地规则"""
    tmp_dir = Path("./tmp")
    tmp_dir.mkdir(exist_ok=True)
    
    # 复制本地规则文件
    local_files = {
        "./data/mod/adblock.txt": tmp_dir / "adblock01.txt",
        "./data/mod/whitelist.txt": tmp_dir / "allow01.txt"
    }
    
    for src, dst in local_files.items():
        try:
            if Path(src).exists():
                shutil.copy(src, dst)
                print(f"已复制: {src} -> {dst}")
        except Exception as e:
            print(f"复制失败 {src}: {e}")

def download_file(url, filename, session=None):
    """下载单个文件"""
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
    }
    
    for attempt in range(MAX_RETRIES):
        try:
            response = (session or requests).get(
                url, 
                headers=headers, 
                timeout=REQUEST_TIMEOUT
            )
            response.raise_for_status()
            
            # 处理编码
            response.encoding = response.apparent_encoding
            
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(response.text)
                
            print(f"✓ 下载成功: {url}")
            return True
            
        except Exception as e:
            if attempt < MAX_RETRIES - 1:
                print(f"⚠️ 下载失败 (尝试 {attempt + 1}/{MAX_RETRIES}): {url} - {e}")
                time.sleep(RETRY_DELAY)
            else:
                print(f"✗ 下载失败(最终): {url} - {e}")
    return False

def download_files(urls, prefix, start_index=2):
    """并发下载文件组"""
    session = requests.Session()
    results = []
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {
            executor.submit(
                download_file, 
                url, 
                f"tmp/{prefix}{i:02d}.txt", 
                session
            ): url for i, url in enumerate(urls, start_index)
        }
        
        for future in concurrent.futures.as_completed(futures):
            url = futures[future]
            results.append(future.result())
    
    session.close()
    return sum(results)

# ============== 完整规则列表 ==============
def get_adblock_urls():
    """拦截规则列表 (完整保留原始所有条目)"""
    return [
        # 大萌主-接口广告规则
        "https://raw.githubusercontent.com/damengzhu/banad/main/jiekouAD.txt",
        # DD-AD去广告规则
        "https://raw.githubusercontent.com/afwfv/DD-AD/main/rule/DD-AD.txt",
        # GitHub加速hosts
        "https://raw.hellogithub.com/hosts",
        # Anti-AD通用规则
        #"https://anti-ad.net/easylist.txt",
        # Cats-Team广告规则
        #"https://raw.githubusercontent.com/Cats-Team/AdRules/main/adblock.txt",
        # 挡广告hosts规则
        #"https://raw.githubusercontent.com/qq5460168/dangchu/main/adhosts.txt",
        # 10007自动规则
        #"https://lingeringsound.github.io/10007_auto/adb.txt",
        # 晴雅去广告规则
        "https://raw.githubusercontent.com/790953214/qy-Ads-Rule/main/black.txt",
        # 海哥广告规则
        "https://raw.githubusercontent.com/2771936993/HG/main/hg1.txt",
        # FCM hosts规则
        "https://github.com/entr0pia/fcm-hosts/raw/fcm/fcm-hosts",
        # 秋风广告规则
        "https://raw.githubusercontent.com/TG-Twilight/AWAvenue-Ads-Rule/main/AWAvenue-Ads-Rule.txt",

        # SMAdHosts规则
        #"https://raw.githubusercontent.com/2Gardon/SM-Ad-FuckU-hosts/master/SMAdHosts",
        # 茯苓拦截规则
        "https://raw.githubusercontent.com/Kuroba-Sayuki/FuLing-AdRules/main/FuLingRules/FuLingBlockList.txt"
    ]

def get_allow_urls():
    """白名单规则列表 (完整保留原始所有条目)"""
    return [
        # 挡广告白名单
        "https://raw.githubusercontent.com/qq5460168/dangchu/main/white.txt",
        # AdGuardHome通用白名单
        "https://raw.githubusercontent.com/mphin/AdGuardHomeRules/main/Allowlist.txt",
        # 冷漠域名白名单
        "https://file-git.trli.club/file-hosts/allow/Domains",
        # jhsvip白名单
        "https://raw.githubusercontent.com/jhsvip/ADRuls/main/white.txt",
        # liwenjie119白名单
        "https://raw.githubusercontent.com/liwenjie119/adg-rules/master/white.txt",
        # 喵二白名单
        "https://raw.githubusercontent.com/miaoermua/AdguardFilter/main/whitelist.txt",
        # 茯苓白名单
        "https://raw.githubusercontent.com/Kuroba-Sayuki/FuLing-AdRules/main/FuLingRules/FuLingAllowList.txt",
        # Cats-Team白名单
        "https://raw.githubusercontent.com/Cats-Team/AdRules/script/script/allowlist.txt",
        # 浅笑白名单
        "https://raw.githubusercontent.com/user001235/112/main/white.txt",
        # 酷安cocieto白名单
        "https://raw.githubusercontent.com/urkbio/adguardhomefilter/main/whitelist.txt",
        # anti-ad混合名单
        "https://anti-ad.net/easylist.txt" 
    ]

# ============== 主程序 ==============
def main():
    # GitHub Actions分组输出
    if is_github_actions():
        print("::group::初始化清理")
    
    clean_files()
    prepare_temp_dir()
    
    if is_github_actions():
        print("::endgroup::")
        print("::group::下载规则列表")
        print(f"拦截规则数: {len(get_adblock_urls())} | 白名单数: {len(get_allow_urls())}")
    
    # 记录开始时间
    start_time = time.time()
    
    # 并发下载
    success_ad = download_files(get_adblock_urls(), "adblock")
    success_allow = download_files(get_allow_urls(), "allow")
    
    # 计算耗时
    elapsed = time.time() - start_time
    
    # 输出结果
    print(f"\n✅ 下载完成 | 拦截: {success_ad}/{len(get_adblock_urls())} | 白名单: {success_allow}/{len(get_allow_urls())} | 耗时: {elapsed:.2f}s")
    
    if is_github_actions():
        print("::endgroup::")

if __name__ == "__main__":
    main()