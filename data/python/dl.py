import os
import concurrent.futures
import requests
import shutil
import time
from glob import glob

# 高性能路径处理
WORKSPACE = os.getenv('WORKSPACE', os.getcwd())
TEMP_DIR = os.path.join(WORKSPACE, "tmp")
DATA_MOD_DIR = os.path.join(WORKSPACE, "data", "mod")

def clean_files():
    """极速清理根目录下的.txt和.mrs文件"""
    deleted = 0
    for ext in ("*.txt", "*.mrs"):
        for file_path in glob(os.path.join(WORKSPACE, ext)):
            try:
                os.remove(file_path)
                deleted += 1
            except OSError:
                pass  # 静默失败
    print(f"清理完成: {deleted}文件")

def create_temp_dir():
    """原子性创建临时目录并复制关键文件"""
    os.makedirs(TEMP_DIR, exist_ok=True)
    shutil.copy2(os.path.join(DATA_MOD_DIR, "adblock.txt"), os.path.join(TEMP_DIR, "adblock01.txt"))
    shutil.copy2(os.path.join(DATA_MOD_DIR, "whitelist.txt"), os.path.join(TEMP_DIR, "allow01.txt"))

def download_file(url, filename):
    """高性能下载函数（带智能重试）"""
    for attempt in range(3):  # 最多重试3次
        try:
            # 极简请求配置
            response = requests.get(
                url, 
                headers={'User-Agent': 'AdRulesFastDownloader/1.0'},
                timeout=(2, 4)  # 激进超时: 连接2秒, 读取4秒
            )
            response.raise_for_status()
            
            # 直接写入文件避免内存占用
            with open(filename, 'wb') as f:
                f.write(response.content)
                
            return True
        except requests.RequestException as e:
            if attempt < 2:  # 前两次失败等待1秒重试
                time.sleep(1)
            else:
                print(f"最终失败 [{url}]: {type(e).__name__}")
    return False

def download_rules():
    """规则下载主函数（智能并发控制）"""
    # 保留全部规则源
    ADBLOCK_SOURCES = [
        "https://raw.githubusercontent.com/damengzhu/banad/main/jiekouAD.txt",
        "https://raw.githubusercontent.com/afwfv/DD-AD/main/rule/DD-AD.txt",
        
"https://raw.hellogithub.com/hosts",
        "https://raw.githubusercontent.com/790953214/qy-Ads-Rule/main/black.txt",
        "https://raw.githubusercontent.com/2771936993/HG/main/hg1.txt",
        "https://github.com/entr0pia/fcm-hosts/raw/fcm/fcm-hosts",
        "https://raw.githubusercontent.com/TG-Twilight/AWAvenue-Ads-Rule/main/AWAvenue-Ads-Rule.txt",
        "https://raw.githubusercontent.com/TG-Twilight/AWAvenue-Ads-Rule/main/Filters/AWAvenue-Ads-Rule-Replenish.txt",
        #"https://raw.githubusercontent.com/2Gardon/SM-Ad-FuckU-hosts/master/SMAdHosts",
        "https://raw.githubusercontent.com/Kuroba-Sayuki/FuLing-AdRules/main/FuLingRules/FuLingBlockList.txt"
    ]
    
    ALLOW_SOURCES = [
        #"https://raw.githubusercontent.com/qq5460168/dangchu/main/white.txt",
        #"https://raw.githubusercontent.com/mphin/AdGuardHomeRules/main/Allowlist.txt",
        "https://file-git.trli.club/file-hosts/allow/Domains",
        "https://raw.githubusercontent.com/jhsvip/ADRuls/main/white.txt",
        "https://raw.githubusercontent.com/liwenjie119/adg-rules/master/white.txt",
        #"https://raw.githubusercontent.com/miaoermua/AdguardFilter/main/whitelist.txt",
        "https://raw.githubusercontent.com/Kuroba-Sayuki/FuLing-AdRules/main/FuLingRules/FuLingAllowList.txt",
        #"https://raw.githubusercontent.com/Cats-Team/AdRules/script/script/allowlist.txt",
        "https://raw.githubusercontent.com/user001235/112/main/white.txt",
        "https://raw.githubusercontent.com/urkbio/adguardhomefilter/main/whitelist.txt",
        
#"https://anti-ad.net/easylist.txt"
    ]
    
    # 智能并发控制：根据源数量动态调整
    max_workers = min(8, len(ADBLOCK_SOURCES) + len(ALLOW_SOURCES))
    print(f"并发下载: {max_workers}线程 | 拦截规则:{len(ADBLOCK_SOURCES)} 白名单:{len(ALLOW_SOURCES)}")
    
    success_count = 0
    start_time = time.time()
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        # 批量提交任务
        futures = []
        for i, url in enumerate(ADBLOCK_SOURCES, 2):
            filepath = os.path.join(TEMP_DIR, f"adblock{i:02d}.txt")
            futures.append(executor.submit(download_file, url, filepath))
            
        for i, url in enumerate(ALLOW_SOURCES, 2):
            filepath = os.path.join(TEMP_DIR, f"allow{i:02d}.txt")
            futures.append(executor.submit(download_file, url, filepath))
        
        # 流式处理结果
        for future in concurrent.futures.as_completed(futures):
            if future.result():
                success_count += 1
    
    total_time = time.time() - start_time
    print(f"下载完成: {success_count}/{len(futures)} 成功 | 耗时 {total_time:.1f}秒")
    return success_count

if __name__ == "__main__":
    print("🚀 极速规则下载器启动")
    print(f"工作目录: {WORKSPACE}")
    
    # 启动性能计时
    global_start = time.time()
    
    # 执行核心流程
    clean_files()
    create_temp_dir()
    success_count = download_rules()
    
    # 最终状态报告
    total_time = time.time() - global_start
    if success_count > 0:
        print(f"✅ 部分成功: {success_count}规则 | 总耗时 {total_time:.1f}s")
    else:
        print(f"❌ 全部失败! 总耗时 {total_time:.1f}s")
        raise SystemExit(1)