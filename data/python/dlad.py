import requests
import os
import time
import sys

def download_adblock_rules():
    """
    下载广告规则并保存到适当的目录
    """
    # 配置参数
    url = "http://rssv.cn/adguard/config/black.txt"
    
    # 定义可能的输出目录
    possible_dirs = [
        "/data/filter",  # 绝对路径
        "./data/filter",  # 相对路径
    ]
    
    # 检查根目录/data/filter/是否存在
    root_filter_dir = "/data/filter"
    if os.path.exists(root_filter_dir) and os.path.isdir(root_filter_dir):
        output_dir = root_filter_dir
        print(f"✓ 检测到根目录文件夹存在: {root_filter_dir}")
    else:
        # 使用相对路径
        script_dir = os.path.dirname(os.path.abspath(__file__))
        output_dir = os.path.join(script_dir, "../../filter")
        output_dir = os.path.normpath(output_dir)  # 规范化路径
        print(f"✗ 根目录文件夹不存在，使用相对路径: {output_dir}")
    
    filename = "adblock99.txt"
    full_path = os.path.join(output_dir, filename)
    
    max_retries = 5
    timeout = 45
    
    print("\n开始下载广告规则...")
    print(f"URL: {url}")
    print(f"保存路径: {full_path}")
    
    # 创建目录（如果不存在）
    try:
        os.makedirs(output_dir, exist_ok=True)
        print(f"✓ 目录已创建/确认: {output_dir}")
    except Exception as e:
        print(f"✗ 创建目录失败: {e}")
        return False
    
    # 设置请求头
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
        'Accept': 'text/plain, */*',
        'Accept-Language': 'en-US,en;q=0.5',
    }
    
    # 重试机制
    for attempt in range(max_retries):
        try:
            print(f"尝试下载 (第 {attempt + 1}/{max_retries} 次)...")
            
            # 发送请求
            response = requests.get(url, headers=headers, timeout=timeout)
            response.raise_for_status()
            
            # 检查响应内容
            if not response.text.strip():
                raise ValueError("响应内容为空")
            
            # 保存文件
            with open(full_path, 'w', encoding='utf-8') as f:
                f.write(response.text)
            
            print("✓ 下载成功")
            
            # 验证文件
            if os.path.exists(full_path) and os.path.getsize(full_path) > 0:
                file_size = os.path.getsize(full_path)
                print(f"✓ 文件已保存: {full_path}")
                print(f"✓ 文件大小: {file_size} 字节")
                return True
            else:
                raise ValueError("文件保存失败")
                
        except requests.exceptions.Timeout:
            print(f"✗ 请求超时")
        except requests.exceptions.ConnectionError:
            print(f"✗ 连接错误")
        except requests.exceptions.HTTPError as e:
            print(f"✗ HTTP错误: {e}")
        except Exception as e:
            print(f"✗ 错误: {e}")
        
        # 如果不是最后一次尝试，等待后重试
        if attempt < max_retries - 1:
            wait_time = (attempt + 1) * 5
            print(f"等待 {wait_time} 秒后重试...")
            time.sleep(wait_time)
    
    return False

if __name__ == "__main__":
    print("=" * 50)
    print("广告规则下载脚本")
    print("=" * 50)
    
    # 检测根目录/data/filter/是否存在
    root_filter_dir = "/data/filter"
    if os.path.exists(root_filter_dir) and os.path.isdir(root_filter_dir):
        print(f"✓ 检测到根目录文件夹: {root_filter_dir}")
    else:
        print(f"✗ 未检测到根目录文件夹: {root_filter_dir}")
    
    start_time = time.time()
    
    # 执行下载
    if download_adblock_rules():
        download_time = time.time() - start_time
        print(f"\n✅ 下载完成! 耗时: {download_time:.2f} 秒")
        sys.exit(0)
    else:
        print("\n❌ 下载失败")
        sys.exit(1)