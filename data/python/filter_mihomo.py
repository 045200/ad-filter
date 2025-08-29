#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Mihomo规则转换工具
使用allow_adh.txt过滤adblock_adh.txt，避免误杀
"""

import os
import re
from typing import List, Set

# ==============================================================================
# 配置
# ==============================================================================
class Config:
    BASE_DIR = os.getenv("GITHUB_WORKSPACE", os.getcwd())
    
    INPUT = {
        "BLACKLIST": os.path.join(BASE_DIR, "adblock_adh.txt"),
        "WHITELIST": os.path.join(BASE_DIR, "allow_adh.txt")
    }
    
    OUTPUT = {
        "MIHOMO": os.path.join(BASE_DIR, "adb.mrs"),
        "TEMP_CLASH": os.path.join(BASE_DIR, "temp_clash.yaml")
    }
    
    MIHOMO_TOOL = os.path.join(BASE_DIR, "data/mihomo-tool")
    
    # 规则类型
    RULE_TYPE = "domain"


# ==============================================================================
# 工具函数
# ==============================================================================
def is_valid_domain(domain: str) -> bool:
    """验证域名是否合法"""
    if not domain or domain.strip() == "":
        return False
    
    domain = domain.strip()
    
    # 排除纯IP地址
    if re.match(r'^(?:\d{1,3}\.){3}\d{1,3}$', domain):
        return False
    
    # 排除包含非法字符的域名
    if re.search(r'[:/\\\s#,@]', domain):
        return False
    
    # 检查通配符位置
    if domain.startswith('*') and not domain.startswith('*.'):
        return False
    if domain.endswith('*'):
        return False
    
    # 检查开头和结尾的点
    if domain.startswith('.') or domain.endswith('.'):
        return False
    
    # 校验域名分段
    parts = domain.split('.')
    if len(parts) < 2:
        return False
    
    for part in parts:
        if not part or len(part) > 63:
            return False
        if not re.match(r'^[a-zA-Z0-9-*]+$', part):
            return False
        if part.startswith('-') or part.endswith('-'):
            return False
    
    return True


def extract_domains_from_file(file_path: str) -> Set[str]:
    """从文件中提取所有有效域名"""
    domains = set()
    
    if not os.path.exists(file_path):
        return domains
        
    with open(file_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            
            # 跳过注释行和空行
            if not line or line.startswith("!"):
                continue
                
            # 移除AGH规则的特殊字符
            clean_line = re.sub(r'^[\|@\*\^]+', '', line)
            clean_line = re.sub(r'[\|@\*\^]+$', '', clean_line)
            
            # 移除修饰符部分
            clean_line = clean_line.split('$')[0]
            
            # 尝试提取域名
            domain = ""
            if re.match(r'^\|\|([a-zA-Z0-9-.*]+\.[a-zA-Z0-9-.*]+)\^', clean_line):
                # 匹配 ||domain.com^ 格式
                domain = re.match(r'^\|\|([a-zA-Z0-9-.*]+\.[a-zA-Z0-9-.*]+)\^', clean_line).group(1)
            elif re.match(r'^([a-zA-Z0-9-.*]+\.[a-zA-Z0-9-.*]+)\^', clean_line):
                # 匹配 domain.com^ 格式
                domain = re.match(r'^([a-zA-Z0-9-.*]+\.[a-zA-Z0-9-.*]+)\^', clean_line).group(1)
            elif re.match(r'^(?:0\.0\.0\.0|127\.0\.0\.1)\s+([a-zA-Z0-9-.*]+\.[a-zA-Z0-9-.*]+)', clean_line):
                # 匹配 hosts 格式
                domain = re.match(r'^(?:0\.0\.0\.0|127\.0\.0\.1)\s+([a-zA-Z0-9-.*]+\.[a-zA-Z0-9-.*]+)', clean_line).group(1)
            elif re.match(r'^@@\|\|([a-zA-Z0-9-.*]+\.[a-zA-Z0-9-.*]+)\^', clean_line):
                # 匹配 @@||domain.com^ 格式
                domain = re.match(r'^@@\|\|([a-zA-Z0-9-.*]+\.[a-zA-Z0-9-.*]+)\^', clean_line).group(1)
            else:
                # 尝试直接提取域名
                parts = clean_line.split()
                for part in parts:
                    if is_valid_domain(part):
                        domain = part
                        break
            
            if domain and is_valid_domain(domain):
                domains.add(domain)
    
    return domains


def is_subdomain(subdomain: str, domain: str) -> bool:
    """检查subdomain是否是domain的子域"""
    if not subdomain or not domain:
        return False
        
    # 处理通配符
    if domain.startswith('*.'):
        base_domain = domain[2:]
        return subdomain == base_domain or subdomain.endswith('.' + base_domain)
    elif subdomain.startswith('*.'):
        base_subdomain = subdomain[2:]
        return domain == base_subdomain or domain.endswith('.' + base_subdomain)
    else:
        return subdomain == domain or subdomain.endswith('.' + domain)


def filter_blacklist_with_whitelist(black_domains: Set[str], white_domains: Set[str]) -> Set[str]:
    """使用白名单过滤黑名单域名"""
    filtered_domains = set()
    
    for black_domain in black_domains:
        should_include = True
        
        for white_domain in white_domains:
            if is_subdomain(black_domain, white_domain):
                should_include = False
                break
                
        if should_include:
            filtered_domains.add(black_domain)
    
    return filtered_domains


def create_clash_yaml(domains: Set[str], output_path: str) -> None:
    """创建Clash格式的YAML文件"""
    with open(output_path, "w", encoding="utf-8") as f:
        f.write("payload:\n")
        for domain in sorted(domains):
            if domain.startswith('*'):
                f.write(f"  - '{domain}'\n")
            else:
                f.write(f"  - '+.{domain}'\n")


def compile_mihomo(clash_yaml_path: str, output_path: str) -> bool:
    """使用mihomo-tool编译规则集"""
    if not os.path.exists(Config.MIHOMO_TOOL):
        print(f"❌ Mihomo工具不存在：{Config.MIHOMO_TOOL}")
        return False
        
    cmd = [
        Config.MIHOMO_TOOL,
        "convert-ruleset",
        Config.RULE_TYPE,
        "yaml",
        clash_yaml_path,
        output_path
    ]
    
    try:
        import subprocess
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        if result.returncode == 0:
            return True
        else:
            print(f"❌ Mihomo编译失败：{result.stderr}")
            return False
    except Exception as e:
        print(f"❌ Mihomo编译异常：{e}")
        return False


# ==============================================================================
# 主流程
# ==============================================================================
def main():
    print("=" * 60)
    print("🛡️  Mihomo规则转换工具")
    print("📝 使用白名单过滤黑名单，避免误杀")
    print("=" * 60)
    
    # 步骤1：提取域名
    print("\n【1/4】提取域名...")
    black_domains = extract_domains_from_file(Config.INPUT["BLACKLIST"])
    white_domains = extract_domains_from_file(Config.INPUT["WHITELIST"])
    
    print(f"📊 提取统计：")
    print(f"  - 黑名单域名：{len(black_domains)} 个")
    print(f"  - 白名单域名：{len(white_domains)} 个")
    
    # 步骤2：过滤黑名单
    print("\n【2/4】过滤黑名单...")
    filtered_domains = filter_blacklist_with_whitelist(black_domains, white_domains)
    filtered_count = len(black_domains) - len(filtered_domains)
    print(f"📊 过滤统计：")
    print(f"  - 过滤前：{len(black_domains)} 个域名")
    print(f"  - 过滤后：{len(filtered_domains)} 个域名")
    print(f"  - 过滤掉：{filtered_count} 个可能误杀的域名")
    
    # 步骤3：创建临时Clash文件
    print("\n【3/4】创建临时Clash文件...")
    create_clash_yaml(filtered_domains, Config.OUTPUT["TEMP_CLASH"])
    print(f"✅ 临时文件创建成功：{Config.OUTPUT['TEMP_CLASH']}")
    
    # 步骤4：编译Mihomo规则集
    print("\n【4/4】编译Mihomo规则集...")
    if compile_mihomo(Config.OUTPUT["TEMP_CLASH"], Config.OUTPUT["MIHOMO"]):
        mrs_size = os.path.getsize(Config.OUTPUT["MIHOMO"]) / 1024 if os.path.exists(Config.OUTPUT["MIHOMO"]) else 0
        print(f"✅ Mihomo规则集生成成功：{Config.OUTPUT['MIHOMO']}（{mrs_size:.2f} KB）")
    else:
        print("❌ Mihomo规则集生成失败")
    
    # 清理临时文件
    if os.path.exists(Config.OUTPUT["TEMP_CLASH"]):
        os.remove(Config.OUTPUT["TEMP_CLASH"])
        print(f"🧹 已清理临时文件：{Config.OUTPUT['TEMP_CLASH']}")
    
    print("\n" + "=" * 60)
    print("🎉 Mihomo转换任务完成！")
    print("=" * 60)


if __name__ == "__main__":
    main()