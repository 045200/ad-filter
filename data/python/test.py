#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import dns.resolver
import time
import json
import sys
import concurrent.futures
from datetime import datetime
import requests
import re
from urllib.parse import urlparse
import os

# 广告域名列表（可以从文件读取或直接在这里定义）
AD_DOMAINS = [
    # 这里可以添加您需要测试的广告域名
    # 示例：
    "ad.example.com",
    "tracking.example.org",
    "ads.google.com",
    "adservice.google.com",
    "ad.doubleclick.net",
    "ad.360.cn",
    "ad.taobao.com",
    "ad.baidu.com",
    "adx.baidu.com",
    "adui.tg.meitu.com",
    "ads.mopub.com",
    "ads.facebook.com",
    "analytics.google.com",
    "stats.g.doubleclick.net",
    "pagead2.googlesyndication.com",
    "partnerad.l.doubleclick.net",
    "securepubads.g.doubleclick.net",
    "tpc.googlesyndication.com",
    "ad.qq.com",
    "adcdn.tencent.com",
    "ads.tencent.com",
    "admaster.com.cn",
    "adn.insight.ucweb.com",
    "adx.yiche.com",
    "adxserver.ad.cmvideo.cn",
    "ad.weibo.com",
    "ad.weibo.com.cn",
    "adimg.uve.weibo.com",
    "adimgs.x.cn",
    "adx.dlads.cn",
    "adx.pro.cn",
    "adx.sina.com.cn",
    "adx.sina.cn",
    "adxstatic.sina.cn",
    "ad.zhangyue.com",
    "ad.api.zhangyue.com",
    "adlog.vivo.com.cn",
    "ads.wasu.cn",
    "adshow.58.com",
    "adshow.g.58.com",
    "adx.58.com",
    "adx.gifshow.com",
    "adx.kuaishou.com",
    "adx.kuaishouzt.com",
    "adx.kuwo.cn",
    "adx.yiche.com",
    "adx.zhangyue.com",
    "adx.zhangyue.com.cn"
]

# 专注于国内DNS服务器
DNS_SERVERS = {
    # 国内公共DNS服务器
    "114DNS": {"ip": "114.114.114.114", "type": "udp"},
    "AliDNS": {"ip": "223.5.5.5", "type": "udp"},
    "TencentDNS": {"ip": "119.29.29.29", "type": "udp"},
    "BaiduDNS": {"ip": "180.76.76.76", "type": "udp"},
    
    # 国内DoH服务器
    "AliDoH": {"url": "https://dns.alidns.com/dns-query", "type": "doh"},
    "TencentDoH": {"url": "https://doh.pub/dns-query", "type": "doh"},
    "360DoH": {"url": "https://doh.360.cn/dns-query", "type": "doh"},
    
    # 运营商DNS
    "ChinaTelecom": {"ip": "218.2.2.2", "type": "udp"},
    "ChinaUnicom": {"ip": "123.123.123.123", "type": "udp"},
    "ChinaMobile": {"ip": "211.136.192.6", "type": "udp"},
}

def load_ad_domains_from_file(file_path):
    """从文件加载广告域名列表"""
    domains = []
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    # 处理AdBlock规则格式
                    if line.startswith('||'):
                        domain = line[2:].split('^')[0]
                        domains.append(domain)
                    elif line.startswith('|http://') or line.startswith('|https://'):
                        parsed = urlparse(line[1:])
                        domains.append(parsed.netloc)
                    else:
                        domains.append(line)
        return domains
    except FileNotFoundError:
        print(f"文件 {file_path} 不存在，使用内置域名列表")
        return AD_DOMAINS

def test_domain_resolution(domain, dns_server_info, timeout=5):
    """测试单个域名的DNS解析"""
    try:
        if dns_server_info["type"] == "udp":
            resolver = dns.resolver.Resolver()
            resolver.nameservers = [dns_server_info["ip"]]
            resolver.timeout = timeout
            resolver.lifetime = timeout
            
            start_time = time.time()
            answers = resolver.resolve(domain)
            end_time = time.time()
            
            response_time = (end_time - start_time) * 1000  # 转换为毫秒
            return {
                "success": True,
                "time": round(response_time, 2),
                "ip": answers[0].to_text() if answers else "N/A"
            }
            
        elif dns_server_info["type"] == "doh":
            headers = {
                'accept': 'application/dns-json',
                'content-type': 'application/dns-json'
            }
            
            params = {
                'name': domain,
                'type': 'A'
            }
            
            start_time = time.time()
            response = requests.get(dns_server_info["url"], headers=headers, params=params, timeout=timeout)
            end_time = time.time()
            
            response_time = (end_time - start_time) * 1000  # 转换为毫秒
            
            if response.status_code == 200:
                data = response.json()
                if 'Answer' in data and len(data['Answer']) > 0:
                    return {
                        "success": True,
                        "time": round(response_time, 2),
                        "ip": data['Answer'][0]['data']
                    }
            
            return {
                "success": False,
                "time": 0,
                "error": f"HTTP {response.status_code}",
                "ip": "N/A"
            }
            
    except Exception as e:
        return {
            "success": False,
            "time": 0,
            "error": str(e),
            "ip": "N/A"
        }

def test_domain_with_multiple_dns(domain, dns_servers, timeout=5):
    """使用多个DNS服务器测试域名解析"""
    results = {}
    
    for server_name, server_info in dns_servers.items():
        result = test_domain_resolution(domain, server_info, timeout)
        results[server_name] = result
        
        # 如果有一个DNS服务器解析成功，就认为域名有效
        if result["success"]:
            break
    
    return results

def main():
    print("开始广告域名DNS解析测试...")
    print(f"测试时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    # 从文件加载广告域名或使用内置列表
    ad_domains_file = "ad_domains.txt"
    if os.path.exists(ad_domains_file):
        ad_domains = load_ad_domains_from_file(ad_domains_file)
    else:
        ad_domains = AD_DOMAINS
    
    print(f"测试域名总数: {len(ad_domains)}")
    print(f"使用DNS服务器: {', '.join(DNS_SERVERS.keys())}")
    print("-" * 80)
    
    valid_domains = []
    invalid_domains = []
    results = {}
    
    # 使用线程池并行测试域名
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        future_to_domain = {
            executor.submit(test_domain_with_multiple_dns, domain, DNS_SERVERS): domain 
            for domain in ad_domains
        }
        
        for future in concurrent.futures.as_completed(future_to_domain):
            domain = future_to_domain[future]
            try:
                domain_results = future.result()
                results[domain] = domain_results
                
                # 检查是否有DNS服务器成功解析
                is_valid = any(result["success"] for result in domain_results.values())
                
                if is_valid:
                    valid_domains.append(domain)
                    print(f"✓ {domain} - 有效")
                else:
                    invalid_domains.append(domain)
                    print(f"✗ {domain} - 无效")
                    
            except Exception as e:
                print(f"测试 {domain} 时发生错误: {str(e)}")
                invalid_domains.append(domain)
    
    # 输出统计结果
    print("=" * 80)
    print(f"测试完成!")
    print(f"有效域名: {len(valid_domains)} 个")
    print(f"无效域名: {len(invalid_domains)} 个")
    print(f"成功率: {len(valid_domains) / len(ad_domains) * 100:.2f}%")
    
    # 保存结果到文件
    with open("dns_test_results.json", "w", encoding="utf-8") as f:
        json.dump({
            "timestamp": datetime.now().isoformat(),
            "total_domains": len(ad_domains),
            "valid_domains": valid_domains,
            "invalid_domains": invalid_domains,
            "results": results
        }, f, ensure_ascii=False, indent=2)
    
    # 保存无效域名列表
    with open("invalid_domains.txt", "w", encoding="utf-8") as f:
        for domain in invalid_domains:
            f.write(f"{domain}\n")
    
    print("测试完成!")
    print(f"结果已保存到 dns_test_results.json")
    print(f"无效域名列表已保存到 invalid_domains.txt")
    
    return 0

if __name__ == "__main__":
    sys.exit(main())