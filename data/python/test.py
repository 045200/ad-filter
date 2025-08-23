#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import dns.resolver
import time
import statistics
import json
import sys
from datetime import datetime

# 测试的域名列表 - 国内和国外
DOMAINS = [
    # 国内主流网站
    "www.baidu.com",          # 百度
    "www.taobao.com",         # 淘宝
    "www.qq.com",             # 腾讯
    "www.jd.com",             # 京东
    "www.sina.com.cn",        # 新浪
    "www.163.com",            # 网易
    "www.weibo.com",          # 微博
    "www.zhihu.com",          # 知乎
    "www.bilibili.com",       # B站
    "www.douyin.com",         # 抖音
    "www.xiaohongshu.com",    # 小红书
    "www.meituan.com",        # 美团
    "www.dianping.com",       # 大众点评
    "www.ctrip.com",          # 携程
    "www.12306.cn",           # 铁路官网
    "www.gov.cn",             # 政府网
    
    # 国外主流网站
    "www.google.com",         # Google
    "www.facebook.com",       # Facebook
    "www.twitter.com",        # Twitter
    "www.instagram.com",      # Instagram
    "www.youtube.com",        # YouTube
    "www.amazon.com",         # Amazon
    "www.microsoft.com",      # Microsoft
    "www.apple.com",          # Apple
    "www.netflix.com",        # Netflix
    "www.wikipedia.org",      # Wikipedia
    "www.reddit.com",         # Reddit
    "www.linkedin.com",       # LinkedIn
    "www.spotify.com",        # Spotify
    "www.tiktok.com",         # TikTok
    "www.discord.com",        # Discord
    "www.twitch.tv",          # Twitch
    
    # CDN和云服务
    "cloudflare.com",
    "aws.amazon.com",
    "azure.microsoft.com",
    "cloud.google.com",
    
    # 国际新闻媒体
    "www.bbc.com",
    "www.cnn.com",
    "www.nytimes.com",
    "www.theguardian.com"
]

# DNS服务器列表 - 国内和国外
DNS_SERVERS = {
    # 国内DNS服务器
    "国内DNS-114": "114.114.114.114",
    "国内DNS-114备": "114.114.115.115",
    "国内DNS-阿里": "223.5.5.5",
    "国内DNS-阿里备": "223.6.6.6",
    "国内DNS-腾讯": "119.29.29.29",
    "国内DNS-百度": "180.76.76.76",
    "国内DNS-清华": "101.6.6.6",
    "国内DNS-清华备": "101.7.7.7",
    "国内DNS-南京信风": "114.114.114.119",  # 纯净无劫持
    "国内DNS-南京信风备": "114.114.115.119",
    "国内DNS-360": "101.226.4.6",         # 360安全DNS
    "国内DNS-360备": "123.125.81.6",
    
    # 国外DNS服务器
    "国外DNS-Google": "8.8.8.8",
    "国外DNS-Google备": "8.8.4.4",
    "国外DNS-Cloudflare": "1.1.1.1",
    "国外DNS-Cloudflare备": "1.0.0.1",
    "国外DNS-OpenDNS": "208.67.222.222",
    "国外DNS-OpenDNS备": "208.67.220.220",
    "国外DNS-Quad9": "9.9.9.9",           # 安全DNS
    "国外DNS-Quad9备": "149.112.112.112",
    "国外DNS-AdGuard": "94.140.14.14",    # AdGuard DNS
    "国外DNS-AdGuard备": "94.140.15.15",
    "国外DNS-Comodo": "8.26.56.26",       # Comodo安全DNS
    "国外DNS-Comodo备": "8.20.247.20",
    "国外DNS-Norton": "199.85.126.10",    # Norton ConnectSafe
    "国外DNS-Norton备": "199.85.127.10",
    "国外DNS-Yandex": "77.88.8.8",        # 俄罗斯Yandex DNS
    "国外DNS-Yandex备": "77.88.8.1",
    "国外DNS-Level3": "209.244.0.3",      # Level3通信
    "国外DNS-Level3备": "209.244.0.4",
    "国外DNS-Verisign": "64.6.64.6",      # Verisign公共DNS
    "国外DNS-Verisign备": "64.6.65.6"
}

def test_dns_server(server_name, server_ip, domains):
    """测试单个DNS服务器的解析速度"""
    resolver = dns.resolver.Resolver()
    resolver.nameservers = [server_ip]
    resolver.timeout = 5  # 设置超时时间为5秒
    resolver.lifetime = 5  # 设置总超时时间为5秒
    
    results = []
    
    for domain in domains:
        try:
            start_time = time.time()
            answers = resolver.resolve(domain)
            end_time = time.time()
            
            response_time = (end_time - start_time) * 1000  # 转换为毫秒
            results.append({
                "domain": domain,
                "time": round(response_time, 2),
                "success": True,
                "ip": answers[0].to_text() if answers else "N/A"
            })
        except Exception as e:
            results.append({
                "domain": domain,
                "time": 0,
                "success": False,
                "error": str(e),
                "ip": "N/A"
            })
    
    # 计算平均响应时间（仅成功请求）
    success_times = [r["time"] for r in results if r["success"]]
    avg_time = statistics.mean(success_times) if success_times else 0
    success_rate = len(success_times) / len(results) * 100
    
    return {
        "server": server_name,
        "ip": server_ip,
        "results": results,
        "avg_time": round(avg_time, 2),
        "success_rate": round(success_rate, 2)
    }

def categorize_domains(domains):
    """将域名分类为国内和国外"""
    china_domains = []
    overseas_domains = []
    
    # 国内域名关键词
    china_keywords = ['.cn', '.com.cn', 'baidu', 'taobao', 'qq', 'jd', 'sina', '163', 
                     'weibo', 'zhihu', 'bilibili', 'douyin', 'xiaohongshu', 'meituan',
                     'dianping', 'ctrip', '12306', 'gov']
    
    for domain in domains:
        if any(keyword in domain for keyword in china_keywords):
            china_domains.append(domain)
        else:
            overseas_domains.append(domain)
    
    return china_domains, overseas_domains

def main():
    print("开始DNS解析速度测试...")
    print(f"测试时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"测试域名总数: {len(DOMAINS)}")
    
    # 分类域名
    china_domains, overseas_domains = categorize_domains(DOMAINS)
    print(f"国内域名: {len(china_domains)} 个")
    print(f"国外域名: {len(overseas_domains)} 个")
    print("-" * 80)
    
    all_results = []
    
    # 测试所有DNS服务器
    for server_name, server_ip in DNS_SERVERS.items():
        print(f"正在测试 {server_name} ({server_ip})...")
        result = test_dns_server(server_name, server_ip, DOMAINS)
        all_results.append(result)
        
        print(f"  平均响应时间: {result['avg_time']} ms")
        print(f"  成功率: {result['success_rate']}%")
        print()
    
    # 按平均响应时间排序
    all_results.sort(key=lambda x: x["avg_time"])
    
    # 输出结果
    print("=" * 80)
    print("DNS服务器响应时间排名:")
    for i, result in enumerate(all_results, 1):
        print(f"{i}. {result['server']} ({result['ip']}): {result['avg_time']} ms (成功率: {result['success_rate']}%)")
    
    # 保存结果到文件
    with open("dns_test_results.json", "w", encoding="utf-8") as f:
        json.dump({
            "timestamp": datetime.now().isoformat(),
            "domains": DOMAINS,
            "china_domains": china_domains,
            "overseas_domains": overseas_domains,
            "results": all_results
        }, f, ensure_ascii=False, indent=2)
    
    print("测试完成，结果已保存到 dns_test_results.json")
    return 0

if __name__ == "__main__":
    sys.exit(main())