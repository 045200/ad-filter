#!/usr/bin/env python3
"""
广告规则转换终极完整版
功能：
1. 自动获取最新mihomo版本
2. 支持五大拦截器规则转换
3. 生成带广告优化参数的.mrs文件
4. 严格/宽容模式可选
"""

import os
import re
import sys
import json
import gzip
import shutil
import hashlib
import urllib.request
from pathlib import Path
from datetime import datetime
import tempfile
import subprocess
from typing import List, Set, Dict, Optional

# 配置常量
REPO_ROOT = Path(__file__).parent.parent.parent
STRICT_MODE = False  # 广告规则严格模式开关

class MihomoManager:
    """Mihomo工具链全自动管理器"""
    
    def __init__(self):
        self.tool_dir = REPO_ROOT / "mihomo_tools"
        self.binary_path = None
        self.latest_version = None

    def _get_latest_version(self) -> Optional[str]:
        """获取GitHub最新发行版"""
        try:
            with urllib.request.urlopen(
                "https://api.github.com/repos/MetaCubeX/mihomo/releases/latest",
                timeout=10
            ) as response:
                data = json.loads(response.read())
                return data['tag_name']
        except Exception as e:
            print(f"获取最新版本失败: {str(e)}", file=sys.stderr)
            return None

    def _download_tool(self, version: str) -> bool:
        """下载并解压mihomo工具"""
        try:
            self.tool_dir.mkdir(parents=True, exist_ok=True)
            platform = "linux-amd64"  # 可根据实际系统修改
            url = f"https://github.com/MetaCubeX/mihomo/releases/download/{version}/mihomo-{platform}-{version}.gz"
            gz_path = self.tool_dir / f"mihomo-{version}.gz"
            
            print(f"下载mihomo {version}...")
            urllib.request.urlretrieve(url, gz_path)
            
            # 解压并设置权限
            self.binary_path = self.tool_dir / f"mihomo-{version}"
            with gzip.open(gz_path, 'rb') as f_in:
                with open(self.binary_path, 'wb') as f_out:
                    shutil.copyfileobj(f_in, f_out)
            
            self.binary_path.chmod(0o755)
            gz_path.unlink()
            return True
            
        except Exception as e:
            print(f"工具下载失败: {str(e)}", file=sys.stderr)
            return False

    def prepare(self) -> bool:
        """准备最新版mihomo工具链"""
        if not (self.latest_version := self._get_latest_version()):
            return False
            
        self.binary_path = self.tool_dir / f"mihomo-{self.latest_version}"
        if self.binary_path.exists():
            print(f"使用缓存工具: {self.latest_version}")
            return True
            
        return self._download_tool(self.latest_version)

class AdRuleConverter:
    """广告规则转换引擎"""
    
    AD_KEYWORDS = {
        'ad', 'ads', 'advert', 'analytics', 'track', 
        'counter', 'metric', 'pixel', 'beacon'
    }

    def __init__(self):
        self.rule_cache: Set[str] = set()
        self.stats = {'block': 0, 'allow': 0}

    def _is_ad_related(self, domain: str) -> bool:
        """宽松模式广告检测"""
        domain = domain.lower()
        return any(kw in domain for kw in self.AD_KEYWORDS)

    def _parse_rule(self, line: str) -> Optional[Dict]:
        """支持所有主流广告规则语法[citation:1][citation:6]"""
        line = line.strip()
        if not line or line.startswith(('!', '#')):
            return None

        # 处理白名单规则
        if line.startswith('@@'):
            if match := re.match(r'^@@\|\|?([\w*.-]+)\^?', line):
                return {
                    'type': 'allow',
                    'domain': match.group(1).replace('*.', ''),
                    'raw': line
                }
            return None

        # 处理拦截规则
        rule_patterns = [
            (r'^\|\|([\w*.-]+)\^', 'domain'),      # AdBlock语法
            (r'^\|?https?://([\w*.-]+)/?', 'url'),  # URL规则
            (r'^(0\.0\.0\.0|127\.0\.0\.1)\s+([\w.-]+)', 'hosts'),  # Hosts
            (r'^([\w*.-]+)$', 'plain')              # 纯域名
        ]

        for pattern, _ in rule_patterns:
            if match := re.match(pattern, line):
                domain = match.group(1) if 'hosts' not in pattern else match.group(2)
                return {
                    'type': 'block',
                    'domain': domain.replace('*.', ''),
                    'raw': line,
                    'is_ad': True if STRICT_MODE else self._is_ad_related(domain)
                }
        return None

    def _convert_rule(self, rule: Dict) -> Optional[str]:
        """高精度规则转换[citation:7]"""
        if not rule['domain'] or '*' in rule['domain']:
            return None

        if rule['type'] == 'allow':
            self.stats['allow'] += 1
            return f"DOMAIN-SUFFIX,{rule['domain']},DIRECT"
        
        if not rule.get('is_ad', True):
            return None

        self.stats['block'] += 1
        return f"DOMAIN-SUFFIX,{rule['domain']},REJECT,adblock"

    def process_file(self, input_path: Path, is_allow: bool = False) -> List[str]:
        """处理规则文件"""
        converted = []
        if not input_path.exists():
            return converted

        with open(input_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                if rule := self._parse_rule(line):
                    if converted_rule := self._convert_rule(rule):
                        if converted_rule not in self.rule_cache:
                            self.rule_cache.add(converted_rule)
                            converted.append(converted_rule)
        return converted

def main():
    print(f"{datetime.now()} [INFO] 开始广告规则转换")
    
    # 1. 准备mihomo工具链
    mgr = MihomoManager()
    if not mgr.prepare():
        print(f"{datetime.now()} [ERROR] 无法准备mihomo工具链", file=sys.stderr)
        sys.exit(1)

    # 2. 处理规则文件
    converter = AdRuleConverter()
    input_files = {
        'allow': REPO_ROOT / "allow.txt",
        'block': REPO_ROOT / "adblock.txt"
    }
    
    rules = []
    for name, path in input_files.items():
        if file_rules := converter.process_file(path, is_allow=(name == 'allow')):
            rules.extend(file_rules)

    # 3. 添加系统必要规则[citation:2][citation:8]
    essential_rules = [
        "GEOSITE,ads,REJECT",  # 广告域名分类
        "GEOIP,CN,DIRECT",     # 中国IP直连
        "MATCH,PROXY"          # 默认策略
    ]
    rules.extend(essential_rules)

    # 4. 生成临时规则文件（带广告参数）
    with tempfile.NamedTemporaryFile(mode='w+') as tmp:
        tmp.write(f"""params:
  enable-adblock: true
  adblock-speedup: true
  strict-mode: {str(STRICT_MODE).lower()}
  disable-geoip: false
rules:
""")
        tmp.write("\n".join(rules))
        tmp.flush()

        # 5. 转换为.mrs格式[citation:6]
        result = subprocess.run([
            str(mgr.binary_path), "rulegen",
            "-i", tmp.name,
            "-o", str(REPO_ROOT / "adblock.mrs"),
            "--adblock",
            "--strict" if STRICT_MODE else "--loose"
        ], capture_output=True, text=True)

        if result.returncode != 0:
            print(f"{datetime.now()} [ERROR] 规则生成失败: {result.stderr}", file=sys.stderr)
            sys.exit(1)

    # 输出统计
    print(f"{datetime.now()} [INFO] 转换成功！")
    print(f"拦截规则: {converter.stats['block']}条")
    print(f"白名单规则: {converter.stats['allow']}条")
    print(f"输出文件: {REPO_ROOT/'adblock.mrs'}")

if __name__ == "__main__":
    main()