#!/usr/bin/env python3
"""
广告拦截规则转换器 (支持ABP/AdGuard/uBO/Easylist/hosts)
将多种广告拦截规则转换为标准化DNS过滤规则
"""

import re
import ipaddress
from pathlib import Path
from collections import OrderedDict
from typing import Dict, Optional, Set, Tuple, List
import sys

class DNSRuleConverter:
    """支持多源广告拦截规则转换的核心处理器"""

    def __init__(self):
        # 编译正则表达式（按匹配频率排序）
        self._patterns = {
            # 基础域名规则（高频）
            'abp_standard': re.compile(r'^\|\|([\w*.-]+)\^(?:\$[\w-]+(?:=[^,\s]+)?(?:,~?[\w-]+)*$'),
            'hosts_entry': re.compile(
                r'^(?:'
                r'(?P<ip>0\.0\.0\.0|127\.0\.0\.1|'          # IPv4
                r'::(?:1|0)|'                                # IPv6本地
                r'(?:[0-9a-fA-F]{1,4}:){1,7}[0-9a-fA-F]{0,4}|'  # 标准IPv6
                r'\[(?:[0-9a-fA-F:]+)\](?::\d+)?'           # [IPv6]:port
                r')\s+(?P<domain>[\w*.-]+)(?:\s*#.*)?$'     # 域名+可选注释
            ),
            
            # 各平台特色规则（中频）
            'ubo_special': re.compile(r'^\|\|([\w.-]+)\^\$.*,\~?\w+'),
            'adguard_dns': re.compile(r'^\|\|([\w.-]+)\^\$(?:dnstype|dnsrewrite)=[^,\s]+'),
            'easylist_domain': re.compile(r'^([\w*.-]+)##[^#\s\[]'),
            
            # 其他规则（低频）
            'pure_domain': re.compile(r'^([\w*.-]+)$'),
            'redirect_rule': re.compile(r'^\|\|([\w.-]+)\^\$redirect(?:-rule)?=([^\s,]+)'),
            
            # 过滤规则
            'comment': re.compile(r'^\s*[!#]|^\s*$'),
            'element_hiding': re.compile(r'^##[^#\s\[]'),
            'exception': re.compile(r'^@@'),
            'dynamic_content': re.compile(r'^\+\w+\(')
        }

        # DNS标准配置
        self._valid_dns_types = {
            'A', 'AAAA', 'CNAME', 'MX', 'TXT',
            'NS', 'SOA', 'PTR', 'SRV', 'NAPTR'
        }
        
        # 修饰符转换映射
        self._modifier_map = {
            'redirect-rule': 'redirect',
            'denyallow': 'badfilter'
        }

    def process_file(self, input_file: Path, output_file: Path) -> Tuple[int, int]:
        """
        处理输入文件并生成DNS规则
        :return: (有效规则数, 警告数)
        """
        seen = OrderedDict()
        stats = {'valid': 0, 'warnings': 0}

        with input_file.open('r', encoding='utf-8', errors='replace') as f_in:
            for line_num, line in enumerate(f_in, 1):
                line = line.strip()
                result = self._process_line(line, line_num)
                
                if result:
                    if result not in seen:
                        seen[result] = True
                        stats['valid'] += 1
                else:
                    stats['warnings'] += 1

        # 写入输出文件
        with output_file.open('w', encoding='utf-8') as f_out:
            f_out.write(f"! 由 {self.__class__.__name__} 生成\n")
            f_out.write(f"! 源文件: {input_file.name}\n")
            f_out.write(f"! 规则数: {stats['valid']}\n\n")
            f_out.write('\n'.join(seen.keys()))

        return stats['valid'], stats['warnings']

    def _process_line(self, line: str, line_num: int) -> Optional[str]:
        """单行规则处理管道"""
        # 阶段1：快速跳过
        if self._should_skip(line):
            return None

        # 阶段2：域名提取
        domain = self._extract_domain(line)
        if not domain:
            self._log_warning(line_num, "无效域名格式", line)
            return None

        # 阶段3：DNS验证
        if not self._validate_domain(domain):
            self._log_warning(line_num, "域名不符合DNS规范", line)
            return None

        # 阶段4：修饰符处理
        modifiers = self._parse_modifiers(line)
        if not self._validate_modifiers(modifiers):
            self._log_warning(line_num, "无效修饰符", line)
            return None

        # 阶段5：规则生成
        return self._build_rule(domain, modifiers)

    def _should_skip(self, line: str) -> bool:
        """判断是否应跳过当前行"""
        return any(
            pattern.match(line)
            for pattern in [
                self._patterns['comment'],
                self._patterns['exception'],
                self._patterns['element_hiding'],
                self._patterns['dynamic_content']
            ]
        )

    def _extract_domain(self, line: str) -> Optional[str]:
        """多模式域名提取"""
        # 尝试各匹配模式（按优先级）
        for pattern_name in [
            'abp_standard',
            'hosts_entry',
            'ubo_special',
            'adguard_dns',
            'easylist_domain',
            'pure_domain',
            'redirect_rule'
        ]:
            if match := self._patterns[pattern_name].match(line):
                if pattern_name == 'hosts_entry':
                    return match.group('domain').lower()
                return match.group(1).lower()
        return None

    def _validate_domain(self, domain: str) -> bool:
        """严格域名验证 (RFC 1035)"""
        if not domain or domain.startswith('.') or domain.endswith('.'):
            return False

        # 通配符检查
        if '*' in domain:
            if domain not in ('*', '*.') and not domain.startswith('*.'):
                return False
            domain = domain.lstrip('*.')

        # 标签验证
        for label in domain.split('.'):
            if not 0 < len(label) < 64:
                return False
            if not re.match(r'^[a-z0-9-]+$', label, re.IGNORECASE):
                return False
        return True

    def _parse_modifiers(self, line: str) -> Dict[str, str]:
        """修饰符解析与标准化"""
        if '$' not in line:
            return {}

        modifiers = {}
        # 提取原始修饰符
        raw_mods = line.split('$', 1)[1].split(',')
        
        for mod in raw_mods:
            if '=' in mod:
                key, val = mod.split('=', 1)
                key = self._modifier_map.get(key, key)
                modifiers[key] = val
            else:
                key = self._modifier_map.get(mod, mod)
                modifiers[key] = ''

        return modifiers

    def _validate_modifiers(self, modifiers: Dict[str, str]) -> bool:
        """修饰符有效性验证"""
        # DNS类型检查
        if 'dnstype' in modifiers:
            types = modifiers['dnstype'].upper().replace('~', '').split(',')
            if not all(t in self._valid_dns_types for t in types):
                return False

        # 重定向目标检查
        if 'redirect' in modifiers:
            target = modifiers['redirect'].split('#')[0].strip()
            if not (self._is_valid_ip(target) or self._validate_domain(target.split(':')[0])):
                return False

        return True

    def _is_valid_ip(self, ip_str: str) -> bool:
        """验证IP地址有效性"""
        try:
            # 处理[IPv6]:port格式
            if ip_str.startswith('[') and ']' in ip_str:
                ip_str = ip_str[1:ip_str.index(']')]
            ipaddress.ip_address(ip_str)
            return True
        except ValueError:
            return False

    def _build_rule(self, domain: str, modifiers: Dict[str, str]) -> str:
        """构建标准化DNS规则"""
        rule = f"||{domain}^"
        
        # 无修饰符的默认处理
        if not modifiers:
            return f"{rule}$dnsrewrite=NOERROR;;"

        # 处理特殊修饰符
        processed = []
        if 'dnstype' in modifiers:
            processed.append(f"dnstype={modifiers['dnstype']}")
        if 'dnsrewrite' in modifiers:
            processed.append(f"dnsrewrite={modifiers['dnsrewrite']}")
        elif 'redirect' in modifiers:
            processed.append(f"dnsrewrite=NOERROR;{modifiers['redirect']}")
        if 'important' in modifiers:
            processed.append("important")

        return f"{rule}${','.join(processed)}" if processed else rule

    def _log_warning(self, line_num: int, reason: str, line: str):
        """输出警告信息（可重定向到日志系统）"""
        print(f"[WARN] 行 {line_num}: {reason} -> {line[:50]}{'...' if len(line)>50 else ''}",
              file=sys.stderr)

def main():
    """命令行入口"""
    # 路径解析（适配GitHub目录结构）
    script_path = Path(__file__).absolute()
    repo_root = script_path.parent.parent.parent if script_path.parent.name == 'python' else script_path.parent
    
    input_file = repo_root / "adblock.txt"
    output_file = repo_root / "dns.txt"
    
    if not input_file.exists():
        print(f"错误: 输入文件不存在 {input_file}", file=sys.stderr)
        sys.exit(1)

    converter = DNSRuleConverter()
    try:
        valid, warnings = converter.process_file(input_file, output_file)
        print(f"转换完成: {valid} 条有效规则 | {warnings} 条警告")
        print(f"输出文件: {output_file}")
    except Exception as e:
        print(f"致命错误: {str(e)}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()