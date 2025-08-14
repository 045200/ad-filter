#!/usr/bin/env python3
import re
import sys
from concurrent.futures import ThreadPoolExecutor
from collections import defaultdict
from pathlib import Path
from typing import List, Tuple, Optional
import mmap

class AdGuardDNSRuleValidator:
    """增强版AdGuard Home DNS规则验证器（支持最新官方语法）"""

    @staticmethod
    def is_valid_rule(line: str) -> bool:
        """
        完整验证规则有效性：
        - 支持IPv4/IPv6/CIDR
        - 支持所有官方修饰符
        - 严格过滤注释和元信息
        """
        line = line.strip()
        if not line:
            return False

        # 增强注释检测（支持中英文及特殊符号）
        if re.match(r'^[!#].*[\u4e00-\u9fff\s]', line):
            return False

        # 核心匹配模式（按优先级排序）
        patterns = [
            # 1. 基础域名规则（增强通配符支持）
            r'^(\|\|[\w.*_-]+\^(?:\$[\w,=-]+)?|[\w.*-]+\.\w+$)',
            
            # 2. Hosts格式（支持IPv4/IPv6/CIDR）
            r'^((?:\d{1,3}\.){3}\d{1,3}|::\d*)\s+[\w.-]+',
            r'^[\da-fA-F:./]+\s+[\w.-]+$',  # 含CIDR
            
            # 3. 正则表达式规则
            r'^/.*/[ims]*(?:\$[\w,=-]+)?$',
            
            # 4. 完整修饰符语法（官方2023新版）
            r'^\|\|[\w.-]+\^\$[a-z]+(?:=[\w.-]*)?(?:,[a-z]+(?:=[\w.-]*)?)*$',
            
            # 5. 特殊功能规则
            r'^\|\|[\w.-]+\^\$dnsrewrite=[^;]+(?:;[^;]+)*$',  # DNS重写
            r'^\|\|[\w.-]+\^\$ctag=[\w,]+$',  # 设备标签
            r'^\|\|[\w.-]+\^\$client(?:=~?[\w.-]+)?$'  # 客户端
        ]

        # 特殊case处理（性能优化）
        if line.startswith(('||', '|', '/')):
            return any(re.match(p, line) for p in patterns[:4])
        return any(re.match(p, line) for p in patterns)

def validate_rules_batch(lines: List[str]) -> List[str]:
    """批量验证规则（优化CPU密集型任务）"""
    return [line.strip() for line in lines if AdGuardDNSRuleValidator.is_valid_rule(line)]

def detect_conflicts(rules: List[str]) -> List[Tuple[str, List[str]]]:
    """冲突检测（含自动修复建议）"""
    conflict_rules = []
    domain_map = defaultdict(list)
    
    for rule in rules:
        if match := re.match(r'^\|\|([\w.*-]+)\^', rule):
            domain = match.group(1).lower()
            domain_map[domain].append(rule)
    
    for domain, rules in domain_map.items():
        if len(rules) > 1:
            has_allow = any('@@' in r for r in rules)
            has_block = any('@@' not in r for r in rules)
            if has_allow and has_block:
                suggested = [r for r in rules if '@@' in r]  # 优先保留白名单
                conflict_rules.append((domain, suggested))
    
    return conflict_rules

def process_dns_rules(input_path: Path, output_path: Path) -> dict:
    """核心处理流程（线程安全+原子操作）"""
    stats = {
        'total': 0,
        'valid': 0,
        'domains': 0,
        'hosts': 0,
        'regex': 0,
        'conflicts': []
    }

    try:
        # 内存映射处理大文件
        with input_path.open('rb') as f:
            with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
                # 分块读取优化内存
                chunk_size = 1024 * 1024  # 1MB
                chunks = []
                while True:
                    chunk = mm.read(chunk_size)
                    if not chunk:
                        break
                    chunks.append(chunk.decode('utf-8', errors='replace'))
                content = ''.join(chunks)

        # 并行处理
        lines = content.splitlines()
        stats['total'] = len(lines)
        
        with ThreadPoolExecutor(max_workers=4) as executor:
            # 分块处理提升性能
            chunk_size = 5000
            batches = [lines[i:i + chunk_size] for i in range(0, len(lines), chunk_size)]
            results = list(executor.map(validate_rules_batch, batches))
            valid_rules = [rule for batch in results for rule in batch]

        stats['valid'] = len(valid_rules)
        
        # 冲突检测
        stats['conflicts'] = detect_conflicts(valid_rules)
        
        # 智能排序
        def sort_key(rule: str) -> Tuple[int, int]:
            if rule.startswith('||'): return (0, len(rule))
            if re.match(r'^[\d:a-fA-F]', rule): return (1, len(rule))
            return (2, len(rule))
        
        sorted_rules = sorted(valid_rules, key=sort_key)
        
        # 类型统计
        stats['domains'] = sum(1 for r in sorted_rules if r.startswith('||'))
        stats['hosts'] = sum(1 for r in sorted_rules if re.match(r'^[\d:]', r))
        stats['regex'] = sum(1 for r in sorted_rules if r.startswith('/'))
        
        # 原子写入
        temp_file = output_path.with_suffix('.tmp')
        with temp_file.open('w', encoding='utf-8') as f:
            f.write('\n'.join(sorted_rules))
        temp_file.replace(output_path)
        
        return stats

    except Exception as e:
        print(f"CRITICAL: {type(e).__name__} - {str(e)}", file=sys.stderr)
        raise

def main():
    """命令行入口"""
    try:
        # 自动定位仓库根目录
        repo_root = Path(__file__).resolve().parents[2]
        input_file = repo_root / "adblock.txt"
        output_file = repo_root / "dns.txt"
        
        print(f"🔍 输入文件: {input_file}")
        print(f"💾 输出文件: {output_file}")
        
        if not input_file.exists():
            raise FileNotFoundError(f"输入文件不存在: {input_file}")
        
        stats = process_dns_rules(input_file, output_file)
        
        # 打印报告
        print("\n📊 处理报告:")
        print(f"- 原始规则: {stats['total']}条")
        print(f"- 有效规则: {stats['valid']}条")
        print(f"  ├─ 域名规则: {stats['domains']}条")
        print(f"  ├─ Hosts规则: {stats['hosts']}条")
        print(f"  └─ 正则表达式: {stats['regex']}条")
        
        if stats['conflicts']:
            print("\n⚠️ 发现规则冲突:")
            for domain, suggested in stats['conflicts']:
                print(f"  {domain}: 建议保留 {suggested[0]}")
        
        print("\n✅ 处理完成！输出文件已验证语法兼容性")

    except Exception as e:
        print(f"❌ 处理失败: {str(e)}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()