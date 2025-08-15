import os
import glob
import re
from pathlib import Path
from typing import List, Set, Pattern, Tuple, Optional, Dict
from concurrent.futures import ThreadPoolExecutor
import hashlib

# 全局配置
os.chdir('tmp')
TARGET_DIR = Path('../')
TARGET_DIR.mkdir(exist_ok=True)

class RuleValidator:
    """全覆盖的广告拦截规则验证器（支持五大拦截器）"""

    BASE_PATTERNS = {
        # 基础规则模式
        'domain': r'^\|\|[\w*.-]+\^(?:\$[\w-]+(?:=[\w.-]*)?(?:,~?[\w-]+(?:=[\w.-]*)?)*)?$',
        'domain_suffix': r'^\|\|\*\.?[\w*.-]+\^',
        'exact_domain': r'^\|https?://[\w*.-]+/',
        'regex_domain': r'^/@\|\|[\w*.-]+\^/',
        
        # 元素规则
        'element_hiding': r'^##[^#\s\[].*',
        'extended_css': r'^#\?#[^#\s\[].*',
        'exception_hiding': r'^#@#.+',
        
        # 网络规则
        'hosts': r'^\d+\.\d+\.\d+\.\d+\s+[\w*.-]+',
        'regex': r'^/(?:[^/\\]|\\.)*/[imsxADSUXJ]*$',
        'pihole': r'^[\w*.-]+$',  # Pi-hole纯域名规则[citation:4]
        
        # 修饰符（增强版）
        'modifiers': {
            'basic': r'\$(~?[\w-]+(?:=[\w.-]*)?(?:,~?[\w-]+(?:=[\w.-]*)?)*)$',
            'document': r'document',
            'script': r'script',
            'image': r'image',
            'stylesheet': r'stylesheet',
            'subrequest': r'subrequest',
            'popup': r'popup',
            'xmlhttprequest': r'xmlhttprequest',
            'websocket': r'websocket',
            'webrtc': r'webrtc',
            'font': r'font',
            'media': r'media',
            'object': r'object',
            'other': r'other',
            'third-party': r'third-party',
            'first-party': r'~third-party',
            'domain': r'domain=([\w.-]+|\|[\w.-]+\|)',
            'sitekey': r'sitekey=[\w/+=-]+',
            'denyallow': r'denyallow=[\w.|-]+',
            'redirect': r'redirect(?:-rule)?=[\w-]+',
            'removeparam': r'removeparam=[^&]+',
            'csp': r'csp=[\w\s-]+',
            'header': r'header=[\w-]+',
            'cookie': r'cookie=[^;]+',
            'replace': r'replace=/[^/]+(?:/[^/]*)?/$',
            'jsinject': r'jsinject',
            'elemhide': r'elemhide',
            'generichide': r'generichide',
            'specifichide': r'specificblock',
            'content': r'content',
            'urlblock': r'urlblock',
            'important': r'important',
            'badfilter': r'badfilter',
            'empty': r'empty',
            'mp4': r'mp4',
            # 拦截器特有修饰符
            'adguard_ctag': r'ctag=\w+',  # AdGuard特有[citation:2]
            'ublock_redirect': r'redirect(?:-rule)?=[\w-]+',  # uBO特有[citation:2]
            'adguard_script': r'^\$\$[\w#.-]+',  # AdGuard脚本规则[citation:2]
            'ublock_js': r'^\+js\([^)]+\)',  # uBO动态规则[citation:2]
        },
        
        # 白名单规则
        'whitelist': {
            'domain': r'^@@\|\|[\w*.-]+\^',
            'element': r'^@@##[^#\s]',
            'regex': r'^@@/[^/]+/',
            'modifiers': r'^@@\|\|[\w*.-]+\^\$[\w-]+',
            'document': r'^@@\|\|[\w*.-]+\^\$document',
        },
        
        # 特殊规则（各拦截器特有）
        'special': {
            'ublock': r'^\|\|[\w.-]+\^\$.*,~?\w+',
            'abp': r'^\|\|[\w.-]+\^\$~?\w+(?:,~?[\w]+)*',
            'adguard': r'^\|\|[\w.-]+\^\$(?:[\w-]+=[\w.-]+|ctag|dnstype)',
            'pihole': r'^(?:[\w*.-]+\s)?[\d.]+[\w*.-]+',
            'brave': r'^\|\|[\w.-]+\^\$\$',
            'vannila': r'^\|\|[\w.-]+\^\$all',
        }
    }

    @classmethod
    def compile_patterns(cls) -> Tuple[Pattern, Pattern]:
        """编译完整的正则表达式模式（增强版）"""
        try:
            # 黑名单模式（包含所有拦截器特有规则）
            block_parts = [
                cls.BASE_PATTERNS['domain'],
                cls.BASE_PATTERNS['domain_suffix'],
                cls.BASE_PATTERNS['exact_domain'],
                cls.BASE_PATTERNS['regex_domain'],
                cls.BASE_PATTERNS['element_hiding'],
                cls.BASE_PATTERNS['extended_css'],
                cls.BASE_PATTERNS['exception_hiding'],
                cls.BASE_PATTERNS['hosts'],
                cls.BASE_PATTERNS['regex'],
                cls.BASE_PATTERNS['pihole'],  # 添加Pi-hole支持[citation:4]
                rf'^\|\|[\w.-]+\^{cls.BASE_PATTERNS["modifiers"]["basic"]}',
                *[rf'^\|\|[\w.-]+\^\${mod}' 
                  for mod in cls.BASE_PATTERNS['modifiers'].values() 
                  if isinstance(mod, str)],
                *[rf'^\|\|[\w.-]+\^{pattern}' 
                  for pattern in cls.BASE_PATTERNS['special'].values()],
                # 添加拦截器特有规则
                cls.BASE_PATTERNS['modifiers']['adguard_script'],  # AdGuard $$规则[citation:2]
                cls.BASE_PATTERNS['modifiers']['ublock_js'],  # uBO +js()规则[citation:2]
            ]
            block_pattern = '|'.join(block_parts)

            # 白名单模式（增强版）
            allow_parts = [
                cls.BASE_PATTERNS['whitelist']['domain'],
                cls.BASE_PATTERNS['whitelist']['element'],
                cls.BASE_PATTERNS['whitelist']['regex'],
                cls.BASE_PATTERNS['whitelist']['modifiers'],
                cls.BASE_PATTERNS['whitelist']['document'],
                r'^@@\d+\.\d+\.\d+\.\d+',
                r'^@@\|\*\.',
                r'^@@[\w.-]+\^',
                rf'^@@\|\|[\w.-]+\^{cls.BASE_PATTERNS["modifiers"]["basic"]}',
                *[rf'^@@\|\|[\w.-]+\^\${mod}' 
                  for mod in cls.BASE_PATTERNS['modifiers'].values() 
                  if isinstance(mod, str)],
            ]
            allow_pattern = '|'.join(allow_parts)

            return re.compile(block_pattern), re.compile(allow_pattern)
        except re.error as e:
            raise ValueError(f"正则表达式编译错误: {e}") from e

class AdblockProcessor:
    """广告拦截规则处理器（增强版）"""

    def __init__(self):
        try:
            self.block_pattern, self.allow_pattern = RuleValidator.compile_patterns()
            self.seen_rules = set()  # 用于去重的规则集合
            self.domain_map = {}  # 域名到规则的映射（用于模糊去重）
        except ValueError as e:
            print(f"初始化失败: {e}")
            raise

    def normalize_rules(self, content: str) -> str:
        """高级规则标准化（增强版）"""
        def normalize_match(match: re.Match) -> str:
            text = match.group(0)

            # 统一域名格式
            if text.startswith(('||', '@@||', '|', '@@|')):
                text = text.lower()

            # 标准化修饰符
            if '$' in text:
                parts = text.split('$')
                domain = parts[0]
                modifiers = '$' + '$'.join(parts[1:]).lower()
                
                # 特殊处理修饰符
                modifiers = re.sub(
                    r'\$domain=([\w.-]+)',
                    lambda m: f'$domain={m.group(1).lower()}',
                    modifiers
                )
                # 处理拦截器特有修饰符
                if 'redirect-rule' in modifiers:
                    modifiers = modifiers.replace('redirect-rule', 'redirect')  # 统一uBO格式[citation:2]
                text = domain + modifiers
            
            # 补全Pi-hole规则格式[citation:4]
            if re.match(RuleValidator.BASE_PATTERNS['pihole'], text) and not text.startswith(('||', '|', '@@')):
                text = f'||{text}^'
            
            return text

        # 应用标准化
        content = re.sub(
            r'(?:\|\||@@\|\||\||@@\|)[\w*.-]+\^?(\$[^$]+)?|^[\w*.-]+$',
            normalize_match,
            content,
            flags=re.IGNORECASE | re.MULTILINE
        )

        # 标准化注释
        content = re.sub(
            r'^(!+\s*)(.*)',
            lambda m: m.group(1) + m.group(2).strip(),
            content,
            flags=re.MULTILINE
        )

        return content

    def clean_rules(self, content: str, pattern: Pattern) -> str:
        """智能规则清理（增强版）"""
        lines = []
        for line in content.splitlines():
            line = line.strip()
            if not line:
                continue

            # 保留注释和空行
            if line.startswith('!'):
                lines.append(line)
                continue

            # 处理badfilter规则优先[citation:6]
            if '$badfilter' in line:
                lines.insert(0, line)  # 将badfilter规则置顶
                continue

            # 验证规则
            if not pattern.search(line):
                fixed = self.fix_rule(line)
                if fixed and pattern.search(fixed):
                    line = fixed
                else:
                    continue

            # 域名模糊去重[citation:6][citation:7]
            domain = self.extract_domain(line)
            if domain and domain in self.domain_map:
                existing_rule = self.domain_map[domain]
                if self.is_superior_rule(line, existing_rule):
                    self.domain_map[domain] = line
                    # 替换旧规则
                    if existing_rule in lines:
                        lines[lines.index(existing_rule)] = line
                continue
            
            # 精确去重
            rule_hash = hashlib.md5(line.encode()).hexdigest()
            if rule_hash not in self.seen_rules:
                self.seen_rules.add(rule_hash)
                if domain:
                    self.domain_map[domain] = line
                lines.append(line)

        return '\n'.join(lines)

    def extract_domain(self, rule: str) -> Optional[str]:
        """从规则中提取基础域名（用于模糊去重）"""
        if rule.startswith('||'):
            return rule.split('^')[0].lower()
        elif rule.startswith('@@||'):
            return rule.split('^')[0][2:].lower()
        elif re.match(r'^\d+\.\d+\.\d+\.\d+', rule):  # Hosts规则
            return rule.split()[-1].lower()
        return None

    def is_superior_rule(self, new_rule: str, existing_rule: str) -> bool:
        """判断新规则是否比现有规则更优（用于模糊去重）"""
        # 优先保留带修饰符的规则
        if '$' in new_rule and '$' not in existing_rule:
            return True
        # 优先保留更具体的规则
        if 'specific' in new_rule.lower() and 'specific' not in existing_rule.lower():
            return True
        # 优先保留白名单规则
        if new_rule.startswith('@@') and not existing_rule.startswith('@@'):
            return True
        return False

    def fix_rule(self, line: str) -> Optional[str]:
        """自动修复常见规则问题（增强版）"""
        # 修复域名规则
        if line.startswith('||') and not line.endswith('^') and '$' not in line:
            return line + '^'
        
        # 修复白名单规则
        if line.startswith('@@||') and '$' not in line:
            return line + '$document'  # 补全通用白名单格式[citation:6]

        # 修复元素规则
        if line.startswith(('##', '#@#')) and ' ' in line:
            return line.split(' ')[0]

        # 修复修饰符
        if '$' in line:
            parts = line.split('$')
            domain = parts[0]
            mod = '$' + '$'.join(parts[1:])

            # 检查已知修饰符
            for mod_type in RuleValidator.BASE_PATTERNS['modifiers'].values():
                if isinstance(mod_type, str) and re.search(rf'\${mod_type}', mod):
                    return domain + mod.lower()

        # 转换Pi-hole规则[citation:4]
        if re.match(RuleValidator.BASE_PATTERNS['pihole'], line):
            return f'||{line}^'

        return None

    def process_files(self):
        """处理规则文件（增强版）"""
        print("合并拦截规则...")
        with open('combined_adblock.txt', 'w', encoding='utf-8') as out:
            for file in glob.glob('adblock*.txt'):
                with open(file, 'r', encoding='utf-8', errors='ignore') as f:
                    content = self.normalize_rules(f.read())
                    out.write(content + '\n')

        print("处理黑名单规则...")
        with open('combined_adblock.txt', 'r', encoding='utf-8') as f:
            content = f.read()
            # 提取白名单规则
            allow_rules = '\n'.join(
                line for line in content.splitlines() 
                if line.startswith('@@') and self.allow_pattern.search(line)
            )
            # 处理黑名单规则（并行处理提高性能）
            with ThreadPoolExecutor() as executor:
                chunks = self.split_content(content, 10000)  # 分块处理
                block_results = list(executor.map(
                    lambda c: self.clean_rules(c, self.block_pattern),
                    chunks
                ))
            block_rules = '\n'.join(block_results)

        with open('cleaned_adblock.txt', 'w', encoding='utf-8') as f:
            f.write(block_rules)

        print("合并白名单规则...")
        with open('combined_allow.txt', 'w', encoding='utf-8') as out:
            for file in glob.glob('allow*.txt'):
                with open(file, 'r', encoding='utf-8', errors='ignore') as f:
                    out.write(self.normalize_rules(f.read()) + '\n')

        print("处理白名单规则...")
        with open('combined_allow.txt', 'r', encoding='utf-8') as f:
            content = f.read() + '\n' + allow_rules
            allow_rules = self.clean_rules(content, self.allow_pattern)

        with open('allow.txt', 'w', encoding='utf-8') as f:
            f.write(allow_rules)

        print("检测规则冲突...")
        self.detect_conflicts(block_rules, allow_rules)

        print("生成最终规则集...")
        with open('cleaned_adblock.txt', 'a', encoding='utf-8') as f:
            f.write('\n' + allow_rules)

        # 移动文件
        Path('cleaned_adblock.txt').rename(TARGET_DIR / 'adblock.txt')
        Path('allow.txt').rename(TARGET_DIR / 'allow.txt')

        print("规则去重处理...")
        self.deduplicate_files()

        print("验证规则有效性...")
        self.validate_files()

        print("处理完成！生成文件：")
        print(f"- {TARGET_DIR / 'adblock.txt'}")
        print(f"- {TARGET_DIR / 'allow.txt'}")

    def split_content(self, content: str, chunk_size: int) -> List[str]:
        """将内容分割为多个块用于并行处理"""
        lines = content.splitlines()
        return ['\n'.join(lines[i:i+chunk_size]) for i in range(0, len(lines), chunk_size)]

    def detect_conflicts(self, block_rules: str, allow_rules: str):
        """检测黑白名单规则冲突[citation:8]"""
        black_domains = set(re.findall(r'\|\|([\w.-]+)\^', block_rules))
        white_domains = set(re.findall(r'@@\|\|([\w.-]+)\^', allow_rules))
        conflicts = black_domains & white_domains
        
        if conflicts:
            print(f"警告：发现{len(conflicts)}个冲突域名（同时在黑名单和白名单中）")
            for domain in sorted(conflicts)[:10]:  # 只显示前10个冲突
                print(f"- {domain}")
            if len(conflicts) > 10:
                print(f"- ...共{len(conflicts)}个冲突（仅显示前10个）")

    def deduplicate_files(self):
        """文件去重（增强版）"""
        for file in [TARGET_DIR / 'adblock.txt', TARGET_DIR / 'allow.txt']:
            if file.exists():
                with open(file, 'r+', encoding='utf-8') as f:
                    seen = set()
                    unique = []
                    for line in f:
                        norm = line.lower().strip() if not line.startswith('!') else line
                        if norm not in seen:
                            seen.add(norm)
                            unique.append(line)
                    f.seek(0)
                    f.writelines(unique)
                    f.truncate()

    def validate_files(self):
        """规则验证（增强版）"""
        for file in [TARGET_DIR / 'adblock.txt', TARGET_DIR / 'allow.txt']:
            with open(file, 'r', encoding='utf-8') as f:
                for i, line in enumerate(f, 1):
                    line = line.strip()
                    if not line or line.startswith('!'):
                        continue

                    is_allow = file.name == 'allow.txt'
                    pattern = self.allow_pattern if is_allow else self.block_pattern

                    if not pattern.search(line):
                        err_type = "白名单" if is_allow else "黑名单"
                        print(f"警告：{err_type}规则第{i}行可能无效 - {line[:50]}...")

if __name__ == '__main__':
    try:
        processor = AdblockProcessor()
        processor.process_files()
    except Exception as e:
        print(f"处理失败: {e}")
        exit(1)