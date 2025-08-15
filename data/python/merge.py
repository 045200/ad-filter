import os
import glob
import re
from pathlib import Path
from typing import List, Set, Pattern, Tuple, Optional, Dict, Any
from concurrent.futures import ThreadPoolExecutor, as_completed
import hashlib
from dataclasses import dataclass

# 全局配置
WORKING_DIR = Path('tmp')
TARGET_DIR = Path('../')
WORKING_DIR.mkdir(exist_ok=True)
TARGET_DIR.mkdir(exist_ok=True)

@dataclass
class ProcessingConfig:
    """处理配置参数"""
    chunk_size: int = 10000
    max_workers: int = 4
    show_conflicts: int = 10
    keep_whitelist_in_blacklist: bool = True

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
        'pihole': r'^[\w*.-]+$',  # Pi-hole纯域名规则

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
            'adguard_ctag': r'ctag=\w+',  # AdGuard特有
            'ublock_redirect': r'redirect(?:-rule)?=[\w-]+',  # uBO特有
            'adguard_script': r'^\$\$[\w#.-]+',  # AdGuard脚本规则
            'ublock_js': r'^\+js\([^)]+\)',  # uBO动态规则
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
            cls.BASE_PATTERNS['pihole'],
            rf'^\|\|[\w.-]+\^{cls.BASE_PATTERNS["modifiers"]["basic"]}',
            *[rf'^\|\|[\w.-]+\^\${mod}' 
              for mod in cls.BASE_PATTERNS['modifiers'].values() 
              if isinstance(mod, str)],
            *[rf'^\|\|[\w.-]+\^{pattern}' 
              for pattern in cls.BASE_PATTERNS['special'].values()],
            cls.BASE_PATTERNS['modifiers']['adguard_script'],
            cls.BASE_PATTERNS['modifiers']['ublock_js'],
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

class AdblockProcessor:
    """广告拦截规则处理器（增强版）"""

    def __init__(self, config: ProcessingConfig = ProcessingConfig()):
        self.config = config
        self.block_pattern, self.allow_pattern = RuleValidator.compile_patterns()
        self.seen_rules = set()  # 用于去重的规则集合
        self.domain_map = {}  # 域名到规则的映射（用于模糊去重）
        print("AdblockProcessor初始化成功")

    def _check_input_files(self) -> bool:
        """检查输入文件是否存在"""
        adblock_files = list(WORKING_DIR.glob('adblock*.txt'))
        allow_files = list(WORKING_DIR.glob('allow*.txt'))

        if not adblock_files:
            print("未找到任何adblock*.txt文件")
            return False

        print(f"找到{len(adblock_files)}个黑名单文件，{len(allow_files)}个白名单文件")
        return True

    def normalize_rule(self, rule: str) -> str:
        """标准化单个规则"""
        if not rule.strip() or rule.startswith('!'):
            return rule

        # 统一域名格式
        if rule.startswith(('||', '@@||', '|', '@@|')):
            rule = rule.lower()

        # 标准化修饰符
        if '$' in rule:
            parts = rule.split('$')
            domain = parts[0]
            modifiers = '$' + '$'.join(parts[1:]).lower()

            # 特殊处理修饰符
            modifiers = re.sub(
                r'\$domain=([\w.-]+)',
                lambda m: f'$domain={m.group(1).lower()}',
                modifiers
            )
            if 'redirect-rule' in modifiers:
                modifiers = modifiers.replace('redirect-rule', 'redirect')
            rule = domain + modifiers

        # 补全Pi-hole规则格式
        if re.match(RuleValidator.BASE_PATTERNS['pihole'], rule) and not rule.startswith(('||', '|', '@@')):
            rule = f'||{rule}^'

        return rule

    def normalize_rules(self, content: str) -> str:
        """高级规则标准化（增强版）"""
        normalized_lines = []
        for line in content.splitlines():
            # 标准化注释
            if line.startswith('!'):
                normalized = re.sub(
                    r'^(!+\s*)(.*)',
                    lambda m: m.group(1) + m.group(2).strip(),
                    line
                )
            else:
                normalized = self.normalize_rule(line)

            normalized_lines.append(normalized)

        return '\n'.join(normalized_lines)

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

            # 处理badfilter规则优先
            if '$badfilter' in line:
                lines.insert(0, line)
                continue

            # 验证规则
            if not pattern.search(line):
                fixed = self.fix_rule(line)
                if fixed and pattern.search(fixed):
                    line = fixed
                else:
                    continue

            # 域名模糊去重
            domain = self.extract_domain(line)
            if domain and domain in self.domain_map:
                existing_rule = self.domain_map[domain]
                if self.is_superior_rule(line, existing_rule):
                    self.domain_map[domain] = line
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
        """判断新规则是否比现有规则更优"""
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
        """自动修复常见规则问题"""
        # 修复域名规则
        if line.startswith('||') and not line.endswith('^') and '$' not in line:
            return line + '^'

        # 修复白名单规则
        if line.startswith('@@||') and '$' not in line:
            return line + '$document'

        # 修复元素规则
        if line.startswith(('##', '#@#')) and ' ' in line:
            return line.split(' ')[0]

        # 修复修饰符
        if '$' in line:
            parts = line.split('$')
            domain = parts[0]
            mod = '$' + '$'.join(parts[1:])

            for mod_type in RuleValidator.BASE_PATTERNS['modifiers'].values():
                if isinstance(mod_type, str) and re.search(rf'\${mod_type}', mod):
                    return domain + mod.lower()

        # 转换Pi-hole规则
        if re.match(RuleValidator.BASE_PATTERNS['pihole'], line):
            return f'||{line}^'

        return None

    def process_files(self):
        """处理规则文件主流程"""
        if not self._check_input_files():
            raise FileNotFoundError("缺少输入文件")

        # 合并拦截规则
        print("合并拦截规则...")
        with open(WORKING_DIR / 'combined_adblock.txt', 'w', encoding='utf-8') as out:
            for file in WORKING_DIR.glob('adblock*.txt'):
                with open(file, 'r', encoding='utf-8', errors='ignore') as f:
                    content = self.normalize_rules(f.read())
                    out.write(content + '\n')

        # 处理黑名单规则
        print("处理黑名单规则...")
        with open(WORKING_DIR / 'combined_adblock.txt', 'r', encoding='utf-8') as f:
            content = f.read()

            # 提取白名单规则
            allow_rules = []
            for line in content.splitlines():
                if line.startswith('@@') and self.allow_pattern.search(line):
                    allow_rules.append(line)

            # 处理黑名单规则（并行处理）
            block_results = []
            with ThreadPoolExecutor(max_workers=self.config.max_workers) as executor:
                futures = []
                for chunk in self.split_content(content, self.config.chunk_size):
                    futures.append(executor.submit(
                        self.clean_rules, 
                        chunk, 
                        self.block_pattern
                    ))

                for future in as_completed(futures):
                    block_results.append(future.result())

            block_rules = '\n'.join(block_results)

        # 写入黑名单文件（包含白名单规则）
        with open(WORKING_DIR / 'cleaned_adblock.txt', 'w', encoding='utf-8') as f:
            f.write(block_rules)
            if self.config.keep_whitelist_in_blacklist:
                f.write('\n' + '\n'.join(allow_rules))

        # 合并白名单规则
        print("合并白名单规则...")
        with open(WORKING_DIR / 'combined_allow.txt', 'w', encoding='utf-8') as out:
            for file in WORKING_DIR.glob('allow*.txt'):
                with open(file, 'r', encoding='utf-8', errors='ignore') as f:
                    out.write(self.normalize_rules(f.read()) + '\n')

        # 处理白名单规则
        print("处理白名单规则...")
        with open(WORKING_DIR / 'combined_allow.txt', 'r', encoding='utf-8') as f:
            content = f.read() + '\n' + '\n'.join(allow_rules)
            allow_rules = self.clean_rules(content, self.allow_pattern)

        with open(WORKING_DIR / 'allow.txt', 'w', encoding='utf-8') as f:
            f.write(allow_rules)

        # 检测冲突
        self.detect_conflicts(block_rules, allow_rules)

        # 生成最终文件
        print("生成最终规则集...")
        Path(WORKING_DIR / 'cleaned_adblock.txt').rename(TARGET_DIR / 'adblock.txt')
        Path(WORKING_DIR / 'allow.txt').rename(TARGET_DIR / 'allow.txt')

        # 文件去重
        self.deduplicate_files()

        print("处理完成！生成文件：")
        print(f"- {TARGET_DIR / 'adblock.txt'}")
        print(f"- {TARGET_DIR / 'allow.txt'}")

    def split_content(self, content: str, chunk_size: int) -> List[str]:
        """将内容分割为多个块用于并行处理"""
        lines = content.splitlines()
        return ['\n'.join(lines[i:i+chunk_size]) for i in range(0, len(lines), chunk_size)]

    def detect_conflicts(self, block_rules: str, allow_rules: str):
        """检测黑白名单规则冲突"""
        black_domains = set(re.findall(r'\|\|([\w.-]+)\^', block_rules))
        white_domains = set(re.findall(r'@@\|\|([\w.-]+)\^', allow_rules))
        conflicts = black_domains & white_domains

        if conflicts:
            print(f"发现{len(conflicts)}个冲突域名（同时在黑名单和白名单中）")
            for domain in sorted(conflicts)[:self.config.show_conflicts]:
                print(f"- {domain}")
            if len(conflicts) > self.config.show_conflicts:
                print(f"- ...共{len(conflicts)}个冲突（仅显示前{self.config.show_conflicts}个）")

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

if __name__ == '__main__':
    # 配置处理参数
    config = ProcessingConfig(
        chunk_size=10000,
        max_workers=4,
        show_conflicts=10,
        keep_whitelist_in_blacklist=True  # 确保白名单规则保留在黑名单中
    )

    # 切换到工作目录
    os.chdir(WORKING_DIR)

    processor = AdblockProcessor(config)
    processor.process_files()