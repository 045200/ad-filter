import os
import re
from pathlib import Path
from typing import List, Set, Pattern, Tuple, Optional, Dict, Any
from concurrent.futures import ThreadPoolExecutor, as_completed
import hashlib
from dataclasses import dataclass
from urllib.parse import urlsplit
import logging

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('adblock_processor.log')
    ]
)

# 全局配置
WORKING_DIR = Path('tmp')
TARGET_DIR = Path('.')
INPUT_DIR = Path('tmp')
WORKING_DIR.mkdir(exist_ok=True)
TARGET_DIR.mkdir(exist_ok=True)

@dataclass
class ProcessingConfig:
    """处理配置参数"""
    chunk_size: int = 10000
    max_workers: int = 4
    show_conflicts: int = 10
    keep_whitelist_in_blacklist: bool = True
    ci_mode: bool = os.getenv('GITHUB_ACTIONS') == 'true'

class RuleValidator:
    """广告拦截规则验证器（支持ABP/AdGuard/uBO）"""

    BASE_PATTERNS = {
        # 基础规则模式 [citation:1][citation:4][citation:5]
        'domain': r'^\|\|[\w*.-]+\^(?:\$[\w-]+(?:=[\w.-]*)?(?:,~?[\w-]+)*)?$',
        'domain_suffix': r'^\|\|\*\.?[\w*.-]+\^',
        'exact_domain': r'^\|https?://[\w*.-]+/',
        'regex_domain': r'^/@\|\|[\w*.-]+\^/',
        
        # 元素规则 [citation:3][citation:4][citation:7]
        'element_hiding': r'^##[^#\s\[].*',
        'extended_css': r'^#\?#[^#\s\[].*',
        'exception_hiding': r'^#@#.+',
        'ubo_procedural': r'^[\w.-]+##.+:has(?:-text)?\(.+\)',  # uBO过程式规则
        
        # 网络规则 [citation:1][citation:5]
        'regex': r'^/(?:[^/\\]|\\.)*/[gimsu]*$',
        'hosts': r'^\d+\.\d+\.\d+\.\d+\s+[\w*.-]+',  # AdGuard Home支持[citation:2][citation:5]
        
        # 修饰符（三大拦截器共同支持）[citation:1][citation:4][citation:5]
        'modifiers': [
            r'document', r'script', r'image', r'stylesheet', 
            r'subdocument', r'xmlhttprequest', r'websocket',
            r'webrtc', r'font', r'media', r'other', 
            r'third-party', r'~third-party', r'popup',
            r'domain=[\w.-]+', r'denyallow=[\w.|-]+',
            r'redirect=[\w-]+', r'removeparam=[^&]+',
            r'csp=[\w\s-]+', r'badfilter', r'important',
            r'generichide', r'specifichide', r'elemhide',
            r'dnsrewrite=\w+',  # AdGuard Home特有[citation:5]
            r'ctag=\w+'  # AdGuard特有[citation:8]
        ],
        
        # 白名单规则 [citation:1][citation:5]
        'whitelist': [
            r'^@@\|\|[\w*.-]+\^',
            r'^@@##[^#\s]',
            r'^@@\|\|[\w*.-]+\^\$document',
            r'^@@\|\|[\w*.-]+\^\$[\w-]+',
            r'^@@/[^/]+/',
            r'^@@\d+\.\d+\.\d+\.\d+'  # AdGuard Home IP白名单[citation:2]
        ],
        
        # 特殊规则 [citation:3][citation:7]
        'special': {
            'ubo_js': r'^\+js\([^)]+\)',  # uBO动态规则
            'adguard_script': r'^\$\$[\w#.-]+',  # AdGuard脚本规则
            'ubo_css': r'^[\w.-]+##.+\{[^}]+\}'  # uBO CSS注入规则
        }
    }

    @classmethod
    def compile_patterns(cls) -> Tuple[Pattern, Pattern]:
        """编译正则表达式模式"""
        # 黑名单模式（包含所有拦截器特有规则）
        block_parts = [
            cls.BASE_PATTERNS['domain'],
            cls.BASE_PATTERNS['domain_suffix'],
            cls.BASE_PATTERNS['exact_domain'],
            cls.BASE_PATTERNS['element_hiding'],
            cls.BASE_PATTERNS['extended_css'],
            cls.BASE_PATTERNS['regex'],
            cls.BASE_PATTERNS['hosts'],
            cls.BASE_PATTERNS['ubo_procedural'],
            *[rf'^\|\|[\w.-]+\^\${mod}' for mod in cls.BASE_PATTERNS['modifiers']],
            cls.BASE_PATTERNS['special']['ubo_js'],
            cls.BASE_PATTERNS['special']['adguard_script'],
            cls.BASE_PATTERNS['special']['ubo_css']
        ]
        block_pattern = '|'.join(block_parts)

        # 白名单模式
        allow_pattern = '|'.join(cls.BASE_PATTERNS['whitelist'])

        return re.compile(block_pattern), re.compile(allow_pattern)

class AdblockProcessor:
    """广告拦截规则处理器（增强版）"""

    def __init__(self, config: ProcessingConfig = ProcessingConfig()):
        self.config = config
        self.block_pattern, self.allow_pattern = RuleValidator.compile_patterns()
        self.seen_rules = set()
        self.domain_map = {}
        self.logger = logging.getLogger(__name__)
        self.logger.info("AdblockProcessor初始化完成")

    def _check_input_files(self) -> bool:
        """检查输入文件是否存在"""
        adblock_files = list(INPUT_DIR.glob('adblock*.txt'))
        if not adblock_files:
            self.logger.error("未找到任何adblock*.txt文件")
            return False
        
        allow_files = list(INPUT_DIR.glob('allow*.txt'))
        self.logger.info(f"找到{len(adblock_files)}个黑名单文件，{len(allow_files)}个白名单文件")
        return True

    def normalize_rule(self, rule: str) -> str:
        """标准化单个规则"""
        rule = rule.strip()
        if not rule or rule.startswith(('!', '#')):
            return rule

        # 处理特殊规则优先
        if rule.startswith(('+js(', '$$')):
            return rule  # uBO和AdGuard特殊规则不处理大小写

        # 统一域名格式 [citation:1][citation:4]
        if rule.startswith(('||', '@@||', '|http', '@@|http')):
            rule = rule.lower()

        # 标准化修饰符 [citation:1][citation:7]
        if '$' in rule and not rule.startswith(('+js(', '$$')):
            parts = rule.split('$', 1)
            domain = parts[0]
            modifiers = '$' + parts[1].lower()
            
            # 特殊处理AdGuard Home的DNS重写规则 [citation:5]
            if 'dnsrewrite=' in modifiers:
                modifiers = re.sub(
                    r'dnsrewrite=([^,]+)',
                    lambda m: f'dnsrewrite={m.group(1).lower()}',
                    modifiers
                )
            
            # 标准化domain修饰符 [citation:4]
            modifiers = re.sub(
                r'domain=([\w.-]+)',
                lambda m: f'domain={m.group(1).lower()}',
                modifiers
            )
            
            rule = domain + modifiers

        return rule

    def normalize_rules(self, content: str) -> str:
        """规则标准化"""
        normalized = []
        for line in content.splitlines():
            try:
                normalized.append(self.normalize_rule(line))
            except Exception as e:
                self.logger.warning(f"规则标准化失败: {line[:50]}... 错误: {str(e)}")
                normalized.append(line)  # 保留原始规则
        
        return '\n'.join(normalized)

    def clean_rules(self, content: str, pattern: Pattern) -> str:
        """智能规则清理"""
        lines = []
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith(('!', '#')):
                lines.append(line)
                continue

            # 跳过无效规则
            if not pattern.search(line):
                self.logger.debug(f"跳过无效规则: {line[:50]}...")
                continue

            # 提取关键信息用于去重
            domain = self.extract_domain(line)
            modifiers = self.extract_modifiers(line)
            
            # 域名模糊去重 [citation:1][citation:4]
            if domain and domain in self.domain_map:
                existing_rule = self.domain_map[domain]
                if self.is_superior_rule(line, existing_rule):
                    self.domain_map[domain] = line
                    if existing_rule in lines:
                        lines[lines.index(existing_rule)] = line
                    continue

            # 精确去重
            rule_hash = self._generate_rule_hash(line)
            if rule_hash not in self.seen_rules:
                self.seen_rules.add(rule_hash)
                if domain:
                    self.domain_map[domain] = line
                lines.append(line)

        return '\n'.join(lines)

    def _generate_rule_hash(self, rule: str) -> str:
        """生成规则哈希（优化CI环境性能）"""
        if self.config.ci_mode:
            # CI环境下使用更快的哈希算法
            return str(hash(rule))
        return hashlib.md5(rule.encode()).hexdigest()

    def extract_domain(self, rule: str) -> Optional[str]:
        """从规则中提取基础域名（增强版）[citation:1][citation:4][citation:5]"""
        if rule.startswith('||'):
            return rule.split('^')[0].lower()
        elif rule.startswith('@@||'):
            return rule.split('^')[0][2:].lower()
        elif rule.startswith(('|http', '@@|http')):
            try:
                return urlsplit(rule.split('|')[1]).netloc.lower()
            except:
                return None
        elif re.match(r'^\d+\.\d+\.\d+\.\d+', rule):  # Hosts规则
            return rule.split()[-1].lower()
        return None

    def extract_modifiers(self, rule: str) -> Set[str]:
        """提取规则修饰符"""
        if '$' not in rule:
            return set()
        
        modifiers = rule.split('$')[1]
        return {m.split('=')[0] for m in modifiers.split(',')}

    def is_superior_rule(self, new_rule: str, existing_rule: str) -> bool:
        """判断新规则是否比现有规则更优 [citation:1][citation:4][citation:7]"""
        # 优先保留带重要修饰符的规则
        important_modifiers = {'important', 'badfilter', 'csp'}
        new_mods = self.extract_modifiers(new_rule)
        existing_mods = self.extract_modifiers(existing_rule)
        
        if new_mods & important_modifiers and not (existing_mods & important_modifiers):
            return True
            
        # 优先保留更具体的修饰符
        if len(new_mods) > len(existing_mods):
            return True
            
        # 优先保留白名单规则
        if new_rule.startswith('@@') and not existing_rule.startswith('@@'):
            return True
            
        return False

    def process_files(self):
        """处理规则文件主流程"""
        if not self._check_input_files():
            return

        try:
            # 合并拦截规则
            self.logger.info("开始合并拦截规则...")
            combined_block = WORKING_DIR / 'combined_adblock.txt'
            with open(combined_block, 'w', encoding='utf-8') as out:
                for file in INPUT_DIR.glob('adblock*.txt'):
                    self.logger.info(f"处理文件: {file.name}")
                    with open(file, 'r', encoding='utf-8', errors='ignore') as f:
                        if self.config.ci_mode:
                            # CI环境下分块读取
                            while chunk := f.read(1024*1024):  # 1MB chunks
                                out.write(self.normalize_rules(chunk) + '\n')
                        else:
                            out.write(self.normalize_rules(f.read()) + '\n')

            # 处理黑名单规则
            self.logger.info("开始处理黑名单规则...")
            with open(combined_block, 'r', encoding='utf-8') as f:
                content = f.read()
                
                # 提取白名单规则
                allow_rules = [line for line in content.splitlines() 
                             if line.startswith('@@') and self.allow_pattern.search(line)]

                # 并行处理黑名单规则
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
                        try:
                            block_results.append(future.result())
                        except Exception as e:
                            self.logger.error(f"处理块时出错: {str(e)}")

                block_rules = '\n'.join(block_results)

            # 写入黑名单文件
            cleaned_block = WORKING_DIR / 'cleaned_adblock.txt'
            with open(cleaned_block, 'w', encoding='utf-8') as f:
                f.write(block_rules)
                if self.config.keep_whitelist_in_blacklist:
                    f.write('\n' + '\n'.join(allow_rules))

            # 合并白名单规则
            self.logger.info("开始合并白名单规则...")
            combined_allow = WORKING_DIR / 'combined_allow.txt'
            with open(combined_allow, 'w', encoding='utf-8') as out:
                for file in INPUT_DIR.glob('allow*.txt'):
                    self.logger.info(f"处理文件: {file.name}")
                    with open(file, 'r', encoding='utf-8', errors='ignore') as f:
                        if self.config.ci_mode:
                            while chunk := f.read(1024*1024):
                                out.write(self.normalize_rules(chunk) + '\n')
                        else:
                            out.write(self.normalize_rules(f.read()) + '\n')

            # 处理白名单规则
            self.logger.info("开始处理白名单规则...")
            with open(combined_allow, 'r', encoding='utf-8') as f:
                content = f.read() + '\n' + '\n'.join(allow_rules)
                allow_rules = self.clean_rules(content, self.allow_pattern)

            with open(WORKING_DIR / 'allow.txt', 'w', encoding='utf-8') as f:
                f.write(allow_rules)

            # 检测冲突
            self.detect_conflicts(block_rules, allow_rules)

            # 生成最终文件
            self.logger.info("生成最终规则集...")
            Path(cleaned_block).rename(TARGET_DIR / 'adblock.txt')
            Path(WORKING_DIR / 'allow.txt').rename(TARGET_DIR / 'allow.txt')

            # 文件去重
            self.deduplicate_files()

            self.logger.info("处理完成！生成文件：")
            self.logger.info(f"- {TARGET_DIR / 'adblock.txt'}")
            self.logger.info(f"- {TARGET_DIR / 'allow.txt'}")

        except Exception as e:
            self.logger.error(f"处理过程中发生错误: {str(e)}")
            if self.config.ci_mode:
                print(f"::error::处理失败: {str(e)}")
            raise

    def split_content(self, content: str, chunk_size: int) -> List[str]:
        """将内容分割为多个块用于并行处理"""
        lines = content.splitlines()
        return ['\n'.join(lines[i:i+chunk_size]) for i in range(0, len(lines), chunk_size)]

    def detect_conflicts(self, block_rules: str, allow_rules: str):
        """检测黑白名单规则冲突 [citation:1][citation:5]"""
        black_domains = set(re.findall(r'\|\|([\w.-]+)\^', block_rules))
        white_domains = set(re.findall(r'@@\|\|([\w.-]+)\^', allow_rules))
        conflicts = black_domains & white_domains

        if conflicts:
            self.logger.warning(f"发现{len(conflicts)}个冲突域名")
            for domain in sorted(conflicts)[:self.config.show_conflicts]:
                self.logger.warning(f"- {domain}")
            if len(conflicts) > self.config.show_conflicts:
                self.logger.warning(f"- ...共{len(conflicts)}个冲突（仅显示前{self.config.show_conflicts}个）")

    def deduplicate_files(self):
        """文件去重"""
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
        max_workers=2 if os.getenv('CI') else 4,
        show_conflicts=10,
        keep_whitelist_in_blacklist=True
    )

    processor = AdblockProcessor(config)
    processor.process_files()