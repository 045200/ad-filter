import os
import re
from pathlib import Path
from typing import List, Set, Pattern, Tuple, Optional, Dict, Any
from concurrent.futures import ThreadPoolExecutor, as_completed
import hashlib
from dataclasses import dataclass
from urllib.parse import urlsplit
import logging
import ipaddress
import socket


# 全局配置
WORKING_DIR = Path('tmp')
TARGET_DIR = Path('/')
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
    validate_dns: bool = True  # 是否验证DNS规则

class RuleValidator:
    """广告拦截规则验证器（支持多源格式）"""

    BASE_PATTERNS = {
        # 基础规则模式 [AdBlock/uBO/AdGuard/ABP]
        'domain': r'^\|\|[\w*.-]+\^(?:\$[\w-]+(?:=[\w.-]*)?(?:,~?[\w-]+)*)?$',
        'domain_suffix': r'^\|\|\*\.?[\w*.-]+\^',
        'exact_domain': r'^\|https?://[\w*.-]+/',
        'regex_domain': r'^/@\|\|[\w*.-]+\^/',
        'abp_specific': r'^[\w*.-]+\#\#[^#]+',  # ABP特定规则

        # 元素规则 [uBO/AdGuard/ABP]
        'element_hiding': r'^##[^#\s\[].*',
        'extended_css': r'^#\?#[^#\s\[].*',
        'exception_hiding': r'^#@#.+',
        'ubo_procedural': r'^[\w.-]+##.+:has(?:-text)?\(.+\)',  # uBO过程式规则
        'ubo_scriptlet': r'^[\w.-]+##.*script:.*',  # uBO脚本规则

        # 网络规则 [通用]
        'regex': r'^/(?:[^/\\]|\\.)*/[gimsu]*$',
        'hosts': r'^\d+\.\d+\.\d+\.\d+\s+[\w*.-]+',  # Hosts格式
        'hosts_ipv6': r'^[0-9a-fA-F:]+(?:\s+[\w*.-]+)+',  # IPv6 Hosts格式

        # DNS规则 [AdGuard Home/AdGuard DNS]
        'dns_block': r'^\|\|[\w*.-]+\^\$dns',
        'dns_allow': r'^@@\|\|[\w*.-]+\^\$dns',
        'dns_rewrite': r'^\|\|[\w*.-]+\^\$dnsrewrite=',
        'dns_cname': r'^\|\|[\w*.-]+\^\$dnsrewrite=.*\.cname\.[^,]+,',

        # 修饰符（多拦截器支持）
        'modifiers': [
            r'document', r'script', r'image', r'stylesheet', 
            r'subdocument', r'xmlhttprequest', r'websocket',
            r'webrtc', r'font', r'media', r'other', 
            r'third-party', r'~third-party', r'popup',
            r'domain=[\w.-|]+', r'denyallow=[\w.|-]+',
            r'redirect=[\w-]+', r'removeparam=[^&]+',
            r'csp=[\w\s-]+', r'badfilter', r'important',
            r'generichide', r'specifichide', r'elemhide',
            r'dnsrewrite=\w+',  # AdGuard Home特有
            r'ctag=\w+',  # AdGuard特有
            r'cookie', r'network', r'stealth'  # 高级修饰符
        ],

        # 白名单规则 [通用]
        'whitelist': [
            r'^@@\|\|[\w*.-]+\^',
            r'^@@##[^#\s]',
            r'^@@\|\|[\w*.-]+\^\$document',
            r'^@@\|\|[\w*.-]+\^\$[\w-]+',
            r'^@@/[^/]+/',
            r'^@@\d+\.\d+\.\d+\.\d+',  # IP白名单
            r'^@@\|\|[\w*.-]+\^\$dns'  # DNS白名单
        ],

        # 特殊规则 [各拦截器特有]
        'special': {
            'ubo_js': r'^\+js\([^)]+\)',  # uBO动态规则
            'adguard_script': r'^\$\$[\w#.-]+',  # AdGuard脚本规则
            'ubo_css': r'^[\w.-]+##.+\{[^}]+\}',  # uBO CSS注入规则
            'abp_snippet': r'#\?#.*script:.*',  # ABP脚本片段
            'adguard_filter': r'^\#\#.+\{.*:\s*.*!important;\}',  # AdGuard过滤规则
            'adguard_hide': r'^\#\#.+\{display:\s*none!important;\}',  # AdGuard隐藏规则
            'ubo_static': r'^\|\|[\w.-]+\^\$.*,static'  # uBO静态规则
        }
    }

    @classmethod
    def compile_patterns(cls) -> Tuple[Pattern, Pattern]:
        """编译正则表达式模式（支持多源格式）"""
        # 黑名单模式（包含所有拦截器特有规则）
        block_parts = [
            cls.BASE_PATTERNS['domain'],
            cls.BASE_PATTERNS['domain_suffix'],
            cls.BASE_PATTERNS['exact_domain'],
            cls.BASE_PATTERNS['element_hiding'],
            cls.BASE_PATTERNS['extended_css'],
            cls.BASE_PATTERNS['regex'],
            cls.BASE_PATTERNS['hosts'],
            cls.BASE_PATTERNS['hosts_ipv6'],
            cls.BASE_PATTERNS['ubo_procedural'],
            cls.BASE_PATTERNS['ubo_scriptlet'],
            cls.BASE_PATTERNS['abp_specific'],
            cls.BASE_PATTERNS['dns_block'],
            cls.BASE_PATTERNS['dns_rewrite'],
            *[rf'^\|\|[\w.-]+\^\${mod}' for mod in cls.BASE_PATTERNS['modifiers']],
            *cls.BASE_PATTERNS['special'].values()
        ]
        block_pattern = '|'.join(block_parts)

        # 白名单模式
        allow_pattern = '|'.join(cls.BASE_PATTERNS['whitelist'])

        return re.compile(block_pattern), re.compile(allow_pattern)

class DNSValidator:
    """DNS规则验证器"""
    
    @staticmethod
    def is_valid_ip(ip_str: str) -> bool:
        """验证IP地址格式"""
        try:
            ipaddress.ip_address(ip_str)
            return True
        except ValueError:
            return False
    
    @staticmethod
    def is_valid_domain(domain: str) -> bool:
        """验证域名格式"""
        if not domain or len(domain) > 253:
            return False
        
        # 检查标签
        labels = domain.split('.')
        for label in labels:
            if not re.match(r'^[a-zA-Z0-9-]{1,63}$', label) or label.startswith('-') or label.endswith('-'):
                return False
        return True
    
    @staticmethod
    def validate_dns_rewrite(rule: str) -> bool:
        """验证DNS重写规则"""
        if '$dnsrewrite=' not in rule:
            return False
            
        try:
            parts = rule.split('$dnsrewrite=')[1].split(',')
            if len(parts) < 2:
                return False
                
            # 验证重写类型
            rewrite_type = parts[0].lower()
            if rewrite_type == 'a' or rewrite_type == 'aaaa':
                return DNSValidator.is_valid_ip(parts[1])
            elif rewrite_type == 'cname':
                return DNSValidator.is_valid_domain(parts[1].rstrip('.'))
            elif rewrite_type == 'mx':
                return len(parts) == 3 and DNSValidator.is_valid_domain(parts[2].rstrip('.'))
            elif rewrite_type == 'txt' or rewrite_type == 'ptr':
                return True  # 内容格式不限制
            else:
                return False
        except:
            return False

class AdblockProcessor:
    """广告拦截规则处理器（多源支持版）"""

    def __init__(self, config: ProcessingConfig = ProcessingConfig()):
        self.config = config
        self.block_pattern, self.allow_pattern = RuleValidator.compile_patterns()
        self.seen_rules = set()
        self.domain_map = {}
        self.logger = logging.getLogger(__name__)
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        self.logger.info("AdblockProcessor初始化完成")

    def _check_input_files(self) -> bool:
        """检查输入文件是否存在"""
        adblock_files = list(INPUT_DIR.glob('*block*.txt'))
        if not adblock_files:
            self.logger.error("未找到任何广告拦截规则文件")
            return False

        allow_files = list(INPUT_DIR.glob('allow*.txt'))
        self.logger.info(f"找到{len(adblock_files)}个拦截规则文件，{len(allow_files)}个白名单文件")
        return True

    def normalize_rule(self, rule: str) -> str:
        """标准化单个规则（多格式支持）"""
        rule = rule.strip()
        if not rule or rule.startswith(('!', '#')):
            return rule

        # 处理特殊规则优先
        if rule.startswith(('+js(', '$$', '#?#', '##^')):
            return rule  # uBO和AdGuard特殊规则不处理大小写

        # 统一域名格式
        if rule.startswith(('||', '@@||', '|http', '@@|http')):
            rule = rule.lower()

        # 标准化Hosts规则
        if re.match(r'^\d+\.\d+\.\d+\.\d+', rule) or re.match(r'^[0-9a-fA-F:]+', rule):
            parts = re.split(r'\s+', rule)
            if len(parts) >= 2:
                ip = parts[0].lower()
                domains = ' '.join([d.lower() for d in parts[1:]])
                return f"{ip} {domains}"

        # 标准化修饰符
        if '$' in rule and not rule.startswith(('+js(', '$$')):
            parts = rule.split('$', 1)
            domain = parts[0]
            modifiers = '$' + parts[1].lower()

            # 特殊处理DNS重写规则
            if 'dnsrewrite=' in modifiers and self.config.validate_dns:
                if not DNSValidator.validate_dns_rewrite(rule):
                    self.logger.warning(f"无效DNS重写规则: {rule}")
                    return ""

            # 标准化domain修饰符
            modifiers = re.sub(
                r'domain=([\w.-|]+)',
                lambda m: f'domain={m.group(1).lower()}',
                modifiers
            )

            # 标准化denyallow修饰符
            modifiers = re.sub(
                r'denyallow=([\w.|-]+)',
                lambda m: f'denyallow={m.group(1).lower()}',
                modifiers
            )

            rule = domain + modifiers

        return rule

    def normalize_rules(self, content: str) -> str:
        """规则标准化（批量处理）"""
        normalized = []
        for line in content.splitlines():
            try:
                norm_line = self.normalize_rule(line)
                if norm_line:  # 跳过空行（如无效DNS规则）
                    normalized.append(norm_line)
            except Exception as e:
                self.logger.warning(f"规则标准化失败: {line[:50]}... 错误: {str(e)}")
                normalized.append(line)  # 保留原始规则

        return '\n'.join(normalized)

    def clean_rules(self, content: str, pattern: Pattern) -> str:
        """智能规则清理（多格式支持）"""
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

            # 域名模糊去重
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
        return hashlib.sha256(rule.encode()).hexdigest()

    def extract_domain(self, rule: str) -> Optional[str]:
        """从规则中提取基础域名（增强多格式支持）"""
        # 标准域名规则
        if rule.startswith('||'):
            return rule.split('^')[0].lower()
        elif rule.startswith('@@||'):
            return rule.split('^')[0][2:].lower()
        elif rule.startswith(('|http', '@@|http')):
            try:
                return urlsplit(rule.split('|')[1]).netloc.lower()
            except:
                return None
        # Hosts规则
        elif re.match(r'^\d+\.\d+\.\d+\.\d+', rule) or re.match(r'^[0-9a-fA-F:]+', rule):
            parts = re.split(r'\s+', rule)
            return parts[-1].lower() if len(parts) > 1 else None
        # ABP特定规则
        elif '##' in rule and not rule.startswith(('##', '#@#')):
            return rule.split('##')[0].lower()
        # DNS规则
        elif '$dns' in rule.lower():
            domain_part = rule.split('^')[0]
            if domain_part.startswith('||'):
                return domain_part[2:].lower()
        return None

    def extract_modifiers(self, rule: str) -> Set[str]:
        """提取规则修饰符（多格式支持）"""
        if '$' not in rule:
            return set()

        modifiers = rule.split('$')[1].split(',')[0]  # 只取第一个修饰符组
        return {m.split('=')[0] for m in modifiers.split(',')}

    def is_superior_rule(self, new_rule: str, existing_rule: str) -> bool:
        """判断新规则是否比现有规则更优（多格式支持）"""
        # 优先保留带重要修饰符的规则
        important_modifiers = {'important', 'badfilter', 'csp', 'stealth'}
        new_mods = self.extract_modifiers(new_rule)
        existing_mods = self.extract_modifiers(existing_rule)

        if new_mods & important_modifiers and not (existing_mods & important_modifiers):
            return True

        # 优先保留更具体的修饰符
        if len(new_mods) > len(existing_mods):
            return True

        # 优先保留DNS规则
        if '$dns' in new_rule.lower() and '$dns' not in existing_rule.lower():
            return True

        # 优先保留白名单规则
        if new_rule.startswith('@@') and not existing_rule.startswith('@@'):
            return True

        # 优先保留更具体的规则
        if len(new_rule) > len(existing_rule):
            return True

        return False

    def process_files(self):
        """处理规则文件主流程（增强版）"""
        if not self._check_input_files():
            return

        try:
            # 合并拦截规则
            self.logger.info("开始合并拦截规则...")
            combined_block = WORKING_DIR / 'combined_adblock.txt'
            with open(combined_block, 'w', encoding='utf-8') as out:
                for file in INPUT_DIR.glob('*block*.txt'):
                    self.logger.info(f"处理文件: {file.name}")
                    with open(file, 'r', encoding='utf-8', errors='ignore') as f:
                        if self.config.ci_mode:
                            # CI环境下分块读取
                            while chunk := f.read(1024*1024):  # 1MB chunks
                                normalized = self.normalize_rules(chunk)
                                if normalized:
                                    out.write(normalized + '\n')
                        else:
                            content = f.read()
                            normalized = self.normalize_rules(content)
                            if normalized:
                                out.write(normalized + '\n')

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
                            result = future.result()
                            if result:
                                block_results.append(result)
                        except Exception as e:
                            self.logger.error(f"处理块时出错: {str(e)}")

                block_rules = '\n'.join(block_results)

            # 写入黑名单文件
            cleaned_block = WORKING_DIR / 'cleaned_adblock.txt'
            with open(cleaned_block, 'w', encoding='utf-8') as f:
                f.write(block_rules)
                if self.config.keep_whitelist_in_blacklist and allow_rules:
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
                                normalized = self.normalize_rules(chunk)
                                if normalized:
                                    out.write(normalized + '\n')
                        else:
                            content = f.read()
                            normalized = self.normalize_rules(content)
                            if normalized:
                                out.write(normalized + '\n')

            # 处理白名单规则
            self.logger.info("开始处理白名单规则...")
            with open(combined_allow, 'r', encoding='utf-8') as f:
                content = f.read()
                if allow_rules:
                    content += '\n' + '\n'.join(allow_rules)
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

            # 输出统计信息
            self.log_stats(block_rules, allow_rules)

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
        """检测黑白名单规则冲突（增强版）"""
        # 检测标准域名冲突
        black_domains = set(re.findall(r'\|\|([\w.-]+)\^', block_rules))
        white_domains = set(re.findall(r'@@\|\|([\w.-]+)\^', allow_rules))
        conflicts = black_domains & white_domains

        if conflicts:
            self.logger.warning(f"发现{len(conflicts)}个标准域名冲突")
            for domain in sorted(conflicts)[:self.config.show_conflicts]:
                self.logger.warning(f"- {domain}")
            if len(conflicts) > self.config.show_conflicts:
                self.logger.warning(f"- ...共{len(conflicts)}个冲突（仅显示前{self.config.show_conflicts}个）")

        # 检测DNS规则冲突
        dns_block = set(re.findall(r'\|\|([\w.-]+)\^\$dns', block_rules))
        dns_allow = set(re.findall(r'@@\|\|([\w.-]+)\^\$dns', allow_rules))
        dns_conflicts = dns_block & dns_allow

        if dns_conflicts:
            self.logger.warning(f"发现{len(dns_conflicts)}个DNS规则冲突")
            for domain in sorted(dns_conflicts)[:self.config.show_conflicts]:
                self.logger.warning(f"- {domain}")

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

    def log_stats(self, block_rules: str, allow_rules: str):
        """输出规则统计信息"""
        # 黑名单统计
        block_lines = block_rules.splitlines()
        total_block = len(block_lines)
        domain_block = sum(1 for line in block_lines if line.startswith('||'))
        element_block = sum(1 for line in block_lines if line.startswith('##'))
        dns_block = sum(1 for line in block_lines if '$dns' in line.lower())
        regex_block = sum(1 for line in block_lines if line.startswith('/') and line.endswith('/'))

        # 白名单统计
        allow_lines = allow_rules.splitlines()
        total_allow = len(allow_lines)
        domain_allow = sum(1 for line in allow_lines if line.startswith('@@||'))
        element_allow = sum(1 for line in allow_lines if line.startswith('@@##'))
        dns_allow = sum(1 for line in allow_lines if '$dns' in line.lower())

        self.logger.info("\n规则统计:")
        self.logger.info(f"黑名单总数: {total_block}")
        self.logger.info(f"  ├─ 域名规则: {domain_block}")
        self.logger.info(f"  ├─ 元素规则: {element_block}")
        self.logger.info(f"  ├─ DNS规则: {dns_block}")
        self.logger.info(f"  └─ 正则规则: {regex_block}")
        
        self.logger.info(f"白名单总数: {total_allow}")
        self.logger.info(f"  ├─ 域名规则: {domain_allow}")
        self.logger.info(f"  ├─ 元素规则: {element_allow}")
        self.logger.info(f"  └─ DNS规则: {dns_allow}")

if __name__ == '__main__':
    # 配置处理参数
    config = ProcessingConfig(
        chunk_size=10000,
        max_workers=2 if os.getenv('CI') else 4,
        show_conflicts=10,
        keep_whitelist_in_blacklist=True,
        validate_dns=True
    )

    # 初始化处理器
    processor = AdblockProcessor(config)
    
    # 处理文件
    try:
        processor.process_files()
    except Exception as e:
        processor.logger.error(f"处理失败: {str(e)}")
        exit(1)