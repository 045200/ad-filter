import re
from pathlib import Path
import logging

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('dns_filter.log', encoding='utf-8')
    ]
)
logger = logging.getLogger(__name__)

class AdGuardRuleValidator:
    """AdGuard Home规则验证器（支持所有官方语法）[citation:3][citation:8]"""
    
    @staticmethod
    def is_valid_rule(line):
        """
        验证规则是否符合AdGuard Home支持的完整语法：
        1. Adblock-style语法：||domain^、|https://、/regex/
        2. Hosts语法：0.0.0.0 domain
        3. 纯域名：domain.com
        4. 正则表达式：/^ads.*\.com$/
        5. 特殊修饰符规则：||domain^$dnstype=A
        """
        line = line.strip()
        
        # 跳过空行和注释[citation:3]
        if not line or line.startswith(('!', '#', '@@', '=====', '//')):
            return False
            
        # 匹配Adblock语法[citation:3][citation:8]
        if re.match(r'^(\|\|[\w.-]+\^|\|https?://|/{2}.*?/)', line):
            return True
            
        # 匹配带修饰符的规则[citation:3]
        if re.match(r'^[\w|*/].+\$[a-z]+(=.*)?(,.*)?$', line):
            return True
            
        # 匹配Hosts语法[citation:3][citation:4]
        if re.match(r'^(0\.0\.0\.0|127\.0\.0\.1)\s+[\w.-]+', line):
            return True
            
        # 匹配纯域名规则（需包含点且不含特殊字符）[citation:3]
        if re.match(r'^([\w-]+\.)+[\w-]+$', line):
            return True
            
        # 匹配正则表达式规则[citation:3]
        if re.match(r'^/.*/$', line):
            return True
            
        return False

    @staticmethod
    def normalize_rule(rule):
        """规则标准化处理（保留原始格式）"""
        return rule.strip()

def filter_dns_rules(input_path, output_path, keep_comments=False):
    """
    生成AdGuard Home兼容的DNS规则文件
    :param input_path: 输入文件路径
    :param output_path: 输出文件路径
    :param keep_comments: 是否保留关键注释（如! Title等）
    """
    input_path = Path(input_path)
    output_path = Path(output_path)

    if not input_path.exists():
        logger.error(f"输入文件不存在: {input_path}")
        raise FileNotFoundError(f"输入文件不存在: {input_path}")

    try:
        with input_path.open('r', encoding='utf-8', errors='replace') as infile, \
             output_path.open('w', encoding='utf-8', newline='\n') as outfile:

            rule_count = 0
            for line in infile:
                # 处理关键注释[citation:3]
                if keep_comments and line.strip().startswith(('! Title:', '! Version:')):
                    outfile.write(line)
                    continue
                    
                if AdGuardRuleValidator.is_valid_rule(line):
                    normalized = AdGuardRuleValidator.normalize_rule(line)
                    outfile.write(normalized + '\n')
                    rule_count += 1

            logger.info(f"已提取 {rule_count} 条有效规则 -> {output_path}")

    except IOError as e:
        logger.error(f"文件处理错误: {e}")
        raise

def main():
    # 文件路径配置
    base_dir = Path(__file__).parent.parent  # 指向项目根目录
    input_file = base_dir / "adblock.txt"    # 混合规则输入文件
    output_file = base_dir / "dns.txt"      # 规则输出文件
    
    # 确保输出目录存在
    output_file.parent.mkdir(parents=True, exist_ok=True)
    
    try:
        filter_dns_rules(
            input_file, 
            output_file,
            keep_comments=True  # 保留关键注释
        )
    except Exception as e:
        logger.error(f"处理失败: {e}")
        exit(1)

if __name__ == "__main__":
    main()