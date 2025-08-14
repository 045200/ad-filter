import os
import glob
import re
from pathlib import Path
import logging

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('rule_processor.log', encoding='utf-8')
    ]
)
logger = logging.getLogger(__name__)

# 设置工作目录
os.chdir('tmp')

# AdGuard完整语法规则匹配模式（基于官方文档）
ADGUARD_RULE_PATTERN = re.compile(
    r'^(\|\|[\w.-]+(\^|\*)?(\$~?[\w,;=-]+)?)|'      # 域名规则
    r'(^##[^#\s]+)|'                               # 元素隐藏
    r'(^#@#[^#\s]+)|'                              # 例外元素隐藏
    r'(^\$\$[^#\s]+)|'                             # JS/CSS注入
    r'(^@@\|\|[\w.-]+(\^|\*)?(\$~?[\w,;=-]+)?)|'   # 域名白名单
    r'(^@@##[^#\s]+)|'                             # 元素隐藏例外
    r'(^@@\$\$[^#\s]+)|'                           # JS/CSS注入例外
    r'(^/[^/]+/\$~?[\w,=-]+)|'                     # 正则规则
    r'(^@@/[^/]+/\$~?[\w,=-]+)|'                   # 正则例外
    r'(^\|\|[\w.-]+\$[^$\s]+)|'                    # 带修饰符规则
    r'(^@@\|\|[\w.-]+\$[^$\s]+)|'                  # 带修饰符白名单
    r'(^\d+\.\d+\.\d+\.\d+\s+[\w.-]+)|'           # Hosts格式
    r'(^\d+\.\d+\.\d+\.\d+\/\d+\s+[\w.-]+)|'      # CIDR格式
    r'(^\|\|[\w.-]+\^\$document)|'                 # 文档级拦截
    r'(^@@\|\|[\w.-]+\^\$document)|'              # 文档级例外
    r'(^\|\|[\w.-]+\^\$popup)|'                    # 弹出窗口拦截
    r'(^\*[^$]+\$[^$]+)'                           # 通用规则
)

CRITICAL_DIRECTIVES = (
    '!#if', '!#endif', '!#include',  # 预处理指令
    '!+ ', '! ',                     # 可能包含重要配置
    '!CSP', '!header', '!redirect'   # 安全策略
)

def clean_rules(content):
    """严格清理规则，仅保留有效内容和关键指令"""
    lines = []
    for line in content.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
            
        # 保留关键指令
        if any(stripped.startswith(d) for d in CRITICAL_DIRECTIVES):
            lines.append(line)
        # 保留有效规则
        elif ADGUARD_RULE_PATTERN.search(line):
            lines.append(line)
    return '\n'.join(lines)

def extract_allow_rules(content):
    """精确提取白名单规则（含相关指令）"""
    allow_lines = []
    for line in content.splitlines():
        stripped = line.strip()
        if stripped.startswith('@@') and ADGUARD_RULE_PATTERN.search(line):
            allow_lines.append(line)
        elif any(stripped.startswith(d) for d in CRITICAL_DIRECTIVES):
            allow_lines.append(line)
    return '\n'.join(allow_lines)

def merge_files(output_file, input_pattern):
    """安全合并文件，处理编码问题"""
    with open(output_file, 'w', encoding='utf-8') as outfile:
        for file in glob.glob(input_pattern):
            try:
                with open(file, 'r', encoding='utf-8', errors='replace') as infile:
                    outfile.write(infile.read() + '\n')
                logger.info(f"已合并: {file}")
            except Exception as e:
                logger.error(f"合并失败 {file}: {str(e)}")

def deduplicate_file(filepath):
    """保留顺序的专业去重"""
    try:
        with open(filepath, 'r+', encoding='utf-8') as f:
            seen = set()
            unique_lines = []
            for line in f:
                normalized = re.sub(r'\s+', '', line.strip()).lower()
                if not normalized or normalized not in seen:
                    seen.add(normalized)
                    unique_lines.append(line)
            
            f.seek(0)
            f.writelines(unique_lines)
            f.truncate()
        logger.info(f"已去重: {filepath}")
    except Exception as e:
        logger.error(f"去重错误: {str(e)}")

def main():
    try:
        logger.info("开始处理规则文件")
        
        # 1. 处理拦截规则
        merge_files('combined_block.txt', 'adblock*.txt')
        with open('combined_block.txt', 'r', encoding='utf-8') as f:
            block_content = clean_rules(f.read())
            extracted_allow = extract_allow_rules(block_content)
        
        # 2. 处理白名单规则
        merge_files('combined_allow.txt', 'allow*.txt')
        with open('combined_allow.txt', 'r', encoding='utf-8') as f:
            allow_content = clean_rules(f.read()) + '\n' + extracted_allow
        
        # 3. 生成最终文件
        with open('adblock.txt', 'w', encoding='utf-8') as f:
            f.write(block_content)  # 主规则文件（含内置白名单）
        
        with open('allow.txt', 'w', encoding='utf-8') as f:
            f.write(clean_rules(allow_content))  # 独立白名单文件
        
        # 4. 移动文件
        target_dir = Path('../')
        target_dir.mkdir(exist_ok=True)
        
        Path('adblock.txt').rename(target_dir / 'adblock.txt')
        Path('allow.txt').rename(target_dir / 'allow.txt')
        
        logger.info(f"生成文件: {target_dir/'adblock.txt'}")
        logger.info(f"生成文件: {target_dir/'allow.txt'}")

    except Exception as e:
        logger.error(f"处理失败: {str(e)}", exc_info=True)

if __name__ == '__main__':
    main()