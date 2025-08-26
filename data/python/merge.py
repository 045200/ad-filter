import os
import requests
from pathlib import Path
from pybloom_live import BloomFilter


class AdFilterConfig:
    """配置类 - 支持AdBlock、AdGuard、AdGuard Home全语法规则"""
    # 路径配置
    INPUTDIR = Path(os.getenv('INPUTDIR', './data/filter'))
    OUTPUTDIR = Path(os.getenv('OUTPUTDIR', './data/filter'))

    # 文件模式（覆盖AdBlock/AdGuard常见命名）
    BLOCKPATTERNS = ['adblock*.txt', 'adguard*.txt', 'filter*.txt']
    ALLOWPATTERNS = ['allow*.txt', 'whitelist*.txt']
    OUTPUTBLOCK = 'adblock_ag_filter.txt'
    OUTPUTALLOW = 'allow_ag_filter.txt'

    # 布隆过滤器参数
    BLOOMINITCAP = 1000000
    BLOOMERRORRATE = 0.0001

    # AdGuard/AdGuard Home特殊语法标识（用于规则过滤）
    AG_VALID_PREFIXES = ('||', '|', '^', '*', '@@', '!#include', '!#if', '!#endif')
    AG_IGNORE_PREFIXES = ('!#',)  # 仅排除非指令类注释（保留!#开头的有效指令）
    HTTP_TIMEOUT = 10  # 远程规则下载超时时间（秒）


def load_remote_rule(url: str) -> list[str]:
    """加载AdGuard !#include引用的远程规则（HTTP/HTTPS）"""
    remote_rules = []
    try:
        response = requests.get(url, timeout=AdFilterConfig.HTTP_TIMEOUT)
        response.raise_for_status()  # 触发HTTP错误（4xx/5xx）
        lines = response.text.strip().split('\n')
        for line in lines:
            rule = line.strip()
            # 过滤远程规则中的无效行，保留AdGuard语法有效规则
            if (not rule) or (rule.startswith(('!', '#')) and not rule.startswith(AdFilterConfig.AG_VALID_PREFIXES)):
                continue
            remote_rules.append(rule)
        print(f"成功加载远程规则 {url}，获取有效规则 {len(remote_rules)} 条")
    except Exception as e:
        print(f"加载远程规则 {url} 失败：{str(e)}")
    return remote_rules


def load_local_include_rule(include_path: str, base_dir: Path) -> list[str]:
    """加载AdGuard !#include引用的本地规则文件"""
    local_rules = []
    # 处理相对路径（相对于主规则文件目录）
    rule_path = Path(include_path) if Path(include_path).is_absolute() else (base_dir / include_path)
    if rule_path.exists() and rule_path.is_file():
        local_rules = load_and_filter_rules(rule_path)
        print(f"成功加载本地引用规则 {rule_path}，获取有效规则 {len(local_rules)} 条")
    else:
        print(f"本地引用规则 {rule_path} 不存在，跳过")
    return local_rules


def load_and_filter_rules(file_path: Path) -> list[str]:
    """
    读取规则文件（支持AdBlock/AdGuard/AdGuard Home全语法）
    保留：有效规则、AdGuard指令（!#include/!#if等）、特殊前缀规则（||/@@/*等）
    过滤：空行、普通注释（!/#开头且非AdGuard指令）
    """
    valid_rules = []
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                rule = line.strip()
                # 1. 过滤空行
                if not rule:
                    continue
                # 2. 过滤普通注释（!/#开头，但不是AdGuard有效指令/前缀）
                if (rule.startswith(('!', '#')) and 
                    not any(rule.startswith(prefix) for prefix in AdFilterConfig.AG_VALID_PREFIXES)):
                    continue
                # 3. 处理AdGuard !#include指令（本地/远程引用）
                if rule.startswith('!#include'):
                    include_target = rule.split('"')[1] if '"' in rule else rule.split()[1]
                    # 区分远程URL和本地路径
                    if include_target.startswith(('http://', 'https://')):
                        include_rules = load_remote_rule(include_target)
                    else:
                        include_rules = load_local_include_rule(include_target, file_path.parent)
                    valid_rules.extend(include_rules)
                    continue
                # 4. 保留AdGuard特殊语法规则（||/@@/*等）和元指令（!#if等）
                valid_rules.append(rule)
    except Exception as e:
        print(f"读取文件 {file_path} 失败：{str(e)}")
    return valid_rules


def recursive_load_rules(input_dir: Path, file_patterns: list[str]) -> list[str]:
    """递归读取目录下所有符合模式的规则文件（含AdGuard引用规则）"""
    all_rules = []
    if not input_dir.exists():
        print(f"输入目录 {input_dir} 不存在，创建空目录")
        input_dir.mkdir(parents=True, exist_ok=True)
        return all_rules

    for pattern in file_patterns:
        for file in input_dir.rglob(pattern):
            if file.is_file():
                rules = load_and_filter_rules(file)
                all_rules.extend(rules)
                print(f"读取主规则文件 {file}，获取有效规则（含引用）{len(rules)} 条")
    return all_rules


def deduplicate_rules(rules: list[str], init_cap: int, error_rate: float) -> set[str]:
    """布隆过滤器+哈希表精准去重（支持AdGuard特殊语法规则）"""
    bloomfilter = BloomFilter(capacity=init_cap, error_rate=error_rate)
    uniquerules = set()

    for rule in rules:
        if rule not in bloomfilter:
            bloomfilter.add(rule)
            uniquerules.add(rule)
    return uniquerules


def save_rules(rules: set[str], output_path: Path) -> None:
    """保存去重后的完整规则（保留AdGuard语法结构）"""
    output_path.parent.mkdir(parents=True, exist_ok=True)

    # 按规则类型排序（元指令→白名单→黑名单，便于维护）
    sorted_rules = sorted(rules, key=lambda x: (
        0 if x.startswith('!#') else  # 1. AdGuard元指令（!#if/!#include等）
        1 if x.startswith('@@') else   # 2. 白名单规则（@@开头）
        2                              # 3. 黑名单规则
    ))

    with open(output_path, 'w', encoding='utf-8') as f:
        for rule in sorted_rules:
            f.write(f"{rule}\n")
    print(f"规则已保存到 {output_path}，共 {len(rules)} 条有效规则")


def main():
    cfg = AdFilterConfig()
    print("=== AdBlock/AdGuard/AdGuard Home 规则合并去重脚本 ===")
    print(f"输入目录：{cfg.INPUTDIR}")
    print(f"输出目录：{cfg.OUTPUTDIR}")

    # 处理黑名单规则（含AdGuard特殊语法）
    print("\n--- 开始处理黑名单规则 ---")
    blockrules = recursive_load_rules(cfg.INPUTDIR, cfg.BLOCKPATTERNS)
    uniqueblock = deduplicate_rules(blockrules, cfg.BLOOMINITCAP, cfg.BLOOMERRORRATE)
    save_rules(uniqueblock, cfg.OUTPUTDIR / cfg.OUTPUTBLOCK)

    # 处理白名单规则
    print("\n--- 开始处理白名单规则 ---")
    allowrules = recursive_load_rules(cfg.INPUTDIR, cfg.ALLOWPATTERNS)
    uniqueallow = deduplicate_rules(allowrules, cfg.BLOOMINITCAP, cfg.BLOOMERRORRATE)
    save_rules(uniqueallow, cfg.OUTPUTDIR / cfg.OUTPUTALLOW)

    print("\n=== 所有规则处理完成 ===")


if __name__ == "__main__":
    # 需提前安装依赖：pip install pybloom-live requests
    main()
