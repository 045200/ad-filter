const { Engine } = require('tsurlfilter');
const fs = require('fs');

// 从命令行参数获取输入文件路径
const inputFile = process.argv[2];

function classifyRules(rules) {
    const result = { adb: [], adw: [], dns: [] };
    const engine = new Engine();

    rules.forEach(rule => {
        try {
            engine.addRule(rule);
            result.adb.push(rule);

            // 白名单规则
            if (rule.startsWith('@@')) {
                result.adw.push(rule);
            }

            // DNS规则（含重写）
            if (rule.includes('$dnsrewrite') || /^\d+\.\d+\.\d+\.\d+\s/.test(rule)) {
                result.dns.push(rule);
            }
        } catch (e) {
            console.error(`[SKIPPED] Invalid rule: ${rule}`);
        }
    });

    return result;
}

// 主流程
try {
    const rules = fs.readFileSync(inputFile, 'utf-8')
        .split('\n')
        .filter(line => line.trim() && !line.startsWith('!'));
    
    const classified = classifyRules(rules);
    console.log(JSON.stringify(classified));
} catch (e) {
    console.error(`❌ 文件读取失败: ${e.message}`);
    process.exit(1);
}