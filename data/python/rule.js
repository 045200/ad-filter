// 使用绝对路径引入tsurlfilter（兼容GitHub Actions）
const { Engine } = require('tsurlfilter/packages/tsurlfilter/dist/engine');
const fs = require('fs');

function classifyRules(rules) {
    const result = { adb: [], adw: [], dns: [] };
    const engine = new Engine();

    rules.forEach(rule => {
        rule = rule.trim();
        if (!rule || rule.startsWith('!')) return;

        try {
            // 先分类再添加（避免无效规则污染engine）
            if (rule.startsWith('@@')) {
                result.adw.push(rule);
            }
            if (rule.includes('$dnsrewrite') || /^\d+\.\d+\.\d+\.\d+\s/.test(rule)) {
                result.dns.push(rule);
            }

            // 验证规则有效性
            engine.addRule(rule);
            result.adb.push(rule);
        } catch (e) {
            console.error(`[SKIPPED] Invalid rule: ${rule}`);
        }
    });

    return result;
}

// 主流程
try {
    const rules = fs.readFileSync(process.argv[2], 'utf-8')
        .split('\n')
        .filter(line => line.trim());

    const classified = classifyRules(rules);
    console.log(JSON.stringify(classified));
} catch (e) {
    console.error(`❌ 处理失败: ${e.message}`);
    process.exit(1);
}