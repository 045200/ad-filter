// 加载编译后的模块
const path = require('path');
try {
    // 尝试从NODE_PATH加载
    const { Engine } = require('tsurlfilter/dist/engine');
    console.error("✔ 从NODE_PATH成功加载tsurlfilter");
} catch (e) {
    console.error("❌ 从NODE_PATH加载失败，尝试直接路径...");
    try {
        // 备用加载方式
        const { Engine } = require(path.join(process.env.NODE_PATH, 'dist/engine'));
    } catch (e) {
        console.error(`❌ 模块加载失败: ${e.message}`);
        process.exit(1);
    }
}

const fs = require('fs');

function classifyRules(rules) {
    const result = { adb: [], adw: [], dns: [] };
    const engine = new Engine();

    rules.forEach(rule => {
        rule = rule.trim();
        if (!rule || rule.startsWith('!')) return;

        try {
            // 白名单规则
            if (rule.startsWith('@@')) {
                result.adw.push(rule);
            }
            
            // DNS规则
            if (rule.includes('$dnsrewrite') || /^\d+\.\d+\.\d+\.\d+\s/.test(rule)) {
                result.dns.push(rule);
            }

            // 验证规则有效性
            if (engine.validateRule(rule)) {
                result.adb.push(rule);
            } else {
                console.error(`[INVALID] ${rule}`);
            }
        } catch (e) {
            console.error(`[ERROR] 处理规则失败: ${rule}\n${e.message}`);
        }
    });

    return result;
}

// 主流程
try {
    if (process.argv.length < 3) {
        throw new Error("请提供输入文件路径");
    }

    const inputFile = process.argv[2];
    const rules = fs.readFileSync(inputFile, 'utf-8')
        .split('\n')
        .filter(line => line.trim());

    console.error(`📄 已加载 ${rules.length} 条原始规则`);
    const classified = classifyRules(rules);
    
    // 输出统计信息到stderr
    console.error(`✔ 分类完成: 
      AdBlock: ${classified.adb.length}
      白名单: ${classified.adw.length}
      DNS规则: ${classified.dns.length}`);
    
    // 输出JSON结果到stdout
    console.log(JSON.stringify(classified));
} catch (e) {
    console.error(`❌ 处理失败: ${e.message}`);
    process.exit(1);
}