import os
import subprocess
import time
import shutil

# 删除目录下所有的文件
directory = "./data/rules/"

# 确保目录存在并遍历删除其中的文件
if os.path.exists(directory):
    for file_name in os.listdir(directory):
        file_path = os.path.join(directory, file_name)
        try:
            if os.path.isfile(file_path):
                os.unlink(file_path)
        except Exception as e:
            print(f"无法删除文件: {file_path}, 错误: {e}")
else:
    print(f"目录 {directory} 不存在")

# 删除目录本身
try:
    shutil.rmtree(directory)
    print(f"成功删除目录 {directory} 及其中的所有文件")
except Exception as e:
    print(f"无法删除目录 {directory}, 错误: {e}")

# 创建临时文件夹
os.makedirs("./tmp/", exist_ok=True)

# 复制补充规则到tmp文件夹
subprocess.run("cp ./data/mod/adblock.txt ./tmp/adblock01.txt", shell=True)
subprocess.run("cp ./data/mod/whitelist.txt ./tmp/allow01.txt", shell=True)


# 拦截规则
adblock = [
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/multi.txt",
 "https://raw.githubusercontent.com/8680/GOODBYEADS/master/data/rules/adblock.txt",

"https://raw.githubusercontent.com/xndeye/adblock_list/beta/rule/easylist.txt",
 "https://raw.gitmirror.com/lingeringsound/adblock_auto/main/Rules/adblock_auto.txt",

"https://raw.hellogithub.com/hosts",

"https://raw.gitmirror.com/lingeringsound/10007_auto/master/reward",

"https://raw.githubusercontent.com/PhoenixLjw/AdRules/main/adguard.txt",

"https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/adblockdns.txt",

"https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/adblockfilters.txt",

"https://raw.githubusercontent.com/qq5460168/dangchu/main/black.txt",

"https://mirror.ghproxy.com/raw.githubusercontent.com/qq5460168/666/master/rules.txt"
    ]

# 白名单规则
allow = [

"https://hub.gitmirror.com/https://raw.githubusercontent.com/qq5460168/dangchu/main/white.txt",

"https://file-git.trli.club/file-hosts/allow/Domains",

"https://mirror.ghproxy.com/raw.githubusercontent.com/8680/GOODBYEADS/master/allow.txt",

"https://mirror.ghproxy.com/raw.githubusercontent.com/qq5460168/666/master/allow.txt"
]

# 下载
for i, adblock_url in enumerate(adblock):
    subprocess.Popen(f"curl -m 60 --retry-delay 2 --retry 5 -k -L -C - -o tmp/adblock{i}.txt --connect-timeout 60 -s {adblock_url} | iconv -t utf-8", shell=True).wait()
    time.sleep(1)

for j, allow_url in enumerate(allow):
    subprocess.Popen(f"curl -m 60 --retry-delay 2 --retry 5 -k -L -C - -o tmp/allow{j}.txt --connect-timeout 60 -s {allow_url} | iconv -t utf-8", shell=True).wait()
    time.sleep(1)
    
print('规则下载完成')


