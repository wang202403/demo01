import os
import re
import csv
from collections import defaultdict

# 设置根目录（一级文件夹所在的目录），请修改为实际路径
root_dir = r"./classification"  # 举例

# 正则表达式，用于匹配文件名中的 CWE 编号（支持 CWE787 和 CWE-787 两种形式）
cwe_pattern = re.compile(r"(CWE-?\d+)")

# 固定两组的 CWE 列（注意：CWE190 在两组中都出现）
sard_cwes = ["CWE121", "CWE190", "CWE191", "CWE134", "CWE124"]
cve_cwes  = ["CWE125", "CWE190", "CWE416", "CWE476", "CWE787"]

# 存储每个一级目录的统计数据，数据结构为： 
#   all_folder_data = [(folder_name, cwe_counts), ...]
# 其中 cwe_counts 的结构： { "CWE编号": {"multi_line_fail": 计数, "multi_line_success": 计数,
#                                         "single_line_fail": 计数, "single_line_success": 计数} }
all_folder_data = []

# 遍历一级文件夹（例如，不同的 LLM，如 COT、Few-shot ICL 等）
for first_level in os.listdir(root_dir):
    first_level_path = os.path.join(root_dir, first_level)
    if not os.path.isdir(first_level_path):
        continue

    # 初始化当前目录下各个 CWE 的计数
    cwe_counts = defaultdict(lambda: {"multi_line_fail": 0, "multi_line_success": 0,
                                      "single_line_fail": 0, "single_line_success": 0})
    
    # 遍历二级文件夹，排除名称为 "invalid" 的目录
    for second_level in os.listdir(first_level_path):
        if second_level == "invalid":
            continue

        second_level_path = os.path.join(first_level_path, second_level)
        if not os.path.isdir(second_level_path):
            continue

        # 仅处理预期的四个子目录
        if second_level not in ["multi_line_fail", "multi_line_success", "single_line_fail", "single_line_success"]:
            continue

        # 遍历当前二级目录下所有文件
        for file_name in os.listdir(second_level_path):
            file_path = os.path.join(second_level_path, file_name)
            if not os.path.isfile(file_path):
                continue

            # 使用正则提取文件名中的 CWE 编号，并将其标准化（去掉“-”）
            match = cwe_pattern.search(file_name)
            if match:
                cwe = match.group(1).replace("-", "")
                cwe_counts[cwe][second_level] += 1

    # 输出统计信息（可选）
    print(f"一级文件夹：{first_level}")
    print(f"  不同 CWE 种类数：{len(cwe_counts)}")
    for cwe, counts in cwe_counts.items():
        total = sum(counts.values())
        if total > 0:
            percent_single = ((counts["single_line_fail"] + counts["single_line_success"]) / total) * 100
            percent_multi = ((counts["multi_line_fail"] + counts["multi_line_success"]) / total) * 100
            # success 百分比基于各自的 all 计算：
            percent_single_success = (counts["single_line_success"] / (counts["single_line_fail"] + counts["single_line_success"])) * 100 if (counts["single_line_fail"] + counts["single_line_success"]) > 0 else 0
            percent_multi_success = (counts["multi_line_success"] / (counts["multi_line_fail"] + counts["multi_line_success"])) * 100 if (counts["multi_line_fail"] + counts["multi_line_success"]) > 0 else 0
        else:
            percent_single = percent_multi = percent_single_success = percent_multi_success = 0
        print(f"  {cwe}: 总数={total}")
        print(f"    单行占比：{percent_single:.2f}%")
        print(f"    多行占比：{percent_multi:.2f}%")
        print(f"    single_line_success 占比（相对于 single all）：{percent_single_success:.2f}%")
        print(f"    multi_line_success 占比（相对于 multi all）：{percent_multi_success:.2f}%")
    print("-" * 60)
    
    all_folder_data.append((first_level, cwe_counts))

# 构造 CSV 表头：前三列固定，后面依次为 SARD 组（5 列）和 CVE 组（5 列）
header = ["LLM", "Prompting strategy", "Complexity level"] + sard_cwes + cve_cwes

# 定义 4 个提示策略及对应的“计数”函数（用于取出对应的计数值）
# 注意：后面在计算百分比时，不同策略的分母不同
strategies = [
    ("Single-line, all", lambda d: d.get("single_line_fail", 0) + d.get("single_line_success", 0)),
    ("Single-line, success", lambda d: d.get("single_line_success", 0)),
    ("Multi-line, all", lambda d: d.get("multi_line_fail", 0) + d.get("multi_line_success", 0)),
    ("Multi-line, success", lambda d: d.get("multi_line_success", 0)),
]

# 定义每种策略对应的分母函数，用于计算百分比
# “Single-line, all” 和 “Multi-line, all” 以当前 CWE 的总计（单行+多行）为分母
# 而 success 策略则以对应类别（单行或多行）的总数作为分母
denom_funcs = {
    "Single-line, all": lambda d: sum(d.values()),
    "Single-line, success": lambda d: d.get("single_line_fail", 0) + d.get("single_line_success", 0),
    "Multi-line, all": lambda d: sum(d.values()),
    "Multi-line, success": lambda d: d.get("multi_line_fail", 0) + d.get("multi_line_success", 0),
}

csv_rows = []
csv_rows.append(header)

# 针对每个一级目录，生成 4 行数据（第一行显示 LLM 名称和默认的 Complexity level “Standard”，其余行 LLM 和 Complexity level 列留空）
for folder_name, counts in all_folder_data:
    # 对于每个固定的 CWE，计算该 CWE 的总计数（这里仅用于“all”策略的分母，success 分母单独计算）
    cwe_total = {}
    for cwe in set(sard_cwes + cve_cwes):
        cwe_total[cwe] = sum(counts.get(cwe, {}).values())
    
    for i, (strategy_label, num_func) in enumerate(strategies):
        row = []
        if i == 0:
            row.append(folder_name)         # LLM 列
            row.append(strategy_label)        # Prompting strategy
            row.append("Standard")            # Complexity level（可根据需要修改）
        else:
            row.extend(["", strategy_label, ""])
        
        # 针对 SARD 组的每个 CWE
        for cwe in sard_cwes:
            d = counts.get(cwe, {})
            # 根据策略选择合适的分母
            denom = denom_funcs[strategy_label](d)
            if denom > 0:
                value = num_func(d) / denom * 100
            else:
                value = 0
            row.append(f"{value:.2f}%")
        # 针对 CVE 组的每个 CWE
        for cwe in cve_cwes:
            d = counts.get(cwe, {})
            denom = denom_funcs[strategy_label](d)
            if denom > 0:
                value = num_func(d) / denom * 100
            else:
                value = 0
            row.append(f"{value:.2f}%")
        csv_rows.append(row)

# 将数据写入 CSV 文件
output_csv = "output.csv"
with open(output_csv, "w", newline="", encoding="utf-8") as f:
    writer = csv.writer(f)
    writer.writerows(csv_rows)

print(f"CSV 文件已保存至 {output_csv}")
