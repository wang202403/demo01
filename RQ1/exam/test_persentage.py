import os
import re
from collections import defaultdict

def calculate_cwe_percentage(directory):
    cwe_count = defaultdict(int)
    total_files = 0
    
    # 正则表达式匹配CWE编号
    cwe_pattern = re.compile(r'^CWE(\d+)_')
    
    # 遍历目录下的文件
    for filename in os.listdir(directory):
        match = cwe_pattern.match(filename)
        if match:
            cwe_number = match.group(1)
            cwe_count[cwe_number] += 1
            total_files += 1

    # 计算百分比并输出
    if total_files == 0:
        print("No matching files found.")
        return

    print("CWE Number Percentage Breakdown:")
    for cwe, count in cwe_count.items():
        percentage = (count / total_files) * 100
        print(f"CWE{cwe}: {percentage:.2f}%")

if __name__ == "__main__":
    directory = input("Enter the directory path: ")
    if os.path.isdir(directory):
        calculate_cwe_percentage(directory)
    else:
        print("Invalid directory path.")
