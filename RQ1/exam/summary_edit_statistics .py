import os
import pandas as pd

# ================ 配置路径 ================
# Output根目录（根据实际情况修改）
OUTPUT_ROOT = r"./COT_Output"
FINAL_DIR = os.path.join(OUTPUT_ROOT, "final")

# ================ 统计函数 ================
def count_files_in_dir(dir_path):
    """统计指定目录下的文件数量（不递归，仅当前目录）"""
    if os.path.exists(dir_path) and os.path.isdir(dir_path):
        return len([f for f in os.listdir(dir_path) if os.path.isfile(os.path.join(dir_path, f))])
    return 0

def compute_edit_percentages(base_path):
    """
    对于给定的base_path（例如：最终目录下某个模型的“Single-line, all”目录），
    统计其下子目录 "add"、"del"、"replace" 中的文件数量，并计算百分比。
    返回一个字典：{"add": pct_add, "del": pct_del, "replace": pct_replace}
    """
    add = count_files_in_dir(os.path.join(base_path, "add"))
    dele = count_files_in_dir(os.path.join(base_path, "del"))
    replace = count_files_in_dir(os.path.join(base_path, "replace"))
    total = add + dele + replace
    if total == 0:
        return {"add": 0, "del": 0, "replace": 0}
    return {
        "add": add / total * 100,
        "del": dele / total * 100,
        "replace": replace / total * 100
    }

def determine_dataset(model_name):
    """根据模型文件夹名称判断数据集"""
    if "SARD" in model_name.upper():
        return "SARD"
    elif "CVE" in model_name.upper():
        return "CVE-LLM"
    else:
        return "Unknown"

# ================ 生成统计表 ============
def generate_statistics():
    rows = []
    # 遍历FINAL目录下的模型文件夹
    for model_folder in os.listdir(FINAL_DIR):
        model_path = os.path.join(FINAL_DIR, model_folder)
        if not os.path.isdir(model_path):
            continue
        dataset = determine_dataset(model_folder)
        
        # 编辑类别：四个目录
        for edits in ["Single-line, all", "Single-line, success", "Multi-line, all", "Multi-line, success"]:
            edits_path = os.path.join(model_path, edits)
            if not os.path.exists(edits_path):
                continue

            # 统计对应目录下"add","del","replace"的情况
            percentages = compute_edit_percentages(edits_path)
            rows.append({
                "model": model_folder,
                "Dataset": dataset,
                "Edits": edits,
                "%add": round(percentages["add"], 2),
                "%del": round(percentages["del"], 2),
                "%replace": round(percentages["replace"], 2)
            })
    return pd.DataFrame(rows)

# ================ 主流程 ================
if __name__ == "__main__":
    df = generate_statistics()
    print("生成的统计表如下：")
    print(df)
    
    # 保存为CSV文件
    output_csv = "Final_Statistics.csv"
    df.to_csv(output_csv, index=False)
    print(f"\n统计结果已保存为 {output_csv}")
