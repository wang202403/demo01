import numpy as np
import pandas as pd
from statsmodels.stats.inter_rater import fleiss_kappa

# 读取CSV文件并提取所需行的数据
def read_vector_from_csv(filename):
    df = pd.read_csv(filename)
    row = df[(df['LLM'] == 'GPT-4o') & (df['Prompting strategy'] == 'Standard') & (df['Dataset'] == 'SARD')]
    if row.empty:
        raise ValueError(f"未能在 {filename} 中找到 GPT-4o, Standard, SARD 的数据")
    vector = row.iloc[0, 3:-1].astype(float).values  # 取数值并丢弃最后一列
    return vector

# 归一化并调整总和
def normalize_and_adjust(vector, total):
    new_vector = np.floor(vector / 100 * total).astype(int)  # 先除以100再乘以total，并向下取整
    diff = total - np.sum(new_vector)  # 计算误差
    if diff != 0:
        indices = np.argsort(-vector)[:abs(diff)]  # 选择最大值的索引进行调整
        adjustment = 1 if diff > 0 else -1
        for i in indices:
            new_vector[i] += adjustment
    return new_vector

# 生成分类向量
def generate_class_vector(new_vector):
    class_vector = []
    for i, count in enumerate(new_vector):
        class_vector.extend([i + 1] * count)  # i+1 表示类别
    return class_vector

# 计算 Fleiss' kappa 和 Randolph's kappa
def calculate_kappa(vec1, vec2):
    # 构造 Fleiss kappa 需要的矩阵 (N subjects, k categories)
    categories = np.unique(vec1 + vec2)
    table = np.zeros((len(vec1), len(categories)), dtype=int)

    for i, v in enumerate(vec1):
        table[i, v - 1] += 1
    for i, v in enumerate(vec2):
        table[i, v - 1] += 1

    kappa_fleiss = fleiss_kappa(table, method='fleiss')
    kappa_randolph = fleiss_kappa(table, method='randolph')

    return kappa_fleiss, kappa_randolph


# basic settings
total_CVELLM = 220
total_SARD = 380

# 读取向量
vector_a = read_vector_from_csv("a.csv")
vector_b = read_vector_from_csv("b.csv")

# 归一化并调整
new_vector_a = normalize_and_adjust(vector_a, total_CVELLM)
new_vector_b = normalize_and_adjust(vector_b, total_CVELLM)

# 生成分类向量
class_vector_a = generate_class_vector(new_vector_a)
class_vector_b = generate_class_vector(new_vector_b)

# 计算 kappa 统计量
kappa_fleiss, kappa_randolph = calculate_kappa(class_vector_a, class_vector_b)

# 输出结果
print("Fleiss' kappa:", kappa_fleiss)
print("Randolph's kappa:", kappa_randolph)
