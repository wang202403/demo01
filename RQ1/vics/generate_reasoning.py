import json
import requests
import os
import time

# === 配置 ===
INPUT_FILE = 'cwe_vulnerabilities_with_reasoning.json'
OUTPUT_FILE = 'cwe_vulnerabilities_with_updated_reasoning_v2.json'
OPENAI_API_KEY = ''  # 请替换为你的API Key
OPENAI_MODEL = 'gpt-4o'  # 这个是实际可用的最新GPT-4.5模型名称

# === OpenAI请求函数 ===
def generate_reasoning(cot_reasoning, cwe_id, sample_name):
    prompt = (
        f"You are an expert in software security and vulnerability injection techniques. "
        f"The following is a vulnerability injection case study related to {cwe_id}. "
        f"The goal is to describe how a vulnerability was **deliberately introduced** when transitioning from version V1 (normal) to version V2 (vulnerable). "
        f"This is not a vulnerability fix case; instead, V2 is intentionally **made vulnerable** to demonstrate the weakness.\n\n"
        f"Sample Name: {sample_name}\n"
        f"V1 code and its corresponding vulnerable code V2:\n{cot_reasoning}\n\n"
        f"---\n"
        f"Please rewrite the above explanation into a professional and clear 'reasoning' section suitable for a vulnerability injection dataset.\n"
        f"**Key requirements:**\n"
        f"- Emphasize how V2 introduces the vulnerability (what unsafe change was made and why it is dangerous).\n"
        f"- Clearly state that V2 is deliberately weakened to introduce the vulnerability.\n"
        f"- Focus on the technical mechanism (e.g., buffer overflow, out-of-bounds access, dangling pointer).\n"
        f"- Do not describe V1 as 'correct', 'secure', or 'fixed'. Treat V1 as a neutral starting point.\n"
        f"- Do not describe V2 as a 'mistake', 'oversight', or 'error'. It is a **deliberate weakening**.\n"
        f"- Avoid using phrases like 'prevents', 'fixes', 'ensures', 'improves', 'mitigates', 'protects', etc.\n"
        f"- Only describe the weakening action and the technical impact.\n\n"
        f"Final 'reasoning':"
    )

    headers = {
        'Authorization': f'Bearer {OPENAI_API_KEY}',
        'Content-Type': 'application/json'
    }

    payload = {
        'model': OPENAI_MODEL,
        'messages': [{'role': 'user', 'content': prompt}],
        'max_tokens': 1000,
        'temperature': 0.3
    }

    try:
        response = requests.post('https://api.openai.com/v1/chat/completions', json=payload, headers=headers)
        response.raise_for_status()
        reasoning_text = response.json()['choices'][0]['message']['content'].strip()
        return reasoning_text
    except Exception as e:
        print(f"⚠️ Error generating reasoning for {sample_name} - {e}")
        return "Error generating reasoning."

# === 读取原始JSON ===
with open(INPUT_FILE, 'r', encoding='utf-8') as f:
    data = json.load(f)

# === 遍历数据并处理每个样本 ===
for cwe_id, samples in data.items():
    for sample in samples:
        sample.pop('concise_reasoning', None)  # 删除concise_reasoning
        cot_reasoning = sample.get('cot_reasoning', '')
        sample_name = sample.get('name', '')

        if cot_reasoning:
            print(f"🔄 Generating reasoning for {sample_name} ({cwe_id})...")
            new_reasoning = generate_reasoning(cot_reasoning, cwe_id, sample_name)
            sample['reasoning'] = new_reasoning
            time.sleep(0.5)  # 防止API请求过于频繁

# === 保存新的JSON文件 ===
with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
    json.dump(data, f, indent=4, ensure_ascii=False)

print(f"✅ New file saved as: {OUTPUT_FILE}")
