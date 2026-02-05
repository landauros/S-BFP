"""
浏览器指纹熵 (Entropy) 分析脚本
用于分析收集的浏览器指纹数据的区分能力

核心概念：
- 熵 (Entropy): 衡量特征的区分能力/信息量
- H = -Σ p(x) * log2(p(x))
- 熵越高 = 区分能力越强
"""

import json
import os
import math
import hashlib
from collections import Counter
from pathlib import Path
import pandas as pd

# 数据目录
USERS_DIR = Path(r"C:\Users\W\Desktop\IEEE s&p\App_eng\App_eng\User_Manager\data\users")
RESULTS_DIR = Path(r"C:\Users\W\Desktop\IEEE s&p\App_eng\App_eng\results")


def calculate_entropy(values):
    """
    计算熵值 (Shannon Entropy)
    H = -Σ p(x) * log2(p(x))
    
    返回值单位: bits
    """
    if not values:
        return 0.0
    
    total = len(values)
    counter = Counter(values)
    
    entropy = 0.0
    for count in counter.values():
        if count > 0:
            p = count / total
            entropy -= p * math.log2(p)
    
    return entropy


def calculate_anonymity_set(values):
    """
    计算匿名集大小 - 每个唯一值平均有多少用户共享
    """
    if not values:
        return 0
    
    counter = Counter(values)
    unique_count = len(counter)
    total = len(values)
    
    # 平均匿名集大小
    avg_anonymity = total / unique_count if unique_count > 0 else 0
    return avg_anonymity


def calculate_uniqueness_rate(values):
    """
    计算唯一性比率 - 有多少比例的值是唯一的
    """
    if not values:
        return 0.0
    
    counter = Counter(values)
    unique_count = sum(1 for count in counter.values() if count == 1)
    return unique_count / len(values) * 100


def get_max_entropy(n_samples):
    """
    计算理论最大熵 (所有值都不同时)
    H_max = log2(N)
    """
    if n_samples <= 1:
        return 0.0
    return math.log2(n_samples)


def load_user_fingerprints():
    """
    加载所有用户的指纹数据
    适应新的数据结构
    """
    fingerprints = []
    
    for file_path in USERS_DIR.glob("*.json"):
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
                
                # 构建统一的指纹对象
                fp = {
                    'username': data.get('username', file_path.stem),
                    'source_file': file_path.name,
                }
                
                # 提取指纹数据
                if 'fingerprint' in data:
                    fp_data = data['fingerprint']
                    fp['fingerprint_hash'] = fp_data.get('hash', '')
                    fp['captured_at'] = fp_data.get('captured_at', '')
                    fp['user_agent'] = fp_data.get('user_agent', '')
                    fp['client_ip'] = fp_data.get('client_ip', '')
                    
                    # Canvas 数据 (Base64 图片)
                    if 'canvas_data' in fp_data:
                        canvas = fp_data['canvas_data']
                        # 使用图片数据的哈希作为特征
                        if isinstance(canvas, dict) and 'imageBase64' in canvas:
                            fp['canvas_hash'] = hashlib.sha256(
                                canvas['imageBase64'].encode()
                            ).hexdigest()[:16]
                        elif isinstance(canvas, str):
                            fp['canvas_hash'] = hashlib.sha256(
                                canvas.encode()
                            ).hexdigest()[:16]
                    
                # Audio 基线
                if 'audio_baseline' in data:
                    fp['audio_baseline'] = data['audio_baseline']
                
                # Audio 稳定性测试
                if 'audio_stability' in data and len(data['audio_stability']) > 0:
                    stability = data['audio_stability'][0]
                    fp['audio_all_stable'] = stability.get('all_stable', False)
                    fp['audio_unique_hashes'] = len(stability.get('unique_hashes', []))
                    
                    # 提取音频配置
                    if 'runs' in stability and len(stability['runs']) > 0:
                        audio_config = stability['runs'][0].get('audioConfig', {})
                        fp['audio_sample_rate'] = audio_config.get('sampleRate', 0)
                
                # WebGL 数据
                if 'webgl_baseline' in data:
                    fp['webgl_baseline'] = data['webgl_baseline']
                
                if 'webgl_stability' in data and len(data['webgl_stability']) > 0:
                    webgl_stab = data['webgl_stability'][0]
                    fp['webgl_all_stable'] = webgl_stab.get('all_stable', False)
                
                # WebGL2 数据
                if 'webgl2_baseline' in data:
                    fp['webgl2_baseline'] = data['webgl2_baseline']
                
                # Canvas 数据
                if 'canvas_baseline' in data:
                    fp['canvas_baseline'] = data['canvas_baseline']
                
                fingerprints.append(fp)
                
        except Exception as e:
            print(f"Error loading {file_path}: {e}")
    
    return fingerprints


def extract_feature_values(fingerprints, feature_key):
    """
    从指纹数据中提取特定特征的所有值
    """
    values = []
    
    for fp in fingerprints:
        value = fp.get(feature_key)
        if value is not None:
            if isinstance(value, (dict, list)):
                value = json.dumps(value, sort_keys=True)
            else:
                value = str(value)
            values.append(value)
    
    return values


def analyze_single_feature(fingerprints, feature_name, feature_key):
    """
    分析单个特征的熵
    """
    values = extract_feature_values(fingerprints, feature_key)
    
    if not values:
        return None
    
    n_samples = len(values)
    n_unique = len(set(values))
    entropy = calculate_entropy(values)
    max_entropy = get_max_entropy(n_samples)
    normalized_entropy = entropy / max_entropy if max_entropy > 0 else 0
    uniqueness_rate = calculate_uniqueness_rate(values)
    anonymity_set = calculate_anonymity_set(values)
    
    return {
        'feature': feature_name,
        'n_samples': n_samples,
        'n_unique_values': n_unique,
        'entropy_bits': round(entropy, 4),
        'max_entropy_bits': round(max_entropy, 4),
        'normalized_entropy': round(normalized_entropy, 4),
        'uniqueness_rate_%': round(uniqueness_rate, 2),
        'avg_anonymity_set': round(anonymity_set, 2),
        'distinguishing_power': round(2 ** entropy, 2)  # 理论上可以区分多少用户
    }


def get_feature_list():
    """
    定义要分析的特征列表
    (特征名称, 数据key)
    """
    return [
        # 基础信息
        ("User Agent", "user_agent"),
        ("Client IP", "client_ip"),
        
        # 主指纹哈希
        ("Fingerprint Hash", "fingerprint_hash"),
        
        # Canvas 指纹
        ("Canvas Hash", "canvas_hash"),
        ("Canvas Baseline", "canvas_baseline"),
        
        # WebGL 指纹
        ("WebGL Baseline", "webgl_baseline"),
        ("WebGL Stable", "webgl_all_stable"),
        ("WebGL2 Baseline", "webgl2_baseline"),
        
        # Audio 指纹
        ("Audio Baseline", "audio_baseline"),
        ("Audio Stable", "audio_all_stable"),
        ("Audio Sample Rate", "audio_sample_rate"),
    ]


def analyze_combined_features(fingerprints, feature_combinations):
    """
    分析组合特征的熵
    """
    results = []
    
    for combo_name, feature_keys in feature_combinations:
        combined_values = []
        
        for fp in fingerprints:
            combo_value = []
            for key in feature_keys:
                value = fp.get(key)
                if value is not None:
                    combo_value.append(str(value))
            
            if combo_value:
                combined_values.append('|'.join(combo_value))
        
        if combined_values:
            n_samples = len(combined_values)
            n_unique = len(set(combined_values))
            entropy = calculate_entropy(combined_values)
            max_entropy = get_max_entropy(n_samples)
            
            results.append({
                'combination': combo_name,
                'n_samples': n_samples,
                'n_unique_values': n_unique,
                'entropy_bits': round(entropy, 4),
                'max_entropy_bits': round(max_entropy, 4),
                'normalized_entropy': round(entropy / max_entropy if max_entropy > 0 else 0, 4),
            })
    
    return results


def print_value_distribution(fingerprints, feature_key, feature_name, top_n=10):
    """
    打印特征值的分布情况
    """
    values = extract_feature_values(fingerprints, feature_key)
    if not values:
        return
    
    counter = Counter(values)
    total = len(values)
    
    print(f"\n  {feature_name} 值分布 (Top {min(top_n, len(counter))}):")
    for value, count in counter.most_common(top_n):
        # 截断过长的值
        display_value = value[:50] + "..." if len(value) > 50 else value
        percentage = count / total * 100
        print(f"    - '{display_value}': {count} ({percentage:.1f}%)")


def main():
    print("=" * 70)
    print("🔬 浏览器指纹熵 (Entropy) 分析报告")
    print("=" * 70)
    print("\n📖 熵(Entropy)概念说明:")
    print("   - 熵衡量特征的区分能力/信息量")
    print("   - 公式: H = -Σ p(x) × log₂(p(x))")
    print("   - 熵越高 = 值越分散 = 区分能力越强")
    print("   - 最大熵 = log₂(N), N为样本数")
    
    # 加载数据
    fingerprints = load_user_fingerprints()
    print(f"\n📊 加载了 {len(fingerprints)} 个用户指纹数据\n")
    
    if len(fingerprints) == 0:
        print("❌ 没有找到指纹数据!")
        return
    
    # 显示加载的用户
    print("用户列表:")
    for fp in fingerprints:
        print(f"  - {fp['username']} ({fp['source_file']})")
    
    # 1. 单个特征熵分析
    print("\n" + "-" * 70)
    print("📈 单个特征熵分析")
    print("-" * 70)
    
    feature_results = []
    for feature_name, feature_key in get_feature_list():
        result = analyze_single_feature(fingerprints, feature_name, feature_key)
        if result:
            feature_results.append(result)
    
    # 按熵值排序
    feature_results.sort(key=lambda x: x['entropy_bits'], reverse=True)
    
    # 打印结果表格
    print(f"\n{'特征名称':<20} {'熵(bits)':<10} {'唯一值':<8} {'唯一率%':<10} {'区分力':<10} {'归一化熵':<10}")
    print("-" * 70)
    
    for r in feature_results:
        print(f"{r['feature']:<20} {r['entropy_bits']:<10} {r['n_unique_values']:<8} {r['uniqueness_rate_%']:<10} {r['distinguishing_power']:<10} {r['normalized_entropy']:.4f}")
    
    # 2. 显示关键特征的值分布
    print("\n" + "-" * 70)
    print("📊 特征值分布详情")
    print("-" * 70)
    
    key_features = [
        ("fingerprint_hash", "Fingerprint Hash"),
        ("audio_baseline", "Audio Baseline"),
        ("webgl_baseline", "WebGL Baseline"),
        ("canvas_baseline", "Canvas Baseline"),
        ("user_agent", "User Agent"),
    ]
    
    for key, name in key_features:
        print_value_distribution(fingerprints, key, name, top_n=5)
    
    # 3. 组合特征分析
    print("\n" + "-" * 70)
    print("🔗 组合特征熵分析")
    print("-" * 70)
    
    combinations = [
        ("Audio + WebGL", ["audio_baseline", "webgl_baseline"]),
        ("Audio + WebGL + WebGL2", ["audio_baseline", "webgl_baseline", "webgl2_baseline"]),
        ("Canvas + WebGL + Audio", ["canvas_baseline", "webgl_baseline", "audio_baseline"]),
        ("Complete Fingerprint", ["fingerprint_hash"]),
    ]
    
    combo_results = analyze_combined_features(fingerprints, combinations)
    
    if combo_results:
        print(f"\n{'组合名称':<25} {'熵(bits)':<10} {'唯一值':<8} {'归一化熵':<10}")
        print("-" * 60)
        
        for r in combo_results:
            print(f"{r['combination']:<25} {r['entropy_bits']:<10} {r['n_unique_values']:<8} {r['normalized_entropy']:.4f}")
    
    # 4. 熵分析总结
    print("\n" + "=" * 70)
    print("📋 分析总结")
    print("=" * 70)
    
    n_samples = len(fingerprints)
    max_possible_entropy = get_max_entropy(n_samples)
    
    print(f"\n样本数量: {n_samples}")
    print(f"理论最大熵: {max_possible_entropy:.4f} bits")
    print(f"(即如果每个用户都完全唯一，可以达到的最大熵)")
    
    if feature_results:
        top_features = [r for r in feature_results if r['entropy_bits'] > 0][:5]
        if top_features:
            print(f"\n🏆 熵值最高的特征 (区分能力最强):")
            for i, r in enumerate(top_features, 1):
                print(f"  {i}. {r['feature']}: {r['entropy_bits']:.4f} bits (可区分 {r['distinguishing_power']} 用户)")
    
    # 5. 保存详细报告
    output_dir = Path(r"C:\Users\W\Desktop\IEEE s&p\App_eng\App_eng\reports3")
    output_dir.mkdir(exist_ok=True)
    
    # 保存为CSV
    if feature_results:
        df = pd.DataFrame(feature_results)
        csv_path = output_dir / "entropy_analysis_report.csv"
        df.to_csv(csv_path, index=False, encoding='utf-8-sig')
        print(f"\n📁 详细报告已保存: {csv_path}")
    
    # 6. 计算理论识别能力
    print("\n" + "-" * 70)
    print("🎯 指纹识别能力估算")
    print("-" * 70)
    
    # 假设特征独立，总熵 = 各特征熵之和 (上界估计)
    # 排除重复的特征 (如 fingerprint_hash 已包含其他)
    independent_features = ['audio_baseline', 'webgl_baseline', 'canvas_baseline']
    total_entropy_upper = sum(
        r['entropy_bits'] for r in feature_results 
        if r['feature'].lower().replace(' ', '_') in [f.replace('_', ' ').lower() for f in independent_features]
        and r['entropy_bits'] > 0
    )
    
    # 实际总熵 (用完整哈希)
    full_hash_result = next((r for r in feature_results if r['feature'] == 'Fingerprint Hash'), None)
    actual_entropy = full_hash_result['entropy_bits'] if full_hash_result else 0
    
    print(f"\n独立特征熵之和: {total_entropy_upper:.4f} bits")
    print(f"完整指纹熵: {actual_entropy:.4f} bits")
    
    if actual_entropy > 0:
        distinguishable = 2 ** actual_entropy
        print(f"可区分的理论用户数: 2^{actual_entropy:.2f} ≈ {distinguishable:.0f} 用户")
    
    # 7. 建议
    print("\n" + "-" * 70)
    print("💡 改进建议")
    print("-" * 70)
    
    print(f"""
当前数据量: {n_samples} 用户 (较少)

为了更准确的熵分析，建议:
1. 收集更多样本 (至少 100+ 用户)
2. 覆盖不同浏览器/设备组合
3. 分析跨时间的稳定性

熵分析的意义:
- 高熵特征 → 适合作为主要识别依据
- 低熵特征 → 可作为辅助特征
- 组合多个特征可以增加总熵

参考文献推荐:
- Eckersley (2010): "How Unique Is Your Web Browser?"
- Laperdrix et al.: "Browser Fingerprinting: A Survey"
""")
    
    print("\n" + "=" * 70)
    print("分析完成!")
    print("=" * 70)


if __name__ == "__main__":
    main()
