# FABEO: Fast Attribute-Based Encryption with Optimal Security

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue.svg)](https://www.python.org/)
[![Security](https://img.shields.io/badge/Security-Optimal%20GGM%20Adaptive-green.svg)](https://eprint.iacr.org/)
[![License](https://img.shields.io/badge/License-MIT-purple.svg)](LICENSE)

本專案為論文 **《FABEO: Fast Attribute-Based Encryption with Optimal Security》**（Doreen Riepel & Hoeteck Wee, ACM CCS / ePrint 2022）的完整工程實作與學術評測基準框架。

FABEO 是第一個同時具備下列四項重要特性的配對（Pairing-based）屬性加密方案：
1. **表達力強（Expressive Policies）**：支援任意單調布林公式（Monotone Boolean Formulas）與單調跨度程式（Monotone Span Programs, MSP），並進一步拓展至正規語言（Deterministic Finite Automata, DFA）。
2. **無限制策略與屬性（Unrestricted Policies & Arbitrary Attributes）**：不限制策略大小或屬性數量，允許任意字串（例如身分證號、部門名稱、URL）作為屬性。
3. **極致解密效能（Fast Decryption via Randomness Reuse）**：解密配對運算次數與屬性數量脫鉤，CP-ABE 僅需 $\tau + 2$ 次配對，KP-ABE 僅需 $\tau + 1$ 次配對（無屬性重複使用時分別僅需 **3 次** 與 **2 次** 配對）。
4. **最優自適應安全性（Optimal Adaptive Security）**：在通用群模型（Generic Bilinear Group Model, GGM）與隨機預言機模型（Random Oracle Model, ROM）下，首創達成面對任意多次密文與金鑰查詢的最優緊緻安全界線 $O(t^2/p)$。

---

## 專案架構概覽 (Architecture)

```text
FABEO/
├── core/
│   ├── pairing_group.py      # Type-III 非對稱雙線性配對群引擎 (G1, G2, GT, Zp, Hash-to-G1, 計數器)
│   ├── msp.py                # 單調跨度程式 (MSP) 與 Lewko-Waters 布林策略編譯器 (高斯消去求解器)
│   ├── dfa.py                # 確定有限狀態自動機 (DFA) 引擎與執行路徑追蹤器
│   ├── dem.py                # 資料封裝機制 (DEM: HKDF-SHA256 + 認證對稱加密)
│   ├── metrics.py            # 評測指標結構體 (時間、運算計數、密鑰與密文大小)
│   └── profiler.py           # 奈秒級高精確度計時器
├── schemes/
│   ├── base_abe.py           # ABE 方案抽象基類 (Setup, KeyGen, Encrypt, Decrypt)
│   ├── fabeo_cp.py           # 論文 Figure 1 (左): FABEO CP-ABE (支援屬性重複使用 tau)
│   ├── fabeo_kp.py           # 論文 Figure 1 (右): FABEO KP-ABE (支援屬性重複使用 tau)
│   ├── fabeo_dfa.py          # 論文 Figure 4: FABEO DFA KP-ABE (正規語言字串存取控制)
│   ├── abgw_cp.py            # Baseline: ABGW CP-ABE (Ambrona et al., CCS 2017 / 附錄 C)
│   ├── abgw_kp.py            # Baseline: ABGW KP-ABE (Ambrona et al., CCS 2017 / 附錄 C)
│   ├── bsw_cp.py             # Baseline: BSW CP-ABE (Bethencourt et al., S&P 2007)
│   └── fame_cp.py            # Baseline: FAME CP-ABE (Agrawal & Chase, CCS 2017)
├── runner/
│   └── benchmark_runner.py   # 自動化跨論文評測執行器 (複現論文第 7 節實驗)
├── analysis/
│   ├── exporter.py           # 評測數據結構化匯出 (JSON 與 CSV)
│   └── plotter.py            # 格式化學術對比表與加速比分析報告輸出
├── tests/
│   ├── test_pairing.py       # 雙線性、非退化性、群哈希與序列化測試
│   ├── test_msp.py           # 策略解析、門邏輯編譯、多重使用參數 tau 求解測試
│   ├── test_fabeo_cp.py      # FABEO CP-ABE 授權解密、非授權拒絕與多重屬性測試
│   ├── test_fabeo_kp.py      # FABEO KP-ABE 金鑰策略測試
│   ├── test_fabeo_dfa.py     # FABEO DFA 正規語言匹配與拒絕測試
│   └── test_baselines.py     # 各基準方案 (BSW, ABGW) 正確性驗證
├── results/                  # 評測輸出資料夾 (benchmark_summary.csv / .json)
├── tool.py                   # 統整高階 API (混合加密 PKE/DEM, 金鑰/密文封裝與解封)
├── main.py                   # 命令行主入口 CLI (demo, benchmark, test)
└── requirements.txt          # 依賴配置 (預設採用純標準函式庫，零強制作業依賴)
```

---

## 方案理論比較 (Theoretical Comparison)

對應論文 **Table 1**、**Table 3** 與 **Table 5**：

### 1. 特性綜合對比 (Table 1)

| 方案 (Scheme) | 無限制策略 (Unrestricted Policies) | 任意字串屬性 (Arbitrary Attributes) | 快速解密 (Fast Decryption) | 屬性多重使用 (Multi-use) | 多密文安全界線 (Security Bound) |
|:---|:---:|:---:|:---:|:---:|:---:|
| **BSW [12]** | ✓ | ✓ | ✗ | ✓ | $O(t^3/p)$ |
| **Waters [52]** | ✓ | ✗ | ✗ | ✓ | Selective |
| **ABGW [6]** | ✓ | ✓ | ✗ | ✓ | $O(t^4/p)$ |
| **FAME [2]** | ✓ | ✓ | ✓ | ✗ ($\hat{\tau}=1$) | $O(t^4/p)$ |
| **FABEO (Ours)** | **✓** | **✓** | **✓** | **✓** | **$O(t^2/p)$ (Optimal)** |

### 2. 解密配對次數與群元素大小對比 (Table 3 & Table 5, $\tau=1$)

| 方案 | CP-ABE 解密配對 | KP-ABE 解密配對 | CP 密鑰大小 ($G_1, G_2$) | CP 密文大小 ($G_1, G_2$) | KP 密鑰大小 ($G_1, G_2$) | KP 密文大小 ($G_1, G_2$) |
|:---|:---:|:---:|:---:|:---:|:---:|:---:|
| **BSW** | $2I + 1$ | — | $m+1, m$ | $n_1, n_1+1$ | — | — |
| **ABGW** | $I + 2$ | $2I$ | $0, m+2$ | $3n_1, 0$ | $0, 2n_1$ | $2m, 0$ |
| **FAME** | $6$ | $6$ | $3m+3, 3$ | $3n_1, 3$ | $3n_1, 3$ | $3m, 3$ |
| **FABEO (Ours)** | **$3$** | **$2$** | **$m+1, 1$** | **$n_1, 2$** | **$n_1, 1$** | **$m, 1$** |

> 註：$m$ 為屬性集合大小，$n_1$ 為策略行數（屬性子句數），$I$ 為解密使用的屬性子集大小。在 100 個屬性的場景下，FABEO 的解密配對次數比 BSW 少 **98.5%**，密文與密鑰體積大幅縮減 **60% ~ 66%**。

---

## 快速使用教學 (Quickstart)

本專案經過精心設計，採用 Python 3.8+ 原生標準庫（`hashlib`, `hmac`, `secrets`）即可直接完整運行，無需預先編譯複雜的 C 底層密碼庫。

### 1. 執行單元與整合測試
```bash
python3 FABEO/main.py test
```
> 將自動遍歷 14 項測試，覆蓋 Type-III 配對群運算、MSP 策略編譯器、CP-ABE / KP-ABE / DFA 以及所有 Baseline 方案。

### 2. 執行完整端到端展示 (Demo)
```bash
python3 FABEO/main.py demo
```
輸出範例：
- **CP-ABE**：醫學機密病歷授權解密與非授權拒絕。
- **Multi-Use CP-ABE**：屬性重複使用 `(A and B) or (A and C)` 成功解密。
- **KP-ABE**：金鑰存取策略 `FACILITY:LAB_A and CLEARANCE:LEVEL_3` 加解密。
- **DFA KP-ABE**：基因 DNA 序列特徵字串（如 `CGTA`）正規語言匹配解密。

### 3. 執行跨論文效能基準測試 (Benchmark)
```bash
python3 FABEO/main.py benchmark --attributes 10,20,50,100 --trials 3
```
> 測試結果將即時輸出為對齊終端表格，並同步輸出結構化數據至 `results/benchmark_summary.csv` 與 `results/benchmark_summary.json`。

---

## Python API 使用範例

### Ciphertext-Policy ABE (CP-ABE 混合加密)

```python
from FABEO.tool import FabeoTool

tool = FabeoTool()

# 1. 系統初始化 (Setup)
mpk, msk = tool.cp_setup()

# 2. 針對使用者的屬性核發私鑰 (KeyGen)
user_attrs = {"DEPT_ENGINEERING", "ROLE_SECURITY"}
sk = tool.cp_keygen(msk, user_attrs)

# 3. 指定存取策略並加密高敏感機密資料 (Encrypt)
policy = "(DEPT_ENGINEERING AND ROLE_SECURITY) OR ROLE_ADMIN"
plaintext = b"DATABASE_PASSWORD=SuperSecretKey123!"
package = tool.cp_encrypt_message(mpk, policy, plaintext)

# 4. 具備合法屬性的使用者解密 (Decrypt)
decrypted = tool.cp_decrypt_message(mpk, package, sk)
print(decrypted.decode())  # "DATABASE_PASSWORD=SuperSecretKey123!"
```

### Deterministic Finite Automata (DFA KP-ABE)

```python
from FABEO.tool import FabeoTool
from FABEO.core.dfa import DFA

tool = FabeoTool()
alphabet = set("ACGT")

# 建立搜尋特定 DNA 片段 "CGTA" 的自動機
dfa = DFA.from_pattern_substring("CGTA", alphabet)
mpk, msk = tool.dfa_setup(alphabet)
sk = tool.dfa_keygen(msk, dfa)

# 當輸入的 DNA 字串包含此片段時即可解密
stream = "AACGTAGGCT"
pkg = tool.dfa_encrypt_message(mpk, stream, b"Pathogen Marker Verified")
print(tool.dfa_decrypt_message(mpk, pkg, sk).decode())
```

---

## 授權 (License)

本專案遵循 MIT 開源授權協議。
詳細演算法與安全性證明請參閱原論文：
> Doreen Riepel and Hoeteck Wee. "FABEO: Fast Attribute-Based Encryption with Optimal Security." In *Proceedings of the 2022 ACM SIGSAC Conference on Computer and Communications Security (CCS '22)* / *Cryptology ePrint Archive, Report 2022/1093*.
