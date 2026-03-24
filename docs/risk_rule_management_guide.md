# 风险量化与规则管理说明

本说明用于回答三个问题：

1. 当前风险量化模型如何体现？
2. 风险模型如何改进？
3. 自动导入和手动导入规则哪个更适合本科毕业设计？

## 1. 当前风险量化模型体现

系统在 `vuln_assessor/risk/evaluator.py` 中实现风险评分，当前版本为 `v2`：

```text
Risk = 0.45*CVSS + 0.20*AssetCriticality + 0.15*PortExposure + 0.10*ExploitMaturity + 0.10*MatchConfidence
```

其中：

1. `CVSS`：漏洞基础分；
2. `AssetCriticality`：资产重要性；
3. `PortExposure`：暴露端口风险；
4. `ExploitMaturity`：漏洞可利用性；
5. `MatchConfidence`：匹配置信度（由服务识别完整度估计）。

风险等级划分：

1. `score >= 8.0` -> `HIGH`
2. `5.0 <= score < 8.0` -> `MEDIUM`
3. `< 5.0` -> `LOW`

## 2. 如何改进风险量化模型

建议按“可实现、可解释、可对比”推进：

1. 先固定可解释权重（当前已实现）；
2. 用 2 组数据对比（真实网络 + 可控靶场）；
3. 对比旧模型（仅 CVSS）与新模型（多因子）排序差异；
4. 统计 Top-N 风险变动，写入论文实验章节；
5. 在结论中说明参数可进一步数据驱动优化（AHP、回归等）。

推荐论文写法：

1. 先给出模型公式；
2. 再解释每个因子来源；
3. 最后给出案例（例如 SSH 漏洞 CVSS 高但综合风险受资产重要性/置信度影响）。

## 3. 规则库导入方式建议

### 3.1 手动导入

优点：

1. 规则质量可控，误报率低；
2. 结果稳定，实验易复现；
3. 答辩时逻辑清晰，老师容易认可。

缺点：

1. 维护成本高；
2. 更新速度慢。

### 3.2 自动导入

优点：

1. 更新快，覆盖面高；
2. 体现工程化能力。

缺点：

1. 数据清洗复杂；
2. 版本规则标准化难；
3. 误报和噪声可能增加。

### 3.3 本科毕设最佳实践（推荐）

采用“混合方案”：

1. 主实验使用手动精选规则（保证论文数据可信可复现）；
2. 增加自动更新能力作为扩展功能（体现系统创新与工程价值）。

## 4. 已实现命令

查看规则统计：

```bash
python3 main.py rules list
```

手动导入：

```bash
python3 main.py rules import --input docs/rules_feed.example.json --mode merge
```

自动更新：

```bash
python3 main.py rules update --url https://example.com/my_rules.json --mode merge
```

带资产画像扫描：

```bash
python3 main.py scan --target 127.0.0.1/32 --methods icmp --ports 2222,6379 --asset-profile docs/asset_profile.example.json
```

服务识别与漏洞匹配结果对比（CLI）：

```bash
python3 main.py compare --base 16 --new 17
```

Web 前端（含并发任务和结果对比页面）：

```bash
python3 main.py web --host 127.0.0.1 --port 5000 --max-concurrent 3
```
