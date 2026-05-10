# 项目测试报告

更新时间：`2026-04-13`

本文档用于说明当前项目已经完成了哪些测试、留档放在哪里、结论是什么。

## 1. 测试目标

本轮测试重点覆盖：

- GUI 主流程可用性
- 本地靶场链路可复现性
- 扫描方式组合行为
- 主动探测与弱口令尝试对结果的影响
- Web 报告中心、报告删除、历史对比

## 2. 自动化回归

执行命令：

```powershell
python -m unittest tests.test_auth_probes tests.test_active_checks tests.test_confidence_tiers tests.test_config_parse_ports tests.test_desktop_gui_workflows tests.test_desktop_web_control tests.test_discovery_platform tests.test_gui_launcher tests.test_lab_manager tests.test_orchestrator_active_checks tests.test_workbench_flow -v
```

结果：

- `51/51 OK`

说明：

- GUI 工作流
- 主动探测
- 弱口令探测
- 发现平台差异
- Web 报告中心
- 本地靶场管理

均已纳入自动化验证。

## 3. GUI 冒烟测试

本轮做了一次按“真实用户点击顺序”组织的 GUI 冒烟，留档在：

- [gui_smoke_summary.json](/C:/Users/Administrator/Desktop/Yu_workspace/intra_vuln_assessor/data/manual_gui_smoke_sameproc_20260413/gui_smoke_summary.json)

测试覆盖：

- 资产发现 4 轮
- 规则导入 1 轮
- 分析 4 轮
- 报告对比 1 轮
- Web 报告中心启动与访问
- 资产报告删除与分析报告删除

### 3.1 关键结果

- 默认分析：`4` 个服务，`10` 个风险
- 关闭主动探测：`4` 个服务，`8` 个风险
- 加载资产画像：`4` 个服务，`10` 个风险，最高分由 `8.68` 抬升到 `8.88`
- 再开启弱口令尝试：`4` 个服务，`11` 个风险

对应代表性报告：

- [gui_analysis_no_active/report.html](/C:/Users/Administrator/Desktop/Yu_workspace/intra_vuln_assessor/data/manual_gui_smoke_sameproc_20260413/reports/gui_analysis_no_active/report.html)
- [gui_analysis_profiled/report.html](/C:/Users/Administrator/Desktop/Yu_workspace/intra_vuln_assessor/data/manual_gui_smoke_sameproc_20260413/reports/gui_analysis_profiled/report.html)
- [gui_analysis_auth/report.html](/C:/Users/Administrator/Desktop/Yu_workspace/intra_vuln_assessor/data/manual_gui_smoke_sameproc_20260413/reports/gui_analysis_auth/report.html)

## 4. 扫描方式组合矩阵

扫描组合矩阵留档在：

- [combo_results.json](/C:/Users/Administrator/Desktop/Yu_workspace/intra_vuln_assessor/data/manual_combo_matrix_20260413/combo_results.json)

本轮在本地回环靶场 `127.0.0.0/29` 上的结果为：

- `icmp` -> 发现 `6`
- `arp` -> 发现 `0`
- `syn` -> 发现 `0`
- `icmp,arp` -> 发现 `6`
- `icmp,syn` -> 发现 `6`
- `arp,syn` -> 发现 `0`
- `icmp,arp,syn` -> 发现 `6`

结论：

- 本地回环靶场适合验证 `ICMP`
- `ARP/SYN` 在这套靶场里没有真实二层意义，不适合作为“是否发现主机”的主验证项

## 5. 自定义扫描方式验证

我额外验证了 GUI 的“自定义扫描方式”本身是否真的生效，留档在：

- [gui_custom_icmp_syn/report.html](/C:/Users/Administrator/Desktop/Yu_workspace/intra_vuln_assessor/data/gui_custom_preset_check_20260413/reports/gui_custom_icmp_syn/report.html)

结论：

- `icmp,syn` 组合会正确写入快照
- GUI 自定义模式本身是有效的

## 6. Web 报告中心验证

GUI 冒烟中已验证：

- `/`
- `/scan/<id>`
- `/report/<id>`

都能返回 `200` 并正确展示 HTML。

同时已验证：

- GUI 中删除报告
- Web 报告中心访问报告
- 历史对比页面生成

## 7. 当前非阻塞项

### 7.1 Windows 回环靶场限制

当前回环靶场并不适合验证：

- 真实 ARP 探测
- 真实公网 / 局域网路由行为

这属于实验环境边界，不是程序阻塞缺陷。

### 7.2 `test_lab_manager` 的 `ResourceWarning`

当前自动化测试中，`test_lab_manager` 仍会打印一条子进程相关 `ResourceWarning`。  
这条告警不影响：

- 靶场启动
- 扫描结果
- GUI 使用

目前判断为非阻塞问题。

## 8. 外网验证现状

本轮没有直接对第三方公网靶场发起扫描。  
原因：

- 需要明确授权边界
- 不应默认对第三方公网资产做验证

如果后续要做“外部网络验证”，请按：

- [SECURITY_ETHICS.md](./SECURITY_ETHICS.md)
- [external_validation_manual.md](./external_validation_manual.md)

执行。
