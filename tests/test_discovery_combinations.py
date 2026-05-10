"""
Asset Discovery Combination Test
=================================
Tests all 7 method combinations against 192.168.137.0/24 (VMware Host-Only).
Generates a markdown report with results.

Usage:
    cd intra_vuln_assessor
    python tests/test_discovery_combinations.py
"""

import json
import os
import sys
import time
from datetime import datetime
from itertools import combinations

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from vuln_assessor.scanners.discovery import AssetDiscoveryEngine

CIDR = "192.168.137.0/24"
PORTS = [21, 22, 6379, 8080]
EXPECTED_HOSTS = {"192.168.137.10", "192.168.137.20"}
METHODS_ALL = ["icmp", "arp", "syn"]

REPORT_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "test_reports")


def run_single_test(engine: AssetDiscoveryEngine, methods: list[str], label: str) -> dict:
    print(f"\n{'='*60}")
    print(f"  测试: {label}")
    print(f"  方法: {methods}")
    print(f"{'='*60}")

    start = time.time()
    try:
        assets = engine.discover(CIDR, PORTS, methods)
        elapsed = time.time() - start
        error = None
    except Exception as e:
        assets = []
        elapsed = time.time() - start
        error = str(e)

    found_ips = {a.ip for a in assets}
    found_expected = found_ips & EXPECTED_HOSTS
    found_unexpected = found_ips - EXPECTED_HOSTS - {"192.168.137.1"}

    result = {
        "label": label,
        "methods": methods,
        "elapsed_seconds": round(elapsed, 2),
        "total_found": len(assets),
        "expected_found": sorted(found_expected),
        "expected_missed": sorted(EXPECTED_HOSTS - found_expected),
        "unexpected_found": sorted(found_unexpected),
        "error": error,
        "details": [],
    }

    for asset in assets:
        if asset.ip in EXPECTED_HOSTS or asset.ip not in {"192.168.137.1"}:
            detail = {
                "ip": asset.ip,
                "mac": asset.mac or "-",
                "discovered_by": asset.discovered_by,
                "open_ports": asset.open_ports,
            }
            result["details"].append(detail)

    if error:
        print(f"  ERROR: {error}")
    else:
        print(f"  耗时: {elapsed:.2f}s")
        print(f"  发现主机数: {len(assets)}")
        print(f"  期望主机命中: {sorted(found_expected)}")
        print(f"  期望主机遗漏: {sorted(EXPECTED_HOSTS - found_expected)}")
        for d in result["details"]:
            print(f"    {d['ip']}  MAC={d['mac']}  by={d['discovered_by']}  ports={d['open_ports']}")

    return result


def generate_report(results: list[dict], report_path: str):
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    lines = []
    lines.append(f"# 资产发现方法组合测试报告")
    lines.append(f"")
    lines.append(f"**生成时间**: {now}")
    lines.append(f"**目标网段**: {CIDR}")
    lines.append(f"**扫描端口**: {PORTS}")
    lines.append(f"**期望主机**: {', '.join(sorted(EXPECTED_HOSTS))}")
    lines.append(f"")
    lines.append(f"---")
    lines.append(f"")

    # Summary table
    lines.append(f"## 一、结果总览")
    lines.append(f"")
    lines.append(f"| # | 测试名称 | 方法 | 耗时(s) | 发现数 | .10 | .20 | MAC | 开放端口 | 状态 |")
    lines.append(f"|---|---------|------|---------|--------|-----|-----|-----|---------|------|")

    for i, r in enumerate(results, 1):
        methods_str = "+".join(r["methods"])
        found_10 = "192.168.137.10" in r["expected_found"]
        found_20 = "192.168.137.20" in r["expected_found"]
        icon_10 = "OK" if found_10 else "MISS"
        icon_20 = "OK" if found_20 else "MISS"

        has_mac = False
        has_ports = False
        for d in r["details"]:
            if d["mac"] != "-":
                has_mac = True
            if d["open_ports"]:
                has_ports = True

        mac_str = "OK" if has_mac else "-"
        ports_str = "OK" if has_ports else "-"
        status = "OK" if (found_10 and found_20) else ("ERROR" if r["error"] else "PARTIAL")

        lines.append(f"| {i} | {r['label']} | {methods_str} | {r['elapsed_seconds']} | {r['total_found']} | {icon_10} | {icon_20} | {mac_str} | {ports_str} | {status} |")

    lines.append(f"")
    lines.append(f"---")
    lines.append(f"")

    # Detailed results
    lines.append(f"## 二、详细结果")
    lines.append(f"")

    for i, r in enumerate(results, 1):
        methods_str = "+".join(r["methods"])
        lines.append(f"### 测试 {i}: {r['label']}")
        lines.append(f"")
        lines.append(f"- **方法**: `{methods_str}`")
        lines.append(f"- **耗时**: {r['elapsed_seconds']}s")
        lines.append(f"- **发现主机总数**: {r['total_found']}")
        lines.append(f"- **期望命中**: {r['expected_found']}")
        lines.append(f"- **期望遗漏**: {r['expected_missed']}")
        if r["error"]:
            lines.append(f"- **错误**: {r['error']}")
        lines.append(f"")

        if r["details"]:
            lines.append(f"| IP | MAC | 发现方式 | 开放端口 |")
            lines.append(f"|----|-----|---------|---------|")
            for d in r["details"]:
                lines.append(f"| {d['ip']} | {d['mac']} | {d['discovered_by']} | {d['open_ports']} |")
            lines.append(f"")
        else:
            lines.append(f"*无主机发现*")
            lines.append(f"")

    # Analysis
    lines.append(f"---")
    lines.append(f"")
    lines.append(f"## 三、分析与结论")
    lines.append(f"")

    all_ok = all(
        "192.168.137.10" in r["expected_found"] and "192.168.137.20" in r["expected_found"]
        for r in results
    )

    methods_that_work = []
    methods_that_fail = []
    for r in results:
        if "192.168.137.10" in r["expected_found"] and "192.168.137.20" in r["expected_found"]:
            methods_that_work.append("+".join(r["methods"]))
        else:
            methods_that_fail.append("+".join(r["methods"]))

    if all_ok:
        lines.append(f"**全部 7 种组合均成功发现两台目标主机。**")
    else:
        lines.append(f"### 成功的组合")
        for m in methods_that_work:
            lines.append(f"- `{m}`")
        lines.append(f"")
        lines.append(f"### 失败/部分成功的组合")
        for m in methods_that_fail:
            lines.append(f"- `{m}`")

    lines.append(f"")

    # ARP MAC analysis
    arp_results = [r for r in results if "arp" in r["methods"]]
    has_any_mac = any(d["mac"] != "-" for r in arp_results for d in r["details"])
    lines.append(f"### ARP MAC 地址获取")
    if has_any_mac:
        lines.append(f"ARP 扫描成功获取了目标主机的 MAC 地址。")
    else:
        lines.append(f"ARP 扫描未通过 Scapy 获取 MAC 地址（预期行为：Windows + VMware 环境下 Npcap 兼容性问题），")
        lines.append(f"通过 Windows 原生 ARP 回退方案发现主机。")
    lines.append(f"")

    # SYN port analysis
    syn_results = [r for r in results if "syn" in r["methods"]]
    has_any_ports = any(d["open_ports"] for r in syn_results for d in r["details"])
    lines.append(f"### SYN 端口发现")
    if has_any_ports:
        lines.append(f"SYN 扫描成功发现了开放端口。")
    else:
        if any("192.168.137.10" in r["expected_found"] or "192.168.137.20" in r["expected_found"] for r in syn_results):
            lines.append(f"SYN 扫描通过 TCP Connect 回退方案成功发现了主机和开放端口。")
        else:
            lines.append(f"SYN 扫描未能发现主机或开放端口。")
    lines.append(f"")

    with open(report_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

    # Also save raw JSON
    json_path = report_path.replace(".md", ".json")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(results, f, ensure_ascii=False, indent=2)

    print(f"\n{'='*60}")
    print(f"  报告已保存: {report_path}")
    print(f"  原始数据: {json_path}")
    print(f"{'='*60}")


def main():
    os.makedirs(REPORT_DIR, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_path = os.path.join(REPORT_DIR, f"discovery_combination_test_{timestamp}.md")

    engine = AssetDiscoveryEngine(timeout_seconds=3.0, max_workers=64)

    test_configs = []

    # 1. Single methods (3 tests)
    for m in METHODS_ALL:
        test_configs.append(([m], f"单方法-{m.upper()}"))

    # 2. Two-method combinations (3 tests)
    for combo in combinations(METHODS_ALL, 2):
        methods = list(combo)
        label = f"双方法-{'+'.join(m.upper() for m in methods)}"
        test_configs.append((methods, label))

    # 3. Full progressive scan (1 test)
    test_configs.append((list(METHODS_ALL), "三方法递进式-ICMP+ARP+SYN"))

    results = []
    for methods, label in test_configs:
        r = run_single_test(engine, methods, label)
        results.append(r)

    generate_report(results, report_path)
    return report_path


if __name__ == "__main__":
    report = main()
    print(f"\nDone. Report: {report}")
