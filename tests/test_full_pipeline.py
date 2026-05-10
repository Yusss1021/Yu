"""
Full Pipeline Test — Service Identification & Vulnerability Matching
=====================================================================
Simulates GUI operations against 192.168.137.10 and 192.168.137.20.
Tests all stages: discovery → service fingerprint → vuln matching → active checks → risk evaluation.

Usage:
    cd intra_vuln_assessor
    python tests/test_full_pipeline.py
"""

import json
import os
import sys
import time
import shutil
from datetime import datetime
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from vuln_assessor.models import HostAsset, ServiceFingerprint, VulnerabilityFinding
from vuln_assessor.orchestrator import ScanOrchestrator
from vuln_assessor.scanners.service_fingerprint import ServiceFingerprintEngine
from vuln_assessor.vuln import VulnerabilityMatcher
from vuln_assessor.active_checks import ActiveCheckEngine
from vuln_assessor.risk import RiskEvaluator
from vuln_assessor.storage import ScanRepository
from vuln_assessor.config import RULE_FILE_PATH

CIDR = "192.168.137.0/24"
TARGET_IPS = ["192.168.137.10", "192.168.137.20"]
PORTS = [21, 22, 6379, 8080]
REPORT_DIR = Path(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))) / "test_reports"
DB_PATH = REPORT_DIR / "test_pipeline.db"


def section(title: str):
    print(f"\n{'='*70}")
    print(f"  {title}")
    print(f"{'='*70}\n")


def test_1_nmap_available() -> bool:
    """Check if nmap is installed and accessible."""
    section("测试 1: Nmap 可用性检查")
    nmap_path = shutil.which("nmap")
    if nmap_path:
        print(f"  OK: nmap found at {nmap_path}")
        os.system("nmap --version 2>&1 | head -2")
        return True
    else:
        print("  FAIL: nmap not found in PATH!")
        return False


def test_2_service_fingerprint(assets: list[HostAsset]) -> list[dict]:
    """Test service fingerprinting via Nmap."""
    section("测试 2: 服务指纹识别 (Nmap -sV -Pn)")
    engine = ServiceFingerprintEngine()

    start = time.time()
    services = engine.fingerprint(
        assets=assets,
        fallback_ports=PORTS,
        nmap_arguments=["-sV", "-Pn", "--version-intensity", "5"],
        require_nmap=True,
    )
    elapsed = time.time() - start

    print(f"  耗时: {elapsed:.2f}s")
    print(f"  发现服务数: {len(services)}")
    print()

    results = []
    for svc in services:
        detail = {
            "host_ip": svc.host_ip,
            "port": svc.port,
            "protocol": svc.protocol,
            "service_name": svc.service_name,
            "product": svc.product or "-",
            "version": svc.version or "-",
            "fingerprint_method": svc.fingerprint_method,
            "fingerprint_confidence": svc.fingerprint_confidence,
        }
        results.append(detail)
        print(f"  {svc.host_ip}:{svc.port}  {svc.service_name}  "
              f"{svc.product or '-'}/{svc.version or '-'}  "
              f"[{svc.fingerprint_method}, conf={svc.fingerprint_confidence}]")

    expected_services = [
        ("192.168.137.10", 22, "ssh"),
        ("192.168.137.10", 8080, "http"),
        ("192.168.137.20", 21, "ftp"),
        ("192.168.137.20", 6379, "redis"),
    ]
    print(f"\n  期望服务验证:")
    for ip, port, svc_name in expected_services:
        found = any(s.host_ip == ip and s.port == port for s in services)
        status = "OK" if found else "MISS"
        print(f"    {ip}:{port} ({svc_name}): {status}")

    return results


def test_3_vuln_matching(services: list[ServiceFingerprint]) -> list[dict]:
    """Test vulnerability rule matching."""
    section("测试 3: 漏洞规则匹配")
    matcher = VulnerabilityMatcher(RULE_FILE_PATH)

    start = time.time()
    vulns = matcher.match(services)
    elapsed = time.time() - start

    print(f"  耗时: {elapsed:.4f}s")
    print(f"  匹配漏洞数: {len(vulns)}")
    print()

    results = []
    for v in vulns:
        detail = {
            "host_ip": v.host_ip,
            "port": v.port,
            "cve_id": v.cve_id,
            "severity": v.severity,
            "cvss_score": v.cvss,
            "description": v.description[:60] if v.description else "-",
            "confidence_tier": getattr(v, "confidence_tier", "-"),
        }
        results.append(detail)
        print(f"  {v.host_ip}:{v.port}  {v.cve_id}  severity={v.severity}  "
              f"cvss={v.cvss}  conf={getattr(v, 'confidence_tier', '-')}")

    if not vulns:
        print("  WARNING: 没有匹配到任何漏洞！检查 rules.json 是否包含 OpenSSH/nginx/vsftpd/Redis 规则。")

    return results


def test_4_active_checks(assets: list[HostAsset], services: list[ServiceFingerprint]) -> list[dict]:
    """Test active vulnerability probes (FTP anon, Redis unauth)."""
    section("测试 4: 主动探测 (FTP匿名 / Redis未授权)")
    engine = ActiveCheckEngine(timeout_seconds=5.0)

    start = time.time()
    findings = engine.run(
        assets=assets,
        services=services,
        fallback_ports=PORTS,
        enable_auth_checks=False,
    )
    elapsed = time.time() - start

    print(f"  耗时: {elapsed:.2f}s")
    print(f"  主动探测发现数: {len(findings)}")
    print()

    results = []
    for f in findings:
        detail = {
            "host_ip": f.host_ip,
            "port": f.port,
            "cve_id": f.cve_id,
            "severity": f.severity,
            "description": f.description[:80] if f.description else "-",
        }
        results.append(detail)
        print(f"  {f.host_ip}:{f.port}  {f.cve_id}  severity={f.severity}")
        print(f"    {f.description[:80] if f.description else '-'}")

    expected_checks = [
        ("192.168.137.20", 21, "FTP 匿名访问"),
        ("192.168.137.20", 6379, "Redis 未授权"),
    ]
    print(f"\n  期望主动探测验证:")
    for ip, port, desc in expected_checks:
        found = any(f.host_ip == ip and f.port == port for f in findings)
        status = "OK" if found else "MISS"
        print(f"    {ip}:{port} ({desc}): {status}")

    return results


def test_5_auth_checks(assets: list[HostAsset], services: list[ServiceFingerprint]) -> list[dict]:
    """Test weak credential probes (FTP/SSH)."""
    section("测试 5: 弱口令探测 (FTP/SSH)")
    engine = ActiveCheckEngine(timeout_seconds=5.0)

    start = time.time()
    findings = engine.run(
        assets=assets,
        services=services,
        fallback_ports=PORTS,
        enable_auth_checks=True,
    )
    elapsed = time.time() - start

    print(f"  耗时: {elapsed:.2f}s")
    print(f"  弱口令探测发现数: {len(findings)}")
    print()

    results = []
    for f in findings:
        detail = {
            "host_ip": f.host_ip,
            "port": f.port,
            "cve_id": f.cve_id,
            "severity": f.severity,
            "description": f.description[:80] if f.description else "-",
        }
        results.append(detail)
        print(f"  {f.host_ip}:{f.port}  {f.cve_id}  severity={f.severity}")
        print(f"    {f.description[:80] if f.description else '-'}")

    return results


def test_6_risk_evaluation(vulns: list[VulnerabilityFinding]) -> list[dict]:
    """Test multi-factor risk evaluation."""
    section("测试 6: 多因子风险评估")
    evaluator = RiskEvaluator()

    start = time.time()
    risks = evaluator.evaluate(vulns)
    elapsed = time.time() - start

    print(f"  耗时: {elapsed:.4f}s")
    print(f"  风险条目数: {len(risks)}")
    print()

    results = []
    for r in risks:
        detail = {
            "host_ip": r.host_ip,
            "port": r.port,
            "cve_id": r.cve_id,
            "risk_level": r.risk_level,
            "risk_score": r.risk_score,
            "cvss_score": r.cvss,
            "confidence_tier": getattr(r, "confidence_tier", "-"),
        }
        results.append(detail)
        print(f"  {r.host_ip}:{r.port}  {r.cve_id}  "
              f"level={r.risk_level}  score={r.risk_score}  cvss={r.cvss}")

    # Summary by level
    levels = {}
    for r in risks:
        levels[r.risk_level] = levels.get(r.risk_level, 0) + 1
    print(f"\n  风险等级分布: {dict(sorted(levels.items()))}")

    return results


def test_7_full_orchestrator() -> dict:
    """Test full orchestrator pipeline (same as GUI 'analyze_target')."""
    section("测试 7: 完整编排流程 (模拟 GUI 操作)")

    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    if DB_PATH.exists():
        DB_PATH.unlink()

    repository = ScanRepository(DB_PATH)
    repository.initialize()
    orchestrator = ScanOrchestrator(repository)

    print(f"  目标: {CIDR}")
    print(f"  端口: {PORTS}")
    print(f"  方法: icmp (仅用于快速发现)")
    print(f"  Nmap参数: -sV -Pn --version-intensity 5")
    print(f"  主动探测: 开启")
    print(f"  弱口令探测: 开启")
    print()

    start = time.time()
    result = orchestrator.run_scan(
        target_cidr=CIDR,
        methods=["icmp"],
        ports=PORTS,
        output_dir=REPORT_DIR,
        scan_name="pipeline_test",
        nmap_arguments=["-sV", "-Pn", "--version-intensity", "5"],
        require_nmap=True,
        enable_active_checks=True,
        enable_auth_checks=True,
    )
    elapsed = time.time() - start

    print(f"  总耗时: {elapsed:.2f}s")
    print(f"  扫描ID: {result['scan_id']}")
    print(f"  发现主机: {result['total_hosts']}")
    print(f"  服务数: {result['total_services']}")
    print(f"  风险数: {result['total_risks']}")
    print(f"  报告路径: {result['report_path']}")
    print()

    # Verify data can be read back (tests the display path)
    scan_id = int(result["scan_id"])
    services_from_db = repository.get_services(scan_id)
    vulns_from_db = repository.get_vulnerabilities(scan_id)

    print(f"  数据库读回验证:")
    print(f"    services (DB): {len(services_from_db)} 条")
    print(f"    vulnerabilities (DB): {len(vulns_from_db)} 条")

    if not services_from_db:
        print("    WARNING: 数据库中无服务记录！这会导致 GUI 显示为空！")
    if not vulns_from_db:
        print("    WARNING: 数据库中无漏洞记录！这可能导致 GUI '漏洞匹配结果' 为空！")

    return {
        "scan_id": scan_id,
        "result": result,
        "services_from_db": services_from_db,
        "vulns_from_db": vulns_from_db,
    }


def generate_report(all_results: dict, report_path: str):
    """Generate markdown test report."""
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    lines = []
    lines.append("# 漏洞匹配与服务识别 — 全流程测试报告")
    lines.append("")
    lines.append(f"**测试时间**: {now}")
    lines.append(f"**目标网段**: {CIDR}")
    lines.append(f"**目标主机**: {', '.join(TARGET_IPS)}")
    lines.append(f"**扫描端口**: {PORTS}")
    lines.append("")
    lines.append("---")
    lines.append("")

    # Test 1: Nmap
    lines.append("## 测试 1: Nmap 可用性")
    lines.append(f"- 状态: {'PASS' if all_results.get('nmap_ok') else 'FAIL'}")
    lines.append("")

    # Test 2: Service Fingerprint
    lines.append("## 测试 2: 服务指纹识别")
    svcs = all_results.get("services", [])
    lines.append(f"- 发现服务数: {len(svcs)}")
    lines.append("")
    if svcs:
        lines.append("| 主机 | 端口 | 服务 | 产品 | 版本 | 方法 | 置信度 |")
        lines.append("|------|------|------|------|------|------|--------|")
        for s in svcs:
            lines.append(f"| {s['host_ip']} | {s['port']} | {s['service_name']} | {s['product']} | {s['version']} | {s['fingerprint_method']} | {s['fingerprint_confidence']} |")
    lines.append("")

    # Test 3: Vuln Matching
    lines.append("## 测试 3: 漏洞规则匹配")
    vulns = all_results.get("vulns", [])
    lines.append(f"- 匹配漏洞数: {len(vulns)}")
    lines.append("")
    if vulns:
        lines.append("| 主机 | 端口 | CVE ID | 严重度 | CVSS | 置信度 |")
        lines.append("|------|------|--------|--------|------|--------|")
        for v in vulns:
            lines.append(f"| {v['host_ip']} | {v['port']} | {v['cve_id']} | {v['severity']} | {v['cvss_score']} | {v['confidence_tier']} |")
    lines.append("")

    # Test 4: Active Checks
    lines.append("## 测试 4: 主动探测")
    active = all_results.get("active_checks", [])
    lines.append(f"- 发现数: {len(active)}")
    lines.append("")
    if active:
        lines.append("| 主机 | 端口 | CVE/类型 | 严重度 | 描述 |")
        lines.append("|------|------|----------|--------|------|")
        for a in active:
            lines.append(f"| {a['host_ip']} | {a['port']} | {a['cve_id']} | {a['severity']} | {a['description'][:50]} |")
    lines.append("")

    # Test 5: Auth Checks
    lines.append("## 测试 5: 弱口令探测")
    auth = all_results.get("auth_checks", [])
    lines.append(f"- 发现数: {len(auth)}")
    lines.append("")
    if auth:
        lines.append("| 主机 | 端口 | CVE/类型 | 严重度 | 描述 |")
        lines.append("|------|------|----------|--------|------|")
        for a in auth:
            lines.append(f"| {a['host_ip']} | {a['port']} | {a['cve_id']} | {a['severity']} | {a['description'][:50]} |")
    lines.append("")

    # Test 6: Risk Evaluation
    lines.append("## 测试 6: 风险评估")
    risks = all_results.get("risks", [])
    lines.append(f"- 风险条目数: {len(risks)}")
    lines.append("")
    if risks:
        lines.append("| 主机 | 端口 | CVE ID | 风险等级 | 风险分 | CVSS |")
        lines.append("|------|------|--------|---------|-------|------|")
        for r in risks:
            lines.append(f"| {r['host_ip']} | {r['port']} | {r['cve_id']} | {r['risk_level']} | {r['risk_score']} | {r['cvss_score']} |")
    lines.append("")

    # Test 7: Full Pipeline
    lines.append("## 测试 7: 完整编排 (GUI 模拟)")
    orch = all_results.get("orchestrator", {})
    if orch:
        res = orch.get("result", {})
        lines.append(f"- 扫描ID: {orch.get('scan_id')}")
        lines.append(f"- 发现主机: {res.get('total_hosts')}")
        lines.append(f"- 服务数: {res.get('total_services')}")
        lines.append(f"- 风险数: {res.get('total_risks')}")
        lines.append(f"- 报告路径: {res.get('report_path')}")
        lines.append(f"- DB服务数: {len(orch.get('services_from_db', []))}")
        lines.append(f"- DB漏洞数: {len(orch.get('vulns_from_db', []))}")
        lines.append("")
        if not orch.get("services_from_db"):
            lines.append("**BUG: 数据库中无服务记录，GUI 将显示空白！**")
        if not orch.get("vulns_from_db"):
            lines.append("**注意: 数据库中无漏洞匹配记录（可能是版本规则未覆盖当前安装版本）**")
    lines.append("")

    # Summary
    lines.append("---")
    lines.append("")
    lines.append("## 总结")
    lines.append("")
    total_pass = sum(1 for k in ["nmap_ok", "services", "orchestrator"] if all_results.get(k))
    lines.append(f"- Nmap: {'OK' if all_results.get('nmap_ok') else 'FAIL'}")
    lines.append(f"- 服务识别: {'OK' if svcs else 'FAIL'} ({len(svcs)} 条)")
    lines.append(f"- 漏洞匹配: {'OK' if vulns else 'WARN-无匹配'} ({len(vulns)} 条)")
    lines.append(f"- 主动探测: {'OK' if active else 'WARN'} ({len(active)} 条)")
    lines.append(f"- 弱口令: {len(auth)} 条")
    lines.append(f"- 风险评估: {len(risks)} 条")
    lines.append(f"- 完整流程: {'OK' if orch.get('services_from_db') else 'FAIL'}")

    with open(report_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    print(f"\n报告已保存: {report_path}")


def main():
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_path = str(REPORT_DIR / f"full_pipeline_test_{timestamp}.md")

    all_results: dict = {}

    # Test 1: Nmap check
    all_results["nmap_ok"] = test_1_nmap_available()
    if not all_results["nmap_ok"]:
        print("\nFATAL: Nmap not available. Cannot proceed with service identification.")
        return

    # Prepare assets (bypass discovery — already tested separately)
    assets = [HostAsset(ip=ip) for ip in TARGET_IPS]

    # Test 2: Service Fingerprint
    svc_results = test_2_service_fingerprint(assets)
    all_results["services"] = svc_results

    # Build ServiceFingerprint objects for subsequent tests
    engine = ServiceFingerprintEngine()
    services = engine.fingerprint(
        assets=assets,
        fallback_ports=PORTS,
        nmap_arguments=["-sV", "-Pn", "--version-intensity", "5"],
        require_nmap=True,
    )

    # Test 3: Vuln Matching
    matcher = VulnerabilityMatcher(RULE_FILE_PATH)
    vuln_objects = matcher.match(services)
    all_results["vulns"] = test_3_vuln_matching(services)

    # Test 4: Active Checks (no auth)
    all_results["active_checks"] = test_4_active_checks(assets, services)

    # Test 5: Auth Checks
    all_results["auth_checks"] = test_5_auth_checks(assets, services)

    # Combine all findings for risk evaluation
    active_engine = ActiveCheckEngine(timeout_seconds=5.0)
    active_findings = active_engine.run(assets=assets, services=services, fallback_ports=PORTS, enable_auth_checks=True)
    all_vulns = list(vuln_objects) + list(active_findings)

    # Test 6: Risk Evaluation
    all_results["risks"] = test_6_risk_evaluation(all_vulns)

    # Test 7: Full Orchestrator (end-to-end like GUI)
    all_results["orchestrator"] = test_7_full_orchestrator()

    # Generate report
    generate_report(all_results, report_path)
    print(f"\nAll tests complete. Report: {report_path}")


if __name__ == "__main__":
    main()
