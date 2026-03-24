# pyright: reportMissingImports=false
# pyright: reportMissingTypeArgument=false
# pyright: reportUnknownVariableType=false
# pyright: reportUnknownMemberType=false
# pyright: reportUnknownArgumentType=false
# pyright: reportUnusedCallResult=false
# pyright: reportImplicitStringConcatenation=false
# pyright: reportUnknownParameterType=false

from __future__ import annotations

import argparse
from pathlib import Path
from typing import cast

from vuln_assessor.config import (
    DEFAULT_DB_PATH,
    DEFAULT_METHODS,
    DEFAULT_PORTS,
    DEFAULT_REPORT_DIR,
    RULE_FILE_PATH,
    parse_methods,
    parse_ports,
)
from vuln_assessor.orchestrator import ScanOrchestrator
from vuln_assessor.risk import load_asset_profile
from vuln_assessor.storage import ScanRepository
from vuln_assessor.vuln import VulnerabilityRuleManager


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="企业内网脆弱性扫描与风险评估系统")
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan_parser = subparsers.add_parser("scan", help="执行一次扫描任务")
    scan_parser.add_argument("--target", required=True, help="目标网段，例如 192.168.1.0/24")
    scan_parser.add_argument(
        "--methods",
        default=",".join(DEFAULT_METHODS),
        help="发现方法组合，支持 icmp,arp,syn",
    )
    scan_parser.add_argument(
        "--ports",
        default=",".join(str(port) for port in DEFAULT_PORTS),
        help="端口列表，支持 22,80,443 或 1-1024",
    )
    scan_parser.add_argument("--output", default=str(DEFAULT_REPORT_DIR), help="HTML 报告输出目录")
    scan_parser.add_argument("--db", default=str(DEFAULT_DB_PATH), help="SQLite 数据库路径")
    scan_parser.add_argument("--name", default="", help="报告文件名（不带 .html）")
    scan_parser.add_argument(
        "--asset-profile",
        default="",
        help="资产重要性画像文件(JSON)，示例见 docs/asset_profile.example.json",
    )

    history_parser = subparsers.add_parser("history", help="查看历史扫描记录")
    history_parser.add_argument("--db", default=str(DEFAULT_DB_PATH), help="SQLite 数据库路径")
    history_parser.add_argument("--limit", type=int, default=20, help="显示记录条数")

    compare_parser = subparsers.add_parser("compare", help="对比两次扫描差异")
    compare_parser.add_argument("--db", default=str(DEFAULT_DB_PATH), help="SQLite 数据库路径")
    compare_parser.add_argument("--base", type=int, required=True, help="基线扫描 ID")
    compare_parser.add_argument("--new", type=int, required=True, help="新扫描 ID")

    rules_parser = subparsers.add_parser("rules", help="漏洞规则库管理")
    rules_subparsers = rules_parser.add_subparsers(dest="rules_command", required=True)

    rules_list_parser = rules_subparsers.add_parser("list", help="查看规则库统计")
    rules_list_parser.add_argument("--rules-file", default=str(RULE_FILE_PATH), help="规则库文件路径")

    rules_import_parser = rules_subparsers.add_parser("import", help="手动导入规则文件(JSON)")
    rules_import_parser.add_argument("--input", required=True, help="待导入规则文件路径")
    rules_import_parser.add_argument(
        "--mode",
        choices=["merge", "replace"],
        default="merge",
        help="merge=合并更新，replace=覆盖替换",
    )
    rules_import_parser.add_argument("--rules-file", default=str(RULE_FILE_PATH), help="规则库文件路径")

    rules_update_parser = rules_subparsers.add_parser("update", help="从 URL 自动更新规则库")
    rules_update_parser.add_argument("--url", required=True, help="远程 JSON 地址（需符合规则格式）")
    rules_update_parser.add_argument(
        "--mode",
        choices=["merge", "replace"],
        default="merge",
        help="merge=合并更新，replace=覆盖替换",
    )
    rules_update_parser.add_argument("--timeout", type=int, default=20, help="网络请求超时时间（秒）")
    rules_update_parser.add_argument("--rules-file", default=str(RULE_FILE_PATH), help="规则库文件路径")

    web_parser = subparsers.add_parser("web", help="启动 Web 前端")
    web_parser.add_argument("--host", default="127.0.0.1", help="监听地址")
    web_parser.add_argument("--port", type=int, default=5000, help="监听端口")
    web_parser.add_argument("--db", default=str(DEFAULT_DB_PATH), help="SQLite 数据库路径")
    web_parser.add_argument("--max-concurrent", type=int, default=3, help="Web并发扫描任务数")
    web_parser.add_argument("--debug", action="store_true", help="开启 Flask Debug 模式")

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    command = cast(str, args.command)

    if command == "scan":
        return handle_scan(args)
    if command == "history":
        return handle_history(args)
    if command == "compare":
        return handle_compare(args)
    if command == "rules":
        return handle_rules(args)
    if command == "web":
        return handle_web(args)
    parser.print_help()
    return 1


def handle_scan(args: argparse.Namespace) -> int:
    db_path = Path(cast(str, args.db))
    output_dir = Path(cast(str, args.output))
    asset_profile_arg = cast(str, args.asset_profile)
    profile_path = Path(asset_profile_arg) if asset_profile_arg else None

    try:
        methods = parse_methods(cast(str, args.methods))
        ports = parse_ports(cast(str, args.ports))
    except ValueError as exc:
        print(f"扫描参数错误: {exc}")
        return 1

    try:
        asset_map, default_asset = load_asset_profile(profile_path)
    except Exception as exc:
        print(f"资产画像加载失败: {exc}")
        return 1

    repository = ScanRepository(db_path)
    repository.initialize()
    orchestrator = ScanOrchestrator(
        repository,
        asset_criticality_map=asset_map,
        default_asset_criticality=default_asset,
    )

    print("注意: 权限提示：ARP/SYN 可能需要 root/CAP_NET_RAW；无权限会降级。")
    print("注意: 准确性提示：ICMP 不通不代表主机不存在；版本缺失会降低置信度并可能需要手动确认。")
    print("注意: 合规提示：仅在授权网络执行，可能触发 IDS/日志。")
    try:
        result = orchestrator.run_scan(
            target_cidr=cast(str, args.target),
            methods=methods,
            ports=ports,
            output_dir=output_dir,
            scan_name=cast(str, args.name),
        )
    except Exception as exc:
        print(f"扫描执行失败: {exc}")
        return 1

    print(f"扫描完成，扫描 ID: {result['scan_id']}")
    print(f"目标网段: {result['target']}")
    print(f"扫描时长: {result['duration_seconds']} 秒")
    print(f"发现主机: {result['total_hosts']}")
    print(f"识别服务: {result['total_services']}")
    print(f"风险总数: {result['total_risks']} (HIGH={result['high_count']}, MEDIUM={result['medium_count']}, LOW={result['low_count']})")
    print("风险模型: v2 (CVSS + 资产重要性 + 暴露面 + 可利用性 + 匹配置信度)")
    if profile_path:
        print(f"资产画像: {profile_path}")
    print(f"报告路径: {result['report_path']}")
    return 0


def handle_history(args: argparse.Namespace) -> int:
    repository = ScanRepository(Path(cast(str, args.db)))
    repository.initialize()
    rows = repository.list_scans(limit=int(cast(int, args.limit)))
    if not rows:
        print("暂无历史扫描记录。")
        return 0

    header = (
        f"{'ID':<5}{'Time':<20}{'Target':<20}"
        f"{'Hosts':<8}{'Services':<10}{'Risks':<8}{'High':<8}{'Med':<8}{'Low':<8}"
    )
    print(header)
    print("-" * len(header))
    for row in rows:
        time_text = str(row["started_at"])[:19]
        target_text = str(row["target"])[:18]
        print(
            f"{row['id']:<5}{time_text:<20}{target_text:<20}"
            f"{row['total_hosts']:<8}{row['total_services']:<10}{row['total_risks']:<8}"
            f"{row['high_count']:<8}{row['medium_count']:<8}{row['low_count']:<8}"
        )
        print(f"  report: {row['report_path']}")
    return 0


def handle_compare(args: argparse.Namespace) -> int:
    repository = ScanRepository(Path(cast(str, args.db)))
    repository.initialize()
    try:
        result = repository.compare_scan_outputs(
            base_scan_id=int(cast(int, args.base)),
            new_scan_id=int(cast(int, args.new)),
        )
    except ValueError as exc:
        print(f"对比失败: {exc}")
        return 1

    print(f"对比结果: base={result['base_scan_id']} -> new={result['new_scan_id']}")
    print("")
    print("服务识别对比")
    print(f"新增服务: {len(result['service_new'])}")
    for item in result["service_new"][:20]:
        print(
            f"  + {item['host_ip']}:{item['port']}/{item['protocol']} "
            f"{item['service_name']} {item['product']} {item['version']}"
        )
    print(f"已消失服务: {len(result['service_resolved'])}")
    for item in result["service_resolved"][:20]:
        print(
            f"  - {item['host_ip']}:{item['port']}/{item['protocol']} "
            f"{item['service_name']} {item['product']} {item['version']}"
        )
    print(f"持续存在服务: {len(result['service_persisted'])}")

    print("")
    print("漏洞匹配对比")
    print(f"新增漏洞: {len(result['vulnerability_new'])}")
    for item in result["vulnerability_new"][:20]:
        print(f"  + {item['host_ip']}:{item['port']} {item['cve_id']} ({item['risk_level']} {item['risk_score']})")

    print(f"已修复漏洞: {len(result['vulnerability_resolved'])}")
    for item in result["vulnerability_resolved"][:20]:
        print(f"  - {item['host_ip']}:{item['port']} {item['cve_id']} ({item['risk_level']} {item['risk_score']})")

    print(f"持续存在漏洞: {len(result['vulnerability_persisted'])}")
    print(f"风险变化漏洞: {len(result['vulnerability_changed'])}")
    for item in result["vulnerability_changed"][:20]:
        print(
            f"  * {item['host_ip']}:{item['port']} {item['cve_id']} "
            f"{item['base_risk_score']}->{item['new_risk_score']} ({item['base_risk_level']}->{item['new_risk_level']})"
        )
    return 0


def handle_rules(args: argparse.Namespace) -> int:
    manager = VulnerabilityRuleManager(Path(cast(str, args.rules_file)))
    rules_command = cast(str, args.rules_command)

    if rules_command == "list":
        summary = manager.summary()
        print(f"规则总数: {summary['total']}")
        if not summary["severity_count"]:
            print("暂无规则。")
            return 0
        print("按严重等级统计:")
        for severity, count in summary["severity_count"].items():
            print(f"  {severity}: {count}")
        return 0

    if rules_command == "import":
        try:
            result = manager.import_from_file(Path(cast(str, args.input)), mode=cast(str, args.mode))
        except Exception as exc:
            print(f"规则导入失败: {exc}")
            return 1
        _print_rule_update_result(result, title="手动导入完成")
        return 0

    if rules_command == "update":
        try:
            result = manager.update_from_url(
                cast(str, args.url),
                mode=cast(str, args.mode),
                timeout_seconds=max(int(cast(int, args.timeout)), 1),
            )
        except Exception as exc:
            print(f"自动更新失败: {exc}")
            return 1
        _print_rule_update_result(result, title="自动更新完成")
        return 0

    print("未知规则命令。")
    return 1


def _print_rule_update_result(result: dict, title: str) -> None:
    print(title)
    print(f"来源: {result['source']}")
    print(f"模式: {result['mode']}")
    print(f"输入条目: {result['incoming_count']}")
    print(f"有效条目: {result['valid_count']}")
    print(f"新增条目: {result['added_count']}")
    print(f"更新条目: {result['updated_count']}")
    print(f"规则库总量: {result['stored_count']}")
    print(f"规则文件: {result['rule_file']}")


def handle_web(args: argparse.Namespace) -> int:
    from vuln_assessor.webapp import run_web_app

    run_web_app(
        db_path=Path(cast(str, args.db)),
        host=cast(str, args.host),
        port=int(cast(int, args.port)),
        max_concurrent=max(int(cast(int, args.max_concurrent)), 1),
        debug=bool(cast(bool, args.debug)),
    )
    return 0
