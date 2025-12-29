"""
VulnScanner CLI - Command Line Interface for vulnerability scanning.
"""

import logging
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional

import click
from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskID
from rich.table import Table
from rich.text import Text

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from vulnscan.config import Config, get_config, set_config
from vulnscan.core.models import RiskLevel
from vulnscan.core.pipeline import ScanPipelineRunner, PipelineResult
from vulnscan.storage.database import Database
from vulnscan.storage.repository import ScanRepository

console = Console()

# i18n strings
I18N = {
    "zh_CN": {
        "welcome": "脆弱性扫描与风险评估系统",
        "scanning": "正在扫描",
        "host_discovery": "主机发现",
        "service_scan": "服务识别",
        "verification": "漏洞验证",
        "vuln_match": "漏洞匹配",
        "risk_scoring": "风险评估",
        "report_gen": "生成报告",
        "complete": "扫描完成",
        "hosts_found": "发现主机",
        "services_found": "发现服务",
        "vulns_found": "发现漏洞",
        "report_saved": "报告已保存至",
        "scan_history": "扫描历史",
        "no_history": "暂无扫描历史",
        "error": "错误",
    },
    "en_US": {
        "welcome": "Vulnerability Scanner & Risk Assessment System",
        "scanning": "Scanning",
        "host_discovery": "Host Discovery",
        "service_scan": "Service Scan",
        "verification": "Verification",
        "vuln_match": "Vuln Matching",
        "risk_scoring": "Risk Scoring",
        "report_gen": "Report Generation",
        "complete": "Scan Complete",
        "hosts_found": "Hosts Found",
        "services_found": "Services Found",
        "vulns_found": "Vulnerabilities Found",
        "report_saved": "Report saved to",
        "scan_history": "Scan History",
        "no_history": "No scan history",
        "error": "Error",
    },
}


def get_i18n(lang: str = "zh_CN") -> dict:
    return I18N.get(lang, I18N["en_US"])


def setup_logging(verbose: bool):
    """Configure logging based on verbosity."""
    level = logging.DEBUG if verbose else logging.WARNING
    logging.basicConfig(
        level=level,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )


@click.group()
@click.option("--lang", "-l", default="zh_CN", help="Language (zh_CN/en_US)")
@click.option("--verbose", "-v", is_flag=True, help="Enable verbose output")
@click.option("--db", type=click.Path(), help="Database file path")
@click.pass_context
def cli(ctx, lang: str, verbose: bool, db: Optional[str]):
    """VulnScanner - Network Vulnerability Scanner & Risk Assessment System"""
    ctx.ensure_object(dict)
    ctx.obj["lang"] = lang
    ctx.obj["i18n"] = get_i18n(lang)

    setup_logging(verbose)

    if db:
        config = get_config()
        config.database.path = Path(db)
        set_config(config)


@cli.command()
@click.argument("target")
@click.option(
    "--method", "-m",
    type=click.Choice(["icmp", "arp", "syn", "all"]),
    default="icmp",
    help="Host discovery method",
)
@click.option("--ports", "-p", default="1-1024", help="Port range for SYN scan")
@click.option("--no-service", is_flag=True, help="Skip service identification")
@click.option("--no-vuln", is_flag=True, help="Skip vulnerability matching")
@click.option("--no-report", is_flag=True, help="Skip report generation")
@click.option("--verify", is_flag=True, help="Enable active vulnerability verification (weak passwords, SSL audit, NSE scripts)")
@click.option("--output", "-o", type=click.Path(), help="Report output path")
@click.pass_context
def scan(
    ctx,
    target: str,
    method: str,
    ports: str,
    no_service: bool,
    no_vuln: bool,
    no_report: bool,
    verify: bool,
    output: Optional[str],
):
    """Run a vulnerability scan on the target.

    TARGET can be:
      - Single IP: 192.168.1.1
      - CIDR: 192.168.1.0/24
      - Range: 192.168.1.1-254
    """
    lang = ctx.obj["lang"]
    i18n = ctx.obj["i18n"]

    console.print(Panel(
        f"[bold blue]{i18n['welcome']}[/bold blue]\n"
        f"[dim]Target: {target}[/dim]",
        border_style="blue",
    ))

    stage_names = {
        "host_discovery": i18n["host_discovery"],
        "service_scan": i18n["service_scan"],
        "verification": i18n["verification"],
        "vuln_match": i18n["vuln_match"],
        "risk_scoring": i18n["risk_scoring"],
        "report_gen": i18n["report_gen"],
        "complete": i18n["complete"],
    }

    current_stage = ["host_discovery"]
    current_percent = [0]

    def progress_callback(stage: str, percent: int):
        current_stage[0] = stage
        current_percent[0] = percent

    try:
        config = get_config()
        db = Database(config.database.path)
        runner = ScanPipelineRunner(db=db, progress_callback=progress_callback)

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            console=console,
        ) as progress:
            task = progress.add_task(
                f"[cyan]{i18n['scanning']}...", total=100
            )

            import threading
            scan_result = [None]
            scan_error = [None]

            def run_scan():
                try:
                    scan_result[0] = runner.run(
                        target_range=target,
                        discovery_method=method,
                        port_range=ports,
                        service_scan=not no_service,
                        verify_services=verify,
                        vuln_match=not no_vuln,
                        generate_report=not no_report,
                        report_path=Path(output) if output else None,
                        language=lang,
                    )
                except Exception as e:
                    scan_error[0] = e

            thread = threading.Thread(target=run_scan)
            thread.start()

            while thread.is_alive():
                stage_name = stage_names.get(current_stage[0], current_stage[0])
                progress.update(
                    task,
                    completed=current_percent[0],
                    description=f"[cyan]{stage_name}",
                )
                thread.join(timeout=0.1)

            progress.update(task, completed=100)

        if scan_error[0]:
            raise scan_error[0]

        result: PipelineResult = scan_result[0]
        _display_results(result, i18n)

    except PermissionError:
        console.print(f"[red]{i18n['error']}: Root privileges required for scanning[/red]")
        console.print("[dim]Try: sudo vulnscan scan ...[/dim]")
        sys.exit(1)
    except Exception as e:
        console.print(f"[red]{i18n['error']}: {e}[/red]")
        sys.exit(1)


def _display_results(result: PipelineResult, i18n: dict):
    """Display scan results in a formatted table."""
    console.print()

    # Summary table
    summary = Table(title=i18n["complete"], show_header=False, border_style="green")
    summary.add_column("Metric", style="cyan")
    summary.add_column("Value", style="bold")

    summary.add_row(i18n["hosts_found"], str(len(result.hosts)))
    summary.add_row(i18n["services_found"], str(len(result.services)))
    summary.add_row(i18n["vulns_found"], str(len(result.vulnerabilities)))

    console.print(summary)

    # Risk summary
    if result.risk_results:
        console.print()
        risk_table = Table(title="Risk Assessment", border_style="red")
        risk_table.add_column("Host", style="cyan")
        risk_table.add_column("Score", justify="right")
        risk_table.add_column("Level")
        risk_table.add_column("Vulns", justify="right")

        for rr in sorted(result.risk_results, key=lambda r: r.risk_score, reverse=True)[:10]:
            host = next((h for h in result.hosts if h.id == rr.host_id), None)
            ip = host.ip if host else "N/A"

            level_style = {
                RiskLevel.CRITICAL: "bold red",
                RiskLevel.HIGH: "bold yellow",
                RiskLevel.MEDIUM: "yellow",
                RiskLevel.LOW: "blue",
                RiskLevel.INFO: "dim",
            }.get(rr.risk_level, "")

            risk_table.add_row(
                ip,
                f"{rr.risk_score:.1f}",
                Text(rr.risk_level.value, style=level_style),
                str(rr.vuln_count),
            )

        console.print(risk_table)

    # Report path
    if result.report_path:
        console.print()
        console.print(f"[green]{i18n['report_saved']}:[/green] {result.report_path}")


@cli.command()
@click.option("--limit", "-n", default=10, help="Number of records to show")
@click.pass_context
def history(ctx, limit: int):
    """Show scan history."""
    i18n = ctx.obj["i18n"]

    config = get_config()
    db = Database(config.database.path)
    repo = ScanRepository(db)

    scans = repo.list_all(limit=limit)

    if not scans:
        console.print(f"[dim]{i18n['no_history']}[/dim]")
        return

    table = Table(title=i18n["scan_history"], border_style="blue")
    table.add_column("ID", style="dim")
    table.add_column("Target")
    table.add_column("Started")
    table.add_column("Status")

    for scan in scans:
        status_style = {
            "completed": "green",
            "running": "yellow",
            "failed": "red",
            "pending": "dim",
        }.get(scan.status.value, "")

        started = scan.started_at.strftime("%Y-%m-%d %H:%M") if scan.started_at else "-"

        table.add_row(
            str(scan.id),
            scan.target_range,
            started,
            Text(scan.status.value, style=status_style),
        )

    console.print(table)


@cli.command()
@click.argument("scan_id", type=int)
@click.option("--output", "-o", type=click.Path(), help="Output path")
@click.option("--format", "-f", "fmt", type=click.Choice(["html", "pdf", "json"]), default="html", help="Report format")
@click.pass_context
def report(ctx, scan_id: int, output: Optional[str], fmt: str):
    """Generate report for an existing scan."""
    lang = ctx.obj["lang"]
    i18n = ctx.obj["i18n"]

    config = get_config()
    db = Database(config.database.path)

    from vulnscan.storage.repository import (
        HostRepository,
        ServiceRepository,
        VulnerabilityRepository,
        RiskResultRepository,
    )
    from vulnscan.reporting.generator import ReportGenerator

    scan_repo = ScanRepository(db)
    host_repo = HostRepository(db)
    service_repo = ServiceRepository(db)
    vuln_repo = VulnerabilityRepository(db)
    risk_repo = RiskResultRepository(db)

    scan = scan_repo.get(scan_id)
    if not scan:
        console.print(f"[red]{i18n['error']}: Scan {scan_id} not found[/red]")
        sys.exit(1)

    hosts = host_repo.get_by_scan(scan_id)
    services = []
    for host in hosts:
        services.extend(service_repo.get_by_host(host.id))

    risk_results = risk_repo.get_by_scan(scan_id)

    # Get unique vulnerabilities
    vuln_ids = set()
    vulnerabilities = []
    for svc in services:
        svc_vulns = vuln_repo.get_by_service(svc.id)
        for vuln in svc_vulns:
            if vuln.id not in vuln_ids:
                vuln_ids.add(vuln.id)
                vulnerabilities.append(vuln)

    generator = ReportGenerator(language=lang)

    # Determine output path and extension
    report_dir = Path(config.database.path).parent / "reports"
    report_dir.mkdir(parents=True, exist_ok=True)

    ext = fmt if fmt != "json" else "json"
    if not output:
        output = report_dir / f"scan_{scan_id}_{datetime.now():%Y%m%d_%H%M%S}.{ext}"
    else:
        output = Path(output)

    if fmt == "pdf":
        generator.generate_pdf(
            scan=scan,
            hosts=hosts,
            services=services,
            vulnerabilities=vulnerabilities,
            risk_results=risk_results,
            output_path=output,
        )
    elif fmt == "json":
        import json
        data = generator.generate_json(
            scan=scan,
            hosts=hosts,
            services=services,
            vulnerabilities=vulnerabilities,
            risk_results=risk_results,
        )
        output.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    else:
        generator.generate(
            scan=scan,
            hosts=hosts,
            services=services,
            vulnerabilities=vulnerabilities,
            risk_results=risk_results,
            output_path=output,
        )

    console.print(f"[green]{i18n['report_saved']}:[/green] {output}")


@cli.command()
def version():
    """Show version information."""
    console.print("[bold]VulnScanner[/bold] v1.0.0")
    console.print("[dim]Network Vulnerability Scanner & Risk Assessment System[/dim]")

    # Check dependencies
    try:
        from vulnscan.scanners.service.nmap import get_nmap_version
        nmap_ver = get_nmap_version()
        if nmap_ver:
            console.print(f"[dim]Nmap: {nmap_ver}[/dim]")
    except Exception:
        pass


@cli.command()
@click.argument("scan_id_old", type=int)
@click.argument("scan_id_new", type=int)
@click.pass_context
def compare(ctx, scan_id_old: int, scan_id_new: int):
    """Compare two scan results to identify changes.

    Example: vulnscan compare 1 2
    """
    i18n = ctx.obj["i18n"]
    config = get_config()
    db = Database(config.database.path)

    from vulnscan.core.diff import ScanComparator
    from vulnscan.storage.repository import (
        HostRepository,
        ServiceRepository,
        VulnerabilityRepository,
        RiskResultRepository,
    )

    scan_repo = ScanRepository(db)
    host_repo = HostRepository(db)
    service_repo = ServiceRepository(db)
    vuln_repo = VulnerabilityRepository(db)
    risk_repo = RiskResultRepository(db)

    scan_old = scan_repo.get(scan_id_old)
    scan_new = scan_repo.get(scan_id_new)

    if not scan_old:
        console.print(f"[red]{i18n['error']}: Scan {scan_id_old} not found[/red]")
        sys.exit(1)
    if not scan_new:
        console.print(f"[red]{i18n['error']}: Scan {scan_id_new} not found[/red]")
        sys.exit(1)

    # Gather data for both scans
    hosts_old = host_repo.get_by_scan(scan_id_old)
    hosts_new = host_repo.get_by_scan(scan_id_new)

    services_old, services_new = [], []
    vulns_old, vulns_new = [], []
    vuln_ids_old, vuln_ids_new = set(), set()

    for h in hosts_old:
        svcs = service_repo.get_by_host(h.id)
        services_old.extend(svcs)
        for s in svcs:
            for v in vuln_repo.get_by_service(s.id):
                if v.id not in vuln_ids_old:
                    vuln_ids_old.add(v.id)
                    vulns_old.append(v)

    for h in hosts_new:
        svcs = service_repo.get_by_host(h.id)
        services_new.extend(svcs)
        for s in svcs:
            for v in vuln_repo.get_by_service(s.id):
                if v.id not in vuln_ids_new:
                    vuln_ids_new.add(v.id)
                    vulns_new.append(v)

    risks_old = risk_repo.get_by_scan(scan_id_old)
    risks_new = risk_repo.get_by_scan(scan_id_new)

    comparator = ScanComparator()
    diff = comparator.compare(
        scan_old, scan_new,
        hosts_old, hosts_new,
        services_old, services_new,
        vulns_old, vulns_new,
        risks_old, risks_new,
    )

    # Display results
    console.print(Panel(
        f"[bold cyan]Scan Comparison[/bold cyan]\n"
        f"[dim]#{scan_id_old} vs #{scan_id_new}[/dim]",
        border_style="cyan",
    ))

    summary_table = Table(title="Changes Summary", border_style="blue")
    summary_table.add_column("Category", style="cyan")
    summary_table.add_column("Added", style="green", justify="right")
    summary_table.add_column("Removed", style="red", justify="right")

    summary_table.add_row("Hosts", str(len(diff.hosts_added)), str(len(diff.hosts_removed)))
    summary_table.add_row("Services", str(len(diff.services_added)), str(len(diff.services_removed)))
    summary_table.add_row("Vulnerabilities", str(len(diff.vulns_added)), str(len(diff.vulns_fixed)))

    console.print(summary_table)

    # Risk delta
    delta_style = "red" if diff.risk_delta > 0 else "green" if diff.risk_delta < 0 else "dim"
    delta_sign = "+" if diff.risk_delta > 0 else ""
    console.print(f"\n[{delta_style}]Risk Score Change: {delta_sign}{diff.risk_delta}[/{delta_style}]")

    # New hosts
    if diff.hosts_added:
        console.print("\n[green]New Hosts:[/green]")
        for h in diff.hosts_added[:10]:
            console.print(f"  [green]+[/green] {h.ip}")

    # Removed hosts
    if diff.hosts_removed:
        console.print("\n[red]Removed Hosts:[/red]")
        for h in diff.hosts_removed[:10]:
            console.print(f"  [red]-[/red] {h.ip}")

    # New vulnerabilities
    if diff.vulns_added:
        console.print("\n[yellow]New Vulnerabilities:[/yellow]")
        for v in diff.vulns_added[:10]:
            sev = v.severity.value if v.severity else "N/A"
            console.print(f"  [yellow]+[/yellow] {v.cve_id} ({sev})")

    # Fixed vulnerabilities
    if diff.vulns_fixed:
        console.print("\n[green]Fixed Vulnerabilities:[/green]")
        for v in diff.vulns_fixed[:10]:
            console.print(f"  [green]✓[/green] {v.cve_id}")


# === NVD Command Group ===
@cli.group()
def nvd():
    """NVD data management commands."""
    pass


@nvd.command()
@click.option(
    "--mode", "-m",
    type=click.Choice(["auto", "full", "incremental"]),
    default="auto",
    help="Sync mode (auto/full/incremental)",
)
@click.option("--years", "-y", help="Year range for full sync (e.g., 2020-2024)")
@click.option("--force", "-f", is_flag=True, help="Force re-download feeds")
@click.pass_context
def sync(ctx, mode: str, years: Optional[str], force: bool):
    """Synchronize NVD vulnerability data.

    Modes:
      - auto: Full sync if not initialized, else incremental
      - full: Download and import NVD data feeds (offline)
      - incremental: Fetch recent changes via API (requires key)
    """
    from vulnscan.nvd import HybridSyncCoordinator
    from vulnscan.storage.database import Database
    from vulnscan.storage.schema import init_database

    config = get_config()
    db = Database(config.database.path)
    init_database()

    year_list = None
    if years:
        if "-" in years:
            start, end = years.split("-")
            year_list = list(range(int(start), int(end) + 1))
        else:
            year_list = [int(years)]

    coordinator = HybridSyncCoordinator(db=db)

    console.print(Panel(
        f"[bold cyan]NVD Data Sync[/bold cyan]\n"
        f"[dim]Mode: {mode.upper()}[/dim]",
        border_style="cyan",
    ))

    def progress_cb(msg: str):
        console.print(f"  [dim]{msg}[/dim]")

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("[cyan]Synchronizing...", total=None)

        result = coordinator.sync(
            mode=mode,
            years=year_list,
            force=force,
            progress_callback=progress_cb,
        )

        progress.update(task, completed=100, total=100)

    # Display results
    table = Table(title="Sync Result", border_style="green" if result.success else "red")
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="bold")

    table.add_row("Mode", result.mode.upper())
    table.add_row("Duration", f"{result.duration:.1f}s")
    table.add_row("CVEs Added", str(result.cves_added))
    table.add_row("CVEs Updated", str(result.cves_updated))
    table.add_row("Total in Cache", str(result.cves_total))

    if result.feeds_processed:
        table.add_row("Feeds Processed", ", ".join(map(str, result.feeds_processed)))

    console.print(table)

    if result.errors:
        console.print("\n[yellow]Warnings:[/yellow]")
        for err in result.errors:
            console.print(f"  [dim]- {err}[/dim]")


@nvd.command()
@click.pass_context
def status(ctx):
    """Show NVD cache status."""
    from vulnscan.nvd import HybridSyncCoordinator
    from vulnscan.storage.database import Database

    config = get_config()
    db = Database(config.database.path)

    try:
        coordinator = HybridSyncCoordinator(db=db)
        state = coordinator.get_sync_state()
        stats = coordinator.get_cache_stats()

        table = Table(title="NVD Cache Status", border_style="blue")
        table.add_column("Property", style="cyan")
        table.add_column("Value", style="bold")

        table.add_row("Initialized", "Yes" if state.is_initialized else "No")
        table.add_row("Total CVEs", str(stats["total"]))
        table.add_row(
            "Last Full Sync",
            state.last_full_sync.strftime("%Y-%m-%d %H:%M") if state.last_full_sync else "Never"
        )
        table.add_row(
            "Last Incremental",
            state.last_incremental_sync.strftime("%Y-%m-%d %H:%M") if state.last_incremental_sync else "Never"
        )

        if state.feeds_imported:
            table.add_row("Imported Years", ", ".join(map(str, state.feeds_imported)))

        console.print(table)

        if stats["by_severity"]:
            sev_table = Table(title="By Severity", border_style="dim")
            sev_table.add_column("Severity", style="cyan")
            sev_table.add_column("Count", justify="right")

            for sev, count in sorted(stats["by_severity"].items()):
                style = {"CRITICAL": "red", "HIGH": "yellow", "MEDIUM": "blue"}.get(sev, "dim")
                sev_table.add_row(Text(sev, style=style), str(count))

            console.print(sev_table)

    except Exception as e:
        console.print(f"[yellow]Cache not initialized or error: {e}[/yellow]")
        console.print("[dim]Run 'vulnscan nvd sync' to initialize.[/dim]")


@nvd.command()
@click.option("--confirm", is_flag=True, help="Confirm cache clear")
@click.pass_context
def clear(ctx, confirm: bool):
    """Clear NVD cache data."""
    if not confirm:
        console.print("[yellow]Use --confirm to clear all NVD cached data.[/yellow]")
        return

    from vulnscan.storage.database import Database

    config = get_config()
    db = Database(config.database.path)

    try:
        db.conn.execute("DELETE FROM vulnerabilities")
        db.conn.execute("DELETE FROM nvd_feed_imports")
        db.conn.execute("DELETE FROM nvd_sync_state")
        db.conn.commit()
        console.print("[green]NVD cache cleared successfully.[/green]")
    except Exception as e:
        console.print(f"[red]Error clearing cache: {e}[/red]")


# === Schedule Command Group ===
@cli.group()
def schedule():
    """Scheduled scan management."""
    pass


@schedule.command("list")
@click.pass_context
def schedule_list(ctx):
    """List all scheduled scans."""
    from vulnscan.scheduler import ScheduleRepository
    from vulnscan.storage.database import Database

    config = get_config()
    db = Database(config.database.path)
    repo = ScheduleRepository(db)

    schedules = repo.get_all()

    if not schedules:
        console.print("[dim]No scheduled scans. Use 'vulnscan schedule add' to create one.[/dim]")
        return

    table = Table(title="Scheduled Scans", border_style="blue")
    table.add_column("ID", style="dim")
    table.add_column("Name")
    table.add_column("Target")
    table.add_column("Cron")
    table.add_column("Status")
    table.add_column("Last Run")

    for s in schedules:
        status = Text("Enabled", style="green") if s.is_enabled else Text("Disabled", style="dim")
        last_run = s.last_run.strftime("%Y-%m-%d %H:%M") if s.last_run else "-"
        table.add_row(str(s.id), s.name, s.target_range, s.cron_expr, status, last_run)

    console.print(table)


@schedule.command("add")
@click.option("--name", "-n", required=True, help="Schedule name")
@click.option("--target", "-t", required=True, help="Target range (CIDR/IP)")
@click.option("--cron", "-c", required=True, help="Cron expression (e.g., '0 2 * * *')")
@click.option("--method", "-m", default="icmp", help="Discovery method")
@click.option("--ports", "-p", default="1-1024", help="Port range")
@click.pass_context
def schedule_add(ctx, name: str, target: str, cron: str, method: str, ports: str):
    """Add a new scheduled scan."""
    from vulnscan.scheduler import ScheduledScan, ScheduleRepository
    from vulnscan.scheduler.runner import get_next_run
    from vulnscan.storage.database import Database
    from vulnscan.storage.schema import init_database

    config = get_config()
    db = Database(config.database.path)
    init_database()

    repo = ScheduleRepository(db)

    # Validate cron expression
    next_run = get_next_run(cron)
    if not next_run:
        console.print(f"[red]Invalid cron expression: {cron}[/red]")
        return

    schedule = ScheduledScan(
        name=name,
        target_range=target,
        cron_expr=cron,
        method=method,
        ports=ports,
        next_run=next_run,
    )

    repo.create(schedule)
    repo.bump_schedule_version()
    console.print(f"[green]Created schedule:[/green] {name}")
    console.print(f"[dim]Next run: {next_run.strftime('%Y-%m-%d %H:%M')}[/dim]")


@schedule.command("remove")
@click.argument("schedule_id", type=int)
@click.pass_context
def schedule_remove(ctx, schedule_id: int):
    """Remove a scheduled scan."""
    from vulnscan.scheduler import ScheduleRepository
    from vulnscan.storage.database import Database

    config = get_config()
    db = Database(config.database.path)
    repo = ScheduleRepository(db)

    if repo.delete(schedule_id):
        repo.bump_schedule_version()
        console.print(f"[green]Removed schedule #{schedule_id}[/green]")
    else:
        console.print(f"[red]Schedule #{schedule_id} not found[/red]")


@schedule.command("toggle")
@click.argument("schedule_id", type=int)
@click.pass_context
def schedule_toggle(ctx, schedule_id: int):
    """Enable/disable a scheduled scan."""
    from vulnscan.scheduler import ScheduleRepository
    from vulnscan.storage.database import Database

    config = get_config()
    db = Database(config.database.path)
    repo = ScheduleRepository(db)

    schedule = repo.get(schedule_id)
    if not schedule:
        console.print(f"[red]Schedule #{schedule_id} not found[/red]")
        return

    repo.toggle(schedule_id)
    repo.bump_schedule_version()
    new_status = "disabled" if schedule.is_enabled else "enabled"
    console.print(f"[green]Schedule #{schedule_id} {new_status}[/green]")


@schedule.command("start")
@click.option("--daemon", "-d", is_flag=True, help="Run in background")
@click.pass_context
def schedule_start(ctx, daemon: bool):
    """Start the scheduler daemon."""
    from vulnscan.scheduler import SchedulerRunner
    from vulnscan.storage.database import Database

    config = get_config()
    db = Database(config.database.path)

    console.print("[cyan]Starting scheduler...[/cyan]")

    runner = SchedulerRunner(db)

    if daemon:
        console.print("[dim]Running in background. Press Ctrl+C to stop.[/dim]")
        runner.start(blocking=False)
        import time
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            runner.stop()
    else:
        console.print("[dim]Press Ctrl+C to stop.[/dim]")
        runner.start(blocking=True)


def main():
    """Entry point for the CLI."""
    cli(obj={})


if __name__ == "__main__":
    main()
