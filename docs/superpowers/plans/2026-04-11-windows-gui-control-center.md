# Windows GUI Control Center Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Rework the project around a Windows-first desktop control center with five tabs, split asset discovery from analysis, keep the web app as a report center only, and split default vs advanced dependencies.

**Architecture:** Keep the current scanning, reporting, storage, and web layers, but add explicit scan/report typing, a dedicated asset-report path, and a reorganized Tkinter GUI that treats each tab as an isolated workflow. Web remains read-only for reports and comparisons, while the GUI becomes the only primary control surface for scan execution.

**Tech Stack:** Python, Tkinter/ttk, Flask, SQLite, Jinja2, unittest, nmap, optional scapy

---

## File Structure

### Existing files to modify

- `vuln_assessor/storage/repository.py`
  Add scan typing support, filtering helpers, and migration-safe schema updates for mixed asset/analysis history.
- `vuln_assessor/orchestrator.py`
  Split “analysis from existing assets” from “run full scan”, and add an asset-discovery report path.
- `vuln_assessor/workbench.py`
  Expose separate desktop workflows for asset discovery and analysis, plus filtered history/comparison helpers.
- `vuln_assessor/report/generator.py`
  Support rendering asset-only reports without pretending service/vulnerability data exists.
- `vuln_assessor/webapp.py`
  Keep web read-only and filter compare/history views to analysis reports by default.
- `vuln_assessor/desktop_gui.py`
  Restructure the GUI into five tabs and Windows-first controls, including the Web Report Center tab and advanced toggles.
- `vuln_assessor/gui_launcher.py`
  Update Windows/Tk messaging where it still assumes Linux-centric setup wording.
- `vuln_assessor/config.py`
  Add Windows-friendly discovery presets / defaults where needed.
- `vuln_assessor/vuln/rule_manager.py`
  Keep remote URL update behavior, but prepare for “simple by default, advanced when expanded” GUI usage.
- `README.md`
  Rewrite quickstart and feature description around Windows-first GUI + report-center-only web.
- `docs/INSTALL.md`
  Rewrite install instructions around Windows-first setup and split advanced dependencies.

### New files to create

- `requirements-advanced.txt`
  Hold optional/high-friction dependencies such as `scapy`.
- `tests/test_desktop_gui_workflows.py`
  Focused regression tests for the split workflows and tab-driven desktop behavior.

### Existing tests to modify

- `tests/test_workbench_flow.py`
  Verify asset report generation, analysis-only compare eligibility, and no auto-chaining between workflows.
- `tests/test_gui_launcher.py`
  Keep Web launcher behavior aligned with the new report-center tab wording.
- `tests/test_desktop_web_control.py`
  Keep desktop web control stable under the new Windows-first flow.

## Task 1: Add Explicit Scan Types and Asset-Only Report Flow

**Files:**
- Modify: `vuln_assessor/storage/repository.py`
- Modify: `vuln_assessor/orchestrator.py`
- Modify: `vuln_assessor/workbench.py`
- Modify: `vuln_assessor/report/generator.py`
- Test: `tests/test_workbench_flow.py`

- [ ] **Step 1: Write failing tests for split report types**

Add tests in `tests/test_workbench_flow.py` that expect:

```python
result = workbench.discover_assets(...)
self.assertEqual(result.report_type, "asset_discovery")

analysis = workbench.run_analysis(...)
self.assertEqual(analysis["scan_type"], "analysis")

rows = repository.list_scans(limit=10, scan_type="analysis")
self.assertTrue(all(row["scan_type"] == "analysis" for row in rows))
```

and a second test that confirms compare helpers ignore asset-only scans by default.

- [ ] **Step 2: Run the focused tests and confirm they fail for the right reason**

Run: `python -m unittest tests.test_workbench_flow -v`

Expected:
- Failures mentioning missing `scan_type` / `report_type`
- No unrelated import or environment failures

- [ ] **Step 3: Extend repository schema and query helpers**

Update `vuln_assessor/storage/repository.py` to add a migration-safe `scan_type` column plus filtered list helpers. The target shape is:

```python
CREATE TABLE IF NOT EXISTS scans (
    ...,
    report_path TEXT NOT NULL,
    scan_type TEXT NOT NULL DEFAULT 'analysis'
)
```

and:

```python
def save_scan(..., scan_type: str = "analysis") -> int: ...
def list_scans(self, limit: int = 20, scan_type: str | None = None) -> list[dict[str, Any]]: ...
def compare_scan_outputs(self, base_scan_id: int, new_scan_id: int, allowed_scan_type: str = "analysis") -> dict[str, Any]: ...
```

- [ ] **Step 4: Add asset-only reporting and summary support**

Update `vuln_assessor/orchestrator.py`, `vuln_assessor/workbench.py`, and `vuln_assessor/report/generator.py` so that asset discovery can generate and store an HTML report without inventing service or vulnerability rows. The minimal interface target is:

```python
def generate_asset_report(
    self,
    target: str,
    methods: list[str],
    ports: list[int],
    assets: list[HostAsset],
    output_dir: Path,
    scan_name: str = "",
) -> str: ...
```

and:

```python
def discover_assets(... ) -> DiscoverySnapshot:
    ...
    snapshot = self._save_discovery_snapshot(...)
    report_path = orchestrator.generate_asset_report(...)
    snapshot.report_path = report_path
    snapshot.scan_id = repository.save_scan(..., scan_type="asset_discovery")
```

Use the existing report template when practical, but make its service/vulnerability sections conditional rather than fake.

- [ ] **Step 5: Run focused tests again**

Run: `python -m unittest tests.test_workbench_flow -v`

Expected:
- New split-flow tests pass
- Existing “web report center only” test still passes or reveals only expected downstream failures

- [ ] **Step 6: Commit checkpoint**

```bash
git add vuln_assessor/storage/repository.py vuln_assessor/orchestrator.py vuln_assessor/workbench.py vuln_assessor/report/generator.py tests/test_workbench_flow.py
git commit -m "feat: add scan typing and asset-only report flow"
```

## Task 2: Reshape the Desktop GUI Around Five Isolated Tabs

**Files:**
- Modify: `vuln_assessor/desktop_gui.py`
- Modify: `vuln_assessor/config.py`
- Modify: `vuln_assessor/gui_launcher.py`
- Test: `tests/test_desktop_gui_workflows.py`

- [ ] **Step 1: Write failing GUI workflow tests**

Create `tests/test_desktop_gui_workflows.py` with tests that target the non-visual behavior:

```python
def test_discovery_preset_defaults_to_progressive_scan(self):
    gui = DesktopControlCenterGUI()
    self.assertEqual(gui.discovery_preset_var.get(), "progressive")

def test_analysis_defaults_to_standard_nmap_profile(self):
    gui = DesktopControlCenterGUI()
    self.assertEqual(gui.analysis_nmap_preset_var.get(), "standard")
```

and a test that ensures asset discovery action does not call analysis handlers.

- [ ] **Step 2: Run the new GUI workflow tests**

Run: `python -m unittest tests.test_desktop_gui_workflows -v`

Expected:
- Failures because the new preset vars / split handlers do not exist yet

- [ ] **Step 3: Reorganize GUI state and tab builders**

Refactor `vuln_assessor/desktop_gui.py` so the notebook tabs are:

```python
("资产发现", "漏洞匹配与服务识别", "规则库导入", "报告对比", "Web 报告中心")
```

and the window state includes:

```python
self.discovery_preset_var = StringVar(value="progressive")
self.discovery_advanced_visible = False
self.analysis_target_var = StringVar(value="127.0.0.1/32")
self.analysis_nmap_preset_var = StringVar(value="standard")
self.analysis_extra_args_var = StringVar(value="")
```

Move the current top header web controls into a dedicated Web tab instead of a global header row.

- [ ] **Step 4: Implement Windows-friendly preset and advanced controls**

Update the discovery and analysis tab handlers so the user sees presets first and raw controls only in advanced sections. The behavioral target is:

```python
def _resolve_discovery_methods(self) -> list[str]:
    if self.discovery_preset_var.get() == "progressive":
        return ["icmp", "arp", "syn"]
    return parse_methods(self.discovery_methods_var.get().strip())

def _resolve_analysis_profile(self) -> list[str]:
    preset = self.analysis_nmap_preset_var.get()
    if preset == "quick":
        return ["-sV", "-Pn", "--version-light"]
    if preset == "deep":
        return ["-sV", "-Pn", "--version-all"]
    return ["-sV", "-Pn", "--version-intensity", "5"]
```

If the service fingerprint layer cannot yet accept explicit nmap args, wire the preset into a simpler internal enum first and finish the handoff in Task 3.

- [ ] **Step 5: Keep environment failures non-blocking in discovery and explicit in analysis**

In `vuln_assessor/desktop_gui.py`, ensure:

```python
except OptionalCapabilityError as exc:
    self.discovery_status_var.set(f"已降级继续：{exc}")
    self._append_log(str(exc))
```

and:

```python
except NmapUnavailableError as exc:
    self.analysis_status_var.set("分析未执行")
    messagebox.showerror("缺少 nmap", str(exc))
```

Use existing exception types if available; otherwise introduce lightweight, file-local handling that does not mask failures as empty results.

- [ ] **Step 6: Run the GUI workflow tests**

Run: `python -m unittest tests.test_desktop_gui_workflows -v`

Expected:
- New GUI workflow tests pass
- No regressions in launcher imports

- [ ] **Step 7: Commit checkpoint**

```bash
git add vuln_assessor/desktop_gui.py vuln_assessor/config.py vuln_assessor/gui_launcher.py tests/test_desktop_gui_workflows.py
git commit -m "feat: reorganize desktop gui into windows-first control center"
```

## Task 3: Make Analysis Truly Independent and Keep Web as Report Center Only

**Files:**
- Modify: `vuln_assessor/scanners/service_fingerprint.py`
- Modify: `vuln_assessor/workbench.py`
- Modify: `vuln_assessor/webapp.py`
- Modify: `vuln_assessor/web/templates/dashboard.html`
- Modify: `vuln_assessor/web/templates/compare.html`
- Modify: `vuln_assessor/web/templates/scan_detail.html`
- Test: `tests/test_workbench_flow.py`

- [ ] **Step 1: Write failing tests for independent analysis and filtered web history**

Add tests that expect:

```python
result = workbench.run_analysis(
    target="192.168.10.0/24",
    nmap_profile="standard",
    ...
)
self.assertEqual(result["scan_type"], "analysis")
```

and:

```python
response = client.get("/")
html = response.get_data(as_text=True)
self.assertIn("分析报告", html)
self.assertNotIn("提交扫描任务", html)
```

with list and compare data filtered to analysis scans.

- [ ] **Step 2: Run the focused tests and confirm red state**

Run: `python -m unittest tests.test_workbench_flow -v`

Expected:
- Failures showing no independent analysis entry point or missing filtered history

- [ ] **Step 3: Add an explicit independent analysis workflow**

Update `vuln_assessor/workbench.py` and `vuln_assessor/scanners/service_fingerprint.py` so the analysis tab can operate from a user-entered target without consuming discovery snapshots. The target API is:

```python
def analyze_target(
    self,
    target: str,
    ports: list[int],
    nmap_profile: str = "standard",
    extra_nmap_args: list[str] | None = None,
    scan_name: str = "",
    output_dir: Path | None = None,
    asset_profile_path: Path | None = None,
) -> dict[str, object]: ...
```

Internally, this may still discover hosts first, but that must stay encapsulated in the analysis workflow rather than sharing the discovery-tab trigger.

- [ ] **Step 4: Filter web history and compare views to analysis scans by default**

Update `vuln_assessor/webapp.py` and templates so:

```python
scans = repository.list_scans(limit=30, scan_type="analysis")
```

is the default dashboard / compare listing, while scan detail pages still work for both scan types when opened directly.

- [ ] **Step 5: Re-run the focused tests**

Run: `python -m unittest tests.test_workbench_flow -v`

Expected:
- Split analysis tests pass
- Web report-center-only behavior remains intact

- [ ] **Step 6: Commit checkpoint**

```bash
git add vuln_assessor/scanners/service_fingerprint.py vuln_assessor/workbench.py vuln_assessor/webapp.py vuln_assessor/web/templates/dashboard.html vuln_assessor/web/templates/compare.html vuln_assessor/web/templates/scan_detail.html tests/test_workbench_flow.py
git commit -m "feat: separate analysis workflow and filter web report center"
```

## Task 4: Simplify Rules UI and Split Default vs Advanced Dependencies

**Files:**
- Modify: `requirements.txt`
- Create: `requirements-advanced.txt`
- Modify: `README.md`
- Modify: `docs/INSTALL.md`
- Modify: `docs/usage_guide.md`
- Modify: `docs/USER_MANUAL.md`
- Modify: `vuln_assessor/desktop_gui.py`
- Test: `tests/test_desktop_gui_workflows.py`

- [ ] **Step 1: Write a failing dependency/documentation regression test**

Add a lightweight test in `tests/test_desktop_gui_workflows.py` or a new small documentation test that asserts:

```python
requirements = Path("requirements.txt").read_text(encoding="utf-8")
self.assertNotIn("scapy", requirements)
self.assertIn("scapy", Path("requirements-advanced.txt").read_text(encoding="utf-8"))
```

- [ ] **Step 2: Run the targeted test**

Run: `python -m unittest tests.test_desktop_gui_workflows -v`

Expected:
- Fail because `requirements-advanced.txt` does not exist yet

- [ ] **Step 3: Split dependency files**

Update dependency files to the target shape:

`requirements.txt`

```text
jinja2>=3.1.4,<4.0
flask>=3.0.0,<4.0
```

`requirements-advanced.txt`

```text
-r requirements.txt
scapy>=2.5.0,<3.0
```

- [ ] **Step 4: Rewrite install/docs around Windows-first setup**

Update `README.md`, `docs/INSTALL.md`, `docs/usage_guide.md`, and `docs/USER_MANUAL.md` so the primary path is:

```powershell
py -3 -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

with separate notes for:

- install `nmap` on Windows
- Tk is typically bundled with the standard Windows Python installer
- `requirements-advanced.txt` is optional for high-friction discovery features
- Linux / WSL2 is supplementary rather than primary

- [ ] **Step 5: Simplify the rules tab default view**

In `vuln_assessor/desktop_gui.py`, make local file import the default visible UI and keep URL update behind an explicit advanced-toggle section, for example:

```python
self.rules_advanced_visible = False
ttk.Button(parent, text="展开高级功能", command=self._toggle_rules_advanced).grid(...)
```

and only render or reveal the URL update row when the advanced section is active.

- [ ] **Step 6: Re-run the targeted tests**

Run: `python -m unittest tests.test_desktop_gui_workflows -v`

Expected:
- Dependency split assertions pass
- GUI workflow tests still pass

- [ ] **Step 7: Commit checkpoint**

```bash
git add requirements.txt requirements-advanced.txt README.md docs/INSTALL.md docs/usage_guide.md docs/USER_MANUAL.md vuln_assessor/desktop_gui.py tests/test_desktop_gui_workflows.py
git commit -m "docs: split advanced dependencies and simplify rules ui"
```

## Task 5: Full Verification Before Completion

**Files:**
- Verify: `tests/test_workbench_flow.py`
- Verify: `tests/test_desktop_gui_workflows.py`
- Verify: `tests/test_gui_launcher.py`
- Verify: `tests/test_desktop_web_control.py`

- [ ] **Step 1: Run the workflow and launcher tests**

Run: `python -m unittest tests.test_workbench_flow tests.test_desktop_gui_workflows tests.test_gui_launcher tests.test_desktop_web_control -v`

Expected:
- All tests pass
- No hidden import or environment regressions

- [ ] **Step 2: Run a syntax-level project check**

Run: `python -m compileall .`

Expected:
- No syntax errors in modified modules

- [ ] **Step 3: Re-read the spec and verify coverage**

Check [2026-04-11-windows-gui-control-center-design.md](/C:/Users/Administrator/Desktop/Yu_workspace/intra_vuln_assessor/docs/superpowers/specs/2026-04-11-windows-gui-control-center-design.md:1) against the completed diff and confirm:

```text
- five tabs exist
- web is report-center only
- discovery and analysis are split
- rules page is simple by default
- windows-first docs and dependency split exist
```

- [ ] **Step 4: Final commit checkpoint**

```bash
git add vuln_assessor tests requirements.txt requirements-advanced.txt README.md docs
git commit -m "feat: deliver windows-first desktop control center"
```
