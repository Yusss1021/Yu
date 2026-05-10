# Windows Entry, Lab, and Git Delivery Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a Windows double-click GUI entry, remove Linux launcher paths, expand local rules, build a Windows-friendly local lab, and safely initialize/push Git.

**Architecture:** Keep the current Python/Tkinter GUI and scanning pipeline, then add Windows-facing wrappers and a Python-based lab controller instead of shell scripts. Git setup is handled conservatively so remote history is not overwritten blindly.

**Tech Stack:** Python, Tkinter, batch (`.bat`), SQLite, nmap, unittest, Git

---

### Task 1: Add Windows Double-Click GUI Entry

**Files:**
- Create: `start_gui.bat`
- Modify: `README.md`
- Modify: `docs/INSTALL.md`
- Modify: `docs/usage_guide.md`

- [ ] Add a root-level batch launcher that prioritizes `.venv\Scripts\pythonw.exe`, then `pyw`, then `pythonw`, then `python`.
- [ ] Make the launcher `cd` to the project root before starting `main.py gui`.
- [ ] Ensure failure cases keep a visible message instead of silently exiting.
- [ ] Update the docs so Windows users are told to double-click `start_gui.bat`.

### Task 2: Remove Linux Launcher Paths

**Files:**
- Delete: `start_web.sh`
- Delete: `stop_web.sh`
- Delete: `web_control_panel.sh`
- Modify: `README.md`
- Modify: `docs/usage_guide.md`

- [ ] Delete the root-level Linux web launcher scripts.
- [ ] Remove or rewrite docs that still present those scripts as the primary path.

### Task 3: Replace Shell-Based Lab Control with Windows-Friendly Entry

**Files:**
- Create: `lab/lab_manager.py`
- Create: `lab/start_demo_lab.bat`
- Create: `lab/stop_demo_lab.bat`
- Create: `lab/run_demo_scan.bat`
- Delete: `lab/start_demo_lab.sh`
- Delete: `lab/stop_demo_lab.sh`
- Delete: `lab/run_demo_scan.sh`

- [ ] Implement a Python lab manager that can `start`, `stop`, and `scan`.
- [ ] Use PID files in `lab/run/` so the lab can be stopped reliably on Windows.
- [ ] Start mock services on separate loopback hosts for a multi-host feel.
- [ ] Keep the command-line UX simple enough for direct double-click or terminal use.

### Task 4: Expand the Local Rule Library

**Files:**
- Modify: `vuln_assessor/vuln/rules.json`
- Modify: `docs/rules_feed.example.json`

- [ ] Expand rules for the services already in the lab first.
- [ ] Add a few additional common enterprise service rules without changing schema.
- [ ] Keep remediation text and severity conventions consistent.

### Task 5: Add Verification Tests for the New Delivery Paths

**Files:**
- Modify: `tests/test_desktop_gui_workflows.py`
- Create: `tests/test_lab_manager.py`

- [ ] Add tests that assert the Windows batch-oriented delivery files exist.
- [ ] Add tests that validate the lab manager can compute expected service targets and state paths.
- [ ] Keep tests focused on deterministic logic rather than GUI visual behavior.

### Task 6: Clean Runtime Junk and Obvious Redundant Files

**Files:**
- Delete: `.runtime/` runtime artifacts
- Delete: `lab/run/` runtime artifacts
- Delete: `__pycache__/` directories where present

- [ ] Remove generated runtime artifacts from the workspace where safe.
- [ ] Do not delete thesis, docs, tests, or source modules that still have clear value.

### Task 7: Initialize Git and Push Safely

**Files:**
- Create: `.git/` metadata

- [ ] Initialize Git in `intra_vuln_assessor`.
- [ ] Add `origin https://github.com/Yusss1021/Yu.git`.
- [ ] Inspect remote `master` before pushing.
- [ ] If histories are unrelated, avoid destructive overwrite and report the exact condition if manual intervention is needed.
- [ ] If safe, commit current work and push to `origin/master`.

### Task 8: Full Verification

**Files:**
- Verify: `tests/test_workbench_flow.py`
- Verify: `tests/test_desktop_gui_workflows.py`
- Verify: `tests/test_discovery_platform.py`
- Verify: `tests/test_gui_launcher.py`
- Verify: `tests/test_desktop_web_control.py`
- Verify: `tests/test_lab_manager.py`

- [ ] Run the targeted and full unittest suite after implementation.
- [ ] Start the local lab and run at least one real scan against the loopback multi-host target.
- [ ] Confirm reports are written and can be opened through the report center path.
