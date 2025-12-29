"""
Chinese (Simplified) language messages.
"""

MESSAGES = {
    # Common
    "title": "网络脆弱性扫描与风险评估系统",
    "welcome": "欢迎使用脆弱性扫描系统",
    "error": "错误",
    "success": "成功",
    "warning": "警告",
    "info": "信息",

    # Navigation
    "dashboard": "仪表盘",
    "new_scan": "新建扫描",
    "history": "扫描历史",
    "settings": "设置",

    # Dashboard
    "total_scans": "扫描总数",
    "hosts_scanned": "已扫描主机",
    "vulns_found": "发现漏洞",
    "critical_hosts": "高危主机",
    "recent_scans": "最近扫描",

    # Scan
    "scanning": "正在扫描",
    "scan_target": "扫描目标",
    "discovery_method": "发现方式",
    "port_range": "端口范围",
    "start_scan": "开始扫描",
    "stop_scan": "停止扫描",

    # Status
    "pending": "等待中",
    "running": "运行中",
    "completed": "已完成",
    "failed": "失败",

    # Scan Details
    "scan_details": "扫描详情",
    "host_list": "主机列表",
    "service_list": "服务列表",
    "vulnerability_list": "漏洞列表",

    # Host
    "ip_address": "IP地址",
    "hostname": "主机名",
    "mac_address": "MAC地址",
    "os": "操作系统",
    "services": "服务",

    # Service
    "port": "端口",
    "protocol": "协议",
    "service_name": "服务名称",
    "product": "产品",
    "version": "版本",

    # Vulnerability
    "cve_id": "CVE编号",
    "severity": "严重程度",
    "cvss": "CVSS评分",
    "description": "描述",
    "affected_products": "受影响产品",
    "solution": "解决方案",

    # Risk
    "risk_score": "风险评分",
    "risk_level": "风险等级",
    "risk_critical": "严重",
    "risk_high": "高危",
    "risk_medium": "中危",
    "risk_low": "低危",
    "risk_info": "信息",

    # Report
    "report_title": "网络脆弱性扫描报告",
    "executive_summary": "执行摘要",
    "host_inventory": "主机清单",
    "vulnerability_details": "漏洞详情",
    "export_report": "导出报告",
    "print_report": "打印报告",
    "generated_by": "报告生成工具",

    # Actions
    "view_details": "查看详情",
    "download": "下载",
    "delete": "删除",
    "refresh": "刷新",
    "cancel": "取消",
    "confirm": "确认",

    # Progress
    "host_discovery": "主机发现",
    "service_scan": "服务识别",
    "verification": "漏洞验证",
    "vuln_match": "漏洞匹配",
    "risk_scoring": "风险评估",
    "report_gen": "生成报告",
    "complete": "扫描完成",

    # Messages
    "scan_started": "扫描已开始",
    "scan_completed": "扫描已完成",
    "scan_failed": "扫描失败",
    "no_hosts_found": "未发现主机",
    "no_vulns_found": "未发现漏洞",
    "report_saved": "报告已保存至",
    "root_required": "需要root权限运行扫描",
}
