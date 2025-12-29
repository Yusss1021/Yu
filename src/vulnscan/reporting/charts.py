"""
ECharts configuration generator.
"""

import json
from typing import Any, Dict, List

from ..core.models import RiskLevel, Severity


class ChartGenerator:
    """
    Generate ECharts configuration for vulnerability reports.
    """

    # Color schemes
    SEVERITY_COLORS = {
        "CRITICAL": "#dc3545",  # Red
        "HIGH": "#fd7e14",      # Orange
        "MEDIUM": "#ffc107",    # Yellow
        "LOW": "#0d6efd",       # Blue
        "INFO": "#6c757d",      # Gray
    }

    RISK_COLORS = {
        "Critical": "#dc3545",
        "High": "#fd7e14",
        "Medium": "#ffc107",
        "Low": "#0d6efd",
        "Info": "#6c757d",
    }

    def severity_pie_chart(
        self,
        critical: int,
        high: int,
        medium: int,
        low: int,
        title: str = "Vulnerability Severity Distribution",
    ) -> Dict[str, Any]:
        """
        Generate pie chart config for severity distribution.

        Args:
            critical: Critical count
            high: High count
            medium: Medium count
            low: Low count
            title: Chart title

        Returns:
            ECharts option dictionary
        """
        data = []
        if critical > 0:
            data.append({
                "value": critical,
                "name": "Critical",
                "itemStyle": {"color": self.SEVERITY_COLORS["CRITICAL"]}
            })
        if high > 0:
            data.append({
                "value": high,
                "name": "High",
                "itemStyle": {"color": self.SEVERITY_COLORS["HIGH"]}
            })
        if medium > 0:
            data.append({
                "value": medium,
                "name": "Medium",
                "itemStyle": {"color": self.SEVERITY_COLORS["MEDIUM"]}
            })
        if low > 0:
            data.append({
                "value": low,
                "name": "Low",
                "itemStyle": {"color": self.SEVERITY_COLORS["LOW"]}
            })

        return {
            "title": {
                "text": title,
                "left": "center",
            },
            "tooltip": {
                "trigger": "item",
                "formatter": "{b}: {c} ({d}%)",
            },
            "legend": {
                "orient": "vertical",
                "left": "left",
            },
            "series": [
                {
                    "name": "Severity",
                    "type": "pie",
                    "radius": "50%",
                    "data": data,
                    "emphasis": {
                        "itemStyle": {
                            "shadowBlur": 10,
                            "shadowOffsetX": 0,
                            "shadowColor": "rgba(0, 0, 0, 0.5)",
                        }
                    },
                }
            ],
        }

    def risk_bar_chart(
        self,
        hosts: List[str],
        scores: List[float],
        title: str = "Host Risk Scores",
    ) -> Dict[str, Any]:
        """
        Generate bar chart config for host risk scores.

        Args:
            hosts: List of host IPs
            scores: Corresponding risk scores
            title: Chart title

        Returns:
            ECharts option dictionary
        """
        # Color bars based on score
        colors = []
        for score in scores:
            if score >= 70:
                colors.append(self.RISK_COLORS["Critical"])
            elif score >= 40:
                colors.append(self.RISK_COLORS["High"])
            elif score >= 20:
                colors.append(self.RISK_COLORS["Medium"])
            else:
                colors.append(self.RISK_COLORS["Low"])

        return {
            "title": {
                "text": title,
                "left": "center",
            },
            "tooltip": {
                "trigger": "axis",
                "axisPointer": {"type": "shadow"},
            },
            "xAxis": {
                "type": "category",
                "data": hosts,
                "axisLabel": {"rotate": 45},
            },
            "yAxis": {
                "type": "value",
                "name": "Risk Score",
                "max": 100,
            },
            "series": [
                {
                    "name": "Risk Score",
                    "type": "bar",
                    "data": [
                        {"value": score, "itemStyle": {"color": color}}
                        for score, color in zip(scores, colors)
                    ],
                }
            ],
        }

    def port_distribution_chart(
        self,
        ports: Dict[int, int],
        title: str = "Open Ports Distribution",
    ) -> Dict[str, Any]:
        """
        Generate bar chart for port distribution.

        Args:
            ports: Dictionary mapping port numbers to counts
            title: Chart title

        Returns:
            ECharts option dictionary
        """
        sorted_ports = sorted(ports.items(), key=lambda x: x[1], reverse=True)[:20]
        port_labels = [str(p[0]) for p in sorted_ports]
        port_counts = [p[1] for p in sorted_ports]

        return {
            "title": {
                "text": title,
                "left": "center",
            },
            "tooltip": {
                "trigger": "axis",
            },
            "xAxis": {
                "type": "category",
                "data": port_labels,
                "name": "Port",
            },
            "yAxis": {
                "type": "value",
                "name": "Count",
            },
            "series": [
                {
                    "name": "Hosts",
                    "type": "bar",
                    "data": port_counts,
                    "itemStyle": {"color": "#0d6efd"},
                }
            ],
        }

    def risk_gauge_chart(
        self,
        score: float,
        title: str = "Overall Risk Score",
    ) -> Dict[str, Any]:
        """
        Generate gauge chart for overall risk score.

        Args:
            score: Risk score (0-100)
            title: Chart title

        Returns:
            ECharts option dictionary
        """
        # Determine color based on score
        if score >= 70:
            color = self.RISK_COLORS["Critical"]
        elif score >= 40:
            color = self.RISK_COLORS["High"]
        elif score >= 20:
            color = self.RISK_COLORS["Medium"]
        else:
            color = self.RISK_COLORS["Low"]

        return {
            "title": {
                "text": title,
                "left": "center",
            },
            "series": [
                {
                    "name": "Risk",
                    "type": "gauge",
                    "min": 0,
                    "max": 100,
                    "splitNumber": 10,
                    "axisLine": {
                        "lineStyle": {
                            "width": 10,
                            "color": [
                                [0.2, self.RISK_COLORS["Low"]],
                                [0.4, self.RISK_COLORS["Medium"]],
                                [0.7, self.RISK_COLORS["High"]],
                                [1, self.RISK_COLORS["Critical"]],
                            ],
                        }
                    },
                    "pointer": {
                        "itemStyle": {"color": "auto"},
                    },
                    "axisTick": {"distance": -10, "length": 8},
                    "splitLine": {"distance": -10, "length": 14},
                    "axisLabel": {"distance": 15},
                    "detail": {
                        "valueAnimation": True,
                        "formatter": "{value}",
                        "color": color,
                        "fontSize": 24,
                    },
                    "data": [{"value": round(score, 1)}],
                }
            ],
        }


    def severity_pie_chart_image(
        self,
        critical: int,
        high: int,
        medium: int,
        low: int,
        title: str = "Severity Distribution",
    ) -> str:
        """Generate static pie chart as base64 PNG for PDF."""
        import io
        import base64
        import matplotlib
        matplotlib.use('Agg')
        import matplotlib.pyplot as plt

        plt.rcParams['font.sans-serif'] = ['Noto Sans CJK SC', 'WenQuanYi Micro Hei', 'SimHei', 'sans-serif']
        plt.rcParams['axes.unicode_minus'] = False

        labels, sizes, colors = [], [], []
        for name, count, color in [
            ("Critical", critical, self.SEVERITY_COLORS["CRITICAL"]),
            ("High", high, self.SEVERITY_COLORS["HIGH"]),
            ("Medium", medium, self.SEVERITY_COLORS["MEDIUM"]),
            ("Low", low, self.SEVERITY_COLORS["LOW"]),
        ]:
            if count > 0:
                labels.append(name)
                sizes.append(count)
                colors.append(color)

        if not sizes:
            return ""

        fig, ax = plt.subplots(figsize=(6, 4))
        ax.pie(sizes, labels=labels, colors=colors, autopct='%1.1f%%', startangle=90)
        ax.set_title(title, fontsize=12, fontweight='bold')

        buf = io.BytesIO()
        plt.savefig(buf, format='png', dpi=150, bbox_inches='tight', facecolor='white')
        plt.close(fig)
        buf.seek(0)
        return base64.b64encode(buf.getvalue()).decode('utf-8')

    def risk_bar_chart_image(
        self,
        hosts: List[str],
        scores: List[float],
        title: str = "Host Risk Scores",
    ) -> str:
        """Generate static bar chart as base64 PNG for PDF."""
        import io
        import base64
        import matplotlib
        matplotlib.use('Agg')
        import matplotlib.pyplot as plt

        if not hosts or not scores:
            return ""

        plt.rcParams['font.sans-serif'] = ['Noto Sans CJK SC', 'WenQuanYi Micro Hei', 'SimHei', 'sans-serif']
        plt.rcParams['axes.unicode_minus'] = False

        colors = []
        for score in scores:
            if score >= 70:
                colors.append(self.RISK_COLORS["Critical"])
            elif score >= 40:
                colors.append(self.RISK_COLORS["High"])
            elif score >= 20:
                colors.append(self.RISK_COLORS["Medium"])
            else:
                colors.append(self.RISK_COLORS["Low"])

        fig, ax = plt.subplots(figsize=(8, 4))
        bars = ax.barh(hosts, scores, color=colors)
        ax.set_xlim(0, 100)
        ax.set_xlabel('Risk Score')
        ax.set_title(title, fontsize=12, fontweight='bold')
        ax.invert_yaxis()

        for bar, score in zip(bars, scores):
            ax.text(score + 2, bar.get_y() + bar.get_height()/2, f'{score:.1f}',
                    va='center', fontsize=9)

        buf = io.BytesIO()
        plt.savefig(buf, format='png', dpi=150, bbox_inches='tight', facecolor='white')
        plt.close(fig)
        buf.seek(0)
        return base64.b64encode(buf.getvalue()).decode('utf-8')


def to_json(chart_config: Dict[str, Any]) -> str:
    """
    Convert chart configuration to JSON string.

    Args:
        chart_config: ECharts option dictionary

    Returns:
        JSON string
    """
    return json.dumps(chart_config, ensure_ascii=False)
