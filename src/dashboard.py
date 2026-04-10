"""
dashboard.py — Real-time CLI dashboard using the Rich library.

Displays:
  - Live packet capture statistics (total, pps, protocol breakdown)
  - Recent alerts table with color-coded severity
  - ML model status and anomaly stats
  - Rule engine stats
  - Top attacking source IPs
  - Alert distribution by type and severity
"""

import datetime
from typing import Optional

from rich.console import Console
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.align import Align
from rich.columns import Columns
from rich import box

from src.database import DatabaseManager
from src.packet_capture import PacketCapture
from src.rule_engine import RuleEngine
from src.ml_detector import MLDetector, FeatureExtractor
from src.alert_manager import AlertManager


# Severity color mapping for alert tables
SEVERITY_STYLES = {
    "LOW": "cyan",
    "MEDIUM": "yellow",
    "HIGH": "red",
    "CRITICAL": "bold white on red",
}


class Dashboard:
    """
    Rich-based live CLI dashboard for NIDS monitoring.

    Usage:
        dash = Dashboard(config, db, capture, rule_engine, ml_detector, alert_mgr, feature_ext)
        dash.run()   # Blocks — runs the live dashboard until Ctrl+C
    """

    def __init__(
        self,
        config: dict,
        db: DatabaseManager,
        capture: PacketCapture,
        rule_engine: RuleEngine,
        ml_detector: MLDetector,
        alert_manager: AlertManager,
        feature_extractor: FeatureExtractor,
    ):
        self.config = config.get("dashboard", {})
        self.db = db
        self.capture = capture
        self.rule_engine = rule_engine
        self.ml = ml_detector
        self.alert_mgr = alert_manager
        self.feature_ext = feature_extractor
        self.console = Console()
        self.refresh_rate = self.config.get("refresh_rate", 1.0)
        self.max_alerts = self.config.get("max_alerts_display", 20)

    def run(self):
        """Start the live-updating dashboard. Blocks until KeyboardInterrupt."""
        with Live(
            self._build_layout(),
            console=self.console,
            refresh_per_second=1 / self.refresh_rate,
            screen=True,
        ) as live:
            try:
                while self.capture.is_running:
                    live.update(self._build_layout())
            except KeyboardInterrupt:
                pass

    def _build_layout(self) -> Layout:
        """Construct the full dashboard layout from individual panels."""
        layout = Layout()

        # Top row: header
        layout.split_column(
            Layout(name="header", size=3),
            Layout(name="body"),
            Layout(name="footer", size=3),
        )

        # Header
        header_text = Text(
            "  🛡️  NETWORK INTRUSION DETECTION SYSTEM  🛡️  ",
            style="bold white on dark_blue",
            justify="center",
        )
        timestamp = Text(
            f"  {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  ",
            style="dim",
            justify="center",
        )
        layout["header"].update(
            Panel(Align.center(header_text), style="dark_blue")
        )

        # Body: two columns
        layout["body"].split_row(
            Layout(name="left", ratio=1),
            Layout(name="right", ratio=2),
        )

        # Left column: stats panels stacked
        layout["left"].split_column(
            Layout(name="capture_stats"),
            Layout(name="ml_stats"),
            Layout(name="top_ips"),
        )

        layout["capture_stats"].update(self._capture_stats_panel())
        layout["ml_stats"].update(self._ml_stats_panel())
        layout["top_ips"].update(self._top_ips_panel())

        # Right column: alerts
        layout["right"].split_column(
            Layout(name="alert_summary", size=8),
            Layout(name="recent_alerts"),
        )
        layout["alert_summary"].update(self._alert_summary_panel())
        layout["recent_alerts"].update(self._recent_alerts_panel())

        # Footer
        layout["footer"].update(
            Panel(
                Align.center(Text(
                    "Press Ctrl+C to stop  |  "
                    f"Rules loaded: {self.rule_engine.rule_count}  |  "
                    f"Uptime: {self._uptime()}",
                    style="dim"
                )),
                style="dark_blue",
            )
        )

        return layout

    # ------------------------------------------------------------------
    # Individual panels
    # ------------------------------------------------------------------
    def _capture_stats_panel(self) -> Panel:
        """Live packet capture statistics."""
        stats = self.capture.get_stats()
        table = Table(show_header=False, box=box.SIMPLE, expand=True)
        table.add_column("Metric", style="bold cyan")
        table.add_column("Value", justify="right")

        table.add_row("Total Packets", f"{stats['total_packets']:,}")
        table.add_row("Packets/sec", f"{stats['packets_per_second']:.1f}")
        table.add_row("─" * 15, "─" * 10)

        # Protocol breakdown
        for proto, count in sorted(
            stats["protocol_distribution"].items(),
            key=lambda x: x[1], reverse=True
        ):
            pct = (count / max(stats["total_packets"], 1)) * 100
            table.add_row(f"  {proto}", f"{count:,} ({pct:.1f}%)")

        return Panel(table, title="📡 Capture Stats", border_style="blue")

    def _ml_stats_panel(self) -> Panel:
        """Machine learning model status and stats."""
        ml_stats = self.ml.get_stats()
        table = Table(show_header=False, box=box.SIMPLE, expand=True)
        table.add_column("Metric", style="bold magenta")
        table.add_column("Value", justify="right")

        status = "✅ Trained" if ml_stats["is_trained"] else "⏳ Collecting data"
        table.add_row("Model Status", status)
        table.add_row(
            "Training Samples",
            f"{ml_stats['training_samples']}/{ml_stats['min_samples_needed']}"
        )
        table.add_row("Predictions", f"{ml_stats['total_predictions']:,}")
        table.add_row("Anomalies Found", f"{ml_stats['total_anomalies']:,}")
        table.add_row(
            "Anomaly Rate",
            f"{ml_stats['anomaly_rate']:.2%}"
        )
        table.add_row("Feature Buffer", f"{self.feature_ext.buffer_size}")

        return Panel(table, title="🤖 ML Detector", border_style="magenta")

    def _top_ips_panel(self) -> Panel:
        """Top source IPs by alert count."""
        top_ips = self.db.top_source_ips(limit=8)
        table = Table(show_header=True, box=box.SIMPLE_HEAVY, expand=True)
        table.add_column("#", style="dim", width=3)
        table.add_column("Source IP", style="bold")
        table.add_column("Alerts", justify="right", style="red")

        for rank, (ip, count) in enumerate(top_ips, 1):
            table.add_row(str(rank), ip, str(count))

        if not top_ips:
            table.add_row("-", "No alerts yet", "-")

        return Panel(table, title="🎯 Top Attackers", border_style="red")

    def _alert_summary_panel(self) -> Panel:
        """Summary counts by attack type and severity."""
        by_type = self.db.count_by_attack_type()
        by_sev = self.db.count_by_severity()
        total = self.db.count_alerts()

        # Attack type table
        type_table = Table(
            title="By Attack Type", box=box.ROUNDED, expand=True
        )
        type_table.add_column("Type", style="bold")
        type_table.add_column("Count", justify="right")
        for atype, cnt in sorted(by_type.items(), key=lambda x: x[1], reverse=True):
            type_table.add_row(atype, str(cnt))

        # Severity table
        sev_table = Table(
            title="By Severity", box=box.ROUNDED, expand=True
        )
        sev_table.add_column("Level", style="bold")
        sev_table.add_column("Count", justify="right")
        for level in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            cnt = by_sev.get(level, 0)
            style = SEVERITY_STYLES.get(level, "white")
            sev_table.add_row(Text(level, style=style), str(cnt))

        columns = Columns([type_table, sev_table], expand=True)
        header = Text(f"Total Alerts: {total:,}", style="bold white")
        content = Layout()
        content.split_column(
            Layout(Align.center(header), size=1),
            Layout(columns),
        )

        return Panel(content, title="📊 Alert Summary", border_style="yellow")

    def _recent_alerts_panel(self) -> Panel:
        """Table of the most recent alerts."""
        alerts = self.db.get_recent_alerts(limit=self.max_alerts)

        table = Table(box=box.HEAVY_EDGE, expand=True, show_lines=False)
        table.add_column("Time", style="dim", width=19)
        table.add_column("Severity", width=10)
        table.add_column("Attack", style="bold", width=14)
        table.add_column("Source", width=22)
        table.add_column("Dest", width=22)
        table.add_column("Proto", width=6)
        table.add_column("Source", width=10)
        table.add_column("Details", ratio=1)

        for alert in alerts:
            sev_style = SEVERITY_STYLES.get(alert.severity, "white")
            ts = alert.timestamp.strftime("%m-%d %H:%M:%S") if alert.timestamp else "-"
            src = f"{alert.src_ip}:{alert.src_port or '-'}"
            dst = f"{alert.dst_ip or '-'}:{alert.dst_port or '-'}"
            desc = (alert.description or "")[:60]

            table.add_row(
                ts,
                Text(alert.severity, style=sev_style),
                alert.attack_type,
                src,
                dst,
                alert.protocol or "-",
                alert.detection_source or "-",
                desc,
            )

        if not alerts:
            table.add_row("-", "-", "No alerts yet", "-", "-", "-", "-", "-")

        return Panel(table, title="🚨 Recent Alerts", border_style="green")

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    _start_time = None

    def _uptime(self) -> str:
        """Return a human-readable uptime string."""
        if Dashboard._start_time is None:
            Dashboard._start_time = datetime.datetime.now()
        delta = datetime.datetime.now() - Dashboard._start_time
        hours, remainder = divmod(int(delta.total_seconds()), 3600)
        minutes, seconds = divmod(remainder, 60)
        return f"{hours:02d}:{minutes:02d}:{seconds:02d}"
