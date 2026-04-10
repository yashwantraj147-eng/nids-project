"""
alert_manager.py — Multi-channel alert dispatcher.

Sends detection alerts to:
  1. Terminal (Rich colored output)
  2. Log file (rotating file handler)
  3. Email (SMTP with TLS)
  4. Slack (incoming webhook)

Each channel respects a minimum severity threshold from config.yaml.
"""

import os
import json
import logging
import smtplib
import datetime
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from logging.handlers import RotatingFileHandler
from typing import Optional

import requests
from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from src.database import DatabaseManager


# Severity ordering for threshold comparisons
SEVERITY_ORDER = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}

console = Console()


class AlertManager:
    """
    Central alert dispatcher.

    Usage:
        mgr = AlertManager(config["alerts"], db_manager)
        mgr.fire_alert(
            src_ip="10.0.0.5", dst_ip="192.168.1.1",
            attack_type="port_scan", severity="HIGH",
            description="Scanned 42 ports in 10s",
            protocol="TCP", detection_source="rule_engine"
        )
    """

    def __init__(self, alert_config: dict, db: DatabaseManager):
        self.config = alert_config
        self.db = db

        # --- File logger setup ---
        self.file_logger = None
        file_cfg = self.config.get("file", {})
        if file_cfg.get("enabled", False):
            log_path = file_cfg.get("path", "logs/alerts.log")
            os.makedirs(os.path.dirname(log_path) if os.path.dirname(log_path) else ".", exist_ok=True)
            self.file_logger = logging.getLogger("nids.alerts")
            self.file_logger.setLevel(logging.DEBUG)
            # Prevent duplicate handlers on re-init
            if not self.file_logger.handlers:
                handler = RotatingFileHandler(
                    log_path,
                    maxBytes=file_cfg.get("max_size_mb", 50) * 1024 * 1024,
                    backupCount=file_cfg.get("backup_count", 5),
                )
                fmt = file_cfg.get("format", "%(asctime)s | %(levelname)s | %(message)s")
                handler.setFormatter(logging.Formatter(fmt))
                self.file_logger.addHandler(handler)

        # --- Email config ---
        self.email_cfg = self.config.get("email", {})
        # Allow password from env var override
        if not self.email_cfg.get("password"):
            self.email_cfg["password"] = os.environ.get("NIDS_EMAIL_PASSWORD", "")

        # --- Slack config ---
        self.slack_cfg = self.config.get("slack", {})
        if not self.slack_cfg.get("webhook_url"):
            self.slack_cfg["webhook_url"] = os.environ.get("NIDS_SLACK_WEBHOOK", "")

        # Internal counters for dashboard stats
        self.total_alerts_fired = 0
        self.alerts_by_severity: dict[str, int] = {s: 0 for s in SEVERITY_ORDER}

    # ------------------------------------------------------------------
    # Core dispatch
    # ------------------------------------------------------------------
    def fire_alert(
        self,
        src_ip: str,
        attack_type: str,
        severity: str,
        dst_ip: Optional[str] = None,
        src_port: Optional[int] = None,
        dst_port: Optional[int] = None,
        protocol: Optional[str] = None,
        description: Optional[str] = None,
        raw_packet: Optional[str] = None,
        detection_source: Optional[str] = None,
        confidence: Optional[float] = None,
    ):
        """
        Process a detection event across all enabled channels.
        Also persists the alert in the SQLite database.
        """
        severity = severity.upper()
        now = datetime.datetime.now(datetime.UTC)

        # 1. Persist to database
        record = self.db.insert_alert(
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            protocol=protocol,
            attack_type=attack_type,
            severity=severity,
            description=description,
            raw_packet=raw_packet,
            detection_source=detection_source,
            confidence=confidence,
            timestamp=now,
        )

        self.total_alerts_fired += 1
        self.alerts_by_severity[severity] = self.alerts_by_severity.get(severity, 0) + 1

        # 2. Terminal alert
        if self.config.get("terminal", {}).get("enabled", True):
            self._terminal_alert(record)

        # 3. File log
        if self.file_logger:
            self._file_alert(record)

        # 4. Email (if severity meets threshold)
        if self.email_cfg.get("enabled", False):
            min_sev = self.email_cfg.get("min_severity", "HIGH")
            if SEVERITY_ORDER.get(severity, 0) >= SEVERITY_ORDER.get(min_sev, 3):
                self._email_alert(record)

        # 5. Slack webhook (if severity meets threshold)
        if self.slack_cfg.get("enabled", False) and self.slack_cfg.get("webhook_url"):
            min_sev = self.slack_cfg.get("min_severity", "MEDIUM")
            if SEVERITY_ORDER.get(severity, 0) >= SEVERITY_ORDER.get(min_sev, 2):
                self._slack_alert(record)

    # ------------------------------------------------------------------
    # Channel implementations
    # ------------------------------------------------------------------
    def _terminal_alert(self, record):
        """Print a colorful Rich panel to the terminal."""
        color_map = self.config.get("terminal", {}).get("colors", {})
        style = color_map.get(record.severity, "white")

        header = Text(f"⚠  {record.attack_type.upper()} DETECTED", style=f"bold {style}")
        body_lines = [
            f"Severity   : {record.severity}",
            f"Source     : {record.src_ip}:{record.src_port or '-'}",
            f"Dest       : {record.dst_ip or '-'}:{record.dst_port or '-'}",
            f"Protocol   : {record.protocol or '-'}",
            f"Source     : {record.detection_source or '-'}",
            f"Time       : {record.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')}",
        ]
        if record.description:
            body_lines.append(f"Details    : {record.description}")
        if record.confidence is not None:
            body_lines.append(f"Confidence : {record.confidence:.2%}")

        body = Text("\n".join(body_lines))
        console.print(Panel(body, title=header, border_style=style, expand=False))

    def _file_alert(self, record):
        """Write structured log line."""
        msg = (
            f"[{record.severity}] {record.attack_type} | "
            f"{record.src_ip}:{record.src_port or '-'} -> "
            f"{record.dst_ip or '-'}:{record.dst_port or '-'} | "
            f"{record.protocol or '-'} | {record.description or ''} | "
            f"source={record.detection_source or '-'}"
        )
        level_map = {
            "LOW": logging.INFO,
            "MEDIUM": logging.WARNING,
            "HIGH": logging.ERROR,
            "CRITICAL": logging.CRITICAL,
        }
        self.file_logger.log(level_map.get(record.severity, logging.WARNING), msg)

    def _email_alert(self, record):
        """Send alert via SMTP email."""
        cfg = self.email_cfg
        try:
            msg = MIMEMultipart("alternative")
            subject_prefix = cfg.get("subject_prefix", "[NIDS ALERT]")
            msg["Subject"] = f"{subject_prefix} {record.severity} - {record.attack_type}"
            msg["From"] = cfg["sender"]
            msg["To"] = ", ".join(cfg.get("recipients", []))

            # Plain-text body
            text_body = (
                f"NIDS Alert\n"
                f"{'='*40}\n"
                f"Attack Type : {record.attack_type}\n"
                f"Severity    : {record.severity}\n"
                f"Source IP   : {record.src_ip}\n"
                f"Dest IP     : {record.dst_ip or 'N/A'}\n"
                f"Protocol    : {record.protocol or 'N/A'}\n"
                f"Timestamp   : {record.timestamp}\n"
                f"Description : {record.description or 'N/A'}\n"
                f"Detection   : {record.detection_source or 'N/A'}\n"
            )
            msg.attach(MIMEText(text_body, "plain"))

            # HTML body for nicer rendering
            html_body = f"""
            <html><body>
            <h2 style="color:red;">🚨 NIDS Alert — {record.severity}</h2>
            <table border="1" cellpadding="5">
              <tr><td><b>Attack</b></td><td>{record.attack_type}</td></tr>
              <tr><td><b>Source</b></td><td>{record.src_ip}:{record.src_port or '-'}</td></tr>
              <tr><td><b>Destination</b></td><td>{record.dst_ip or '-'}:{record.dst_port or '-'}</td></tr>
              <tr><td><b>Protocol</b></td><td>{record.protocol or '-'}</td></tr>
              <tr><td><b>Time</b></td><td>{record.timestamp}</td></tr>
              <tr><td><b>Details</b></td><td>{record.description or '-'}</td></tr>
            </table>
            </body></html>
            """
            msg.attach(MIMEText(html_body, "html"))

            with smtplib.SMTP(cfg["smtp_server"], cfg["smtp_port"]) as server:
                if cfg.get("use_tls", True):
                    server.starttls()
                if cfg.get("password"):
                    server.login(cfg["sender"], cfg["password"])
                server.sendmail(cfg["sender"], cfg.get("recipients", []), msg.as_string())

        except Exception as e:
            # Email failure should never crash the NIDS — log and continue
            if self.file_logger:
                self.file_logger.error(f"Email alert failed: {e}")
            console.print(f"[dim red]Email alert failed: {e}[/dim red]")

    def _slack_alert(self, record):
        """Post alert to a Slack incoming webhook."""
        cfg = self.slack_cfg
        try:
            severity_emoji = {
                "LOW": "🔵",
                "MEDIUM": "🟡",
                "HIGH": "🔴",
                "CRITICAL": "🚨",
            }
            emoji = severity_emoji.get(record.severity, "⚠️")

            payload = {
                "channel": cfg.get("channel", "#security-alerts"),
                "username": cfg.get("username", "NIDS Bot"),
                "icon_emoji": cfg.get("icon_emoji", ":shield:"),
                "blocks": [
                    {
                        "type": "header",
                        "text": {
                            "type": "plain_text",
                            "text": f"{emoji} {record.attack_type.upper()} — {record.severity}",
                        },
                    },
                    {
                        "type": "section",
                        "fields": [
                            {"type": "mrkdwn", "text": f"*Source:*\n{record.src_ip}:{record.src_port or '-'}"},
                            {"type": "mrkdwn", "text": f"*Dest:*\n{record.dst_ip or '-'}:{record.dst_port or '-'}"},
                            {"type": "mrkdwn", "text": f"*Protocol:*\n{record.protocol or '-'}"},
                            {"type": "mrkdwn", "text": f"*Detection:*\n{record.detection_source or '-'}"},
                        ],
                    },
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": f"📝 {record.description or 'No details'}",
                        },
                    },
                    {
                        "type": "context",
                        "elements": [
                            {
                                "type": "mrkdwn",
                                "text": f"🕐 {record.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')}",
                            }
                        ],
                    },
                ],
            }

            resp = requests.post(
                cfg["webhook_url"],
                data=json.dumps(payload),
                headers={"Content-Type": "application/json"},
                timeout=5,
            )
            resp.raise_for_status()

        except Exception as e:
            if self.file_logger:
                self.file_logger.error(f"Slack alert failed: {e}")
            console.print(f"[dim red]Slack alert failed: {e}[/dim red]")
