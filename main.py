#!/usr/bin/env python3
"""
main.py — Entry point for the Network Intrusion Detection System.

Ties together all subsystems:
  1. Loads config from config.yaml
  2. Initializes the SQLite database
  3. Sets up the alert manager (terminal + file + email + Slack)
  4. Starts live packet capture (Scapy)
  5. Initializes the rule engine (Snort-style rules + heuristics)
  6. Initializes the ML anomaly detector (Isolation Forest)
  7. Launches the Rich CLI dashboard

CLI usage:
    python main.py                   # Run with defaults (config.yaml)
    python main.py --config my.yaml  # Custom config
    python main.py --interface eth0  # Override capture interface
    python main.py --train           # Pre-train ML model on synthetic data
    python main.py --no-dashboard    # Run without the dashboard (log-only mode)
    python main.py --list-interfaces # List available network interfaces
"""

import os
import sys
import time
import argparse
import signal
import threading

import yaml
from rich.console import Console

from src.database import DatabaseManager
from src.alert_manager import AlertManager
from src.packet_capture import PacketCapture, PacketInfo, list_interfaces
from src.rule_engine import RuleEngine
from src.ml_detector import MLDetector, FeatureExtractor, generate_synthetic_training_data
from src.dashboard import Dashboard

console = Console()

# Global flag for graceful shutdown
_shutdown_event = threading.Event()


def load_config(path: str) -> dict:
    """Load and return the YAML configuration file."""
    if not os.path.exists(path):
        console.print(f"[red]Config file not found: {path}[/red]")
        sys.exit(1)
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def signal_handler(signum, frame):
    """Handle Ctrl+C gracefully."""
    console.print("\n[yellow]🛑 Shutdown signal received. Stopping...[/yellow]")
    _shutdown_event.set()


def packet_callback_factory(
    rule_engine: RuleEngine,
    ml_detector: MLDetector,
    feature_extractor: FeatureExtractor,
    alert_manager: AlertManager,
    ml_config: dict,
):
    """
    Create the callback function that is invoked for every captured packet.
    Runs both rule-based and ML-based detection.
    """
    # Counter for batching ML feature extraction
    _state = {"pkt_count": 0, "last_train_time": time.time()}
    batch_size = ml_config.get("batch_size", 10)
    retrain_interval = ml_config.get("retrain_interval", 3600)
    ml_enabled = ml_config.get("enabled", True)

    def callback(pkt: PacketInfo):
        # --- Rule-based detection ---
        alerts = rule_engine.evaluate(pkt)
        for alert_data in alerts:
            alert_manager.fire_alert(**alert_data)

        # --- ML-based detection ---
        if not ml_enabled:
            return

        # Add packet to feature extractor's rolling window
        feature_extractor.add_packet(pkt)
        _state["pkt_count"] += 1

        # Every batch_size packets, extract features and run ML
        if _state["pkt_count"] % batch_size == 0:
            features = feature_extractor.extract_features()
            if features is not None:
                if not ml_detector.is_trained:
                    # Still collecting training data
                    ml_detector.add_training_sample(features)
                    if ml_detector.training_samples_count >= ml_detector.min_samples:
                        console.print("[green]📊 Training ML model...[/green]")
                        success = ml_detector.train()
                        if success:
                            console.print("[green]✅ ML model trained successfully![/green]")
                        else:
                            console.print("[red]❌ ML training failed.[/red]")
                else:
                    # Model is trained — run prediction
                    result = ml_detector.predict(features)
                    if result and result["is_anomaly"]:
                        alert_manager.fire_alert(
                            src_ip="N/A (aggregated)",
                            attack_type="anomaly",
                            severity="HIGH" if result["confidence"] > 0.7 else "MEDIUM",
                            protocol="MULTI",
                            description=(
                                f"ML anomaly detected: score={result['score']:.3f}, "
                                f"confidence={result['confidence']:.2%}"
                            ),
                            detection_source="ml_detector",
                            confidence=result["confidence"],
                        )

                    # Periodic retraining
                    now = time.time()
                    if retrain_interval > 0 and (now - _state["last_train_time"]) > retrain_interval:
                        ml_detector.add_training_sample(features)
                        ml_detector.train()
                        _state["last_train_time"] = now

    return callback


def pre_train_model(config: dict):
    """Pre-train the ML model on synthetic data for bootstrapping."""
    console.print("[cyan]🔧 Generating synthetic training data...[/cyan]")
    ml_config = config.get("ml", {})
    detector = MLDetector(ml_config)

    data = generate_synthetic_training_data(n_samples=1500)
    for sample in data:
        detector.add_training_sample(sample)

    console.print(f"[cyan]📊 Training on {len(data)} synthetic samples...[/cyan]")
    success = detector.train()
    if success:
        console.print(f"[green]✅ Model saved to {ml_config.get('model_path', 'models/')}[/green]")
    else:
        console.print("[red]❌ Training failed.[/red]")
    return success


def main():
    """Main entry point — parse args, init subsystems, start capture + dashboard."""

    parser = argparse.ArgumentParser(
        description="Network Intrusion Detection System (NIDS)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "-c", "--config", default="config.yaml",
        help="Path to YAML config file (default: config.yaml)"
    )
    parser.add_argument(
        "-i", "--interface", default=None,
        help="Network interface to capture on (overrides config)"
    )
    parser.add_argument(
        "--train", action="store_true",
        help="Pre-train the ML model on synthetic data and exit"
    )
    parser.add_argument(
        "--no-dashboard", action="store_true",
        help="Run without the Rich dashboard (log-only mode)"
    )
    parser.add_argument(
        "--list-interfaces", action="store_true",
        help="List available network interfaces and exit"
    )
    args = parser.parse_args()

    # --- List interfaces ---
    if args.list_interfaces:
        console.print("\n[bold cyan]Available Network Interfaces:[/bold cyan]\n")
        for iface in list_interfaces():
            console.print(f"  • {iface['name']:30s}  ({iface['address']})")
        return

    # --- Load config ---
    config = load_config(args.config)

    # --- Pre-train mode ---
    if args.train:
        pre_train_model(config)
        return

    # --- Register signal handler for graceful shutdown ---
    signal.signal(signal.SIGINT, signal_handler)
    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, signal_handler)

    # --- Startup banner ---
    console.print("\n[bold bright_white on dark_blue]" + "=" * 60 + "[/]")
    console.print("[bold bright_white on dark_blue]   🛡️  NETWORK INTRUSION DETECTION SYSTEM  🛡️          [/]")
    console.print("[bold bright_white on dark_blue]" + "=" * 60 + "[/]\n")

    # --- Initialize Database ---
    db_config = config.get("database", {})
    db = DatabaseManager(
        db_path=db_config.get("path", "data/nids_alerts.db"),
        echo=db_config.get("echo", False),
        max_alerts=db_config.get("max_alerts", 100_000),
    )
    console.print("[green]✅ Database initialized[/green]")

    # --- Initialize Alert Manager ---
    alert_mgr = AlertManager(config.get("alerts", {}), db)
    console.print("[green]✅ Alert manager ready[/green]")

    # --- Initialize Packet Capture ---
    capture_config = config.get("capture", {})
    if args.interface:
        capture_config["interface"] = args.interface
    capture = PacketCapture(capture_config)
    console.print("[green]✅ Packet capture configured[/green]")

    # --- Initialize Rule Engine ---
    rule_engine = RuleEngine(config, capture)
    console.print(f"[green]✅ Rule engine loaded ({rule_engine.rule_count} rules)[/green]")

    # --- Initialize ML Detector ---
    ml_config = config.get("ml", {})
    ml_detector = MLDetector(ml_config)
    feature_extractor = FeatureExtractor(
        window_seconds=ml_config.get("feature_window", 60)
    )
    if ml_detector.is_trained:
        console.print("[green]✅ ML model loaded from disk[/green]")
    else:
        console.print("[yellow]⏳ ML model will train after sufficient data collected[/yellow]")

    # --- Build the per-packet callback ---
    callback = packet_callback_factory(
        rule_engine=rule_engine,
        ml_detector=ml_detector,
        feature_extractor=feature_extractor,
        alert_manager=alert_mgr,
        ml_config=ml_config,
    )

    # --- Start packet capture ---
    console.print("\n[bold cyan]🚀 Starting packet capture...[/bold cyan]")
    console.print("[dim]   (Requires root/admin privileges)[/dim]\n")
    capture.start(callback=callback)

    # Give the capture thread a moment to start (or fail)
    time.sleep(1)
    if not capture.is_running:
        console.print("[red]❌ Packet capture failed to start. Are you running as admin?[/red]")
        db.close()
        sys.exit(1)

    console.print("[green]✅ Capture active[/green]\n")

    # --- Launch dashboard or headless mode ---
    if not args.no_dashboard:
        try:
            dashboard = Dashboard(
                config=config,
                db=db,
                capture=capture,
                rule_engine=rule_engine,
                ml_detector=ml_detector,
                alert_manager=alert_mgr,
                feature_extractor=feature_extractor,
            )
            dashboard.run()
        except KeyboardInterrupt:
            pass
    else:
        # Headless mode: just keep running until interrupted
        console.print("[dim]Running in headless mode. Press Ctrl+C to stop.[/dim]")
        try:
            while not _shutdown_event.is_set():
                _shutdown_event.wait(timeout=1)
        except KeyboardInterrupt:
            pass

    # --- Cleanup ---
    console.print("\n[yellow]Shutting down...[/yellow]")
    capture.stop()
    db.prune_old_alerts()
    db.close()
    console.print("[green]✅ NIDS stopped cleanly.[/green]\n")


if __name__ == "__main__":
    main()
