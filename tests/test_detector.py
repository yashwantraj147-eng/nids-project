"""
test_detector.py — Unit tests for the NIDS modules.

Tests cover:
  - Database CRUD and analytics
  - Rule engine parsing and matching
  - Heuristic detectors (port scan, SYN flood, brute force, ARP spoof, DNS poison)
  - ML feature extraction and prediction pipeline
  - Alert manager fire_alert (with mocked channels)

Run with:
    pytest tests/test_detector.py -v
"""

import os
import sys
import time
import datetime
import tempfile

import numpy as np
import pytest

# Ensure the project root is on the path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.database import DatabaseManager, AlertRecord
from src.packet_capture import PacketInfo, PacketCapture
from src.rule_engine import Rule, RuleEngine
from src.ml_detector import MLDetector, FeatureExtractor, generate_synthetic_training_data
from src.alert_manager import AlertManager


# =====================================================================
# Helpers — create mock PacketInfo objects
# =====================================================================

def make_packet(
    src_ip="10.0.0.1",
    dst_ip="192.168.1.1",
    src_port=12345,
    dst_port=80,
    protocol="TCP",
    flags="S",
    payload_size=100,
    src_mac="aa:bb:cc:dd:ee:ff",
    dst_mac="11:22:33:44:55:66",
    dns_query=None,
    dns_answers=None,
    timestamp=None,
) -> PacketInfo:
    """Create a PacketInfo with specified fields."""
    pkt = PacketInfo()
    pkt.src_ip = src_ip
    pkt.dst_ip = dst_ip
    pkt.src_port = src_port
    pkt.dst_port = dst_port
    pkt.protocol = protocol
    pkt.flags = flags
    pkt.payload_size = payload_size
    pkt.src_mac = src_mac
    pkt.dst_mac = dst_mac
    pkt.dns_query = dns_query
    pkt.dns_answers = dns_answers or []
    pkt.timestamp = timestamp or time.time()
    pkt.raw_summary = f"{protocol} {src_ip}:{src_port} > {dst_ip}:{dst_port} [{flags}]"
    return pkt


# =====================================================================
# Database Tests
# =====================================================================

class TestDatabase:
    """Tests for the SQLite ORM layer."""

    @pytest.fixture(autouse=True)
    def setup_db(self, tmp_path):
        """Create a fresh in-memory-like DB for each test."""
        db_path = str(tmp_path / "test.db")
        self.db = DatabaseManager(db_path=db_path, echo=False, max_alerts=100)
        yield
        self.db.close()

    def test_insert_and_retrieve(self):
        """Insert an alert and verify it can be retrieved."""
        record = self.db.insert_alert(
            src_ip="10.0.0.1",
            attack_type="port_scan",
            severity="HIGH",
            dst_ip="192.168.1.1",
            protocol="TCP",
            description="Test port scan alert",
        )
        assert record.id is not None
        assert record.src_ip == "10.0.0.1"
        assert record.attack_type == "port_scan"
        assert record.severity == "HIGH"

    def test_get_recent_alerts(self):
        """Insert multiple alerts and check ordering."""
        for i in range(5):
            self.db.insert_alert(
                src_ip=f"10.0.0.{i}",
                attack_type="test",
                severity="LOW",
            )
        recent = self.db.get_recent_alerts(limit=3)
        assert len(recent) == 3
        # Most recent should be first (highest ID)
        assert recent[0].id > recent[1].id

    def test_count_by_attack_type(self):
        """Test grouping counts by attack type."""
        self.db.insert_alert(src_ip="1.1.1.1", attack_type="port_scan", severity="HIGH")
        self.db.insert_alert(src_ip="1.1.1.2", attack_type="port_scan", severity="HIGH")
        self.db.insert_alert(src_ip="1.1.1.3", attack_type="syn_flood", severity="CRITICAL")

        counts = self.db.count_by_attack_type()
        assert counts["port_scan"] == 2
        assert counts["syn_flood"] == 1

    def test_count_by_severity(self):
        """Test grouping counts by severity."""
        self.db.insert_alert(src_ip="1.1.1.1", attack_type="test", severity="LOW")
        self.db.insert_alert(src_ip="1.1.1.2", attack_type="test", severity="HIGH")
        self.db.insert_alert(src_ip="1.1.1.3", attack_type="test", severity="HIGH")

        counts = self.db.count_by_severity()
        assert counts["LOW"] == 1
        assert counts["HIGH"] == 2

    def test_top_source_ips(self):
        """Test top attacker IP ranking."""
        for _ in range(5):
            self.db.insert_alert(src_ip="attacker.ip", attack_type="test", severity="HIGH")
        for _ in range(2):
            self.db.insert_alert(src_ip="other.ip", attack_type="test", severity="LOW")

        top = self.db.top_source_ips(limit=2)
        assert top[0][0] == "attacker.ip"
        assert top[0][1] == 5

    def test_prune_old_alerts(self):
        """Test that pruning removes excess alerts."""
        # Set max_alerts to 5
        self.db.max_alerts = 5
        for i in range(10):
            self.db.insert_alert(src_ip=f"10.0.0.{i}", attack_type="test", severity="LOW")

        deleted = self.db.prune_old_alerts()
        assert deleted == 5
        assert self.db.count_alerts() == 5

    def test_get_alerts_by_type(self):
        """Filter alerts by type."""
        self.db.insert_alert(src_ip="1.1.1.1", attack_type="brute_force", severity="HIGH")
        self.db.insert_alert(src_ip="1.1.1.2", attack_type="port_scan", severity="MEDIUM")

        results = self.db.get_alerts_by_type("brute_force")
        assert len(results) == 1
        assert results[0].attack_type == "brute_force"

    def test_alert_to_dict(self):
        """Test serialization to dictionary."""
        record = self.db.insert_alert(
            src_ip="10.0.0.1",
            attack_type="test",
            severity="LOW",
            dst_ip="192.168.1.1",
            protocol="TCP",
        )
        d = record.to_dict()
        assert d["src_ip"] == "10.0.0.1"
        assert "timestamp" in d
        assert d["attack_type"] == "test"


# =====================================================================
# Rule Engine Tests
# =====================================================================

class TestRuleEngine:
    """Tests for Snort-style rule parsing and matching."""

    def test_parse_rule(self):
        """Parse a single Snort-style rule string."""
        engine = self._make_engine()
        rule = engine._parse_rule(
            'alert tcp any any -> any 22 (msg:"SSH attempt"; sid:1001; severity:HIGH; flags:S; attack_type:brute_force;)'
        )
        assert rule is not None
        assert rule.sid == 1001
        assert rule.protocol == "tcp"
        assert rule.dst_port == "22"
        assert rule.flags == "S"
        assert rule.attack_type == "brute_force"
        assert rule.severity == "HIGH"

    def test_rule_matches_packet(self):
        """A TCP SYN to port 22 should match an SSH rule."""
        rule = Rule(
            sid=1001, protocol="tcp", dst_port="22",
            flags="S", attack_type="brute_force", severity="HIGH",
            msg="SSH attempt"
        )
        pkt = make_packet(dst_port=22, protocol="TCP", flags="S")
        assert rule.matches(pkt) is True

    def test_rule_no_match_wrong_port(self):
        """A packet to port 80 should NOT match an SSH rule."""
        rule = Rule(sid=1001, protocol="tcp", dst_port="22", flags="S")
        pkt = make_packet(dst_port=80, protocol="TCP", flags="S")
        assert rule.matches(pkt) is False

    def test_rule_no_match_wrong_protocol(self):
        """A UDP packet should NOT match a TCP rule."""
        rule = Rule(sid=1001, protocol="tcp", dst_port="22")
        pkt = make_packet(dst_port=22, protocol="UDP", flags="")
        assert rule.matches(pkt) is False

    def test_rule_port_range(self):
        """Port range matching (e.g., 1:1024)."""
        rule = Rule(sid=2001, protocol="tcp", dst_port="1:1024")
        pkt_in = make_packet(dst_port=443, protocol="TCP")
        pkt_out = make_packet(dst_port=8080, protocol="TCP")
        assert rule.matches(pkt_in) is True
        assert rule.matches(pkt_out) is False

    def test_rule_any_matches_all(self):
        """A rule with all 'any' should match any packet."""
        rule = Rule(sid=9999)
        pkt = make_packet()
        assert rule.matches(pkt) is True

    # --- Heuristic detector tests ---

    def test_port_scan_detection(self):
        """Simulate a port scan and verify detection."""
        engine = self._make_engine(port_scan_threshold=5)

        alerts = []
        for port in range(20):
            pkt = make_packet(
                src_ip="scanner.ip", dst_port=port, protocol="TCP",
                flags="S", timestamp=time.time()
            )
            result = engine._detect_port_scan(pkt)
            if result:
                alerts.append(result)

        assert len(alerts) >= 1
        assert alerts[0]["attack_type"] == "port_scan"

    def test_syn_flood_detection(self):
        """Simulate a SYN flood and verify detection."""
        engine = self._make_engine(syn_threshold=10, syn_window=60)

        alerts = []
        now = time.time()
        for i in range(15):
            pkt = make_packet(
                src_ip="flooder.ip", dst_port=80, protocol="TCP",
                flags="S", timestamp=now + i * 0.1
            )
            result = engine._detect_syn_flood(pkt)
            if result:
                alerts.append(result)

        assert len(alerts) >= 1
        assert alerts[0]["attack_type"] == "syn_flood"
        assert alerts[0]["severity"] == "CRITICAL"

    def test_brute_force_detection(self):
        """Simulate SSH brute force and verify detection."""
        engine = self._make_engine(brute_threshold=3)

        alerts = []
        now = time.time()
        for i in range(5):
            pkt = make_packet(
                src_ip="bruter.ip", dst_port=22, protocol="TCP",
                flags="S", timestamp=now + i
            )
            result = engine._detect_brute_force(pkt)
            if result:
                alerts.append(result)

        assert len(alerts) >= 1
        assert alerts[0]["attack_type"] == "brute_force"

    def test_arp_spoof_detection(self):
        """Simulate ARP spoofing with two MACs claiming the same IP."""
        config = self._base_config()
        capture = PacketCapture({"interface": None})
        # Manually inject conflicting ARP entries
        capture.arp_table["192.168.1.1"].add("aa:bb:cc:dd:ee:01")
        capture.arp_table["192.168.1.1"].add("aa:bb:cc:dd:ee:02")

        engine = RuleEngine(config, capture)

        pkt = make_packet(
            src_ip="192.168.1.1", protocol="ARP",
            src_mac="aa:bb:cc:dd:ee:02"
        )
        result = engine._detect_arp_spoof(pkt)
        assert result is not None
        assert result["attack_type"] == "arp_spoof"
        assert result["severity"] == "CRITICAL"

    def test_dns_poison_detection(self):
        """Simulate DNS poisoning with divergent answers."""
        config = self._base_config()
        config["thresholds"]["dns_poison"]["response_threshold"] = 2
        capture = PacketCapture({"interface": None})

        # Inject divergent DNS responses
        now = time.time()
        capture.dns_cache["example.com"] = [
            ({"1.1.1.1"}, now),
            ({"2.2.2.2"}, now + 1),
            ({"3.3.3.3"}, now + 2),
        ]

        engine = RuleEngine(config, capture)

        pkt = make_packet(protocol="UDP", dns_query="example.com", dns_answers=["4.4.4.4"])
        result = engine._detect_dns_poison(pkt)
        assert result is not None
        assert result["attack_type"] == "dns_poison"

    # --- Helpers ---

    def _base_config(self):
        return {
            "thresholds": {
                "port_scan": {"unique_ports": 15, "time_window": 60},
                "syn_flood": {"syn_count": 100, "time_window": 10},
                "brute_force": {"attempts": 5, "time_window": 60, "ports": [22, 21]},
                "arp_spoof": {"duplicate_ips": 2, "time_window": 30},
                "dns_poison": {"response_threshold": 5, "time_window": 10},
            },
            "rules": {"enabled": False},
        }

    def _make_engine(self, port_scan_threshold=15, syn_threshold=100,
                     syn_window=10, brute_threshold=5):
        """Create a RuleEngine with custom thresholds for testing."""
        config = self._base_config()
        config["thresholds"]["port_scan"]["unique_ports"] = port_scan_threshold
        config["thresholds"]["syn_flood"]["syn_count"] = syn_threshold
        config["thresholds"]["syn_flood"]["time_window"] = syn_window
        config["thresholds"]["brute_force"]["attempts"] = brute_threshold

        capture = PacketCapture({"interface": None})
        return RuleEngine(config, capture)


# =====================================================================
# ML Detector Tests
# =====================================================================

class TestMLDetector:
    """Tests for the ML anomaly detection pipeline."""

    @pytest.fixture(autouse=True)
    def setup(self, tmp_path):
        """Create a temporary model directory."""
        self.model_path = str(tmp_path / "model.joblib")
        self.scaler_path = str(tmp_path / "scaler.joblib")
        self.ml_config = {
            "model_path": self.model_path,
            "scaler_path": self.scaler_path,
            "contamination": 0.05,
            "n_estimators": 50,
            "min_samples_for_training": 50,
        }

    def test_feature_extraction(self):
        """Test that features are extracted correctly from packets."""
        extractor = FeatureExtractor(window_seconds=60)

        now = time.time()
        for i in range(20):
            pkt = make_packet(
                src_ip=f"10.0.0.{i % 5}",
                dst_port=80 + i,
                payload_size=100 + i * 10,
                timestamp=now + i,
            )
            extractor.add_packet(pkt)

        features = extractor.extract_features()
        assert features is not None
        assert len(features) == len(FeatureExtractor.FEATURE_NAMES)
        assert all(np.isfinite(features))

    def test_training_and_prediction(self):
        """Train the model and make predictions."""
        detector = MLDetector(self.ml_config)

        # Generate and add training data
        data = generate_synthetic_training_data(n_samples=100)
        for sample in data:
            detector.add_training_sample(sample)

        assert detector.training_samples_count == 100

        # Train
        success = detector.train()
        assert success is True
        assert detector.is_trained is True

        # Predict on a normal sample
        normal_sample = data[0]
        result = detector.predict(normal_sample)
        assert result is not None
        assert "is_anomaly" in result
        assert "score" in result
        assert "confidence" in result

    def test_anomaly_detection(self):
        """Verify that clearly anomalous data is flagged."""
        detector = MLDetector(self.ml_config)

        # Train on normal data
        data = generate_synthetic_training_data(n_samples=200)
        for sample in data:
            detector.add_training_sample(sample)
        detector.train()

        # Create an extreme outlier
        anomaly = np.array([
            5000,    # Extreme PPS
            1,       # Single source IP (DDoS-like)
            1,       # Single dest IP
            500,     # Massive port range
            0.95,    # Almost all SYN (flood)
            10,      # Tiny payloads
            0.1,     # Very low entropy
            0.99,    # All TCP
            0.0,
            0.0,
            0.0,
            50000,   # Very high avg port
            60000,   # Huge range
            0.01,    # Very low diversity
        ])

        result = detector.predict(anomaly)
        assert result is not None
        # The extreme outlier should be detected as anomalous
        # Use == instead of 'is' because sklearn returns np.True_ not Python True
        assert result["is_anomaly"] == True

    def test_model_persistence(self):
        """Test save and load of the model."""
        detector = MLDetector(self.ml_config)
        data = generate_synthetic_training_data(n_samples=100)
        for sample in data:
            detector.add_training_sample(sample)
        detector.train()

        # Create a new detector that should load the saved model
        detector2 = MLDetector(self.ml_config)
        assert detector2.is_trained is True

        # Should produce the same prediction
        result1 = detector.predict(data[0])
        result2 = detector2.predict(data[0])
        assert result1["is_anomaly"] == result2["is_anomaly"]

    def test_insufficient_data(self):
        """Model should not train with insufficient samples."""
        detector = MLDetector(self.ml_config)
        for i in range(10):  # Less than min_samples (50)
            detector.add_training_sample(np.random.rand(14))

        success = detector.train()
        assert success is False
        assert detector.is_trained is False

    def test_predict_untrained(self):
        """Prediction on untrained model should return None."""
        detector = MLDetector(self.ml_config)
        result = detector.predict(np.random.rand(14))
        assert result is None

    def test_synthetic_data_shape(self):
        """Verify synthetic data has the correct shape."""
        data = generate_synthetic_training_data(n_samples=50)
        assert data.shape == (50, 14)
        assert np.all(np.isfinite(data))

    def test_ml_stats(self):
        """Test the stats reporting method."""
        detector = MLDetector(self.ml_config)
        stats = detector.get_stats()
        assert "is_trained" in stats
        assert "training_samples" in stats
        assert "total_predictions" in stats
        assert "anomaly_rate" in stats


# =====================================================================
# Alert Manager Tests
# =====================================================================

class TestAlertManager:
    """Tests for the alert dispatcher (with mocked external channels)."""

    @pytest.fixture(autouse=True)
    def setup(self, tmp_path):
        """Set up a test DB and alert config."""
        db_path = str(tmp_path / "test_alerts.db")
        self.db = DatabaseManager(db_path=db_path)
        self.alert_config = {
            "terminal": {"enabled": False},  # Disable terminal output in tests
            "file": {"enabled": False},
            "email": {"enabled": False},
            "slack": {"enabled": False},
            "severity_levels": {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4},
        }
        self.mgr = AlertManager(self.alert_config, self.db)
        yield
        self.db.close()

    def test_fire_alert_saves_to_db(self):
        """Verify that fire_alert persists the alert in the database."""
        self.mgr.fire_alert(
            src_ip="10.0.0.1",
            attack_type="port_scan",
            severity="HIGH",
            dst_ip="192.168.1.1",
            protocol="TCP",
            description="Test scan",
            detection_source="rule_engine",
        )
        alerts = self.db.get_recent_alerts(limit=1)
        assert len(alerts) == 1
        assert alerts[0].src_ip == "10.0.0.1"
        assert alerts[0].attack_type == "port_scan"

    def test_alert_counter(self):
        """Verify that alert counters increment."""
        self.mgr.fire_alert(src_ip="1.1.1.1", attack_type="test", severity="HIGH")
        self.mgr.fire_alert(src_ip="1.1.1.2", attack_type="test", severity="CRITICAL")

        assert self.mgr.total_alerts_fired == 2
        assert self.mgr.alerts_by_severity["HIGH"] == 1
        assert self.mgr.alerts_by_severity["CRITICAL"] == 1

    def test_severity_normalization(self):
        """Verify that severity is uppercased."""
        self.mgr.fire_alert(src_ip="1.1.1.1", attack_type="test", severity="low")
        alerts = self.db.get_recent_alerts(limit=1)
        assert alerts[0].severity == "LOW"

    def test_multiple_alerts(self):
        """Fire many alerts and verify all are stored."""
        for i in range(20):
            self.mgr.fire_alert(
                src_ip=f"10.0.0.{i}",
                attack_type="test",
                severity="MEDIUM",
            )
        assert self.db.count_alerts() == 20
        assert self.mgr.total_alerts_fired == 20


# =====================================================================
# Integration Test
# =====================================================================

class TestIntegration:
    """End-to-end integration tests combining multiple modules."""

    @pytest.fixture(autouse=True)
    def setup(self, tmp_path):
        """Set up a complete NIDS pipeline for integration testing."""
        db_path = str(tmp_path / "integration.db")
        self.db = DatabaseManager(db_path=db_path)

        self.alert_config = {
            "terminal": {"enabled": False},
            "file": {"enabled": False},
            "email": {"enabled": False},
            "slack": {"enabled": False},
        }
        self.alert_mgr = AlertManager(self.alert_config, self.db)

        self.config = {
            "thresholds": {
                "port_scan": {"unique_ports": 5, "time_window": 60},
                "syn_flood": {"syn_count": 10, "time_window": 10},
                "brute_force": {"attempts": 3, "time_window": 60, "ports": [22, 21]},
                "arp_spoof": {"duplicate_ips": 2, "time_window": 30},
                "dns_poison": {"response_threshold": 3, "time_window": 10},
            },
            "rules": {"enabled": False},
        }
        self.capture = PacketCapture({"interface": None})
        self.rule_engine = RuleEngine(self.config, self.capture)
        yield
        self.db.close()

    def test_full_port_scan_pipeline(self):
        """Simulate a port scan through the full pipeline."""
        now = time.time()
        for port in range(10):
            pkt = make_packet(
                src_ip="attacker.ip",
                dst_port=port,
                protocol="TCP",
                flags="S",
                timestamp=now + port * 0.1,
            )
            alerts = self.rule_engine.evaluate(pkt)
            for alert in alerts:
                self.alert_mgr.fire_alert(**alert)

        # Verify alerts were created in the database
        db_alerts = self.db.get_alerts_by_type("port_scan")
        assert len(db_alerts) >= 1
        assert db_alerts[0].src_ip == "attacker.ip"
        assert db_alerts[0].severity == "HIGH"

    def test_full_brute_force_pipeline(self):
        """Simulate SSH brute force through the full pipeline."""
        now = time.time()
        for i in range(5):
            pkt = make_packet(
                src_ip="bruter.ip",
                dst_port=22,
                protocol="TCP",
                flags="S",
                timestamp=now + i,
            )
            alerts = self.rule_engine.evaluate(pkt)
            for alert in alerts:
                self.alert_mgr.fire_alert(**alert)

        db_alerts = self.db.get_alerts_by_type("brute_force")
        assert len(db_alerts) >= 1


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
