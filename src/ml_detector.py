"""
ml_detector.py — Machine Learning anomaly detection module.

Uses Isolation Forest (unsupervised) to detect anomalous traffic patterns.
Features are extracted from sliding windows of packet metadata:
  - Packets per second
  - Unique source IPs
  - Unique destination ports
  - SYN packet ratio
  - Average payload size
  - Protocol entropy
  - Connection diversity score

Includes:
  - Feature extraction from raw PacketInfo objects
  - Model training on baseline "normal" traffic
  - Real-time prediction on new feature vectors
  - Model persistence (save/load via joblib)
"""

import os
import time
import math
import threading
from collections import defaultdict, deque
from typing import Optional

import numpy as np
import joblib
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

from src.packet_capture import PacketInfo


class FeatureExtractor:
    """
    Accumulates packets in a time window and computes feature vectors
    suitable for the anomaly detection model.

    Each feature vector represents a summary of traffic over a fixed
    time window (default 60 seconds).
    """

    # Feature names in order — useful for debugging and logging
    FEATURE_NAMES = [
        "packets_per_second",
        "unique_src_ips",
        "unique_dst_ips",
        "unique_dst_ports",
        "syn_ratio",
        "avg_payload_size",
        "protocol_entropy",
        "tcp_ratio",
        "udp_ratio",
        "icmp_ratio",
        "arp_ratio",
        "avg_dst_port",
        "port_range_span",
        "connection_diversity",
    ]

    def __init__(self, window_seconds: int = 60):
        self.window = window_seconds
        # Rolling buffer of packets within the current window
        self._buffer: deque[PacketInfo] = deque()
        self._lock = threading.Lock()

    def add_packet(self, pkt: PacketInfo):
        """Add a packet to the rolling buffer (thread-safe)."""
        with self._lock:
            self._buffer.append(pkt)
            # Evict packets older than the window
            cutoff = time.time() - self.window
            while self._buffer and self._buffer[0].timestamp < cutoff:
                self._buffer.popleft()

    def extract_features(self) -> Optional[np.ndarray]:
        """
        Compute a feature vector from the current window of packets.
        Returns None if buffer is empty.
        """
        with self._lock:
            packets = list(self._buffer)

        if not packets:
            return None

        n = len(packets)
        time_span = max(packets[-1].timestamp - packets[0].timestamp, 0.001)

        # --- Basic counts ---
        src_ips = set()
        dst_ips = set()
        dst_ports = set()
        protocol_counts: dict[str, int] = defaultdict(int)
        syn_count = 0
        total_payload = 0
        port_values = []

        for pkt in packets:
            if pkt.src_ip:
                src_ips.add(pkt.src_ip)
            if pkt.dst_ip:
                dst_ips.add(pkt.dst_ip)
            if pkt.dst_port is not None:
                dst_ports.add(pkt.dst_port)
                port_values.append(pkt.dst_port)
            protocol_counts[pkt.protocol] += 1
            if pkt.protocol == "TCP" and "S" in pkt.flags and "A" not in pkt.flags:
                syn_count += 1  # Pure SYN (not SYN-ACK)
            total_payload += pkt.payload_size

        # --- Derived features ---
        pps = n / time_span

        syn_ratio = syn_count / max(n, 1)  # Fraction of packets that are pure SYN
        avg_payload = total_payload / max(n, 1)

        # Protocol entropy (Shannon entropy over protocol distribution)
        total_proto = sum(protocol_counts.values())
        entropy = 0.0
        for count in protocol_counts.values():
            if count > 0:
                p = count / total_proto
                entropy -= p * math.log2(p)

        # Protocol ratios
        tcp_ratio = protocol_counts.get("TCP", 0) / max(n, 1)
        udp_ratio = protocol_counts.get("UDP", 0) / max(n, 1)
        icmp_ratio = protocol_counts.get("ICMP", 0) / max(n, 1)
        arp_ratio = protocol_counts.get("ARP", 0) / max(n, 1)

        # Port statistics
        avg_dst_port = np.mean(port_values) if port_values else 0
        port_range = (max(port_values) - min(port_values)) if len(port_values) >= 2 else 0

        # Connection diversity: unique (src_ip, dst_ip, dst_port) tuples / total packets
        connections = set()
        for pkt in packets:
            connections.add((pkt.src_ip, pkt.dst_ip, pkt.dst_port))
        conn_diversity = len(connections) / max(n, 1)

        feature_vector = np.array([
            pps,
            len(src_ips),
            len(dst_ips),
            len(dst_ports),
            syn_ratio,
            avg_payload,
            entropy,
            tcp_ratio,
            udp_ratio,
            icmp_ratio,
            arp_ratio,
            avg_dst_port,
            port_range,
            conn_diversity,
        ], dtype=np.float64)

        return feature_vector

    @property
    def buffer_size(self) -> int:
        return len(self._buffer)


class MLDetector:
    """
    Isolation Forest based anomaly detector.

    Workflow:
        1. Collect normal traffic samples (feature vectors)
        2. Train the model
        3. Run real-time prediction on new feature windows

    Usage:
        detector = MLDetector(config)
        # During baseline collection:
        detector.add_training_sample(feature_vector)
        # When enough samples collected:
        detector.train()
        # During live detection:
        result = detector.predict(feature_vector)
        # result = {"is_anomaly": True, "score": -0.85, "confidence": 0.92}
    """

    def __init__(self, config: dict):
        self.config = config
        self.model_path = config.get("model_path", "models/anomaly_model.joblib")
        self.scaler_path = config.get("scaler_path", "models/scaler.joblib")
        self.contamination = config.get("contamination", 0.05)
        self.n_estimators = config.get("n_estimators", 100)
        self.min_samples = config.get("min_samples_for_training", 500)

        self.model: Optional[IsolationForest] = None
        self.scaler: Optional[StandardScaler] = None
        self.is_trained = False

        # Training data accumulator
        self._training_data: list[np.ndarray] = []
        self._lock = threading.Lock()

        # Stats
        self.total_predictions = 0
        self.total_anomalies = 0

        # Try to load a pre-trained model
        self._load_model()

    def _load_model(self):
        """Load a previously saved model and scaler from disk."""
        if os.path.exists(self.model_path) and os.path.exists(self.scaler_path):
            try:
                self.model = joblib.load(self.model_path)
                self.scaler = joblib.load(self.scaler_path)
                self.is_trained = True
            except Exception as e:
                print(f"[!] Failed to load ML model: {e}")
                self.is_trained = False

    def add_training_sample(self, features: np.ndarray):
        """Add a feature vector to the training dataset."""
        with self._lock:
            self._training_data.append(features)

    @property
    def training_samples_count(self) -> int:
        return len(self._training_data)

    def train(self) -> bool:
        """
        Train the Isolation Forest on accumulated samples.
        Returns True if training succeeded, False otherwise.
        """
        with self._lock:
            if len(self._training_data) < self.min_samples:
                return False

            X = np.array(self._training_data)

        # Fit scaler to normalize features
        self.scaler = StandardScaler()
        X_scaled = self.scaler.fit_transform(X)

        # Train Isolation Forest
        self.model = IsolationForest(
            n_estimators=self.n_estimators,
            contamination=self.contamination,
            random_state=42,
            n_jobs=-1,  # Parallelize across all cores
        )
        self.model.fit(X_scaled)
        self.is_trained = True

        # Persist to disk
        self._save_model()
        return True

    def _save_model(self):
        """Save the trained model and scaler to disk."""
        os.makedirs(os.path.dirname(self.model_path) or ".", exist_ok=True)
        joblib.dump(self.model, self.model_path)
        joblib.dump(self.scaler, self.scaler_path)

    def predict(self, features: np.ndarray) -> Optional[dict]:
        """
        Predict whether a feature vector represents anomalous traffic.
        Returns dict with is_anomaly, score, and confidence, or None if not trained.
        """
        if not self.is_trained or self.model is None or self.scaler is None:
            return None

        try:
            # Reshape for single sample prediction
            X = features.reshape(1, -1)
            X_scaled = self.scaler.transform(X)

            # predict: +1 = normal, -1 = anomaly
            prediction = self.model.predict(X_scaled)[0]

            # decision_function: negative = more anomalous
            raw_score = self.model.decision_function(X_scaled)[0]

            # Convert raw score to a 0-1 confidence value
            # More negative raw_score = higher anomaly confidence
            # Typical raw scores range from -0.5 (very anomalous) to +0.5 (very normal)
            confidence = max(0.0, min(1.0, 0.5 - raw_score))

            is_anomaly = prediction == -1

            self.total_predictions += 1
            if is_anomaly:
                self.total_anomalies += 1

            return {
                "is_anomaly": is_anomaly,
                "score": float(raw_score),
                "confidence": float(confidence),
            }
        except Exception as e:
            print(f"[!] ML prediction error: {e}")
            return None

    def get_stats(self) -> dict:
        """Return model statistics for the dashboard."""
        return {
            "is_trained": self.is_trained,
            "training_samples": self.training_samples_count,
            "min_samples_needed": self.min_samples,
            "total_predictions": self.total_predictions,
            "total_anomalies": self.total_anomalies,
            "anomaly_rate": (
                self.total_anomalies / max(self.total_predictions, 1)
            ),
            "model_path": self.model_path,
        }


def generate_synthetic_training_data(n_samples: int = 1000) -> np.ndarray:
    """
    Generate synthetic "normal" traffic feature vectors for initial training.
    Useful for bootstrapping the model before real traffic is available.

    The synthetic data models a typical small office network:
      - 10-100 packets/sec
      - 5-15 unique source IPs
      - Mostly TCP traffic with some UDP and ICMP
    """
    rng = np.random.RandomState(42)

    data = np.zeros((n_samples, len(FeatureExtractor.FEATURE_NAMES)))

    for i in range(n_samples):
        data[i] = [
            rng.uniform(10, 100),          # pps
            rng.randint(3, 20),            # unique src IPs
            rng.randint(3, 25),            # unique dst IPs
            rng.randint(5, 40),            # unique dst ports
            rng.uniform(0.01, 0.15),       # syn_ratio (low for normal traffic)
            rng.uniform(100, 1400),        # avg payload size
            rng.uniform(0.5, 2.0),         # protocol entropy
            rng.uniform(0.4, 0.8),         # tcp ratio
            rng.uniform(0.1, 0.4),         # udp ratio
            rng.uniform(0.0, 0.05),        # icmp ratio
            rng.uniform(0.0, 0.02),        # arp ratio
            rng.uniform(80, 8000),         # avg dst port
            rng.uniform(100, 5000),        # port range span
            rng.uniform(0.3, 0.8),         # connection diversity
        ]

    return data
