import csv
import json
import os

import yaml

import ml_detector
from ml_detector import MLDetectorDaemon, ModelTrainer, SyntheticDataGenerator

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def test_pcap_generation_and_offline_extraction(tmp_path):
    import generate_pcap
    from feature_extractor import ScapyExtractor

    pcap = str(tmp_path / "capture.pcap")
    generate_pcap.generate(pcap, n_benign=2, seed=7)
    assert os.path.isfile(pcap)

    extractor = ScapyExtractor(interface="lo")
    extractor.read_pcap(pcap)
    assert len(extractor.flows) > 0

    csv_path = str(tmp_path / "flows.csv")
    records = extractor.export_flows(csv_path)
    assert os.path.isfile(csv_path)
    assert len(records) > 0
    with open(csv_path) as f:
        assert len(list(csv.DictReader(f))) == len(records)


def test_batch_detect_processes_eve_json(tmp_path):
    X, y = SyntheticDataGenerator.generate_dataset(n_benign=200, n_attack=50)
    trainer = ModelTrainer(model_type="isolation_forest")
    trainer.train(X, y)

    eve = tmp_path / "eve.json"
    with open(eve, "w") as f:
        for i in range(3):
            f.write(
                json.dumps(
                    {
                        "timestamp": "2026-09-16T00:00:00",
                        "event_type": "flow",
                        "flow": {
                            "flow_id": i,
                            "duration": 0.5,
                            "pkts_toserver": 120,
                            "pkts_toclient": 10,
                            "bytes_toserver": 8000,
                            "bytes_toclient": 600,
                            "syn_count": 110,
                            "ack_count": 5,
                        },
                    }
                )
                + "\n"
            )

    daemon = MLDetectorDaemon(eve_json_path=str(eve), threshold=0.7)
    daemon.trainer = trainer
    daemon.trainer.is_trained = True
    report = daemon.process_file(str(eve), str(tmp_path / "report.json"))
    assert report["total_events"] == 3
    assert os.path.isfile(str(tmp_path / "report.json"))


def test_batch_detect_missing_eve_json_skips(tmp_path):
    daemon = MLDetectorDaemon(eve_json_path=str(tmp_path / "does-not-exist.json"))
    report = daemon.process_file()
    assert report.get("skipped") is True


def test_live_attacks_config_has_7_vectors():
    with open(os.path.join(ROOT, "config", "attacks_live.yaml")) as f:
        config = yaml.safe_load(f)
    assert "attacks" in config
    assert len(config["attacks"]) == 7


def test_compose_gateway_uses_single_rule_flag():
    with open(os.path.join(ROOT, "infra", "docker-compose.yml")) as f:
        compose = yaml.safe_load(f)
    cmd = compose["services"]["security-gateway"]["command"]
    assert cmd.count("-S ") <= 1
    for svc in compose["services"].values():
        for vol in svc.get("volumes", []):
            assert not vol.startswith("./"), f"compose paths must be repo-rooted: {vol}"


def test_run_everything_helpers_exist():
    for name in ("run_everything.sh", "wait_for_infra.sh"):
        path = os.path.join(ROOT, "scripts", name)
        assert os.path.isfile(path)
        assert os.access(path, os.X_OK)
