import os
import re

import pytest
import yaml

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def test_docker_compose_parses():
    path = os.path.join(ROOT, "infra", "docker-compose.yml")
    with open(path, "r", encoding="utf-8") as f:
        compose = yaml.safe_load(f)
    assert "services" in compose
    for name, svc in compose["services"].items():
        assert not (
            svc.get("network_mode") == "host" and svc.get("networks")
        ), f"{name} declares both host networking and bridge networks"
    assert "vpc-net" in compose["networks"]


def test_dockerfiles_exist():
    assert os.path.isfile(os.path.join(ROOT, "ml", "Dockerfile"))
    assert os.path.isfile(os.path.join(ROOT, "scripts", "Dockerfile"))


def test_attacks_yaml_exists_and_parses():
    path = os.path.join(ROOT, "config", "attacks.yaml")
    with open(path, "r", encoding="utf-8") as f:
        config = yaml.safe_load(f)
    assert "attacks" in config
    assert len(config["attacks"]) == 7


def test_rule_files_contain_51_alerts():
    total = 0
    for name in ("suricata_a1.rules", "suricata_a4.rules"):
        path = os.path.join(ROOT, "rules", name)
        with open(path, "r", encoding="utf-8") as f:
            content = f.read()
        total += len(re.findall(r"^\s*alert\s", content, flags=re.MULTILINE))
    assert total == 51


def test_suricata_config_has_no_missing_emerging_refs():
    path = os.path.join(ROOT, "config", "suricata.yaml")
    with open(path, "r", encoding="utf-8") as f:
        config = yaml.safe_load(f)
    rule_files = config.get("rule-files", [])
    for rule in rule_files:
        assert "emerging-" not in rule