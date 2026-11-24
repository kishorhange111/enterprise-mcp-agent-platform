"""Static checks on the Kubernetes manifests: security posture and cross-file consistency."""

from __future__ import annotations

from pathlib import Path

import yaml

K8S = Path(__file__).resolve().parent.parent / "deploy" / "k8s"


def _load(name: str) -> dict:
    return yaml.safe_load((K8S / name).read_text(encoding="utf-8"))


def test_kustomization_lists_every_manifest():
    listed = set(_load("kustomization.yaml")["resources"])
    on_disk = {p.name for p in K8S.glob("*.yaml")} - {"kustomization.yaml"}
    assert listed == on_disk


def test_deployment_is_hardened():
    spec = _load("deployment.yaml")["spec"]["template"]["spec"]
    container = spec["containers"][0]
    assert spec["securityContext"]["runAsNonRoot"] is True
    assert spec["automountServiceAccountToken"] is False
    sc = container["securityContext"]
    assert sc["allowPrivilegeEscalation"] is False
    assert sc["readOnlyRootFilesystem"] is True
    assert sc["capabilities"]["drop"] == ["ALL"]
    assert {"requests", "limits"} <= container["resources"].keys()
    assert container["readinessProbe"]["httpGet"]["path"] == "/healthz"
    assert container["livenessProbe"]["httpGet"]["path"] == "/healthz"


def test_selectors_and_ports_agree_across_manifests():
    dep = _load("deployment.yaml")
    labels = dep["spec"]["template"]["metadata"]["labels"]
    assert dep["spec"]["selector"]["matchLabels"] == labels
    assert _load("service.yaml")["spec"]["selector"] == labels
    assert _load("pdb.yaml")["spec"]["selector"]["matchLabels"] == labels
    assert _load("networkpolicy.yaml")["spec"]["podSelector"]["matchLabels"] == labels
    port = dep["spec"]["template"]["spec"]["containers"][0]["ports"][0]
    assert _load("service.yaml")["spec"]["ports"][0]["targetPort"] == port["name"]
    assert (
        _load("networkpolicy.yaml")["spec"]["ingress"][0]["ports"][0]["port"]
        == port["containerPort"]
    )


def test_hpa_targets_deployment_and_respects_pdb():
    hpa = _load("hpa.yaml")["spec"]
    assert hpa["scaleTargetRef"]["name"] == _load("deployment.yaml")["metadata"]["name"]
    assert hpa["minReplicas"] > _load("pdb.yaml")["spec"]["minAvailable"]
