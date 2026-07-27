from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest


def test_router_key_name_and_candidates(m, manager_factory, monkeypatch, tmp_path):
    assert m.XrayManager.normalize_router_key_name("id_ed25519.pub") == "id_ed25519"
    for value in ("", ".", "../key", "bad name"):
        with pytest.raises(RuntimeError):
            m.XrayManager.normalize_router_key_name(value)
    instance = manager_factory()
    instance.router_ssh_key_path_override = str(tmp_path / "custom")
    monkeypatch.setattr(m, "ROUTER_PRIMARY_KEY_DIR", tmp_path / "primary")
    monkeypatch.setattr(m, "ROUTER_SECONDARY_KEY_DIR", tmp_path / "secondary")
    monkeypatch.setattr(m, "WORKDIR", tmp_path / "work")
    candidates = instance.router_key_candidates()
    assert candidates[0].name == "id_ed25519"
    assert Path(instance.router_ssh_key_path_override) in candidates
    assert len(candidates) == len(set(map(str, candidates)))
    assert m.XrayManager.public_key_path(Path("/x/key")) == Path("/x/key.pub")


def test_ensure_public_key_file(m, manager_factory, monkeypatch, tmp_path):
    instance = manager_factory()
    private = tmp_path / "id"
    private.write_text("private", encoding="utf-8")
    calls = []
    monkeypatch.setattr(m.subprocess, "run", lambda command, **kwargs: calls.append(command) or subprocess.CompletedProcess(command, 0, "ssh-ed25519 AAAA comment\n", ""))
    public = instance.ensure_public_key_file(private)
    assert public.read_text(encoding="utf-8") == "ssh-ed25519 AAAA comment xray-proxy-manager@homeassistant\n"
    assert calls[0][:3] == [m.SSH_KEYGEN_BIN, "-y", "-f"]
    assert oct(public.stat().st_mode & 0o777) == "0o644"
    monkeypatch.setattr(m.subprocess, "run", lambda *a, **k: subprocess.CompletedProcess([], 0, "", ""))
    with pytest.raises(RuntimeError, match="did not return"):
        instance.ensure_public_key_file(private)


def test_install_generated_key_with_password(m, manager_factory, monkeypatch):
    instance = manager_factory()
    instance.router_ssh_password = "pw"
    captured = {}
    def run(command, **kwargs):
        captured.update(command=command, kwargs=kwargs)
        return subprocess.CompletedProcess(command, 0, "ok", "")
    monkeypatch.setattr(m.subprocess, "run", run)
    instance.install_generated_key_with_password("ssh-ed25519 AAAA")
    assert captured["command"][0:2] == [m.SSHPASS_BIN, "-e"]
    assert captured["kwargs"]["env"]["SSHPASS"] == "pw"
    monkeypatch.setattr(m.subprocess, "run", lambda *a, **k: subprocess.CompletedProcess([], 1, "", "denied"))
    with pytest.raises(RuntimeError, match="denied"):
        instance.install_generated_key_with_password("ssh-ed25519 AAAA")


def test_prepare_router_auth_modes(m, manager_factory, monkeypatch, tmp_path):
    instance = manager_factory()
    instance.router_control_enabled = False
    instance.prepare_router_auth()

    instance.router_control_enabled = True
    instance.router_auth_method = "password"
    instance.router_ssh_password = ""
    instance.prepare_router_auth()
    assert "password" in instance.router_state["error"]

    key = tmp_path / "id"
    key.write_text("private", encoding="utf-8")
    pub = tmp_path / "id.pub"
    pub.write_text("ssh-ed25519 AAAA", encoding="utf-8")
    instance.router_auth_method = "existing_key"
    instance.router_state["error"] = ""
    instance.router_key_candidates = lambda: [key]
    instance.ensure_public_key_file = lambda _: pub
    instance.prepare_router_auth()
    assert instance.router_ssh_key_path == key
    assert instance.router_state["public_key"] == "ssh-ed25519 AAAA"
    assert oct(key.stat().st_mode & 0o777) == "0o600"

    instance.router_key_candidates = lambda: [tmp_path / "missing"]
    instance.router_ssh_key_path = None
    instance.prepare_router_auth()
    assert "не найден" in instance.router_state["error"]


def test_router_ssh_command_password_and_key(m, manager_factory, tmp_path):
    instance = manager_factory()
    instance.router_auth_method = "password"
    instance.router_ssh_password = "secret"
    command, env = instance.router_ssh_command("echo ok")
    assert command[0:2] == [m.SSHPASS_BIN, "-e"]
    assert env["SSHPASS"] == "secret"
    assert command[-2:] == ["root@192.0.2.1", "echo ok"]

    instance.router_auth_method = "existing_key"
    instance.router_ssh_key_path = tmp_path / "key"
    command, _ = instance.router_ssh_command("echo ok")
    assert "-i" in command
    instance.router_ssh_key_path = None
    with pytest.raises(RuntimeError, match="не подготовлен"):
        instance.router_ssh_command("echo ok")


def test_run_router_command_guards_and_result(m, manager_factory, monkeypatch, tmp_path):
    instance = manager_factory()
    instance.router_control_enabled = False
    with pytest.raises(RuntimeError, match="отключено"):
        instance.run_router_command("x")
    instance.router_control_enabled = True
    instance.router_auth_method = "password"
    instance.router_ssh_password = ""
    with pytest.raises(RuntimeError, match="Пароль"):
        instance.run_router_command("x")
    instance.router_auth_method = "existing_key"
    instance.router_ssh_key_path = tmp_path / "key"
    with pytest.raises(RuntimeError, match="не найден"):
        instance.run_router_command("x")
    instance.router_ssh_key_path.write_text("x")
    instance.router_ssh_command = lambda cmd: (["ssh", cmd], os.environ.copy())
    monkeypatch.setattr(m.subprocess, "run", lambda *a, **k: subprocess.CompletedProcess([], 0, " output \n", ""))
    assert instance.run_router_command("x") == "output"
    monkeypatch.setattr(m.subprocess, "run", lambda *a, **k: subprocess.CompletedProcess([], 1, "", "failed"))
    with pytest.raises(RuntimeError, match="failed"):
        instance.run_router_command("x")


def test_router_rule_script_contains_status_and_optional_change(m, manager_factory):
    instance = manager_factory()
    status = instance.router_rule_remote_script()
    enable = instance.router_rule_remote_script(True)
    disable = instance.router_rule_remote_script(False)
    assert "mark_domains" in status
    assert "enabled:%s" in status
    assert "enabled=1" in enable
    assert "firewall reload" in enable
    assert "enabled=0" in disable


def test_refresh_router_status_and_restore_external_change(m, manager_factory):
    instance = manager_factory()
    instance.router_control_enabled = False
    instance.refresh_router_status()
    assert instance.router_state["configured"] is False

    instance.router_control_enabled = True
    instance.run_router_command = lambda *a, **k: "enabled:cfg123"
    instance.refresh_router_status()
    assert instance.router_state["available"] is True
    assert instance.router_state["rule_enabled"] is True
    assert instance.router_state["rule_section"] == "cfg123"
    assert instance.state["router_rule_desired_enabled"] is True

    instance.router_state["desired_rule_enabled"] = False
    restored = []
    instance.set_router_rule = lambda desired, automatic=False: restored.append((desired, automatic))
    instance.refresh_router_status()
    assert restored == [(False, True)]

    instance.run_router_command = lambda *a, **k: "unexpected"
    instance.refresh_router_status()
    assert instance.router_state["available"] is False
    assert "unexpected" in instance.router_state["error"]


def test_set_router_rule_success_failure_and_lock(m, manager_factory):
    instance = manager_factory()
    instance.run_router_command = lambda *a, **k: "disabled:cfg"
    instance.set_router_rule(False)
    assert instance.router_state["rule_enabled"] is False
    assert instance.router_state["busy"] is False
    assert instance.state["router_rule_desired_enabled"] is False

    instance.run_router_command = lambda *a, **k: "enabled:cfg"
    with pytest.raises(RuntimeError, match="не перешло"):
        instance.set_router_rule(False)
    assert instance.router_state["available"] is False
    assert instance.router_state["busy"] is False

    assert instance.router_lock.acquire(blocking=False)
    try:
        with pytest.raises(RuntimeError, match="уже выполняется"):
            instance.set_router_rule(True)
    finally:
        instance.router_lock.release()


def test_router_status_loop_one_iteration(m, manager_factory):
    instance = manager_factory()
    calls = []
    class Event:
        def __init__(self): self.done = False
        def is_set(self): return self.done
        def wait(self, _): self.done = True; return True
    instance.stop_event = Event()
    instance.refresh_router_status = lambda: calls.append(True)
    instance.router_status_loop()
    assert calls == [True]
