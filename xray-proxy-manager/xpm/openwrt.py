from __future__ import annotations

import os
import re
import shlex
import subprocess
from pathlib import Path
from typing import Any
from . import common as xpm_common


class OpenwrtMixin:
    @staticmethod
    def normalize_router_key_name(value: Any) -> str:
        name = str(value or '').strip()
        if name.endswith('.pub'):
            name = name[:-4]
        if not name or name in {'.', '..'} or Path(name).name != name:
            raise RuntimeError('router_ssh_key_name must contain only a file name, without a path.')
        if not xpm_common.SAFE_KEY_NAME_RE.fullmatch(name):
            raise RuntimeError('router_ssh_key_name contains unsupported characters.')
        return name

    def router_key_candidates(self) -> list[Path]:
        candidates: list[Path] = [
            xpm_common.ROUTER_PRIMARY_KEY_DIR / self.router_ssh_key_name,
            xpm_common.ROUTER_SECONDARY_KEY_DIR / self.router_ssh_key_name,
            xpm_common.WORKDIR / self.router_ssh_key_name,
        ]
        if self.router_ssh_key_path_override:
            candidates.append(Path(self.router_ssh_key_path_override))
        candidates.append(xpm_common.WORKDIR / 'router_ssh_key')
        unique: list[Path] = []
        seen: set[str] = set()
        for candidate in candidates:
            key = str(candidate)
            if key not in seen:
                seen.add(key)
                unique.append(candidate)
        return unique

    @staticmethod
    def public_key_path(private_path: Path) -> Path:
        return Path(f'{private_path}.pub')

    def ensure_public_key_file(self, private_path: Path) -> Path:
        public_path = self.public_key_path(private_path)
        result = subprocess.run(
            [xpm_common.SSH_KEYGEN_BIN, '-y', '-f', str(private_path)],
            check=True,
            capture_output=True,
            text=True,
            timeout=20,
        )
        derived_key = result.stdout.strip()
        if not derived_key:
            raise RuntimeError('ssh-keygen did not return a public key')

        existing_key = ''
        if public_path.exists():
            existing_key = public_path.read_text(encoding='utf-8').strip()
        derived_identity = ' '.join(derived_key.split()[:2])
        existing_identity = ' '.join(existing_key.split()[:2])
        if existing_identity != derived_identity:
            public_path.write_text(
                f'{derived_key} xray-proxy-manager@homeassistant\n',
                encoding='utf-8',
            )
        public_path.chmod(0o644)
        return public_path

    def install_generated_key_with_password(self, public_key: str) -> None:
        if not self.router_ssh_password:
            return
        remote_script = (
            'set -e; umask 077; mkdir -p /etc/dropbear; '
            'touch /etc/dropbear/authorized_keys; '
            f'KEY={shlex.quote(public_key)}; '
            'grep -qxF "$KEY" /etc/dropbear/authorized_keys 2>/dev/null || '
            'printf "%s\n" "$KEY" >> /etc/dropbear/authorized_keys; '
            'chmod 600 /etc/dropbear/authorized_keys; echo key-installed'
        )
        command = [
            xpm_common.SSHPASS_BIN, '-e', xpm_common.SSH_BIN,
            '-p', str(self.router_ssh_port),
            '-o', 'ConnectTimeout=6',
            '-o', 'ServerAliveInterval=5',
            '-o', 'ServerAliveCountMax=1',
            '-o', 'StrictHostKeyChecking=accept-new',
            '-o', f'UserKnownHostsFile={xpm_common.WORKDIR / "router_known_hosts"}',
            '-o', 'LogLevel=ERROR',
            '-o', 'BatchMode=no',
            '-o', 'PreferredAuthentications=password,keyboard-interactive',
            f'{self.router_ssh_user}@{self.router_host}',
            remote_script,
        ]
        environment = os.environ.copy()
        environment['SSHPASS'] = self.router_ssh_password
        result = subprocess.run(
            command, capture_output=True, text=True, timeout=20, env=environment
        )
        if result.returncode != 0:
            message = (result.stderr or result.stdout or f'ssh exit {result.returncode}').strip()
            raise RuntimeError(f'Не удалось установить сгенерированный ключ: {message}')

    def prepare_router_auth(self) -> None:
        if not self.router_control_enabled:
            return
        if self.router_auth_method == 'password':
            if not self.router_ssh_password:
                self.router_state['error'] = 'Для password требуется router_ssh_password'
            return
        try:
            key_path: Path | None = None
            for candidate in self.router_key_candidates():
                if candidate.exists() and candidate.is_file():
                    key_path = candidate
                    break

            if key_path is None and self.router_auth_method == 'generate_key':
                key_path = xpm_common.ROUTER_PRIMARY_KEY_DIR / self.router_ssh_key_name
                key_path.parent.mkdir(parents=True, exist_ok=True)
                subprocess.run(
                    [xpm_common.SSH_KEYGEN_BIN, '-q', '-t', 'ed25519', '-N', '', '-C',
                     'xray-proxy-manager@homeassistant', '-f', str(key_path)],
                    check=True,
                    capture_output=True,
                    text=True,
                    timeout=20,
                )

            if key_path is None:
                searched = ', '.join(str(item) for item in self.router_key_candidates())
                raise RuntimeError(
                    f'Приватный SSH-ключ {self.router_ssh_key_name} не найден. Проверены: {searched}'
                )

            key_path.chmod(0o600)
            public_path = self.ensure_public_key_file(key_path)
            self.router_ssh_key_path = key_path
            public_key = public_path.read_text(encoding='utf-8').strip()
            self.router_state['public_key'] = public_key
            self.router_state['key_name'] = self.router_ssh_key_name

            if self.router_auth_method == 'generate_key' and self.router_ssh_password:
                self.install_generated_key_with_password(public_key)
        except Exception as exc:
            self.router_state['error'] = f'Не удалось подготовить SSH-доступ: {exc}'
            xpm_common.log(self.router_state['error'], error=True)

    def router_ssh_command(self, remote_command: str) -> tuple[list[str], dict[str, str]]:
        command: list[str] = []
        environment = os.environ.copy()
        use_password = self.router_auth_method == 'password'
        if use_password:
            command.extend([xpm_common.SSHPASS_BIN, '-e'])
            environment['SSHPASS'] = self.router_ssh_password
        command.extend([
            xpm_common.SSH_BIN,
            '-p', str(self.router_ssh_port),
            '-o', 'ConnectTimeout=6',
            '-o', 'ServerAliveInterval=5',
            '-o', 'ServerAliveCountMax=1',
            '-o', 'StrictHostKeyChecking=accept-new',
            '-o', f'UserKnownHostsFile={xpm_common.WORKDIR / "router_known_hosts"}',
            '-o', 'LogLevel=ERROR',
        ])
        if use_password:
            command.extend(['-o', 'BatchMode=no', '-o', 'PreferredAuthentications=password,keyboard-interactive'])
        else:
            if self.router_ssh_key_path is None:
                raise RuntimeError('SSH-ключ для OpenWrt не подготовлен')
            command.extend(['-o', 'BatchMode=yes', '-i', str(self.router_ssh_key_path)])
        command.extend([f'{self.router_ssh_user}@{self.router_host}', remote_command])
        return command, environment

    def run_router_command(self, remote_command: str, timeout: int = 20) -> str:
        if not self.router_control_enabled:
            raise RuntimeError('Управление правилом OpenWrt отключено в настройках')
        if self.router_auth_method == 'password':
            if not self.router_ssh_password:
                raise RuntimeError('Пароль OpenWrt не указан')
        elif self.router_ssh_key_path is None or not self.router_ssh_key_path.exists():
            raise RuntimeError(f'Приватный SSH-ключ {self.router_ssh_key_name} не найден')
        command, environment = self.router_ssh_command(remote_command)
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            env=environment,
        )
        if result.returncode != 0:
            message = (result.stderr or result.stdout or f'ssh exit {result.returncode}').strip()
            raise RuntimeError(message)
        return result.stdout.strip()

    def router_rule_remote_script(self, desired: bool | None = None) -> str:
        # router_firewall_rule is validated by SAFE_RULE_RE during initialization.
        lines = [
            'set -e',
            f'RULE={shlex.quote(self.router_firewall_rule)}',
            'SECTION="$RULE"',
            'if ! uci -q get "firewall.$SECTION" >/dev/null 2>&1; then',
            r'''  SECTION="$(uci -q show firewall | sed -n "s/^firewall\.\([^=]*\)\.name='$RULE'$/\1/p" | head -n 1)"''',
            'fi',
            '[ -n "$SECTION" ] || { echo "rule-not-found"; exit 4; }',
        ]
        if desired is not None:
            value = '1' if desired else '0'
            lines.extend([
                f'uci set "firewall.$SECTION.enabled={value}"',
                'uci commit firewall',
                'RELOAD_LOG=/tmp/xray-proxy-manager-firewall-reload.log',
                'if ! /etc/init.d/firewall reload >"$RELOAD_LOG" 2>&1; then',
                '  cat "$RELOAD_LOG" >&2',
                '  exit 5',
                'fi',
            ])
        lines.extend([
            'VALUE="$(uci -q get "firewall.$SECTION.enabled" || true)"',
            'if [ "$VALUE" = "0" ]; then',
            '  printf "disabled:%s\n" "$SECTION"',
            'else',
            '  printf "enabled:%s\n" "$SECTION"',
            'fi',
        ])
        return f'sh -c {shlex.quote(chr(10).join(lines))}'

    def refresh_router_status(self) -> None:
        if not self.router_control_enabled:
            with self.lock:
                self.router_state.update({
                    'configured': False,
                    'available': False,
                    'rule_enabled': None,
                    'rule_name': self.router_firewall_rule,
                    'error': 'Управление правилом отключено',
                    'last_checked_at': xpm_common.now_ts(),
                })
            return
        try:
            output = self.run_router_command(self.router_rule_remote_script(), timeout=12)
            match = re.search(r'^(enabled|disabled):(.+)$', output.strip(), re.MULTILINE)
            if not match:
                raise RuntimeError(output or 'OpenWrt вернул неизвестный ответ')
            enabled = match.group(1) == 'enabled'
            section = match.group(2).strip()
            restore_to: bool | None = None
            with self.lock:
                desired = self.router_state.get('desired_rule_enabled')
                if not isinstance(desired, bool):
                    desired = enabled
                    self.router_state['desired_rule_enabled'] = desired
                    self.state['router_rule_desired_enabled'] = desired
                    self.save_state()
                elif desired != enabled and not self.router_state.get('busy'):
                    restore_to = desired
                self.router_state.update({
                    'configured': True,
                    'available': True,
                    'rule_enabled': enabled,
                    'rule_name': self.router_firewall_rule,
                    'rule_section': section,
                    'error': '',
                    'last_checked_at': xpm_common.now_ts(),
                })
            if restore_to is not None:
                xpm_common.log(
                    f'OpenWrt rule {self.router_firewall_rule} changed outside the manager; '
                    f'restoring {"enabled" if restore_to else "disabled"} state'
                )
                self.set_router_rule(restore_to, automatic=True)
        except Exception as exc:
            with self.lock:
                self.router_state.update({
                    'configured': True,
                    'available': False,
                    'rule_enabled': None,
                    'rule_name': self.router_firewall_rule,
                    'error': str(exc),
                    'last_checked_at': xpm_common.now_ts(),
                })

    def set_router_rule(self, enabled: bool, *, automatic: bool = False) -> None:
        if not self.router_lock.acquire(blocking=False):
            raise RuntimeError('Изменение правила уже выполняется')
        try:
            with self.lock:
                self.router_state['busy'] = True
                self.router_state['desired_rule_enabled'] = enabled
                self.state['router_rule_desired_enabled'] = enabled
                self.save_state()
            output = self.run_router_command(self.router_rule_remote_script(enabled), timeout=25)
            match = re.search(r'^(enabled|disabled):(.+)$', output.strip(), re.MULTILINE)
            if not match:
                raise RuntimeError(output or 'OpenWrt вернул неизвестный ответ')
            actual_enabled = match.group(1) == 'enabled'
            if actual_enabled != enabled:
                raise RuntimeError('Правило не перешло в требуемое состояние')
            with self.lock:
                self.router_state.update({
                    'available': True,
                    'rule_enabled': actual_enabled,
                    'rule_name': self.router_firewall_rule,
                    'rule_section': match.group(2).strip(),
                    'desired_rule_enabled': enabled,
                    'error': '',
                    'last_checked_at': xpm_common.now_ts(),
                })
            if automatic:
                xpm_common.log(
                    f'OpenWrt rule {self.router_firewall_rule} automatically restored to '
                    f'{"enabled" if enabled else "disabled"}'
                )
        except Exception as exc:
            with self.lock:
                self.router_state.update({
                    'available': False,
                    'rule_enabled': None,
                    'rule_name': self.router_firewall_rule,
                    'error': str(exc),
                    'last_checked_at': xpm_common.now_ts(),
                })
            raise
        finally:
            with self.lock:
                self.router_state['busy'] = False
            self.router_lock.release()

    def router_status_loop(self) -> None:
        while not self.stop_event.is_set():
            self.refresh_router_status()
            if self.stop_event.wait(self.router_status_interval_seconds):
                break
