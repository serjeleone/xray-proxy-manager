"""Publication stays opt-in for an existing tag, including test branch pushes."""
from __future__ import annotations

import os
from pathlib import Path
import subprocess

import pytest
import yaml

WORKFLOW = yaml.safe_load((Path(__file__).parents[1] / '.github/workflows/build.yml').read_text())


@pytest.mark.parametrize('event, ref, existing, trailer, manual, expected', [
    ('push', 'main', True, '', '', False),
    ('push', 'main', True, 'v0.9.5', '', True),
    ('push', 'main', True, 'v0.9.6', '', False),
    ('push', 'release/v0.9.5', True, 'v0.9.5', '', False),
    ('pull_request', 'main', True, 'v0.9.5', '', False),
    ('push', 'main', False, '', '', True),
    ('workflow_dispatch', 'main', True, '', 'true', True),
])
def test_existing_tag_requires_explicit_rebuild(tmp_path, event, ref, existing, trailer, manual, expected):
    (tmp_path / 'scripts').mkdir()
    (tmp_path / 'scripts/check_version.py').write_text("print('0.9.5')\n")
    def git(*args):
        subprocess.run(['git', *args], cwd=tmp_path, check=True, capture_output=True)
    git('init', '-q')
    message = 'Test fixes' + (f'\n\nRebuild-Release: {trailer}' if trailer else '')
    git('-c', 'user.name=Test', '-c', 'user.email=test@example.test', 'commit', '--allow-empty', '-m', message)
    if existing:
        git('tag', 'v0.9.5')
    output = tmp_path / 'output'
    env = {**os.environ, 'GITHUB_EVENT_NAME': event, 'GITHUB_REF': f'refs/heads/{ref}',
           'GITHUB_REF_TYPE': 'branch', 'GITHUB_REF_NAME': ref, 'GITHUB_OUTPUT': str(output),
           'MANUAL_PUBLISH': manual, 'PUBLISHED_TAG': ''}
    script = next(step['run'] for step in WORKFLOW['jobs']['prepare']['steps'] if step.get('id') == 'version')
    subprocess.run(['bash', '-e', '-c', script], env=env, cwd=tmp_path, check=True, capture_output=True)
    assert f'publish={str(expected).lower()}' in output.read_text().splitlines()


@pytest.mark.parametrize('branch_sha, deleted', [('commit-under-test', True), ('newer-work', False)])
def test_republish_updates_tag_and_only_deletes_a_fully_released_branch(tmp_path, branch_sha, deleted):
    # No network calls: record the gh commands and return the remote branch SHA.
    cli = tmp_path / 'gh'
    cli.write_text('#!/usr/bin/env python3\n'
                   'import json, os, sys\n'
                   "with open(os.environ['GH_TEST_LOG'], 'a') as f: f.write(json.dumps(sys.argv[1:]) + '\\n')\n"
                   "if 'api' in sys.argv and '--jq' in sys.argv: print(os.environ['GH_TEST_BRANCH_SHA'])\n")
    cli.chmod(0o755)
    log = tmp_path / 'gh.log'
    env = {**os.environ, 'PATH': f'{tmp_path}:{os.environ["PATH"]}', 'GH_TEST_LOG': str(log),
           'GH_TEST_BRANCH_SHA': branch_sha, 'GH_REPO': 'example/project', 'GITHUB_SHA': 'commit-under-test',
           'GITHUB_REF': 'refs/heads/main', 'RELEASE_TAG': 'v0.9.5'}
    script = WORKFLOW['jobs']['release']['steps'][-1]['run']
    subprocess.run(['bash', '-e', '-c', script], env=env, cwd=tmp_path, check=True, capture_output=True)
    commands = log.read_text()
    assert 'PATCH' in commands and 'refs/tags/v0.9.5' in commands
    assert '"release", "edit"' in commands
    assert ('DELETE' in commands) is deleted
