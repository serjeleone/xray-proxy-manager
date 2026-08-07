from __future__ import annotations

import json
from pathlib import Path

import pytest


def test_resolve_test_urls_and_legacy_migration(m):
    options = {"latency_test_url": "https://one/", "health_check_url": "https://one/"}
    assert m.resolve_test_urls(options) == ("https://one/", m.DEFAULT_SECONDARY_TEST_URL)
    assert m.migrate_test_url_options(options)
    assert options == {
        "primary_test_url": "https://one/",
        "secondary_test_url": "https://one/",
    }
    assert not m.migrate_test_url_options(options)
    assert not m.migrate_secondary_test_url_option(options)


def test_migrate_excluded_option(m):
    options = {m.LEGACY_AUTO_SWITCH_EXCLUDED_KEY: "ru, nl"}
    assert m.migrate_auto_switch_excluded_option(options)
    assert options == {"auto_switch_excluded": "ru, nl"}
    assert not m.migrate_auto_switch_excluded_option(options)


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("ru; NL\nserver fragment, RU", "RU, NL, server fragment"),
        (None, ""),
        ("  Germany node  ", "Germany node"),
    ],
)
def test_normalize_auto_switch_exclusions(m, raw, expected):
    assert m.normalize_auto_switch_exclusions(raw) == expected
    assert m.normalize_country_codes(raw) == expected


@pytest.mark.parametrize("raw", ["ZZ", "x", "ab"])
def test_normalize_auto_switch_exclusions_rejects_invalid_values(m, raw):
    with pytest.raises(ValueError):
        m.normalize_auto_switch_exclusions(raw)


def test_preference_normalizers_and_parser(m):
    assert m.normalize_preferred_country(" nl ") == "NL"
    assert m.normalize_preferred_country("") == ""
    with pytest.raises(ValueError):
        m.normalize_preferred_country("XX")
    assert m.normalize_preferred_protocol(" vless ") == "VLESS"
    assert m.normalize_preferred_protocol("") == ""
    with pytest.raises(ValueError):
        m.normalize_preferred_protocol("bad protocol!")
    assert m.parse_auto_switch_exclusions("RU, node text, NL") == (
        {"RU", "NL"},
        ["node text"],
    )


@pytest.mark.parametrize(
    ("values", "expected"),
    [
        (("🇫🇮 Helsinki",), "FI"),
        (("NL Amsterdam",), "NL"),
        (("server-germany-01",), "DE"),
        (("edge-us-west",), "US"),
        (("unknown",), ""),
    ],
)
def test_infer_country_code(m, values, expected):
    assert m.infer_country_code(*values) == expected


def test_log_normalization_buffer_and_release_notes(m, isolated_paths):
    line = "[Info] infra/conf/serial: Reading config: &{Name:/config/config.json Format:json}"
    assert m.normalize_xray_log_line(line) == "[Info] Reading config: /config/config.json"
    m.append_ui_log("\x1b[31mfirst\x1b[0m\n")
    m.append_ui_log("")
    m.append_ui_log("second")
    assert m.ui_log_snapshot(1) == (["second"], 2)
    payload = m.release_notes_payload()
    assert payload == {"version": "v0.9.0", "items": ["Change one", "Change two"]}
    payload["items"].append("mutated")
    assert m.release_notes_payload()["items"] == ["Change one", "Change two"]


def test_json_helpers_are_atomic_and_safe(m, tmp_path):
    target = tmp_path / "nested" / "state.json"
    m.atomic_write_json(target, {"ключ": 1})
    assert json.loads(target.read_text(encoding="utf-8")) == {"ключ": 1}
    assert not target.with_name(".state.json.tmp").exists()
    assert m.load_json(target, {}) == {"ключ": 1}
    target.write_text("broken", encoding="utf-8")
    default = {"items": []}
    loaded = m.load_json(target, default)
    loaded["items"].append(1)
    assert default == {"items": []}


def test_scalar_helpers(m):
    assert m.first_text(None, " ", " value ", "later") == "value"
    assert m.first_text(None, 3) == ""
    assert m.to_bool(True)
    assert m.to_bool("YES")
    assert not m.to_bool("off")
    assert m.to_bool(1)
    assert m.bounded_int("5", 1, 10, "field") == 5
    with pytest.raises(ValueError, match="целое"):
        m.bounded_int("x", 1, 10, "field")
    with pytest.raises(ValueError, match="диапазон"):
        m.bounded_int(11, 1, 10, "field")


@pytest.mark.parametrize(
    ("outbound", "expected"),
    [
        ({"settings": {"vnext": [{"address": "a", "port": 443}]}}, ("a", 443)),
        ({"settings": {"servers": [{"server": "b", "port": "1080"}]}}, ("b", 1080)),
        ({"settings": {"address": "c", "port": "bad"}}, ("c", None)),
    ],
)
def test_extract_endpoint(m, outbound, expected):
    assert m.extract_endpoint(outbound) == expected


def test_config_names_tags_and_recursive_walk(m):
    assert m.config_display_name({"metadata": {"title": "Meta"}}, 2) == "Meta"
    assert m.config_display_name({}, 2) == "Профиль 3"
    config = {
        "outbounds": [
            {"tag": "same", "protocol": "vless"},
            {"tag": "same", "protocol": "trojan"},
            {"protocol": "shadowsocks"},
            "ignored",
        ]
    }
    tagged = m.ensure_outbound_tags(config)
    assert [item.get("tag") for item in tagged["outbounds"] if isinstance(item, dict)] == [
        "same", "ui-outbound-2", "ui-outbound-3"
    ]
    assert config["outbounds"][1]["tag"] == "same"
    objects = list(m.walk_objects({"a": [{"b": 1}]}))
    assert {"b": 1} in objects


def test_routing_tag_fix_addition_and_validation(m):
    config = {
        "outbounds": [{"tag": "proxy", "protocol": "vless"}],
        "routing": {
            "balancers": [{"tag": "balance"}],
            "rules": [
                {"outboundTag": "balance"},
                {"outboundTag": "proxy-direct"},
            ],
        },
    }
    fixed = m.fix_routing_tags(config, True)
    assert fixed["routing"]["rules"][0] == {"balancerTag": "balance"}
    with_direct = m.add_proxy_direct(fixed, True)
    assert {item["tag"] for item in with_direct["outbounds"]} == {"proxy", "proxy-direct"}
    m.validate_routing_tags(with_direct, True)
    with pytest.raises(ValueError, match="missing outboundTag"):
        m.validate_routing_tags({"outbounds": [], "routing": {"rules": [{"outboundTag": "missing"}]}}, True)
    same = {"value": 1}
    assert m.fix_routing_tags(same, False) is same
    assert m.add_proxy_direct(same, False) is same
    m.validate_routing_tags(same, False)


def test_candidate_public_and_slot_running(m, candidate_factory, tmp_path):
    candidate = candidate_factory("id", country="FI")
    public = candidate.public({"status": "ok", "latency_ms": 42}, True)
    assert public["id"] == "id"
    assert public["country_code"] == "FI"
    assert public["active"] is True
    slot = m.XraySlot("xray-a", 10808, True, tmp_path / "a.json")
    assert not slot.running()
    class Process:
        def poll(self): return None
    slot.process = Process()
    assert slot.running()


def test_migrate_legacy_workdir(m, isolated_paths):
    isolated_paths.LEGACY_WORKDIR.mkdir()
    (isolated_paths.LEGACY_WORKDIR / "subscription.json").write_text("[]", encoding="utf-8")
    (isolated_paths.LEGACY_WORKDIR / "state.json").write_text("{}", encoding="utf-8")
    m.migrate_legacy_workdir()
    assert isolated_paths.SUBSCRIPTION_PATH.exists()
    assert isolated_paths.STATE_PATH.exists()
    assert not isolated_paths.LEGACY_WORKDIR.exists()
