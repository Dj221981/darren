"""Tests for cybersec_toolkit.main CLI helpers and hardening paths."""

from types import SimpleNamespace
from unittest.mock import Mock

import pytest

import cybersec_toolkit.main as main


class DummyConsole:
    def __init__(self):
        self.print = Mock()


class DummyProgress:
    def __init__(self, *args, **kwargs):
        pass

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False


class DummyPrompt:
    responses = []

    @classmethod
    def ask(cls, *args, **kwargs):
        if not cls.responses:
            raise AssertionError("No prompt response queued")
        return cls.responses.pop(0)


class DummyConfirm:
    responses = []

    @classmethod
    def ask(cls, *args, **kwargs):
        if not cls.responses:
            raise AssertionError("No confirm response queued")
        return cls.responses.pop(0)


class DummyIntPrompt:
    responses = []

    @classmethod
    def ask(cls, *args, **kwargs):
        if not cls.responses:
            raise AssertionError("No int prompt response queued")
        return cls.responses.pop(0)


class FakeTable:
    def __init__(self, *args, **kwargs):
        self.columns = []
        self.rows = []

    def add_column(self, *args, **kwargs):
        self.columns.append((args, kwargs))

    def add_row(self, *args, **kwargs):
        self.rows.append((args, kwargs))


class FakeRule:
    def __init__(self, text):
        self.text = text


class FakePanel:
    def __init__(self, *args, **kwargs):
        self.args = args
        self.kwargs = kwargs


class FakeText:
    def __init__(self, *args, **kwargs):
        self.parts = []

    def append(self, text, style=None):
        self.parts.append((text, style))


@pytest.fixture(autouse=True)
def patch_cli(monkeypatch):
    monkeypatch.setattr(main, "console", DummyConsole())
    monkeypatch.setattr(main, "Prompt", DummyPrompt)
    monkeypatch.setattr(main, "Confirm", DummyConfirm)
    monkeypatch.setattr(main, "IntPrompt", DummyIntPrompt)
    monkeypatch.setattr(main, "Progress", DummyProgress)
    monkeypatch.setattr(main, "Table", FakeTable)
    monkeypatch.setattr(main, "Rule", FakeRule)
    monkeypatch.setattr(main, "Panel", FakePanel)
    monkeypatch.setattr(main, "Text", FakeText)
    monkeypatch.setattr(main, "__version__", "1.0.0")

    DummyPrompt.responses = []
    DummyConfirm.responses = []
    DummyIntPrompt.responses = []


class TestCliHelpers:
    def test_show_main_menu_uses_menu_items(self):
        main.show_main_menu()
        assert main.console.print.call_count >= 1

    def test_print_hash_result_with_file_info(self):
        main._print_hash_result(
            {
                "algorithm": "SHA-256",
                "digest": "abcd",
                "file_size_bytes": 4,
                "file": "sample.txt",
                "security_status": "Recommended",
                "security_note": "ok",
            }
        )
        output = " ".join(str(call.args[0]) for call in main.console.print.call_args_list)
        assert "SHA-256" in output
        assert "sample.txt" in output

    def test_main_exits_cleanly_on_zero_choice(self, monkeypatch):
        DummyPrompt.responses = ["0"]
        monkeypatch.setattr(main, "show_banner", Mock())
        monkeypatch.setattr(main, "show_main_menu", Mock())
        main.main()
        assert main.show_banner.called
        assert main.show_main_menu.called

    def test_main_handles_keyboard_interrupt_in_handler(self, monkeypatch):
        DummyPrompt.responses = ["1", "0"]
        monkeypatch.setattr(main, "show_banner", Mock())
        monkeypatch.setattr(main, "show_main_menu", Mock())
        monkeypatch.setattr(main, "menu_password_analyzer", Mock(side_effect=KeyboardInterrupt))
        main.main()
        assert main.menu_password_analyzer.called

    def test_menu_password_analyzer_shows_strength_output(self, monkeypatch):
        DummyPrompt.responses = ["hunter2"]
        monkeypatch.setattr(main.password_analyzer, "analyze_password", lambda password: SimpleNamespace(
            strength="Strong",
            percentage=88,
            entropy_bits=75.2,
            criteria={
                "length": {"value": 7, "score": 20, "max": 20},
                "variety": {"lowercase": True, "uppercase": False, "digits": True, "special": False, "score": 20, "max": 20},
                "entropy": {"bits": 75.2, "score": 15, "max": 15},
                "patterns": {"score": 10, "max": 10},
                "common": {"is_common": False, "score": 10, "max": 10},
            },
            issues=[],
            suggestions=[]
        ))
        main.menu_password_analyzer()
        output = " ".join(str(call.args[0]) for call in main.console.print.call_args_list)
        assert "Strength:" in output
        assert "Entropy:" in output

    def test_menu_password_generator_random_path(self, monkeypatch):
        DummyPrompt.responses = ["1"]
        DummyIntPrompt.responses = [20]
        DummyConfirm.responses = [True, True, True, True, False]
        monkeypatch.setattr(main.password_generator, "GeneratorConfig", lambda **kwargs: SimpleNamespace(**kwargs))
        monkeypatch.setattr(main.password_generator, "generate_password", lambda cfg: "Abc123!@#Abc123!@#Abc")
        monkeypatch.setattr(main.password_analyzer, "analyze_password", lambda pwd: SimpleNamespace(strength="Strong", percentage=90))

        main.menu_password_generator()
        output = " ".join(str(call.args[0]) for call in main.console.print.call_args_list)
        assert "Generated password" in output

    def test_menu_password_generator_invalid_config_is_reported(self, monkeypatch):
        DummyPrompt.responses = ["1"]
        DummyIntPrompt.responses = [12]
        DummyConfirm.responses = [True, True, True, True, False]
        monkeypatch.setattr(main.password_generator, "GeneratorConfig", lambda **kwargs: SimpleNamespace(**kwargs))
        monkeypatch.setattr(main.password_generator, "generate_password", lambda cfg: (_ for _ in ()).throw(ValueError("bad config")))

        main.menu_password_generator()
        output = " ".join(str(call.args[0]) for call in main.console.print.call_args_list)
        assert "Error: bad config" in output

    def test_menu_hash_tools_verify_branch(self, monkeypatch):
        DummyPrompt.responses = ["3", "hello", "deadbeef", "sha256"]
        monkeypatch.setattr(main.hash_tools, "verify_hash", lambda text, expected, algo: True)
        main.menu_hash_tools()
        output = " ".join(str(call.args[0]) for call in main.console.print.call_args_list)
        assert "Hash matches" in output

    def test_menu_hash_tools_file_error_is_reported(self, monkeypatch):
        DummyPrompt.responses = ["4", "/missing.txt", "sha256"]
        monkeypatch.setattr(main.hash_tools, "hash_file", lambda path, algo: (_ for _ in ()).throw(FileNotFoundError("missing")))
        main.menu_hash_tools()
        output = " ".join(str(call.args[0]) for call in main.console.print.call_args_list)
        assert "Error: missing" in output

    def test_menu_file_integrity_verify_missing_file_is_reported(self, monkeypatch):
        DummyPrompt.responses = ["2", "manifest.json"]
        monkeypatch.setattr(main.file_integrity, "verify_manifest", lambda manifest: (_ for _ in ()).throw(FileNotFoundError("manifest missing")))
        main.menu_file_integrity()
        output = " ".join(str(call.args[0]) for call in main.console.print.call_args_list)
        assert "Error: manifest missing" in output

    def test_menu_port_scanner_handles_error(self, monkeypatch):
        DummyPrompt.responses = ["example.com", "common", "1.0"]
        DummyConfirm.responses = [False]
        monkeypatch.setattr(main.port_scanner, "scan", lambda **kwargs: SimpleNamespace(error="boom"))
        main.menu_port_scanner()
        output = " ".join(str(call.args[0]) for call in main.console.print.call_args_list)
        assert "Error: boom" in output

    def test_menu_port_scanner_custom_ports_filters_non_digits(self, monkeypatch):
        DummyPrompt.responses = ["example.com", "custom", "22,80,abc,443", "1.0"]
        DummyConfirm.responses = [False]
        captured = {}

        def fake_scan(**kwargs):
            captured.update(kwargs)
            return SimpleNamespace(error=None, target="example.com", target_ip="1.2.3.4", ports_scanned=3, open_ports=[], duration_seconds=0.2)

        monkeypatch.setattr(main.port_scanner, "scan", fake_scan)
        main.menu_port_scanner()
        assert captured["ports"] == [22, 80, 443]

    def test_menu_cipher_tools_hex_encode_path(self, monkeypatch):
        DummyPrompt.responses = ["7", "encode", "hello"]
        monkeypatch.setattr(main.cipher_tools, "to_hex", lambda text: "68656c6c6f")
        main.menu_cipher_tools()
        output = " ".join(str(call.args[0]) for call in main.console.print.call_args_list)
        assert "68656c6c6f" in output

    def test_menu_network_tools_dns_error_is_reported(self, monkeypatch):
        DummyPrompt.responses = ["1", "example.com"]
        monkeypatch.setattr(main.network_tools, "dns_lookup", lambda host: {"error": "dns failed", "forward_records": [], "reverse_records": []})
        main.menu_network_tools()
        output = " ".join(str(call.args[0]) for call in main.console.print.call_args_list)
        assert "Error: dns failed" in output

    def test_show_main_menu_rejects_non_numeric_keys_is_currently_unsafe(self):
        main.MENU_ITEMS.append(("x", "Bad", "bad"))
        with pytest.raises(ValueError):
            main.show_main_menu()
        main.MENU_ITEMS.pop()
