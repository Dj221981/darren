"""Tests for cybersec_toolkit.main CLI helpers."""

from types import SimpleNamespace
from unittest.mock import Mock

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


class TestCliHelpers:
    def setup_method(self):
        self._orig_console = main.console
        self._orig_prompt = main.Prompt
        self._orig_confirm = main.Confirm
        self._orig_intprompt = main.IntPrompt
        self._orig_progress = main.Progress
        self._orig_table = main.Table
        self._orig_rule = main.Rule
        self._orig_panel = main.Panel
        self._orig_text = main.Text
        self._orig_version = main.__version__

        main.console = DummyConsole()
        main.Prompt = DummyPrompt
        main.Confirm = DummyConfirm
        main.IntPrompt = DummyIntPrompt
        main.Progress = DummyProgress
        main.Table = FakeTable
        main.Rule = FakeRule
        main.Panel = FakePanel
        main.Text = FakeText
        main.__version__ = "1.0.0"

    def teardown_method(self):
        main.console = self._orig_console
        main.Prompt = self._orig_prompt
        main.Confirm = self._orig_confirm
        main.IntPrompt = self._orig_intprompt
        main.Progress = self._orig_progress
        main.Table = self._orig_table
        main.Rule = self._orig_rule
        main.Panel = self._orig_panel
        main.Text = self._orig_text
        main.__version__ = self._orig_version

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

    def test_menu_hash_tools_verify_branch(self, monkeypatch):
        DummyPrompt.responses = ["3", "hello", "deadbeef", "sha256"]
        monkeypatch.setattr(main.hash_tools, "verify_hash", lambda text, expected, algo: True)
        main.menu_hash_tools()
        output = " ".join(str(call.args[0]) for call in main.console.print.call_args_list)
        assert "Hash matches" in output

    def test_menu_port_scanner_handles_error(self, monkeypatch):
        DummyPrompt.responses = ["example.com", "common", "1.0"]
        DummyConfirm.responses = [False]
        monkeypatch.setattr(main.port_scanner, "scan", lambda **kwargs: SimpleNamespace(error="boom"))
        main.menu_port_scanner()
        output = " ".join(str(call.args[0]) for call in main.console.print.call_args_list)
        assert "Error: boom" in output

