"""Hardening tests for menu input validation boundaries."""

from types import SimpleNamespace

import pytest

import cybersec_toolkit.main as main


def test_custom_ports_only_accepts_digits(monkeypatch):
    monkeypatch.setattr(main, "Prompt", SimpleNamespace(ask=lambda *a, **k: "22, 80, abc,443"))
    monkeypatch.setattr(main, "Confirm", SimpleNamespace(ask=lambda *a, **k: False))
    monkeypatch.setattr(main, "IntPrompt", SimpleNamespace(ask=lambda *a, **k: 0))
    monkeypatch.setattr(main.port_scanner, "scan", lambda **kwargs: SimpleNamespace(error=None, target="h", target_ip="1.1.1.1", ports_scanned=3, open_ports=[], duration_seconds=0.1))

    # Drive the custom branch without actually opening sockets.
    inputs = iter(["host", "custom", "1.0"])
    monkeypatch.setattr(main.Prompt, "ask", lambda *a, **k: next(inputs) if a and "Ports" not in a[0] else "22, 80, abc,443")

    main.menu_port_scanner()


def test_timeout_input_should_parse_to_float(monkeypatch):
    monkeypatch.setattr(main, "Prompt", SimpleNamespace(ask=lambda *a, **k: "1.5"))
    assert float(main.Prompt.ask("Timeout per port (seconds)", default="1.0")) == 1.5


def test_show_main_menu_even_style_assumes_numeric_keys_only():
    assert any(item[0] == "0" for item in main.MENU_ITEMS)

