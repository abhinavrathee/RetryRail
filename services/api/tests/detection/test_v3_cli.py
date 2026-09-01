"""Command-line state reporting for detector-v3 evaluation artifacts."""

from types import ModuleType

import pytest

from retryrail.detection import (
    v3_adversarial,
    v3_evaluation,
    v3_freeze,
    v3_protocol,
)

_MODULE_CASES = (
    (
        v3_protocol,
        "write_v3_protocol",
        "check_v3_protocol",
        "render_v3_protocol",
        "wrote detector-v3 pre-candidate protocol\n",
        "detector-v3 protocol is current; candidate and blind nonce remain unfrozen\n",
    ),
    (
        v3_evaluation,
        "write_development_artifacts",
        "check_development_artifacts",
        "render_development_artifacts",
        "wrote passing detector-v3 development artifacts\n",
        "detector-v3 passes both development partitions; release remains blocked\n",
    ),
    (
        v3_adversarial,
        "write_adversarial_report",
        "check_adversarial_report",
        "render_adversarial_report",
        "wrote passing detector-v3 adversarial report\n",
        "detector-v3 adversarial suite passed; release remains blocked\n",
    ),
    (
        v3_freeze,
        "write_candidate_freeze",
        "check_candidate_freeze",
        "render_candidate_freeze_bytes",
        "wrote detector-v3 candidate freeze; blind runner not frozen\n",
        "detector-v3 candidate freeze is current and nonce-free\n",
    ),
)


def _main(module: ModuleType) -> None:
    entrypoint = module.__dict__["main"]
    entrypoint()


@pytest.mark.parametrize("case", _MODULE_CASES)
def test_v3_cli_write_paths_are_explicit(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    case: tuple[ModuleType, str, str, str, str, str],
) -> None:
    module, write_name, _check_name, _render_name, expected, _checked = case
    called: list[bool] = []
    monkeypatch.setattr(module, write_name, lambda: called.append(True))
    monkeypatch.setattr("sys.argv", ["retryrail-v3", "--write"])

    _main(module)

    assert called == [True]
    assert capsys.readouterr().out == expected


@pytest.mark.parametrize("case", _MODULE_CASES)
def test_v3_cli_check_paths_report_success(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    case: tuple[ModuleType, str, str, str, str, str],
) -> None:
    module, _write_name, check_name, _render_name, _written, expected = case
    monkeypatch.setattr(module, check_name, list)
    monkeypatch.setattr("sys.argv", ["retryrail-v3", "--check"])

    _main(module)

    assert capsys.readouterr().out == expected


@pytest.mark.parametrize("case", _MODULE_CASES)
def test_v3_cli_check_paths_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    case: tuple[ModuleType, str, str, str, str, str],
) -> None:
    module, _write_name, check_name, _render_name, _written, _checked = case
    monkeypatch.setattr(module, check_name, lambda: ["safe artifact drift"])
    monkeypatch.setattr("sys.argv", ["retryrail-v3", "--check"])

    with pytest.raises(SystemExit) as raised:
        _main(module)

    assert raised.value.code == 1
    assert capsys.readouterr().err == "safe artifact drift\n"


@pytest.mark.parametrize("case", _MODULE_CASES)
def test_v3_cli_print_paths_are_byte_exact(
    monkeypatch: pytest.MonkeyPatch,
    capsysbinary: pytest.CaptureFixture[bytes],
    case: tuple[ModuleType, str, str, str, str, str],
) -> None:
    module, _write_name, _check_name, render_name, _written, _checked = case
    expected = b'{"synthetic":true}\n'
    if module is v3_evaluation:
        monkeypatch.setattr(
            module,
            render_name,
            lambda: {module._SUITE_REPORT_PATH: expected},  # noqa: SLF001
        )
        argument = "--print-suite"
    else:
        monkeypatch.setattr(module, render_name, lambda: expected)
        argument = "--print"
    monkeypatch.setattr("sys.argv", ["retryrail-v3", argument])

    _main(module)

    assert capsysbinary.readouterr().out == expected
