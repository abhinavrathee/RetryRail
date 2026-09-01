"""Fail-closed protected-push behavior."""

from pathlib import Path

import pytest

from retryrail.security import pre_push


def test_pre_push_runs_offline_scan_then_ggshield(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    (tmp_path / ".gitguardian.yaml").write_text("version: 2\n", encoding="utf-8")
    (tmp_path / "safe.txt").write_text("synthetic content\n", encoding="utf-8")
    captured: list[dict[str, object]] = []

    monkeypatch.setenv("GITGUARDIAN_API_KEY", "not-a-secret")
    monkeypatch.setenv("GITGUARDIAN_API_URL", "https://example.invalid")
    monkeypatch.setenv("GITGUARDIAN_EXIT_ZERO", "true")
    monkeypatch.setenv("GITGUARDIAN_MAX_COMMITS_FOR_HOOK", "1")
    monkeypatch.setenv("SKIP", "ggshield")

    def fake_run(
        command: tuple[str, ...],
        *,
        refs: bytes,
        root: Path,
        environment: dict[str, str],
    ) -> int:
        captured.append(
            {
                "command": command,
                "refs": refs,
                "root": root,
                "environment": environment,
            }
        )
        return 0

    monkeypatch.setattr(pre_push, "_run_ggshield", fake_run)

    result = pre_push.execute_pre_push(
        tmp_path,
        ("origin", "https://example.invalid/retryrail.git"),
        b"local-ref local-sha remote-ref remote-sha\n",
        ggshield_path="ggshield-test",
    )

    assert result == 0
    assert [call["command"] for call in captured] == [
        (
            "ggshield-test",
            "--config-path",
            str(tmp_path / ".gitguardian.yaml"),
            "secret",
            "scan",
            "repo",
            str(tmp_path),
        ),
        (
            "ggshield-test",
            "--config-path",
            str(tmp_path / ".gitguardian.yaml"),
            "secret",
            "scan",
            "pre-push",
            "origin",
            "https://example.invalid/retryrail.git",
        ),
    ]
    assert captured[0]["refs"] == b""
    assert captured[1]["refs"] == b"local-ref local-sha remote-ref remote-sha\n"
    assert all(call["root"] == tmp_path for call in captured)
    environment = captured[0]["environment"]
    assert isinstance(environment, dict)
    assert environment["GITGUARDIAN_DONT_LOAD_ENV"] == "1"
    assert environment["GITGUARDIAN_FAIL_ON_SERVER_ERROR"] == "true"
    assert environment["GITGUARDIAN_INSTANCE"] == "https://dashboard.gitguardian.com"
    for key in (
        "GITGUARDIAN_API_KEY",
        "GITGUARDIAN_API_URL",
        "GITGUARDIAN_EXIT_ZERO",
        "GITGUARDIAN_MAX_COMMITS_FOR_HOOK",
        "SKIP",
    ):
        assert key not in environment


def test_pre_push_stops_when_full_repository_scan_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    (tmp_path / ".gitguardian.yaml").write_text("version: 2\n", encoding="utf-8")
    commands: list[tuple[str, ...]] = []

    def fake_run(
        command: tuple[str, ...],
        *,
        refs: bytes,
        root: Path,
        environment: dict[str, str],
    ) -> int:
        del refs, root, environment
        commands.append(command)
        return 7

    monkeypatch.setattr(pre_push, "_run_ggshield", fake_run)

    result = pre_push.execute_pre_push(
        tmp_path,
        ("origin", "https://example.invalid/retryrail.git"),
        b"local-ref local-sha remote-ref remote-sha\n",
        ggshield_path="ggshield-test",
    )

    assert result == 7
    assert commands == [
        (
            "ggshield-test",
            "--config-path",
            str(tmp_path / ".gitguardian.yaml"),
            "secret",
            "scan",
            "repo",
            str(tmp_path),
        )
    ]


def test_pre_push_propagates_outgoing_scan_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    (tmp_path / ".gitguardian.yaml").write_text("version: 2\n", encoding="utf-8")
    results = iter((0, 9))

    def fake_run(
        command: tuple[str, ...],
        *,
        refs: bytes,
        root: Path,
        environment: dict[str, str],
    ) -> int:
        del command, refs, root, environment
        return next(results)

    monkeypatch.setattr(pre_push, "_run_ggshield", fake_run)

    assert (
        pre_push.execute_pre_push(
            tmp_path,
            (),
            b"",
            ggshield_path="ggshield-test",
        )
        == 9
    )


def test_pre_push_fails_closed_without_ggshield(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    (tmp_path / ".gitguardian.yaml").write_text("version: 2\n", encoding="utf-8")
    monkeypatch.setattr(
        "retryrail.security.pre_push.shutil.which",
        lambda _name: None,
    )

    assert pre_push.execute_pre_push(tmp_path, (), b"") == 1


def test_pre_push_blocks_before_cloud_scan_on_local_finding(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    (tmp_path / ".gitguardian.yaml").write_text("version: 2\n", encoding="utf-8")
    (tmp_path / "unsafe.json").write_text(
        '{"authorization_id":"truth_access_' + "a1b2c3d4e5f60718293a" + '"}\n',
        encoding="utf-8",
    )

    def unexpected_run(*_args: object, **_kwargs: object) -> int:
        pytest.fail("ggshield must not run after an offline finding")

    monkeypatch.setattr(pre_push, "_run_ggshield", unexpected_run)

    result = pre_push.execute_pre_push(
        tmp_path,
        (),
        b"",
        ggshield_path="ggshield-test",
    )

    assert result == 1


def test_pre_push_fails_closed_without_config(tmp_path: Path) -> None:
    assert (
        pre_push.execute_pre_push(
            tmp_path,
            (),
            b"",
            ggshield_path="ggshield-test",
        )
        == 1
    )
