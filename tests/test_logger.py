"""Tests for sofapy.logger module."""

import logging
import sys
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

from sofapy.logger import SofaLog

if TYPE_CHECKING:
    from _pytest.capture import CaptureFixture
    from _pytest.logging import LogCaptureFixture


def test_sofa_log_default_init() -> None:
    """Test SofaLog initialization with default values."""
    sofa_log = SofaLog()

    assert sofa_log.logger_name == "sofapy"
    assert sofa_log.max_bytes == 1048576 * 100
    assert sofa_log.backup_count == 10
    assert sofa_log.logfile is None
    assert sofa_log._logger is None
    assert sofa_log._debug_mode is False


def test_sofa_log_custom_init() -> None:
    """Test SofaLog initialization with custom values."""
    sofa_log = SofaLog(
        logger_name="custom_logger",
        max_bytes=1024,
        backup_count=5,
    )

    assert sofa_log.logger_name == "custom_logger"
    assert sofa_log.max_bytes == 1024
    assert sofa_log.backup_count == 5


def test_sofa_log_with_logfile(tmp_path: Path) -> None:
    """Test SofaLog initialization with logfile path."""
    logfile = tmp_path / "test.log"
    sofa_log = SofaLog(logfile=logfile)

    assert sofa_log.logfile == logfile
    assert logfile.exists()


def test_sofa_log_creates_parent_directories(tmp_path: Path) -> None:
    """Test SofaLog creates parent directories for logfile."""
    logfile = tmp_path / "nested" / "dir" / "test.log"
    sofa_log = SofaLog(logfile=logfile)

    assert sofa_log.logfile == logfile
    assert logfile.exists()
    assert logfile.parent.exists()


def test_setup_logger_without_logfile() -> None:
    """Test setup_logger works without a logfile configured."""
    sofa_log = SofaLog()  # No logfile

    # Should not raise TypeError
    logger = sofa_log.setup_logger(debug=True)

    assert isinstance(logger, logging.Logger)
    assert sofa_log._logger is logger
    assert sofa_log._debug_mode is True


def test_setup_logger_returns_logger(tmp_path: Path) -> None:
    """Test setup_logger returns a logger instance."""
    logfile = tmp_path / "test.log"
    sofa_log = SofaLog(logfile=logfile)

    logger = sofa_log.setup_logger()

    assert isinstance(logger, logging.Logger)
    assert sofa_log._logger is logger


def test_setup_logger_custom_name(tmp_path: Path) -> None:
    """Test setup_logger with custom logger name."""
    logfile = tmp_path / "test.log"
    sofa_log = SofaLog(logfile=logfile)

    logger = sofa_log.setup_logger(name="custom_name")

    assert logger.name == "custom_name"


def test_setup_logger_debug_mode(tmp_path: Path) -> None:
    """Test setup_logger enables debug mode."""
    logfile = tmp_path / "test.log"
    sofa_log = SofaLog(logfile=logfile)

    sofa_log.setup_logger(debug=True)

    assert sofa_log._debug_mode is True


def test_setup_logger_no_duplicate_handlers(tmp_path: Path) -> None:
    """Test setup_logger doesn't add duplicate handlers."""
    logfile = tmp_path / "test.log"
    sofa_log = SofaLog(logfile=logfile)

    logger1 = sofa_log.setup_logger()
    initial_handler_count = len(logger1.handlers)

    # Call setup_logger again
    logger2 = sofa_log.setup_logger()

    assert len(logger2.handlers) == initial_handler_count


def test_setup_child_logger(tmp_path: Path) -> None:
    """Test setup_child_logger creates child logger."""
    logfile = tmp_path / "test.log"
    sofa_log = SofaLog(logfile=logfile)
    sofa_log.setup_logger()

    child_logger = sofa_log.setup_child_logger("child")

    assert child_logger.name == "sofapy.child"


def test_setup_child_logger_custom_parent(tmp_path: Path) -> None:
    """Test setup_child_logger with custom parent name."""
    logfile = tmp_path / "test.log"
    sofa_log = SofaLog(logfile=logfile)

    child_logger = sofa_log.setup_child_logger("child", loggerName="custom_parent")

    assert child_logger.name == "custom_parent.child"


def test_debug_logs_when_logger_set(tmp_path: Path, caplog: "LogCaptureFixture") -> None:
    """Test debug method logs message when logger is set."""
    logfile = tmp_path / "test.log"
    sofa_log = SofaLog(logfile=logfile)
    sofa_log.setup_logger(debug=True)

    with caplog.at_level(logging.DEBUG, logger="sofapy"):
        sofa_log.debug("Test debug message")

    assert "Test debug message" in caplog.text


def test_debug_echoes_in_debug_mode(tmp_path: Path, capsys: "CaptureFixture[str]") -> None:
    """Test debug method echoes to console in debug mode."""
    logfile = tmp_path / "test.log"
    sofa_log = SofaLog(logfile=logfile)
    sofa_log.setup_logger(debug=True)

    sofa_log.debug("Test debug message")

    captured = capsys.readouterr()
    assert "DEBUG: Test debug message" in captured.out


def test_debug_silent_without_debug_mode(tmp_path: Path, capsys: "CaptureFixture[str]") -> None:
    """Test debug method doesn't echo without debug mode."""
    logfile = tmp_path / "test.log"
    sofa_log = SofaLog(logfile=logfile)
    sofa_log.setup_logger(debug=False)

    sofa_log.debug("Test debug message")

    captured = capsys.readouterr()
    assert "DEBUG:" not in captured.out


def test_info_logs_message(tmp_path: Path, caplog: "LogCaptureFixture") -> None:
    """Test info method logs message."""
    logfile = tmp_path / "test.log"
    sofa_log = SofaLog(logfile=logfile)
    sofa_log.setup_logger(debug=True)

    with caplog.at_level(logging.INFO, logger="sofapy"):
        sofa_log.info("Test info message")

    assert "Test info message" in caplog.text


def test_info_echoes_in_debug_mode(tmp_path: Path, capsys: "CaptureFixture[str]") -> None:
    """Test info method echoes to console in debug mode."""
    logfile = tmp_path / "test.log"
    sofa_log = SofaLog(logfile=logfile)
    sofa_log.setup_logger(debug=True)

    sofa_log.info("Test info message")

    captured = capsys.readouterr()
    assert "INFO: Test info message" in captured.out


def test_warning_logs_message(tmp_path: Path, caplog: "LogCaptureFixture") -> None:
    """Test warning method logs message."""
    logfile = tmp_path / "test.log"
    sofa_log = SofaLog(logfile=logfile)
    sofa_log.setup_logger(debug=True)

    with caplog.at_level(logging.WARNING, logger="sofapy"):
        sofa_log.warning("Test warning message")

    assert "Test warning message" in caplog.text


def test_warning_echoes_in_debug_mode(tmp_path: Path, capsys: "CaptureFixture[str]") -> None:
    """Test warning method echoes to console in debug mode."""
    logfile = tmp_path / "test.log"
    sofa_log = SofaLog(logfile=logfile)
    sofa_log.setup_logger(debug=True)

    sofa_log.warning("Test warning message")

    captured = capsys.readouterr()
    assert "WARNING: Test warning message" in captured.out


def test_error_logs_message(tmp_path: Path, caplog: "LogCaptureFixture") -> None:
    """Test error method logs message."""
    logfile = tmp_path / "test.log"
    sofa_log = SofaLog(logfile=logfile)
    sofa_log.setup_logger()

    with caplog.at_level(logging.ERROR, logger="sofapy"):
        sofa_log.error("Test error message")

    assert "Test error message" in caplog.text


def test_logging_without_logger_setup(capsys: "CaptureFixture[str]") -> None:
    """Test logging methods handle case when logger is not set up."""
    sofa_log = SofaLog()

    # Should not raise errors
    sofa_log.debug("debug")
    sofa_log.info("info")
    sofa_log.warning("warning")
    sofa_log.error("error")


def test_custom_excepthook_logs_exception(tmp_path: Path, capsys: "CaptureFixture[str]") -> None:
    """Test custom_excepthook logs unhandled exceptions."""
    logfile = tmp_path / "test.log"
    sofa_log = SofaLog(logfile=logfile)
    sofa_log.setup_logger()

    try:
        raise ValueError("Test exception")
    except ValueError:
        exc_type, exc_value, exc_tb = sys.exc_info()
        sofa_log.custom_excepthook(exc_type, exc_value, exc_tb)  # type: ignore[arg-type]

    captured = capsys.readouterr()
    assert "ValueError" in captured.err
    assert "Test exception" in captured.err


def test_custom_excepthook_shows_logfile_hint(
    tmp_path: Path, capsys: "CaptureFixture[str]"
) -> None:
    """Test custom_excepthook shows logfile hint when logfile is set."""
    logfile = tmp_path / "test.log"
    sofa_log = SofaLog(logfile=logfile)
    sofa_log.setup_logger()

    try:
        raise RuntimeError("Test")
    except RuntimeError:
        exc_type, exc_value, exc_tb = sys.exc_info()
        sofa_log.custom_excepthook(exc_type, exc_value, exc_tb)  # type: ignore[arg-type]

    captured = capsys.readouterr()
    assert "log file" in captured.err.lower()


def test_custom_excepthook_keyboard_interrupt(
    tmp_path: Path, capsys: "CaptureFixture[str]"
) -> None:
    """Test custom_excepthook handles KeyboardInterrupt gracefully."""
    logfile = tmp_path / "test.log"
    sofa_log = SofaLog(logfile=logfile)
    sofa_log.setup_logger()

    with pytest.raises(SystemExit) as exc_info:
        sofa_log.custom_excepthook(KeyboardInterrupt, KeyboardInterrupt(), None)

    assert exc_info.value.code == 130


def test_custom_excepthook_writes_to_log(tmp_path: Path, caplog: "LogCaptureFixture") -> None:
    """Test custom_excepthook writes exception details to log file."""
    logfile = tmp_path / "test.log"
    sofa_log = SofaLog(logfile=logfile)
    sofa_log.setup_logger()

    with caplog.at_level(logging.ERROR, logger="sofapy.UnhandledException"):
        try:
            raise TypeError("Type error test")
        except TypeError:
            exc_type, exc_value, exc_tb = sys.exc_info()
            sofa_log.custom_excepthook(exc_type, exc_value, exc_tb)  # type: ignore[arg-type]

    assert "TypeError" in caplog.text
    assert "Type error test" in caplog.text
