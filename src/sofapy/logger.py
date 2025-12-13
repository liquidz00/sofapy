import logging
import sys
import traceback
from logging.handlers import RotatingFileHandler
from pathlib import Path
from types import TracebackType
from typing import Type

import asyncclick as click


class SofaLog:
    def __init__(
        self,
        logger_name: str | None = "sofapy",
        max_bytes: int | None = 1048576 * 100,  # 100 MB
        backup_count: int | None = 10,
        logfile: str | Path | None = None,
    ) -> None:
        self.logger_name = logger_name
        self.max_bytes = max_bytes
        self.backup_count = backup_count
        self.logfile: Path | None = None
        self._logger: logging.Logger | None = None
        self._debug_mode: bool = False

        if logfile:
            self.logfile = self._create_logfile(Path(logfile))

    def _create_logfile(self, logfile: Path) -> Path:
        """Create log file and parent directories if they don't exist."""
        if not logfile.parent.exists():
            logfile.parent.mkdir(exist_ok=True, parents=True)
        if not logfile.exists():
            logfile.touch()
        return logfile

    def setup_logger(
        self,
        name: str | None = None,
        level: int | None = logging.INFO,
        debug: bool = False,
    ) -> logging.Logger:
        """
        Configures and returns a logger. If the logger is already configured, it ensures no duplicate handlers.

        :param name: Name of the logger, defaults to "sofapy".
        :type name: str | None
        :param level: Logging level, defaults to INFO if not specified.
        :type level: int | None
        :param debug: Whether to enable debug logging for console, defaults to False.
        :type debug: bool
        :return: The configured logger.
        :rtype: logging.Logger
        """
        self._debug_mode = debug
        logger_name = name if name else self.logger_name
        logger = logging.getLogger(logger_name)

        if not logger.hasHandlers():
            # Only add file handler if logfile is configured
            if self.logfile:
                file_handler = RotatingFileHandler(
                    self.logfile,
                    maxBytes=self.max_bytes,
                    backupCount=self.backup_count,
                )
                file_handler.setFormatter(
                    logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
                )
                file_handler.setLevel(level)
                logger.addHandler(file_handler)

            logger.setLevel(logging.DEBUG)  # Capture all messages, delegate to handlers

        self._logger = logger
        return logger

    def setup_child_logger(self, childName: str, loggerName: str | None = None) -> logging.Logger:
        """
        Setup a child logger for a specified context.

        :param childName: The name of the child logger.
        :type childName: str
        :param loggerName: The name of the parent logger, defaults to "sofapy".
        :type loggerName: str
        :return: The configured child logger.
        :rtype: logging.Logger
        """
        name = loggerName if loggerName else self.logger_name
        return logging.getLogger(name).getChild(childName)

    def debug(self, msg: str) -> None:
        """
        Log a debug message. Echoes to console in magenta if debug mode is enabled.

        :param msg: The message to log.
        :type msg: str
        """
        if self._logger:
            self._logger.debug(msg)
        if self._debug_mode:
            click.echo(click.style(f"DEBUG: {msg}", fg="magenta"))

    def info(self, msg: str) -> None:
        """
        Log a info message. Echoes to console in blue if debug mode is enabled.

        :param msg: The message to log.
        :type msg: str
        """
        if self._logger:
            self._logger.info(msg)
        if self._debug_mode:
            click.echo(click.style(f"INFO: {msg}", fg="blue"))

    def warning(self, msg: str) -> None:
        """
        Log a warning message. Echoes to console in yellow if debug mode is enabled.

        :param msg: The message to log.
        :type msg: str
        """
        if self._logger:
            self._logger.warning(msg)
        if self._debug_mode:
            click.echo(click.style(f"WARNING: {msg}", fg="yellow", bold=True))

    def error(self, msg: str) -> None:
        """
        Log an error message.

        :param msg: The message to log
        :type msg: str
        """
        if self._logger:
            self._logger.error(msg)

    def custom_excepthook(
        self,
        exc_type: Type[BaseException],
        exc_value: BaseException,
        exc_traceback: TracebackType | None,
    ) -> None:
        """
        A custom exception handler for unhandled exceptions.

        This method is intended to be assigned to ``sys.excepthook`` to handle any uncaught exceptions in the application.

        :param exc_type: The class of the exception raised.
        :type exc_type: Type[BaseException]
        :param exc_value: The instance of the exception raised.
        :type exc_value: BaseException
        :param exc_traceback: The traceback object associated with the exception.
        :type exc_traceback: TracebackType | None
        """
        parent_logger = logging.getLogger(self.logger_name)
        child_logger = parent_logger.getChild("UnhandledException")
        child_logger.setLevel(parent_logger.level)

        if exc_type.__name__ == "KeyboardInterrupt":
            # Exit gracefully on keyboard interrupt
            child_logger.info("User interrupted the process.")
            sys.exit(130)  # SIGINT

        # format traceback
        formatted_traceback = "".join(
            traceback.format_exception(exc_type, exc_value, exc_traceback)
        )

        child_logger.error(
            f"Unhandled exception: {exc_type.__name__}: {exc_value}\n{formatted_traceback}"
        )

        # Show user-friendly message in console
        console_message = f"❌ {exc_type.__name__}: {exc_value}"

        click.echo(
            click.style(console_message, fg="red", bold=True),
            err=True,
        )
        if self.logfile:
            click.echo(
                f"💡 For more details, please check the log file at: '{self.logfile}'",
                err=True,
            )
        return
