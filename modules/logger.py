"""
logger.py
==========
Configures the application-wide logger with:
  - Colored console output (INFO+)
  - Full rotating file log (DEBUG+)
"""

import logging
import os
from logging.handlers import RotatingFileHandler


class ColorFormatter(logging.Formatter):
    """Adds ANSI color codes to console log output."""

    COLORS = {
        logging.DEBUG:    "\033[38;5;240m",  # dark gray
        logging.INFO:     "\033[38;5;39m",   # blue
        logging.WARNING:  "\033[38;5;220m",  # yellow
        logging.ERROR:    "\033[38;5;196m",  # red
        logging.CRITICAL: "\033[38;5;196m\033[1m",  # bold red
    }
    RESET = "\033[0m"

    def format(self, record: logging.LogRecord) -> str:
        color = self.COLORS.get(record.levelno, "")
        record.levelname = f"{color}{record.levelname:<8}{self.RESET}"
        return super().format(record)


def setup_logger(level: int = logging.INFO, log_file: str = "logs/audit.log") -> logging.Logger:
    """
    Configure and return the root logger for the audit tool.

    Args:
        level:    Logging level for console handler (DEBUG or INFO)
        log_file: Path to the rotating log file

    Returns:
        Configured Logger instance
    """
    logger = logging.getLogger("credaudit")
    logger.setLevel(logging.DEBUG)  # capture everything; handlers filter

    if logger.handlers:
        return logger  # avoid duplicate handlers on repeated calls

    fmt_console = "%(levelname)s %(message)s"
    fmt_file    = "%(asctime)s [%(levelname)-8s] %(name)s — %(message)s"

    # ── Console handler ───────────────────────────────────────────────────────
    ch = logging.StreamHandler()
    ch.setLevel(level)
    ch.setFormatter(ColorFormatter(fmt_console))
    logger.addHandler(ch)

    # ── File handler ──────────────────────────────────────────────────────────
    try:
        log_dir = os.path.dirname(log_file)
        if log_dir:
            os.makedirs(log_dir, exist_ok=True)
        fh = RotatingFileHandler(
            log_file,
            maxBytes=5 * 1024 * 1024,   # 5 MB
            backupCount=3,
            encoding="utf-8",
        )
        fh.setLevel(logging.DEBUG)
        fh.setFormatter(logging.Formatter(fmt_file))
        logger.addHandler(fh)
    except (OSError, PermissionError) as e:
        logger.warning(f"Could not create log file '{log_file}': {e}. File logging disabled.")

    return logger
