import logging
import os
from pathlib import Path
from typing import Optional

_loggers: dict[str, logging.Logger] = {}

CONSOLE_FORMAT = "[%(levelname)s] %(message)s"
CONSOLE_DATE_FORMAT = None

FILE_FORMAT = "[%(asctime)s] [%(levelname)-8s] [%(name)s:%(funcName)s:%(lineno)d] %(message)s"
FILE_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"


def _create_console_formatter() -> logging.Formatter:
    """Create a clean console log formatter."""
    return logging.Formatter(
        CONSOLE_FORMAT,
        datefmt=CONSOLE_DATE_FORMAT
    )


def _create_file_formatter() -> logging.Formatter:
    """Create a detailed file log formatter."""
    return logging.Formatter(
        FILE_FORMAT,
        datefmt=FILE_DATE_FORMAT
    )


def get_logger(name: Optional[str] = None) -> logging.Logger:
    """Get or create a logger instance with file and console handlers."""
    if name is None:
        name = "viper"
    
    if name in _loggers:
        return _loggers[name]
    
    logger = logging.getLogger(name)
    logger.setLevel(logging.DEBUG)
    
    if logger.hasHandlers():
        return logger
    
    log_dir = Path("logs")
    log_dir.mkdir(exist_ok=True)
    
    file_handler = logging.FileHandler(
        log_dir / "viper.log",
        encoding="utf-8"
    )
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(_create_file_formatter())
    logger.addHandler(file_handler)
    
    console_enabled = os.getenv("VIPER_CONSOLE_LOG", "0") == "1"
    if console_enabled:
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)
        console_handler.setFormatter(_create_console_formatter())
        logger.addHandler(console_handler)
    
    _loggers[name] = logger
    
    return logger


def enable_console_logging():
    """Enable console logging output."""
    os.environ["VIPER_CONSOLE_LOG"] = "1"
    for logger in _loggers.values():
        has_console = any(
            isinstance(h, logging.StreamHandler)
            for h in logger.handlers
        )
        if not has_console:
            console_handler = logging.StreamHandler()
            console_handler.setLevel(logging.INFO)
            console_handler.setFormatter(_create_console_formatter())
            logger.addHandler(console_handler)


def disable_console_logging():
    """Disable console logging output."""
    os.environ["VIPER_CONSOLE_LOG"] = "0"
    for logger in _loggers.values():
        logger.handlers = [
            h for h in logger.handlers
            if not isinstance(h, logging.StreamHandler)
        ]
