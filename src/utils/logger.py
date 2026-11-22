"""Centralized logging and timing utilities for ML-IDS."""

import functools
import logging
import os
import sys
import time
from typing import Any, Callable


def get_logger(name: str = "ml_ids", log_file: str = None) -> logging.Logger:
    """Configure and return a structured logger instance.

    Args:
        name: Name of the logger instance.
        log_file: Optional file path to persist logs.

    Returns:
        Configured logging.Logger object.
    """
    logger = logging.getLogger(name)
    if logger.handlers:
        return logger

    logger.setLevel(logging.INFO)
    formatter = logging.Formatter(
        fmt="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    if log_file:
        os.makedirs(os.path.dirname(log_file), exist_ok=True)
        file_handler = logging.FileHandler(log_file)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

    return logger


def timer_decorator(func: Callable[..., Any]) -> Callable[..., Any]:
    """Measure and log execution time of a function.

    Args:
        func: Function to wrap.

    Returns:
        Wrapped function that logs execution duration.
    """
    logger = get_logger(func.__module__)

    @functools.wraps(func)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        start_time = time.perf_counter()
        result = func(*args, **kwargs)
        elapsed = time.perf_counter() - start_time
        logger.info("Completed '%s' in %.4f seconds.", func.__name__, elapsed)
        return result

    return wrapper
