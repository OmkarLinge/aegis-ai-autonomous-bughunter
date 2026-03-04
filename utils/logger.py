"""
Aegis AI — Structured Logger
Provides colored console output and file-based logging for all agents.
"""
import logging
import sys
from datetime import datetime
from pathlib import Path

LOG_DIR = Path(__file__).parent.parent / "logs"
LOG_DIR.mkdir(exist_ok=True)

# ANSI color codes for terminal output
COLORS = {
    "RESET": "\033[0m",
    "RED": "\033[91m",
    "GREEN": "\033[92m",
    "YELLOW": "\033[93m",
    "BLUE": "\033[94m",
    "MAGENTA": "\033[95m",
    "CYAN": "\033[96m",
    "WHITE": "\033[97m",
    "BOLD": "\033[1m",
}

AGENT_COLORS = {
    "RECON": COLORS["CYAN"],
    "ENDPOINT": COLORS["BLUE"],
    "EXPLOIT": COLORS["RED"],
    "CLASSIFIER": COLORS["MAGENTA"],
    "ANOMALY": COLORS["YELLOW"],
    "STRATEGY": COLORS["GREEN"],
    "REPORT": COLORS["WHITE"],
    "ORCHESTRATOR": COLORS["BOLD"],
}


class AgentFormatter(logging.Formatter):
    """Custom formatter that adds agent name and colors to log output."""

    def format(self, record):
        timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        agent = getattr(record, "agent", "SYSTEM")
        color = AGENT_COLORS.get(agent, COLORS["WHITE"])
        level = record.levelname
        message = record.getMessage()

        if record.levelno >= logging.ERROR:
            level_color = COLORS["RED"]
        elif record.levelno >= logging.WARNING:
            level_color = COLORS["YELLOW"]
        else:
            level_color = COLORS["GREEN"]

        formatted = (
            f"{COLORS['WHITE']}[{timestamp}]{COLORS['RESET']} "
            f"{color}[{agent:12}]{COLORS['RESET']} "
            f"{level_color}{level:8}{COLORS['RESET']} "
            f"{message}"
        )
        return formatted


def get_logger(name: str, agent: str = "SYSTEM") -> logging.Logger:
    """
    Get a configured logger for a specific agent.

    Args:
        name: Logger name (usually __name__)
        agent: Agent identifier for color-coding

    Returns:
        Configured Logger instance
    """
    logger = logging.getLogger(name)

    if logger.handlers:
        return logger

    logger.setLevel(logging.DEBUG)

    # Console handler with colors
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.DEBUG)
    console_handler.setFormatter(AgentFormatter())

    # File handler (plain text)
    log_file = LOG_DIR / f"aegis_{datetime.now().strftime('%Y%m%d')}.log"
    file_handler = logging.FileHandler(log_file, encoding="utf-8")
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(
        logging.Formatter("%(asctime)s [%(name)s] %(levelname)s %(message)s")
    )

    logger.addHandler(console_handler)
    logger.addHandler(file_handler)

    # Attach agent name to all log records from this logger
    old_factory = logging.getLogRecordFactory()

    def record_factory(*args, **kwargs):
        record = old_factory(*args, **kwargs)
        record.agent = agent
        return record

    return logger


def log_agent_event(logger: logging.Logger, event: str, details: dict = None):
    """Log a structured agent event with optional details."""
    msg = f"EVENT={event}"
    if details:
        details_str = " | ".join(f"{k}={v}" for k, v in details.items())
        msg += f" | {details_str}"
    logger.info(msg)
