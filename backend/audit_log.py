"""Local audit trail for CoA actions and switch commands. Never logs passwords."""
import json
import logging
import sys
from datetime import datetime
from pathlib import Path

_LOG_DIR = Path(sys.executable).parent if getattr(sys, "frozen", False) else Path(__file__).parent

_logger = logging.getLogger("ise_audit")
_logger.setLevel(logging.INFO)
_handler = logging.FileHandler(_LOG_DIR / "audit.log", encoding="utf-8")
_handler.setFormatter(logging.Formatter("%(message)s"))
_logger.addHandler(_handler)
_logger.propagate = False


def log(action: str, **details) -> None:
    entry = {"ts": datetime.now().isoformat(timespec="seconds"), "action": action, **details}
    _logger.info(json.dumps(entry, ensure_ascii=False))


if __name__ == "__main__":
    log("self_check", host="1.2.3.4", user="admin", mac="00:11:22:33:44:55", result="ok")
    last_line = _handler.baseFilename
    with open(last_line, encoding="utf-8") as f:
        last = json.loads(f.readlines()[-1])
    assert last["action"] == "self_check"
    assert "password" not in json.dumps(last)
    print("audit_log self-check ok ->", last_line)
