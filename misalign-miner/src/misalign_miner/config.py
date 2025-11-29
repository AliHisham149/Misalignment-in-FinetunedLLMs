# src/misalign_miner/config.py
from dataclasses import dataclass
from datetime import date

@dataclass
class Settings:
    DATA_DIR: str
    BACKUP_DIR: str
    START_DATE: date
    END_DATE: date
    WINDOW_DAYS: int = 180
    QUIET: bool = True
    MAX_ISSUES_PER_QUERY: int = 1000
    MAX_PRS_PER_QUERY: int = 1000
