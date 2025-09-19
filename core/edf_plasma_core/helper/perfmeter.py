"""Performance counter helper"""

from dataclasses import dataclass, field
from datetime import datetime, timedelta


@dataclass
class PerformanceMeter:
    """Performance counter combines operation timer and counter"""

    beg: datetime = field(default_factory=datetime.now)
    end: datetime | None = None
    count: int = 0

    def __enter__(self):
        self.reset()
        return self

    def __exit__(self, exc_typ, exc_val, exc_trb):
        self.stop()

    @property
    def stopped(self) -> bool:
        """Determine if timer is stopped"""
        return self.end is not None

    @property
    def elapsed(self) -> timedelta:
        """Elapsed time between latest reset and stop"""
        end = self.end or datetime.now()
        return end - self.beg

    def tick(self):
        """Increment internal counter"""
        self.count += 1

    def reset(self):
        """Reset the timer"""
        self.beg = datetime.now()
        self.end = None
        self.count = 0

    def stop(self):
        """Stop the timer"""
        self.end = datetime.now()
