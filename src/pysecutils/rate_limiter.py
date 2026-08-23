import time
import threading
from collections import deque
from typing import Dict

class SlidingWindowRateLimiter:
    """Thread-safe Sliding Window Rate Limiter."""

    def __init__(self, max_requests: int, window_seconds: int):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.requests: Dict[str, deque] = {}
        self.lock = threading.Lock()

    def is_allowed(self, identifier: str) -> bool:
        now = time.time()
        with self.lock:
            if identifier not in self.requests:
                self.requests[identifier] = deque()
            
            queue = self.requests[identifier]
            
            while queue and queue[0] <= now - self.window_seconds:
                queue.popleft()
            
            if len(queue) < self.max_requests:
                queue.append(now)
                return True
            return False

class TokenBucketRateLimiter:
    """Thread-safe Token Bucket Rate Limiter."""

    def __init__(self, capacity: int, refill_rate_per_second: float):
        self.capacity = capacity
        self.refill_rate = refill_rate_per_second
        self.tokens = float(capacity)
        self.last_refill = time.time()
        self.lock = threading.Lock()

    def consume(self, tokens: int = 1) -> bool:
        now = time.time()
        with self.lock:
            elapsed = now - self.last_refill
            self.tokens = min(self.capacity, self.tokens + elapsed * self.refill_rate)
            self.last_refill = now
            
            if self.tokens >= tokens:
                self.tokens -= tokens
                return True
            return False
