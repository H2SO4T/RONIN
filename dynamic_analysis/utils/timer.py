import time

class Timer:

    # timer expressed in minutes
    def __init__(self, timer=10):
        self.start = time.perf_counter()
        self.timer = timer

    def time_elapsed_seconds(self):
        return time.perf_counter() - self.start

    def time_elapsed_minutes(self):
        return int((time.perf_counter() - self.start) / 60.0)

    def timer_expired(self):
        return True if (int((time.perf_counter() - self.start) / 60.0) >= self.timer) else False