import threading
import time

from . import accounts, config, ipa, store
from .jobs import run_capture
from .log import log

DUE_INTERVAL = 30 * 60
# Runs that leave an app due back off up to this, so one shared failure (Apple refusing the
# account, a device that stays away) isn't retried every 30 minutes. Arrivals still run at once.
MAX_BACKOFF = 4 * 60 * 60
IDLE_INTERVAL = 6 * 60 * 60
ARRIVAL_DEBOUNCE = 5 * 60
RUN_TIMEOUT = 6 * 60 * 60


def configured(cfg=None):
    cfg = cfg or config.read()
    return bool(cfg["APPLE_ID"] and cfg["APPLE_PASSWORD"] and store.device_ids() and store.app_ids()) or any(
        accounts.ready(accounts.resolve(a, u)) for a in store.app_ids() for u in store.app_devices(a))


class Watcher:
    def __init__(self, jobs, health):
        self.jobs, self.health = jobs, health
        self.next_run = time.time() + 120
        self.misses = 0
        self.last_poke = {}
        self.queue = set()
        self.lock = threading.Lock()

    def renewals(self):
        """When each installed, auto re-signed target enters its renewal window."""
        window = config.renew_before_days() * 86400
        for app_id in store.app_ids():
            min_ios = ipa.required_ios(ipa.cached(config.APPS / app_id),
                                       store.app_meta(app_id)["KEEP_EXTENSIONS"] == "1")
            for udid in store.app_devices(app_id):
                # An app the device's iOS can't run is flagged in the UI; retrying it can't succeed.
                if ipa.requires_newer(min_ios, store.device_ios(udid)):
                    continue
                # Only apps the user installed and left on auto re-sign; never first installs.
                expiry = store.read_state(accounts.state_folder(app_id, udid))["expiry"]
                if expiry and store.auto_resign(app_id, udid):
                    yield expiry - window

    def due(self):
        return any(at <= time.time() for at in self.renewals())

    def schedule(self, ran=False):
        now = time.time()
        renewals = list(self.renewals())
        upcoming = min(renewals, default=None)
        if upcoming is not None and upcoming <= now:
            # Still due after a run: it failed or the device was away, so wait longer each time.
            self.misses = min(self.misses + int(ran), 4)
            self.next_run = now + min(DUE_INTERVAL * 2 ** max(self.misses - 1, 0), MAX_BACKOFF)
            # A failing target must not delay another target entering its renewal window.
            future = min((at for at in renewals if at > now), default=None)
            if future is not None:
                self.next_run = min(self.next_run, future + 5)
        else:
            self.misses = 0
            # Wake when the next app enters its window, not up to IDLE_INTERVAL later.
            self.next_run = now + IDLE_INTERVAL if upcoming is None else min(now + IDLE_INTERVAL, upcoming + 5)

    def soon(self):
        """Run a check shortly, e.g. after a device's signing account changed."""
        self.misses = 0
        self.next_run = min(self.next_run, time.time() + 30)

    def poke(self, udid):
        now = time.time()
        with self.lock:
            if now - self.last_poke.get(udid, 0) < ARRIVAL_DEBOUNCE:
                return
            self.last_poke[udid] = now
            self.queue.add(udid)
        log(f"watcher: {store.device_name(udid)} came online")

    def loop(self):
        while True:
            time.sleep(5)
            try:
                self.tick()
            except Exception as e:
                # One bad read must not end automatic re-signing for good.
                log(f"watcher: {type(e).__name__}: {e}")
                self.next_run = time.time() + DUE_INTERVAL

    def tick(self):
        timer = time.time() >= self.next_run
        with self.lock:
            queued = sorted(self.queue)
        if not timer and not queued:
            return
        cfg = config.read()
        if cfg["AUTO_CHECK"] != "1" or not configured(cfg):
            with self.lock:
                self.queue.clear()
            self.schedule()
            return
        job = self.jobs.claim_auto()
        if not job:
            return
        with self.lock:
            self.queue.clear()
        try:
            for udid in [None] if timer else queued:
                run_capture(job, ["refresh.sh"] + (["--device", udid] if udid else []), RUN_TIMEOUT)
        finally:
            job.ended = time.time()
            if job.lines:
                log("watcher:", job.lines[-1])
            previous_run = self.next_run
            self.schedule(ran=timer)
            if not timer:
                # An arrival only checks the queued devices. Keep the deadline for all others.
                self.next_run = min(previous_run, self.next_run)
            self.health.scan()
