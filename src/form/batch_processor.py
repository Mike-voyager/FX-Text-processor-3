"""
batch_processor.py

Safe and extensible batch processing engine for FX Text Processor 3.
Features:
  - job queue, statuses, detailed log, retries, timeout
  - on_status_change / on_complete hooks for progress
  - cancel, export results, save/load state
  - security hooks: audit, permission, signature support (safely stubbed if modules missing)
"""

import csv
import json
import logging
import queue
import threading
import time
from dataclasses import asdict, dataclass, field
from enum import Enum, auto
from typing import Any, Callable, Dict, List, Optional, Union

logger = logging.getLogger(__name__)

# ==== Security Stubs (for testability) ====
try:
    from security.audit.logger import log_batch_event  # type: ignore
    from security.auth.permissions import check_permission  # type: ignore
    from security.crypto.symmetric import decrypt, encrypt  # type: ignore
except ImportError:

    def log_batch_event(*args, **kwargs) -> None:  # type: ignore
        pass

    def check_permission(*args, **kwargs) -> bool:  # type: ignore
        return True

    def encrypt(data, *a, **k) -> Any:  # type: ignore
        return data

    def decrypt(data, *a, **k) -> Any:  # type: ignore
        return data


# ==== Batch Status Enum ====
class BatchStatus(Enum):
    PENDING = auto()
    RUNNING = auto()
    SUCCESS = auto()
    ERROR = auto()
    SKIPPED = auto()
    CANCELLED = auto()


@dataclass
class BatchLogEntry:
    timestamp: float
    level: str
    message: str


@dataclass
class BatchTask:
    name: str
    func: Callable[..., Any]
    args: tuple = field(default_factory=tuple)
    kwargs: dict = field(default_factory=dict)
    status: BatchStatus = BatchStatus.PENDING
    result: Any = None
    error: Optional[str] = None
    duration: Optional[float] = None
    retries: int = 0
    log: List[BatchLogEntry] = field(default_factory=list)
    started: Optional[float] = None
    finished: Optional[float] = None

    def add_log(self, msg: str, level: str = "INFO") -> None:
        self.log.append(BatchLogEntry(time.time(), level, msg))


class BatchProcessor:
    def __init__(
        self,
        parallel: bool = False,
        max_threads: int = 4,
        max_retries: int = 2,
        task_timeout: Optional[float] = None,
        secure_mode: bool = False,
    ):
        self.tasks: List[BatchTask] = []
        self.parallel = parallel
        self.max_threads = max_threads
        self.max_retries = max_retries
        self.task_timeout = task_timeout
        self.secure_mode = secure_mode
        self.results: List[BatchTask] = []
        self._cancel: bool = False
        self.on_status_change: Optional[Callable[[BatchTask], None]] = None
        self.on_complete: Optional[Callable[[List[BatchTask]], None]] = None

    def add_task(
        self, name: str, func: Callable[..., Any], *args: Any, **kwargs: Any
    ) -> None:
        if self.secure_mode and "user_id" in kwargs:
            check_permission(kwargs["user_id"], "run_batch")
            log_batch_event(
                kwargs["user_id"], action="batch_task_create", details={"task": name}
            )
        self.tasks.append(BatchTask(name, func, args, kwargs))

    def clear(self) -> None:
        self.tasks.clear()
        self.results.clear()

    def cancel(self) -> None:
        self._cancel = True

    def process(self) -> List[BatchTask]:
        self.results.clear()
        self._cancel = False
        if self.parallel and len(self.tasks) > 1:
            self._process_parallel()
        else:
            self._process_sequential()
        if self.on_complete:
            self.on_complete(self.results)
        return self.results

    def _run_task(self, task: BatchTask) -> None:
        if self._cancel:
            task.status = BatchStatus.CANCELLED
            task.add_log("Task cancelled before start.", "WARN")
            if self.on_status_change:
                self.on_status_change(task)
            return
        retries = 0
        while retries <= self.max_retries:
            task.status = BatchStatus.RUNNING
            task.started = time.monotonic()
            try:
                if self.task_timeout:
                    result_holder: Dict[str, Any] = {}
                    exc_holder: Dict[str, Any] = {}

                    def _target() -> None:
                        try:
                            result_holder["result"] = task.func(
                                *task.args, **task.kwargs
                            )
                        except Exception as ex:
                            exc_holder["error"] = ex

                    thread = threading.Thread(target=_target, daemon=True)
                    thread.start()
                    thread.join(timeout=self.task_timeout)
                    if thread.is_alive():
                        task.status = BatchStatus.ERROR
                        task.error = f"Timeout ({self.task_timeout}s)"
                        task.add_log(
                            f"Timeout: task exceeded {self.task_timeout} sec.", "ERROR"
                        )
                        logger.error(f"Timeout in task {task.name}")
                        return
                    if "error" in exc_holder:
                        raise exc_holder["error"]
                    result = result_holder.get("result")
                else:
                    result = task.func(*task.args, **task.kwargs)
                task.result = result
                task.status = BatchStatus.SUCCESS
                task.add_log("Task completed successfully.")
                if self.secure_mode and "user_id" in task.kwargs:
                    log_batch_event(
                        task.kwargs["user_id"],
                        action="batch_task_complete",
                        details={"task": task.name},
                    )
                break
            except Exception as ex:
                retries += 1
                task.retries = retries
                task.error = str(ex)
                task.status = BatchStatus.ERROR
                task.add_log(f"Error (attempt {retries}): {ex}", "ERROR")
                logger.error(f"Batch task {task.name} failed: {ex}")
                if retries > self.max_retries:
                    break
                else:
                    task.add_log(f"Retrying (delay 0.1s)...", "INFO")
                    time.sleep(0.1)
            finally:
                task.finished = time.monotonic()
                task.duration = round(task.finished - task.started, 4)
        if self.on_status_change:
            self.on_status_change(task)

    def _process_sequential(self) -> None:
        for task in self.tasks:
            if self._cancel:
                task.status = BatchStatus.SKIPPED
                task.add_log("Skipped due to batch cancellation.", "WARN")
                self.results.append(task)
                continue
            self._run_task(task)
            self.results.append(task)

    def _process_parallel(self) -> None:
        q: queue.Queue[BatchTask] = queue.Queue()
        for task in self.tasks:
            q.put(task)
        lock = threading.Lock()

        def worker() -> None:
            while not q.empty():
                try:
                    task = q.get_nowait()
                except queue.Empty:
                    break
                if self._cancel:
                    task.status = BatchStatus.SKIPPED
                    task.add_log("Skipped due to batch cancellation.", "WARN")
                    with lock:
                        self.results.append(task)
                    continue
                self._run_task(task)
                with lock:
                    self.results.append(task)
                q.task_done()

        threads = []
        for _ in range(min(self.max_threads, len(self.tasks))):
            t = threading.Thread(target=worker, daemon=True)
            t.start()
            threads.append(t)
        for t in threads:
            t.join()

    def summary(self) -> Dict[str, Any]:
        return {
            "tasks": len(self.results),
            "success": sum(1 for t in self.results if t.status == BatchStatus.SUCCESS),
            "error": sum(1 for t in self.results if t.status == BatchStatus.ERROR),
            "cancelled": sum(
                1 for t in self.results if t.status == BatchStatus.CANCELLED
            ),
            "skipped": sum(1 for t in self.results if t.status == BatchStatus.SKIPPED),
            "results": [
                {
                    "name": t.name,
                    "status": t.status.name,
                    "duration": t.duration,
                    "error": t.error,
                    "retries": t.retries,
                    "log": [asdict(entry) for entry in t.log],
                }
                for t in self.results
            ],
        }

    def export_results(self, path: str, as_json: bool = True) -> None:
        if as_json:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(self.summary(), f, ensure_ascii=False, indent=2)
        else:
            with open(path, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["name", "status", "duration", "error", "retries"])
                for t in self.results:
                    writer.writerow(
                        [t.name, t.status.name, t.duration, t.error, t.retries]
                    )

    def save_state(self, path: str) -> None:
        with open(path, "w", encoding="utf-8") as f:
            data = [asdict(t) for t in self.tasks]
            json.dump(data, f, ensure_ascii=False, indent=2)

    def load_state(self, path: str) -> None:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        self.clear()
        for item in data:
            task = BatchTask(
                name=item["name"],
                func=lambda *a, **k: None,  # placeholder; override for restore in production!
                args=tuple(item.get("args", [])),
                kwargs=item.get("kwargs", {}),
                status=BatchStatus[item.get("status", "PENDING")],
                result=item.get("result", None),
                error=item.get("error", None),
                duration=item.get("duration"),
                retries=item.get("retries", 0),
                log=[BatchLogEntry(**le) for le in item.get("log", [])],
                started=item.get("started"),
                finished=item.get("finished"),
            )
            self.tasks.append(task)


# ==== Batch Actions Registry ====
ACTION_REGISTRY: Dict[str, Callable[..., Any]] = {}


def batch_action(name: str) -> Any:
    def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
        ACTION_REGISTRY[name] = func
        return func

    return decorator


# === Example secure batch action ===
@batch_action("secure_export")
def secure_export(form_data: dict, user_id: str) -> dict:
    check_permission(user_id, "export_form")
    result = {"data": form_data, "digest": "imithash"}
    # Try security feature, fallback to dummy
    try:
        from security.signatures import sign_with_private_key  # type: ignore

        result["signature"] = sign_with_private_key(form_data, user_id)
    except ImportError:
        result["signature"] = "[fake signature]"
    log_batch_event(
        user_id, action="secure_export", details={"form_id": form_data.get("id")}
    )
    return result


# ==== Usage Example ====
if __name__ == "__main__":
    import random

    @batch_action("uppercase")
    def to_uppercase(text: str) -> str:
        return text.upper()

    @batch_action("unstable")
    def random_fail(val: int) -> int:
        if random.random() < 0.5:
            raise RuntimeError("Random fail")
        return val * 2

    def on_progress(task: BatchTask) -> None:
        print(f"{task.name}: {task.status.name} (retries={task.retries})")

    def on_finish(results: List[BatchTask]) -> None:
        print("Batch done.", [t.status.name for t in results])

    bp = BatchProcessor(parallel=True, max_retries=3, task_timeout=2, secure_mode=True)
    bp.on_status_change = on_progress
    bp.on_complete = on_finish
    bp.add_task("to-upper", to_uppercase, "heLLo Fx89O")
    bp.add_task("maybe-fail", random_fail, 99)
    bp.add_task(
        "secure-form", secure_export, {"id": "123", "payload": "abc"}, user_id="tester"
    )
    bp.process()
    print(bp.summary())
    bp.export_results("batch_results.json")
    bp.save_state("batch_state.json")
