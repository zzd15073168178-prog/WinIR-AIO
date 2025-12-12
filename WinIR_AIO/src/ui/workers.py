"""
Worker Module
Generic background task handling using QThreadPool and QRunnable
"""

import sys
import traceback
import logging
from typing import Callable, Any, Optional, Dict

from PySide6.QtCore import QObject, QRunnable, Signal, Slot, QThreadPool

logger = logging.getLogger(__name__)

class WorkerSignals(QObject):
    """
    Defines the signals available from a running worker thread.
    
    Supported signals are:
    finished
        No data
    error
        tuple (exctype, value, traceback.format_exc())
    result
        object data returned from processing, anything
    progress
        int indicating % progress
    status
        str indicating status message
    """
    finished = Signal()
    error = Signal(tuple)
    result = Signal(object)
    progress = Signal(int)
    status = Signal(str)

class Worker(QRunnable):
    """
    Worker thread
    
    Inherits from QRunnable to handle worker thread setup, signals and wrap-up.
    
    :param fn: The function callback to run on this worker thread. Supplied args and
                     kwargs will be passed through to the runner.
    :type fn: function
    :param args: Arguments to pass to the callback function
    :param kwargs: Keywords to pass to the callback function
    """

    def __init__(self, fn: Callable, *args, **kwargs):
        super().__init__()

        # Store constructor arguments (re-used for processing)
        self.fn = fn
        self.args = args
        self.kwargs = kwargs
        self.signals = WorkerSignals()
        
        # Add the progress callback to kwargs
        self.kwargs['progress_callback'] = self.signals.progress
        self.kwargs['status_callback'] = self.signals.status

    @Slot()
    def run(self):
        """
        Initialise the runner function with passed args, kwargs.
        """
        try:
            result = self.fn(*self.args, **self.kwargs)
        except Exception:
            traceback.print_exc()
            exctype, value = sys.exc_info()[:2]
            self.signals.error.emit((exctype, value, traceback.format_exc()))
        else:
            self.signals.result.emit(result)
        finally:
            self.signals.finished.emit()

class TaskManager(QObject):
    """
    Central manager for background tasks
    """
    
    def __init__(self):
        super().__init__()
        self.threadpool = QThreadPool()
        logger.info(f"Task Manager initialized with {self.threadpool.maxThreadCount()} threads")
        
    def start_task(self, 
                  task_func: Callable, 
                  on_result: Optional[Callable] = None,
                  on_error: Optional[Callable] = None,
                  on_finished: Optional[Callable] = None,
                  on_progress: Optional[Callable] = None,
                  on_status: Optional[Callable] = None,
                  *args, **kwargs):
        """
        Start a background task
        
        Args:
            task_func: Function to run
            on_result: Callback for result
            on_error: Callback for error
            on_finished: Callback for completion
            on_progress: Callback for progress updates
            on_status: Callback for status updates
            *args, **kwargs: Arguments for task_func
        """
        worker = Worker(task_func, *args, **kwargs)
        
        if on_result:
            worker.signals.result.connect(on_result)
        if on_error:
            worker.signals.error.connect(on_error)
        if on_finished:
            worker.signals.finished.connect(on_finished)
        if on_progress:
            worker.signals.progress.connect(on_progress)
        if on_status:
            worker.signals.status.connect(on_status)
            
        self.threadpool.start(worker)
        
    def wait_all(self):
        """Wait for all tasks to complete"""
        self.threadpool.waitForDone()

# Global instance
global_task_manager = TaskManager()
