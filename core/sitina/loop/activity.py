"""Process-local UI progress, never an execution or recovery authority."""
from collections import OrderedDict
from pathlib import Path
from threading import Lock
from time import time

_lock = Lock()
_tasks = OrderedDict()


def record_context_activity(state_root, task_id, owner, phase, ordinal):
    key = (str(Path(state_root).resolve()), task_id)
    with _lock:
        task = _tasks.setdefault(key, {'revision':0,'owners':{},'completed':0})
        task['revision'] += 1
        task['owners'][owner] = {'phase':phase,'ordinal':ordinal,'at':time()}
        if phase == 'COMPLETED':
            task['completed'] += 1
        _tasks.move_to_end(key)
        while len(_tasks) > 256:
            _tasks.popitem(last=False)


def read_context_activity(state_root, task_id):
    key = (str(Path(state_root).resolve()), task_id)
    with _lock:
        task = _tasks.get(key)
        if task is None:
            return {'active':False,'revision':0,'completed':0}
        return {'active':any(item['phase'] == 'COMPACTING' for item in task['owners'].values()),
                'revision':task['revision'],'completed':task['completed'],
                'failed':any(item['phase'] == 'FAILED' for item in task['owners'].values())}
