from datetime import datetime
import hashlib
import json
import os
from sqlite3 import Timestamp
import time
from functools import wraps
import logging


# Only do basicConfig if no handlers have been configured
if len(logging._handlerList) == 0:
    logging.basicConfig(level=logging.INFO, format="%(asctime)-15s %(message)s")
LOGGER = logging.getLogger(__name__)



################# Caller ##################
class BaseRemoteCallerClass:
    def __init__(self, queue):
        self.queue = queue

    #### JOB CONTROL ####
    def JobStatus(self, job_id):
        # returns status, msg
        # status can be "NotFound", "Running", "Done", "Error"
        # msg can be the error message or Result_id in case of Done
        # Check mongoqueue for job_id if Error or Running -> Return
        # Check results-collection/job-archive for results with original_job_id=job_id
        # -> either return "Done" with result / where to find result, OR NotFound
        pass

    def getQueueData(self, filter=None):
        LOGGER.debug(f"getQueueData(filter={filter}):")
        if filter is not None:
            # TODO apply filter to more fields
            return [job._data for job in self.queue.get_jobs() if filter in job.parameters]
        return [job._data for job in self.queue.get_jobs()]

    def getJob(self, job_id):
        LOGGER.debug("GetJob: %s", job_id)
        return self.queue.get_job(job_id)

    def getJobData(self, job_id):
        LOGGER.debug("GetJobData: %s", job_id)
        return self.queue.get_job(job_id)._data

    def getResultForJob(self, job_id):
        result = None
        res_id = self.queue.get_job(job_id).result
        if res_id is not None:
            LOGGER.debug("GetResultForJob: %s -> %s", job_id, res_id)
            result = self.queue._grid_to_dicts(res_id)
        return result

    def getJobIdForResult(self, result_id):
        job_id = None
        meta = self.queue._grid_to_meta(result_id)
        if meta is not None and "job" in meta:
            job_id = meta["job"]
            LOGGER.debug("getJobIdForResult: %s -> %s", result_id, job_id)
        return job_id

    def getResult(self, res_id):
        result_dict = self.queue._grid_to_dicts(res_id)
        return result_dict

    def awaitResult(self, job_id):
        job = self.queue.get_job(job_id)
        terminated = job._is_terminated(use_cached=True)
        failed = job.is_failed
        result_id = job.result
        while (result_id is None) and (not terminated) and (not failed):
            time.sleep(0.05)
            # TODO what if job is already killed by clear?
            job = self.queue.get_job(job_id)
            terminated = job._is_terminated(use_cached=True)
            failed = job.is_failed
            result_id = job.result
        return result_id


########### START Class Metaprogramming
# Add proxies to clsCallee to clsCaller
# clsCallee is expected to be derived from QueueRemoteCallee
# clsCaller needs an self.queue attribute
def addRemoteCallFunctions(clsCallee, clsCaller):
    method_list = [func for func in dir(clsCallee) if callable(getattr(clsCallee, func)) and not func.startswith("__")]
    for name, method in zip(method_list, [getattr(clsCallee, func) for func in method_list]):
        if hasattr(method, "remote") and method.remote == True:
            new_method = RemotifyFunctionWrapper(method)
            new_method.__qualname__ = ".".join([clsCaller.__qualname__, new_method.__name__])
            setattr(clsCaller, name, new_method)
    return clsCaller


# Usage:
# MyCallerClass = QueueRemoteCallee(MyWorkerClass)
# or
# class MyAdvancedCallerClass(QueueRemoteCallee(MyWorkerClass)):
#     ...
def QueueRemoteCaller(clsCallee):
    class RemoteCallerClass(BaseRemoteCallerClass):
        pass

    return addRemoteCallFunctions(clsCallee, RemoteCallerClass)


########### END Class Metaprogramming

# Wrapper that creates a remote call proxy for a given method
def RemotifyFunctionWrapper(function):
    def submitPayloadQueue(self, payload, await_jobs):
        return str(self.queue.put(payload, await_jobs=await_jobs))

    # remote call proxy
    def remote_call_function(self, *params, await_jobs=None, force_recalculation=False, **kwparams):
        name = function.__name__

        # join file locations:
        file_locations = function.kwfile_locations + function.file_locations
        json_locations = function.kwjson_locations + function.json_locations

        # get rearranged parameters
        params, file_params = rearrange_params(params, kwparams, file_locations, json_locations)

        # get descriptor:
        hashes = hash_all(file_params)
        descriptor = get_descriptor(name, params, hashes)

        # Evaluate Cached jobs
        if not force_recalculation:
            cachedJobId = self.queue.get_cached_job_id({"descriptor": descriptor})
            if cachedJobId is not None:
                return str(cachedJobId)

        # Upload
        grid_params = upload_file_params(self, file_params, hashes)

        # Submit
        payload = _createJobPayload(name, params, grid_params, descriptor)
        if await_jobs is None:
            await_jobs = []
        job_id = submitPayloadQueue(self, payload, await_jobs)

        # Add job ids to parameters
        add_job_id_to_files(self, job_id, grid_params)

        return job_id

    return wraps(function)(remote_call_function)


### Helper functions
def sha256(data):
    return hashlib.sha256(data).hexdigest()


def to_binary(dicts):
    return json.dumps(dicts, sort_keys=True).encode("ascii")


## helpers for rearange_params
def add_list_to_dict(Dict, List):
    for i, entry in enumerate(List):
        Dict[i] = entry


def stringify_keys(d):
    return {str(key): val for key, val in d.items()}


def json_param_preprocessing(params, locations):
    for f in locations:
        if f in params:
            params[f] = to_binary(params[f])
    return params


def file_param_split(params, locations):
    files = {}
    for f in locations:
        if f in params:
            files[str(f)] = params[f]
            params[f] = None
    return params, files


# This function merges params and kwparams, by using VALUE-KEYS like "0", "1", ...
# Then the parameters are split again, into "normal" params, and file_params, which are transmitted via gridfs
def rearrange_params(params, kwparams, file_locations, json_locations):
    all_file_locations = file_locations + json_locations
    # join parameters:
    add_list_to_dict(kwparams, params)
    # all parameters are in params now:
    params = kwparams
    # do json preprocessing, replacing datastructures with strings
    params = json_param_preprocessing(params, json_locations)
    # split params into params and file_params
    params, file_params = file_param_split(params, all_file_locations)
    # stringify keys for params
    params = stringify_keys(params)
    # file_params = stringify_keys(file_params) #already done bei file_param_split
    return params, file_params


def hash_all(d):
    return {key: sha256(val) for key, val in d.items()}


def get_descriptor(name, params, hashes):
    return json.dumps((name, params, hashes), sort_keys=True)


def upload_file_params(self, file_params, hashes):
    grid_params = {}
    for key, val in file_params.items():
        grid = self.queue.get_file_by_hash_inc_lock(hashes[key])
        if grid is None:
            metadata = {"sha256": hashes[key], "tmp_lock": 1, "jobs": []}
            grid = self.queue._file_to_grid(val, metadata=metadata)
        grid_params[key] = grid
    return grid_params


def add_job_id_to_files(self, job_id, grid_params):
    for key, val in grid_params.items():
        self.queue.add_job_id_to_file(job_id, val)


# Function to encode call
def _createJobPayload(method_name, params, grid_params, descriptor):
    payload = {
        "method": method_name,
        "params": json.dumps(params),
        "file_params": json.dumps(grid_params),
        "descriptor": descriptor,
    }
    return payload



################# Callee ##################

# Marks Functions within a QueueRemoteCallee
def Remote(progress=False, file_locations=[], kwfile_locations=[], json_locations=[], kwjson_locations=[]):
    def change_function(function):
        function.remote = True
        function.progressor = progress
        function.file_locations = file_locations
        function.kwfile_locations = kwfile_locations
        function.json_locations = json_locations
        function.kwjson_locations = kwjson_locations
        return function

    return change_function


# Class to be extended
# It is derived from BaseRemoteCallerClass -> it can also query job results, etc
class QueueRemoteCallee(BaseRemoteCallerClass):
    def __init__(self, queue, profiling_path=None):
        self.queue = queue
        self.queue.clean()
        self._alive = True
        self.t_last_cleanup = time.time()
        if profiling_path is not None:
            self._executeJob = self.profiling_wrapper(self._executeJob, profiling_path)
    
    def profiling_wrapper(self, function, profiling_path):
        import cProfile
        @wraps(function)
        def wrapped_function(job, *args, **kwargs):
            start = datetime.utcnow()
            with cProfile.Profile() as pr:
                result = function(job, *args, **kwargs)
            end = datetime.utcnow()
            method = job.payload["method"]
            duration = int((end - start).total_seconds()*1000)
            filename = f"WORKER-{method}-{int(start.timestamp())}-{duration}ms.prof"
            pr.dump_stats(os.path.join(profiling_path, filename))
            return result
        return wrapped_function

    def _receive_files(self, d):
        for key, val in d.items():
            d[key] = self.queue._grid_to_file(val, results_only=False)
        return d

    def _decodeJobPayload(self, job_payload):
        payload = job_payload
        method_name = job_payload["method"]
        method = getattr(self, method_name)
        if not (hasattr(method, "remote") and method.remote == True):
            raise NotImplementedError

        params = json.loads(job_payload["params"])
        params = restore_int_keys(params)

        file_params = json.loads(job_payload["file_params"])
        file_params = restore_int_keys(file_params)

        file_params = self._receive_files(file_params)
        file_params = json_post_processing(file_params, method.json_locations + method.kwjson_locations)

        params = join_files_to_params(params, file_params)
        params, kwparams = split_list_dict(params)

        return method, params, kwparams

    def _executeJobPayload(self, job_payload, job):
        LOGGER.debug("DECODE JOB: %s", job_payload)
        method, params, kwparams = self._decodeJobPayload(job_payload)
        # Add progress reporter if necessary:
        if method.progressor:
            LOGGER.debug("kwparams: %s", kwparams)
            kwparams["progress_reporter"] = JobProgressReporter(job, 0.1)
        LOGGER.debug("EXECUTE JOB: %s", job_payload)
        result = method(*params, **kwparams)
        LOGGER.debug("FINISHED JOB: %s", job_payload)
        return result

    def _executeJob(self, job):
        if time.time() - self.t_last_cleanup >= self.queue.clean_interval:
            self.queue.clean()
            self.t_last_cleanup = time.time()
        try:
            with job as j:
                LOGGER.info("Processing Remote Job: %s", job)
                result = self._executeJobPayload(j["payload"], job)
                LOGGER.debug("Remote Job Result: %s", result)
                # ensure we always have a job_id for finished job payloads
                job.result = self.queue._dicts_to_grid(result, metadata={"result": True, "job": job.job_id})
                LOGGER.info("Finished Remote Job: %s", job)
        except Exception as exc:
            pass

    def run(self):
        self._alive = True
        while self._alive:
            job = self.queue.next()
            if job:
                LOGGER.debug("Found job")
                self._executeJob(job)
            else:
                time.sleep(0.1)

    def terminate(self):
        self._alive = False


### Helper functions


def from_binary(binary):
    return json.loads(binary.decode("ascii"))


def join_files_to_params(params, file_params):
    for key, val in file_params.items():
        params[key] = val
    return params


def split_list_dict(in_dict):
    L = []
    i = 0
    while i in in_dict:
        L.append(in_dict[i])
        i += 1
    out_dict = {key: val for key, val in in_dict.items() if type(key) != int}
    return L, out_dict


def json_post_processing(params, locations):
    for f in locations:
        if f in params:
            params[f] = from_binary(params[f])
    return params


def restore_int_keys(params):
    int_dict = {}
    del_keys = []
    for key, val in params.items():
        try:
            key_int = int(key)
            int_dict[key_int] = val
            del_keys.append(key)
        except:
            pass

    for k in del_keys:
        del params[k]
    params.update(int_dict)
    return params

################################### progress iterator


class NoProgressReporter:
    def set_total(self, total):
        pass

    def step(self):
        pass


class JobProgressReporter:
    def __init__(self, job, report_interval):
        self._job = job
        self._total = 1
        self._last_update = time.time()
        self._report_interval = report_interval
        self._count = 0
        self._submit_progress(0)

    # Total should be set after creation of this object, in the called function.
    # If total is not set, progress will be reported as absolute number of steps.
    def set_total(self, total):
        self._total = total

    def step(self):
        self._count += 1
        now = time.time()
        if now - self._last_update > self._report_interval:
            progress = self._count / self._total
            self._submit_progress(progress)
            if self._check_terminated():
                self._terminate_job()
            self._last_update = now

    def _submit_progress(self, progress):
        self._job.progressor(count=progress)

    def _check_terminated(self):
        return self._job._is_terminated()

    def _terminate_job(self):
        raise Exception("The job received a terminatation message while reporting progress")


class EmptyProgressWrapper:
    def __init__(self, iterable, total=None):
        self._iterable = iterable
        self._iterator = None
        if total is not None:
            self._length = total
        else:
            self._length = len(iterable)
        self._progress_reporter = JobProgressReporter(None, 1)

    def __iter__(self):
        self._iterator = iter(self._iterable)
        return self

    def __next__(self):
        self._progress_reporter.step()
        return next(self._iterator)
