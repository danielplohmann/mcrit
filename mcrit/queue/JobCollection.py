from typing import List

from mcrit.queue.LocalQueue import Job


class JobCollection:
    def __init__(self, jobs: List[Job]):
        self._jobs = jobs

    @property
    def count(self):
        return len(self._jobs)

    def getJobs(self):
        return self._jobs

    def getJobsForSample(self, sample_id: int, method=None, matching_only=False, finished_only=False) -> bool:
        selected_jobs = []
        for job in self._jobs:
            if matching_only and not job.is_matching_job:
                continue
            if finished_only and not job.is_finished:
                continue
            if method is not None and not job.method == method:
                continue
            if job.has_sample_id(sample_id):
                selected_jobs.append(job)
        return selected_jobs

    def filterToSampleIds(self, sample_ids: List[int]):
        filtered_jobs = []
        for job in self._jobs:
            if job.sample_id in sample_ids:
                filtered_jobs.append(job)
        self._jobs = filtered_jobs

    def filterToMethods(self, methods: List[str]):
        filtered_jobs = []
        for job in self._jobs:
            if job.method in methods:
                filtered_jobs.append(job)
        self._jobs = filtered_jobs

    def getJobById(self, job_id):
        for job in self._jobs:
            if job.job_id == job_id:
                return job
