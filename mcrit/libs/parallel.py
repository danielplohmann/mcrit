from multiprocessing import cpu_count, get_context


def create_process_pool(processes=None):
    """Use a spawn-based context to avoid Python 3.12 fork warnings on Linux."""
    process_count = processes if processes is not None else cpu_count()
    return get_context("spawn").Pool(process_count)
