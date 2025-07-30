# MinHash-based Code Relationship & Investigation Toolkit (MCRIT)
[![Test](https://github.com/danielplohmann/mcrit/actions/workflows/test.yml/badge.svg)](https://github.com/danielplohmann/mcrit/actions/workflows/test.yml)

MCRIT is a framework created to simplify the application of the MinHash algorithm in the context of code similarity.
It can be used to rapidly implement "shinglers", i.e. methods which encode properties of disassembled functions, to then be used for similarity estimation via the MinHash algorithm.
It is tailored to work with disassembly reports emitted by [SMDA](https://github.com/danielplohmann/smda).

## Usage

### Dockerized Usage

We highly recommend to use the fully packaged [docker-mcrit](https://github.com/danielplohmann/docker-mcrit) for trivial deployment and usage.  
First and foremost, this will ensure that you have fully compatible versions across all components, including a database for persistence and a web frontend for convenient interaction.

### Standalone Usage

Installing MCRIT on its own will require some more steps.  
For the following, we assume Ubuntu as host operating system.

The Python installation requirements are listed in `requirements.txt` and can be installed using:

```bash
# install python and MCRIT dependencies
$ sudo apt install python3 python3-pip
$ pip install -r requirements.txt 
```

By default, MongoDB 5.0 is used as backend, which is also the recommended mode of operation as it provides a persistent data storage.
The following commands outline an example installation on Ubuntu:
```bash
# fetch mongodb signing key
$ sudo apt-get install gnupg
$ wget -qO - https://www.mongodb.org/static/pgp/server-5.0.asc | sudo apt-key add -
# add package repository (Ubuntu 22.04)
$ echo "deb [ arch=amd64,arm64 ] https://repo.mongodb.org/apt/ubuntu jammy/mongodb-org/5.0 multiverse" | sudo tee /etc/apt/sources.list.d/mongodb-org-5.0.list
# OR add package repository (Ubuntu 20.04)
$ echo "deb [ arch=amd64,arm64 ] https://repo.mongodb.org/apt/ubuntu focal/mongodb-org/5.0 multiverse" | sudo tee /etc/apt/sources.list.d/mongodb-org-5.0.list
# OR add package repository (Ubuntu 18.04)
$ echo "deb [ arch=amd64,arm64 ] https://repo.mongodb.org/apt/ubuntu bionic/mongodb-org/5.0 multiverse" | sudo tee /etc/apt/sources.list.d/mongodb-org-5.0.list
# install mongodb
$ sudo apt-get update
$ sudo apt-get install -y mongodb-org
# start mongodb as a service
$ sudo systemctl start mongod
# optionally configure to start the service with system startup
$ sudo systemctl enable mongod
```

When doing the standalone installation, you possibly want to install the MCRIT module based on the cloned repository, like so:

```bash
$ pip install -e .
```

After this initial installation and if desired, MCRIT can be used without an internet connection.


#### Operation

The MCRIT backend is generally divided into two components, a server providing an API interface to work with and one or more workers processing queued jobs.
They can be started in seperate shells using:

```bash
$ mcrit server
```

and

```bash
$ mcrit worker
```

By default, the REST API server will be listening on [http://127.0.0.1:8000/](http://127.0.0.1:8000/).


## Interaction

Regardless of your choice for installation, once running you can interact with the MCRIT backend.


### MCRIT Client

We have created a Python client module that is capable of working with all available endpoints of the server.  
Documentation for this client module is currently in development.

### MCRIT CLI

There is also a CLI which is based on this client package, examples:

```bash
# query some stats of the data stored in the backend 
$ mcrit client status
{'status': {'db_state': 187, 'storage_type': 'mongodb', 'num_bands': 20, 'num_samples': 137, 'num_families': 14, 'num_functions': 129110, 'num_pichashes': 25385}}
# submit a malware sample with filename sample_unpacked, using family name "some_family"
$ mcrit client submit sample_unpacked -f some_family
 1.039s -> (architecture: intel.32bit, base_addr: 0x10000000): 634 functions
```

A more extensive documentation of the MCRIT CLI is available [here](docs/mcrit-cli.md)

### MCRIT IDA Plugin

An IDA plugin is also currently under development.
To use it, first create your own config.py and make required changes depending on the deployment of your MCRIT instance:
```
cp ./plugins/ida/template.config.py ./plugins/ida/config.py
nano ./plugins/ida/config.py
```

Then simply run the script found at

```
./plugins/ida/ida_mcrit.py
```

in IDA.

### Reference Data 

In July 2023, we started populating a [Github repository](https://github.com/danielplohmann/mcrit-data) which contains ready-to-use reference data for common compilers and libraries.


## Version History

 * 2025-07-30 v1.4.1:  Filtering for unique matches now takes precedence over scores.
 * 2025-06-13 v1.4.0:  Changed the way how percentages for matching are calculated, now using only matchable code vs. all code as baseline. Minor IDA plugin fixes.
 * 2025-05-22 v1.3.22: McritCLI now supports ENV variables (`MCRIT_CLI_SERVER` and `MCRIT_CLI_APITOKEN`) and a `.env` file for setting server and apitoken  - THX to @r0ny123 for the suggestion!
 * 2025-03-11 v1.3.21: McritCLI now supports submissions with a a spawned worker (requires --worker flag).
 * 2025-02-26 v1.3.20: Fixed a bug where crashing SpawningWorker would not be properly handled - THX to @yankovs!.
 * 2025-02-26 v1.3.18: Added server and API token support for the CLI.
 * 2024-06-20 v1.3.17: Job deletion and cleanup are now [more robust](https://github.com/danielplohmann/mcrit/pull/77) and won't accidentally purge samples unwantedly - @yankovs - THX!!
 * 2024-05-10 v1.3.16: Queue cleanup has been extended to also purge files uploaded during all 3 types of queries (mapped, unmapped, smda).
 * 2024-04-17 v1.3.15: Worker type `spawningworker` will now terminate children after QueueConfig.QUEUE_SPAWNINGWORKER_CHILDREN_TIMEOUT seconds.
 * 2024-04-02 v1.3.14: Experimental: Introduction of new worker type `spawningworker` - this variant will consume jobs from the queue as usual but defer the actual job execution into a separate (sub)process, which should reduce issues with locked memory allocations.
 * 2024-04-02 v1.3.13: When cleaning up the queue, now also [delete all failed jobs](https://github.com/danielplohmann/mcrit/pull/70) @yankovs - THX!!
 * 2024-03-06 v1.3.12: Fixed a bug where protection of recent samples from queue cleanup would lead to key errors as reported by @yankovs - THX!!
 * 2024-02-21 v1.3.10: Bump SMDA to 1.13.16, which covers another 200 instructions in a better escaped category (affects MinHashes).
 * 2024-02-16 v1.3.9:  Finished and integrated automated queue cleanup feature (disabled by default) proposed by @yankovs - THX!!
 * 2024-02-15 v1.3.8:  Bump SMDA to address issues with version recognition in SmdaFunction, fixed exception prints in IDA plugin's McritInterface (THX to @malwarefrank!!).
 * 2024-02-12 v1.3.5:  Recalculating minhashes will now show correct percentages (THX to @malwarefrank!!).
 * 2024-02-02 v1.3.4:  Mini fix in the IDA plugin to avoid referencing a potentially uninitialized object (THX to @r0ny123!!).
 * 2024-02-01 v1.3.2:  FIX: Non-parallelized matching now outputs the [same data format](https://github.com/danielplohmann/mcrit/pull/63) (THX to @dannyquist!!).
 * 2024-01-30 v1.3.1:  The connection to MongoDB is now fully [configurable](https://github.com/danielplohmann/mcrit/pull/61) (THX to @dannyquist!!).
 * 2024-01-24 v1.3.0:  BREAKING: Milestone release with indexing improvements for PicHash and MinHash. To ensure full backward compatibility, recalculation of all hashes is recommended. Check this [migration guide](https://github.com/danielplohmann/mcrit/blob/main/docs/migration-v1.3.0.md). 
 * 2024-01-23 v1.2.26: Pinning lief to 0.13.2 in order to ensure that the pinned SMDA remains compatible.
 * 2024-01-09 v1.2.25: Ensure that we can deliver system status regardless of whether there is a `db_state` and `db_timestamp` or not.
 * 2024-01-05 v1.2.24: Now supporting "query" argument in CLI, as well as compact MatchingResults (without function match info) to reduce file footprint.
 * 2024-01-03 v1.2.23: Limit maximum export size to protect the system against OOM crashes.
 * 2024-01-02 v1.2.22: Introduced data class for UniqueBlocksResult with convenience functionality.
 * 2023-12-28 v1.2.21: McritClient now doing passthrough for binary query matching.
 * 2023-12-28 v1.2.20: Status now provides timestamp of last DB update.
 * 2023-12-13 v1.2.18: Bounds check versus sample_ids passed to getUniqueBlocks.
 * 2023-12-05 v1.2.15: Added convenience functionality to Job objects, version number aligned with mcritweb.
 * 2023-11-24 v1.2.11: SMDA pinned to version 1.12.7 before we upgrade SMDA and introduce a database migration to recalculate pic + picblock hashes with the improved generalization.
 * 2023-11-17 v1.2.10: Added ability to set an authorization token for the server via header field: `apitoken`; added ability to filter by job groups; added ability to fail orphaned jobs.
 * 2023-10-17 v1.2.8:  Minor fix in job groups.
 * 2023-10-16 v1.2.6:  Summarized queue statistics, refined Job classification.
 * 2023-10-13 v1.2.4:  Exposed Queue/Job Deletion to REST interface, improved query speed for various queue lookups via indexing and parameterized mongodb queries.
 * 2023-10-13 v1.2.3:  Workers will now de-register from in-progress jobs in case they crash (THX to @yankovs for the code template).
 * 2023-10-03 v1.2.2:  MatchingResult filtering for min/max num samples (incl. fix).
 * 2023-10-02 v1.2.0:  Milestone release for Virus Bulletin 2023.
 * 2023-09-18 v1.1.7:  Bugfix: Tasking matching with 0 bands now deactivates minhash matching as it was supposed to be before. Also matching job progress percentage fixed.
 * 2023-09-15 v1.1.6:  Bugfix in BlockMatching, convenience functionality for interacting with Job objects.
 * 2023-09-14 v1.1.5:  Deactivated gunicorn as default WSGI handler for the time being due to issues with non-returning calls when handling compute-heavy calls.
 * 2023-09-14 v1.1.4:  BUGFIX: Added `requirements.txt` to `data_files` in `setup.py` to ensure it's available for the package.
 * 2023-09-13 v1.1.3:  Extracted some performance critical constants into parameters configurable in MinHashConfig and StorageConfig, fixed progress reporting for batched matching, BUGFIX: usage of GunicornConfig to proper dataclass.
 * 2023-09-13 v1.1.1:  Streamlined requirements / setup, excluded `gunicorn` for Windows (THX to @yankovs!!).
 * 2023-09-12 v1.1.0:  For Linux deployments, MCRIT now uses `gunicorn` instead of `waitress` as WSGI server because of [much better performance](https://github.com/danielplohmann/mcrit/pull/39). As gunicorn needs its own config, this required bumping the minor versions (THX to @yankovs!!).
 * 2023-09-08 v1.0.21: All methods of McritClient now forward apitokens/usernames to the backend.
 * 2023-09-05 v1.0.20: Use two-complement to represent addresses in SampleEntry, FunctionEntry when storing in MongoDB to address BSON limitations (THX to @yankovs).
 * 2023-09-05 v1.0.19: Statistics are now using the internal counters that had been created a while ago (THX to @yankovs).
 * 2023-08-30 v1.0.18: Refined LinkHunt scoring and clustering of results via ICFG relationship.
 * 2023-08-24 v1.0.15: Integrated first attempt at link hunting capability in MatchingResult.
 * 2023-08-24 v1.0.13: Rebuilding the minhash bands will no longer explode RAM usage. Removed redundant path checks (THX to @yankovs).
 * 2023-08-23 v1.0.12: Added the ability to rebuild the minhash bands used for indexing.
 * 2023-08-22 v1.0.11: Fixed a bug where when importing bulk data, the `function_name` was not also added as a `function_label`.
 * 2023-08-11 v1.0.10: Fixed a bug where when importing bulk data, the function_id would not be adjusted prior to adding MinHashes to bands, possibly leading to non-existing function_ids.
 * 2023-08-02 v1.0.9:  IDA plugin can now filter by block size and minhash score, optimized layout and user experience (THX for the feedback to @r0ny123!!)
 * 2023-07-28 v1.0.8:  IDA plugin can now display colored graphs for remote functions and do queries for PicBlockHashes (for basic blocks) for the currently viewed function.
 * 2023-06-06 v1.0.7:  Extended filtering capabilities on MatchingResult.
 * 2023-06-02 v1.0.6:  IDA plugin can now task matching jobs, show their results and batch import labels. Harmonization of MatchingResult.
 * 2023-05-22 v1.0.3:  More robustness for path verification when using MCRIT CLI on Malpedia repo folder.
 * 2023-05-12 v1.0.1:  Some progress on label import for the IDA plugin. Reflected API extension of MCRITweb in McritClient.
 * 2023-04-10 v1.0.0:  Milestone release for Botconf 2023.
 * 2023-04-10 v0.25.0: IDA plugin can now do function queries for the currently viewed function.
 * 2023-03-24 v0.24.2: McritClient can forward username/apitoken, addJsonReport is now forwardable.
 * 2023-03-21 v0.24.0: FunctionEntries now can store additional FunctionLabelEntries, along submitting user/date.
 * 2023-03-17 v0.23.0: It is now possible to query matches for single SmdaFunctions (synchronously).
 * 2023-03-15 v0.22.0: McritClient now supports apitokens and raw responses for a subset of functionality.
 * 2023-03-14 v0.21.0: Backend support for more fine grained filtering.
 * 2023-03-13 v0.20.6: Backend support for filtering family/sample by score in MatchResult.
 * 2023-02-22 v0.20.4: Bugfix for calculating unique scores and accessing these results.
 * 2023-02-21 v0.20.3: Supporting frontend capabilities with result presentation.
 * 2023-02-17 v0.20.2: Extended match report object to support frontend improvements.
 * 2023-02-14 v0.20.0: Overhauled console client to simplify shell-based interactions with the backend.
 * 2023-01-12 v0.19.4: Additional filtering capabilities for MatchingResults.
 * 2022-12-13 v0.19.1: It is now possible to require specific (higher) amounts of band matches for candidates (i.e. reduce fuzziness of matching).
 * 2022-12-13 v0.18.x: Enable matching of arbitrary function IDs.
 * 2022-11-25 v0.18.9: Accelerated Query matching.
 * 2022-11-18 v0.18.8: Harmonized handling of deletion and modifications, minor fixes.
 * 2022-11-13 v0.18.7: Drastically accelerated sample deletion.
 * 2022-11-13 v0.18.6: Added functionality to modify existing sample and family information.
 * 2022-11-11 v0.18.2: Upgrading matching procedure, should now be able to handle larger binaries more robustly and efficiently.
 * 2022-11-03 v0.18.1: Minor fixes.
 * 2022-11-03 v0.18.0: Unique block isolation now also generates a proposal for a YARA rule, restructured result output.
 * 2022-10-24 v0.17.4: Harmonized setup.py with requirements, improved memory efficiency for processing cross jobs.
 * 2022-10-18 v0.17.3: Added a convenience script to recursively produce SMDA reports from a semi-structured folder.
 * 2022-10-13 v0.17.2: Fixed potential OOM issues during MinHash calculation by processing functions to be hashed in smaller batches.
 * 2022-10-12 v0.17.1: Added a function to schedule a job that will ensure minhashes have been calculated for all samples/functions.
 * 2022-10-11 v0.17.0: Search for unique blocks is now an asychronous job through the Worker.
 * 2022-10-11 v0.16.0: Samples from MatchQuery jobs will now be stored with their Sample/FunctionEntries to allow better post processing.
 * 2022-10-04 v0.15.4: Server can now display its version.
 * 2022-09-28 v0.15.3: Addressing performance issues for bigger instances, generating escaped instruction sequence for unique blocks.
 * 2022-09-26 v0.15.0: CrossJobs now in backend, started to provide functionality to identify unique basic blocks in samples.
 * 2022-08-29 v0.14.2: Minor fixes for deployment.
 * 2022-08-22 v0.14.0: Jobs can now depend on other jobs (preparation for moving crossjobs to backend), QoL improvements to job handling.
 * 2022-08-17 v0.13.1: Added commandline option for profiling (requires cProfile).
 * 2022-08-09 v0.13.0: Can now do efficient direct queries for PicHash and PicBlockHash matches.
 * 2022-08-09 v0.12.3: Bugfix for FamilyEntry
 * 2022-08-08 v0.12.2: Bugfix for delivery of XCFG data, added missing dependency.
 * 2022-08-08 v0.12.0: Integrated Advanced Search syntax.
 * 2022-08-03 v0.11.0: (BREAKING) Families are now represented with a FamilyEntry.
 * 2022-08-03 v0.10.3: Now leaving function xcfg data by default in DB, exposed access to it via REST API and McritClient.
 * 2022-07-29 v0.10.2: Added ability to delete families - now also keeping XCFG info for all functions by default.
 * 2022-07-12 v0.10.1: Improved performance.
 * 2022-07-12 v0.10.0: (BREAKING) Job handling simplified.
 * 2022-05-13  v0.9.4: Bug fix for receiving submitted files.
 * 2022-05-13  v0.9.3: Further updates to MatchingResults.
 * 2022-05-13  v0.9.2: Added another field and more convenience functions in MatchingResult for better access - those are breaking changes for previously created MatchingResults.
 * 2022-05-05  v0.9.1: Processing of binary submissions, minor fixes for minhash queuing - INITIAL RELEASE.
 * 2022-02-09  v0.9.0: Added PicBlocks to MCRIT.
 * 2022-01-19  v0.8.0: Migrated the client and the examples into the primary MCRIT repository.
 * 2021-12-16  v0.7.0: Initial private release.

## Credits & Notes

Thanks to Steffen Enders and Paul Hordiienko for their contributions to the internal research prototype of this project!
Thanks to Manuel Blatt for his extensive contributions to and refactorings of this project as well as for the client module!

Pull requests welcome! :)

## License
```
    MinHash-based Code Relationship & Investigation Toolkit (MCRIT)
    Copyright (C) 2022  Daniel Plohmann, Manuel Blatt

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
    
    Some plug-ins and libraries may have different licenses. 
    If so, a license file is provided in the plug-in's folder.
```
