# MinHash-based Code Recognition & Investigation Toolkit (MCRIT)

MCRIT is a framework created to simplify the application of the MinHash algorithm in the context of code similarity.
It can be used to rapidly implement "shinglers", i.e. methods which encode properties of disassembled functions, to then be used for similarity estimation via the MinHash algorithm.
It is tailored to work with disassembly reports emitted by [SMDA](https://github.com/danielplohmann/smda).

## Installation

The Python installation requirements are listed in `requirements.txt` and can be installed using:

By default, MongoDB 5.0 is used as backend, which is also the recommended mode of operation as it provides a persistent data storage.
The following commands outline an example installation on Ubuntu:
```bash
# install python and MCRIT dependencies
$ sudo apt install python3 python3-pip
$ pip install -r requirements.txt 
# fetch mongodb signing key
$ sudo apt-get install gnupg
$ wget -qO - https://www.mongodb.org/static/pgp/server-5.0.asc | sudo apt-key add -
# add package repository (Ubuntu 20.04)
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

After this initial installation and if desired, MCRIT can be used without an internet connection.

## Operation

The MCRIT framework is generally divided into two components, a server providing an interface to work with and a set of one or more workers.
They can be started in seperate shells using:

```bash
$ python -m mcrit server
```

and

```bash
$ python -m mcrit worker
```

Right now, you can only use the REST interface of the server, which is by default listening on [http://127.0.0.1:8000/](http://127.0.0.1:8000/).
We are currently working on a WebUI and we are planning to provide a dockerized deployment and an IDA Pro plugin in later releases.

### Interaction

The current release is considered an preview of MCRITs still experimental but increasingly stable state.

As long as MCRIT is not yet available on PyPI, you can do a local package installation using:

```bash
$ pip install -r requirements.txt
$ pip install -e .
```

This allows you to use the code from the provided [examples](https://github.com/danielplohmann/mcrit/tree/main/examples), which serve as a demonstration of how to use the Python client implementation, which simplifies usage and integration of MCRIT.

The two example scripts that enable basic interaction with the server are:

* ./examples/cross_compare/cross-compare.py
* ./examples/send_reports.py

The script `cross_compare.py` consumes a CSV file with columns `<family>,<version>,<filepath>` and will automatically generate a full comparison of all files listed.
It takes an optional `-c` parameter to use a hierachical clustering algorithm to group input files, otherwise the sequence as listed in the CSV file. 
Output by default is generated into `./examples/cross_compare/reports`, but this can be controlled by using the `-o <path>` parameter.

The script `send_reports.py` can be used to supply additional files to consider for matching and/or library elimination.

To easily reset the MongoDB database for a new evaluation, issue a drop command via the terminal:

```bash
$ mongo mcrit --eval "printjson(db.dropDatabase())"
```

## Version History
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
    MinHash-based Code Recognition & Investigation Toolkit (MCRIT)
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
