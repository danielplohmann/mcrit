# MCRIT Migration Guide for v1.3.0

With the MCRIT v1.3.0 release, we address several issues noticed with SMDA over the last months.  
In particular, we noticed e.g. that not all addresses were [properly masked](https://github.com/danielplohmann/smda/issues/37), which caused functions that should be PicHash-identical to have different hashes and thus being missed during this matching phase.
Additionally, some of you experienced log output about [unhandled instructions](https://github.com/danielplohmann/smda/issues/48) during mnemonic escaping, which also in rare cases broke [opcode bytes](https://github.com/danielplohmann/smda/issues/46).
Larger Delphi binaries could furthermore stall batch processing, as there were [issues](https://github.com/danielplohmann/smda/issues/44) in parsing internal structures.

All of these have been fixed, but some of this comes at the price of potential incompatibility with calculated PicHashes and MinHashes in your databases.  
To simplify the migration and especially avoid having to reprocess any binary content, we have introduced specific migration functions in the MinHashIndex that will help to modernize all content to the new SMDA version.

## Triggering the Database Migration

After updating to the latest requirements, you should have SMDA v1.3.11 or higher available:

```bash
$ python -m pip install -r requirements.txt
...
$ python -m pip freeze | grep smda
smda==1.3.11
```

You can now do one of the following:

* use curl to queue the recalculation jobs for PicHash and MinHash: 
```bash
$ curl http://127.0.0.1:8000/recalculate_pichashes
$ curl http://127.0.0.1:8000/recalculate_minhashes
```

* use the McritClient to queue the recalculation jobs for PicHash and MinHash: 
```python
>>> from mcrit.client.McritClient import McritClient
>>> c = McritClient()
>>> c.recalculatePicHashes()
>>> c.recalculateMinHashes()
```
* use the McritWeb front-end to trigger the matching jobs  
-> this will be implemented asap and then be available to admin users in the server section.

Note that these jobs may run for an extensive amount of time depending on the number of functions indexed in your database.