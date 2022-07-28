## Support

All issues and inquiries relating to this 128iid implementation must contact Armis support at `support@armis.com`.

## Prerequisites

This task with communicate with Armis and Kenna APIs. To run the task you will need

1. armis_api_host (Armis Hostname)
2. armis_api_secret_token (Armis Secret Key)
3. kenna_api_key (Kenna API Key)
4. kenna_api_host (Kenna API Host)
5. kenna_connector_id (Kenna Connector ID)

## Running the Task

Run Task with required options

```
docker run -it --rm 128iid:latest
        task=armis \
        armis_api_host="integration-xyz" \
        armis_api_secret_token=your-api-token \
        kenna_api_key=your-api-key  \
        kenna_api_host=your-api-host \
        kenna_connector_id=connector-id \
        enable_checkpoint=false
```

In case you want to run the task with checkpoint feature enabled

```
docker run -it --rm \
        -v <repository-path>/output:/opt/app/128iid/output \
        -t 128iid:latest task=armis \
        armis_api_host="integration-xyz" \
        armis_api_secret_token=your-api-token \
        kenna_api_key=your-api-key  \
        kenna_api_host=your-api-host \
        kenna_connector_id=connector-id \
        enable_checkpoint=true
```

The checkpoint feature allows you to sync only devices which have been detected since last time the task was executed.

When `enable_checkpoint` is `true`, the task will look for existence of checkpoint file which contains last run information. If the checkpoint file found, then it will pull devices since the datetime mentioned in the checkpoint file. Checkpointing feature depends on device's `lastSeen` date. Task will sync only devices whose `lastSeen` has been updated since last run.

Note: If you're seeing any discrepancy in CVEs data, it might be because CVE status might have been updated but related device's `lastSeen` might not have updated. Due to which such devices and associated CVEs might not get pulled. In such scenarios you can run the task with `enable_checkpoint=false`.

Detailed setup and task execution instructions can be found from [here](https://github.com/denistreshchev/128iid/blob/main/README.md). 

## Command Line

See the main 128iid for instructions on running tasks. For this task, if you leave off the Kenna API Key and Kenna Connector ID, the task will create a json file in the default or specified output directory. You can review the file before attempting to upload to the Kenna directly.

Recommended Steps: 

1. Run with Armis Keys only to ensure you are able to get data properly from the scanner
2. Review output for expected data
3. Create Kenna Data Importer connector in Kenna (example name: Armis KDI) 
4. Manually run the connector with the json from step 1 
5. Click on the name of the connector to get the connector id
6. Run the task with Armis Keys and Kenna Key + Connector id

Complete list of Options:

| Option | Required | Description | default |
| --- | --- | --- | --- |
| armis_api_host | true | Armis instance hostname, e.g. "integration-xyz"  | n/a |
| armis_api_secret_token | true | Armis Secret Key | n/a |
| batch_size | false | Maximum number of devices to retrieve in single batch | 500 |
| armis_aql_query | true | Armis Query Language. `timeFrame` option is not supported in provided aql string. Must escape query string in command line script, e.g. \\"in:devices\\". | "in:devices" |
| armis_backfill_duration | false | Armis Backfill Duration (In Days): Number of days to look back. In case `enable_checkpoint` is `true` and checkpoint file exists, this option will have no effect. | 15 |
| enable_checkpoint | false | If set to true, enables checkpoint mechanism. This feature instructs task to track last run information at directory specified in `checkpoint_directory` option. Used to fetch only devices which have been detected since last run. | true |
| checkpoint_directory | false | If set, will write a file upon completion. Checkpoint file will contain `lastSeen` date of last pulled device. Path is relative to #{$basedir} | output/armis/checkpoint |
| kenna_api_key | false | Kenna API Key for use with connector option | n/a |
| kenna_api_host | false | Kenna API Hostname if not US shared | api.denist.dev |
| kenna_connector_id | false | If set, we'll try to upload to this connector | n/a |
| output_directory | false | If set, will write a file upon completion. Path is relative to #{$basedir} | output/armis |

## Armis - Kenna Mapping Information

Please go through [data mapping document](kenna-armis-mapping.pdf) to understand which fields gets synced through this connector.
