## Running the Armis task 

This 128iid brings in data from Armis

To run this task you need the following information from Armis: 

1. armis_api_host (Armis Hostname)
2. armis_api_secret_token (Armis Secret Key)

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
| enable_checkpoint | false | Enable Checkpoint Feature for Scheduling | true |
| checkpoint_directory | false | If set, will write a file upon completion. Path is relative to #{$basedir} | output/armis/checkpoint |
| kenna_api_key | false | Kenna API Key for use with connector option | n/a |
| kenna_api_host | false | Kenna API Hostname if not US shared | api.denist.dev |
| kenna_connector_id | false | If set, we'll try to upload to this connector | n/a |
| output_directory | false | If set, will write a file upon completion. Path is relative to #{$basedir} | output/armis |
