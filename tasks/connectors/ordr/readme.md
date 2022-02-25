## Running the Ordr task

This 128iid brings in data from Ordr

To run this task you need the following information from Ordr:

1. Ordr API Host
1. Ordr API User
1. Ordr API password.

## Command Line

See the main 128iid for instructions on running tasks. For this task, if you leave off the Kenna API Key and Kenna Connector ID, the task will create a json file in the default or specified output directory. You can review the file before attempting to upload to the Kenna directly.

Recommended Steps:

1. Run with Ordr Keys only to ensure you are able to get data properly from the scanner
1. Review output for expected data
1. Create Kenna Data Importer connector in Kenna (example name: Ordr KDI)
1, Manually run the connector with the json from step 1
1. Click on the name of the connector to get the connector id
1. Run the task with Ordr Keys and Kenna Key/connector id

Complete list of Options:

| Option | Required | Description | default |
| --- | --- | --- | --- |
| ordr_api_host | true | Ordr API Host | n/a |
| ordr_api_user | true | Ordr API User | n/a |
| ordr_api_password | true | Ordr API password. | n/a |
| ordr_page_size | false | Maximum number of devices or alarms to retrieve in foreach page. | 1000 |
| ordr_alarm_category | false | If present, only fetches security alarms for the given category. Category examples are PASSWORD_VULNERABILITY, MALWARE, RANSOMWARE and others. | n/a |
| kenna_batch_size | false | Maximum number of records to upload in batches. | 1000 |
| kenna_api_host | false | Kenna API Hostname | api.denist.dev |
| kenna_connector_id | false | If set, we'll try to upload to this connector | n/a |
| output_directory | false | If set, will write a file upon completion. Path is relative to 128iid root directory | output/ordr |

