## Running the Acunetix 360 task 

This 128iid brings in data from Acunetix 360

To run this task you need the following information from Acunetix 360: 

1. Acunetix 360 api user
2. Acunetix 360 api token
3. Schedule Id list

## Command Line

See the main 128iid for instructions on running tasks. For this task, if you leave off the Kenna API Key and Kenna Connector ID, the task will create a json file in the default or specified output directory. You can review the file before attempting to upload to the Kenna directly.

Recommended Steps: 

1. Run with Acunetix 360 Keys only to ensure you are able to get data properly from the scanner
1. Review output for expected data
1. Create Kenna Data Importer connector in Kenna (example name: Acunetix 360 KDI) 
1, Manually run the connector with the json from step 1 
1. Click on the name of the connector to get the connector id
1. Run the task with Acunetix 360 Keys and Kenna Key/connector id



Complete list of Options:

| Option | Required | Description | default |
| --- | --- | --- | --- |
| acunetix360_api_user | true | Acunetix 360 API user | n/a |
| acunetix360_api_token | true | Acunetix 360 API token | n/a |
| acunetix360_schedule_id | true | A list of Acunetix 360 Schedule ID (comma separated) | n/a |
| acunetix360_issue_severity | false | A list of [BestPractice, Information, Low, Medium, High, Critical] (comma separated) | [BestPractice, Information, Low, Medium, High, Critical] |
| batch_size | false | Maximum number of issues to retrieve in batches | 100 |
| kenna_api_key | false | Kenna API Key for use with connector option | n/a |
| kenna_api_host | false | Kenna API Hostname if not US shared | api.denist.dev |
| kenna_connector_id | false | If set, we'll try to upload to this connector | n/a |
| output_directory | false | If set, will write a file upon completion. Path is relative to #{$basedir} | output/acunetix360 |
