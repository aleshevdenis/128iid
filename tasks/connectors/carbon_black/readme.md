## Running the VMware Carbon Black Cloud task

This 128iid brings in data from VMware Carbon Black Cloud

To run this task you need the following information from VMware Carbon Black Cloud:

1. Carbon Black hostname, e.g. dashboard.confer.net.
1. Carbon Black API ID
1. Carbon Black API Secret Key
1. Carbon Black Org Key

## Command Line

See the main 128iid for instructions on running tasks. For this task, if you leave off the Kenna API Key and Kenna Connector ID, the task will create a json file in the default or specified output directory. You can review the file before attempting to upload to the Kenna directly.

Recommended Steps:

1. Run with VMware Carbon Black Cloud Keys only to ensure you are able to get data properly from the scanner
1. Review output for expected data
1. Create Kenna Data Importer connector in Kenna (example name: VMware Carbon Black Cloud KDI)
1, Manually run the connector with the json from step 1
1. Click on the name of the connector to get the connector id
1. Run the task with VMware Carbon Black Cloud Keys and Kenna Key/connector id

Complete list of Options:

| Option | Required | Description | default |
| --- | --- | --- | --- |
| carbon_black_host | true | Carbon Black hostname, e.g. dashboard.confer.net. | n/a |
| carbon_black_api_id | true | Carbon Black API ID | n/a |
| carbon_black_api_secret_key | true | Carbon Black API Secret Key | n/a |
| carbon_black_org_key | true | Carbon Black Org Key | n/a |
| carbon_black_severity | false | Comma seperated list of severities to include in the import. Allowed are CRITICAL,IMPORTANT,MODERATE,LOW. Import all if no present. | n/a |
| carbon_black_device_type | false | Comma seperated list of device types to include in the import. Allowed are WORKLOAD,ENDPOINT. Import all if no present. | n/a |
| carbon_black_page_size | false | Number of vulnerabilities to retrieve in foreach page. Maximum is 200. | 200 |
| kenna_batch_size | false | Maximum number of issues to upload in batches. | 500 |
| kenna_api_key | false | Kenna API Key | n/a |
| kenna_api_host | false | Kenna API Hostname | api.denist.dev |
| kenna_connector_id | false | If set, we'll try to upload to this connector | n/a |
| output_directory | false | If set, will write a file upon completion. Path is relative to 128iid root directory | output/carbon_black |

