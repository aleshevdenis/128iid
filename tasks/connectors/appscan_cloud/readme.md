## Running the AppScan on Cloud task 

This 128iid brings in data from AppScan on Cloud

To run this task you need the following information from AppScan on Cloud: 

1. AppScan on Cloud api Key Id
2. AppScan on Cloud api Key Secret
3. Applications Id list

## Command Line

See the main 128iid for instructions on running tasks. For this task, if you leave off the Kenna API Key and Kenna Connector ID, the task will create a json file in the default or specified output directory. You can review the file before attempting to upload to the Kenna directly.

Recommended Steps: 

1. Run with AppScan on Cloud Keys only to ensure you are able to get data properly from the scanner
1. Review output for expected data
1. Create Kenna Data Importer connector in Kenna (example name: AppScan on Cloud KDI) 
1, Manually run the connector with the json from step 1 
1. Click on the name of the connector to get the connector id
1. Run the task with AppScan on Cloud Keys and Kenna Key/connector id



Complete list of Options:

| Option | Required | Description | default |
| --- | --- | --- | --- |
| appscan_cloud_key_id | true | AppScan on Cloud API Key Id | n/a |
| appscan_cloud_key_secret | true | AppScan on Cloud API Key Secret | n/a |
| appscan_cloud_applications | true | A list of AppScan on Cloud Application ID's (comma separated) | n/a |
| appscan_cloud_severities | false | Filter issues using list of ['Undetermined', 'Informational', 'Low', 'Medium', 'High', 'Critical'] (comma separated) | No filtering |
| page_size | false | Maximum number of issues to retrieve in batches | 100 |
| kenna_api_key | false | Kenna API Key for use with connector option | n/a |
| kenna_api_host | false | Kenna API Hostname if not US shared | api.denist.dev |
| kenna_connector_id | false | If set, we'll try to upload to this connector | n/a |
| output_directory | false | If set, will write a file upon completion. Path is relative to #{$basedir} | output/appscan_cloud |
