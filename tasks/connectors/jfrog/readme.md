## Running the JFrog task 

This 128iid brings in data from JFrog

To run this task you need the following information from JFrog: 

1. JFrog api user
2. JFrog api token
3. Schedule Id list

## Command Line

See the main 128iid for instructions on running tasks. For this task, if you leave off the Kenna API Key and Kenna Connector ID, the task will create a json file in the default or specified output directory. You can review the file before attempting to upload to the Kenna directly.

Recommended Steps: 

1. Run with JFrog Keys only to ensure you are able to get data properly from the scanner
1. Review output for expected data
1. Create Kenna Data Importer connector in Kenna (example name: JFrog KDI) 
1. Manually run the connector with the json from step 1 
1. Click on the name of the connector to get the connector id
1. Run the task with JFrog Keys and Kenna Key/connector id



Complete list of Options:

| Option | Required | Description | default |
| --- | --- | --- | --- |
| jfrog_hostname | true | Frog hostname e.g. your-subdomain.jfrog.io or \"https://host.example.com\". (Use escaped quotes if https:// is included.) | n/a |
| jfrog_api_user | true | JFrog API user | n/a |
| jfrog_api_token | true | JFrog API token | n/a |
| jfrog_repository | true | A list of JFrog Repository (comma separated) | n/a |
| jfrog_issue_severity | false | A list of [Low, Medium, High, Critical] (comma separated) | No filtering |
| days_back | false | Get results n days back up to today. Default is one day. | 100 |
| batch_size | false | Maximum number of issues to retrieve in batches | 100 |
| report_timeout | false | Time (in seconds) to wait for JFrog report execution before timing out. Default is 5 minutes. | 300 |
| kenna_api_key | false | Kenna API Key for use with connector option | n/a |
| kenna_api_host | false | Kenna API Hostname if not US shared | api.denist.dev |
| kenna_connector_id | false | If set, we'll try to upload to this connector | n/a |
| output_directory | false | If set, will write a file upon completion. Path is relative to #{$basedir} | output/jfrog |
