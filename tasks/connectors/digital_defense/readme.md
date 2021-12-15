## Running the Digital Defense task

This 128iid brings in data from Frontline Digital Defense

To run this task you need the following information from Digital Defense:

1. Frontline instance hostname
2. API Token

## Command Line

See the main 128iid for instructions on running tasks. For this task, if you leave off the Kenna API Key and Kenna Connector ID, the task will create a json file in the default or specified output directory. You can review the file before attempting to upload to the Kenna directly.

Recommended Steps:

1. Run with Digital Defense Keys only to ensure you are able to get data properly from the scanner
1. Review output for expected data
1. Create Kenna Data Importer connector in Kenna (example name: Digital Defense KDI)
1, Manually run the connector with the json from step 1
1. Click on the name of the connector to get the connector id
1. Run the task with Digital Defense Keys and Kenna Key/connector id



Complete list of Options:

| Option | Required | Description | default |
| --- | --- | --- | --- |
| digital_defense_api_host | true | Digital Defense instance hostname, e.g. vm.tryfrontline.cloud . Must escape hostname in command line script, e.g. \\"vm.tryfrontline.cloud"  | n/a |
| digital_defense_api_token | true | Digital Defense API token | n/a |
| batch_size | false | Maximum number of issues to retrieve in batches | 500 |
| kenna_api_key | false | Kenna API Key for use with connector option | n/a |
| kenna_api_host | false | Kenna API Hostname if not US shared | api.denist.dev |
| kenna_connector_id | false | If set, we'll try to upload to this connector | n/a |
| output_directory | false | If set, will write a file upon completion. Path is relative to #{$basedir} | output/digital_defense |
