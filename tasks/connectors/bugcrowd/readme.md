## Running the Bugcrowd task 

This 128iid brings in data from Bugcrowd

To run this task you need the following information from Bugcrowd: 

1. Bugcrowd API username
2. Bugcrowd API password

## Command Line

See the main 128iid for instructions on running tasks. For this task, if you leave off the Kenna API Key and Kenna Connector ID, the task will create a json file in the default or specified output directory. You can review the file before attempting to upload to the Kenna directly.

Recommended Steps: 

1. Run with Bugcrowd Keys only to ensure you are able to get data properly from the scanner
1. Review output for expected data
1. Create Kenna Data Importer connector in Kenna (example name: Bugcrowd KDI) 
1, Manually run the connector with the json from step 1 
1. Click on the name of the connector to get the connector id
1. Run the task with Bugcrowd Keys and Kenna Key/connector id

Complete list of Options:

| Option | Required | Description | default |
| --- | --- | --- | --- |
| bugcrowd_api_user | true | API username | n/a |
| bugcrowd_api_password | true | API password | n/a |
| bugcrowd_api_host | false | "Bugcrowd hostname, e.g. api.bugcrowd.com" | api.bugcrowd.com |
| batch_size | false | Maximum number of issues to retrieve in batches. Max allowed value is 100. | 100 |
| include_duplicated | false | Indicates whether to include duplicated submissions, defaults to false. | false |
| severity | false | Limit results to a list of severity values ranging from 1 to 5 (comma separated). Only a maximum of 4 values are allowed. | n/a |
| state | false | Limit results to a list of [new, out_of_scope, not_applicable, not_reproducible, triaged, unresolved, resolved, informational]. | n/a |
| source | false | Limit results to a list of [api, csv, platform, qualys, external_form, email, jira]. | n/a |
| submitted_from | false | Get results above date. Use YYYY-MM-DD format. | n/a |
| kenna_api_key | false | Kenna API Key for use with connector option | n/a |
| kenna_api_host | false | Kenna API Hostname if not US shared | api.denist.dev |
| kenna_connector_id | false | If set, we'll try to upload to this connector | n/a |
| output_directory | false | If set, will write a file upon completion. Path is relative to #{$basedir} | output/bugcrowd |
