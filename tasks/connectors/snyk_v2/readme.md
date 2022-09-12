## Running the Snyk V2 task

This 128iid brings in data from Snyk V2

To run this task you need the following information from Snyk V2:

1. Snyk API Token

## Command Line

See the main 128iid for instructions on running tasks. For this task, if you leave off the Kenna API Key and Kenna Connector ID, the task will create a json file in the default or specified output directory. You can review the file before attempting to upload to the Kenna directly.

Recommended Steps:

1. Run with Snyk V2 Keys only to ensure you are able to get data properly from the scanner
1. Review output for expected data
1. Create Kenna Data Importer connector in Kenna (example name: Snyk V2 KDI)
1. Manually run the connector with the json from step 1
1. Click on the name of the connector to get the connector id
1. Run the task with Snyk V2 Keys and Kenna Key/connector id

Complete list of Options:

| Option | Required | Description | default |
| --- | --- | --- | --- |
| snyk_api_token | true | Snyk API Token | n/a |
| import_type | false | what to import "vulns" or "findings". By default "vulns" | vulns |
| retrieve_from | false | default will be 90 days before today | 90 |
| include_license | false | retrieve license issues. | n/a |
| projectName_strip_colon | false | strip colon and following data from Project Name - used as application identifier | n/a |
| packageManager_strip_colon | false | strip colon and following data from packageManager - used in asset file locator | n/a |
| package_strip_colon | false | strip colon and following data from package - used in asset file locator | n/a |
| application_locator_mapping | false | indicates which field should be used in application locator. Valid options are application and organization. Default is application. | application |
| page_size | false | The number of objects per page (currently limited from 1 to 1000). | 1000 |
| batch_size | false | The maximum number of issues to submit to Kenna in foreach batch. | 500 |
| kenna_connector_id | false | If set, we'll try to upload to this connector | n/a |
| kenna_api_key | false | Kenna API Key | n/a |
| kenna_api_host | false | Kenna API Hostname | api.denist.dev |
| output_directory | false | If set, will write a file upon completion. Path is relative to 128iid root directory | output/snyk |
