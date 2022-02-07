## Running the Insight AppSec task

This 128iid brings in data from Insight AppSec

To run this task you need the following information from Insight AppSec:

1. Insight AppSec User API key
1. Insight AppSec application name

## Command Line

See the main 128iid for instructions on running tasks. For this task, if you leave off the Kenna API Key and Kenna Connector ID, the task will create a json file in the default or specified output directory. You can review the file before attempting to upload to the Kenna directly.

Recommended Steps:

1. Run with Insight AppSec Keys only to ensure you are able to get data properly from the scanner
1. Review output for expected data
1. Create Kenna Data Importer connector in Kenna (example name: Insight AppSec KDI)
1, Manually run the connector with the json from step 1
1. Click on the name of the connector to get the connector id
1. Run the task with Insight AppSec Keys and Kenna Key/connector id

Complete list of Options:

| Option | Required | Description | default |
| --- | --- | --- | --- |
| insight_appsec_api_key | true | Insight AppSec User API key | n/a |
| insight_appsec_app_name | true | Insight AppSec application name | n/a |
| insight_appsec_issue_severity | false | A list of [SAFE, INFORMATIONAL, LOW, MEDIUM, HIGH] (comma separated) | INFORMATIONAL, LOW, MEDIUM, HIGH |
| page_size | false | The number of objects per page (currently limited from 1 to 100). | 500 |
| batch_size | false | The maximum number of issues to submit to Kenna in foreach batch. | 100 |
| kenna_api_key | false | Kenna API Key | n/a |
| kenna_api_host | false | Kenna API Hostname | api.denist.dev |
| kenna_connector_id | false | If set, we'll try to upload to this connector | n/a |
| output_directory | false | If set, will write a file upon completion. Path is relative to 128iid root directory | output/insight_appsec |

