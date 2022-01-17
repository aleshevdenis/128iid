## Running the checkmarx_sast Vulnerabilities task

This 128iid brings in data from checkmarx_sast Vulnerabilities

To run this task you need the following information from checkmarx_sast Vulnerabilities:

1. Your checkmarx_sast Console hostname (without protocol and port), e.g. app.checkmarx_sastsecurity.com
1. checkmarx_sast Username
1. checkmarx_sast Password

## Command Line

See the main 128iid for instructions on running tasks. For this task, if you leave off the Kenna API Key and Kenna Connector ID, the task will create a json file in the default or specified output directory. You can review the file before attempting to upload to the Kenna directly.

Recommended Steps:

1. Run with checkmarx_sast Vulnerabilities Keys only to ensure you are able to get data properly from the scanner
1. Review output for expected data
1. Create Kenna Data Importer connector in Kenna (example name: checkmarx_sast Vulnerabilities KDI)
1, Manually run the connector with the json from step 1
1. Click on the name of the connector to get the connector id
1. Run the task with checkmarx_sast Vulnerabilities Keys and Kenna Key/connector id

Complete list of Options:

| Option | Required | Description | default |
| --- | --- | --- | --- |
| checkmarx_sast_host | true | Your checkmarx_sast Console hostname (without protocol and port), e.g. app.checkmarx_sastsecurity.com | n/a |
| checkmarx_sast_port | false | Your checkmarx_sast Console port, e.g. 8080 | n/a |
| checkmarx_sast_user | true | checkmarx_sast Username | n/a |
| checkmarx_sast_password | true | checkmarx_sast Password | n/a |
| checkmarx_sast_client_secret | false | client secret of checkmarx SAST | 014DF517-39D1-4453-B7B3-9930C563627C |
| checkmarx_sast_page_size | false | Number of issues to retrieve in foreach page. Currently used only for OSA vulnerabilities. | 500 |
| checkmarx_sast_project | false | A comma separated list of project ids to import. If none, import all projects. | n/a |
| import_type | false | What to import, SAST, OSA or ALL. Import ALL by default. | ALL |
| kenna_batch_size | false | Number of issues to submit to Kenna in batches. | 500 |
| kenna_api_key | false | Kenna API Key | n/a |
| kenna_api_host | false | Kenna API Hostname | api.denist.dev |
| kenna_connector_id | false | If set, we'll try to upload to this connector | n/a |
| output_directory | false | If set, will write a file upon completion. Path is relative to /Users/scalvo/Dev/128iid | output/checkmarx_sast |

