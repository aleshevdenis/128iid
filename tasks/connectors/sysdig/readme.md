## Running the Sysdig task

This 128iid brings in data from Sysdig

To run this task you need the following information from Sysdig:

1. Sysdig hostname depending on SaaS region, e.g. us2.app.sysdig.com
1. Sysdig User API token

## Command Line

See the main 128iid for instructions on running tasks. For this task, if you leave off the Kenna API Key and Kenna Connector ID, the task will create a json file in the default or specified output directory. You can review the file before attempting to upload to the Kenna directly.

Recommended Steps:

1. Run with Sysdig Keys only to ensure you are able to get data properly from the scanner
1. Review output for expected data
1. Create Kenna Data Importer connector in Kenna (example name: Sysdig KDI)
1, Manually run the connector with the json from step 1
1. Click on the name of the connector to get the connector id
1. Run the task with Sysdig Keys and Kenna Key/connector id

Complete list of Options:

| Option | Required | Description | default |
| --- | --- | --- | --- |
| sysdig_api_host | true | Sysdig hostname depending on SaaS region, e.g. us2.app.sysdig.com | n/a |
| sysdig_api_token | true | Sysdig User API token | n/a |
| sysdig_severity_mapping | false | Maps Severity name to 0-10 Kenna severity score. The score has effect on non CVE vulnerabilities, e.g. VULNDB | Critical:8,High:7,Medium:5,Low:3,Negligible:0,Unknown:0 |
| sysdig_vuln_severity | false | A comma separated list of severity types to import. Allowed are Critical, High, Medium, Low, Negligible, Unknown. Import all if absent. | n/a |
| sysdig_page_size | false | Maximum number of issues to retrieve in foreach page. | 500 |
| days_back | false | Get results n days back up to today. If absent, retrieves all history. | n/a |
| kenna_api_key | false | Kenna API Key | n/a |
| kenna_api_host | false | Kenna API Hostname | api.denist.dev |
| kenna_connector_id | false | If set, we'll try to upload to this connector | n/a |
| output_directory | false | If set, will write a file upon completion. Path is relative to /Users/scalvo/Dev/128iid | output/sysdig |

