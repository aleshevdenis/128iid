## Running the GitHub Code Scanning task 

This 128iid brings in data from GitHub code scanning alerts.

To run this task you need the following information from GitHub: 

1. GitHub username
2. GitHub token 
3. One or more repository names

**IMPORTANT: you must be an administrator for the repository or organization, and you must use an access token with the repo scope or security_events scope.**

## Command Line

See the main 128iid for instructions on running tasks. For this task, if you leave off the Kenna API Key and Kenna Connector ID, the task will create a json file in the default or specified output directory. You can review the file before attempting to upload to the Kenna directly.

Recommended Steps: 

1. Run with GitHub Keys only to ensure you are able to get data properly from the scanner
1. Review output for expected data
1. Create Kenna Data Importer connector in Kenna (example name: GitHub Code Scanning) 
1. Manually run the connector with the json from step 1 
1. Click on the name of the connector to get the connector id
1. Run the task with GitHub Keys and Kenna Key/connector id

**IMPORTANT: severity and security_severity are POST processing filters and will not reduce the amount of data pulled from GitHub

Complete list of Options:

| Option                   | Required | Description                                                                                                                                                                | default                     |
|--------------------------|----------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------|-----------------------------|
| github_username          | true     | GitHub username                                                                                                                                                            | n/a                         |
| github_token             | true     | GitHub token. You must be an administrator for the repository or organization, and you must use an access token with the repo scope or security_events scope.              | n/a                         |
| github_repositories      | true     | A list of GitHub repository names (comma-separated). This is required if no organizations are specified. Use owner/repo name format, e.g. denistreshchev/128iid            | n/a                         |
| github_tool_name         | false    | The name of a code scanning tool. Only results by this tool will be imported. If not present, ALL will be imported                                                         | n/a                         |
| github_state             | false    | Set to open or resolved to only import secret scanning alerts in a specific state.                                                                                         | n/a                         |
| github_severity          | false    | A list of [error, warning, note] (comma separated). Only secret scanning alerts with one of these severities are imported. If not present, ALL will be imported.           | n/a                         |
| github_security_severity | false    | A list of [critical, high, medium, or low] (comma separated). Only secret scanning alerts with one of these severities are imported. If not present, ALL will be imported. | n/a                         |
| github_page_size         | false    | Maximum number of alerts to retrieve in foreach page. Maximum is 100.                                                                                                         | 100                         |
| kenna_api_key            | false    | Kenna API Key for use with connector option                                                                                                                                | n/a                         |
| kenna_api_host           | false    | Kenna API Hostname if not US shared                                                                                                                                        | api.denist.dev       |
| kenna_connector_id       | false    | If set, we'll try to upload to this connector                                                                                                                              | n/a                         |
| output_directory         | false    | If set, will write a file upon completion. Path is relative to #{$basedir}                                                                                                 | output/github_code_scanning |


## Example Command Line:

For extracting Image vulnerability data:

    task=github_code_scanning github_token=ghp_xxx kenna_connector_id=15xxxx github_username=myuser kenna_api_host=api.denist.dev kenna_api_key=xxx github_repositories=myuser/WebGoat,myuser/juice-shop
