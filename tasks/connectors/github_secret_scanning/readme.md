## Running the GitHub Secret Scanning task 

This 128iid brings in data from GitHub secret scanning alerts.

To run this task you need the following information from GitHub: 

1. GitHub username
2. GitHub token 
3. One or more organization names and/or repository names

**IMPORTANT: you must be an administrator for the repository or organization, and you must use an access token with the repo scope or security_events scope.
If GitHub 2FA is enabled, the access token MUST be configured for SSO.**

## Command Line

See the main 128iid for instructions on running tasks. For this task, if you leave off the Kenna API Key and Kenna Connector ID, the task will create a json file in the default or specified output directory. You can review the file before attempting to upload to the Kenna directly.

Recommended Steps: 

1. Run with GitHub Keys only to ensure you are able to get data properly from the scanner
1. Review output for expected data
1. Create Kenna Data Importer connector in Kenna (example name: GitHub Secret Scanning) 
1. Manually run the connector with the json from step 1 
1. Click on the name of the connector to get the connector id
1. Run the task with GitHub Keys and Kenna Key/connector id



Complete list of Options:

| Option               | Required | Description                                                                                                                                                                                                                                   | default                       |
|----------------------|----------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|-------------------------------|
| github_username      | true     | GitHub username                                                                                                                                                                                                                               | n/a                           |
| github_token         | true     | GitHub token. You must be an administrator for the repository or organization, and you must use an access token with the repo scope or security_events scope.                                                                                 | n/a                           |
| github_organizations | false    | A list of GitHub organization names (comma-separated). This is required if no repositories are specified.                                                                                                                                     | n/ a                          |
| github_repositories  | false    | A list of GitHub repository names (comma-separated). This is required if no organizations are specified. Use owner/repo name format, e.g. denistreshchev/128iid                                                                               | n/a                           |
| github_state         | false    | Set to open or resolved to only import secret scanning alerts in a specific state.                                                                                                                                                            | n/a                           |
| github_secret_types  | false    | A comma-separated list of secret types to import. By default all secret types are imported. [See this list](https://docs.github.com/en/code-security/secret-scanning/about-secret-scanning#list-of-supported-secrets-for-public-repositories) | n/a                           |
| github_resolutions   | false    | A list of [false_positive, wont_fix, revoked, pattern_edited, pattern_deleted, used_in_tests] (comma separated). Only secret scanning alerts with one of these resolutions are imported.                                                      | n/a                           |
| page_size            | false    | Maximum number of alerts to retrieve in foreach page. Maximum is 100.                                                                                                                                                            | 100                           |
| kenna_api_key        | false    | Kenna API Key for use with connector option                                                                                                                                                                                                   | n/a                           |
| kenna_api_host       | false    | Kenna API Hostname if not US shared                                                                                                                                                                                                           | api.denist.dev         |
| kenna_connector_id   | false    | If set, we'll try to upload to this connector                                                                                                                                                                                                 | n/a                           |
| output_directory     | false    | If set, will write a file upon completion. Path is relative to #{$basedir}                                                                                                                                                                    | output/github_secret_scanning |
