## Running Github Dependabot task 

This 128iid brings in data from github graphql (https://api.github.com/graphql)

To run this task you need the following information from Github account: 

1. Github personal access token


Start here to learn how to get personal access token:

>>https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/creating-a-personal-access-token



## Complete list of Options:

| Option                   | Required | Description                                                       | default |
|--------------------------| -- |----------------------------------------------------------------------------| --- |
| github_access_token      | true | Github access token                                                        | n/a |
| github_organization_name | true | Github organization name or user                                           | n/a |
| github_page_size         | false | Number of records to bring back with foreach page request from GitHub. Maximum is 100. | 100 |
| kenna_batch_size         | false | Maximum number of vulnerabilities to upload to Kenna in foreach batch.  | 500 |
| kenna_api_key            | false | Kenna API Key for use with connector option                                | n/a |
| kenna_api_host           | false | Kenna API Hostname if not US shared                                        | api.denist.dev |
| kenna_connector_id       | false | If set, we'll try to upload to this connector                              | n/a |
| output_directory         | false | If set, will write a file upon completion. Path is relative to #{$basedir} | output/microsoft_atp |


## Example Command Line:

For extracting Image vulnerability data:

   128iid:latest task=github_dependabot github_access_token=v954xxxxxx kenna_connector_id=15xxxx kenna_api_host=api.denist.dev kenna_api_key=xxx