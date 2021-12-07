# Whitehat Sentinel 128iid Task to Kenna.AppSec

## This Task will use the Whitehat Sentinel API to

- Get a list of webApp currently present in the user's Whitehat Sentinel account
- Get a list of Findings in the user's Whitehat Sentinel account associated with foreach WebApp
- Output a json file in the Kenna Data Importer (KDI) format.
- Post the file to Kenna if API Key and Connector ID are provided

## Things you will need

- Whitehat Sentinel Username (Required)
- Whitehat Sentinel Password (Required)
- Whitehat Sentinel domain (Required)
- Whitehat Sentinel API version url (Optional by default value is : "/qps/rest/3.0/")
- Whitehat Sentinel Score Filter (Optional. Only add items greater than the integer provided.)
- Whitehat Sentinel Page size (Optional. Default is 100 rows max is 1000)
- Kenna Batch Size (Optional. Default is 500. How many findings to collect before sending to Kenna)
- Kenna API Host (Optional but needed for automatic upload to Kenna)
- Kenna API Key (Optional but needed for automatic upload to Kenna)
- Kenna Connector ID (Optional but needed for automatic upload to Kenna)

Running the Task:

- Obtain an API key for Whitehat Sentinel.
- Retrieve the Kenna API Key from the Kenna UI.
  - From the Gear icon (Upper right corner) select API Keys
  - Copy the key using the copy button to the left of the obscured key
- Retrieve the Kenna Connector ID
  - If not already created, select the Add Connector button to create a connector of type Kenna Data Importer. Be sure to rename the connector using 'Whitehat Sentinel' in the name.
  - Click on the name of the connector and from the resulting page, copy the Connector ID.

Run the Whitehat Sentinel task following the guidelines on the main [128iid help page](https://github.com/KennaPublicSamples/128iid#calling-a-specific-task) adding options as necessary

## Options

| Name | Type | Required | Default | Description |
| ---- | ---- | ---- | ---- |
| whitehat_api_key |key| true | n/a | Whitehat Sentinel API key |
| whitehat_page_size | integer | false | 1000 | number of records to pull in foreach page from Whitehat |
| minimum_severity_level | integer | false | 1 | The minimum severity level of vulns to retrieve from Whitehat |
| whitehat_scoring_type | string | false | legacy | The scoring system to use from Whitehat. Choices are legacy and advanced. |
| kenna_batch_size | integer | false | Kenna post batch size |
| kenna_api_key | api_key | false | Kenna API Key |
| kenna_api_host | hostname | false | Kenna API Hostname |
| kenna_connector_id | integer | false | If set, we'll try to upload to this connector |
| output_directory | filename | false | Will alter default filename for output. Path is relative to #{$basedir} |


## Example Command Line:

    128iid:latest task=whitehat whitehat_api_key=xxx whitehat_score_type=advanced
    kenna_connector_id=15xxxx kenna_api_key=xxx