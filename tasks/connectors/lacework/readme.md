# Lacework 128iid Task to Kenna.VM

## This Task will use the Lacework API to

- Get a list of CVEs currently present in the user's Lacework account
- Get a list of Hosts in the user's Lacework account associated with foreach CVE
- Output a json file in the Kenna Data Importer (KDI) format.
- Post the file to Kenna if API Key and Connector ID are provided

## Things you will need

- Lacework API Key (Required)
- Lacework API Secret (Required)
- Lacework Account Name (Required)
- Kenna API Key (Optional but needed for automatic upload to Kenna)
- Kenna Connector ID (Optional but needed for automatic upload to Kenna)

Running the Task:

- Retrieve the Lacework API Key and Secret from the Lacework UI.
  - From the Settings menu, create a new API key if none created
  - Download the key file to retrieve the key itself, plus secret
- Retrieve the Kenna API Key from the Kenna UI.
  - From the Gear icon (Upper right corner) select API Keys
  - Copy the key using the copy button to the left of the obscured key
- Retrieve the Kenna Connector ID
  - If not already created, select the Add Connector button to create a connector of type Kenna Data Importer. Be sure to rename the connector using 'Lacework' in the name.
  - Click on the name of the connector and from the resulting page, copy the Connector ID.

Run the Lacework task following the guidelines on the main [128iid help page](https://github.com/KennaPublicSamples/128iid#calling-a-specific-task) adding options as necessary

## Options

| Name | Type | Required | Description |
| ---- | ---- | ---- | ---- |
| lacework_api_token |api_key | true | Lacework API Token |
| lacework_api_secret | string | true | Lacework API Secret |
| lacework_account |string | true | Lacework Account Name |
| kenna_api_key | api_key | false | Kenna API Key |
| kenna_api_host | hostname | false | Kenna API Hostname |
| kenna_connector_id | integer | false | If set, we'll try to upload to this connector |
| output_directory | filename | false | Will alter default filename for output. Path is relative to #{$basedir} |


## Example Command Line:

    128iid:latest task=lacework lacework_api_token=xxx lacework_api_secret=xxx lacework_account=xxx kenna_connector_id=156xxx kenna_api_key:xxx
