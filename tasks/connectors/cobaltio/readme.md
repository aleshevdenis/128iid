# Cobalt.io 128iid Task to Kenna.VM

## This Task will use the Cobalt.io API to

- [Get a list of Findings](https://docs.cobalt.io/#findings) for the Org.
- Output a json file in the Kenna Data Importer (KDI) format.
- Post the file to Kenna if API Key and Connector ID are provided.

## Things you will need

- Cobalt.io API token & org token (Required)
- Kenna API Key (Optional but needed for automatic upload to Kenna)
- Kenna Connector ID (Optional but needed for automatic upload to Kenna)

Running the Task:

- Retrieve the Cobalt.io API Key from the Cobalt.io UI
  - From Account Dropdown (Upper right corner) select API Token
  - Click "Generate Token" to generate an API token, copy it and store it somewhere safe
- Get the Cobalt.io org token from the Cobalt.io API
  - Make a GET request to `https://api.cobalt.io/orgs` and get the `token` value of the org you want to use
  - See [the Cobalt.io API docs](https://docs.cobalt.io) for details
- Retrieve the Kenna API Key from the Kenna UI
  - From the Gear icon (Upper right corner) select API Keys
  - Copy the key using the copy button to the left of the obscured key
- Retrieve the Kenna Connector ID
  - If not already created, select the Add Connector button to create a connector of type Kenna Data Importer. Be sure to rename the connector using "Cobalt.io" in the name
  - Click on the name of the connector and from the resulting page, copy the Connector ID

Run the Cobalt.io task following the guidelines on the main [128iid help page](https://github.com/KennaPublicSamples/128iid#calling-a-specific-task) adding options as necessary

## Options

| Name | Type | Required | Description |
| ---- | ---- | ---- | ---- |
| cobalt_api_token | api_key | true | Cobalt.io API token |
| cobalt_org_token | string | true | Cobalt.io org token |
| kenna_api_key | api_key | false | Kenna API Key |
| kenna_api_host | hostname | false | Kenna API Hostname |
| kenna_connector_id | integer | false | If set, we'll try to upload to this connector |
| kenna_appsec_module | boolean | false | Controls whether to use the newer Kenna AppSec module, set to `false` if you want to use the VM module |
| output_directory | filename | false | Will alter default filename for output. Path is relative to #{$basedir} |


## Example Command Line:

    128iid:latest task=cobaltio cobalt_api_token=xxx cobalt_org_token=xxx kenna_api_key:xxx kenna_connector_id=xxxxxx
