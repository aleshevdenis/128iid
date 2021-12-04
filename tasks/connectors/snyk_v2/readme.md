# Snyk 128iid Task to Kenna.VM

## This Task will use the Snyk API to

- [Get a list of Orgs](https://snyk.io/api/v1/orgs) to which the user has permission
- [Get a list of Projects](https://snyk.io/api/v1/org/#{org}/projects) using the retrieved Orgs
- [Get a list of Issues](https://snyk.io/api/v1/reporting/issues) for the Projects & Orgs
- Output a json file in the Kenna Data Importer (KDI) format.
- Post the file to Kenna if API Key and Connector ID are provided

## Things you will need

- Snyk API Key (Required)
- Kenna API Key (Optional but needed for automatic upload to Kenna)
- Kenna Connector ID (Optional but needed for automatic upload to Kenna)

Running the Task:

- Retrieve the Snyk API Key from the Synk UI.
  - From Name Dropdown (Upper right corner) select General Settings
  - On the Account Settings tab you will see a section for API Token. Show, create or regenerate a token.
- Retrieve the Kenna API Key from the Kenna UI.
  - From the Gear icon (Upper right corner) select API Keys
  - Copy the key using the copy button to the left of the obscured key
- Retrieve the Kenna Connector ID  
  - If not already created, select the Add Connector button to create a connector of type Kenna Data Importer. Be sure to rename the connector using 'Snyk' in the name.
  - Click on the name of the connector and from the resulting page, copy the Connector ID.

Run the Snyk task following the guidelines on the main [128iid help page](https://github.com/KennaPublicSamples/128iid#calling-a-specific-task) adding options as necessary

## Options

| Name | Type | Required | Description |
| ---- | ---- | ---- | ---- |
| snyk_api_token |api_key | true | Snyk API Token |
| import_type | string | false | What to import, "vulns" or "findings". By default "vulns". |
| kenna_api_key | api_key | false | Kenna API Key |
| kenna_api_host | hostname | false | Kenna API Hostname |
| include_license | boolean | false | retrieve license issues? |
| kenna_connector_id | integer | false | If set, we'll try to upload to this connector |
| output_directory | filename | false | Will alter default filename for output. Path is relative to #{$basedir} |


## Example Command Line:

    128iid:latest task=snyk_v2 snyk_api_token=xxx kenna_connector_id=156xxx kenna_api_key:xxx include_license=true

