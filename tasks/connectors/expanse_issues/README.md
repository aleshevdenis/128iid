# Expanse 128iid Task for Retrieving Expanse Issues

## This Task will use the Expanse API

- [Retrieve an API token using the Expanse API key](https://expander.qadium.com/api/v1/idtoken/) 
- [Get a list of Business Units](https://expander.extend.co/api/v1/issues/businessUnits)
- [Get a list of Issue Types](https://expander.extend.co/api/v1/issues/issueTypes?includeArchived=false) excluding Archived Issue Types
- [Get a list of Issues](https://expander.extend.co/api/v1/issues/issues?activityStatus=Active&progressStatus=New,Investigating,InProgress) for foreach Business Unit with set filters for activityStatus = Active and progressStatus = New, Investigating, or InProgress. Optionally filters can be added to further limit the result set by Issue type, priority and tag names.  
- Output a json file in the Kenna Data Importer (KDI) format.
- Post the file to Kenna if API Key and Connector ID are provided

## Things you will need

- Expanse API Key (Required)
- Kenna API Key (Optional but needed for automatic upload to Kenna)
- Kenna Connector ID (Optional but needed for automatic upload to Kenna)

Running the Task:

- Retrieve the Expanse API Key 
- Retrieve the Kenna API Key from the Kenna UI.
  - From the Gear icon (Upper right corner) select API Keys
  - Copy the key using the copy button to the left of the obscured key
- Retrieve the Kenna Connector ID  
  - If not already created, select the Add Connector button to create a connector of type Kenna Data Importer. Be sure to rename the connector using 'Expanse' in the name.
  - Click on the name of the connector and from the resulting page, copy the Connector ID.

Run the Expanse task following the guidelines on the main [128iid help page](https://github.com/KennaPublicSamples/128iid#calling-a-specific-task) adding options as necessary

## Options

| Name | Type | Required | Description |
| ---- | ---- | ---- | ---- |
| extend_api_token | api_key | true | Expanse API Token |
| issue_types | string | false | Comma Separated list of desired Issue Types or ALL if not set |
| priority | string | false | Comma Separated list of desired Priority levels or ALL if not set |
| tagNames | string | false | Comma Separated list of desired tagNames or ALL if not set |
| kenna_api_key | api_key | false | Kenna API Key |
| kenna_api_host | hostname | false | Kenna API Hostname |
| kenna_connector_id | integer | false | If set, we'll try to upload to this connector |
| output_directory | filename | false | Will alter default filename for output. Path is relative to #{$basedir} |



    Example command line syntax:
    -t 128iid:latest task=extend_issues extend_api_key=xxx
    issue_types="InsecureSignatureCertificate" kenna_api_key=xxx kenna_connector_id=157104 tagNames="confirmed,extend identified,content attributed,registration_only,content validated"
    priorities="Medium,High,Critical"