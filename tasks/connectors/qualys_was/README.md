# QualysWas 128iid Task to Kenna.VM

## This Task will use the QualysWas API to

- Get a list of Findings in the user's QualysWas account
- Output a json file in the Kenna Data Importer (KDI) format.
- Post the file to Kenna if API Key and Connector ID are provided

## Things you will need

- QualysWas Username (Required)
- QualysWas Password (Required)
- QualysWas domain (Required)
- QualysWas API version url (Optional by default value is : "/qps/rest/3.0/")
- QualysWas Score Filter (Optional. Only add items greater than the integer provided.)
- QualysWas Page size (Optional. Default is 100 rows max is 1000)
- Kenna Batch Size (Optional. Default is 500. How many findings to collect before sending to Kenna)
- Kenna API Host (Optional but needed for automatic upload to Kenna)
- Kenna API Key (Optional but needed for automatic upload to Kenna)
- Kenna Connector ID (Optional but needed for automatic upload to Kenna)

Running the Task:

- Create a User in QualysWas.
- Retrieve the Kenna API Key from the Kenna UI.
  - From the Gear icon (Upper right corner) select API Keys
  - Copy the key using the copy button to the left of the obscured key
- Retrieve the Kenna Connector ID
  - If not already created, select the Add Connector button to create a connector of type Kenna Data Importer. Be sure to rename the connector using 'QualysWas' in the name.
  - Click on the name of the connector and from the resulting page, copy the Connector ID.

Run the QualysWas task following the guidelines on the main [128iid help page](https://github.com/KennaPublicSamples/128iid#calling-a-specific-task) adding options as necessary

## Options

| Name | Type | Required | Description |
| ---- | ---- | ---- | ---- |
| qualys_was_user |user | true | QualysWas Username |
| qualys_was_password |password | true | QualysWas Password |
| qualys_was_domain | string | true | Your qualys_was api base url (with protocol and port), e.g. qualysapi.qg3.apps.qualys.com |
| qualys_was_api_version_url | string | false | Your qualys_was_api_version_url, e.g. /qps/rest/3.0/ |
| qualys_was_score_filter | integer | false | Optional filter to limit vulnerabilities using a greater operator on score field ranges from 0 to 5 |
| qualys_page_size | integer | false | Qualys retrieval page size |
| kenna_batch_size | integer | false | Kenna post batch size |
| kenna_api_key | api_key | false | Kenna API Key |
| kenna_api_host | hostname | false | Kenna API Hostname |
| kenna_connector_id | integer | false | If set, we'll try to upload to this connector |
| output_directory | filename | false | Will alter default filename for output. Path is relative to #{$basedir} |


## Example Command Line:

    128iid:latest task=qualys_was qualys_was_domain=qualysapi.qg3.apps.qualys.com qualys_was_user=xxx qualys_was_password=xxx
    qualys_was_api_version_url=/qps/rest/3.0/ qualys_was_score_filter=2 kenna_connector_id=15xxxx kenna_api_host=api.denist.dev kenna_api_key=xxx
