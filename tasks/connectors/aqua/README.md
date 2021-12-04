# Aqua 128iid Task to Kenna.VM

## This Task will use the Aqua API to

- Get a list of vulnerabilities currently present in the user's Aqua account
- Get a list of Workloads in the user's Aqua account associated with foreach Vulnerability
- Output a json file in the Kenna Data Importer (KDI) format.
- Post the file to Kenna if API Key and Connector ID are provided

## Things you will need

- Aqua Username (Required)
- Aqua Password (Required)
- Aqua Console Address (Required)
- Kenna API Host (Optional but needed for automatic upload to Kenna)
- Kenna API Key (Optional but needed for automatic upload to Kenna)
- Kenna Connector ID (Optional but needed for automatic upload to Kenna)

Running the Task:

- Create a User in Aqua Console for this task.
- Retrieve the Kenna API Key from the Kenna UI.
  - From the Gear icon (Upper right corner) select API Keys
  - Copy the key using the copy button to the left of the obscured key
- Retrieve the Kenna Connector ID
  - If not already created, select the Add Connector button to create a connector of type Kenna Data Importer. Be sure to rename the connector using 'Aqua' in the name.
  - Click on the name of the connector and from the resulting page, copy the Connector ID.

Run the Aqua task following the guidelines on the main [128iid help page](https://github.com/KennaPublicSamples/128iid#calling-a-specific-task) adding options as necessary

## Options

| Name | Type | Required | Description |
| ---- | ---- | ---- | ---- |
| aqua_console | hostname | true | Aqua Console Address |
| aqua_console_port | integer | false | Aqua Console Port |
| aqua_user |user | true | Aqua Username |
| aqua_password | password | true | Aqua Password |
| container_data | boolean | true | Flag to enable Container data |
| batch_pages_count | integer | false | Number of pages from Aqua (500 default) that should be batched to Kenna |
| kenna_api_key | api_key | false | Kenna API Key |
| kenna_api_host | hostname | false | Kenna API Hostname |
| kenna_connector_id | integer | false | If set, we'll try to upload to this connector |
| output_directory | filename | false | Will alter default filename for output. Path is relative to #{$basedir} |


## Example Command Line:

For extracting Image vulnerability data:

    128iid:latest task=aqua aqua_console=xxx aqua_user=xxx aqua_password=xxx container_data=false kenna_connector_id=15xxxx kenna_api_host=api.sandbox.us.denist.dev kenna_api_key=xxx 

For extracting Container vulnerability data in addition to Images:

    128iid:latest task=aqua aqua_console=xxx aqua_user=xxx aqua_password=xxx container_data=true kenna_connector_id=15xxxx kenna_api_host=api.sandbox.us.denist.dev kenna_api_key=xxx 