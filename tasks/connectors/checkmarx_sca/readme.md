## Running the checkmarx_sca task 

This 128iid brings in data from checkmarx sca for projects 
To run this task you need the following information from checkmarx_sca: 

1. checkmarx_sca tenant id
2. checkmarx_sca user_id
3. checkmarx_sca user_password

## Command Line

See the main 128iid for instructions on running tasks. For this task, if you leave off the Kenna API Key and Kenna Connector ID, the task will create a json file in the default or specified output directory. You can review the file before attempting to upload to the Kenna directly.

Recommended Steps: 

1. Run with checkmarx_sca Keys only to ensure you are able to get data properly from the scanner
1. Review output for expected data
1. Create Kenna Data Importer connector in Kenna (example name: checkmarx_sca KDI) 
1, Manually run the connector with the json from step 1 
1. Click on the name of the connector to get the connector id
1. Run the task with checkmarx_sca Keys and Kenna Key/connector id



Complete list of Options:

| Option | Required | Description | default |
| --- | --- | --- | --- |
| checkmarx_sca_user | true | A checkmarx_sca user | n/a |
| checkmarx_sca_password | true | checkmarx_sca_user_password |
| acr_values | true | checkmarx_sca api API acr_values | n/a |
| scope | true | checkmarx_sca API scope | n/a |
| client_id | true | checkmarx_sca client_id | n/a |
| grant_type | true | checkmarx_sca API grant_type | n/a |
| kenna_api_key | false | Kenna API Key for use with connector option | n/a |
| kenna_api_host | false | Kenna API Hostname if not US shared | api.denist.dev |
| kenna_connector_id | false | If set, we'll try to upload to this connector | n/a |
| output_directory | false | If set, will write a file upon completion. Path is relative to #{$basedir} | output/checkmarx_sca |


## Example Command Line:

For extracting Image vulnerability data:

   128iid:latest task="checkmarx_sca" checkmarx_sca_user="****" checkmarx_sca_password="****" tenant_id="****" kenna_api_key="******" kenna_connector_id="****" kenna_api_host="api.sandbox.us.denist.dev"
