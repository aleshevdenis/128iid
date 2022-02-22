## Running the Nozomi task 

This 128iid brings in data from Nozomi

To run this task you need the following information from Nozomi: 

1. nozomi_user (User you wish to use for the task)
2. nozomi_password (Password for the above user)
3. nozomi_api_host (Nozomi Hostname)

## Command Line

See the main 128iid for instructions on running tasks. For this task, if you leave off the Kenna API Key and Kenna Connector ID, the task will create a json file in the default or specified output directory. You can review the file before attempting to upload to the Kenna directly.

Recommended Steps: 

1. Run with Nozomi Keys only to ensure you are able to get data properly from the scanner
2. Review output for expected data
3. Create a "Kenna Data Importer" Connector in Kenna (example name: Nozomi KDI) 
4. Manually run the connector with the JSON from Step 1 
5. Review resulting data if successful, or diagnose issue if there is a failure
6. Click on the name of the KDI Connector to get the Connector ID
7. Run the task with Nozomi Information and Kenna Key + Connector id



Complete list of Options:

| Option | Required | Description | default |
| --- | --- | --- | --- |
| nozomi_user | true | Nozomi User account you wish to leverage | --- |
| nozomi_password | true | Password for the above Nozomi User account | --- |
| nozomi_api_host | true | Nozomi instance hostname, e.g. http://nozomi.example.com:8080 . Must escape hostname in command line script, e.g. \\"http://nozomi.example.com:8080\"  | n/a |
| nozomi_page_size | false | Maximum number of items to retrieve in batches | 5000 |
| external_id_key | false | Nozomi field name used to set Kenna Asset ExternalID | --- |
| kenna_api_key | false | Kenna API Key for use with connector option | n/a |
| kenna_api_host | false | Kenna API Hostname if not US shared | api.denist.dev |
| kenna_connector_id | false | If set, we'll try to upload to this connector | n/a |
| output_directory | false | If set, will write a file upon completion. Path is relative to #{$basedir} | output/nozomi |
