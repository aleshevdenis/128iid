## Running the HackerOne task 

This 128iid brings in data from Hackerone

To run this task you need the following information from Hackerone: 

1. Hackerone API username
2. Hackerone API password
3. Hackerone API program

## Command Line

See the main 128iid for instructions on running tasks. For this task, if you leave off the Kenna API Key and Kenna Connector ID, the task will create a json file in the default or specified output directory. You can review the file before attempting to upload to the Kenna directly.

Recommended Steps: 

1. Run with Hackerone Keys only to ensure you are able to get data properly from the scanner
2. Review output for expected data
3. Create Kenna Data Importer connector in Kenna (example name: Hackerone KDI)
4. Manually run the connector with the json from step 1
5. Click on the name of the connector to get the connector id
6. Run the task with Hackerone Keys and Kenna Key/connector id



Complete list of Options:

| Option | Required | Description | default |
| --- | --- | --- | --- |
| hackerone_api_user | true | API username | n/a |
| hackerone_api_password | true | API password | n/a |
| hackerone_program_name | true | "Hackerone API program" | n/a |
| page_size | false | The number of objects per page (currently limited from 1 to 100). | 100 |
| severity | false | A list of severities (comma separated) severity='low,new...'. | nil |
| state | false | A list of states (comma separated) state='new,triaged...' or state=not-resolved. | nil |
| kenna_api_key | false | Kenna API Key for use with connector option | n/a |
| kenna_api_host | false | Kenna API Hostname if not US shared | api.denist.dev |
| kenna_connector_id | false | If set, we'll try to upload to this connector | n/a |
| output_directory | false | If set, will write a file upon completion. Path is relative to #{$basedir} | output/hackerone |
