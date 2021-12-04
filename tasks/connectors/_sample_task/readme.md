## Running the Burp task 

This 128iid brings in data from Portswigger Burp Suite Enterprise Edition

To run this task you need the following information from Burp: 

1. Burp instance hostname
2. Schedule Id list (you can see the ID in the browser's tab when you edit the schedule)
3. User API Token

## Command Line

See the main 128iid for instructions on running tasks. For this task, if you leave off the Kenna API Key and Kenna Connector ID, the task will create a json file in the default or specified output directory. You can review the file before attempting to upload to the Kenna directly.

Recommended Steps: 

1. Run with Burp Keys only to ensure you are able to get data properly from the scanner
1. Review output for expected data
1. Create Kenna Data Importer connector in Kenna (example name: Burp KDI) 
1, Manually run the connector with the json from step 1 
1. Click on the name of the connector to get the connector id
1. Run the task with Burp Keys and Kenna Key/connector id



Complete list of Options:

| Option | Required | Description | default |
| --- | --- | --- | --- |
| burp_api_host | true | Burp instance hostname, e.g. http://burp.example.com:8080 . Must escape hostname in command line script, e.g. \\"http://burp.example.com:8080\"  | n/a |
| burp_schedule_id | true | A list of Burp Schedule ID (comma separated) | n/a |
| burp_issue_severity | false | A list of [info, low, medium, high] (comma separated) | [info, low, medium, high] |
| burp_api_token | true | Burp User API token | n/a |
| batch_size | false | Maximum number of issues to retrieve in batches | 500 |
| kenna_api_key | false | Kenna API Key for use with connector option | n/a |
| kenna_api_host | false | Kenna API Hostname if not US shared | api.denist.dev |
| kenna_connector_id | false | If set, we'll try to upload to this connector | n/a |
| output_directory | false | If set, will write a file upon completion. Path is relative to #{$basedir} | output/burp |
