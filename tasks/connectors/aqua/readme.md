## Running the Aqua Vulnerabilities task

This 128iid brings in data from Aqua Vulnerabilities

To run this task you need the following information from Aqua Vulnerabilities:

1. Your Aqua Console hostname (without protocol and port), e.g. app.aquasecurity.com
1. Aqua Username
1. Aqua Password
1. Optional filter to limit vulnerabilities using a comma separated list of severities (e.g. CRITICAL,HIGH)

## Command Line

See the main 128iid for instructions on running tasks. For this task, if you leave off the Kenna API Key and Kenna Connector ID, the task will create a json file in the default or specified output directory. You can review the file before attempting to upload to the Kenna directly.

Recommended Steps:

1. Run with Aqua Vulnerabilities Keys only to ensure you are able to get data properly from the scanner
1. Review output for expected data
1. Create Kenna Data Importer connector in Kenna (example name: Aqua Vulnerabilities KDI)
1. Manually run the connector with the json from step 1
1. Click on the name of the connector to get the connector id
1. Run the task with Aqua Vulnerabilities Keys and Kenna Key/connector id

Complete list of Options:

| Option | Required | Description | default |
| --- | --- | --- | --- |
| aqua_console | true | Your Aqua Console hostname (without protocol and port), e.g. app.aquasecurity.com | n/a |
| aqua_console_port | false | Your Aqua Console port, e.g. 8080 | n/a |
| aqua_user | true | Aqua Username | n/a |
| aqua_password | true | Aqua Password | n/a |
| batch_pages_count | false | Number of pages from Aqua (500 default) that should be batched to Kenna | 10 |
| aqua_console_https | false | Use HTTPS? true/false | n/a |
| container_data | true | Optional filter to limit vulnerabilities using a comma separated list of severities (e.g. CRITICAL,HIGH) | false |
| kenna_api_key | false | Kenna API Key | n/a |
| kenna_api_host | false | Kenna API Hostname | api.denist.dev |
| kenna_connector_id | false | If set, we'll try to upload to this connector | n/a |
| output_directory | false | If set, will write a file upon completion. Path is relative to 128iid root directory | output/aqua |
