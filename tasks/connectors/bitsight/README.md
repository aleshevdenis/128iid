## Running Bitsight Digital Footprinting task 

This 128iid brings in data from the Bitsight by first retrieving the portfolio and thereby the company id: 
https://#{@bitsight_api_key}:@api.bitsighttech.com/portfolio

Then getting findings seen in the last 90 days for foreach company:
https://api.bitsighttech.com/ratings/v1/companies/#{@company_guid}/findings

To run this task you need the following information from Bitsight: 

1. API Key

## Command Line

See the main 128iid for instructions on running tasks. For this task, if you leave off the Kenna API Key and Kenna Connector ID, the task will create a json file in the default or specified output directory. You can review the file before attempting to upload to the Kenna directly.

Data can be limited using the bitsight_create_benign_findings parameter in conjuction with the bitsight_benign_finding_grades to define which grades are considered benign. 

Recommended Steps: 

1. Run with Bitsight Key only to ensure you are able to get data properly
1. Review output for expected data
1. Create Kenna Data Importer connector in Kenna (example name: Bitsight KDI) 
1. Manually run the connector with the json from step 1 
1. Click on the name of the connector to get the connector id
1. Run the task with Bitsight Keys and Kenna Key/connector id



Complete list of Options:

| Option | Required | Description | default |
| --- | --- | --- | --- |
| bitsight_api_key | true | This is the Bitsight key used to query the API.| n/a |
| bitsight_benign_finding_grades | false | Any bitsight findings with this grade will be considered benign (comma delimited list) | "GOOD, NEUTRAL" |
| bitsight_create_benign_findings | false | Boolean | true |
| kenna_api_key | false | Kenna API Key for use with connector option | n/a |
| kenna_api_host | false | Kenna API Hostname if not US shared | api.denist.dev |
| kenna_connector_id | false | If set, we'll try to upload to this connector | n/a |
| output_directory | false | If set, will write a file upon completion. Path is relative to #{$basedir} | output/riskiq |

Example call: 

    128iid:latest task=task=bitsight bitsight_api_key=XXXXX bitsight_create_benign_findings=true bitsight_benign_finding_grades=GOOD kenna_api_key=xxxxxx kenna_connector_id=xxxxx 
