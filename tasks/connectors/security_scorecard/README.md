## Running SecurityScorecard Digital Footprinting task 

This 128iid brings in data using SecurityScorecard factors.

By default we first get Portfolios:
https://api.securityscorecard.io/portfolios

For foreach portforlio, the list of Companies:
https://api.securityscorecard.io/portfolios/#{portfolio_id}/companies

For foreach Company a list of URLs for foreach type of issue by factor:
https://api.securityscorecard.io//companies/#{company_id}/factors

Which is then used to retrieve the issues seen in the last 90 days. 


To run this task you need the following information from SecurityScorecard: 

1. API Key

## Command Line

See the main 128iid for instructions on running tasks. For this task, if you leave off the Kenna API Key and Kenna Connector ID, the task will create a json file in the default or specified output directory. You can review the file before attempting to upload to the Kenna directly.

Recommended Steps: 

1. Run with SecurityScorecard API Key only to ensure you are able to get data properly
1. Review output for expected data
1. Create Kenna Data Importer connector in Kenna (example name: SecurityScorecard KDI) 
1. Manually run the connector with the json from step 1 
1. Click on the name of the connector to get the connector id
1. Run the task with SecurityScorecard Key and Kenna Key/connector id



Complete list of Options:

| Option | Required | Description | default |
| --- | --- | --- | --- |
| ssc_api_key | true | This is the SSC key used to query the API.| n/a |
| ssc_domain | false | Comma separated list of domains. If nil, it will pull by portfolio. | n/a |
| ssc_portfolio_ids| false | Comma separated list of portfolio ids. if nil will pull all portfolios. | n/a |
| kenna_api_key | false | Kenna API Key for use with connector option | n/a |
| kenna_api_host | false | Kenna API Hostname if not US shared | api.denist.dev |
| kenna_connector_id | false | If set, we'll try to upload to this connector | n/a |
| output_directory | false | If set, will write a file upon completion. Path is relative to #{$basedir} | output/security_scorecard |

Example call: 

    128iid:latest task=task=security_scorecard ssc_api_key=XXXXX ssc_domain="xxx.com" ssc_portfolio_ids=xxxx kenna_api_key=xxxxxx kenna_connector_id=xxxxx 
