## Running RiskIQ Digital Footprinting task 

This 128iid brings in data from the RiskIQ Global Inventory API endpoint (https://api.riskiq.net/api/globalinventory/)

To run this task you need the following information from RiskIQ: 

1. API Key
1. API Secret


## Command Line

See the main 128iid for instructions on running tasks. For this task, if you leave off the Kenna API Key and Kenna Connector ID, the task will create a json file in the default or specified output directory. You can review the file before attempting to upload to the Kenna directly.

API calls to RiskIQ use the "recent" parameter to limit data. Refer to the Recency section of the API page https://api.riskiq.net/api/globalinventory/ to view the time period used for the different record types. 

All data can be further limited for data updates using the riskiq_pull_incremental flag and riskiq_incremental_time to set the timeframe desired.
Further and distinctly, port data can be limited by using the port_last_seen parameter when riskiq_create_open_ports is true. 

Recommended Steps: 

1. Run with RiskIQ Keys only to ensure you are able to get data properly
1. Review output for expected data
1. Create Kenna Data Importer connector in Kenna (example name: RiskIQ KDI) 
1, Manually run the connector with the json from step 1 
1. Click on the name of the connector to get the connector id
1. Run the task with RiskIQ Keys and Kenna Key/connector id



Complete list of Options:

| Option | Required | Description | default |
| --- | --- | --- | --- |
| riskiq_api_key | true | This is the RiskIQ key used to query the API.| n/a |
| riskiq_api_secret | true | This is the RiskIQ secret used to query the API. | n/a |
| riskiq_create_cves| true | Create vulns for CVEs | n/a |
| riskiq_create_ssl_misconfigs | true | Create vulns for SSL Miconfigurations | n/a |
| riskiq_create_open_ports | true | Create vulns for open ports | n/a |
| riskiq_port_last_seen | true | Limit ports returned with riskiq_create_open ports to n days | n/a |
| riskiq_pull_incremental | false | Boolean for pulling incrementals | false |
| riskiq_incremental_time | false | Use with pull incrementals - Example '14 days ago' | '2 days ago' |
| batch_page_size | false | Number of assets for foreach file load to Kenna | 500 |
| kenna_api_key | false | Kenna API Key for use with connector option | n/a |
| kenna_api_host | false | Kenna API Hostname if not US shared | api.denist.dev |
| kenna_connector_id | false | If set, we'll try to upload to this connector | n/a |
| output_directory | false | If set, will write a file upon completion. Path is relative to #{$basedir} | output/riskiq |

Example call: 

    128iid:latest task=riskiq riskiq_api_key=XXXXX riskiq_api_secret=xxxxx riskiq_create_open_ports=true riskiq_port_last_seen=14 
    riskiq_create_cves=true riskiq_create_ssl_misconfigs=true riskiq_pull_incremental=false riskiq_incremental_time="7 days ago" 
    batch_page_size=1000 kenna_api_key=xxxxxx kenna_connector_id=xxxxx 
