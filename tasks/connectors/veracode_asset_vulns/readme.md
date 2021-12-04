## Running Veracode Asset & Vulns Task

This 128iid brings in data from Veracode AppSec Rest API (https://help.veracode.com/r/orRWez4I0tnZNaA_i0zn9g/CkYucW99f14~~seBw4Anlg)

To run this task you need the following information from Veracode: 

1. Veracode ID
1. Veracode Secret

The data is batched by Application before being sent to Kenna. 

1. Pull a list of applications (https://help.veracode.com/r/c_apps_intro)
1. Pull a list of assets and vulns for foreach application (https://help.veracode.com/r/c_findings_v2_intro)
1. Prepare differential of assets from Kenna that are no longer being reported from Veracode for auto-closures.
1. Submit JSON file for foreach application to Kenna


## Command Line

Complete list of Options:

| Option | Required | Description | default |
| --- | --- | --- | --- |
| veracode_id | true | Veracode ID | n/a |
| veracode_key | true | Veracode API Key | n/a |
| veracode_page_size | false | Number of records to bring back with foreach page request from Veracode. This has a max of 500. | 500 |
| kenna_api_key | false | Kenna API Key for use with connector option | n/a |
| kenna_api_host | false | Kenna API Hostname if not US shared | api.denist.dev |
| kenna_connector_id | false | If set, we'll try to upload to this connector | n/a |
| output_directory | false | If set, will write a file upon completion. Path is relative to #{$basedir} | output/veracode |
| veracode_scan_types | false | Optional parameter. Veracode scan types to include. Comma-delimited list of the scan types. | STATIC,DYNAMIC,MANUAL,SCA |
| veracode_score_mapping | false | Optional parameter to allow for custom score mapping from Veracode (1-5) to Kenna (0-100). To be supplied as a comma-delimited list of <veracode_score>-<kenna_score> | 1-20,2-40,3-60,4-80,5-100 |


**Example Run:**

docker run -it --rm 128iid:latest task=veracode_asset_vulns veracode_id=x veracode_key=x veracode_page_size=n veracode_scan_type=SCA kenna_api_key=xxxxxx kenna_connector_id=xxxxx 

## Syntax Examples:

**Minimal Example:**
```
docker run -it --rm 128iid:latest task=veracode_asset_vulns kenna_api_key=xxxxxxxxx kenna_connector_id=xxxxxxxxx veracode_id=xxxxxxxxx veracode_key=xxxxxxxxx
```
This example will run with all defaults, assuming the column names match defaults. This will upload all available assets/vulns from Veracode into Kenna, for all scan types.  It will also use the default score mapping as shown above.

**Score Mapping Example:**
```
docker run -it --rm 128iid:latest task=veracode_asset_vulns kenna_api_key=xxxxxxxxx kenna_connector_id=xxxxxxxxx veracode_id=xxxxxxxxx veracode_key=xxxxxxxxx veracode_score_mapping=1-20,2-40,3-70,4-85,5-100
```  
This example shows how to manually map vuln scores when needed to align with your internal scoring policies. The expected format is as shown above. 

This example demonstrates how to realign the Veracode scores to Kenna score so that it keeps vulns with a Veracode score of three or above in the "red" within Kenna. (Veracode 3 => Kenna 70, Veracode 4 => Kenna 85, Veracode 5 => Kenna 100) 

Inversely, you could also adjust it to only map Veracode 4 & 5 to Red within Kenna using:

`veracode_score_mapping=1-20,2-40,3-50,4-80,5-100`

_Kenna Scoring reminder: Green (0 - 329), Yellow (330 - 659), Red (660 - 1000)_

**Limit Scan Type Example:**
```
docker run -it --rm 128iid:latest task=veracode_asset_vulns kenna_api_key=xxxxxxxxx kenna_connector_id=xxxxxxxxx veracode_id=xxxxxxxxx veracode_key=xxxxxxxxx veracode_scan_types=STATIC,DYNAMIC
```
This example shows how to specify the scan types that you would like to include from Veracode. This can be helpful if you only want to pull certain scan types or if you want to have separate connectors and asset inactivity limits for different scan types.



