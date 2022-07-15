# CSV Converstion to Kenna KDI JSON Format & ingest to Kenna Platform

## This Task will take a CSV (utf-8) file as input and utilize the metafile to map the field for conversion into the Kenna KDI JSON format
## More information on the Kenna KDI can be found at help.denist.dev
## A non-128iid version of the script and sample metafiles can be found at:
   https://github.com/KennaPublicSamples/All_Samples/tree/main/KDI%20Importer

This script will transform csv files into json that can be consumed by the Kenna Data Importer. It also can process assets only if required.


Meta Data file
Sample file for this csv2kdi 128iid task:
  https://github.com/denistreshchev/128iid/blob/main/tasks/utilities/csv2kdi/tk_meta.csv

Notes show fields that are required to be mapped. Column can reference the column name if the source data file has headers or the column index if there are no headers.

Locator column is required and is used to deduplicate data in the script itself. Additional deduplication may occur in Kenna after the upload depend on the set locator preference order.

## Options

- Task Option: csv_in (string): CSV to be converted to KDI JSON
               Required:(false): Default: input.csv
- Task Option: has_header (boolean): Does the input file have a header?
               Required:(false): Default: true
- Task Option: meta_file (string): File to map input to Kenna fields
               Required:(false): Default: meta.csv
- Task Option: skip_autoclose (string): If vuln not in scan, do you want to close vulns?
               Required:(false): Default: false
- Task Option: appsec_findings (string): Field to populate findings appsec model
               Required:(false): Default: false
- Task Option: assets_only (string): Field to indicate assets only - no vulns
               Required:(false): Default: false
- Task Option: domain_suffix (string): Optional domain suffix for hostnames
               Required:(false): Default:
- Task Option: input_directory (string): Where input files are found. Path is relative to /opt/app/128iid/
               Required:(false): Default: input
- Task Option: output_directory (string): If set, will write a file upon completion. Path is relative to /opt/app/128iid/
               Required:(false): Default: output
- Task Option: kenna_api_host (string): Host used for the API endpoint
               Required:(false): Default: api.denist.dev
- Task Option: kenna_connector_id (integer): ID required for connector to ingest file converted
               Required:(false): Default:
- Task Option: kenna_api_key (string): Kenna API code to be used to ingest
               Required:(false): Default:
- Task Option: batch_page_size (integer): Number of assets and their vulns to batch to the connector
               Required:(false): Default: 500
- Task Option: file_cleanup (boolean): Use this parameter to clean up files after upload to Kenna
               Required:(false): Default: false
- Task Option: max_retries (integer): Use this parameter to change retries on connector actions
               Required:(false): Default: 5
- Task Option: precheck (boolean): Use this parameter to check meta file mappings to input csv
               Required:(false): Default: false


Example command to get task help for csv2kdi:
docker run -it --rm 128iid:latest task=csv2kdi:help

Example command
docker run -it --rm  \
     -v ~/input:/opt/app/128iid/input \
	   -v ~/output:/opt/app/128iid/output \
	   128iid:latest task=csv2kdi csv_in=input.csv \
     meta_file=metafile.csv:kenna_connector_id=156373 \
     kenna_api_key=APICODE-KEY

	   ( Note: on -v option: Example above has the ~/input on host and /opt/app/128iid/input resides in the container )
     ( Note - 2: The container will run as the default user starting it so therefore will need perms to write to the mounted output volume or change perms appropriately)

Sample run output:
docker run -it --rm \
 -v ~/input:/opt/app/128iid/input -v ~/output:/opt/app/128iid/output \
 -t 128iid task=csv2kdi csv_in=findings1.csv meta_file=findings1_meta.csv \
 appsec_findings=true kenna_connector_id=156842 kenna_api_key=fsw**********

Running: Kenna::128iid::Csv2kdi
[+] (20201205152645) Setting csv_in to default value: input.csv
[+] (20201205152645) Setting has_header to default value: true
[+] (20201205152645) Setting meta_file to default value: meta.csv
[+] (20201205152645) Setting skip_autoclose to default value: false
[+] (20201205152645) Setting appsec_findings to default value: false
[+] (20201205152645) Setting assets_only to default value: false
[+] (20201205152645) Setting input_directory to default value: input
[+] (20201205152645) Setting output_directory to default value: output
[+] (20201205152645) Setting kenna_api_host to default value: api.denist.dev
[+] (20201205152645) Got option: task: csv2kdi
[+] (20201205152645) Got option: csv_in: findings1.csv
[+] (20201205152645) Got option: meta_file: findings1_meta.csv
[+] (20201205152645) Got option: appsec_findings: true
[+] (20201205152645) Got option: kenna_connector_id: 156842
[+] (20201205152645) Got option: kenna_api_key: f*******nj1
[+] (20201205152645) Got option: has_header: true
[+] (20201205152645) Got option: skip_autoclose: false
[+] (20201205152645) Got option: assets_only: false
[+] (20201205152645) Got option: domain_suffix:
[+] (20201205152645) Got option: input_directory: input
[+] (20201205152645) Got option: output_directory: output
[+] (20201205152645) Got option: kenna_api_host: api.denist.dev
[+] (20201205152645)
[+] (20201205152645) Launching the csv2kdi task!
[+] (20201205152645)
[+] (20201205152658) Output #1 is available at: /opt/app/128iid/output/kdiout156842_1_20201205152656.json
[+] (20201205152658) Attempting to upload to Kenna API
[+] (20201205152658) Kenna API host: api.denist.dev
[+] (20201205152658) Sending request
[+] (20201205152702) Success!
[+] (20201205152950) Done!
[+] (20201205152950) Attempting to ingest staged files by running connector_id 156842 at Kenna API at api.denist.dev
[+] (20201205152950) Attempting to upload to Kenna API
[+] (20201205152950) Kenna API host: api.denist.dev
[+] (20201205152950) Sending request
[+] (20201205152951) Success!
[+] (20201205153011) Kenna Data Importer connector running!
[+] (20201205153032) Kenna Data Importer connector running!
[+] (20201205172509) Done!
