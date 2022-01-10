# Running Contrast Security Task

This tasks extracts application vulnerability data from the Contrast API and uploads the file to Kenna.

The follow values need to be provided as a minimum to run this task

1. Your Contrast hostname (without protocol), e.g. app.contrastsecurity.com. This can be seen in the address bar when you access the Contrast platform.
1. Your Contrast API Key, as displayed in User Settings.
1. Your Contrast Authorization Header, which can be copied from User Settings.
1. Your Contrast Organization ID, as displayed in User Settings. This should be a GUID.

The data extraction will be limited to applications which are licensed within the Contrast environment.

## Command Line

See the main 128iid for instructions on running tasks. For this task, if you leave off the Kenna API Key and Kenna Connector ID, the task will create a json file in the default or specified output directory. You can review the file before attempting to upload to the Kenna directly.

### Recommended Steps:

1. Run with Contrast credentials only to ensure you are able to get data properly
1. Review output for expected data
1. Create Kenna Data Importer connector in Kenna (example name: Contrast KDI)
1. Manually run the connector with the json from step 1
1. Click on the name of the connector to get the connector id
1. Run the task with Contrast credentials and Kenna Key/connector id

### Example call:

```bash
    docker run -it --rm 128iid:latest \
    task=contrast \
    contrast_host=<your host> \
    contrast_org_id=<your org> \
    contrast_api_key=<your api key> \
    contrast_auth_token=<your auth header> \
    kenna_api_key=<your kenna api key> \
    kenna_connector_id=<your KDI connector id>
```

## Complete list of Options:

| Option | Required | Description | default |
| --- | --- | --- | --- |
| contrast_host | true | Your Contrast hostname (without protocol), e.g. app.contrastsecurity.com | n/a |
| contrast_use_https | false | Set to false if you would like to force an insecure HTTP connection | true |
| contrast_port | false | Your Contrast port (if on premise), e.g. 8080 | null |
| contrast_api_key | true | Your Contrast API Key, as displayed in User Settings | n/a |
| contrast_auth_token | true | Your Contrast Authorization Header, which can be copied from User Settings. | n/a |
| contrast_org_id | true | Your Contrast Organization ID, as displayed in User Settings | n/a |
| contrast_include_vulns | false | Controls whether Contrast Assess vulnerabilities are sent to Kenna | true |
| contrast_exclude_closed_vulns | false | Optional filter to exclude vulnerabilities with a Closed status | false |
| contrast_application_tags | false | Filter vulnerabilities or libraries using a comma separated list of application tags |  |
| contrast_environments | false | Optional filter to only include vulnerabilities from specific environments (e.g. DEVELOPMENT,QA,PRODUCTION). This filter supports multiple comma separated values and all environments will be included if it is omitted. This applies to vulnerabilities only (not libraries).  |  |
| contrast_severities | false | Optional filter to only include vulnerabilities of specific severities (e.g. CRITICAL,HIGH,MEDIUM,LOW,NOTE). This filter supports multiple comma separated values and all severities will be included if it is omitted. This applies to vulnerabilities only (not libraries). |  |
| contrast_include_libs | false | Controls whether Contrast OSS library CVE data is sent to Kenna | false |
| batch_size | false | Maximum number of records to retrieve in batches | 500 |
| kenna_appsec_module | true | Controls whether to use the newer Kenna AppSec module, set to false if you want to use the VM module | true |
| kenna_api_key | true | Your Kenna API key obtained from the Menu > API keys option | n/a |
| kenna_api_host | false | Your Kenna API environment host | api.denist.dev |
| kenna_connector_id | true | The id of the KDI connector you have created in Kenna (displayed when selecting the connector name) | n/a |
| output_directory | false | If set, will write a file upon completion. Path is relative to the 128iid root. | output/contrast |
