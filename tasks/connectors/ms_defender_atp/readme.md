## Running Microsoft Defender ATP task 

This 128iid brings in data from MS Defender ATP (https://securitycenter.windows.com/dashboard)

To run this task you need the following information from Microsoft: 

1. Tenant ID
1. Client ID
1. Client Secret

Start here to learn how to register your app:

>>https://docs.microsoft.com/en-us/azure/active-directory/develop/scenario-web-api-call-api-app-registration

>>https://docs.microsoft.com/en-us/azure/active-directory/develop/quickstart-modify-supported-accounts


Work is done here: https://portal.azure.com/

1. Create APP
1. Generate Secret - **BE SURE TO SAVE IT SOMEWHERE SAFE - YOU WON’T BE ABLE GET IT FROM THE UI AGAIN**
1. Use App Permissions to set access rights for the Application to the MS Defenders ATP API. 
1. View the app Information page to see the Tenant/Directory ID and the Client/Application ID. 


## Command Line

See the main 128iid for instructions on running tasks. For this task, if you leave off the Kenna API Key and Kenna Connector ID, the task will create a json file in the default or specified output directory. You can review the file before attempting to upload to the Kenna directly.

Recommended Steps: 

1. Run with Microsoft Keys only to ensure you are able to get data properly from Defender ATP
1. Review output for expected data
1. Create Kenna Data Importer connector in Kenna (example name: MS Defender Atp KDI) 
1, Manually run the connector with the json from step 1 
1. Click on the name of the connector to get the connector id
1. Run the task with Microsoft Keys and Kenna Key/connector id



Complete list of Options:

| Option | Required | Description | default |
| --- | --- | --- | --- |
| atp_tenant_id | true | MS Defender ATP Tenant ID | n/a |
| atp_client_id | true | MS Defender ATP Client ID | n/a |
| atp_client_secret | true | MS Defender ATP Client Secret | n/a |
| atp_api_host | false | url to retrieve Defender hosts and vulns | https://api.securitycenter.microsoft.com |
| atp_oath_host | false | url for Defender authentication | https://login.windows.net |
| kenna_api_key | false | Kenna API Key for use with connector option | n/a |
| kenna_api_host | false | Kenna API Hostname if not US shared | api.denist.dev |
| kenna_connector_id | false | If set, we'll try to upload to this connector | n/a |
| output_directory | false | If set, will write a file upon completion. Path is relative to #{$basedir} | output/microsoft_atp |
