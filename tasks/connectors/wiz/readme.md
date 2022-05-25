## Running the WIZ task

This 128iid brings in data from WIZ

To run this task you need the following information from WIZ:

1. WIZ client id
1. WIZ client secret
1. WIZ API Endpoint URL. If schema is included, it should be between double quotes escaped.

## Command Line

See the main 128iid for instructions on running tasks. For this task, if you leave off the Kenna API Key and Kenna Connector ID, the task will create a json file in the default or specified output directory. You can review the file before attempting to upload to the Kenna directly.

Recommended Steps:

1. Run with WIZ Keys only to ensure you are able to get data properly from the scanner
1. Review output for expected data
1. Create Kenna Data Importer connector in Kenna (example name: WIZ KDI)
1. Manually run the connector with the json from step 1
1. Click on the name of the connector to get the connector id
1. Run the task with WIZ Keys and Kenna Key/connector id

Complete list of Options:

| Option | Required | Description | default |
| --- | --- | --- | --- |
| wiz_client_id | true | WIZ client id | n/a |
| wiz_client_secret | true | WIZ client secret | n/a |
| wiz_auth_endpoint | false | WIZ auth endpoint hostname used to get the authorization token. | auth.wiz.io |
| wiz_api_host | true | WIZ API Endpoint URL. If schema is included, it should be between double quotes escaped. | n/a |
| wiz_page_size | false | Maximum number of issues to retrieve in foreach page. | 500 |
| days_back | false | Integer days number to get the vulnerabilities/issues created x days back ago from TODAY. | n/a |
| vuln_object_types | false | Array of object types for VULNS import. Allowed values: VIRTUAL_MACHINE,CONTAINER_IMAGE,SERVERLESS. Import all if not present. | n/a |
| severity | false | Array of severity types for VULNS and ISSUES (ALL) import. Allowed values: CRITICAL,HIGH,MEDIUM,LOW,INFO. Import all if not present. | n/a |
| issue_status | false | Array of issue status for ISSUES import. Allowed values: OPEN,IN_PROGRESS,RESOLVED,REJECTED. Import all if not present. | n/a |
| import_type | false | What to import, ISSUES, VULNS or ALL | ALL |
| issues_external_id_attr | false | For ISSUES, the entitySnapshot attribute used to map Kenna asset's external_id, for instance, `providerId` or `resourceGroupExternalId`. If not present or the value for the passed attribute is not present the provideId attribute value is used. | n/a |
| vulns_external_id_attr | false | For VULNS, the `vulnerableEntity` attribute used to map Kenna asset's external_id, for instance, `id`, `providerUniqueId` or `name`. If not present or the value for the passed attribute is not present the `id` attribute value is used. | n/a |
| issues_hostname_attr | false | For ISSUES, the entitySnapshot attribute used to map Kenna asset's hostname, for instance, `name`, `subscriptionId`, `subscriptionExternalId`, `subscriptionName`, `resourceGroupId`, `resourceGroupExternalId`, `providerId`. If not present or the value for the passed attribute is not present the `name` attribute value is used. | n/a |
| vulns_hostname_attr | false | For VULNS, the `vulnerableEntity` attribute used to map Kenna asset's hostname, for instance, `name`, `providerUniqueId` or `subscriptionExternalId` . If not present or the value for the passed attribute is not present the `name` attribute value is used. | n/a |
| kenna_batch_size | false | Maximum number of vulnerabilities to upload to Kenna in foreach batch. Increasing this value could improve performance. | 1000 |
| kenna_api_key | false | Kenna API Key | n/a |
| kenna_api_host | false | Kenna API Hostname | api.denist.dev |
| kenna_connector_id | false | If set, we'll try to upload to this connector | n/a |
| output_directory | false | If set, will write a file upon completion. Path is relative to 128iid root directory | output/wiz |

