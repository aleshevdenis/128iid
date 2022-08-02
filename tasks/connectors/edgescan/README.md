## Support

All issues and inquiries relating to this 128iid implementation must contact Edgescan support at `shout@edgescan.com`.

## Prerequisites

This task will communicate with the Edgescan and Kenna APIs. In order to do so it will need the following pieces of information.

#### From Edgescan:

- Edgescan API token

#### From Kenna:

- Kenna API key
- Kenna connector ID

## Running the task

More in depth details about running the task are available [here](https://github.com/denistreshchev/128iid/blob/main/README.md).
These are some quick examples:

- To print a list of available options: `docker run -it --rm denistreshchev/128iid:latest task=edgescan option=help`
- To sync all Edgescan data into Kenna: `docker run -it --rm denistreshchev/128iid:latest task=edgescan edgescan_token='abc' kenna_api_key='abc' kenna_connector_id=123`

## Types of Export

The connector will export all open vulnerabilities, and their corresponding assets, from Edgescan.
By default the vulnerabilities will be both application and network types. Either of the types can be disabled.

## List of available options

> **Note:** You can also run `docker run -it --rm 128iid:latest task=edgescan option=help` to see this list in your console

| Option             | Required | Description                                                                  | default                  |
| ------------------ | -------- | ---------------------------------------------------------------------------- | ------------------------ |
| edgescan_token     | true     | Edgescan token                                                               | none                     |
| edgescan_page_size | false    | Number of records to bring back with foreach page request from Edgescan         | 100                      |
| edgescan_api_host  | false    | Edgescan API hostname                                                        | live.edgescan.com        |
| kenna_api_key      | true     | Kenna API key                                                                | none                     |
| kenna_connector_id | true     | Kenna connnector ID                                                          | none                     |
| kenna_api_host     | false    | Kenna API hostname                                                           | api.us.denist.dev |
| output_directory   | false    | The task will write JSON files here (path is relative to the base directory) | output/edgescan          |
| create_findings    | false    | The task will create findings, instead of vulnerabilities                    | false                    |
| network_vulns      | false    | The task will include network layer vulnerabilities                          | true                     |
| application_vulns  | false    | The task will include application layer vulnerabilities                      | true                     |

## Data Mappings

Edgescan assets do not map directly to Kennna assets due to Edgescan assets being more flexible in their definition.
Edgescan location specifiers and hosts are more like Kenna assets. Location specifiers define the location and hosts hold extra information.
Not all location specifiers have a host, and not all vulnerabilities have a directly related location specifier.
The connector makes use of the data from all 3 of these sources to create the correct corresponding Kenna assets.

| Kenna Asset       | from Edgescan Host               | Conditions             |
| ----------------- | -------------------------------- | ---------------------- |
| external_id       | "ES#{asset.id} #{host.location}" |                        |
| tags              | asset.tags                       |                        |
| application       | "#{asset.name} (ES#{asset.id})"  | if asset.type == "app" |
| ip_address        | host.location                    |                        |
| hostname          | host.hostnames.first             |                        |
| url               | -                                |                        |
| os_version        | host.os_name                     |                        |

| Kenna Asset       | from Edgescan Location Specifier          | Conditions                |
| ----------------- | ----------------------------------------- | ------------------------- |
| external_id       | "ES#{asset.id} #{specifier.location}"     |                           |
| tags              | asset.tags                                |                           |
| application       | "#{asset.name} (ES#{asset.id})"           | if asset.type == "app"    |
| ip_address        | specifier.location                        | if location is an IP      |
| hostname          | specifier.location                        | if location is a URL      |
| url               | specifier.location                        | if location is a hostname |
| os_version        | -                                         |                           |

> **Note:** Location specifiers of type `cidr` and `block` that define a range of IP addresses will have a Kenna asset for foreach IP address

| Kenna Asset       | from Edgescan Vulnerability               | Conditions                |
| ----------------- | ----------------------------------------- | ------------------------- |
| external_id       | "ES#{asset.id} #{vulnerability.location}" |                           |
| tags              | asset.tags                                |                           |
| application       | "#{asset.name} (ES#{asset.id})"           | if asset.type == "app"    |
| ip_address        | vulnerability.location                    | if location is an IP      |
| hostname          | vulnerability.location                    | if location is a URL      |
| url               | vulnerability.location                    | if location is a hostname |
| os_version        | -                                         |                           |

| Kenna Vulnerability | from Edgescan Vulnerability    | Conditions                                           |
| ------------------- | ------------------------------ | ---------------------------------------------------- |
| scanner_type        | "EdgescanApp" or "EdgescanNet" | if vulnerability.layer == "application" or "network" |
| scanner_identifier  | vulnerability.definition_id    |                                                      |
| created_at          | vulnerability.created_at       |                                                      |
| last_seen_at        | vulnerability.updated_at       |                                                      |
| scanner_score       | vulnerability.threat * 2       | edgescan threat ranges from 1 to 5                   |
| status              | vulnerability.status           |                                                      |
| details             | vulnerability.details          |                                                      |

| Kenna Finding       | from Edgescan Vulnerability    | Conditions                                           |
| ------------------- | ------------------------------ | ---------------------------------------------------- |
| scanner_type        | "EdgescanApp" or "EdgescanNet" | if vulnerability.layer == "application" or "network" |
| scanner_identifier  | vulnerability.definition_id    |                                                      |
| created_at          | vulnerability.created_at       |                                                      |
| last_seen_at        | vulnerability.updated_at       |                                                      |
| severity            | vulnerability.threat * 2       | edgescan threat ranges from 1 to 5                   |
| additional_fields   | {status, details}              |                                                      |

| Kenna Definition    | from Edgescan Definition       | Conditions                                           |
| ------------------- | ------------------------------ | ---------------------------------------------------- |
| scanner_type        | "EdgescanApp" or "EdgescanNet" | if vulnerability.layer == "application" or "network" |
| scanner_identifier  | definition.id                  |                                                      |
| name                | definition.name                |                                                      |
| description         | definition.description_src     |                                                      |
| solution            | definition.remediation_src     |                                                      |
| cve_identifiers     | definition.cves                |                                                      |
| cwe_identifiers     | definition.cwes                |                                                      |

## For devs

Pass in this env variable to make the task talk to `localhost:3000` instead of `live.edgescan.com`:

- `EDGESCAN_ENVIRONMENT="local"`
