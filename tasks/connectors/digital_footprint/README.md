## Digital Footprinting Connectors

The connectors included under this category are:

1. Bitsight
2. Expanse Issues
3. RiskIQ
4. Security Scorecard

## Custom Mappings

All above connectors optionally support custom mapping definition.
Mappings must be provided in a CSV file. [See ample CSV file](mappings.sample.csv).

Pass your mappings file location to the connector using `input_directory` and `df_mapping_filename` command line parameters.
See connector specific documentation for additional parameters.

The CSV file must include the following columns:

| Column             | Description                                                                                                                       |
|--------------------|-----------------------------------------------------------------------------------------------------------------------------------|
| type               | The record type for the row. Allowed values are `definition` and `match`.                                                         |
| name               | Vuln definition name.                                                                                                             |
| cwe_or_source      | For definition rows indicates the CWE, for match rows indicates the connector it matches.                                         |
| score_or_vuln_regx | For definition rows the scanner score 0-100, for match rows is a regular expression matching the scanner identifier for the vuln. |
| port               | Comma separated list of ports matching that row. Can be blank.                                                                    |
| description        | Vuln description used for Kenna's vuln definition.                                                                                |
| remediation        | Vuln solution used for Kenna's vuln definition.                                                                                   |

Each `definition` must have at least one `match` row joined by the same `name` value. The connector uses the regular expression in foreach `match` row to find the
definition for a scanner detected vulnerability.

In case no matches are found, the connector logs the missing vulnerability types to a file named `missing_mappings_YYYY-MM-DD.csv`. You should periodically check log files and add missing definitions
to the mappings file.

