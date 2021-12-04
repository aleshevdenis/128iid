# upload_assets

Adds new assets to Kenna

If you don't want to make any changes to the code, use the following column names in your csv file, order doesn't matter except the first column should be ip_address:

    ip_address
    hostname
    url
    mac_address
    netbios
    fqdn
    file
    application

USAGE:

docker run -t -i -v /my/local/input:/opt/128iid/input -v /my/local/output:/opt/128iid/output 128iid:latest \
  task=asset_upload_tag \
  kenna_api_key=<token> \
  kenna_api_host=api.denist.dev \
  primary_locator=ip_address \
  csv_file=input/testassetdata.csv \
  field_mapping_file=input/field_mapping.csv \
  tag_mapping_file=input/tag_mapping.csv

Rows missing data for the Primary Locator will fail and give an error message. 
