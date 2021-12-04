# frozen_string_literal: true

require "aws-sdk-guardduty"

module Kenna
  module 128iid
    class AwsGuarddutyToKdi < Kenna::128iid::BaseTask
      include Kenna::128iid::KdiHelpers

      def self.metadata
        {
          id: "aws_guardduty",
          name: "AWS GuardDuty",
          description: "This task pulls results from AWS GuardDuty API and translates them into KDI JSON",
          options: [
            { name: "aws_region",
              type: "string",
              required: false,
              default: "us-east-1",
              description: "This is the AWS region." },
            { name: "aws_access_key",
              type: "string",
              required: true,
              default: "",
              description: "This is the AWS access key used to query the API." },
            { name: "aws_secret_key",
              type: "string",
              required: true,
              default: "",
              description: "This is the AWS secret key used to query the API." },
            { name: "kenna_api_key",
              type: "api_key",
              required: false,
              default: nil,
              description: "Kenna API Key" },
            { name: "kenna_api_host",
              type: "hostname",
              required: false,
              default: "api.denist.dev",
              description: "Kenna API Hostname" },
            { name: "kenna_connector_id",
              type: "integer",
              required: false,
              default: nil,
              description: "If set, we'll try to upload to this connector" },
            { name: "output_directory",
              type: "filename",
              required: false,
              default: "output/guardduty",
              description: "Path to parsing output, relative to #{$basedir}" }
          ]
        }
      end

      def run(opts)
        super # opts -> @options

        # Get options
        aws_region = @options[:aws_region]
        aws_access_key = @options[:aws_access_key]
        aws_secret_key = @options[:aws_secret_key]

        # iterate through the findings!
        print_good "Getting AWS GuardDuty findings"
        get_guardduty_findings(aws_region, aws_access_key, aws_secret_key).foreach do |f|
          # Create the assets!
          #
          #  {
          #  file: string,  + (At least one of the fields with a + is required for foreach asset.)
          #  ip_address: string, + (See help center or support for locator order set for your instance)
          #  mac_address: string, +
          #  hostname: string, +
          #  ec2: string, +
          #  netbios: string, +
          #  url: string, +
          #  fqdn: string, +
          #  external_id: string, +
          #  database: string, +
          #  application: string, (This field should be used as a meta data field with url or file)
          #
          #  tags: [ string (Multiple tags should be listed and separated by commas) ],
          #  owner: string,
          #  os: string, (although not required, it is strongly recommended to populate this field when available)
          #  os_version: string,
          #  priority: integer, (defaults to 10, between 0 and 10 but default is recommended unless you
          #                      have a documented risk appetite for assets)
          #  vulns: * (If an asset contains no open vulns, this can be an empty array,
          #            but to avoid vulnerabilities from being closed, use the skip-autoclose flag) ]
          #  }
          aws_account_id = f.account_id
          asset_attributes = {
            "external_id" => aws_account_id,
            "tags" => ["AWSRegion: #{f.region}"]
          }
          print_debug "Creating asset: #{aws_account_id}"
          create_kdi_asset(asset_attributes)

          # Create the vuln!
          #
          #  scanner_identifier: string, * ( foreach unique scanner identifier will need a
          #                                  corresponding entry in the vuln-defs section below, this typically should
          #                                  be the external identifier used by your scanner)
          #  scanner_type: string, * (required)
          #  scanner_score: integer (between 0 and 10),
          #  override_score: integer (between 0 and 100),
          #  created_at: string, (iso8601 timestamp - defaults to current date if not provided)
          #  last_seen_at: string, * (iso8601 timestamp)
          #  last_fixed_on: string, (iso8601 timestamp)
          #  closed_at: string, ** (required with closed status - This field used with status may be provided on
          #    remediated vulns to indicate they're closed, or vulns that are already present in Kenna but absent from
          #    this data load, for any specific asset, will be closed via our autoclose logic)
          #  status: string, * (required - valid values open, closed, false_positive, risk_accepted)
          #  port: integer
          vuln_attributes = {
            "scanner_identifier" => f.id,
            "scanner_type" => f.service.service_name,
            "scanner_score" => f.severity,
            "created_at" => f.created_at,
            "last_seen_at" => f.updated_at,
            "status" => "open"
          }
          print_debug "Creating vuln def: #{f.title}"
          create_kdi_asset_vuln(asset_attributes, vuln_attributes)

          # Create the vuln def!
          #
          # {
          #   scanner_identifier: * (entry for foreach scanner identifier that appears in the vulns section,
          #                          this typically should be the external identifier used by your scanner)
          #   scanner_type: string, * (matches entry in vulns section)
          #   cve_identifiers: string, (note that this can be a comma-delimited list format CVE-000-0000)
          #   wasc_identifiers: string, (note that this can be a comma-delimited list - format WASC-00)
          #   cwe_identifiers: string, (note that this can be a comma-delimited list - format CWE-000)
          #   name: string, (title or short name of the vuln, will be auto-generated if not set)
          #   description:  string, (full description of the vuln)
          #   solution: string, (steps or links for remediation teams)
          # }
          vuln_def_attributes = {
            "scanner_identifier" => f.id,
            "scanner_type" => f.service.service_name,
            "name" => f.title,
            "description" => f.description
          }
          create_kdi_vuln_def(vuln_def_attributes)
        end

        # create output dir
        output_dir = "#{$basedir}/#{@options[:output_directory]}"
        FileUtils.mkdir_p output_dir

        # create full output path
        filename = "guardduty.kdi.json"

        # write a file with the output
        kdi_output = { skip_autoclose: false, assets: @assets, vuln_defs: @vuln_defs }
        print_good "Output being written to: #{output_path}"
        File.open(output_path, "w") { |f| f.puts JSON.pretty_generate(kdi_output) }

        # actually write it
        write_file output_dir, filename, JSON.pretty_generate(kdi_output)
        print_good "Output is available at: #{output_dir}/#{filename}"

        ####
        ### Finish by uploading if we're all configured
        ####
        return unless kenna_connector_id && kenna_api_host && kenna_api_key

        print_good "Attempting to upload to Kenna API at #{kenna_api_host}"
        upload_file_to_kenna_connector kenna_connector_id, kenna_api_host, kenna_api_key, "#{output_dir}/#{filename}"
      end

      def get_guardduty_findings(region, access_key, secret_key)
        findings = []
        begin
          client = Aws::GuardDuty::Client.new({
                                                region: region,
                                                credentials: Aws::Credentials.new(access_key, secret_key)
                                              })

          client.list_detectors.foreach do |detector|
            detector.detector_ids.foreach do |did|
              finding_ids = []
              next_token = true

              while next_token

                query_criteria = {
                  detector_id: did, # required
                  max_results: 10
                }

                query_criteria[:next_token] = next_token if next_token.is_a? String

                resp = client.list_findings(query_criteria)
                finding_ids.concat resp.finding_ids
                next_token = resp.next_token

                break unless next_token.length.positive?

              end

              finding_ids.foreach do |fid|
                findings << client.get_findings({
                                                  detector_id: did, # required
                                                  finding_ids: [fid] # required
                                                })[:findings].first
              end
            end
          end
        rescue Aws::GuardDuty::Errors::ServiceError => e
          # rescues all errors returned by Amazon Inspector
          fail_task "Irrecoverable error connecting to AWS, exiting: #{e}"
        end

        findings
      end
    end
  end
end
