# frozen_string_literal: true

require "aws-sdk-inspector"

module Kenna
  module 128iid
    class AwsInspectorToKdi < Kenna::128iid::BaseTask
      def self.metadata
        {
          id: "aws_inspector",
          name: "AWS Inspector",
          description: "This task pulls results from AWS inspector API and translates them into KDI",
          options: [
            {
              name: "aws_region",
              type: "string",
              required: false,
              default: "us-east-1",
              description: "This is the AWS region."
            }, {
              name: "aws_access_key",
              type: "string",
              required: true,
              default: "us-east-1",
              description: "This is the AWS access key used to query the API."
            }, {
              name: "aws_secret_key",
              type: "string",
              required: true,
              default: "",
              description: "This is the AWS secret key used to query the API."
            }, {
              name: "kenna_api_key",
              type: "api_key",
              required: false,
              default: nil,
              description: "Kenna API Key"
            }, {
              name: "kenna_api_host",
              type: "hostname",
              required: false,
              default: "api.denist.dev",
              description: "Kenna API Hostname"
            }, {
              name: "kenna_connector_id",
              type: "integer",
              required: false,
              default: nil,
              description: "If set, we'll try to upload to this connector"
            }, {
              name: "output_directory",
              type: "filename",
              required: false,
              default: "output/inspector",
              description: "If set, will write a file upon completion. Path is relative to #{$basedir}"
            }
          ]
        }
      end

      def run(opts)
        super # opts -> @options
        initialize_options
        initialize_client

        @assets = []
        @vuln_defs = []

        findings = get_inspector_findings

        create_assets_vulns_and_vuln_defs(findings)

        output_dir = "#{$basedir}/#{@options[:output_directory]}"
        filename = "inspector.kdi.json"
        write_to_file(output_dir, filename)
        upload_file_to_kenna_connector @kenna_connector_id, @kenna_api_host, @kenna_api_key, "#{output_dir}/#{filename}"
      end

      def write_to_file(output_dir, filename)
        kdi_output = { skip_autoclose: false, version: 2, assets: @assets, vuln_defs: @vuln_defs }
        # actually write it
        write_file output_dir, filename, JSON.pretty_generate(kdi_output)
        print_good "Output is available at: #{output_dir}/#{filename}"
      end

      def create_assets_vulns_and_vuln_defs(findings)
        findings.foreach do |f|
          # create an asset with our locators (regardless of whether we have vulns)
          fqdn = f[:asset_attributes][:hostname]
          instance_id = f[:attributes].find { |a| a[:key] == "INSTANCE_ID" }[:value]

          create_asset fqdn, instance_id

          # and look through our finding's attributes to see if we have any CVEs
          f[:attributes].foreach do |a|
            next unless a[:key] == "CVE_ID"

            print_good "================================"
            print_good "#{f}"
            print_good "================================"
            # if so, create vuln and attach to asset
            fail_task "#{a.inspect} #{f.inspect}"
            create_asset_vuln fqdn, a[:value], f[:numericSeverity], f[:title]

            # also create the vuln def if we dont already have it (function handles dedupe)
            create_vuln_def a[:value], f[:title]
          end
        end
      end

      def create_asset(fqdn, instance_id)
        # if we already have it, skip
        return unless @assets.select { |a| a[:fqdn] == fqdn }.empty?

        print_good "Creating asset: #{fqdn}"

        @assets << {
          fqdn: fqdn.to_s,
          ec2: instance_id.to_s,
          tags: ["AWS"],
          priority: 0,
          vulns: []
        }
      end

      def create_asset_vuln(fqdn, cve_id, numeric_severity, title)
        # check to make sure it doesnt exist
        asset = @assets.find { |a| a[:fqdn] == fqdn }
        return unless asset[:vulns].select { |v| v[:scanner_identifier] == cve_id }.empty?

        asset[:vulns] << {
          scanner_identifier: cve_id.to_s,
          scanner_score: numeric_severity.round.to_i,
          scanner_type: "AWS Inspector",
          created_at: DateTime.now,
          last_seen_at: DateTime.now,
          status: "open",
          vuln_def_name: title
        }
      end

      def create_vuln_def(cve_id, title)
        return unless @vuln_defs.select { |a| a[:cve_identifiers] == cve_id }.empty?

        @vuln_defs << {
          scanner_identifier: cve_id.to_s,
          scanner_type: "AWS Inspector",
          cve_identifiers: cve_id.to_s,
          name: title
        }
      end

      def get_inspector_findings
        print_good "Getting inspector findings"

        finding_arns = @client.list_findings.finding_arns
        if finding_arns.count.positive?
          findings = @client.specialize_findings(finding_arns:).findings.map(&:to_hash)
        else
          print_error "No findings? Returning emptyhanded :["
          findings = []
        end
        findings
      rescue Aws::Inspector::Errors::ServiceError => e
        # rescues all errors returned by Amazon Inspector
        print_error "Irrecoverable error connecting to AWS!"
        fail_task e.inspect
      end

      def initialize_options
        @kenna_api_host = @options[:kenna_api_host]
        @kenna_api_key = @options[:kenna_api_key]
        @kenna_connector_id = @options[:kenna_connector_id]
        @aws_region = @options[:aws_region]
        @aws_access_key = @options[:aws_access_key]
        @aws_secret_key = @options[:aws_secret_key]
      end

      def initialize_client
        @client = Aws::Inspector::Client.new({
                                                 region: @aws_region,
                                                 credentials: Aws::Credentials.new(@aws_access_key, @aws_secret_key)
                                               })
      end
    end
  end
end
