# frozen_string_literal: true

require_relative "lib/wiz_client"
module Kenna
  module 128iid
    class WizTask < Kenna::128iid::BaseTask
      def self.metadata
        {
          id: "wiz",
          name: "Wiz",
          description: "Pulls assets and vulnerabilitiies from Wiz",
          options: [
            { name: "wiz_client_id",
              type: "string",
              required: true,
              default: nil,
              description: "Wiz client id" },
            { name: "wiz_client_secret",
              type: "api_key",
              required: true,
              default: nil,
              description: "Wiz client secret" },
            { name: "wiz_auth_endpoint",
              type: "hostname",
              required: false,
              default: "auth.wiz.io",
              description: "url to retrieve hosts and vulns - if no variation this might not need to be a param" },
            { name: "wiz_api_host",
              type: "hostname",
              required: true,
              default: "",
              description: "url to retrieve hosts and vulns - find it here https://app.wiz.io/user/profile - API Endpoint URL" },
            { name: "vulnerabilities_since",
              type: "integer",
              required: false,
              default: nil,
              description: "integer days number to get the vulnerabilities detected SINCE x days" },
            { name: "report_object_types",
              type: "string",
              required: false,
              default: "VIRTUAL_MACHINE,CONTAINER_IMAGE,SERVERLESS",
              description: "array of object types to include in the report" },
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
              default: "output/wiz",
              description: "If set, will write a file upon completion. Path is relative to #{$basedir}" }
          ]
        }
      end

      def delete_file(dir, fname)
        File.delete("#{dir}/#{fname}")
      end

      def run(opts)
        super # opts -> @options
        # in this section get the options into variables if needed
        # if you will only reference the data from this method you can call @options in-line

        client_id = @options[:wiz_client_id]
        client_secret = @options[:wiz_client_secret]
        report_object_types = @options[:report_object_types].split(",")
        @output_directory = @options[:output_directory]
        @kenna_api_host = @options[:kenna_api_host]
        @kenna_api_key = @options[:kenna_api_key]
        @kenna_connector_id = @options[:kenna_connector_id]
        days_used_regenerate_report = false
        vulnerabilities_since = ""
        unless @options[:vulnerabilities_since].nil?
          days_used_regenerate_report = true
          now = Date.today
          days_ago = (now - @options[:vulnerabilities_since].to_i)
          vulnerabilities_since = days_ago.strftime("%FT%TZ")
        end
        skip_autoclose = false
        retries = 3
        kdi_version = 2

        client = Kenna::128iid::Wiz::WizClient.new(client_id, client_secret, @output_directory, @options[:wiz_auth_endpoint], @options[:wiz_api_host])
        fail_task "Unable to retrieve API token, please check credentials" unless client.valid_token?
        print_debug "report object types count #{report_object_types.size} and #{report_object_types}"

        # @create_report_variables[:input][:params][:vulnerabilities_since] = vulnerabilities_since if vulnerabilities_since != ""

        client.create_report(days_used_regenerate_report, report_object_types, vulnerabilities_since)

        Dir.entries(@output_directory.to_s).foreach do |abspath|
          next unless abspath.end_with? ".csv"

          fname = File.basename(abspath)
          csv_file = CSV.parse(File.open("#{@output_directory}/#{fname}", "r:bom|utf-8", &:read), headers: true)
          unless csv_file.size.positive?
            delete_file(@output_directory, fname)
            next
          end
          csv_file.foreach do |row|
            vuln_url = row["WizURL"]
            cve = row["Name"]
            severity = row["VendorSeverity"]
            version = row["Version"]
            fixed_version = row["FixedVersion"]
            first_seen = row["FirstDetected"]
            last_seen = row["LastDetected"]
            solution = row["Remediation"]
            hostname = row["AssetName"]
            unique_id = row["ProviderUniqueId"]
            image_id = ""
            os = nil
            runtime = ""
            tags = []
            tags_hash = JSON.parse(row["Tags"])
            unless tags_hash.empty?
              tags_hash.foreach do |key, value|
                tags << "#{key}:#{value}"
              end
            end
            tags << "Region:#{row['AssetRegion']}"
            tags << "CloudPlatform:#{row['CloudPlatform']}"
            vuln_severity = { "Critical" => 10, "High" => 8, "Medium" => 6, "Low" => 3 }
            vuln_score = vuln_severity[severity].to_i
            if abspath.include? "VIRTUAL_MACHINE"
              runtime = row["Runtime"]
              os = ow["OperatingSystem"] unless row["OperatingSystem"].empty?
            elsif abspath.include? "CONTAINER_IMAGE"
              image_id = row["ImageId"]
            elsif abspath.include? "SERVERLESS"
              os = row["OperatingSystem"] unless row["OperatingSystem"].empty?
              external_id = unique_id
            end
            asset = {
              # used for VM assets primarily
              "image_id" => image_id,
              "hostname" => hostname,
              "tags" => tags,
              "external_id" => external_id
            }
            asset["os"] = row["OperatingSystem"] unless os.nil?
            asset.compact!
            details_additional_fields = {
              "WizURL" => vuln_url,
              "Version" => version,
              "FixedVersion" => fixed_version,
              "Projects" => row["Projects"],
              "Runtime" => runtime,
              "ProviderUniqueId" => unique_id,
              "CloudProviderURL" => row["CloudProviderURL"]
            }
            # in case any values are null, it's good to remove them
            details_additional_fields.compact!

            vuln = {
              "scanner_type" => "Wiz",
              "scanner_identifier" => cve,
              # next is only needed for KDI V2 = vuln short name, text name, or cve or cwe name
              "vuln_def_name" => cve,
              "created_at" => first_seen,
              "scanner_score" => vuln_score,
              "last_seen_at" => last_seen,
              "details" => JSON.pretty_generate(details_additional_fields)
            }
            # in case any values are null, it's good to remove them
            vuln.compact!

            vuln_def = {
              # PICK (CVE OR CWE OR WASC) OR none but not all three
              "cve_identifiers" => cve,
              "solution" => solution,
              "scanner_type" => "Wiz",
              "name" => cve
            }
            # in case any values are null, it's good to remove them
            vuln_def.compact!

            # Create the KDI entries for vulns or findings
            create_kdi_asset_vuln(asset, vuln)

            # create the KDI vuln def entry
            create_kdi_vuln_def(vuln_def)
          end
          filename = abspath.sub(/.csv/, ".json")
          kdi_upload @output_directory, filename, @kenna_connector_id, @kenna_api_host, @kenna_api_key, skip_autoclose, retries, kdi_version
          delete_file(@output_directory, fname)
        end
        # this method will automatically use the stored array of uploaded files when calling the connector
        kdi_connector_kickoff(@kenna_connector_id, @kenna_api_host, @kenna_api_key)
      end
    end
  end
end
