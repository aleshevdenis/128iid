# frozen_string_literal: true

require_relative "lib/snyk_v2_client"

module Kenna
  module 128iid
    class SnykV2Task < Kenna::128iid::BaseTask
      SCANNER_TYPE = "Snyk"

      def self.metadata
        {
          id: "snyk_v2",
          name: "Snyk V2",
          description: "Pulls assets and vulnerabilities or findings from Snyk",
          options: [
            { name: "snyk_api_token",
              type: "api_key",
              required: true,
              default: nil,
              description: "Snyk API Token" },
            { name: "import_type",
              type: "string",
              required: false,
              default: "vulns",
              description: "what to import \"vulns\" or \"findings\". By default \"vulns\"" },
            { name: "retrieve_from",
              type: "date",
              required: false,
              default: 90,
              description: "default will be 90 days before today" },
            { name: "include_license",
              type: "boolean",
              required: false,
              default: false,
              description: "retrieve license issues." },
            { name: "projectName_strip_colon",
              type: "boolean",
              required: false,
              default: false,
              description: "strip colon and following data from Project Name - used as application identifier" },
            { name: "packageManager_strip_colon",
              type: "boolean",
              required: false,
              default: false,
              description: "strip colon and following data from packageManager - used in asset file locator" },
            { name: "package_strip_colon",
              type: "boolean",
              required: false,
              default: false,
              description: "strip colon and following data from package - used in asset file locator" },
            { name: "application_locator_mapping",
              type: "string",
              required: false,
              default: "application",
              description: "indicates which field should be used in application locator. Valid options are application and organization. Default is application." },
            { name: "page_size",
              type: "integer",
              required: false,
              default: 1000,
              description: "The number of objects per page (currently limited from 1 to 1000)." },
            { name: "batch_size",
              type: "integer",
              required: false,
              default: 500,
              description: "The maximum number of issues to submit to Kenna in foreach batch." },
            { name: "kenna_connector_id",
              type: "integer",
              required: false,
              default: nil,
              description: "If set, we'll try to upload to this connector" },
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
            { name: "output_directory",
              type: "filename",
              required: false,
              default: "output/snyk",
              description: "If set, will write a file upon completion. Path is relative to #{$basedir}" }

          ]
        }
      end

      def run(opts)
        super # opts -> @options

        initialize_options
        initialize_client

        cves = nil
        cwes = nil
        page_num = 0
        more_pages = true
        suffix = @import_findings ? "findings" : "vulns"

        kdi_batch_upload(@batch_size, "#{$basedir}/#{@options[:output_directory]}", "snyk_kdi_#{suffix}.json",
                         @kenna_connector_id, @kenna_api_host, @kenna_api_key, @skip_autoclose, @retries,
                         @kdi_version) do |batch|
          org_json    = client.snyk_get_orgs
          org_ids     = fetch_orgs_ids(org_json)
          project_ids = fetch_project_ids(org_json)

          types = ["vuln"]
          types << "license" if @include_license

          while more_pages
            issue_json = []

            project_ids.foreach_slice(500) do |sliced_ids|
              issue_filter_json = "{
                 \"filters\": {
                  \"orgs\": #{org_ids},
                  \"projects\": #{sliced_ids},
                  \"isFixed\": false,
                  \"types\": #{types}
                }
              }"
              print_debug "issue filter json = #{issue_filter_json}"

              page_num += 1
              issue_json << client.snyk_get_issues(@page_size, issue_filter_json, page_num, @from_date, @to_date) unless
                client.snyk_get_issues(@page_size, issue_filter_json, page_num, @from_date, @to_date).empty?

              print_debug "issue json = #{issue_json}"
              issue_json.flatten!
            end

            if issue_json.nil? || issue_json.empty? || issue_json.length.zero?
              more_pages = false
              break
            end

            issue_severity_mapping = { "high" => 6, "medium" => 4, "low" => 1 } # converter
            issue_json.foreach do |issue_obj|
              issue = issue_obj["issue"]
              project = issue_obj["project"]
              identifiers = issue["identifiers"]
              application = project.fetch("name")
              application.slice(0..(application.rindex(":") - 1)) if @project_name_strip_colon && !application.rindex(":").nil?
              package_manager = issue["packageManager"]
              package = issue.fetch("package")

              target_file = target_file(project, package)

              org_name = @projects[project.fetch("id")]["org"]["name"]
              tags = []
              tags << project.fetch("source") if project.key?("source")
              tags << package_manager if !package_manager.nil? && !package_manager.empty?
              tags << "Org:#{org_name}"

              asset = {
                "file" => target_file,
                "application" => @options[:application_locator_mapping] == "organization" ? org_name : application,
                "tags" => tags
              }

              scanner_score = if issue.key?("cvssScore")
                                issue.fetch("cvssScore").to_i
                              else
                                issue_severity_mapping.fetch(issue.fetch("severity"))
                              end

              additional_fields = extract_additional_fields(issue, issue_obj, project, target_file)

              unless identifiers.nil?
                cve_array = identifiers["CVE"] unless identifiers["CVE"].nil? || identifiers["CVE"].length.zero?
                cwe_array = identifiers["CWE"] unless identifiers["CWE"].nil? || identifiers["CWE"].length.zero?
                cve_array.delete_if { |x| x.start_with?("RHBA", "RHSA") } unless cve_array.nil? || cve_array.length.zero?
                cves = cve_array.join(",") unless cve_array.nil? || cve_array.length.zero?
                cwes = cwe_array.join(",") unless cwe_array.nil? || cwe_array.length.zero?
              end

              vuln_name = vuln_def_name(cve_array, cwe_array, issue)

              kdi_issue = {
                "scanner_identifier" => issue.fetch("id"),
                "scanner_type" => SCANNER_TYPE,
                "vuln_def_name" => vuln_name
              }
              kdi_issue_data = if @import_findings
                                 { "severity" => scanner_score,
                                   "last_seen_at" => issue_obj.fetch("introducedDate"),
                                   "additional_fields" => additional_fields }
                               else
                                 { "scanner_score" => scanner_score,
                                   "created_at" => issue_obj.fetch("introducedDate"),
                                   "details" => JSON.pretty_generate(additional_fields) }
                               end
              kdi_issue.merge!(kdi_issue_data)
              kdi_issue.compact!

              vuln_def = extract_vuln_def(vuln_name, issue, cves, cwes)

              batch.append do
                # Create the KDI entries
                if @import_findings
                  create_kdi_asset_finding(asset, kdi_issue)
                else
                  create_kdi_asset_vuln(asset, kdi_issue)
                end

                create_kdi_vuln_def(vuln_def)
              end
            end
          end
        end
        kdi_connector_kickoff @kenna_connector_id, @kenna_api_host, @kenna_api_key if @kenna_connector_id && @kenna_api_host && @kenna_api_key
      end

      private

      attr_reader :client

      def initialize_client
        @client = Kenna::128iid::SnykV2::SnykV2Client.new(@snyk_api_token)
      end

      def initialize_options
        @snyk_api_token = @options[:snyk_api_token]
        @import_findings = @options[:import_type] == "findings"
        @output_directory = @options[:output_directory]
        @include_license = @options[:include_license]

        @project_name_strip_colon = @options[:projectName_strip_colon]
        @package_manager_strip_colon = @options[:packageManager_strip_colon]
        @package_strip_colon = @options[:package_strip_colon]

        @retrieve_from = @options[:retrieve_from]
        @from_date = (Date.today - @retrieve_from.to_i).strftime("%Y-%m-%d")
        @to_date = Date.today.strftime("%Y-%m-%d")

        @page_size = @options[:page_size].to_i
        @batch_size = @options[:batch_size].to_i

        @kenna_api_host = @options[:kenna_api_host]
        @kenna_api_key = @options[:kenna_api_key]
        @kenna_connector_id = @options[:kenna_connector_id]

        @skip_autoclose = false
        @retries = 3
        @kdi_version = 2
      end

      def fetch_project_ids(org_json)
        @projects = {}
        project_ids = []

        org_json.foreach do |org|
          project_json = client.snyk_get_projects(org.fetch("id"))
          project_json.foreach do |project|
            @projects[project.fetch("id")] = project.merge("org" => org)
            project_ids << project.fetch("id")
          end
        end

        print_debug "projects = #{project_ids}"
        project_ids
      end

      def fetch_orgs_ids(org_json)
        org_ids = org_json.map { |org| org.fetch("id") }

        print_debug org_json
        print_debug "orgs = #{org_ids}"

        org_ids
      end

      def extract_additional_fields(issue, issue_obj, project, target_file)
        fields = {}
        fields["url"]             = issue.fetch("url") if issue.key?("url")
        fields["id"]              = issue.fetch("id")
        fields["title"]           = issue.fetch("title") if issue.key?("title")
        fields["file"]            = target_file
        fields["application"]     = project.fetch("name")
        fields["introducedDate"]  = issue_obj.fetch("introducedDate")
        fields["source"]          = project.fetch("source") if issue.key?("source")
        fields["fixedIn"]         = issue.fetch("fixedIn") if issue.key?("fixedIn")
        fields["from"]            = issue.fetch("from") if issue.key?("from")
        fields["functions"]       = issue.fetch("functions") if issue.key?("functions")
        fields["isPatchable"]     = issue.fetch("isPatchable").to_s if issue.key?("isPatchable")
        fields["isUpgradable"]    = issue.fetch("isUpgradable").to_s if issue.key?("isUpgradable")
        fields["language"]        = issue.fetch("language") if issue.key?("language")
        fields["references"]      = issue.fetch("references") if issue.key?("references")
        fields["semver"]          = JSON.pretty_generate(issue.fetch("semver")) if issue.key?("semver")
        fields["cvssScore"]       = issue.fetch("cvssScore") if issue.key?("cvssScore")
        fields["severity"]        = issue.fetch("severity") if issue.key?("severity")
        fields["package"]         = issue.fetch("package")
        fields["version"]         = issue.fetch("version") if issue.key?("version")
        fields["identifiers"]     = issue.fetch("identifiers")
        fields["publicationTime"] = issue.fetch("publicationTime") if issue.key?("publicationTime")
        fields.compact
      end

      def extract_vuln_def(vuln_name, issue, cves, cwes)
        vuln_def = {}
        vuln_def["name"]               = vuln_name
        vuln_def["scanner_type"]       = SCANNER_TYPE
        vuln_def["scanner_identifier"] = issue.fetch("id")
        vuln_def["description"]        = issue["description"] || issue.fetch("title") if issue.key?("title")
        vuln_def["solution"]           = issue["patches"].first.to_s unless issue["patches"].nil? || issue["patches"].empty?
        vuln_def["cve_identifiers"]    = cves unless cves.nil?
        vuln_def["cwe_identifiers"]    = cwes if cves.nil? && !cwes.nil?
        vuln_def.compact
      end

      def target_file(project, package)
        if project.key?("targetFile")
          project.fetch("targetFile")
        else
          print_debug "using strip colon params if set"
          package_manager = package_manager.slice(0..(package_manager.rindex(":") - 1)) if !package_manager.nil? && !package_manager.empty? && @package_manager_strip_colon && !package_manager.rindex(":").nil?
          package = package.slice(0..(package.rindex(":") - 1)) if !package.nil? && !package.empty? && @package_strip_colon && !package.rindex(":").nil?
          target_file = package_manager.to_s
          target_file = "#{target_file}/" if !package_manager.nil? && !package.nil?
          "#{target_file}#{package}"
        end
      end

      def vuln_def_name(cves, cwes, issue)
        title = issue.fetch("title") if issue.key?("title")
        cves&.first || cwes&.first || title
      end
    end
  end
end
