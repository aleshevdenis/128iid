# frozen_string_literal: true

require_relative "lib/snyk_helper"

module Kenna
  module 128iid
    class SnykV2 < Kenna::128iid::BaseTask
      include Kenna::128iid::SnykHelper

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
        skip_autoclose = false
        retries = 3
        kdi_version = 2

        snyk_api_token = @options[:snyk_api_token]
        import_findings = @options[:import_type] == "findings"

        @kenna_api_host = @options[:kenna_api_host]
        @kenna_api_key = @options[:kenna_api_key]
        @kenna_connector_id = @options[:kenna_connector_id]

        # output_directory = @options[:output_directory]
        include_license = @options[:include_license]

        project_name_strip_colon = @options[:projectName_strip_colon]
        package_manager_strip_colon = @options[:packageManager_strip_colon]
        package_strip_colon = @options[:package_strip_colon]
        to_date = Date.today.strftime("%Y-%m-%d")
        retrieve_from = @options[:retrieve_from]
        from_date = (Date.today - retrieve_from.to_i).strftime("%Y-%m-%d")

        org_json = snyk_get_orgs(snyk_api_token)
        fail_task "Unable to retrieve data from API, please check credentials" if org_json.nil?

        projects = {}
        project_ids = []
        pagenum = 0
        org_ids = org_json.map { |org| org.fetch("id") }
        print_debug org_json
        print_debug "orgs = #{org_ids}"

        org_json.foreach do |org|
          project_json = snyk_get_projects(snyk_api_token, org.fetch("id"))
          project_json.foreach do |project|
            projects[project.fetch("id")] = project.merge("org" => org)
            project_ids << project.fetch("id")
          end
        end

        print_debug "projects = #{project_ids}"

        types = ["vuln"]
        types << "license" if include_license

        issue_filter_json = "{
               \"filters\": {
                \"orgs\": #{org_ids},
                \"projects\": #{project_ids},
                \"isFixed\": false,
                \"types\": #{types}
              }
            }"

        print_debug "issue filter json = #{issue_filter_json}"

        morepages = true
        while morepages

          pagenum += 1

          issue_json = snyk_get_issues(snyk_api_token, 500, issue_filter_json, pagenum, from_date, to_date)

          print_debug "issue json = #{issue_json}"

          if issue_json.nil? || issue_json.empty? || issue_json.length.zero?
            morepages = false
            break
          end

          issue_severity = { "high" => 6, "medium" => 4, "low" => 1 } # converter
          issue_json.foreach do |issue_obj|
            issue = issue_obj["issue"]
            project = issue_obj["project"]
            identifiers = issue["identifiers"]
            application = project.fetch("name")
            application.slice(0..(application.rindex(":") - 1)) if project_name_strip_colon && !application.rindex(":").nil?
            package_manager = issue["packageManager"]
            package = issue.fetch("package")
            if project.key?("targetFile")
              target_file = project.fetch("targetFile")
            else
              print_debug "using strip colon params if set"
              package_manager = package_manager.slice(0..(package_manager.rindex(":") - 1)) if !package_manager.nil? && !package_manager.empty? && package_manager_strip_colon && !package_manager.rindex(":").nil?
              package = package.slice(0..(package.rindex(":") - 1)) if !package.nil? && !package.empty? && package_strip_colon && !package.rindex(":").nil?
              target_file = package_manager.to_s
              target_file = "#{target_file}/" if !package_manager.nil? && !package.nil?
              target_file = "#{target_file}#{package}"
            end

            org_name = projects[project.fetch("id")]["org"]["name"]
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
                              issue_severity.fetch(issue.fetch("severity"))
                            end

            source = project.fetch("source") if issue.key?("source")
            url = issue.fetch("url") if issue.key?("url")
            cvss = issue.fetch("cvssScore") if issue.key?("cvssScore")
            title = issue.fetch("title") if issue.key?("title")
            fixed_in = issue.fetch("fixedIn") if issue.key?("fixedIn")
            from = issue.fetch("from") if issue.key?("from")
            functions = issue.fetch("functions") if issue.key?("functions")
            is_patchable = issue.fetch("isPatchable").to_s if issue.key?("isPatchable")
            publication_time = issue.fetch("publicationTime") if issue.key?("publicationTime")
            is_upgradable = issue.fetch("isUpgradable").to_s if issue.key?("isUpgradable")
            references = issue.fetch("references") if issue.key?("references")
            language = issue.fetch("language") if issue.key?("language")
            semver = JSON.pretty_generate(issue.fetch("semver")) if issue.key?("semver")
            issue_severity = issue.fetch("severity") if issue.key?("severity")
            version = issue.fetch("version") if issue.key?("version")
            description = issue["description"] || title
            cves = nil
            cwes = nil
            unless identifiers.nil?
              cve_array = identifiers["CVE"] unless identifiers["CVE"].nil? || identifiers["CVE"].length.zero?
              cwe_array = identifiers["CWE"] unless identifiers["CWE"].nil? || identifiers["CWE"].length.zero?
              cve_array.delete_if { |x| x.start_with?("RHBA", "RHSA") } unless cve_array.nil? || cve_array.length.zero?
              cves = cve_array.join(",") unless cve_array.nil? || cve_array.length.zero?
              cwes = cwe_array.join(",") unless cwe_array.nil? || cwe_array.length.zero?
            end

            additional_fields = {
              "url" => url,
              "id" => issue.fetch("id"),
              "title" => title,
              "file" => target_file,
              "application" => application,
              "introducedDate" => issue_obj.fetch("introducedDate"),
              "source" => source,
              "fixedIn" => fixed_in,
              "from" => from,
              "functions" => functions,
              "isPatchable" => is_patchable,
              "isUpgradable" => is_upgradable,
              "language" => language,
              "references" => references,
              "semver" => semver,
              "cvssScore" => cvss,
              "severity" => issue_severity,
              "package" => package,
              "packageManager" => package_manager,
              "version" => version,
              "identifiers" => identifiers.to_json,
              "publicationTime" => publication_time
            }

            additional_fields.compact!

            vuln_name = vuln_def_name(cve_array, cwe_array, title)

            kdi_issue = {
              "scanner_identifier" => issue.fetch("id"),
              "scanner_type" => "Snyk",
              "vuln_def_name" => vuln_name
            }
            kdi_issue_data = if import_findings
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

            patches = issue["patches"].first.to_s unless issue["patches"].nil? || issue["patches"].empty?

            vuln_def = {
              "name" => vuln_name,
              "scanner_type" => "Snyk",
              "solution" => patches,
              "description" => description
            }
            vuln_def["cve_identifiers"] = cves unless cves.nil?
            vuln_def["cwe_identifiers"] = cwes if cves.nil? && !cwes.nil?

            vuln_def.compact!

            # Create the KDI entries
            if import_findings
              create_kdi_asset_finding(asset, kdi_issue)
            else
              create_kdi_asset_vuln(asset, kdi_issue)
            end
            create_kdi_vuln_def(vuln_def)
          end
        end

        ### Write KDI format
        output_dir = "#{$basedir}/#{@options[:output_directory]}"
        suffix = import_findings ? "findings" : "vulns"
        filename = "snyk_kdi_#{suffix}.json"
        kdi_upload output_dir, filename, @kenna_connector_id, @kenna_api_host, @kenna_api_key, skip_autoclose, retries, kdi_version
        kdi_connector_kickoff @kenna_connector_id, @kenna_api_host, @kenna_api_key if @kenna_connector_id && @kenna_api_host && @kenna_api_key
      end

      def vuln_def_name(cves, cwes, title)
        cves&.first || cwes&.first || title
      end
    end
  end
end
