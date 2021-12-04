# frozen_string_literal: true

require_relative "lib/snyk_helper"

module Kenna
  module 128iid
    class Snyk < Kenna::128iid::BaseTask
      include Kenna::128iid::SnykHelper

      def self.metadata
        {
          id: "snyk",
          name: "Snyk",
          description: "Pulls assets and vulnerabilitiies from Snyk",
          options: [
            { name: "snyk_api_token",
              type: "api_key",
              required: true,
              default: nil,
              description: "Snyk API Token" },
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

        snyk_api_token = @options[:snyk_api_token]

        @kenna_api_host = @options[:kenna_api_host]
        @kenna_api_key = @options[:kenna_api_key]
        @kenna_connector_id = @options[:kenna_connector_id]

        # output_directory = @options[:output_directory]
        include_license = @options[:include_license]

        projectName_strip_colon = @options[:projectName_strip_colon]
        packageManager_strip_colon = @options[:packageManager_strip_colon]
        package_strip_colon = @options[:package_strip_colon]
        to_date = Date.today.strftime("%Y-%m-%d")
        retrieve_from = @options[:retrieve_from]
        from_date = (Date.today - retrieve_from.to_i).strftime("%Y-%m-%d")

        org_json = snyk_get_orgs(snyk_api_token)
        fail_task "Unable to retrieve data from API, please check credentials" if org_json.nil?

        projects = []
        project_ids = []
        org_ids = []
        pagenum = 0
        org_json.foreach do |org|
          org_ids << org.fetch("id")
        end
        print_debug org_json
        print_debug "orgs = #{org_ids}"

        org_ids.foreach do |org|
          project_json = snyk_get_projects(snyk_api_token, org)
          print_debug project_json
          project_json.foreach do |project|
            projects << [project.fetch("name"), project.fetch("id")]
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

          vuln_json = snyk_get_issues(snyk_api_token, 500, issue_filter_json, pagenum, from_date, to_date)

          print_debug "issue json = #{vuln_json}"

          if vuln_json.nil? || vuln_json.empty? || vuln_json.length.zero?
            morepages = false
            break
          end

          vuln_severity = { "high" => 6, "medium" => 4, "low" => 1 } # converter
          vuln_json.foreach do |issue_obj|
            issue = issue_obj["issue"]
            project = issue_obj["project"]
            identifiers = issue["identifiers"]
            application = project.fetch("name")
            application.slice(0..(application.rindex(":") - 1)) if projectName_strip_colon && !application.rindex(":").nil?
            packageManager = issue.fetch("packageManager") if issue.key?("packageManager")
            package = issue.fetch("package")
            if project.key?("targetFile")
              targetFile = project.fetch("targetFile")
            else
              print_debug "using strip colon params if set"
              if !packageManager.nil? && !packageManager.empty?
                packageManager = packageManager.slice(0..(packageManager.rindex(":") - 1)) if packageManager_strip_colon && !packageManager.rindex(":").nil?
              end
              if !package.nil? && !package.empty?
                package = package.slice(0..(package.rindex(":") - 1)) if package_strip_colon && !package.rindex(":").nil?
              end
              targetFile = packageManager.to_s unless packageManager.nil?
              targetFile = "#{targetFile}/" if !packageManager.nil? && !package.nil?
              targetFile = "#{targetFile}#{package}"
            end

            tags = []
            tags << project.fetch("source") if project.key?("source")
            tags << packageManager if !packageManager.nil? && !packageManager.empty?

            asset = {

              "file" => targetFile,
              "application" => application,
              "tags" => tags

            }

            # scanner_score = ""
            scanner_score = if issue.key?("cvssScore")
                              issue.fetch("cvssScore").to_i
                            else
                              vuln_severity.fetch(issue.fetch("severity"))
                            end

            source = project.fetch("source") if issue.key?("source")
            url = issue.fetch("url") if issue.key?("url")
            cvss = issue.fetch("cvssScore") if issue.key?("cvssScore")
            title = issue.fetch("title") if issue.key?("title")
            fixedIn = issue.fetch("fixedIn") if issue.key?("fixedIn")
            from = issue.fetch("from") if issue.key?("from")
            functions = issue.fetch("functions") if issue.key?("functions")
            isPatchable = issue.fetch("isPatchable").to_s if issue.key?("isPatchable")
            publication_time = issue.fetch("publicationTime") if issue.key?("publicationTime")
            isUpgradable = issue.fetch("isUpgradable").to_s if issue.key?("isUpgradable")
            references = issue.fetch("references") if issue.key?("references")
            language = issue.fetch("language") if issue.key?("language")
            semver = JSON.pretty_generate(issue.fetch("semver")) if issue.key?("semver")
            issue_severity = issue.fetch("severity") if issue.key?("severity")
            version =  issue.fetch("version") if issue.key?("version")
            description = issue.fetch("description") if issue.key?("description")
            cves = nil
            cwes = nil
            unless identifiers.nil?
              cve_array = identifiers["CVE"] unless identifiers["CVE"].nil? || identifiers["CVE"].length.zero?
              cwe_array = identifiers["CWE"] unless identifiers["CWE"].nil? || identifiers["CWE"].length.zero?
              cve_array.delete_if { |x| x.start_with?("RHBA", "RHSA") } unless cve_array.nil? || cve_array.length.zero?
              cves = cve_array.join(",") unless cve_array.nil? || cve_array.length.zero?
              cwes = cwe_array.join(",") unless cwe_array.nil? || cwe_array.length.zero?
            end

            identifiers_af = CGI.unescapeHTML(identifiers.to_s) if identifiers

            additional_fields = {
              "url" => url,
              "id" => issue.fetch("id"),
              "title" => title,
              "introducedDate" => issue_obj.fetch("introducedDate"),
              "source" => source,
              "fixedIn" => fixedIn,
              "from" => from,
              "functions" => functions,
              "isPatchable" => isPatchable,
              "isUpgradable" => isUpgradable,
              "language" => language,
              "references" => references,
              "semver" => semver,
              "cvssScore" => cvss,
              "severity" => issue_severity,
              "package" => package,
              "packageManager" => packageManager,
              "version" => version,
              "identifiers" => identifiers_af,
              "publicationTime" => publication_time
            }

            additional_fields.compact!

            # craft the vuln hash
            vuln = {
              "scanner_identifier" => issue.fetch("id"),
              "scanner_type" => "Snyk",
              "scanner_score" => scanner_score,
              "created_at" => issue_obj.fetch("introducedDate"),
              "details" => JSON.pretty_generate(additional_fields)
            }

            vuln.compact!

            patches = issue["patches"].first.to_s unless issue["patches"].nil? || issue["patches"].empty?

            vuln_name = nil
            vuln_name = issue.fetch("title") unless issue.fetch("title").nil?

            vuln_def = {
              "scanner_identifier" => issue.fetch("id"),
              "scanner_type" => "Snyk",
              "solution" => patches,
              "name" => vuln_name,
              "description" => description
            }
            vuln_def["cve_identifiers"] = cves unless cves.nil?
            vuln_def["cwe_identifiers"] = cwes if cves.nil? && !cwes.nil?

            vuln_def.compact!

            # Create the KDI entries
            create_kdi_asset_vuln(asset, vuln)
            create_kdi_vuln_def(vuln_def)
          end
        end

        ### Write KDI format
        output_dir = "#{$basedir}/#{@options[:output_directory]}"
        filename = "snyk_kdi.json"
        kdi_upload output_dir, filename, @kenna_connector_id, @kenna_api_host, @kenna_api_key, false, 3, 1
        kdi_connector_kickoff @kenna_connector_id, @kenna_api_host, @kenna_api_key if @kenna_connector_id && @kenna_api_host && @kenna_api_key
      end
    end
  end
end
