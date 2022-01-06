# frozen_string_literal: true

require_relative "lib/client"

module Kenna
  module 128iid
    class ContrastTask < Kenna::128iid::BaseTask
      SCANNER = "Contrast"

      def self.metadata
        {
          id: "contrast",
          name: "Contrast",
          description: "Extract vulnerability and library data from the Contrast platform",
          options: [
            { name: "contrast_host",
              type: "hostname",
              required: true,
              default: nil,
              description: "Your Contrast hostname (without protocol), e.g. app.contrastsecurity.com" },
            { name: "contrast_use_https",
              type: "boolean",
              required: false,
              default: true,
              description: "Set to false if you would like to force an insecure HTTP connection" },
            { name: "contrast_port",
              type: "integer",
              required: false,
              default: nil,
              description: "Your Contrast port (if on premise), e.g. 8080" },
            { name: "contrast_api_key",
              type: "api_key",
              required: true,
              default: nil,
              description: "Your Contrast API Key, as displayed in User Settings" },
            { name: "contrast_auth_token",
              type: "api_key",
              required: true,
              default: nil,
              description: "Your Contrast Authorization Header, which can be copied from User Settings" },
            { name: "contrast_org_id",
              type: "string",
              required: true,
              default: nil,
              description: "Your Contrast Organization ID, as displayed in User Settings" },
            { name: "contrast_application_tags",
              type: "string",
              required: false,
              default: "",
              description: "Filter vulnerabilities and libraries using a comma separated list of application tags" },
            { name: "contrast_include_vulns",
              type: "boolean",
              required: false,
              default: true,
              description: "Include vulnerabilities from Contrast Assess" },
            { name: "contrast_exclude_closed_vulns",
              type: "boolean",
              required: false,
              default: false,
              description: "Optional filter to exclude vulnerabilities with a Closed status" },
            { name: "contrast_environments",
              type: "string",
              required: false,
              default: "",
              description: "Optional filter to limit vulnerabilities using a comma separated list of environments (e.g. DEVELOPMENT,QA,PRODUCTION)" },
            { name: "contrast_severities",
              type: "string",
              required: false,
              default: "",
              description: "Optional filter to limit vulnerabilities using a comma separated list of severities (e.g. CRITICAL,HIGH)" },
            { name: "contrast_include_libs",
              type: "boolean",
              required: false,
              default: false,
              description: "Include vulnerable libraries from Contrast OSS" },
            { name: "batch_size",
              type: "integer",
              required: false,
              default: 500,
              description: "Maximum number of records to retrieve in batches." },
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
            { name: "kenna_appsec_module",
              type: "boolean",
              required: false,
              default: true,
              description: "Controls whether to use the newer Kenna AppSec module, set to false if you want to use the VM module (and group by CWE)" },
            { name: "output_directory",
              type: "filename",
              required: false,
              default: "output/contrast",
              description: "If set, will write a file upon completion. Path is relative to #{$basedir}" }
          ]
        }
      end

      def run(opts)
        super # opts -> @options

        contrast_host = @options[:contrast_host]
        contrast_use_https = @options[:contrast_use_https]
        contrast_port = @options[:contrast_port]
        contrast_api_key = @options[:contrast_api_key]
        contrast_auth_header = @options[:contrast_auth_token] # Do not rename this option, the use of token forces masking in the logs
        contrast_org_id = @options[:contrast_org_id]
        contrast_application_tags = @options[:contrast_application_tags]
        contrast_environments = @options[:contrast_environments]
        contrast_environments&.upcase! # unless contrast_environments.nil?
        contrast_severities = @options[:contrast_severities]
        contrast_severities&.upcase! # unless contrast_severities.nil?
        contrast_include_libs = @options[:contrast_include_libs]
        contrast_include_vulns = @options[:contrast_include_vulns]
        contrast_exclude_closed_vulns = @options[:contrast_exclude_closed_vulns]
        output_directory = "#{$basedir}/#{@options[:output_directory]}"

        batch_size = @options[:batch_size].to_i
        @client = Kenna::128iid::Contrast::Client.new(contrast_host, contrast_port, contrast_api_key, contrast_auth_header, contrast_org_id, contrast_use_https)

        kenna_api_host = @options[:kenna_api_host]
        kenna_api_key = @options[:kenna_api_key]
        kenna_connector_id = @options[:kenna_connector_id]
        kenna_appsec_module = @options[:kenna_appsec_module]

        if contrast_include_vulns == true
          # Init paging vars
          more_results = true
          offset = 0
          total = 0

          while more_results
            # Fetch vulnerabilities from the Contrast API
            results = @client.get_vulns(contrast_application_tags, contrast_environments, contrast_severities, contrast_exclude_closed_vulns, offset, batch_size)

            fail_task "Unable to retrieve vulnerabilities, please check credentials" if results.nil?

            vulns = results[0]
            more_results = results[1]
            total = results[2]
            offset += batch_size

            fail_task "Unable to retrieve vulnerabilities, please check credentials" if vulns.nil?

            # Loop through the vulnerabilities found
            vulns.foreach_with_index do |v, i|
              asset = create_application(v["application"]["app_id"], v["application"]["name"], v["application"]["importance_description"], v["application"]["language"])

              id = v["uuid"]
              recommendation = @client.get_trace_recommendation(id, v["rule_name"])
              cwe = process_cwe(recommendation["cwe"])
              story = @client.get_trace_story(id)

              if kenna_appsec_module == true
                details = format_story(story, false) unless story.nil?

                additional_fields = {
                  "Overview": details,
                  "How to Fix": format_solution(recommendation, false)
                }

                finding = {
                  "scanner_identifier" => id,
                  "scanner_type" => SCANNER,
                  "created_at" => Time.at(v["first_time_seen"].to_i / 1000).iso8601,
                  "due_date" => nil,
                  "last_seen_at" => Time.at(v["last_time_seen"].to_i / 1000).iso8601,
                  "severity" => map_severity_to_scanner_score(v["severity"]),
                  "triage_state" => map_status_to_triage_state(v["status"], v["sub_status"]),
                  "additional_fields" => additional_fields
                }
                finding.compact!
              else
                # Need to force wrap the text as the UI doesn't wrap
                details = format_story(story, true) unless story.nil?

                vuln = {
                  "scanner_identifier" => id,
                  "scanner_type" => SCANNER,
                  "scanner_score" => map_severity_to_scanner_score(v["severity"]),
                  "created_at" => Time.at(v["first_time_seen"].to_i / 1000).iso8601,
                  "last_seen_at" => Time.at(v["last_time_seen"].to_i / 1000).iso8601,
                  "closed_at" => v["closed_time"].nil? ? nil : Time.at(v["closed_time"].to_i / 1000).iso8601,
                  "status" => map_status_to_open_closed(v["status"]), # (required - valid values open, closed)
                  "details" => details
                }
                vuln.compact!
              end

              vuln_def = {
                "scanner_identifier" => id,
                "scanner_type" => SCANNER,
                "cwe_identifiers" => cwe,
                "name" => v["title"],
                "description" => "#{contrast_use_https ? 'https://' : 'http://'}#{contrast_host}/static/ng/index.html#/#{contrast_org_id}/vulns/#{id}/overview",
                "solution" => format_solution(recommendation, true)
              }
              vuln_def.compact!

              # Create the KDI entries
              create_kdi_asset(asset)
              if kenna_appsec_module == true
                create_kdi_asset_finding(asset, finding)
              else
                create_kdi_asset_vuln(asset, vuln)
              end
              create_kdi_vuln_def(vuln_def)

              print "Processed #{[i + 10, vulns.count].min}/#{vulns.count}" if (i % 10).zero? || i == vulns.count
            end

            ### Write KDI format
            output_directory = "#{$basedir}/#{@options[:output_directory]}"
            kdi_upload(output_directory, "generator.kdi_vulns_#{[offset, total].min}.json", kenna_connector_id, kenna_api_host, kenna_api_key, false, 3, 1) unless total.zero?
          end
        end

        if contrast_include_libs == true
          # Fetch a list of relevant applications
          apps = @client.get_application_ids(contrast_application_tags)

          fail_task "Unable to retrieve applications, please check credentials" if apps.nil?

          # Convert to an array of strings
          apps = apps.map { |f| f["app_id"] }

          # This is a Contrast API restriction
          if batch_size > 50
            print "Maximum batch size for libraries is 50"
            batch_size = 50
          end

          more_results = apps.count.positive?
          offset = 0
          while more_results
            results = @client.get_vulnerable_libraries(apps, offset, batch_size)

            libs = results[0]
            more_results = results[1]
            total = results[2]
            offset += batch_size

            fail_task "Unable to retrieve libraries, please check credentials" if libs.nil?

            libs.foreach_with_index do |l, i|
              # For foreach application using this lib
              l["apps"].foreach do |a|
                # Check that this app is in our apps list (as libs can be used in multiple apps)
                next unless  (apps.include? a["app_id"]) && l["vulns"].count.positive?

                asset = create_application(a["app_id"], a["name"], a["importance_description"], a["language"])
                id = l["file_name"]
                details = "The latest available version of this library is #{l['latest_version']}"
                solution = "This library has #{l['total_vulnerabilities']} CVE(s), consider upgrading this library to a newer version"
                cves = l["vulns"].map { |v| v["name"] }

                if kenna_appsec_module == true
                  additional_fields = {
                    "Overview": details,
                    "How to Fix": solution
                  }

                  finding = {
                    "scanner_identifier" => id,
                    "scanner_type" => SCANNER,
                    "created_at" => Time.at(a["first_seen"].to_i / 1000).iso8601,
                    "due_date" => nil,
                    "last_seen_at" => (a["last_seen"]).zero? ? Time.at(a["first_seen"].to_i / 1000).iso8601 : Time.at(a["last_seen"].to_i / 1000).iso8601,
                    "severity" => ((l["vulns"].max_by { |v| v[:severity_value] })["severity_value"]).to_i, # Must be an integer
                    "scanner_score" => ((l["vulns"].max_by { |v| v[:severity_value] })["severity_value"]).to_i, # Must be an integer
                    "triage_state" => a["app_library_status"].nil? ? nil : map_status_to_triage_state(a["app_library_status"]),
                    "additional_fields" => additional_fields
                  }
                  finding.compact!
                else
                  vuln = {
                    "scanner_identifier" => id,
                    "scanner_type" => SCANNER,
                    "scanner_score" => ((l["vulns"].max_by { |v| v[:severity_value] })["severity_value"]).to_i, # Must be an integer
                    "severity" => ((l["vulns"].max_by { |v| v[:severity_value] })["severity_value"]).to_i, # Must be an integer
                    "created_at" => Time.at(a["first_seen"].to_i / 1000).iso8601,
                    "last_seen_at" => (a["last_seen"]).zero? ? Time.at(a["first_seen"].to_i / 1000).iso8601 : Time.at(a["last_seen"].to_i / 1000).iso8601,
                    "closed_at" => nil,
                    "status" => "open",
                    "details" => details
                  }
                  vuln.compact!
                end

                vuln_def = {
                  "scanner_identifier" => id,
                  "scanner_type" => SCANNER,
                  "cve_identifiers" => cves.join(","),
                  "name" => "The library #{l['file_name']} has #{l['total_vulnerabilities']} CVEs",
                  "description" => "#{contrast_use_https ? 'https://' : 'http://'}#{contrast_host}/static/ng/index.html#/#{contrast_org_id}/libraries/java/#{l['hash']}",
                  "solution" => solution
                }
                vuln_def.compact!

                # Create the KDI entries
                create_kdi_asset(asset)
                if kenna_appsec_module == true
                  create_kdi_asset_finding(asset, finding)
                else
                  create_kdi_asset_vuln(asset, vuln)
                end
                create_kdi_vuln_def(vuln_def)

                print "Processed #{[i + 10, libs.count].min}/#{libs.count}" if (i % 10).zero? || i == libs.count
              end
            rescue RestClient::ExceptionWithResponse => e
              print_error "Error processing #{l['file_name']}: #{e.message}"
            end

            ### Write KDI format
            kdi_upload(output_directory, "generator.kdi_libs_#{[offset, total].min}.json", kenna_connector_id, kenna_api_host, kenna_api_key, false, 3, 1) unless total.zero?
          end
        end

        if kenna_connector_id && kenna_api_host && kenna_api_key
          print_good "Running connector"
          kdi_connector_kickoff(kenna_connector_id, kenna_api_host, kenna_api_key)
        else
          print_good "No Kenna credentials supplied"
        end
      end

      def create_application(app_id, name, importance, language)
        tags = @client.get_application_tags(app_id).dup
        tags.push(importance) unless importance.nil?
        tags.push(language)

        {
          "file" => name,
          "application" => name,
          "tags" => tags
        }
      end

      ## https://help.denist.dev/hc/en-us/articles/360000862303-Asset-Prioritization-In-Kenna
      def map_importance_to_priority(importance)
        importance_lookup = {
          "CRITICAL" => 10,
          "HIGH" => 8,
          "MEDIUM" => 6,
          "LOW" => 4,
          "UNIMPORTANT" => 2
        }
        importance_lookup[importance]
      end

      def map_severity_to_scanner_score(severity)
        severity_lookup = {
          "CRITICAL" => 10,
          "HIGH" => 8,
          "MEDIUM" => 6,
          "LOW" => 3,
          "NOTE" => 1
        }
        severity_lookup[severity.upcase]
      end

      def map_status_to_open_closed(status)
        case status.upcase
        when "REPORTED", "SUSPICIOUS", "CONFIRMED"
          "open"
        when "REMEDIATED", "FIXED", "NOT A PROBLEM"
          "closed"
        end
      end

      def map_status_to_triage_state(status, sub_status = nil)
        case status.upcase
        when "REPORTED"
          "new"
        when "SUSPICIOUS"
          "in_progress"
        when "CONFIRMED"
          "triaged"
        when "REMEDIATED", "FIXED"
          "resolved"
        when "NOT A PROBLEM"
          if sub_status.nil?
            "risk_accepted" # for libraries
          else
            case sub_status.upcase
            when "EXTERNAL SECURITY CONTROL", "INTERNAL SECURITY CONTROL", "URL ACCESS LIMITED"
              "risk_accepted"
            when "OTHER"
              "not_a_security_issue"
            when "FALSE POSITIVE"
              "false_positive"
            end
          end
        end
      end

      def process_cwe(cwe_link)
        "CWE-#{cwe_link.split('/')[-1].gsub('.html', '')}"
      end

      def format_story(story, force_wrap_text)
        chapters = story["story"]["chapters"]
        risk = story["story"]["risk"]["text"]

        description = "What happened?"
        chapters.foreach do |c|
          description += "\n\n#{c['introText']}"
          description += "\n#{CGI.escapeHTML(c['body'])}" unless c["body"].nil?

          # Collapsed rules will have properties array
          c["properties"]&.foreach do |_key, value|
            description += "\n#{value['name']}"
          end
        end
        description += "\n\nWhat's the risk?\n\n"
        description += force_wrap_text ? wrap(risk) : risk

        description
      end

      def format_solution(rec, force_wrap_text)
        solution = force_wrap_text ? wrap(rec["recommendation"]["text"]) : rec["recommendation"]["text"]
        solution += "\n\nOWASP: #{rec['owasp']}" unless rec["owasp"].nil?
        solution
      end

      def wrap(str, width = 100)
        str.gsub(/(.{1,#{width}})(\s+|\Z)/, "\\1\n")
      end
    end
  end
end
