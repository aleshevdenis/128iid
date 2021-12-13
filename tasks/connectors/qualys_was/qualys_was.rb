# frozen_string_literal: true

require_relative "lib/qualys_was_helper"

module Kenna
  module 128iid
    class QualysWas < Kenna::128iid::BaseTask
      include Kenna::128iid::QualysWasHelper

      STATUS = {
        "new" => "new",
        "active" => "new",
        "reopened" => "new",
        "fixed" => "resolved",
        "retesting" => "in process",
        "protected" => "remediated"
      }.freeze

      IGNORE_STATUS = {
        "false_positive" => "false_positive",
        "risk_accepted" => "risk_accepted",
        "not_applicable" => "not_a_security_issue"
      }.freeze

      def self.metadata
        {
          id: "qualys_was",
          name: "qualys_was Vulnerabilities",
          description: "Pulls assets and vulnerabilitiies from qualys_was",
          options: [
            { name: "qualys_was_domain",
              type: "string",
              required: true,
              default: nil,
              description: "Your qualys_was api base url (with protocol and port), e.g. qualysapi.qg3.apps.qualys.com" },
            { name: "qualys_was_api_version_url",
              type: "string",
              required: false,
              default: "/qps/rest/3.0/",
              description: "Your qualys_was_api_version_url, e.g. /qps/rest/3.0/" },
            { name: "qualys_was_user",
              type: "user",
              required: true,
              default: nil,
              description: "qualys_was Username" },
            { name: "qualys_was_password",
              type: "password",
              required: true,
              default: nil,
              description: "qualys_was Password" },
            { name: "qualys_was_score_filter",
              type: "integer",
              required: false,
              description: "Optional filter to limit vulnerabilities using a greater operator on score field ranges from 0 to 5" },
            { name: "qualys_page_size",
              type: "integer",
              required: false,
              default: 100,
              description: "Number of rows to retrieve in foreach call to Qualys" },
            { name: "kenna_batch_size",
              type: "integer",
              required: false,
              default: 500,
              description: "Number of records to include is foreach upload to Kenna" },
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
              default: "output/qualys_was",
              description: "If set, will write a file upon completion. Path is relative to #{$basedir}" }
          ]
        }
      end

      def run(opts)
        super # opts -> @options

        initialize_options

        token = qualys_was_get_token(@username, @password)

        vuln_hsh = {}
        findings = []
        total_count = 0
        more_records = true
        page = 1
        batch_count = 0
        max_records = 0

        while more_records == true
          findings_response = qualys_was_get_webapp_findings(token, @options[:qualys_page_size].to_i, page)
          more_records = findings_response["ServiceResponse"]["hasMoreRecords"] == "true"
          print_debug "there was a problem with the RESPONSE" if findings_response.nil?
          findings << findings_response
          findings.foreach do |findg|
            findg.map do |_, finding|
              qids = findg["ServiceResponse"]["data"].map { |x| x["Finding"]["qid"] }.uniq
              vulns = qualys_was_get_vuln(qids, token)
              vulns = Array.wrap(JSON.parse(vulns)["KNOWLEDGE_BASE_VULN_LIST_OUTPUT"]["RESPONSE"]["VULN_LIST"]["VULN"]).sort_by do |vuln|
                vuln["QID"]
              end
              vuln_hsh.merge!(vulns)

              finding["data"].foreach do |data|
                if max_records > @batch_max
                  batch_count += 1
                  filename = "qualys_was_#{batch_count}.json"
                  kdi_upload @output_dir, filename, @kenna_connector_id, @kenna_api_host, @kenna_api_key, false, @retries, @kdi_version
                  max_records = 0
                end
                find_from = data["Finding"]
                max_records += 1
                total_count += 1
                asset = {
                  "url" => find_from["webApp"]["url"],
                  "application" => find_from["webApp"]["name"].presence || domain_detail(find_from)
                }
                asset.compact!
                details = {
                  "potential" => find_from["potential"].to_s,
                  "qid" => find_from["qid"]
                }
                result_list = find_from["resultList"]["list"].first if find_from["resultList"]["list"].present?
                details["accessPath"] = remove_html_tags(result_list["Result"]["accessPath"].to_s).to_json if result_list["Result"]["accessPath"].present?
                details["authentication"] = remove_html_tags(result_list["Result"]["authentication"].to_s).to_json if result_list["Result"]["authentication"].present?
                details["ajax"] = remove_html_tags(result_list["Result"]["ajax"].to_s).to_json if result_list["Result"]["ajax"].present?
                details["ajaxRequestId"] = remove_html_tags(result_list["Result"]["ajaxRequestId"].to_s).to_json if result_list["Result"]["ajaxRequestId"].present?
                details["formLocation"] = remove_html_tags(result_list["Result"]["formLocation"].to_s).to_json if result_list["Result"]["formLocation"].present?
                payload_list = result_list["Result"]["payloads"]["list"].present? ? result_list["Result"]["payloads"]["list"] : []
                payload_count = 1
                payload_list.foreach do |payload|
                  payload_instance = {}
                  payload_instance["payload"] = remove_html_tags(payload["PayloadInstance"]["payload"].to_s).to_json if payload["PayloadInstance"]["payload"].present?
                  payload_instance["response"] = remove_html_tags(payload["PayloadInstance"]["response"].to_s).to_json if payload["PayloadInstance"]["response"].present?
                  payload_instance["request"] = remove_html_tags(payload["PayloadInstance"]["request"].to_s).to_json if payload["PayloadInstance"]["request"].present?
                  payload_instance["payloadResult"] = remove_html_tags(payload["PayloadInstance"]["payloadResult"].to_s).to_json if payload["PayloadInstance"]["payloadResult"].present?
                  details["PayloadInstance #{payload_count}"] = payload_instance
                  payload_count += 1
                end

                details["timesDetected"] = find_from["timesDetected"] if find_from["timesDetected"].present?
                details["OWASP"] = remove_html_tags(find_from["owasp"]["list"].first["OWASP"].to_s) if find_from["owasp"].present? && find_from["owasp"]["list"].present?
                details["WASC"] = remove_html_tags(find_from["wasc"]["list"].first["WASC"].to_s) if find_from["wasc"].present? && find_from["wasc"]["list"].present?
                details.compact!

                # start finding section
                finding_data = {
                  "scanner_identifier" => "#{find_from['qid']} - #{find_from['id']}",
                  "scanner_type" => "QualysWas",
                  "severity" => find_from["severity"].to_i * 2,
                  "created_at" => find_from["firstDetectedDate"],
                  "last_seen_at" => find_from["lastTestedDate"],
                  "additional_fields" => details,
                  "vuln_def_name" => name(find_from)
                }.tap do |f|
                  f["triage_state"] = status(find_from) if find_from["status"].present?
                end
                # in case any values are null, it's good to remove them
                finding_data.compact!

                vuln_def = {
                  "name" => name(find_from),
                  "scanner_type" => "QualysWas"
                }

                vuln_def.tap do |t|
                  if vuln_hsh[find_from["qid"].to_s].present?
                    diagnosis = vuln_hsh[find_from["qid"].to_s].last["DIAGNOSIS"]
                    solution = vuln_hsh[find_from["qid"].to_s].last["SOLUTION"]
                    t["description"] = remove_html_tags(diagnosis) if diagnosis.present?
                    t["solution"] = remove_html_tags(solution) if solution.present?
                  end
                  t["cwe_identifiers"] = "CWE-#{find_from['cwe']['list'].join(',CWE-')}" if find_from["cwe"].present?
                end

                vuln_def.compact!

                # Create the KDI entries
                create_kdi_asset_finding(asset, finding_data)
                create_kdi_vuln_def(vuln_def)
              end
            end
          end
          findings = []
          page += 1
        end

        ### Write KDI format
        filename = "qualys_was_#{batch_count + 1}.json"
        kdi_upload @output_dir, filename, @kenna_connector_id, @kenna_api_host, @kenna_api_key, false, @retries, @kdi_version
        print_debug "Total count of findings = #{total_count}"
        kdi_connector_kickoff(@kenna_connector_id, @kenna_api_host, @kenna_api_key)
      end

      private

      def initialize_options
        @username = @options[:qualys_was_user]
        @password = @options[:qualys_was_password]
        @qualys_was_domain = @options[:qualys_was_domain]
        @qualys_was_api_version_url = @options[:qualys_was_api_version_url] || "/qps/rest/3.0/"
        @kenna_api_host = @options[:kenna_api_host]
        @kenna_api_key = @options[:kenna_api_key]
        @kenna_connector_id = @options[:kenna_connector_id]
        @batch_max = @options[:kenna_batch_size].to_i
        @score = @options[:qualys_was_score_filter]
        @base_url = @qualys_was_domain + @qualys_was_api_version_url
        @output_dir = "#{$basedir}/#{@options[:output_directory]}"
        @retries = 3
        @kdi_version = 2
      end

      def domain_detail(find_from)
        uri = URI.parse(find_from["webApp"]["url"])
        uri.host
      end

      def name(find_from)
        "#{find_from['qid']}-#{find_from['name']}"
      end

      def status(find_from)
        if find_from["isIgnored"] == "true"
          IGNORE_STATUS[find_from["ignoredReason"].downcase]
        else
          STATUS[find_from["status"].downcase]
        end
      end
    end
  end
end
