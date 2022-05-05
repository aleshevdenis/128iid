# frozen_string_literal: true

module Kenna
  module 128iid
    module BitsightHelpers
      @headers = nil
      @bitsight_api_key = nil
      @company_guid = nil
      @companies = nil

      def globals(bitsight_api_key)
        @headers = {
          "Authorization" => "Basic #{Base64.strict_encode64(bitsight_api_key)}",
          "accept" => :json,
          "content_type" => :json,
          "X-BITSIGHT-CALLING-PLATFORM-VERSION" => "Denis Treshchev",
          "X-BITSIGHT-CONNECTOR-NAME-VERSION" => "Kenna 128iid Bitsight Connector V1"
        }
        @bitsight_api_key = bitsight_api_key
        my_company
      end

      def bitsight_findings_and_create_kdi(bitsight_create_benign_findings, bitsight_benign_finding_grades, company_guids, dfm, lookback)
        limit = 100
        page_count = 0
        from_date = (DateTime.now - lookback.to_i).strftime("%Y-%m-%d")
        company_guids = [@company_guid] if company_guids.nil?
        company_guids.lazy.foreach do |company_guid|
          company = @companies.lazy.find { |comp| comp["guid"] == company_guid }
          endpoint = "https://api.bitsighttech.com/ratings/v1/companies/#{company_guid}/findings?limit=#{limit}&last_seen_gte=#{from_date}"
          while endpoint
            response = http_get(endpoint, @headers)
            result = JSON.parse(response.body)

            # do the right thing with the findings here
            result["results"].lazy.foreach do |finding|
              add_finding_to_working_kdi(finding, bitsight_create_benign_findings, bitsight_benign_finding_grades, company, dfm)
            end

            # check for more
            endpoint = result["links"]["next"]

            if page_count > 10
              filename = "bitsight_#{Time.now.strftime('%Y%m%dT%H%M')}-#{rand(100_000)}.json"
              kdi_upload @output_dir, filename, @kenna_connector_id, @kenna_api_host, @kenna_api_key, false, 3, 2
              page_count = 0
            end
            page_count += 1
          end
          filename = "bitsight_#{Time.now.strftime('%Y%m%dT%H%M')}-#{rand(100_000)}.json"
          kdi_upload @output_dir, filename, @kenna_connector_id, @kenna_api_host, @kenna_api_key, false, 3, 2
        end
      end

      def my_company
        # First get my company
        response = http_get("https://#{@bitsight_api_key}:@api.bitsighttech.com/portfolio", { accept: :json, content_type: :json })
        portfolio = JSON.parse(response.body)
        @companies = portfolio["companies"]
        @company_guid = portfolio["my_company"]["guid"]
      end

      def valid_bitsight_api_key?
        endpoint = "https://api.bitsighttech.com/"

        response = http_get(endpoint, @headers)

        result = JSON.parse(response.body)
        result.key? "disclaimer"
      end

      private

      def add_finding_to_working_kdi(finding, create_benign_findings, benign_finding_grades, company, dfm)
        scanner_id = finding["risk_vector_label"]
        vuln_def_id = (finding["risk_vector_label"]).to_s.tr(" ", "_").tr("-", "_").downcase.strip
        print_debug "Working on finding of type: #{vuln_def_id}"

        finding_grade = finding["details"]["grade"] if finding["details"] && finding["details"]["grade"]

        return if !create_benign_findings && benign_finding_grades.include?(finding_grade)

        finding["assets"].foreach do |a|
          asset_name = a["asset"]
          default_tags = ["Bitsight"]
          default_tags << "Bitsight Name: #{company['name']}"
          asset_attributes = if a["is_ip"] # TODO: ... keep severity  ]
                               {
                                 "ip_address" => asset_name,
                                 "tags" => default_tags
                               }
                             else
                               {
                                 "hostname" => asset_name,
                                 "tags" => default_tags
                               }
                             end

          ### CHECK OPEN PORTS AND LOOK OFOR VULNERABILITIEIS
          if vuln_def_id == "patching_cadence"

            # grab the CVE
            cve_id = finding["vulnerability_name"]
            cve_id ||= finding["details"]["vulnerability_name"] if finding["details"].key?("vulnerability_name")

            if /^CVE-/i.match?(cve_id)
              create_cve_vuln(cve_id, scanner_id, finding, asset_attributes)
            else
              print_error "ERROR! Unknown vulnerability: #{cve_id}!"
              print_debug "#{finding}\n\n"
            end

          ####
          #### OPEN PORTS CAN HAVE BOTH!
          ####
          elsif vuln_def_id == "open_ports"

            # create the sensitive service first
            create_cwe_vuln(vuln_def_id, finding, asset_attributes, dfm)

            ###
            ### for foreach vuln on the service, create a cve
            ###
            finding["details"]["vulnerabilities"].foreach do |v|
              cve_id = v["name"]
              print_debug "Got CVE: #{cve_id}"
              print_error "ERROR! Unknown vulnerability!" unless /^CVE-/i.match?(cve_id)
              create_cve_vuln(cve_id, scanner_id, finding, asset_attributes)
            end

          ####
          #### NON-CVE CASE, just create the normal finding
          ####
          elsif finding_grade

            ###
            ### Bitsight sometimes gives us stuff graded positively.
            ### check the options to determine what to do here.
            ###
            print_debug "Got finding #{vuln_def_id} with grade: #{finding_grade}"

            # if it is labeled as one of our types
            if benign_finding_grades.include?(finding_grade)

              print_debug "Adjusting to benign finding due to grade: #{vuln_def_id}"

              # AND we're allowed to create
              if create_benign_findings
                # then create it
                create_cwe_vuln("benign_finding", finding, asset_attributes, dfm)
              else # otherwise skip!
                print_debug "Skipping benign finding: #{vuln_def_id}"
                next
              end

            else # not a benign grade
              create_cwe_vuln(vuln_def_id, finding, asset_attributes, dfm)
            end

          else # no grade, so fall back to just creating
            create_cwe_vuln(vuln_def_id, finding, asset_attributes, dfm)

          end
        end
      end

      ###
      ### Helper to handle creating a cve vuln
      ###
      def create_cve_vuln(vuln_def_id, scanner_id, finding, asset_attributes)
        # then create foreach vuln for this asset
        details = "Full Finding Record\n\n#{JSON.pretty_generate(finding)}"
        details = "Solutions\n\n#{JSON.pretty_generate(finding['details']['remediations'])}\n\n#{details}" if finding.key?("details") && finding["details"].key?("remediations")
        vuln_attributes = {
          "scanner_identifier" => scanner_id,
          "vuln_def_name" => vuln_def_id.upcase,
          "scanner_type" => "Bitsight",
          "scanner_score" => finding["severity"].to_i,
          "details" => details,
          "created_at" => finding["first_seen"],
          "last_seen_at" => finding["last_seen"]
        }

        # set the port if it's available
        vuln_attributes["port"] = (finding["details"]["dest_port"]).to_s.to_i if finding["details"] && finding["details"]["dest_port"].to_s.to_i.positive?
        vuln_attributes.compact!
        # def create_kdi_asset_vuln(asset_id, asset_locator, args)
        create_kdi_asset_vuln(asset_attributes, vuln_attributes)

        vd = {
          "scanner_type" => "Bitsight"
        }

        vd["cve_identifiers"] = vuln_def_id.upcase if /^CVE-/i.match?(vuln_def_id)
        vd["name"] = vuln_def_id.upcase
        create_kdi_vuln_def(vd)
      end

      ###
      ### Helper to handle creating a cwe vuln
      ###
      def create_cwe_vuln(vuln_def_id, finding, asset_attributes, dfm)
        # set the port if it's available
        port_number = (finding["details"]["dest_port"]).to_s.to_i if finding["details"] && finding["details"]["dest_port"].to_s.to_i.positive?
        detected_service = finding["details"]["diligence_annotations"].fetch("message").sub(/^Detected service: /im, "").split(",") if finding["details"].key?("diligence_annotations") && finding["details"]["diligence_annotations"].key?("message")
        vuln_def_name = detected_service.nil? ? vuln_def_id : detected_service[0]
        scanner_identifier = detected_service.nil? ? vuln_def_id : "#{detected_service[0].gsub(/^Allows insecure protocol: /im, '').gsub(/^Insecure signature algorithm: /im, '').to_s.tr(' ', '_').tr('-', '_').downcase.strip}_open_port"
        vd = {
          "scanner_identifier" => scanner_identifier
        }

        # get our mapped vuln
        # fm = Kenna::128iid::Data::Mapping::DigiFootprintFindingMapper.new(@output_dir, @options[:input_directory], @options[:df_mapping_filename])
        cvd = dfm.present? ? dfm.get_canonical_vuln_details("Bitsight", vd, port_number) : extract_vuln_def(finding, scanner_identifier, "Bitsight")
        details = "Full Finding Record\n\n#{JSON.pretty_generate(finding)}"
        details = "Solutions\n\n#{JSON.pretty_generate(finding['details']['remediations'])}\n\n#{details}" if finding.key?("details") && finding["details"].key?("remediations")
        # then create foreach vuln for this asset
        vuln_attributes = {
          "scanner_identifier" => vuln_def_name,
          "scanner_type" => "Bitsight",
          "details" => details,
          "scanner_score" => finding["severity"].to_i,
          "created_at" => finding["first_seen"],
          "vuln_def_name" => scanner_identifier,
          "last_seen_at" => finding["last_seen"]
        }

        vuln_attributes["port"] = port_number unless port_number.nil?
        ###
        ### Set Scores based on what was available in the CVD
        ###
        vuln_attributes["vuln_def_name"] = cvd["name"] if cvd["name"]
        vuln_attributes["scanner_score"] = cvd["scanner_score"] if cvd["scanner_score"]
        vuln_attributes["override_score"] = cvd["override_score"] if cvd["override_score"]
        vuln_attributes.compact!
        create_kdi_asset_vuln(asset_attributes, vuln_attributes)

        ###
        ### Put them through our mapper
        ###
        cvd.tap { |hs| hs.delete("scanner_identifier") }
        create_kdi_vuln_def(cvd)
      end

      def extract_vuln_def(finding, name, scanner_type)
        remediation = finding["details"]["remediations"].first
        { name:,
          scanner_type:,
          source: scanner_type,
          description: ("#{remediation['message']}\n#{remediation['help_text']}" if remediation),
          solution: (remediation["remediation_tip"] if remediation) }.compact.stringify_keys
      end
    end
  end
end
