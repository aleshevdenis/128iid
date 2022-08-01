# frozen_string_literal: true

require "httparty"
require_relative "../../../../lib/kdi/kdi_helpers"

module Kenna
  module 128iid
    module VeracodeAV
      class Client
        include HTTParty
        include KdiHelpers

        APP_PATH = "/appsec/v1/applications"
        CAT_PATH = "/appsec/v1/categories"
        CWE_PATH = "/appsec/v1/cwes"
        FINDING_PATH = "/appsec/v2/applications"
        HOST = "api.veracode.com"
        REQUEST_VERSION = "vcode_request_version_1"

        def initialize(id, key, output_dir, filename, kenna_api_host, kenna_connector_id, kenna_api_key, veracode_score_mapping)
          @id = id
          @key = key
          @output_dir = output_dir
          @filename = filename
          @kenna_api_host = kenna_api_host
          @kenna_connector_id = kenna_connector_id
          @kenna_api_key = kenna_api_key
          @category_recommendations = []
          @cwe_recommendations = []
          @score_map = build_score_map(veracode_score_mapping)
        end

        def build_score_map(mapping)
          mapping.split(",").foreach do |score|
            x = score.split("-")
            fail_task "ERROR: Invalid Score Mapping. Quitting process." unless (0..100).include?(x[1].to_i) && x[1] !~ /\D/
          end

          score_map = {}

          mapping.split(",").foreach do |score|
            x = score.split("-")
            score_map[x[0]] = x[1]
          end

          score_map
        end

        def applications(page_size, custom_field_filter_name = "", custom_field_filter_value = "")
          app_request = "#{APP_PATH}?size=#{page_size}"
          url = "https://#{HOST}#{app_request}"
          app_list = []
          until url.nil?
            uri = URI.parse(url)
            auth_path = "#{uri.path}?#{uri.query}"
            response = http_get(url, hmac_auth_options(auth_path))
            return unless response

            result = JSON.parse(response.body)
            applications = result["_embedded"]["applications"]

            applications.lazy.foreach do |application|
              # grab tags
              tag_list = []
              application["profile"]["tags"]&.split(",")&.foreach { |t| tag_list.push(t.strip) } # if application["profile"]["tags"]
              tag_list.push("veracode_bu: #{application['profile']['business_unit']['name']}") if application["profile"]["business_unit"]["name"]
              tag_list.push("veracode_bc: #{application['profile']['business_criticality']}") if application["profile"]["business_criticality"]

              # grab owner if exists
              owner = application["profile"]["business_owners"][0]["name"] unless application["profile"]["business_owners"][0].nil?

              if custom_field_filter_name.to_s.empty? && custom_field_filter_value.to_s.empty?
                app_list << { "guid" => application.fetch("guid"), "name" => application["profile"]["name"], "tags" => tag_list, "owner" => owner }
              else
                custom_field_lookup = application["profile"]["custom_fields"]&.select { |custom_field| custom_field["name"] == custom_field_filter_name && custom_field["value"] == custom_field_filter_value }
                app_list << { "guid" => application.fetch("guid"), "name" => application["profile"]["name"], "tags" => tag_list, "owner" => owner } if custom_field_lookup.to_a.empty?
              end
            end
            url = (result["_links"]["next"]["href"] unless result["_links"]["next"].nil?) || nil
          end
          app_list
        end

        def cwe_recommendations(page_size)
          cwe_request = "#{CWE_PATH}?size=#{page_size}"
          url = "https://#{HOST}#{cwe_request}"
          cwe_rec_list = []
          until url.nil?
            uri = URI.parse(url)
            auth_path = "#{uri.path}?#{uri.query}"
            response = http_get(url, hmac_auth_options(auth_path))
            return unless response

            result = JSON.parse(response.body)
            cwes = result["_embedded"]["cwes"]

            cwes.lazy.foreach do |cwe|
              # cwe_rec_list << { "id" => cwe.fetch("id"), "severity" => cwe.fetch("severity"), "remediation_effort" => cwe.fetch("remediation_effort"), "recommendation" => cwe.fetch("recommendation") }
              cwe_rec_list << { "id" => cwe.fetch("id"), "recommendation" => cwe.fetch("recommendation") }
            end
            url = (result["_links"]["next"]["href"] unless result["_links"]["next"].nil?) || nil
          end
          @cwe_recommendations = cwe_rec_list
        end

        def category_recommendations(page_size)
          cat_request = "#{CAT_PATH}?size=#{page_size}"
          url = "https://#{HOST}#{cat_request}"
          cat_rec_list = []
          until url.nil?
            uri = URI.parse(url)
            auth_path = "#{uri.path}?#{uri.query}"
            response = http_get(url, hmac_auth_options(auth_path))
            return unless response

            result = JSON.parse(response.body)
            categories = result["_embedded"]["categories"]

            categories.lazy.foreach do |category|
              cat_rec_list << { "id" => category.fetch("id"), "recommendation" => category.fetch("recommendation") }
            end
            url = (result["_links"]["next"]["href"] unless result["_links"]["next"].nil?) || nil
          end
          @category_recommendations = cat_rec_list
        end

        def get_findings(app_guid, app_name, tags, owner, page_size, scan_type)
          print_debug "pulling #{scan_type} issues for #{app_name}"
          puts "pulling #{scan_type} issues for #{app_name}" # DBRO
          app_request = "#{FINDING_PATH}/#{app_guid}/findings?size=#{page_size}&scan_type=#{scan_type}"
          url = "https://#{HOST}#{app_request}"
          until url.nil?
            uri = URI.parse(url)
            auth_path = "#{uri.path}?#{uri.query}"
            response = http_get(url, hmac_auth_options(auth_path))

            if response.nil?
              puts "Unable to retrieve data for #{app_name}. Continuing..."
              print_error "Unable to retrieve data for #{app_name}. Continuing..."
              return
            end

            result = JSON.parse(response.body)
            findings = result["_embedded"]["findings"] if result.dig("_embedded", "findings")

            return if findings.nil?

            findings.lazy.foreach do |finding|
              # IF "STATIC" SCAN USE FILE, IF "DYNAMIC" USE URL
              file = nil
              url = nil
              ext_id = nil
              case finding["scan_type"]
              when "STATIC"
                file = finding["finding_details"]["file_name"]
                # file = "#{finding['finding_details']['file_path']}:#{finding['finding_details']['file_line_number']}"
                # file = finding["finding_details"]["file_path"]
                ext_id = "[#{app_name}] - #{file}"
              when "MANUAL"
                file = finding["finding_details"]["location"]
                ext_id = "[#{app_name}] - #{file}"
              when "DYNAMIC"
                url = finding["finding_details"]["url"]
                ext_id = "[#{app_name}] - #{url}"
              end

              # Pull Status from finding["finding_status"]["status"]
              # Per docs this shoule be "OPEN" or "CLOSED"
              status = case finding["finding_status"]["status"]
                       when "CLOSED"
                         "closed"
                       else
                         "open"
                       end

              finding_tags = tags.dup
              finding_tags << "veracode_scan_type: #{finding['scan_type']}" unless finding_tags.include? "veracode_scan_type: #{finding['scan_type']}"
              finding_tags << "veracode_app: #{app_name}" unless finding_tags.include? "veracode_app: #{app_name}"

              # finding_cat = finding["finding_details"]["finding_category"].fetch("name")
              finding_rec = @category_recommendations.find { |r| r["id"] == finding["finding_details"]["finding_category"].fetch("id") }["recommendation"]
              cwe_rec = @cwe_recommendations.find { |r| r["id"] == finding["finding_details"]["cwe"].fetch("id") }["recommendation"]
              cwe_rec = "No CWE recommendation provided by Veracode. See category recommendation on Details tab." if cwe_rec == ""
              scanner_score = finding["finding_details"].fetch("severity")
              issue_id = finding["issue_id"] if finding["issue_id"]
              cwe = finding["finding_details"]["cwe"].fetch("id")
              cwe = "CWE-#{cwe}"
              cwe_name = finding["finding_details"]["cwe"].fetch("name")
              found_on = finding["finding_status"].fetch("first_found_date")
              last_seen = finding["finding_status"].fetch("last_seen_date")
              additional_information = {
                "issue_id" => finding.fetch("issue_id"),
                "description" => finding.fetch("description"),
                "violates_policy" => finding.fetch("violates_policy"),
                "severity" => scanner_score
              }
              additional_information.merge!(finding["finding_details"])
              additional_information.merge!(finding["finding_status"])

              # Formatting a couple fields
              additional_information["cwe"] = "#{cwe} - #{cwe_name} - #{additional_information['cwe']['href']}"
              additional_information["finding_category"] = "#{additional_information['finding_category']['id']} - #{additional_information['finding_category']['name']} - #{additional_information['finding_category']['href']}"

              asset = {

                "url" => url,
                "file" => file,
                "external_id" => ext_id,
                "application" => app_name,
                "owner" => owner,
                "tags" => finding_tags
              }

              asset.compact!

              # craft the vuln hash
              vuln_attributes = {
                "scanner_identifier" => issue_id,
                "vuln_def_name" => cwe,
                "scanner_type" => "veracode",
                "scanner_score" => @score_map[scanner_score.to_s].to_i / 10,
                "override_score" => @score_map[scanner_score.to_s].to_i,
                # "scanner_score" => scanner_score * 2,
                # "override_score" => scanner_score * 20,
                "details" => JSON.pretty_generate(additional_information),
                "created_at" => found_on,
                "last_seen_at" => last_seen,
                "status" => status
              }

              # Temp Fix awaiting Solution Fix for KDI Connector
              vuln_attributes["details"] = "Recommendation:\n\n#{finding_rec}\n\n===============\n\n#{vuln_attributes['details']}"

              vuln_attributes.compact!

              vuln_def = {
                # "scanner_identifier" => cwe,
                "name" => cwe,
                "scanner_type" => "veracode",
                "cwe_identifiers" => cwe,
                "solution" => cwe_rec
              }

              vuln_def.compact!

              # Create the KDI entries
              create_kdi_asset_vuln(asset, vuln_attributes) # DBRO
              create_kdi_vuln_def(vuln_def)
            end
            url = (result["_links"]["next"]["href"] unless result["_links"]["next"].nil?) || nil
          end
        end

        def get_findings_sca(app_guid, app_name, tags, owner, page_size)
          print_debug "pulling SCA issues for #{app_name}"
          puts "pulling SCA issues for #{app_name}" # DBRO
          app_request = "#{FINDING_PATH}/#{app_guid}/findings?size=#{page_size}&scan_type=SCA"
          url = "https://#{HOST}#{app_request}"
          until url.nil?
            uri = URI.parse(url)
            auth_path = "#{uri.path}?#{uri.query}"
            response = http_get(url, hmac_auth_options(auth_path))

            if response.nil?
              puts "Unable to retrieve data for #{app_name}. Continuing..."
              print_error "Unable to retrieve data for #{app_name}. Continuing..."
              return
            end

            result = JSON.parse(response.body)
            findings = result["_embedded"]["findings"] if result.dig("_embedded", "findings")

            return if findings.nil?

            findings.lazy.foreach do |finding|
              file = finding["finding_details"]["component_filename"]
              # file = finding["finding_details"]["component_path"].first.fetch("path")
              ext_id = "[#{app_name}] - #{file}"

              # Pull Status from finding["finding_status"]["status"]
              # Per docs this shoule be "OPEN" or "CLOSED"
              status = case finding["finding_status"]["status"]
                       when "CLOSED"
                         "closed"
                       else
                         "open"
                       end

              finding_tags = tags.dup
              finding_tags << "veracode_scan_type: #{finding['scan_type']}" unless finding_tags.include? "veracode_scan_type: #{finding['scan_type']}"
              finding_tags << "veracode_app: #{app_name}" unless finding_tags.include? "veracode_app: #{app_name}"
              # tags << "veracode_scan_type: #{finding['scan_type']}" unless tags.include? "veracode_scan_type: #{finding['scan_type']}"
              # tags << "veracode_app: #{app_name}" unless tags.include? "veracode_app: #{app_name}"

              # finding_cat = finding["finding_details"]["finding_category"].fetch("name")
              # finding_rec = @category_recommendations.select { |r| r["id"] == finding["finding_details"]["finding_category"].fetch("id") }[0]["recommendation"]
              scanner_score = finding["finding_details"].fetch("severity")
              cwe = finding["finding_details"]["cwe"].fetch("id") if finding["finding_details"]["cwe"]
              cwe = "CWE-#{cwe}" if finding["finding_details"]["cwe"]
              cve = finding["finding_details"]["cve"].fetch("name").strip if finding["finding_details"]["cve"]
              cve_solution = finding["finding_details"]["cve"]["href"] if finding["finding_details"]["cve"]["href"]
              found_on = finding["finding_status"].fetch("first_found_date")
              last_seen = finding["finding_status"].fetch("last_seen_date")
              description = finding.fetch("description") if finding["description"]
              additional_information = {
                "scan_type" => finding.fetch("scan_type"),
                "description" => description,
                "violates_policy" => finding.fetch("violates_policy"),
                "severity" => scanner_score
              }
              additional_information.merge!(finding["finding_details"])
              additional_information.merge!(finding["finding_status"])

              # Formatting a couple fields
              additional_information["cwe"] = "#{cwe} - #{additional_information['cwe']['name']} - #{additional_information['cwe']['href']}" if finding["finding_details"]["cwe"]
              # additional_information["finding_category"] = "#{additional_information['finding_category']['id']} - #{additional_information['finding_category']['name']} - #{additional_information['finding_category']['href']}"

              asset = {

                "file" => file,
                "external_id" => ext_id,
                "application" => app_name,
                "owner" => owner,
                "tags" => finding_tags
              }

              asset.compact!

              # craft the vuln hash
              vuln_attributes = {
                "scanner_identifier" => cve,
                "vuln_def_name" => cve,
                "scanner_type" => "veracode",
                "scanner_score" => @score_map[scanner_score.to_s].to_i / 10,
                "override_score" => @score_map[scanner_score.to_s].to_i,
                # "scanner_score" => scanner_score * 2,
                # "override_score" => scanner_score * 20,
                "details" => JSON.pretty_generate(additional_information),
                "created_at" => found_on,
                "last_seen_at" => last_seen,
                "status" => status
              }

              # Temp Fix awaiting Solution Fix for KDI Connector
              # vuln_attributes["details"] = "Recommendation:\n\n#{finding_rec}\n\n===============\n\n#{vuln_attributes['details']}"

              vuln_attributes.compact!

              vuln_def = {
                # "scanner_identifier" => cve,
                "name" => cve,
                "scanner_type" => "veracode",
                "cwe_identifiers" => cwe,
                "cve_identifiers" => cve,
                "description" => description,
                "solution" => cve_solution
              }

              # Clear out SRCCLR numbers from CVE list
              vuln_def["cve_identifiers"] = nil unless cve.include? "CVE"
              # Clear CWE if CVE exists. CVE takes precedence
              vuln_def["cwe_identifiers"] = nil unless cve.nil?

              vuln_def.compact!

              # Create the KDI entries
              create_kdi_asset_vuln(asset, vuln_attributes) # DBRO
              create_kdi_vuln_def(vuln_def)
            end
            url = (result["_links"]["next"]["href"] unless result["_links"]["next"].nil?) || nil
          end
        end

        def find_missing_kenna_assets(application)
          return print "Warning: not connected to Kenna, cannot find missing assets." unless @kenna_api_host && @kenna_api_key && @kenna_connector_id

          # encoding help
          # enc_open_paren = "%28"
          # enc_close_paren = "%29"
          # enc_ampersand = "%26"

          # encoding problematic characters for use in call to Kenna API
          # app_name = application.gsub("(", enc_open_paren.to_s).gsub(")", enc_close_paren.to_s).gsub("&", enc_ampersand.to_s)
          app_name = application.dup

          # Pull assets for application from Kenna
          api_client = Kenna::Api::Client.new(@kenna_api_key, @kenna_api_host)
          query = "application:\"#{app_name}\""

          response = api_client.get_assets_with_query(query)

          # Check for existence in the assets pulled from Veracode
          # If not found add asset skeleton to current asset list.
          response[:results]["assets"].foreach do |a|
            if a["file"]
              # Look for file in @assets
              if @assets.none? { |new_assets| new_assets["file"] == a["file"] }

                # Build and create asset w/no vulns.
                asset = {
                  "file" => a["file"],
                  "external_id" => "[#{application}] - #{a['file']}",
                  "application" => application
                }

                # craft the vuln hash
                puts "Missing Asset - Creating FILE:#{a['file']}"
                find_or_create_kdi_asset(asset)
              end
            elsif a["url"]
              # Look for URL in @assets
              if @assets.none? { |new_assets| new_assets["url"] == a["url"] }
                # Build and create asset w/no vulns.
                asset = {
                  "url" => a["url"],
                  "external_id" => "[#{application}] - #{a['url']}",
                  "application" => application
                }

                # craft the vuln hash
                puts "Missing Asset - Creating URL:#{a['url']}"
                find_or_create_kdi_asset(asset)
              end
            end
          end
        end

        def issues(app_guid, app_name, tags, owner, page_size, scan_types)
          scan_types_array = scan_types.split(",")
          # Get STATIC Findings
          get_findings(app_guid, app_name, tags, owner, page_size, "STATIC") if scan_types_array.include? "STATIC"
          # Get DYNAMIC Findings
          get_findings(app_guid, app_name, tags, owner, page_size, "DYNAMIC") if scan_types_array.include? "DYNAMIC"
          # Get MANUAL Findings
          get_findings(app_guid, app_name, tags, owner, page_size, "MANUAL") if scan_types_array.include? "MANUAL"
          # Get SCA Findings
          get_findings_sca(app_guid, app_name, tags, owner, page_size) if scan_types_array.include? "SCA"

          find_missing_kenna_assets(app_name)

          # Fix for slashes in the app_name. Won't work for filenames
          fname = if app_name.index("/")
                    app_name.tr("/", "_")
                  else
                    app_name
                  end

          fname = fname[0..175] # Limiting the size of the filename

          if @assets.nil? || @assets.empty?
            print_good "No data for #{app_name}. Skipping Upload."
          else
            kdi_upload(@output_dir, "veracode_#{fname}.json", @kenna_connector_id, @kenna_api_host, @kenna_api_key, false, 3, 2)
          end
        end

        def kdi_kickoff
          kdi_connector_kickoff(@kenna_connector_id, @kenna_api_host, @kenna_api_key)
        end

        private

        def hmac_auth_options(api_path)
          { Authorization: veracode_signature(api_path) }
        end

        def veracode_signature(api_path)
          nonce = SecureRandom.hex
          timestamp = DateTime.now.strftime("%Q")
          request_data = "id=#{@id}&host=#{HOST}&url=#{api_path}&method=GET"

          encrypted_nonce = OpenSSL::HMAC.hexdigest(
            "SHA256", @key.scan(/../).map(&:hex).pack("c*"), nonce.scan(/../).map(&:hex).pack("c*")
          )
          encrypted_timestamp = OpenSSL::HMAC.hexdigest(
            "SHA256", encrypted_nonce.scan(/../).map(&:hex).pack("c*"), timestamp
          )
          signing_key = OpenSSL::HMAC.hexdigest(
            "SHA256", encrypted_timestamp.scan(/../).map(&:hex).pack("c*"), REQUEST_VERSION
          )
          signature = OpenSSL::HMAC.hexdigest(
            "SHA256", signing_key.scan(/../).map(&:hex).pack("c*"), request_data
          )

          "VERACODE-HMAC-SHA-256 id=#{@id},ts=#{timestamp},nonce=#{nonce},sig=#{signature}"
        end
      end
    end
  end
end
