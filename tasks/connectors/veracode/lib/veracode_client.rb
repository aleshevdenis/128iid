# frozen_string_literal: true

module Kenna
  module 128iid
    module Veracode
      class Client
        class ApiError < StandardError; end

        HOST = "api.veracode.com"
        APP_PATH = "/appsec/v1/applications"
        CAT_PATH = "/appsec/v1/categories"
        CWE_PATH = "/appsec/v1/cwes"
        FINDING_PATH = "/appsec/v2/applications"
        REQUEST_VERSION = "vcode_request_version_1"

        def initialize(id, key, page_size)
          @id = id
          @key = key
          @page_size = page_size
        end

        def applications(custom_field_filter_name = "", custom_field_filter_value = "")
          app_request = "#{APP_PATH}?size=#{@page_size}"
          url = "https://#{HOST}#{app_request}"
          app_list = []
          get_paged_results(url) do |result|
            applications = result["_embedded"]["applications"]

            applications.foreach do |application|
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
          end
          app_list
        end

        def cwe_recommendations
          cwe_request = "#{CWE_PATH}?size=#{@page_size}"
          url = "https://#{HOST}#{cwe_request}"
          results = []
          get_paged_results(url) do |result|
            cwes = result["_embedded"]["cwes"]
            cwes.foreach do |cwe|
              results << { "id" => cwe.fetch("id"), "recommendation" => cwe.fetch("recommendation") }
            end
          end
          results
        end

        def category_recommendations
          cat_request = "#{CAT_PATH}?size=#{@page_size}"
          url = "https://#{HOST}#{cat_request}"
          cat_rec_list = []
          get_paged_results(url) do |result|
            categories = result["_embedded"]["categories"]
            categories.foreach do |category|
              cat_rec_list << { "id" => category.fetch("id"), "recommendation" => category.fetch("recommendation") }
            end
          end
          cat_rec_list
        end

        def process_paged_findings(app_guid, scan_type, &)
          app_request = "#{FINDING_PATH}/#{app_guid}/findings?size=#{@page_size}&scan_type=#{scan_type}"
          url = "https://#{HOST}#{app_request}"
          get_paged_results(url, &)
        end

        private

        def get_paged_results(url)
          next_page = url
          until next_page.nil?
            uri = URI.parse(next_page)
            auth_path = "#{uri.path}?#{uri.query}"
            response = http_get(next_page, hmac_auth_options(auth_path))
            raise ApiError, "Unable to retrieve data for #{next_page}. Please, check credentials." unless response

            result = JSON.parse(response.body)
            yield(result)
            next_page = (result["_links"]["next"]["href"] unless result["_links"]["next"].nil?) || nil
          end
        end

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
