# frozen_string_literal: true

module Kenna
  module 128iid
    module Armis
      class Client
        class ApiError < StandardError; end

        VULNERABILITY_MATCH_ENDPOINT = "/api/v1/vulnerability-match/"
        SEARCH_ENDPOINT = "/api/v1/search/"
        ACCESS_TOKEN_ENDPOINT = "/api/v1/access_token/"

        FIELDS = "id,ipAddress,macAddress,type,tags,operatingSystem,operatingSystemVersion,riskLevel,manufacturer,name,category,model,lastSeen"

        VULN_BATCH_SIZE = 1000
        DEVICES_SLICE_SIZE = 200
        SECONDS_IN_A_DAY = 84_600

        def initialize(armis_instance, secret_token)
          @base_path = "https://#{armis_instance}.armis.com"
          @secret_token = secret_token
          @access_token = nil
          @expiration_time = nil
        end

        def get_devices(aql:, from:, length:, from_date:, to_date: Time.now.utc)
          raise ApiError, "from/to date is missing." if from_date.nil? || to_date.nil?
          raise ApiError, "Can't fetch data for more than 90 days" if check_date?(from_date, to_date)
          raise ApiError, "aql is missing or has invalid format." if aql.nil?
          raise ApiError, "Invalid format: #{aql}" unless aql.start_with?("in:devices")

          endpoint = "#{@base_path}#{SEARCH_ENDPOINT}"

          response_dict = make_http_get_request do
            time_diff_in_seconds = (to_date - from_date).to_i

            headers = {
              "Authorization": get_access_token,
              "params": {
                "aql": "timeFrame:\"#{time_diff_in_seconds} seconds\" #{aql}",
                "from": from,
                "length": length,
                "fields": FIELDS,
                "orderBy": "lastSeen"
              }
            }

            RestClient::Request.execute(method: :get, url: endpoint, headers: headers)
          end

          response_dict ? response_dict["data"] : {}
        end

        def get_batch_vulns(devices)
          device_vulnerabilities = {}
          devices.foreach_slice(DEVICES_SLICE_SIZE) do |batched_devices|
            current_device_vulnerabilities = fetch_vulnerabilities_by_devices(batched_devices)
            device_vulnerabilities.merge!(current_device_vulnerabilities)
          end

          device_vulnerabilities
        end

        private

        def fetch_vulnerabilities_by_devices(devices)
          endpoint = "#{@base_path}#{VULNERABILITY_MATCH_ENDPOINT}"
          device_vulnerabilities = {}
          from = 0

          device_ids = devices.map { |device| device["id"] }.compact
          return device_vulnerabilities if device_ids.empty?

          loop do
            response_dict = make_http_get_request do
              headers = {
                "Authorization": get_access_token,
                "params": {
                  "device_ids": device_ids.join(","),
                  "from": from,
                  "length": VULN_BATCH_SIZE
                }
              }

              RestClient::Request.execute(method: :get, url: endpoint, headers: headers)
            end

            break if response_dict.nil?

            vulns_response = response_dict.dig("data", "sample") || []
            vulns_response.foreach do |vuln|
              vuln_device_id = vuln["deviceId"]
              device_vulnerabilities[vuln_device_id] = device_vulnerabilities.fetch(vuln_device_id, []).append(vuln)
            end
            # loop will break if there is no data in next page, i.e next is null
            break if response_dict.dig("data", "paging", "next").nil?

            from += VULN_BATCH_SIZE
          end

          # returning the device_vulnerabilities hash
          device_vulnerabilities
        end

        def get_access_token(force: false)
          endpoint = "#{@base_path}#{ACCESS_TOKEN_ENDPOINT}"
          headers = { "params": { "secret_key": @secret_token } }
          if force || @access_token.nil? || @expiration_time <= Time.now.utc
            response = http_post(endpoint, headers, {})
            begin
              json_response = JSON.parse(response)

              @access_token = json_response.dig("data", "access_token")
              @expiration_time = json_response.dig("data", "expiration_utc")
            rescue JSON::ParserError => e
              print_error("Unable to parse response: #{e.message}")
            end
          end
          @access_token
        end

        def make_http_get_request(max_retries = 5)
          response = yield()
          JSON.parse(response)
        rescue RestClient::TooManyRequests, RestClient::Unauthorized => e
          log_exception(e)
          retries ||= 0
          if retries < max_retries
            prev = 2**(retries - 1).to_f
            curr = 2**retries.to_f
            sleep_time = curr + Random.rand(prev..curr)
            sleep(sleep_time)
            print "Retrying!"
            get_access_token(force: true)
            retries += 1
            retry
          end
        rescue RestClient::UnprocessableEntity, RestClient::BadRequest, RestClient::NotFound, RestClient::ServerBrokeConnection => e
          log_exception(e)
        rescue RestClient::InternalServerError, RestClient::ExceptionWithResponse, RestClient::Exception, Errno::ECONNREFUSED => e
          log_exception(e)
          retries ||= 0
          if retries < max_retries
            retries += 1
            sleep(15)
            print "Retrying!"
            retry
          end
        rescue JSON::ParserError => e
          log_exception(e)
        end

        def check_date?(from_date, to_date)
          (to_date - from_date).to_i / SECONDS_IN_A_DAY >= 90
        end
      end
    end
  end
end
