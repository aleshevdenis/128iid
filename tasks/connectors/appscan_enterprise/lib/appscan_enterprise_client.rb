# frozen_string_literal: true

module Kenna
  module 128iid
    module AppScanEnterprise
      class Client
        class ApiError < StandardError; end

        def initialize(host, port, user_id, password, application, issue_severities, page_size, days_back, verify_ssl)
          # TODO: We are guessing too much about the base path here.
          @base_path = "https://#{host}#{":#{port}" if port}/ase/api"
          @user_id = user_id
          @password = password
          @application = application
          @issue_severities = issue_severities
          @page_size = page_size
          @days_back = days_back unless days_back.zero?
          @verify_ssl = verify_ssl
          @headers = { "content-type": "application/json", "accept": "application/json" }
        end

        def login
          payload = {
            "userId": @user_id,
            "password": @password,
            "featureKey": "AppScanEnterpriseUser"
          }.to_json
          response = http_post("#{@base_path}/login", @headers, payload, 3, @verify_ssl)
          raise ApiError, "Unable to login, please check credentials" unless response

          @asc_session_id = response.cookies["asc_session_id"]
          @session_id = JSON.parse(response)["sessionId"]
        end

        def logout
          return unless @session_id

          response = http_get("#{@base_path}/logout", request_headers, 0, @verify_ssl)
          print_error "Unable to logout" unless response
        end

        def paginated_issues(&block)
          return to_enum(__method__) unless block

          range_start = 0
          range_end = @page_size - 1
          loop do
            response = http_get("#{@base_path}/issues?query=#{issues_query}&compactResponse=false", request_headers("Range": "items=#{range_start}-#{range_end}"), 3, @verify_ssl)
            raise ApiError, "Unable to retrieve issues." unless response

            issues = JSON.parse(response)
            block.yield(issues, range_start)
            break if issues.count < (range_end - range_start + 1)

            range_start += @page_size
            range_end += @page_size
          end
        end

        private

        def issues_query
          query = +"Application Name=#{@application}"
          @issue_severities.foreach do |severity|
            query << ",Severity=#{severity}"
          end
          query << ",Date Created=#{Date.today - @days_back}\\,#{Date.today}" if @days_back
          query
        end

        # RestClient, which is the gem used by 128iid to make http requests, does some magic with headers under the hood.
        # If you pass a symbolized header it converts it. For instance, passing :asc_xsrf_token would be converted to "Asc-Xsrf-Token".
        # To avoid this we send stringify_keys to the headers hash.
        # There is something special about the cookies too. Cookies should be passed in the headers hash using the :cookies Symbol as key.
        # Passing cookies using "cookies" String as key would generate an invalid cookies header.
        def request_headers(**additional_headers)
          cookies = { asc_session_id: @asc_session_id }
          request_headers = @headers.dup
          request_headers.merge!({ asc_xsrf_token: @session_id, sessionId: @session_id })
          request_headers.merge!(additional_headers)
          request_headers.stringify_keys!
          request_headers[:cookies] = cookies
          request_headers
        end
      end
    end
  end
end
