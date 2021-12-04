# frozen_string_literal: true

module Kenna
  module 128iid
    module MSDefenderTvmHelper
      @client_id = nil
      @tenant_id = nil
      @client_secret = nil
      @tvm_query_api = nil
      @tvm_oath_url = nil
      @token = nil
      @uploaded_files = nil
      @file_cleanup = nil
      @batch_page_size = nil
      @tvm_page_size = nil

      def tvm_get_machines(page_param = nil)
        print_debug "Getting machines"
        tvm_get_auth_token if @token.nil?

        url = if page_param.nil?
                "#{@tvm_query_api}/api/v1.0/machines?$orderby=id"
              # url = "#{url}&#{page_param}" if !page_param.nil?
              else
                page_param
              end
        print_debug "url = #{url}"
        begin
          headers = { "Content-Type" => "application/json", "Accept" => "application/json", "Authorization" => "Bearer #{@token}", "accept-encoding" => "identity" }
          response = http_get(url, headers, 1)
          if !response.code == 200
            response = nil
            raise "unauthorized"
          end
        rescue StandardError
          tvm_get_auth_token
          retry
        end
        return nil unless response

        begin
          json = JSON.parse(response.body)
        rescue JSON::ParserError
          print_error "Unable to process response!"
        end

        json
      end

      def tvm_get_vulns(page_param = nil)
        print_debug "Getting vulns"
        tvm_get_auth_token if @token.nil?

        url = if page_param.nil?
                "#{@tvm_query_api}/api/machines/SoftwareVulnerabilitiesByMachine?pageSize=#{@tvm_page_size}"
              else
                page_param
              end
        print_debug "url = #{url}"
        begin
          headers = { "content-type" => "application/json", "accept" => "application/json", "Authorization" => "Bearer #{@token}", "accept-encoding" => "identity" }
          response = http_get(url, headers, 1)
          if !response.code == 200
            response = nil
            raise "unauthorized"
          end
        rescue StandardError
          tvm_get_auth_token
          retry
        end
        return nil unless response

        begin
          json = JSON.parse(response.body)
        rescue JSON::ParserError
          print_error "Unable to process response!"
        end

        json
      end

      def valid_auth_token?
        tvm_get_auth_token if @token.nil?

        !@token.nil?
      end

      def tvm_get_auth_token
        print_debug "Getting token"
        oauth_url = "https://#{@tvm_oath_url}/#{@tenant_id}/oauth2/token"
        print_debug oauth_url
        headers = { "content-type" => "application/x-www-form-urlencoded" }
        mypayload = {
          "resource" => @tvm_query_api,
          "client_id" => @client_id.to_s,
          "client_secret" => @client_secret.to_s,
          "grant_type" => "client_credentials"
        }
        print_debug "oauth_url = #{oauth_url}"
        response = http_post(oauth_url, headers, mypayload)
        return nil unless response

        begin
          json = JSON.parse(response.body)
        rescue JSON::ParserError
          print_error "Unable to process response!"
        end

        @token = json.fetch("access_token")
      end

      def set_client_data(tenant_id, client_id, secret, tvm_query_api, tvm_oath_url, tvm_page_size)
        @tvm_oath_url = tvm_oath_url
        @tenant_id = tenant_id
        @client_id = client_id
        @client_secret = secret
        @tvm_query_api = "https://#{tvm_query_api}"
        @tvm_page_size = tvm_page_size
      end
    end
  end
end
