# frozen_string_literal: true

module Kenna
  module 128iid
    module MSDefenderAtpHelper
      @client_id = nil
      @tenant_id = nil
      @client_secret = nil
      @atp_query_api = nil
      @atp_oath_url = nil
      @token = nil
      @uploaded_files = nil
      @file_cleanup = nil

      def connector_upload(output_dir, filename, kenna_connector_id, kenna_api_host, kenna_api_key, max_retries = 3)
        ### Write KDI format
        kdi_output = { skip_autoclose: false, assets: @paged_assets, vuln_defs: @vuln_defs }
        write_file output_dir, filename, JSON.pretty_generate(kdi_output)
        print_good "Output is available at: #{filename}"

        ### Finish by uploading if we're all configured
        if kenna_connector_id && kenna_api_host && kenna_api_key
          print_good "Attempting to upload to Kenna API at #{kenna_api_host}"
          response_json = upload_file_to_kenna_connector kenna_connector_id, kenna_api_host, kenna_api_key, "#{output_dir}/#{filename}", false, max_retries
          filenum = response_json.fetch("data_file")
          @uploaded_files = [] if @uploaded_files.nil?
          @uploaded_files << filenum
          File.delete("#{output_dir}/#{filename}") if @file_cleanup
        end
        response_json
      end

      def connector_kickoff(kenna_connector_id, kenna_api_host, kenna_api_key, max_retries = 3)
        ### Finish by uploading if we're all configured
        return unless kenna_connector_id && kenna_api_host && kenna_api_key

        print_good "Attempting to run Kenna Connector at #{kenna_api_host}"
        run_files_on_kenna_connector kenna_connector_id, kenna_api_host, kenna_api_key, @uploaded_files, max_retries
      end

      def atp_get_machines(page_param = nil)
        print_debug "Getting machines"
        atp_get_auth_token if @token.nil?

        url = if page_param.nil?
                "#{@atp_query_api}/api/machines?$orderby=id"
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
          atp_get_auth_token
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

      def atp_get_vulns(page_param = nil)
        print_debug "Getting vulns"
        atp_get_auth_token if @token.nil?

        url = if page_param.nil?
                "#{@atp_query_api}/api/vulnerabilities/machinesVulnerabilities?$orderby=machineId"
              # url = "#{url}&#{page_param}" if !page_param.nil?
              else
                page_param
              end
        # ComputerDnsName, LastSeen, HealthStatus, OsPlatform,
        print_debug "url = #{url}"
        begin
          headers = { "content-type" => "application/json", "accept" => "application/json", "Authorization" => "Bearer #{@token}", "accept-encoding" => "identity" }
          response = http_get(url, headers, 1)
          if !response.code == 200
            response = nil
            raise "unauthorized"
          end
        rescue StandardError
          atp_get_auth_token
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
        atp_get_auth_token if @token.nil?

        !@token.nil?
      end

      def atp_get_auth_token
        print_debug "Getting token"
        oauth_url = "https://#{@atp_oath_url}/#{@tenant_id}/oauth2/token"
        headers = { "content-type" => "application/x-www-form-urlencoded" }
        mypayload = {
          "resource" => @atp_query_api,
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

      def set_client_data(tenant_id, client_id, secret, atp_query_api, atp_oath_url, file_cleanup)
        @atp_oath_url = atp_oath_url
        @tenant_id = tenant_id
        @client_id = client_id
        @client_secret = secret
        @atp_query_api = "https://#{atp_query_api}"
        @file_cleanup = file_cleanup
      end
    end
  end
end
