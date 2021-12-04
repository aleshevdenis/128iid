# frozen_string_literal: true

require "json"

module Kenna
  module 128iid
    module AquaHelper
      def aqua_get_token(aqua_url, username, password)
        print_debug "Getting Auth Token"
        aqua_auth_api = "http://#{aqua_url}/api/v1/login"
        # auth_headers = { "content-type" => "application/json",
        #            "accept" => "application/json" }
        # auth_body = { "id" => "administrator",
        #              "password" => "My@rvgicmx1" }

        @headers = { "Content-Type" => "application/json" }
        payload = {
          "id": username.to_s,
          "password": password.to_s
        }

        begin
          auth_response = http_post(aqua_auth_api, @headers, payload.to_json)
          auth_json = JSON.parse(auth_response.body)

          auth_json["token"]
        rescue JSON::ParserError
          print_error "Unable to process Auth Token response!"
        rescue StandardError => e
          print_error "Failed to retrieve Auth Token #{e.message}"
        end
      end

      def aqua_get_vuln(aqua_url, token, pagesize, pagenum)
        print_debug "Getting All Image Vulnerabilities"
        aqua_query_api = "http://#{aqua_url}/api/v2/risks/vulnerabilities?pagesize=#{pagesize}&page=#{pagenum}"
        puts "finding #{aqua_query_api}"
        @headers = { "Content-Type" => "application/json",
                     "accept" => "application/json",
                     "Authorization" => "Bearer #{token}" }

        response = http_get(aqua_query_api, @headers)
        return nil unless response

        begin
          json = JSON.parse(response.body)
        rescue JSON::ParserError
          print_error "Unable to process Vulnerabilities response!"
        end

        json["result"]
      end

      def aqua_get_containers(aqua_url, token, pagesize, pagenum)
        print_debug "Getting All Containers"
        aqua_cont_api = "http://#{aqua_url}/api/v2/containers?pagesize=#{pagesize}&page=#{pagenum}"
        puts "finding #{aqua_cont_api}"
        @headers = { "Content-Type" => "application/json",
                     "accept" => "application/json",
                     "Authorization" => "Bearer #{token}" }

        response = http_get(aqua_cont_api, @headers)
        return nil unless response

        begin
          json = JSON.parse(response.body)
        rescue JSON::ParserError
          print_error "Unable to process Containers response!"
        end

        json["result"]
      end

      def aqua_get_vuln_for_container(aqua_url, token, image, pagesize, pagenum)
        print_debug "Getting Vulnerabilities for a Container image"
        aqua_cont_img_api = "http://#{aqua_url}/api/v2/risks/vulnerabilities?image_name=#{image}&pagesize=#{pagesize}&page=#{pagenum}"
        puts "finding #{aqua_cont_img_api}"
        @headers = { "Content-Type" => "application/json",
                     "accept" => "application/json",
                     "Authorization" => "Bearer #{token}" }

        response = http_get(aqua_cont_img_api, @headers)
        return nil unless response

        begin
          json = JSON.parse(response.body)
        rescue JSON::ParserError
          print_error "Unable to process Image vulnerabilities for Containers response!"
        end

        json["result"]
      end
    end
  end
end
