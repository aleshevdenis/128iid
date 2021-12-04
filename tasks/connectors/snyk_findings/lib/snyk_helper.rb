# frozen_string_literal: true

module Kenna
  module 128iid
    module SnykHelper
      def snyk_get_orgs(token)
        print "Getting list of orgs"
        snyk_query_api = "https://snyk.io/api/v1/orgs"
        headers = { "content-type" => "application/json",
                    "accept" => "application/json",
                    "Authorization" => "token #{token}" }

        response = http_get(snyk_query_api, headers)
        return nil unless response

        begin
          json = JSON.parse(response.body)
        rescue JSON::ParserError
          print_error "Unable to process response!"
        end

        json["orgs"]
      end

      def snyk_get_projects(token, org)
        print "Getting list of projects"
        snyk_query_api = "https://snyk.io/api/v1/org/#{org}/projects"
        headers = { "content-type" => "application/json",
                    "accept" => "application/json",
                    "Authorization" => "token #{token}" }

        response = http_get(snyk_query_api, headers)
        return nil unless response

        begin
          json = JSON.parse(response.body)
        rescue JSON::ParserError
          print_error "Unable to process response!"
        end

        json["projects"]
      end

      def snyk_get_issues(token, perpage, search_json, pagenum, from_date, to_date)
        print "Getting issues"
        snyk_query_api = "https://snyk.io/api/v1/reporting/issues?perPage=#{perpage}&page=#{pagenum}&from=#{from_date}&to=#{to_date}"
        puts "finding #{snyk_query_api}"
        headers = { "content-type" => "application/json",
                    "accept" => "application/json",
                    "Authorization" => "token #{token}" }

        response = http_post(snyk_query_api, headers, search_json)
        return nil unless response

        begin
          json = JSON.parse(response.body)
        rescue JSON::ParserError
          print_error "Unable to process response!"
        end

        json["results"]
      end
    end
  end
end
