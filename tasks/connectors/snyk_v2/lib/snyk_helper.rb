# frozen_string_literal: true

module Kenna
  module 128iid
    module SnykHelper
      def snyk_get_orgs(token)
        print "Getting list of orgs"
        snyk_query_api = "https://snyk.io/api/v1/orgs"
        response = http_get(snyk_query_api, headers(token))
        return nil unless response

        json = parse_json(response.body)
        json["orgs"]
      end

      def snyk_get_projects(token, org)
        print "Getting list of projects"
        snyk_query_api = "https://snyk.io/api/v1/org/#{org}/projects"
        response = http_get(snyk_query_api, headers(token))
        return nil unless response

        json = parse_json(response.body)
        json["projects"]
      end

      def snyk_get_issues(token, perpage, search_json, pagenum, from_date, to_date)
        print "Getting issues"
        snyk_query_api = "https://snyk.io/api/v1/reporting/issues?perPage=#{perpage}&page=#{pagenum}&from=#{from_date}&to=#{to_date}"
        print_debug("Get issues query: #{snyk_query_api}")
        response = http_post(snyk_query_api, headers(token), search_json)
        return nil unless response

        json = parse_json(response.body)
        json["results"]
      end

      private

      def headers(token)
        { "content-type" => "application/json",
          "accept" => "application/json",
          "Authorization" => "token #{token}" }
      end

      def parse_json(json_string)
        JSON.parse(json_string)
      rescue JSON::ParserError
        print_error "Unable to process response!"
        {}
      end
    end
  end
end
