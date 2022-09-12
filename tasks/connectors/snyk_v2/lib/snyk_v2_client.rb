# frozen_string_literal: true

module Kenna
  module 128iid
    module SnykV2
      class SnykV2Client
        class ApiError < StandardError; end

        HOST = "https://snyk.io"

        def initialize(token)
          @token = token
          @headers = {
            "content-type" => "application/json",
            "accept" => "application/json",
            "Authorization" => "token #{token}"
          }
        end

        def snyk_get_orgs
          print "Getting list of orgs"

          response = http_get("#{HOST}/api/v1/orgs", @headers)
          raise ApiError, "Unable to retrieve submissions, please check credentials." unless response

          JSON.parse(response)["orgs"]
        end

        def snyk_get_projects(org)
          print "Getting list of projects"

          response = http_get("#{HOST}/api/v1/org/#{org}/projects", @headers)
          raise ApiError, "Unable to retrieve submissions, please check credentials." unless response

          JSON.parse(response)["projects"]
        end

        def snyk_get_issues(per_page, search_json, page_num, from_date, to_date)
          print "Getting issues"
          snyk_query_api = "https://snyk.io/api/v1/reporting/issues?perPage=#{per_page}&page=#{page_num}&from=#{from_date}&to=#{to_date}"
          print_debug("Get issues query: #{snyk_query_api}")

          response = http_post(snyk_query_api, @headers, search_json)
          raise ApiError, "Unable to retrieve submissions, please check credentials." unless response

          JSON.parse(response)["results"]
        end
      end
    end
  end
end
