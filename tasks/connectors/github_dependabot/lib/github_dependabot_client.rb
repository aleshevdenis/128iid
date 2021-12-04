# frozen_string_literal: true

module Kenna
  module 128iid
    module GithubDependabotModule
      class GithubDependabotClient
        class ApiError < StandardError; end

        def initialize(organization_name, github_token)
          @github_token = github_token
          @organization_name = organization_name
          @endpoint = "https://api.github.com/graphql"
          @headers = { "content-type": "application/json", "Authorization": "Bearer #{github_token}" }
        end

        def security_advisory_response
          response = http_post(@endpoint, @headers, query(security_advisory_query, organization_name: @organization_name))
          raise ApiError, "Unable to retrieve last scheduled scan, please check credentials" unless response

          JSON.parse(response)["data"]["organization"]["repositories"]["nodes"]
        end

        private

        def query(string, params = {})
          query = { query: string, variables: params }
          query.to_json
        end

        def security_advisory_query
          "query($organization_name: String!) {
          organization(login: $organization_name) {
            repositories(orderBy: {field: UPDATED_AT, direction: DESC}, first: 50) {
              nodes {
              name
                vulnerabilityAlerts(last: 50) {
                  nodes {
                    id
                    securityAdvisory {
                      description
                      cvss {
                        score
                      }
                      severity
                      identifiers {
                        type
                        value
                      }
                      summary
                      vulnerabilities(last: 50) {
                        nodes {
                          package {
                            name
                          }
                          severity
                          firstPatchedVersion {
                            identifier
                          }
                        }
                      }
                    }
                  }
                }
              }
            }
          }
        }"
        end
      end
    end
  end
end
