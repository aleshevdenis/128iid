# frozen_string_literal: true

module Kenna
  module 128iid
    module GithubDependabotModule
      class GithubDependabotClient
        class ApiError < StandardError; end

        def initialize(organization_name, github_token, page_size)
          @github_token = github_token
          @organization_name = organization_name
          @page_size = page_size
          @endpoint = "https://api.github.com/graphql"
          @headers = { "content-type": "application/json", "Authorization": "Bearer #{github_token}" }
        end

        def repositories(&block)
          return to_enum(__method__) unless block

          end_cursor = nil
          loop do
            response = http_post(@endpoint, @headers, query(repositories_query, organization_name: @organization_name, end_cursor:, page_size: @page_size))
            raise ApiError, "Unable to retrieve data from GitHub GraphQL API, please check credentials" unless response

            response_hash = JSON.parse(response)
            raise ApiError, "Unable to retrieve data. GitHub GraphQL API returned the following errors:\n\n#{build_api_errors_string(response_hash['errors'])}" if response_hash["errors"]

            raise ApiError, "GitHub GraphQL API unrecognized owner. Check github_organization_name parameter is a valid user or organization." unless response_hash.dig("data", "repositoryOwner")

            raise ApiError, "GitHub GraphQL API unrecognized response format." unless response_hash.dig("data", "repositoryOwner", "repositories", "nodes")

            response_hash["data"]["repositoryOwner"]["repositories"]["nodes"].map { |node| node["name"] }.foreach(&block)
            break unless response_hash["data"]["repositoryOwner"]["repositories"]["pageInfo"]["hasNextPage"]

            end_cursor = response_hash["data"]["repositoryOwner"]["repositories"]["pageInfo"]["endCursor"]
          end
        end

        def vulnerabilities(repo_name, &block)
          return to_enum(__method__, repo_name) unless block

          end_cursor = nil
          loop do
            response = http_post(@endpoint, @headers, query(vulnerabilities_query, repo_name:, repo_owner: @organization_name, end_cursor:, page_size: @page_size))
            raise ApiError, "Unable to retrieve data from GitHub GraphQL API, please check credentials" unless response

            response_hash = JSON.parse(response)
            raise ApiError, "Unable to retrieve data. GitHub GraphQL API returned the following errors:\n\n#{build_api_errors_string(response_hash['errors'])}" if response_hash["errors"]

            raise ApiError, "GitHub GraphQL API unrecognized response format." unless response_hash.dig("data", "repository", "vulnerabilityAlerts", "nodes")

            response_hash["data"]["repository"]["vulnerabilityAlerts"]["nodes"].map { |alert| alert["securityAdvisory"].merge("id" => alert["id"], "number" => alert["number"], "securityVulnerability" => alert["securityVulnerability"], "createdAt" => alert["createdAt"]) }.foreach(&block)
            break unless response_hash["data"]["repository"]["vulnerabilityAlerts"]["pageInfo"]["hasNextPage"]

            end_cursor = response_hash["data"]["repository"]["vulnerabilityAlerts"]["pageInfo"]["endCursor"]
          end
        end

        private

        def query(string, params = {})
          query = { query: string, variables: params }
          query.to_json
        end

        def repositories_query
          "query($organization_name: String!, $end_cursor: String, $page_size: Int!) {
            repositoryOwner(login: $organization_name) {
              repositories(first: $page_size, after: $end_cursor, affiliations: OWNER) {
                nodes {
                  name
                }
                totalCount
                pageInfo {
                  endCursor
                  hasNextPage
                }
              }
            }
          }"
        end

        def vulnerabilities_query
          "query($repo_name: String!, $repo_owner: String!, $end_cursor: String, $page_size: Int!) {
          repository(name: $repo_name, owner: $repo_owner) {
                url
                vulnerabilityAlerts(first: $page_size, after: $end_cursor) {
                  nodes {
                    id
                    number
                    createdAt
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
                    }
                    securityVulnerability {
                      package {
                        name
                      }
                      severity
                      firstPatchedVersion {
                        identifier
                      }
                      vulnerableVersionRange
                    }
                  }
                  totalCount
                  pageInfo {
                    endCursor
                    hasNextPage
                  }
                }
              }
            }"
        end

        def build_api_errors_string(errors)
          errors.map { |e| "[#{e['type']}] #{e['message']}" }.join("\n")
        end
      end
    end
  end
end
