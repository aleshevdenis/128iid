# frozen_string_literal: true

module Kenna
  module 128iid
    module WizV2
      class Client
        class ApiError < StandardError; end

        def initialize(client_id, client_secret, auth_endpoint, api_host, page_size, days_back, vuln_object_types, severity, issue_status)
          @api_host = api_host
          @page_size = page_size
          @days_back = days_back
          @vuln_object_types = vuln_object_types
          @severity = severity
          @issue_status = issue_status
          auth_token = auth(client_id, client_secret, auth_endpoint)
          @headers = { "content-type": "application/json", "accept": "application/json", "Authorization": "Bearer #{auth_token}" }
        end

        def paged_issues(&block)
          return to_enum(__method__) unless block

          next_page = nil
          loop do
            response = api_request(query(issues_query, issues_params(next_page)))
            yield(response["data"]["issues"])
            break unless response["data"]["issues"]["pageInfo"]["hasNextPage"]

            next_page = response["data"]["issues"]["pageInfo"]["endCursor"]
          end
        end

        def paged_vulns(&block)
          return to_enum(__method__) unless block

          next_page = nil
          loop do
            response = api_request(query(vulns_query, vulns_params(next_page)))
            yield(response["data"]["vulnerabilityFindings"])
            break unless response["data"]["vulnerabilityFindings"]["pageInfo"]["hasNextPage"]

            next_page = response["data"]["vulnerabilityFindings"]["pageInfo"]["endCursor"]
          end
        end

        private

        def auth(client_id, client_secret, auth_endpoint)
          headers = { "content-type" => "application/x-www-form-urlencoded" }
          payload = "grant_type=client_credentials&client_id=#{client_id}&client_secret=#{client_secret}&audience=beyond-api"
          response = http_post(auth_endpoint, headers, payload)
          raise ApiError, "Unable to get authorization token. Please check credentials and wiz_auth_host." unless response

          JSON.parse(response).fetch("access_token")
        end

        def query(string, params = {})
          query = { query: string, variables: params }
          query.to_json
        end

        def api_request(api_query)
          response = http_post(@api_host, @headers, api_query)
          raise ApiError, "Unable to retrieve query result." unless response

          response_json = JSON.parse(response)
          raise ApiError, response_json["errors"].map { |e| e["message"] }.join(" / / ") if response_json.key?("errors")

          response_json
        end

        def issues_query
          "query IssuesTable(
            $filterBy: IssueFilters
            $first: Int
            $after: String
            $orderBy: IssueOrder
          ) {
            issues(
              filterBy: $filterBy
              first: $first
              after: $after
              orderBy: $orderBy
            ) {
              nodes {
                ...IssueDetails
              }
              pageInfo {
                hasNextPage
                endCursor
              }
              totalCount
              informationalSeverityCount
              lowSeverityCount
              mediumSeverityCount
              highSeverityCount
              criticalSeverityCount
              uniqueEntityCount
            }
          }

          fragment IssueDetails on Issue {
            id
            control {
              id
              name
              query
            }
            createdAt
            updatedAt
            projects {
              id
              name
              slug
              businessUnit
              riskProfile {
                businessImpact
              }
            }
            status
            severity
            entity {
              id
              name
              type
            }
            entitySnapshot {
              id
              type
              nativeType
              name
              subscriptionId
              subscriptionExternalId
              subscriptionName
              resourceGroupId
              resourceGroupExternalId
              region
              cloudPlatform
              cloudProviderURL
              providerId
              status
              tags
              subscriptionTags
            }
            note
            serviceTicket {
              externalId
              name
              url
            }
            serviceTickets {
              externalId
              name
              url
              action {
                id
                type
              }
            }
          }"
        end

        def issues_params(after = nil)
          params = {
            first: @page_size,
            filterBy: {}
          }
          params[:after] = after if after
          params[:filterBy][:createdAt] = { after: (Date.today - @days_back).to_datetime } if @days_back
          params[:filterBy][:status] = @issue_status if @issue_status
          params[:filterBy][:severity] = @severity if @severity

          params
        end

        def vulns_query
          "query vulnerabilityFindings(
            $first: Int
            $after: String
            $filterBy: VulnerabilityFindingFilters
            ) {
            vulnerabilityFindings(
            first: $first
            after: $after
            filterBy: $filterBy
            ) {
            nodes {
            id
            firstDetectedAt
            lastDetectedAt
            name
            CVEDescription
            description
            CVSSSeverity
            score
            exploitabilityScore
            impactScore
            vendorSeverity
            remediation
            version
            fixedVersion
            link
            locationPath

            vulnerableAsset {
                ... on VulnerableAssetBase {
                id
                type
                name
                region
                providerUniqueId
                cloudProviderURL
                cloudPlatform
                status
                subscriptionExternalId
                tags
                }
                ... on VulnerableAssetVirtualMachine {
                operatingSystem
                ipAddresses
                }
                ... on VulnerableAssetContainerImage {
                imageId
                }
                ... on VulnerableAssetServerless {
                runtime
                }
            }
            },
            totalCount
            pageInfo {
            endCursor
            hasNextPage
            }
          }
        }"
        end

        def vulns_params(after = nil)
          params = {
            first: @page_size,
            filterBy: {}
          }
          params[:after] = after if after
          params[:filterBy][:createdAfter] = (Date.today - @days_back).to_datetime if @days_back
          params[:filterBy][:assetType] = @vuln_object_types if @vuln_object_types
          params[:filterBy][:vendorSeverity] = @severity if @severity

          params
        end
      end
    end
  end
end
