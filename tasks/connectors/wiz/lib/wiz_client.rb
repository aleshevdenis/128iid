# frozen_string_literal: true

require "open-uri"

module Kenna
  module 128iid
    module Wiz
      class WizClient
        def initialize(client_id, client_secret, output_dir, auth_endpoint, api_endpoint)
          # @api_endpoint = "eu3.test"
          @api_call_url = "https://api.#{api_endpoint}.wiz.io/graphql"
          @auth_endpoint = "https://#{auth_endpoint}"
          @output_directory = output_dir
          token = request_wiz_api_token(client_id, client_secret)
          @valid_token = !token.nil?
          @header = { "content-type" => "application/json", "Authorization" => "Bearer #{token}" }
          @get_subs_variables = "{ \"first\" : 500 }"
          # @CreateReport_variables = {"input": {"name": "", "type": "VULNERABILITIES", "params": {"subscriptionIds": [""], "projectId": "*"}}}
          @get_subs_query = "query CloudAccountsPage(
              $filterBy: CloudAccountFilters
              $after: String
            ) {
              cloudAccounts(filterBy: $filterBy, first: 500, after: $after) {
                  nodes {
                    id
                    name
                    externalId
                    cloudProvider
                    status
                    firstScannedAt
                    lastScannedAt
                    virtualMachineCount
                    containerCount
                    sourceConnectors {
                      id
                      name
                      status
                      errorCode
                      lastActivity
                    }
                    linkedProjects {
                      id
                      name
                      slug
                      riskProfile {
                        businessImpact
                      }
                    }
                    connectorIssues {
                      connector {
                        id
                        name
                      }
                      issues {
                        issueIdentifier
                        description
                        severity
                        impact
                        remediation
                        context
                      }
                    }
                  }
                  pageInfo {
                    hasNextPage
                    endCursor
                  }
                  totalCount
                }
              }".delete("\n")

          @reports_query = "query ReportsTable($filterBy: ReportFilters, $after: String) {
              reports(first: 500, after: $after, filterBy: $filterBy) {
                nodes {
                  id
                  name
                  type {
                    id
                    name
                  }
                  parameters {
                    query
                    subscriptions {
                      id
                      name
                      type
                    }
                    entities {
                      id
                      name
                      type
                    }
                  }
                  lastRun {
                    ...LastRunDetails
                  }
                }
                pageInfo {
                  hasNextPage
                  endCursor
                }
                totalCount
              }
            }

            fragment LastRunDetails on ReportRun {
              id
              status
              failedReason
              runAt
              progress
              results {
                ... on ReportRunResultsBenchmark {
                  errorCount
                  passedCount
                  failedCount
                  scannedCount
                }
                ... on ReportRunResultsGraphQuery {
                  resultCount
                  entityCount
                }
                ... on ReportRunResultsNetworkExposure {
                  scannedCount
                  publiclyAccessibleCount
                }
                ... on ReportRunResultsConfigurationFindings {
                  findingsCount
                }
              }
            }".delete("\n")

          @report_download_url_query = "query ReportDownloadUrl($reportId: ID!) {
                report(id: $reportId) {
                  lastRun {
                    url
                  }
                }
              }".delete("\n")

          @rerun_report_query = "mutation RerunReport($reportId: ID!) {
                rerunReport(input: {id: $reportId}) {
                  report {
                    id
                    lastRun {
                      ...LastRunDetails
                    }
                  }
                }
              }

              fragment LastRunDetails on ReportRun {
                id
                status
                failedReason
                runAt
                progress
                results {
                  ... on ReportRunResultsBenchmark {
                    errorCount
                    passedCount
                    failedCount
                    scannedCount
                  }
                  ... on ReportRunResultsGraphQuery {
                    resultCount
                    entityCount
                  }
                  ... on ReportRunResultsNetworkExposure {
                    scannedCount
                    publiclyAccessibleCount
                  }
                  ... on ReportRunResultsConfigurationFindings {
                    findingsCount
                  }
                }
              }".delete("\n")

          @delete_report_query = "mutation DeleteReport($reportId: ID!) {
                deleteReport(input: { id: $reportId }) {
                  _stub
                }
              }".delete("\n")

          @create_report_query = "mutation CreateReport($input: CreateReportInput!) {
                createReport(input: $input) {
                  report {
                    id
                  }
                }
              }".delete("\n")
        end

        def valid_token?
          @valid_token
        end

        # Methods used in this script
        # Used for creating strings from the variables hash. String is used to update query string
        def transform_hash_to_string(hash)
          "{#{hash.map { |k, v| "\"#{k}\":#{v}" }.join ', '}}"
          # return "{#{hash.map {|h| h.join ':'}.join ', '}}"
        end

        # will this to_json method work well? It seems to better than the custom one for nexted variables
        # print_debug create_variables.to_json
        # {"input":{"name":"","type":"VULNERABILITIES","params":{"subscriptionIds":[""],"projectId":"*"}}}

        # Method for downloading the actual reports
        def download_file(url, filename)
          IO.copy_stream(URI.parse(url).open, "#{@output_directory}/#{filename}")
        end

        # Method for generating token from client ID and secret
        def request_wiz_api_token(client_id, client_secret)
          # Retrieve an OAuth access token to be used against Wiz API"
          headers = { "content-type" => "application/x-www-form-urlencoded" }
          payload = "grant_type=client_credentials&client_id=#{client_id}&client_secret=#{client_secret}&audience=beyond-api"
          auth_url = "#{@auth_endpoint}.wiz.io/oauth/token"
          access_code_call = http_post(auth_url, headers, payload)
          return unless access_code_call

          JSON.parse(access_code_call)["access_token"]
        end

        # Various Wiz methods.
        def subs
          g_query = "#{@get_subs_query}\",\"variables\":#{@get_subs_variables},\"operationName\":\"CloudAccountsPage\"}"
          payload = "{\"query\":\"#{g_query}"
          result = http_post(@api_call_url, @header, payload)
          subs_result = JSON.parse(result)["data"]["cloudAccounts"]["nodes"]
          page_info = JSON.parse(result)["data"]["cloudAccounts"]["pageInfo"]
          while page_info["hasNextPage"]
            variables[:after] = "\"#{page_info['endCursor']}\""
            g_query = "#{@get_subs_query}\",\"variables\":#{transform_hash_to_string(@get_subs_variables)},\"operationName\":\"CloudAccountsPage\"}"
            payload = "{\"query\":\"#{g_query}"
            result = http_post(@api_call_url, @header, payload)
            subs_result += JSON.parse(result)["data"]["reports"]["nodes"]
            page_info = JSON.parse(result)["data"]["cloudAccounts"]["pageInfo"]
          end
          subs_result
        end

        def reports(reports_variables = { "filterBy": "{\"type\":[\"VULNERABILITIES\"]}" })
          g_query = "#{@reports_query}\",\"variables\":#{transform_hash_to_string(reports_variables)},\"operationName\":\"ReportsTable\"}"
          payload = "{\"query\":\"#{g_query}"
          result = http_post(@api_call_url, @header, payload)
          report_result = JSON.parse(result)["data"]["reports"]["nodes"]
          page_info = JSON.parse(result)["data"]["reports"]["pageInfo"]
          while page_info["hasNextPage"]
            reports_variables[:after] = "\"#{page_info['endCursor']}\""
            g_query = "#{@reports_query}\",\"variables\":#{transform_hash_to_string(reports_variables)},\"operationName\":\"ReportsTable\"}"
            payload = "{\"query\":\"#{g_query}"
            result = http_post(@api_call_url, @header, payload)
            report_result += JSON.parse(result)["data"]["reports"]["nodes"]
            page_info = JSON.parse(result)["data"]["reports"]["pageInfo"]
          end
          report_result
        end

        def report_download_url(report_id)
          variables = { "reportId": "\"#{report_id}\"" }
          g_query = "#{@report_download_url_query}\",\"variables\":#{transform_hash_to_string(variables)},\"operationName\":\"ReportDownloadUrl\"}"
          payload = "{\"query\":\"#{g_query}"
          # print_debug "reportdownloadurl payload --> #{payload}" # for debugging
          result = http_post(@api_call_url, @header, payload)
          print_debug "reportdownloadurl result --> #{result}" # for debugging
          JSON.parse(result)
        end

        def rerun_report(report_id)
          variables = { "reportId": "\"#{report_id}\"" }
          g_query = "#{@rerun_report_query}\",\"variables\":#{transform_hash_to_string(variables)},\"operationName\":\"RerunReport\"}"
          payload = "{\"query\":\"#{g_query}"
          http_post(@api_call_url, @header, payload)
        end

        def delete_report(report_id)
          variables = { "reportId": "\"#{report_id}\"" }
          g_query = "#{@delete_report_query}\",\"variables\":#{transform_hash_to_string(variables)},\"operationName\":\"DeleteReport\"}"
          payload = "{\"query\":\"#{g_query}"
          http_post(@api_call_url, @header, payload)
        end

        def create_report(days_used_regenerate_report, report_asset_object_type, vulnerabilities_since)
          variables = { "input": { "name": "", "type": "VULNERABILITIES", "params": { "subscriptionIds": [""], "projectId": "*" } } }

          report_list = reports({ "filterBy": "{\"type\":[\"VULNERABILITIES\"]}" })

          subs.foreach do |s|
            print_debug "Focusing on #{s['cloudProvider']} Subscription #{s['externalId']}"
            cve_report_exists = false
            report_asset_object_type.foreach do |aot|
              gen_report_name = "CVE Report for Subscription #{s['externalId']} #{aot}"
              gen_report_name_for_file = "CVE-Report-for-Subscription-#{s['externalId']}-#{aot}-#{DateTime.now.strftime('%Y-%m-%d')}.csv"
              print_debug "Generating report name: \"#{gen_report_name}\" to be used here"
              print_debug "Checking for CVE report \"#{gen_report_name}\" existence"
              report_names = []
              report_id = ""

              report_list.foreach do |r|
                report_names.push(r["name"])
                if r["name"] == gen_report_name
                  report_id = r["id"]
                  cve_report_exists = true
                end
              end

              # cve_report_exists if report_names.count(gen_report_name).positive? ? true : false
              if cve_report_exists == true && days_used_regenerate_report == false
                print_debug "Re-running CVE Report for #{s['cloudProvider']} Subscription \"#{s['externalId']}\", since the report exists"
                print_debug "report ID is #{report_id}"
                rerun_report(report_id)
                reports_variables = { "filterBy": "{\"search\":\"#{gen_report_name}\"}" }
                run = reports(reports_variables)
                last_run = run[0]["lastRun"]["status"]
                print_debug "Checking if report \"#{gen_report_name}\" re-run finished, so you can download"
                while last_run != "COMPLETED"
                  print_debug "Report \"#{gen_report_name}\" is still re-running and its status is #{last_run}"
                  run = reports(reports_variables)
                  last_run = run[0]["lastRun"]["status"]
                end
                print_debug "Report generation status is now #{last_run}"
                print_debug "Downloading report \"#{gen_report_name}\" with ID #{report_id}"
                url = report_download_url(report_id)["data"]["report"]["lastRun"]["url"]
                download_file(url, gen_report_name_for_file)
                print_debug "Report \"#{gen_report_name_for_file}\" downloaded."
              elsif cve_report_exists == true && days_used_regenerate_report == true
                print_debug ">>>> Deleting CVE Report for #{s['cloudProvider']} Subscription \"#{s['externalId']}\" and recreating, since \"vulnerabilities since X days (-d or --Days flag)\" was used."
                print_debug "Creating new CVE Report for #{s['cloudProvider']} Subscription \"#{s['externalId']}\""
                print_debug "report ID is #{report_id}"
                delete_report(report_id)
                subs_as_array = []
                subs_as_array.push(s["id"])
                variables[:input][:params][:subscriptionIds] = subs_as_array # look at this a little more.
                variables[:input][:name] = gen_report_name
                variables[:input][:params][:assetObjectType] = aot
                variables[:input][:params][:vulnerabilitiesSince] = vulnerabilities_since if vulnerabilities_since != ""
                g_query = "#{@create_report_query}\",\"variables\":#{variables.to_json},\"operationName\":\"CreateReport\"}"
                payload = "{\"query\":\"#{g_query}"
                create_report = http_post(@api_call_url, @header, payload)
                report_id = JSON.parse(create_report)["data"]["createReport"]["report"]["id"]
                print_debug "report ID is #{report_id}"
                reports_variables = { "filterBy": "{\"search\": \"#{gen_report_name}\"}" }
                run = reports(reports_variables)
                last_run = run[0]["lastRun"]["status"]
                print_debug "Checking if report #{gen_report_name} creation finished, so you can download"
                while last_run != "COMPLETED"
                  print_debug "Report \"#{gen_report_name}\" is still creating and its status is #{last_run}"
                  run = reports(reports_variables)
                  last_run = run[0]["lastRun"]["status"]
                end
                print_debug "Report generation status is now #{last_run}"
                print_debug "Downloading report #{gen_report_name} with ID #{report_id}"
                url = report_download_url(report_id)["data"]["report"]["lastRun"]["url"]
                download_file(url, gen_report_name_for_file)
                print_debug "Report 2 \"#{gen_report_name_for_file}\" downloaded."
              else
                print_debug "Creating new CVE Report for #{s['cloudProvider']} Subscription \"#{s['externalId']}\""
                subs_as_array = []
                subs_as_array.push(s["id"])
                variables[:input][:params][:subscriptionIds] = subs_as_array
                variables[:input][:name] = gen_report_name
                variables[:input][:params][:assetObjectType] = aot
                variables[:input][:params][:vulnerabilitiesSince] = vulnerabilities_since if vulnerabilities_since != ""
                g_query = "#{@create_report_query}\",\"variables\":#{variables.to_json},\"operationName\":\"CreateReport\"}"
                payload = "{\"query\":\"#{g_query}"
                create_report = http_post(@api_call_url, @header, payload)
                report_id = JSON.parse(create_report)["data"]["createReport"]["report"]["id"]
                reports_variables = { "filterBy": "{\"search\":\"#{gen_report_name}\"}" }
                run = reports(reports_variables)
                print_debug "run = #{run}"
                last_run = run[0]["lastRun"]["status"]
                print_debug "Checking if report \"#{gen_report_name}\" creation finished, so you can download"
                while last_run != "COMPLETED"
                  print_debug "Report \"#{gen_report_name}\" is still creating and its status is #{last_run}"
                  run = reports(reports_variables)
                  last_run = run[0]["lastRun"]["status"]
                end
                print_debug "Report generation status is now #{last_run}"
                print_debug "Downloading report \"#{gen_report_name}\" with ID #{report_id}"
                url = report_download_url(report_id)["data"]["report"]["lastRun"]["url"]
                download_file(url, gen_report_name_for_file)
                print_debug "Report 3 \"#{gen_report_name_for_file}\" downloaded."
              end
            end
          end
        end
      end
    end
  end
end
