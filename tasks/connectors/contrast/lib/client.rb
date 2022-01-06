# frozen_string_literal: true

require "json"

module Kenna
  module 128iid
    module Contrast
      class Client
        def initialize(contrast_host, contrast_port, contrast_api_key, contrast_auth_header, contrast_org_id, contrast_use_https)
          protocol = contrast_use_https ? "https://" : "http://"
          @base_url = "#{protocol}#{contrast_host}#{contrast_port.nil? ? '' : ':'}#{contrast_port}/Contrast/api/ng/#{contrast_org_id}"
          print "Base URL is #{@base_url}"
          @headers = { "Authorization" => contrast_auth_header, "API-Key" => contrast_api_key, "Content-Type" => "application/json" }
          @recs = {}
          @tags = {}
        end

        def get_vulns(tags, environments, severities, exclude_closed, offset, limit)
          quickFilter = exclude_closed ? "OPEN" : ""
          url = "#{@base_url}/orgtraces/filter?expand=application&quickFilter=#{quickFilter}&offset=#{offset}&limit=#{limit}&applicationTags=#{tags}&environments=#{environments}&severities=#{severities}&licensedOnly=true"
          response = http_get(url, @headers, 1)
          return nil if response.nil?

          body = JSON.parse response.body

          more_results = !(response.nil? || response.empty? || (offset + limit) >= body["count"])
          ceiling = [limit + offset, body["count"]].min

          print "Fetched #{ceiling} of #{body['count']} vulnerabilities"

          [body["traces"], more_results, body["count"]]
        rescue RestClient::ExceptionWithResponse => e
          print_error "Error getting vulnerabilities: #{e.message}"
        rescue SocketError => e
          print_error "Error calling API, check server address: #{e.message}"
        end

        def get_vulnerable_libraries(apps, offset, limit)
          payload = {
            quickFilter: "VULNERABLE",
            "apps": apps
          }

          url = "#{@base_url}/libraries/filter?offset=#{offset}&limit=#{limit}&sort=score&expand=skip_links%2Capps%2Cvulns%2Cstatus%2Cusage_counts"
          response = http_post(url, @headers, payload.to_json)
          return nil if response.nil?

          body = JSON.parse response.body

          more_results = !(response.nil? || response.empty? || (offset + limit) >= body["count"])
          ceiling = [limit + offset, body["count"]].min

          print "Fetched #{ceiling} of #{body['count']} libraries"

          [body["libraries"], more_results, body["count"]]
        rescue RestClient::ExceptionWithResponse => e
          print_error "Error getting vulnerable libraries for apps #{apps}: #{e}"
        end

        def get_application_ids(tags)
          url = "#{@base_url}/applications/filter/short?filterTags=#{tags}"
          response = http_get(url, @headers, 1)
          return nil if response.nil?

          temp = JSON.parse response.body
          temp["applications"]
        rescue RestClient::ExceptionWithResponse => e
          print_error "Error getting applications for tags #{tags}: #{e}"
        end

        def get_application_tags(app_id)
          if @tags[app_id].nil?
            url = "#{@base_url}/tags/application/list/#{app_id}"

            response = http_get(url, @headers, 1)
            temp = JSON.parse response.body
            @tags[app_id] = temp["tags"]
          end
          @tags[app_id]
        rescue RestClient::ExceptionWithResponse => e
          print_error "Error getting application tags for app id #{app_id}: #{e}"
        end

        def get_trace_recommendation(id, rule_name)
          if @recs[rule_name].nil?
            url = "#{@base_url}/traces/#{id}/recommendation"
            response = http_get(url, @headers)

            @recs[rule_name] = JSON.parse response.body
          end
          @recs[rule_name]
        rescue RestClient::ExceptionWithResponse => e
          print_error "Error fetching trace recommendation for #{id}: #{e}"
        end

        def get_trace_story(id)
          url = "#{@base_url}/traces/#{id}/story"

          response = http_get(url, @headers)
          JSON.parse response.body
        rescue RestClient::ExceptionWithResponse => e
          print_error "Error fetching trace story for #{id}: #{e}"
        end
      end
    end
  end
end
