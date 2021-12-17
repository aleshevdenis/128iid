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

        def get_vulns(tags, environments, severities, offset, limit)
          url = "#{@base_url}/orgtraces/filter?expand=application&offset=#{offset}&limit=#{limit}&applicationTags=#{tags}&environments=#{environments}&severities=#{severities}&licensedOnly=true"
          response = http_get(url, @headers)
          return nil if response.nil?

          body = JSON.parse response.body

          more_results = !(response.nil? || response.empty? || (offset + limit) >= body["count"])
          ceiling = [limit + offset, body['count']].min

          print "Fetched #{ceiling} of #{body['count']} vulnerabilities" 

          return body["traces"], more_results, body['count']
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
          ceiling = [limit + offset, body['count']].min

          print "Fetched #{ceiling} of #{body['count']} libraries" 

          return body["libraries"], more_results, body['count']
        end

        def get_application_ids(tags)
          print_debug "Getting applications from the Contrast API"
          url = "#{@base_url}/applications/filter/short?filterTags=#{tags}"
          response = http_get(url, @headers)
          return nil if response.nil?

          temp = JSON.parse response.body
          temp["applications"]
        end

        def get_application_tags(app_id)
          if @tags[app_id].nil?
            url = "#{@base_url}/tags/application/list/#{app_id}"

            response = http_get(url, @headers)
            temp = JSON.parse response.body
            @tags[app_id] = temp["tags"]
          end
          @tags[app_id]
        end

        def get_trace_recommendation(id, rule_name)
          if @recs[rule_name].nil?
            # print "Getting recommendation for rule #{rule_name}"
            url = "#{@base_url}/traces/#{id}/recommendation"
            response = RestClient.get(url, @headers)

            @recs[rule_name] = JSON.parse response.body
          end
          @recs[rule_name]
        end

        def get_trace_story(id)
          url = "#{@base_url}/traces/#{id}/story"

          response = http_get(url, @headers)
          JSON.parse response.body
        rescue RestClient::ExceptionWithResponse => e
          print_debug "Error fetching trace story for #{id}: #{e} (unlicensed?)"
        end
      end
    end
  end
end
