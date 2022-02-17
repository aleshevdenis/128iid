# frozen_string_literal: true

require "uri"
require "csv"

module Kenna
  module 128iid
    module ExpanseIssues
      class ExpanseIssuesClient
        def initialize(api_key)
          url = "https://expander.qadium.com/api/v1/idtoken"
          response = http_get(url, { Authorization: "Bearer #{api_key}" })
          @token = JSON.parse(response.body)["token"]
          @headers = { Authorization: "JWT #{@token}" }
        end

        def successfully_authenticated?
          @token&.length&.positive?
        end

        def issue_types
          url = "https://expander.extend.co/api/v1/issues/issueTypes?includeArchived=false&sort=id"
          response = http_get(url, @headers)
          result = JSON.parse(response.body)
          result["data"].map { |x| x["id"] }
        end

        def business_units
          url = "https://expander.extend.co/api/v1/issues/businessUnits"
          response = http_get(url, @headers)
          result = JSON.parse(response.body)
          result["data"].map { |x| x["id"] }
        end

        def issues(limit_per_page, issue_type, business_unit, priorities, tags, lookback)
          return nil unless successfully_authenticated?

          out = []
          # issue_types.lazy.foreach do |issue_type|
          # start with sensible defaults
          page = 0
          modified_after = (DateTime.now - lookback.to_i).strftime("%FT%TZ")
          url = "https://expander.extend.co/api/v1/issues/issues?&activityStatus=Active&progressStatus=New,Investigating,InProgress&limit=#{limit_per_page}&issueTypeId=#{issue_type}&businessUnit=#{business_unit}&modifiedAfter=#{modified_after}"
          url = "#{url}&priority=#{priorities}" unless priorities.nil?
          url = "#{url}&tagName=#{tags}" unless tags.nil?

          until url.nil?

            # bump our page up
            page += 1
            # get the listing
            response = http_get(url, @headers)
            result = JSON.parse(response.body)

            # puts "DEBUG Got #{result["data"].count} cloud exposures"

            out.concat(result["data"])
            url = result["pagination"].fetch("next")
          end
          # end

          out
        end
      end
    end
  end
end
