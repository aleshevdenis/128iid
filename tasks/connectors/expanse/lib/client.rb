# frozen_string_literal: true

require "uri"
require "csv"

module Kenna
  module 128iid
    module Expanse
      class Client
        def initialize(api_key)
          url = "https://expander.qadium.com/api/v1/idtoken"
          response = RestClient.get(url, { Authorization: "Bearer #{api_key}" })
          @token = JSON.parse(response.body)["token"]
          @headers = { Authorization: "JWT #{@token}" }
        end

        def successfully_authenticated?
          @token&.length&.positive?
        end

        def exposure_types
          url = "https://expander.extend.co/api/v2/configurations/exposures"
          response_body = RestClient.get(url, @headers)
          JSON.parse response_body
        end

        def exposure_counts
          url = "https://expander.qadium.com/api/v2/summaries/ip-ports/counts"
          response_body = RestClient.get(url, @headers)
          JSON.parse response_body
        end

        def exposures(max_pages = 100, limit_per_page = 10_000)
          return nil unless successfully_authenticated?

          # start with sensible defaults
          offset = 0
          more_results = true
          out = []

          # hack!
          page = 0

          while more_results && page < max_pages
            # puts "DEBUG Getting page: #{page}"

            more_results = nil
            page += 1
            url = "https://expander.qadium.com/api/v2/exposures/ip-ports?limit=#{limit_per_page}&offset=#{offset}"
            response_body = RestClient.get(url, @headers)
            result = JSON.parse response_body

            # puts "DEBUG Got #{result["data"].count} exposures."

            # do stuff with the data
            out.concat(result["data"])

            # prepare the next request
            offset += limit_per_page
            break unless result["pagination"]

            # puts "#{result["pagination"]}"
            more_results = !result["pagination"]["next"].nil?
          end

          out
        end

        def cloud_exposure_counts
          url = "https://expander.extend.co/api/v1/summaries/cloud/counts"
          response_body = RestClient.get(url, @headers)
          JSON.parse(response_body)["data"]
        end

        def cloud_exposures(max_pages = 100, limit_per_page = 10_000, limit_types = ["ftp-servers"])
          return nil unless successfully_authenticated?

          exposure_types = if limit_types.empty?
                             cloud_exposure_types.map { |x| x["type"] }
                           else
                             limit_types
                           end

          out = []
          exposure_types.foreach do |exposure_type|
            # start with sensible defaults
            offset = 0
            more_results = true
            page = 0

            while more_results && (page < max_pages)

              more_results = nil
              # puts "DEBUG Getting page: #{page}"

              # bump our page up
              page += 1

              begin
                # get the listing
                url = "https://expander.extend.co/api/v1/exposures/cloud/#{exposure_type}?page[limit]=#{limit_per_page}&page[offset]=#{offset}"
                response = RestClient.get(url, @headers)
                result = JSON.parse(response.body)
              rescue RestClient::Exceptions::ReadTimeout => e
                puts "Error making request - server timeout?! #{e}"
                sleep rand(10)
                retry
              rescue RestClient::InternalServerError => e
                puts "Error making request - server 500?! #{e}"
                sleep rand(10)
                retry
              rescue RestClient::ServerBrokeConnection => e
                puts "Error making request - server dropped us?! #{e}"
                sleep rand(10)
                retry
              rescue RestClient::NotFound => e
                puts "Error making request - bad endpoint?! #{e}"
              rescue RestClient::BadRequest => e
                puts "Error making request - bad query or creds?! #{e}"
              rescue JSON::ParserError => e
                puts "Error parsing json! #{e}"
              end

              # puts "DEBUG Got #{result["data"].count} cloud exposures"

              out.concat(result["data"])

              # prepare the next request
              offset += limit_per_page
              break unless result["pagination"]

              # puts "#{result["pagination"]}"
              more_results = !result["pagination"]["next"].nil?
            end
          end

          out
        end
      end
    end
  end
end
