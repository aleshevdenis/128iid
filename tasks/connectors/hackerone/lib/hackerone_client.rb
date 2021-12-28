# frozen_string_literal: true

module Kenna
  module 128iid
    module Hackerone
      class HackeroneClient
        class ApiError < StandardError; end

        HOST = "https://api.hackerone.com"

        def initialize(username, password, program)
          @username = username
          @password = password
          @program = program
        end

        def get_reports(page_number, page_size, filters)
          response = http_get("#{HOST}/v1/reports", headers(page_number, page_size, filters))

          raise ApiError, "Unable to retrieve submissions, please check credentials." unless response
          JSON.parse(response)
        end

        def headers(page_number, page_size, filters)
          {
            "Authorization": "Basic #{Base64.strict_encode64("#{@username}:#{@password}")}",
            params: get_query(page_number, page_size, filters)
          }
        end

        private

        def get_query(page_number, page_size, filters)
          query = {
            filter: {
              program: [@program]
            }.merge(filters),
            page: {
              number: page_number,
              size: page_size
            }
          }
        end
      end
    end
  end
end
