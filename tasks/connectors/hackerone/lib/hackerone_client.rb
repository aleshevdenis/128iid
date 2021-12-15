# frozen_string_literal: true

require 'httparty'
require 'pry'

module Kenna
  module 128iid
    module Hackerone
      class HackeroneClient
        class ApiError < StandardError; end

        HOST = "https://api.hackerone.com"

        def initialize(username, password, program)
          @basic_auth = {
            username: username,
            password: password,
          }
        end

        def get_reports(username, password, program)
          HTTParty.get "#{HOST}/v1/reports",
            query: get_query(program),
            basic_auth: @basic_auth
        end

        private

        def get_query(program)
          query = {
            filter: {
              program: [program]
            }
          }
        end
      end
    end
  end
end
