# frozen_string_literal: true

module Kenna
  module 128iid
    module Ordr
      class Client
        class ApiError < StandardError; end
        attr_reader :host

        def initialize(host, api_user, api_password, alarm_category, page_size)
          @host = host
          @alarm_category = alarm_category
          @page_size = page_size
          @headers = {
            "content-type": "application/json",
            "accept": "application/json",
            "Authorization": "Basic #{Base64.strict_encode64("#{api_user}:#{api_password}")}"
          }
        end

        def devices
          url = "#{host}/Rest/Devices?limit=#{@page_size}"
          devices = []
          next_page = nil
          loop do
            response = api_request(next_page || url)
            devices_array = response.fetch("Devices")
            devices.concat(devices_array)
            print_good("Got #{devices_array.count} devices")
            next_cursor = response["MetaData"]["next"]
            break unless next_cursor

            next_page = "#{host}#{next_cursor}"
          end

          devices
        end

        def alarms(&block)
          return to_enum(__method__) unless block

          url = "#{host}/Rest/SecurityAlarms?limit=#{@page_size}#{alarm_category_filter}"
          next_page = nil
          loop do
            response = api_request(next_page || url)
            yield(response)
            next_cursor = response["MetaData"]["next"]
            break unless next_cursor

            next_page = "#{host}#{next_cursor}"
          end
        end

        private

        def api_request(url)
          response = http_get(url, @headers)
          raise ApiError, "Unable to retrieve query result. PLease check credentials" unless response

          JSON.parse(response)
        end

        def alarm_category_filter
          return "" unless @alarm_category.present?

          "&category=#{@alarm_category}"
        end
      end
    end
  end
end
