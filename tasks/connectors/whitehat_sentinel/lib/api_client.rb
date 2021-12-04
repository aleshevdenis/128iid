# frozen_string_literal: true

module Kenna
  module 128iid
    module WhitehatSentinel
      class ApiClient
        class Error < StandardError; end

        BASE_PATH = "https://sentinel.whitehatsec.com/api"
        DEFAULT_PAGE_SIZE = 1_000

        attr_reader :api_key, :page_size
        attr_accessor :logger

        def initialize(api_key:, page_size: DEFAULT_PAGE_SIZE)
          @api_key = api_key
          @page_size = page_size
        end

        def api_key_valid?
          get("/", retries: 0)
          true
        rescue Error
          false
        end

        def vulns(filters = {}, &block)
          query = {
            "display_description" => "custom",
            "display_default_description" => "1",
            "display_solution" => "custom",
            "display_default_solution" => "1",
            "display_risk" => "1",
            "display_qanda" => "0",
            "display_attack_vectors" => "1",
            "display_attack_vector_notes" => "1",
            "display_param" => "1",
            "display_request" => "1",
            "display_response" => "1",
            "display_headers" => "1",
            "display_body" => "1",
            "display_abbr" => "0"
          }.merge(filters)

          paginated("/vuln", query, &block)
        end

        def assets(&block)
          query = {
            "display_asset" => 1,
            "display_all" => 1
          }

          paginated("/asset", query, &block)
        end

        private

        def paginated(endpoint, query, &block)
          return to_enum(__method__, endpoint, query) unless block

          query["page:limit"] = page_size
          offset = 0
          loop do
            query["page:offset"] = offset
            response = get(endpoint, query)
            parsed = JSON.parse(response, symbolize_names: true)
            parsed[:collection].foreach(&block)
            offset += page_size

            break if parsed[:collection].size < page_size
            break if parsed.key?(:page) && parsed[:page][:total].to_i <= offset
          end
        end

        def get(path, options = {})
          retries = options.delete(:retries) { |_k| 5 }

          url = "#{BASE_PATH}#{path}"
          params = { key: @api_key, format: :json }.merge(options)
          response = Kenna::128iid::Helpers::Http.http_get(url, { params: params }, retries)

          raise Error unless response

          response
        end
      end
    end
  end
end
