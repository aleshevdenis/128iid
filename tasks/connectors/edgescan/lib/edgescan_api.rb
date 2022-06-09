# frozen_string_literal: true

module Kenna
  module 128iid
    module Edgescan
      class EdgescanApi
        class ApiError < StandardError; end

        def initialize(options)
          @edgescan_token = options[:edgescan_token]
          @page_size = options[:edgescan_page_size].to_i
          @api_host = options[:edgescan_api_host]
          @include_application_vulnerabilities = options[:include_application_vulnerabilities]
          @include_network_vulnerabilities = options[:include_network_vulnerabilities]
        end

        # Fetches Edgescan assets and vulnerabilities in batches. Yields foreach batch.
        # Batch size is passed in by the user using `edgescan_page_size` (100 by default).
        def fetch_in_batches
          total_batches = (fetch_assets_count.to_f / @page_size).ceil

          total_batches.times do |batch|
            print_good "Syncing assets batch #{batch + 1} of #{total_batches}..."

            offset = batch * @page_size
            limit = @page_size

            raw_assets = fetch_assets(offset, limit)
            raw_vulnerabilities = fetch_vulnerabilities(raw_assets.map { |asset| asset["id"] })
            raw_definitions = fetch_definitions(raw_vulnerabilities.values.flatten.map { |vuln| vuln["definition_id"] }.uniq)

            assets = build_asset_classes(raw_assets, raw_vulnerabilities)
            definitions = build_definition_classes(raw_definitions)

            yield(assets, definitions)
          end
        end

        private

        def build_asset_classes(assets, vulnerabilities)
          assets.map { |asset| EdgescanAsset.new(asset, vulnerabilities[asset["id"]] || []) }
        end

        def build_definition_classes(definitions)
          definitions.map { |definition| EdgescanDefinition.new(definition) }
        end

        def fetch_assets(offset, limit)
          query("assets", { o: offset, l: limit })
        end

        def fetch_vulnerabilities(asset_ids)
          query("vulnerabilities", { detail_level: "high", c: { asset_id_in: asset_ids.join(","), status: "open" }.merge(layer_query_parameters) })
            .sort_by { |vulnerability| vulnerability["asset_id"] }
        end

        def fetch_definitions(definition_ids)
          query("definitions", { detail_level: "high", c: { id_in: definition_ids.join(",") } })
        end

        def fetch_assets_count
          query("assets", { l: 0 }, unwrap: false)["total"]
        end

        def query(resource, query_payload, unwrap: true)
          response = http_post("#{base_url}/api/v1/#{resource}/query.json", { "X-API-TOKEN": @edgescan_token }, query_payload)
          raise ApiError unless response

          json = JSON.parse(response.body)
          unwrap ? json[resource] : json
        end

        def base_url
          return "http://localhost:3000" if ENV["EDGESCAN_ENVIRONMENT"] == "local"

          "https://#{@api_host}"
        end

        # Application vulnerabilities are on layer 7
        # Network vulnerabilities are on every other layer
        def layer_query_parameters
          if @include_application_vulnerabilities && @include_network_vulnerabilities
            {}
          elsif @include_application_vulnerabilities
            { layer_in: 7 }
          else
            { layer_not_in: 7 }
          end
        end
      end
    end
  end
end
