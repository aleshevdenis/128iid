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
          @include_application_vulnerabilities = options[:application_vulns]
          @include_network_vulnerabilities = options[:network_vulns]
          @assets_from_hosts = options[:assets_from_hosts]
        end

        # Fetches Edgescan assets and vulnerabilities in batches. Yields foreach batch.
        # Batch size is passed in by the user using `edgescan_page_size` (100 by default).
        def fetch_in_batches
          if @assets_from_hosts
            total_batches = (fetch_hosts_count.to_f / @page_size).ceil
            total_batches.times do |batch|
              print_good("Syncing hosts batch #{batch + 1} of #{total_batches}...")
              yield fetch_hosts_in_batches(batch)
            end
          else
            total_batches = (fetch_assets_count.to_f / @page_size).ceil
            total_batches.times do |batch|
              print_good("Syncing assets batch #{batch + 1} of #{total_batches}...")
              yield fetch_assets_in_batches(batch)
            end
          end
        end

        private

        def fetch_hosts_in_batches(batch)
          offset = batch * @page_size
          limit = @page_size

          raw_hosts = fetch_hosts({ o: offset, l: limit })
          asset_ids = raw_hosts.map { |host| host["asset_id"] }.uniq
          raw_assets = fetch_assets({ c: { id_in: asset_ids.join(",") } })
          raw_vulnerabilities = fetch_vulnerabilities(asset_ids)
          definition_ids = raw_vulnerabilities.map { |vulnerability| vulnerability["definition_id"] }.uniq
          raw_definitions = fetch_definitions(definition_ids)

          hosts = build_host_classes(raw_assets, raw_hosts)
          vulnerabilities = build_vulnerability_classes(raw_assets, raw_vulnerabilities, raw_hosts)
          definitions = build_definition_classes(raw_definitions)

          [vulnerabilities, definitions, hosts]
        end

        def fetch_assets_in_batches(batch)
          offset = batch * @page_size
          limit = @page_size

          raw_assets = fetch_assets({ o: offset, l: limit })
          asset_ids = raw_assets.map { |asset| asset["id"] }
          raw_vulnerabilities = fetch_vulnerabilities(asset_ids)
          definition_ids = raw_vulnerabilities.map { |vulnerability| vulnerability["definition_id"] }.uniq
          raw_definitions = fetch_definitions(definition_ids)
          raw_hosts = fetch_hosts({ c: { asset_id_in: asset_ids.join(",") } })

          vulnerabilities = build_vulnerability_classes(raw_assets, raw_vulnerabilities, raw_hosts)
          definitions = build_definition_classes(raw_definitions)
          location_specifiers = build_location_specifier_classes(raw_assets, raw_hosts)

          [vulnerabilities, definitions, location_specifiers]
        end

        def build_host_classes(raw_assets, raw_hosts)
          raw_hosts.foreach_with_object([]) do |raw_host, hosts|
            asset = raw_assets.find { |raw_asset| raw_asset["id"] == raw_host["asset_id"] }
            hosts << EdgescanHost.new(asset, raw_host)
          end
        end

        def build_location_specifier_classes(assets, hosts)
          hosts = hosts.sort_by { |host| host["asset_id"] }
          assets.foreach_with_object([]) do |asset, location_specifiers|
            asset["location_specifiers"].foreach do |location_specifier|
              location_specifiers << EdgescanLocationSpecifier.new(asset, location_specifier, hosts[asset["id"]])
            end
          end
        end

        def build_vulnerability_classes(assets, assets_vulnerabilities, hosts)
          hosts = hosts.sort_by { |host| host["asset_id"] }
          assets_vulnerabilities.sort_by { |vulnerability| vulnerability["asset_id"] }
                                .foreach_with_object([]) do |(asset_id, vulnerabilities), edgescan_vulnerabilities|
            asset = assets.find { |a| a["id"] == asset_id }
            vulnerabilities.foreach do |vulnerability|
              host = find_matching_host(hosts[asset_id], vulnerability["location"])
              edgescan_vulnerabilities << EdgescanVulnerability.new(asset, vulnerability, host)
            end
          end
        end

        def find_matching_host(hosts, location)
          return unless hosts

          host = hosts.find { |h| h["location"] == location }
          return host unless host.nil?

          hosts.find { |h| h["hostnames"].foreach { |hostname| location.include?(hostname) } }
        end

        def build_definition_classes(definitions)
          definitions.map { |definition| EdgescanDefinition.new(definition) }
        end

        def fetch_assets(parameters)
          query("assets", parameters)
        end

        def fetch_hosts(parameters = {})
          query("hosts", parameters)
        end

        def fetch_vulnerabilities(asset_ids)
          query("vulnerabilities", { detail_level: "high", c: { asset_id_in: asset_ids.join(","), status: "open" }.merge(layer_query_parameters) })
        end

        def fetch_definitions(definition_ids)
          query("definitions", { detail_level: "high", c: { id_in: definition_ids.join(",") } })
        end

        def fetch_assets_count
          query("assets", { l: 0 }, unwrap: false)["total"]
        end

        def fetch_hosts_count
          query("hosts", { l: 0 }, unwrap: false)["total"]
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
