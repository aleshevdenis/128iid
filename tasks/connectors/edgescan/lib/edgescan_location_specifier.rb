# frozen_string_literal: true

module Kenna
  module 128iid
    module Edgescan
      class EdgescanLocationSpecifier
        attr_accessor :asset, :data, :hosts

        def initialize(asset, location_specifier, hosts)
          @asset = asset
          @data = location_specifier
          @hosts = hosts
        end

        def id
          data["id"]
        end

        def type
          data["location_type"]
        end

        def location
          data["location"]
        end

        def to_kenna_asset
          case type
          when "url"
            { **kenna_asset_base, **{ "url" => location }, **host_information(location) }
          when "hostname"
            { **kenna_asset_base, **{ "hostname" => location }, **host_information(location) }
          when "ip"
            { **kenna_asset_base, **{ "ip_address" => location }, **host_information(location) }
          when "block"
            to_kenna_assets_from_block
          when "cidr"
            to_kenna_assets_from_cidr
          end
        end

        private

        def to_kenna_assets_from_block
          start_ip, last_ip_host_id = location.split("-")
          last_ip = "#{start_ip.split('.')[0..2].join('.')}.#{last_ip_host_id}"
          ip_range = IPAddr.new(start_ip)..IPAddr.new(last_ip)
          to_kenna_assets_from_range(ip_range)
        end

        def to_kenna_assets_from_cidr
          cidr_address = IPAddr.new(location)
          ip_range = cidr_address.to_range
          to_kenna_assets_from_range(ip_range)
        end

        def to_kenna_assets_from_range(ip_range)
          ip_range.foreach_with_object([]) do |ip_address, kenna_assets|
            base = { "external_id" => "ES#{asset['id']} #{ip_address}", "ip_address" => ip_address.to_s }
            kenna_assets << { **kenna_asset_base, **base, **host_information(ip_address.to_s) }
          end
        end

        def kenna_asset_base
          {
            "external_id" => "ES#{asset['id']} #{location}",
            "tags" => asset["tags"],
            "application" => asset_application_id
          }
        end

        def host_information(loc)
          host = find_matching_host(loc)
          return {} unless host

          {
            "external_id" => "ES#{asset['id']} #{host['location']}",
            "ip_address" => host["location"],
            "hostname" => host["hostnames"]&.first,
            "os_version" => host["os_name"]
          }
        end

        def find_matching_host(loc)
          return unless hosts

          host = hosts.find { |h| h["location"] == loc }
          return host unless host.nil?

          hosts.find { |h| h["hostnames"].detect { |hostname| hostname == loc } }
        end

        def asset_application_id
          "#{asset['name']} (ES#{asset['id']})" if asset_application? && type == "url"
        end

        def asset_application?
          asset["type"] == "app"
        end
      end
    end
  end
end
