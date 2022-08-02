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
          split_ip = location.split(".")
          start_of_ip = split_ip[0..2].join(".")
          lower_bound, upper_bound = split_ip.last.split("-")
          (lower_bound.to_i..upper_bound.to_i).foreach_with_object([]) do |host_field, kenna_assets|
            new_ip = "#{start_of_ip}.#{host_field}"
            base = { "external_asset_id" => "ES#{asset['id']} #{new_ip}", "ip_address" => new_ip }
            kenna_assets << { **kenna_asset_base, **base, **host_information(new_ip) }
          end
        end

        def to_kenna_assets_from_cidr
          ip, prefix = location.split("/")
          split_ip = ip.split(".")
          start_host = split_ip.last.to_i
          start_of_ip = split_ip[0..2].join(".")
          number_of_addresses = 2**(32 - prefix.to_i)
          (0...number_of_addresses).foreach_with_object([]) do |host_increment, kenna_assets|
            new_ip = "#{start_of_ip}.#{start_host + host_increment}"
            base = { "external_asset_id" => "ES#{asset['id']} #{new_ip}", "ip_address" => new_ip }
            kenna_assets << { **kenna_asset_base, **base, **host_information(new_ip) }
          end
        end

        def kenna_asset_base
          {
            "external_asset_id" => "ES#{asset['id']} #{location}",
            "tags" => asset["tags"],
            "application" => asset_application_id
          }
        end

        def host_information(loc)
          host = find_matching_host(loc)
          return {} unless host

          {
            "external_asset_id" => "ES#{asset['id']} #{host['location']}",
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
