# frozen_string_literal: true

module Kenna
  module 128iid
    module Edgescan
      class EdgescanHost
        attr_accessor :data, :asset

        def initialize(asset, host)
          @asset = asset
          @data = host
        end

        def id
          data["id"]
        end

        def asset_id
          data["asset_id"]
        end

        def location
          data["location"]
        end

        def hostname
          data["hostnames"].first
        end

        def os_name
          data["os_name"]
        end

        def to_kenna_asset
          {
            "external_id" => "ES#{asset_id} #{location}",
            "tags" => asset["tags"],
            "ip_address" => location,
            "hostname" => hostname,
            "os_version" => os_name
          }
        end
      end
    end
  end
end
