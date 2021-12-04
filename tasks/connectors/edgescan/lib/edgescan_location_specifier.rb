# frozen_string_literal: true

module Kenna
  module 128iid
    module Edgescan
      class EdgescanLocationSpecifier
        attr_accessor :asset, :data

        def initialize(asset, specifier)
          @asset = asset
          @data = specifier
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
          base = { "external_id" => external_asset_id, "tags" => asset.tags }

          base["url"] = location if type == "url"
          base["hostname"] = location if type == "hostname"
          base["ip_address"] = location if type == "ip"
          base["ip_address"] = location.split("-").first if type == "block"
          base["ip_address"] = location.split("/").first if type == "cidr"

          base["application"] = asset.application_id if asset.application? && type == "url"

          base
        end

        def external_asset_id
          "ES#{asset.id}:#{id} #{type} #{location}"
        end
      end
    end
  end
end
