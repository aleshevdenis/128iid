# frozen_string_literal: true

require_relative "mapper"

module Kenna
  module 128iid
    module Sysdig
      class RuntimeMapper < Mapper
        def extract_asset
          asset = {
            "asset_type" => "container",
            "container_id" => scan_data["hostId"],
            "hostname" => scan_data["hostname"],
            "mac_address" => scan_data["macAddress"],
            "os" => scan_data["operatingSystem"],
            "os_version" => scan_data["osVersion"],
            "owner" => (scan_data["clusterName"] if scan_data["clusterName"].present?),
            "tags" => %W[CloudType:#{scan_data['cloudType']} Scanner:Runtime]
          }
          asset.compact
        end

        def extract_vuln
          super.merge(
            "created_at" => scan_data.fetch("lastScanDate")
          )
        end
      end
    end
  end
end
