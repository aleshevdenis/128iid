# frozen_string_literal: true

require_relative "mapper"

module Kenna
  module 128iid
    module Sysdig
      class StaticMapper < Mapper
        def extract_asset
          asset = {
            "asset_type" => "image",
            "image_id" => scan_data["imageDigest"],
            "hostname" => scan_data["fullTag"],
            "tags" => %W[Registry:#{scan_data['registry']} Scanner:Static]
          }
          asset.compact
        end

        def extract_vuln
          super.merge(
            "created_at" => Time.at(scan_data.fetch("createdAt")).to_datetime.iso8601
          )
        end
      end
    end
  end
end
