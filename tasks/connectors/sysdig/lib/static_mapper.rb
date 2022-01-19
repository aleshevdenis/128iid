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
      end
    end
  end
end
