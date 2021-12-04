# frozen_string_literal: true

module Kenna
  module 128iid
    module Edgescan
      class EdgescanAsset
        attr_accessor :data, :vulnerabilities

        def initialize(asset, vulnerabilities)
          @data = asset
          @vulnerabilities = vulnerabilities.map { |vulnerability| EdgescanVulnerability.new(self, vulnerability) }
        end

        def id
          data["id"]
        end

        def tags
          data["tags"]
        end

        def application_id
          "#{data['name']} (ES#{id})"
        end

        def application?
          data["type"] == "app"
        end

        def location_specifiers
          @location_specifiers ||= @data["location_specifiers"].map do |specifier|
            EdgescanLocationSpecifier.new(self, specifier)
          end
        end

        def find_location_specifier(specifier_id, location)
          location_specifiers.find { |specifier| specifier.id == specifier_id } ||
            location_specifiers.find { |specifier| specifier.location == location }
        end

        # Converts an Edgescan asset into Kenna friendly ones
        #
        # Edgescan and Kenna assets don't map one to one. A Kenna asset is more like an Edgescan
        # location specifier. Because of that, one Edgescan asset usually gets turned into multiple
        # Kenna assets.
        #
        # This will:
        # - Create Kenna assets based on Edgescan location specifiers
        # - Go through the vulnerabilites and if some of them don't have a matching Edgescan
        #   location specifier create Kenna assets for them
        def to_kenna_assets
          location_specifiers_as_kenna_assets +
            vulnerabilities_without_location_specifiers_as_kenna_assets
        end

        private

        def location_specifiers_as_kenna_assets
          location_specifiers.map(&:to_kenna_asset)
        end

        def vulnerabilities_without_location_specifiers_as_kenna_assets
          vulnerabilities.reject(&:matching_location_specifier).map(&:to_corresponding_kenna_asset)
        end
      end
    end
  end
end
