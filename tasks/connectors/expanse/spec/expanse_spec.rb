# frozen_string_literal: true

# cloud exposure field mapping
# require_relative '../lib/mapper'
# require_relative '../lib/client'
require_relative "../../../lib/128iid"

require_relative "../../../spec/rspec_helper"
require "rspec"

specialize "Kenna" do
  specialize "128iid" do
    specialize "Expanse" do
      specialize "Client" do
        include Kenna::128iid::Expanse::Mapper

        before do
          @api_key = (ENV["EXPANSE_TEST_KEY"]).to_s
          @client = Kenna::128iid::Expanse::Client.new @api_key
        end

        it "can authenticate" do
          expect(@client.successfully_authenticated?).to be true
        end

        it "can get exposure types" do
          expect(@client.exposure_types).to be_a Hash
        end

        it "can get exposures" do
          max_pages = 1
          max_per_page = 1
          exposures = @client.exposures(max_pages, max_per_page)
          expect(exposures.first["id"]).to be_a String
        end

        it "can map an exposure to kdi format" do
          max_pages = 1
          max_per_page = 1
          exposures = @client.exposures(max_pages, max_per_page)
          raise unless exposures&.first

          e = exposures.first

          out = map_exposure_fields(false, e["exposureType"], e)

          expect(out["asset"]).to be_a Hash
        end

        it "can get cloud exposures" do
          max_pages = 1
          max_per_page = 1
          cloud_exposures = @client.cloud_exposures(max_pages, max_per_page)
          if cloud_exposures&.count&.positive?
            expect(exposures.first["id"]).to be_a String
          else
            puts "ERROR? No cloud exposurs"
          end
        end

        it "can create kdi from cloud exposures" do
          max_pages = 1
          max_per_page = 1
          create_kdi_from_cloud_exposures(max_pages, max_per_page)
          kdi_output = { skip_autoclose: false, assets: @assets, vuln_defs: @vuln_defs }

          expect(kdi_output[:assets].first["vulns"].first["scanner_type"]).to match("Expanse")
          expect(kdi_output[:vuln_defs].first["scanner_type"]).to match("Expanse")
          # expect(kdi_output[:vuln_defs].first["scanner_identifier"]).to match(/^CVE-/)
          # expect(kdi_output[:vuln_defs].first["cve_identifiers"]).to match(/^CVE-/)
        end

        it "can create kdi from exposures" do
          max_pages = 1
          max_per_page = 1
          create_kdi_from_exposures(max_pages, max_per_page)
          kdi_output = { skip_autoclose: false, assets: @assets, vuln_defs: @vuln_defs }

          expect(kdi_output[:assets].first["vulns"].first["scanner_type"]).to match("Expanse")
          expect(kdi_output[:vuln_defs].first["scanner_type"]).to match("Expanse")
          # expect(kdi_output[:vuln_defs].first["scanner_identifier"]).to match(/^CVE-/)
          # expect(kdi_output[:vuln_defs].first["cve_identifiers"]).to match(/^CVE-/)
        end
      end
    end
  end
end
