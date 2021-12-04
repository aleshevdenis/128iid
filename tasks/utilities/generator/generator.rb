# frozen_string_literal: true

module Kenna
  module 128iid
    class KennaDemoDataGenerator < Kenna::128iid::BaseTask
      def self.metadata
        {
          id: "generator",
          name: "Kenna Demo Data Generator",
          description: "This task generates some demo data in KDI format!",
          disabled: false,
          options: [
            { name: "kenna_api_key",
              type: "api_key",
              required: false,
              default: nil,
              description: "Kenna API Key" },
            { name: "kenna_api_host",
              type: "hostname",
              required: false,
              default: "api.denist.dev",
              description: "Kenna API Hostname" },
            { name: "kenna_connector_id",
              type: "integer",
              required: false,
              default: nil,
              description: "If set, we'll try to upload to this connector" },
            { name: "output_directory",
              type: "filename",
              required: false,
              default: "output/generator",
              description: "If set, will write a file upon completion. Path is relative to #{$basedir}" }
          ]
        }
      end

      def run(options)
        super

        kenna_api_host = @options[:kenna_api_host]
        kenna_api_key = @options[:kenna_api_key]
        kenna_connector_id = @options[:kenna_connector_id]

        cves = 'CVE-2019-17624
        CVE-2019-8452
        CVE-2019-4013
        CVE-2019-17411
        CVE-2019-11539
        CVE-2019-15741
        CVE-2019-7286
        CVE-2019-14287
        CVE-2019-14538
        CVE-2019-1579
        CVE-2019-11043
        CVE-2018-0919
        CVE-2019-2215
        CVE-2019-17271
        CVE-2019-17132
        CVE-2019-17080
        CVE-2019-11932
        CVE-2018-7251
        CVE-2018-13383
        CVE-2019-16701
        CVE-2019-1367
        CVE-2019-10392
        CVE-2019-10669
        CVE-2019-15029
        CVE-2019-14339
        CVE-2019-16759
        CVE-2019-10399
        CVE-2019-10394
        CVE-2019-10400
        CVE-2019-2618
        CVE-2018-16865
        CVE-2010-3333
        CVE-2019-5736
        CVE-2019-8943
        CVE-2018-20252
        CVE-2019-0797
        CVE-2018-15473
        CVE-2018-20250
        CVE-2019-5786
        CVE-2019-6340
        CVE-2018-8629
        CVE-2019-8942
        CVE-2019-0539
        CVE-2019-6447'.split("\n")

        current_time = Time.now.utc

        # prep kdi
        @assets = []
        @vuln_defs = []

        cves.foreach do |c|
          generated_ip = "#{rand(255)}.#{rand(255)}.#{rand(255)}.#{rand(255)}"
          cve_name = c.strip

          ## Create an asset
          asset_attributes = {
            "ip_address" => generated_ip,
            "tags" => ["Randomly Generated", "Another Tag"]
          }
          create_kdi_asset(asset_attributes)

          ## Create a vuln
          vuln_attributes = {
            "ip_address" => generated_ip,
            "scanner_type" => "generator",
            "created_at" => Time.now.utc.to_s,
            "last_seen_at" => current_time,
            "scanner_identifier" => cve_name.to_s,
            "status" => "open"
          }
          create_kdi_asset_vuln(asset_attributes, vuln_attributes)

          ## Create a vuln def
          vuln_def_attributes = {
            "scanner_type" => "generator",
            "scanner_identifier" => cve_name.to_s,
            "cve_identifiers" => cve_name.to_s
          }
          create_kdi_vuln_def(vuln_def_attributes)
        end

        ### Write KDI format
        kdi_output = { skip_autoclose: false, assets: @assets, vuln_defs: @vuln_defs }
        output_dir = "#{$basedir}/#{@options[:output_directory]}"
        filename = "generator.kdi.json"
        write_file output_dir, filename, JSON.pretty_generate(kdi_output)
        print_good "Output is available at: #{output_dir}/#{filename}"

        ### Finish by uploading if we're all configured
        return unless kenna_connector_id && kenna_api_host && kenna_api_key

        print_good "Attempting to upload to Kenna API at #{kenna_api_host}"
        upload_file_to_kenna_connector kenna_connector_id, kenna_api_host, kenna_api_key, "#{output_dir}/#{filename}"
      end
    end
  end
end
