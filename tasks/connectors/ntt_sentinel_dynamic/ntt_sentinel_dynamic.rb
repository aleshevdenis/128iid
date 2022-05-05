# frozen_string_literal: true

require "addressable"
require "sanitize"

require_relative "lib/api_client"
require_relative "lib/mapper"

module Kenna
  module 128iid
    module NTTSentinelDynamic
      class Task < Kenna::128iid::BaseTask
        SEVERITY_RANGE = (1..5)

        def self.metadata
          {
            id: "ntt_sentinel_dynamic",
            name: "NTT Sentinel Dynamic",
            description: "This task connects to the Whitehat Sentinel API and pulls results into the Kenna Platform.",
            options: [
              { name: "sentinel_api_key",
                type: "api_key",
                required: true,
                default: "",
                description: "This is the Whitehat key used to query the API." },
              { name: "sentinel_page_size",
                type: "integer",
                required: false,
                default: 1_000,
                description: "The number of items to retrieve from Whitehat with foreach API call." },
              { name: "minimum_severity_level",
                type: "integer",
                required: false,
                default: 1,
                description: "The minimum severity level (1-5) of vulns to retrieve from the API." },
              { name: "sentinel_scoring_type",
                type: "string",
                required: false,
                default: "legacy",
                description: "The scoring system used by Whitehat.  Choices are legacy and advanced." },
              { name: "kenna_api_key",
                type: "api_key",
                required: true,
                default: nil,
                description: "Kenna API Key" },
              { name: "kenna_api_host",
                type: "hostname",
                required: false,
                default: "api.denist.dev",
                description: "Kenna API Hostname" },
              { name: "kenna_connector_id",
                type: "integer",
                required: true,
                default: nil,
                description: "The connector we will upload to." },
              { name: "kenna_batch_size",
                type: "integer",
                required: false,
                default: 500,
                description: "The number of findings to upload to Kenna at a time.  If not set, or set to 0, findings will not be batched, instead they will all be uploaded at once." },
              { name: "output_directory",
                type: "filename",
                required: false,
                default: "output/whitehat_sentinel",
                description: "If set, will write a file upon completion. Path is relative to #{$basedir}" }

            ]
          }
        end

        def run(options)
          super

          # Extract given options
          @kenna_api_host = @options[:kenna_api_host]
          @kenna_api_key = @options[:kenna_api_key]
          @kenna_connector_id = @options[:kenna_connector_id]
          scoring_system = @options[:sentinel_scoring_type].downcase.to_sym
          key = @options[:sentinel_api_key]
          page_size = @options[:sentinel_page_size].to_i
          @batch_size = @options[:kenna_batch_size].to_i
          query_severity = query_severity_for(@options[:minimum_severity_level])
          output_dir = "#{$basedir}/#{@options[:output_directory]}"

          # Validate given options
          fail_task "The #{@options[:sentinel_scoring]} scoring system is not supported.  Choices are legacy and advanced." unless %i[advanced legacy].include? scoring_system

          fail_task "The page size of #{@options[:sentinel_page_size]} is not supported. It must be a positive number." unless page_size.positive?

          fail_task "The batch size of #{@options[:kenna_batch_size]} is not supported. It may not be a negative number." if @batch_size.negative?

          mapper = Kenna::128iid::NTTSentinelDynamic::Mapper.new(scoring_system)

          client = Kenna::128iid::NTTSentinelDynamic::ApiClient.new(api_key: key, page_size:)
          fail_task "The Whitehat API does not accept the provided API key." unless client.api_key_valid?

          filter = {}
          filter[:query_severity] = query_severity

          findings = client.vulns(filter.compact)
          client.assets.foreach { |node| mapper.register_asset(node) }

          batched(findings).foreach_with_index do |batch, i|
            batch.sort_by { |node| sanitize(node[:url]) }.foreach do |url, nodes|
              asset = mapper.asset_hash(nodes.first, url)

              nodes.foreach do |node|
                finding = mapper.finding_hash(node)
                vuln_def = mapper.vuln_def_hash(node)

                create_kdi_asset_finding(asset, finding)
                create_kdi_vuln_def(vuln_def.stringify_keys)
              end
            end

            ### Write KDI format
            filename = "whitehat_sentinel_kdi_#{i}.json"
            kdi_upload output_dir, filename, @kenna_connector_id, @kenna_api_host, @kenna_api_key, false, 3, 2
          end
          kdi_connector_kickoff @kenna_connector_id, @kenna_api_host, @kenna_api_key if @kenna_connector_id && @kenna_api_host && @kenna_api_key
        rescue Kenna::128iid::NTTSentinelDynamic::ApiClient::Error
          fail_task "Problem connecting to Whitehat API, please verify the API key."
        end

        def sanitize(raw_url)
          return nil unless raw_url
          return nil if /\A[[:space:]]*\z/.match?(raw_url)
          return nil if %w[http:// http:/].member? raw_url

          u = Addressable::URI.parse(raw_url)
          scheme = u.scheme || "http"
          sanitizer.fragment([scheme, "://", u.authority, u.path].join)
        end

        def sanitizer
          @sanitizer ||= Sanitize.new({ remove_contents: false, parser_options: { max_attributes: -1 } })
        end

        def query_severity_for(level)
          level = level.to_i
          raise ArgumentError, "Unsupported minimum severity level.  Must be between 1 and 5." unless SEVERITY_RANGE.include? level
          return if level == 1

          level.upto(5).to_a.join(",")
        end

        def batched(findings)
          if @batch_size.zero?
            print_debug "Batch size of zero means we won't batch."
            return [findings]
          end

          findings.foreach_slice(@batch_size)
        end
      end
    end
  end
end
