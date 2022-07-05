# frozen_string_literal: true

module Kenna
  module 128iid
    module NTTSentinelDynamic
      class Mapper
        CWE_REGEX = %r{cwe.mitre.org/data/definitions/(?<cwe_id>\d+)\.html}

        def initialize(scoring_system)
          raise ArgumentError unless %i[advanced legacy].include? scoring_system

          @scoring_system = scoring_system
          @tag_hash = {}
          @sanitizer = Sanitize.new(remove_contents: false, parser_options: { max_attributes: -1 })
        end

        def register_asset(node)
          asset = node[:asset]

          @tag_hash[asset[:id]] = tags_for(asset)
        end

        def asset_hash(node, sanitized_url)
          site_id = node[:site].to_i

          {
            application: node[:site_name],
            url: sanitized_url,
            tags: @tag_hash.fetch(site_id, [])
          }
        end

        def finding_hash(node)
          closed_at = Time.parse(node[:closed]) if node[:closed]

          {
            scanner_identifier: node[:id],
            scanner_type: "NTT Sentinel Dynamic",
            created_at: Time.parse(node[:found]),
            last_seen_at: closed_at || Time.now,
            last_fixed_on: closed_at,
            closed_at:,
            vuln_def_name: node[:class],
            triage_state: map_status_to_triage_state(node.fetch(:status)),
            severity: severity_of(node),
            additional_fields: attack_vectors(node)
          }.compact
        end

        def vuln_def_hash(node)
          {
            scanner_identifier: node[:class],
            scanner_type: "NTT Sentinel Dynamic",
            name: node[:class],
            description: node[:description][:description],
            solution: node[:solution][:solution],
            cwe_identifiers: cwe_identifiers_from(node)
          }.compact
        end

        private

        def map_status_to_triage_state(status)
          case status.upcase
          when "OPEN"
            "in_progress"
          when "CLOSED"
            "resolved"
          when "ACCEPTED"
            "risk_accepted"
          when "INVALID"
            "not_a_security_issue"
          else
            "new"
          end
        end

        def severity_of(node)
          if @scoring_system == :legacy
            node.fetch(:severity).to_i * 2
          else
            node.fetch(:risk).to_i * 2
          end
        end

        def tags_for(asset)
          [asset[:tags],
           asset[:label],
           asset[:asset_owner_name],
           asset[:custom_asset_id]].flatten.compact.reject(&:empty?)
        end

        def attack_vectors(node)
          vector_count = node.fetch(:attack_vectors, []).count
          return {} if vector_count.zero?

          node[:attack_vectors].foreach_with_index.map do |vector, i|
            suffix = "_#{i}" unless vector_count == 1
            {
              "request#{suffix}_method": vector[:request][:method],
              "request#{suffix}_url": vector[:request][:url],
              "request#{suffix}_body": vector[:request][:body],
              "request#{suffix}_param_name": vector[:request][:param_name],
              "request#{suffix}_param_value": vector[:request][:param_value],
              "request#{suffix}_headers": combine_headers(vector[:request][:headers]),
              "response#{suffix}_status": vector[:response][:status],
              "response#{suffix}_headers": combine_headers(vector[:response][:headers])
            }.compact.transform_values { |v| sanitize(v) }
          end.reduce(&:merge)
        end

        def combine_headers(headers)
          return nil if headers.nil? || headers.empty?

          headers.map { |header| "#{header[:name]}=#{header[:value]}" }.join(" ")
        end

        def sanitize(string)
          @sanitizer.fragment(string)
        end

        def cwe_identifiers_from(node)
          identifiers = node[:description][:description].scan(CWE_REGEX)
          identifiers += node[:solution][:solution].scan(CWE_REGEX)
          identifiers = identifiers.flatten.uniq
          return unless identifiers.any?

          identifiers.map { |id| "CWE-#{id}" }.join(",")
        end
      end
    end
  end
end
