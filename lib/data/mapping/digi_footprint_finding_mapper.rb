# frozen_string_literal: true

module Kenna
  module 128iid
    module Data
      module Mapping
        class DigiFootprintFindingMapper
          def initialize(output_directory, input_directory = "", mapping_file = "")
            @output_dir = output_directory
            @missing_mappings = Set.new
            @input_directory = input_directory
            @mapping_file = mapping_file
            validate_options
          end

          def get_canonical_vuln_details(orig_source, specific_details, port = nil)
            orig_vuln_id = (specific_details["scanner_identifier"]).to_s.downcase.tr(" ", "_").tr("-", "_")
            out = {}

            # If the port id provided, search including port in the condition
            mapping = find_mapping(orig_source, orig_vuln_id, port) if port
            # If no mapping found then search definition ignoring port
            mapping ||= find_mapping(orig_source, orig_vuln_id)

            if mapping
              out = {
                scanner_type: orig_source,
                scanner_identifier: orig_vuln_id,
                source: "#{orig_source} (Kenna Normalized)",
                scanner_score: (mapping[:score] / 10).to_i,
                override_score: (mapping[:score]).to_i,
                name: mapping[:name],
                description: (mapping[:description] || "").strip,
                recommendation: (mapping[:recommendation] || "").strip
              }
              out.compact!
              out = out.stringify_keys
            end
            # we didnt map it, so just pass it back
            if out.empty?
              log_missing(orig_vuln_id, orig_source)
              out = {
                scanner_identifier: orig_vuln_id,
                scanner_type: orig_source,
                source: orig_source,
                name: orig_vuln_id
              }.stringify_keys.merge(specific_details)
            end
            out
          end

          private

          def validate_options
            raise "Missing required input_directory parameter" unless @input_directory
            raise "Missing required mapping_file parameter" unless @mapping_file
            raise "Mappings file not found: #{mapping_file_path}" unless File.exist?(mapping_file_path)
          end

          def mappings
            @mappings ||= build_mappings
          end

          def mapping_file_path
            "#{@input_directory}/#{@mapping_file}"
          end

          def build_mappings
            mappings = []
            rows = CSV.parse(File.open(mapping_file_path, "r:iso-8859-1:utf-8", &:read), headers: true)
            definitions = rows.select { |row| row["type"] == "definition" }
            definitions.each do |row|
              mapping = {
                name: row[1],
                cwe: row[2],
                score: row[3].to_i,
                description: row[5],
                recommendation: row[6]
              }
              mappings << mapping
            end

          mappings_by_name = mappings.index_by { |m| m[:name] }
          total_matchers = 0
          invalid_matchers = 0

          matchers = rows.select { |row| row["type"] == "match" }
          matchers.each do |row|
            mapping = mappings_by_name[row["name"]]

          if mapping.nil?
            invalid_matchers += 1
            raise "Invalid mapping file. Matcher references non existent definition named: #{row[:name]}."
          end

          matcher = {
            source: row[2],
            vuln_id: row[3],
            ports: (row[4] || "").split(",").filter_map { |p| p.strip.to_i if p.strip.present? }
          }

          mapping[:matches] ||= []
          mapping[:matches] << matcher

          total_matchers += 1
      end

          puts "Total Matchers Processed: #{total_matchers}"
          puts "Invalid Matchers: #{invalid_matchers}"
            end
            mappings
          end

          def find_mapping(source, vuln_id, port = nil)
            mappings.find do |mapping|
              mapping[:matches].find do |match|
                match[:source] == source && match[:vuln_id]&.match?(vuln_id) && (port.blank? ? true : match[:ports].include?(port))
              end
            end
          end

          def log_missing(orig_vuln_id, orig_source)
            print_debug "WARNING! Unable to map canonical vuln for type: #{orig_vuln_id}"
            @missing_mappings << [orig_vuln_id, orig_source]
            write_file(@output_dir, "missing_mappings_#{DateTime.now.strftime('%Y-%m-%d')}.csv", @missing_mappings.map(&:to_csv).join) unless @missing_mappings.empty?
          end
        end
      end
    end
  end
end
