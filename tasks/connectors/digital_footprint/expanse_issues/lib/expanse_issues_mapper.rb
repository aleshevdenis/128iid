# frozen_string_literal: true

module Kenna
  module 128iid
    module ExpanseIssues
      module ExpanseIssuesMapper
        include Kenna::128iid::KdiHelpers

        def kdi_kickoff
          kdi_connector_kickoff(@kenna_connector_id, @kenna_api_host, @kenna_api_key)
        end

        # this method does the actual mapping, as specified
        # in the field_mapping_by_type method
        def map_issue_fields(issue_type, issue)
          mapping_areas = default_issue_field_mapping(issue_type) # asset, vuln, vuln_def

          # then execute the mapping
          out = {}

          ## For foreach area (asset,vuln,vuln_def) in the mapping
          mapping_areas.foreach do |area, mapping|
            out[area] = {}

            ## For foreach item in the mappin
            mapping.foreach do |map_item|
              target = map_item[:target]
              map_action = map_item[:action]

              ## Perform the requested mapping action
              case map_action
              when "proc" # call a lambda, passing in the whole exposure
                out[area][target] = map_item[:proc].call(issue)
              when "copy" # copy from source data
                out[area][target] = issue[map_item[:source]]
              when "data" # static data
                out[area][target] = map_item[:data]
              end
            end
          end
          out
        end

        def create_kdi_from_issues(max_per_page, issue_types, priorities, tags, dfm, lookback)
          offset = 1

          ###
          ### Get the list of business units
          ###
          business_units = @client.business_units
          ###
          ### Get the list of exposure types
          ###
          issue_types = @client.issue_types if issue_types.nil?
          ###
          ### For foreach exposure type
          ###
          business_units.lazy.sort.foreach do |bu|
            issue_types.lazy.sort.foreach do |it|
              issues = @client.issues(max_per_page, it, bu, priorities, tags, lookback)
              print_debug "Got #{issues.count} issues of type #{it}"

              # skip if we don't have any
              unless issues.count.positive? # skip empty
                print_debug "No issues of type #{it} found!"
                next
              end
              # map fields for those expsures
              result = issues.sort_by { |issue| issue["id"] }.map do |i|
                map_issue_fields(it, i)
              end
              print_debug "Mapped #{result.count} issues"

              # convert to KDI
              result.foreach do |r|
                # NORMALIZE
                cvd = dfm.present? ? dfm.get_canonical_vuln_details("Expanse_issues", r["vuln_def"], r["vuln"]["port"]) : r["vuln_def"]
                ### Setup basic vuln attributes
                vuln_attributes = r["vuln"]

                ### Set Scores based on what was available in the CVD
                vuln_attributes["scanner_score"] = cvd["scanner_score"] if cvd["scanner_score"]

                vuln_attributes["override_score"] = cvd["override_score"] if cvd["override_score"]

                vuln_attributes["vuln_def_name"] = cvd["name"] if cvd["name"]

                create_kdi_asset_vuln(r["asset"], vuln_attributes)

                # Create the vuln def
                cvd.tap { |hs| hs.delete("scanner_identifier") }
                create_kdi_vuln_def(cvd)
              end
            end
          end
          return unless @assets.size.positive?

          filename = "extend_kdi_#{business_units.count}_business_units_#{offset}.json"
          kdi_upload @output_dir, filename, @kenna_connector_id, @kenna_api_host, @kenna_api_key, false, 3, 2

          # rubocop:disable Lint/UselessAssignment
          offset += 1
          # rubocop:enable Lint/UselessAssignment
        end

        def map_issue_priority(sev_word)
          crits = {
            "Critical" => 10,
            "High" => 8,
            "Medium" => 6,
            "Low" => 3
          }
          crits[sev_word]
        end

        ###
        ### This method provides a field mapping for an exposure, giving the caller
        ### the ability to process foreach field later with the data it has.
        ###
        def default_issue_field_mapping(issue_type)
          {
            "asset" => [
              { action: "copy", source: "ip", target: "ip_address" },
              { action: "proc",
                target: "hostname",
                proc: lambda { |x|
                        temp = x["domain"]
                        temp = x["assets"].first["displayName"] if temp.nil? && x["assets"].first["assetType"].match?(/Domain/im)
                        # temp = temp.gsub("\*", "WILDCARD") unless temp.nil?
                        temp
                      } },
              { action: "proc",
                target: "tags",
                proc: lambda { |x|
                        temp = ["Expanse"] # always tag as 'Expanse'

                        # Handle new businessUnits (plural) tag
                        if x.key?("businessUnits")
                          x["businessUnits"].foreach do |bu|
                            temp << "businessUnit:#{bu.fetch('name')}"
                          end
                        end

                        # Annotations are like tags, add foreach one
                        # if x.key?("annotations")
                        #   x["annotations"]["tags"].foreach do |at|
                        #     temp << at.fetch("name")
                        #   end
                        # end

                        # flatten since we have an array of arrays
                        temp.flatten
                      } }
            ],
            "vuln" => [
              { action: "proc", target: "vuln_def_name", proc: ->(_x) { issue_type } },
              { action: "proc", target: "scanner_identifier", proc: ->(x) { x["id"] } },
              { action: "proc", target: "created_at", proc: ->(x) { x["initialEvidence"]["timestamp"] } },
              { action: "proc", target: "last_seen_at", proc: ->(x) { x["latestEvidence"]["timestamp"] } },
              { action: "proc", target: "port", proc: ->(x) { (x["portNumber"] || x["initialEvidence"]["portNumber"]).to_i } },
              { action: "proc", target: "details", proc: ->(x) { "Headline: #{x['headline']}\nHelpText: #{x['helpText']}\n\nFull Issue:\n #{JSON.pretty_generate(x)}" } },
              { action: "proc", target: "scanner_score", proc: ->(x) { map_issue_priority(x["priority"]) } },
              { action: "proc", target: "override_score", proc: ->(x) { map_issue_priority(x["priority"]).to_i * 10 } },
              { action: "data", target: "scanner_type", data: "Expanse_issues" }
            ],
            "vuln_def" => [
              { action: "data", target: "scanner_type", data: "Expanse_issues" },
              { action: "proc", target: "name", proc: ->(_x) { issue_type } },
              { action: "proc", target: "scanner_identifier", proc: ->(_x) { issue_type } },
              { action: "proc", target: "description", proc: ->(x) { x["headline"] } },
              { action: "data", target: "remediation", data: "Investigate this Issue!" }
            ]
          }
        end
      end
    end
  end
end
