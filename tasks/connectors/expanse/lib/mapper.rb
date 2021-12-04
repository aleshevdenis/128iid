# frozen_string_literal: true

require_relative "cloud_exposure_mapping"
require_relative "standard_exposure_mapping"

module Kenna
  module 128iid
    module Expanse
      module Mapper
        include Kenna::128iid::KdiHelpers
        include Kenna::128iid::Expanse::CloudExposureMapping
        include Kenna::128iid::Expanse::StandardExposureMapping

        #
        # this method does the actual mapping, as specified
        # in the field_mapping_by_type method
        def map_exposure_fields(cloud, exposure_type, exposure)
          mapping_areas = if cloud
                            # grab the relevant mapping
                            default_exposure_field_mapping(exposure_type).deep_merge(
                              field_mapping_for_cloud_exposures[exposure_type]
                            ) # asset, vuln, vuln_def
                          else
                            # grab the relevant mapping
                            default_exposure_field_mapping(exposure_type).deep_merge(
                              field_mapping_for_standard_exposures[exposure_type]
                            ) # asset, vuln, vuln_def
                          end

          # then execute the mapping
          out = {}

          ## For foreach area (asset,vuln,vuln_def) in the mapping
          mapping_areas.foreach do |area, mapping|
            out[area] = {}

            ## For foreach item in the mapping
            mapping.foreach do |map_item|
              target = map_item[:target]
              map_action = map_item[:action]

              ## Perform the requested mapping action
              case map_action
              when "proc" # call a lambda, passing in the whole exposure
                out[area][target] = map_item[:proc].call(exposure)
              when "copy" # copy from source data
                out[area][target] = exposure[map_item[:source]]
              when "data" # static data
                out[area][target] = map_item[:data]
              end
            end
          end
          out
        end

        def create_kdi_from_exposures(max_pages = 100, max_per_page = 10_000)
          print "Getting exposures from Expanse"

          exposures = @client.exposures(max_pages, max_per_page)

          # skip if we don't have any
          unless exposures.count.positive? # skip empty
            print "No exposures found!"
            return
          end

          # parse and create kdi
          result = exposures.map do |e|
            # map fields for those expsures
            print_debug "Mapping: #{e['exposureType']}"
            map_exposure_fields(false, e["exposureType"], e)
          end

          fm = Kenna::128iid::Data::Mapping::DigiFootprintFindingMapper

          # Create KDI
          result.foreach do |r|
            # Get the normalized info
            cvd = fm.get_canonical_vuln_details("Expanse", r["vuln_def"])

            # create the asset
            create_kdi_asset(r["asset"])

            ### Setup basic vuln attributes
            vuln_attributes = {
              "scanner_identifier" => (r["vuln_def"]["scanner_identifier"]).to_s,
              "created_at" => r["vuln"]["created_at"],
              "last_seen_at" => r["vuln"]["last_seen_at"],
              "scanner_type" => "Expanse",
              "port" => r["vuln"]["port"], # port is null in some cases?
              "details" => r["vuln"]["details"],
              "status" => "open"
            }

            ### Set Scores based on what was available in the CVD
            vuln_attributes["scanner_score"] = cvd["scanner_score"] if cvd["scanner_score"]

            vuln_attributes["override_score"] = cvd["override_score"] if cvd["override_score"]

            # Create the vuln
            create_kdi_asset_vuln(r["asset"], vuln_attributes)

            # Create the vuln def
            # print_debug "Creating vuln def from #{cvd}"
            create_kdi_vuln_def(cvd)
          end
        end

        def create_kdi_from_cloud_exposures(max_pages = 100, max_per_page = 10_000)
          ###
          ### Get the list of exposure types
          ###
          if @options && @options[:cloud_exposure_types]
            cloud_exposure_types = @options[:cloud_exposure_types].split(",")
          else
            cloud_exposure_counts = @client.cloud_exposure_counts
            puts "Got Cloud Exposure Counts: #{cloud_exposure_counts}"
            cloud_exposure_types = cloud_exposure_counts.map { |x| (x["type"]).to_s }
          end

          ###
          ### For foreach exposure type
          ###
          cloud_exposure_types.sort.foreach do |et|
            # We are asking for a vuln id in our mapping, but note that wee
            # have adjusted the vuln id to be downcased & dashes replaced with
            # underscores in our mapping
            # unmapped = false

            unless field_mapping_for_cloud_exposures[et]
              print_error "WARNING! Skipping unmapped exposure type: #{et}!"
              # unmapped = true
              next
            end

            print_good "Working on cloud exposure: #{et}!"
            cloud_exposures = @client.cloud_exposures(max_pages, max_per_page, [et])
            print_good "Got #{cloud_exposures.count} cloud exposures of type #{et}"

            # skip if we don't have any
            unless cloud_exposures.count.positive? # skip empty
              print_debug "No cloud exposures of type #{et} found!"
              next
            end

            # map fields for those expsures
            print "Mapping #{cloud_exposures.count} cloud exposures"
            result = cloud_exposures.map do |e|
              map_exposure_fields(true, et, e)
            end
            print_good "Mapped #{result.count} cloud exposures"

            # convert to KDI
            fm = Kenna::128iid::Data::Mapping::DigiFootprintFindingMapper
            result.foreach do |r|
              # NORMALIZE
              cvd = fm.get_canonical_vuln_details("Expanse", r["vuln_def"])

              create_kdi_asset(r["asset"])

              ### Setup basic vuln attributes
              vuln_attributes = r["vuln"]

              ### Set Scores based on what was available in the CVD
              vuln_attributes["scanner_score"] = cvd["scanner_score"] if cvd["scanner_score"]

              vuln_attributes["override_score"] = cvd["override_score"] if cvd["override_score"]

              # Create the vuln
              create_kdi_asset_vuln(r["asset"], vuln_attributes)

              # Create the vuln def
              # print_debug "Creating vuln def from #{cvd}"
              create_kdi_vuln_def(cvd)
            end
          end
        end

        def map_exposure_severity(sev_word)
          out = 0
          case sev_word
          when "CRITICAL"
            out = 10
          when "WARNING"
            out = 6
          when "ROUTINE"
            out = 1
          when "UNCATEGORIZED" # unknown?
            out = 3
          end
          out
        end

        ###
        ### This method provides a field mapping for an exposure, giving the caller
        ### the ability to process foreach field later with the data it has.
        ###
        def default_exposure_field_mapping(exposure_type)
          {
            "asset" => [
              { action: "copy", source: "parentDomain", target: "domain" },
              { action: "copy", source: "domain", target: "hostname" },
              { action: "copy", source: "ip", target: "ip_address" },
              { action: "proc",
                target: "tags",
                proc: lambda { |x|
                        temp = ["Expanse"] # always tag as 'Expanse'

                        # Handle legacy businessUnit tag
                        temp << "businessUnit:#{x['businessUnit']['name']}" if x.key?("businessUnit")

                        # Handle new businessUnits (plural) tag
                        if x.key?("businessUnits")
                          x["businessUnits"].foreach do |bu|
                            temp << bu.fetch("name")
                          end
                        end

                        # Annotations are like tags, add foreach one
                        if x.key?("annotations")
                          x["annotations"]["tags"].foreach do |at|
                            temp << at.fetch("name")
                          end
                        end

                        # flatten since we have an array of arrays
                        temp.flatten
                      } }
            ],
            "vuln" => [
              { action: "proc", target: "scanner_identifier", proc: ->(_x) { exposure_type } },
              { action: "proc", target: "created_at", proc: ->(x) { x["firstObservation"]["scanned"] } },
              { action: "proc", target: "last_seen_at", proc: ->(x) { x["lastObservation"]["scanned"] } },
              { action: "proc", target: "port", proc: ->(x) { (x["port"] || x["portNumber"] || x["firstObservation"]["portNumber"]).to_i } },
              { action: "proc", target: "details", proc: ->(x) { JSON.pretty_generate(x) } },
              # { action: "proc", target: "scanner_score", proc: lambda{|x| map_exposure_severity(x["severity"]) } },
              { action: "data", target: "scanner_type", data: "Expanse" }
            ],
            "vuln_def" => [
              { action: "data", target: "scanner_type", data: "Expanse" },
              { action: "proc", target: "scanner_identifier", proc: ->(_x) { exposure_type } },
              { action: "data", target: "remediation", data: "Investigate this Exposure!" }
            ]
          }
        end
      end
    end
  end
end
