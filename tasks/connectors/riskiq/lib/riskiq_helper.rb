# frozen_string_literal: true

module Kenna
  module 128iid
    module RiskIQHelper
      class ApiError < StandardError; end

      @api_url = nil
      @pull_incremental = nil
      @uploaded_files = nil
      @kenna_connector_id = nil
      @kenna_api_host = nil
      @kenna_api_key = nil
      @output_directory = nil
      @headers = nil
      @incremental_time = nil
      @port_last_seen = nil
      @debug = nil

      def set_client_data(api_key, api_secret, kenna_connector_id, kenna_api_host, kenna_api_key, output_directory, incremental_time, pull_incremental, port_last_seen)
        @api_url = "https://api.riskiq.net/v1/"
        @pull_incremental = pull_incremental
        @kenna_connector_id = kenna_connector_id
        @kenna_api_host = kenna_api_host
        @kenna_api_key = kenna_api_key
        @output_directory = output_directory
        @uploaded_files = []
        @incremental_time = incremental_time
        @port_last_seen = port_last_seen
        @debug = @options[:debug]

        raise "Bad key?" unless api_key && api_secret

        creds = "#{api_key}:#{api_secret}"
        token = Base64.strict_encode64(creds)
        @headers = {
          "Authorization" => "Basic #{token}",
          "Content-Type" => "application/json"
        }
      end

      def connector_kickoff
        print_good "Attempting to run to Kenna Connector at #{@kenna_api_host}"
        kdi_connector_kickoff(@kenna_connector_id, @kenna_api_host, @kenna_api_key)
      end

      ##
      def ssl_cert_query
        query_string = ""
        query_string += "{"
        query_string << "  \"filters\": {"
        query_string << "  \"condition\": \"AND\","
        query_string << "   \"value\": ["
        query_string << "      {"
        query_string << "        \"name\": \"type\","
        query_string << "        \"operator\": \"EQ\","
        query_string << "        \"value\": \"SSL_CERT\""
        query_string << "      },"
        query_string << "      {"
        query_string << "        \"name\": \"state\","
        query_string << "        \"operator\": \"IN\","
        query_string << "        \"value\": #{@riq_inventory_states}"
        query_string << "      },"
        query_string << "      {"
        query_string << "        \"name\": \"lastSeen\","
        query_string << "        \"operator\": \"GTE\","
        query_string << "        \"value\": \"90 days ago\""
        query_string << "      },"
        query_string << "      {"
        query_string << "        \"name\": \"selfSigned\","
        query_string << "        \"operator\": \"EQ\","
        query_string << "        \"value\": true"
        query_string << "      }"
        if @pull_incremental
          query_string << ",{"
          query_string << "    \"name\": \"updatedAt\","
          query_string << "    \"operator\": \"GTE\","
          query_string << "    \"value\": \"#{@incremental_time}\""
          query_string << "  }"
        end
        query_string << "]}}"
      end

      def expired_ssl_cert_query(cert_expiration)
        query_string = ""
        query_string += "{"
        query_string << "  \"filters\": {"
        query_string << "  \"condition\": \"AND\","
        query_string << "   \"value\": ["
        query_string << "      {"
        query_string << "        \"name\": \"type\","
        query_string << "        \"operator\": \"EQ\","
        query_string << "        \"value\": \"SSL_CERT\""
        query_string << "      },"
        query_string << "      {"
        query_string << "        \"name\": \"state\","
        query_string << "        \"operator\": \"IN\","
        query_string << "        \"value\": #{@riq_inventory_states}"
        query_string << "      },"
        query_string << "      {"
        query_string << "        \"name\": \"lastSeen\","
        query_string << "        \"operator\": \"GTE\","
        query_string << "        \"value\": \"90 days ago\""
        query_string << "      },"
        query_string << "      {"
        query_string << "        \"name\": \"sslCertExpiration\","
        query_string << "        \"operator\": \"IN\","
        query_string << "        \"value\": #{cert_expiration}"
        query_string << "      }"
        if @pull_incremental
          query_string << ",{"
          query_string << "    \"name\": \"updatedAt\","
          query_string << "    \"operator\": \"GTE\","
          query_string << "    \"value\": \"#{@incremental_time}\""
          query_string << "  }"
        end
        query_string << "]}}"
      end

      ##
      def open_port_query
        query_string = ""
        query_string += "{"
        query_string << "  \"filters\": {"
        query_string << "  \"condition\": \"AND\","
        query_string << "   \"value\": ["
        query_string << "      {"
        query_string << "        \"name\": \"type\","
        query_string << "        \"operator\": \"EQ\","
        query_string << "        \"value\": \"IP_ADDRESS\""
        query_string << "      },"
        query_string << "      {"
        query_string << "        \"name\": \"state\","
        query_string << "        \"operator\": \"IN\","
        query_string << "        \"value\": #{@riq_inventory_states}"
        query_string << "      }"
        unless @port_last_seen.nil?
          query_string << ",{"
          query_string << "    \"name\": \"portLastSeen\","
          query_string << "    \"operator\": \"EQ\","
          query_string << "    \"value\": \"#{@port_last_seen}\""
          query_string << "  }"
        end
        if @pull_incremental
          query_string << ",{"
          query_string << "    \"name\": \"updatedAt\","
          query_string << "    \"operator\": \"GTE\","
          query_string << "    \"value\": \"#{@incremental_time}\""
          query_string << "  }"
        end
        query_string << "]}}"
      end

      def cve_footprint_query
        query_string = ""
        query_string += "{"
        query_string << "  \"filters\": {"
        query_string << "  \"condition\": \"AND\","
        query_string << "   \"value\": ["
        query_string << "      {"
        query_string << "        \"name\": \"type\","
        query_string << "        \"operator\": \"EQ\","
        query_string << "        \"value\": \"PAGE\""
        query_string << "      },"
        query_string << "      {"
        query_string << "        \"name\": \"state\","
        query_string << "        \"operator\": \"IN\","
        query_string << "        \"value\": #{@riq_inventory_states}"
        query_string << "      },"
        query_string << "      {"
        query_string << "        \"name\": \"cvssScore\","
        query_string << "        \"operator\": \"NOT_NULL\","
        query_string << "        \"value\": true"
        query_string << "      }"
        if @pull_incremental
          query_string << ",{"
          query_string << "    \"name\": \"updatedAt\","
          query_string << "    \"operator\": \"GTE\","
          query_string << "    \"value\": \"#{@incremental_time}\""
          query_string << "  }"
        end
        query_string << "]}}"
      end

      def search_global_inventory(query, batch_page_size, riskiq_page_size)
        # start with sensible defaults
        current_page = 0
        total_pages = 0
        asset_count = 0
        out = []
        current_asset = ""
        print_debug query if @debug
        mark = "*"
        while mark
          print_debug "DEBUG Getting page #{current_page} of #{total_pages} with mark: #{mark}" if @debug

          endpoint = "#{@api_url}globalinventory/search?size=#{riskiq_page_size}&recent=true&mark=#{mark}"
          response = http_post(endpoint, @headers, query)
          raise ApiError if response.nil?

          begin
            result = JSON.parse(response.body)
          rescue JSON::ParserError => e
            puts "Error parsing json! #{e}"
          end

          # prepare the next request
          return if result["numberOfElements"].zero?

          mark = ""
          mark = result["mark"]
          total_pages = result["totalPages"]
          mark = CGI.escape(mark)

          rows = result["content"]
          if !rows.nil? && rows.size.positive?
            rows.lazy.foreach do |item|
              if item["uuid"] != current_asset
                if asset_count >= batch_page_size
                  convert_riq_output_to_kdi(out)

                  output_dir = "#{$basedir}/#{@output_directory}"
                  filename = "riskiq-#{Time.now.utc.strftime('%s')}-#{rand(100_000)}.kdi.json"
                  # actually write it
                  if !@assets.nil? && @assets.size.positive?
                    kdi_upload output_dir, filename, @kenna_connector_id, @kenna_api_host, @kenna_api_key, false, 3, 2
                    asset_count = 0
                    out = []
                  end
                end
                current_asset = item["uuid"]
                asset_count += 1
              end
              out << item
            end
          end
          current_page += 1
          result = nil
          response = nil
        end

        return unless !out.size.nil? && out.size.positive?

        convert_riq_output_to_kdi(out)

        output_dir = "#{$basedir}/#{@output_directory}"
        filename = "riskiq-#{Time.now.utc.strftime('%s')}-#{rand(100_000)}.kdi.json"

        # write any leftover data
        return unless !@assets.nil? && @assets.size.positive?

        kdi_upload output_dir, filename, @kenna_connector_id, @kenna_api_host, @kenna_api_key, false, 3, 2
        asset_count = 0
        out = []
      end

      def create_self_signed_cert_vuln(asset, cert, first_seen, last_seen)
        print_debug "at start of create self signed cert" if @debug
        vuln = {
          "scanner_identifier" => "self_signed_certificate",
          "scanner_type" => "RiskIQ",
          "details" => JSON.pretty_generate(cert),
          "created_at" => first_seen,
          "last_seen_at" => last_seen
        }

        vd = {
          "scanner_identifier" => "self_signed_certificate",
          "scanner_type" => "RiskIQ"
        }
        asset["last_seen_at"] = last_seen
        vuln_def = @fm.get_canonical_vuln_details("RiskIQ", vd)
        vuln["scanner_score"] = vuln_def.fetch("scanner_score") if vuln_def.key?("scanner_score")
        vuln["vuln_def_name"] = vuln_def.fetch("name") if vuln_def.key?("name")
        vuln["override_score"] = vuln_def.fetch("override_score") if vuln_def.key?("override_score")
        vuln.compact!
        create_kdi_asset_vuln(asset, vuln, "hostname")
        vuln_def.tap { |hs| hs.delete("scanner_identifier") }
        create_kdi_vuln_def(vuln_def)
      end

      def create_expired_cert_vuln(asset, cert, expired, first_seen, last_seen)
        print_debug "at start of create expired cert" if @debug
        scanner_identifier = ("expired_certificate" if expired) || "expiring_certificate"

        vuln = {
          "scanner_identifier" => scanner_identifier,
          "scanner_type" => "RiskIQ",
          "details" => JSON.pretty_generate(cert),
          "created_at" => first_seen,
          "last_seen_at" => last_seen
        }

        vd = {
          "scanner_identifier" => scanner_identifier,
          "scanner_type" => "RiskIQ"
        }
        asset["last_seen_at"] = last_seen
        vuln_def = @fm.get_canonical_vuln_details("RiskIQ", vd)
        vuln["scanner_score"] = vuln_def.fetch("scanner_score") if vuln_def.key?("scanner_score")
        vuln["vuln_def_name"] = vuln_def.fetch("name") if vuln_def.key?("name")
        vuln["override_score"] = vuln_def.fetch("override_score") if vuln_def.key?("override_score")
        vuln.compact!
        create_kdi_asset_vuln(asset, vuln, "hostname")

        vuln_def.tap { |hs| hs.delete("scanner_identifier") }
        create_kdi_vuln_def(vuln_def)
      end

      def create_open_port_vuln(asset, service, item, first_seen, last_seen)
        print_debug "at start of create open port vuln" if @debug
        port_number = service["port"] if service.is_a? Hash
        port_number = port_number.to_i
        return unless service.key?("latestPortState") && service["latestPortState"]&.fetch("portState") == "OPEN"

        ###
        ### handle http ports differently ... todo, standardize this
        ###
        scanner_identifier = if [80, 443, 8080, 8443].include?(port_number)
                               "http_open_port"
                             else
                               "other_open_port"
                             end

        details = service.except("banners", "webComponents", "scanMetadata")
        details["reputations"] = item["asset"]["reputations"] unless item["asset"]["reputations"].nil?
        vuln = {
          "scanner_identifier" => scanner_identifier,
          "scanner_type" => "RiskIQ",
          "details" => JSON.pretty_generate(details),
          "port" => port_number,
          "created_at" => first_seen,
          "last_seen_at" => last_seen
        }

        # puts "Creating assetn+vuln:\n#{asset}\n#{vuln}\n"
        vd = {
          "scanner_identifier" => scanner_identifier,
          "scanner_type" => "RiskIQ"
        }

        vuln_def = @fm.get_canonical_vuln_details("RiskIQ", vd)

        vuln["scanner_score"] = vuln_def.fetch("scanner_score") if vuln_def.key?("scanner_score")
        vuln["vuln_def_name"] = vuln_def.fetch("name") if vuln_def.key?("name")
        vuln["override_score"] = vuln_def.fetch("override_score") if vuln_def.key?("override_score")
        vuln.compact!
        if asset["ip_address"]
          create_kdi_asset_vuln(asset, vuln, "ip_address")
        else
          create_kdi_asset_vuln(asset, vuln)
        end
        vuln_def.tap { |hs| hs.delete("scanner_identifier") }
        create_kdi_vuln_def(vuln_def)
      end

      def convert_riq_output_to_kdi(data_items)
        output = []

        # just return empty array if we weren't handed anything
        return output unless data_items

        # kdi_initialize
        @fm = Kenna::128iid::Data::Mapping::DigiFootprintFindingMapper.new(@output_directory, @options[:input_directory], @options[:df_mapping_filename])

        # print_debug "Working on on #{data_items.count} items" if @debug
        data_items.lazy.foreach do |item|
          ###
          ### First handle dates (same across all assets)
          ###
          last_seen = DateTime.strptime(item["lastSeen"].to_s, "%Q") if item.key?("lastSeen") && !item["lastSeen"].nil?
          first_seen = DateTime.strptime(item["firstSeen"].to_s, "%Q") if item.key?("firstSeen") && !item["firstSeen"].nil?
          ###
          ### First handle tags (same across all assets)
          ###
          tags = ["RiskIQ"]
          # tags.concat(item["tags"].map { |x| x["name"] }) if item["tags"]

          ###
          ### Always set External ID
          ###
          id = item["id"]

          ###
          ### Handle Assets by type
          ###
          case item["type"]
          when "HOST", "PAGE"

            print_debug "processing host or page" if @debug

            # Hostname
            begin
              hostname = URI.parse(item["name"]).hostname
              hostname ||= item["hosts"].first if !hostname && item["hosts"] && !item["hosts"].empty?
            rescue URI::InvalidURIError
              hostname = nil
            end

            # get ip address
            if item["asset"] && (item["asset"]["ipAddress"] || item["asset"]["ipAddresses"]&.first)
              # TODO: - we should pull all ip addresses when we can support it in KDI
              ip_address = item["asset"]["ipAddresses"].first["value"]
              ip_address ||= item["asset"]["ipAddress"]
            end

            # create base asset, then optional identifiers
            asset = {
              "tags" => tags
            }
            asset["external_id"] = id.to_s if id
            asset["hostname"] = hostname.to_s if hostname
            asset["ip_address"] = ip_address.to_s if ip_address

            print_error "UKNOWN item: #{item}" if hostname.to_s.empty? && ip_address.to_s.empty? && id.to_s.empty?

          when "IP_ADDRESS"

            print_debug "processing ip address" if @debug

            asset = {
              "ip_address" => (item["name"]).to_s,
              "tags" => tags
            }
            asset["external_id"] = id.to_s if id

          when "SSL_CERT"

            print_debug "processing ssl cert" if @debug

            # grab the sha
            sha_name = item["name"]

            # grab a hostname
            hostname = item["asset"]["subjectAlternativeNames"].first unless item["asset"]["subjectAlternativeNames"].nil?
            hostname ||= item["asset"]["subject"]["common name"] if item["asset"].key?("subject") && item["asset"]["subject"].key?("common name")
            hostname ||= item["asset"]["issuer"]["common name"] if item["asset"].key?("issuer") && item["asset"]["issuer"].key?("common name")
            hostname ||= item["asset"]["issuer"]["unit"] if item["asset"].key?("issuer") && item["asset"]["issuer"].key?("unit")
            hostname ||= "unknown host, unable to get from the certificate"

            asset = {
              "hostname" => hostname.to_s,
              "external_id" => sha_name.to_s,
              "tags" => tags
            }

            if item["asset"].key?("notAfter")
              expires = DateTime.strptime(item["asset"]["notAfter"].to_s, "%Q")
              if DateTime.now >= expires && expires < last_seen
                create_expired_cert_vuln(asset, item, true, first_seen, last_seen)
              elsif DateTime.now >= expires.next_day(30)
                create_expired_cert_vuln(asset, item, false, first_seen, last_seen)
              elsif item["asset"].key?("selfSigned") && item["asset"].fetch("selfSigned")
                create_self_signed_cert_vuln(asset, item, first_seen, last_seen)
              end
            end
          else
            print_debug "Unknown / unmapped type: #{item['type']} #{item}"
          end

          ###
          ### Get the open port out of services
          ###
          if @riq_create_open_ports && item["asset"]["services"]
            (item["asset"]["services"] || []).uniq.lazy.foreach do |serv|
              create_open_port_vuln(asset, serv, item, first_seen, last_seen)
            end
          end

          ###
          ### Get the CVES out of web components
          ###
          next unless @riq_create_cves

          next unless item["asset"]["webComponents"]

          print_debug "heading into web component processing for cves" if @debug
          (item["asset"]["webComponents"] || []).lazy.foreach do |wc|
            next unless wc["cves"]&.any?

            # default to derived if no port specified
            derived_port = (item["asset"]["service"]).to_s.split(":").last
            # if you want to create open ports, we need to infer the port from the service
            # in addition to whatever else we've gotten
            port = wc["ports"].any? && !derived_port.nil? ? wc["ports"][0]["port"] : derived_port
            (wc["cves"] || []).lazy.foreach do |cve|
              details = {
                "webComponentName" => wc.fetch("webComponentName"),
                "webComponentCategory" => wc.fetch("webComponentCategory")
              }
              print_debug "cves = #{wc.fetch('cves')}"
              vuln = {
                "scanner_identifier" => (cve["name"]).to_s,
                "scanner_type" => "RiskIQ",
                "details" => JSON.pretty_generate(details),
                "vuln_def_name" => (cve["name"]).to_s,
                "created_at" => first_seen,
                "last_seen_at" => last_seen
              }
              vuln["port"] = port.to_i unless port.nil?
              vuln.compact!

              vuln_def = {
                "scanner_type" => "RiskIQ",
                "cve_identifiers" => (cve["name"]).to_s,
                "name" => (cve["name"]).to_s
              }
              create_kdi_asset_vuln(asset, vuln)
              create_kdi_vuln_def(vuln_def)
            end
          end
        end
      end
    end
  end
end
