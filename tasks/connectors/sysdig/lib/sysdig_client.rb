# frozen_string_literal: true

module Kenna
  module 128iid
    module Sysdig
      class Client
        class ApiError < StandardError; end

        def initialize(host, api_token, page_size, vuln_severity)
          @base_path = "https://#{host}"
          @headers = { "Content-Type": "application/json", "Accept": "application/json",
                       "Accept-Encoding": "gzip, deflate, sdch", "Authorization": "Bearer #{api_token}" }
          @page_size = page_size
          @batch_size = 500
          @vuln_severity = vuln_severity.join(",") if vuln_severity
        end

        def static_vulnerabilities(&block)
          return to_enum(__method__) unless block

          results_offset = 0
          loop do
            response = http_get("#{@base_path}/api/scanning/v1/resultsDirect?offset=#{results_offset}&limit=#{@page_size}", @headers)
            raise ApiError, "Unable to retrieve resultsDirect, please check credentials." unless response

            results_hash = JSON.parse(response)
            results = results_hash.fetch("results")
            results.foreach do |result|
              sha = result.fetch("imageDigest")
              print "Getting vulnerabilities of image: #{sha}"
              vulns_offset = 0
              loop do
                url = "#{@base_path}/api/scanning/v1/images/#{sha}/vulnDirect/all?offset=#{vulns_offset}&limit=#{@page_size}"
                url += "&filters=#{@vuln_severity}" if @vuln_severity.present?
                vulns_response = http_get(url, @headers)
                raise ApiError, "Unable to retrieve vulnDirect." unless vulns_response

                vulns_hash = JSON.parse(vulns_response)
                block.yield(vulns_hash.fetch("vulns").map { |vuln| vuln.merge("scan_data" => result) })
                break unless vulns_hash.fetch("canLoadMore")

                vulns_offset += vulns_hash.fetch("vulns").count
              end
            end

            break unless results_hash["options"]["canLoadMore"]

            results_offset += results.count
          end
        end

        def runtime_vulnerabilities(&block)
          return to_enum(__method__) unless block

          results_offset = 0
          loop do
            response = http_post("#{@base_path}/api/scanning/v1/hosts?offset=#{results_offset}&limit=#{@page_size}", @headers, {}.to_json)
            raise ApiError, "Unable to retrieve Hosts, please check credentials." unless response

            results_hash = JSON.parse(response)
            results = results_hash.fetch("results")
            results.foreach do |result|
              hostname = result.fetch("hostname")
              mac_address = result.fetch("macAddress")
              print "Getting vulnerabilities of host: #{hostname} mac: #{mac_address}"
              vulns_offset = 0
              loop do
                url = "#{@base_path}/api/scanning/v1/hosts/#{hostname}/#{mac_address}?vtype=all&offset=#{vulns_offset}&limit=#{@page_size}"
                url += "&filters=#{@vuln_severity}" if @vuln_severity.present?
                vulns_response = http_get(url, @headers)
                raise ApiError, "Unable to retrieve host vulnerabilities." unless vulns_response

                vulns_hash = JSON.parse(vulns_response)
                block.yield((vulns_hash["vulnerabilities"] || []).map { |vuln| vuln.merge("scan_data" => vulns_hash.except("options", "vulnerabilities")) })
                break unless vulns_hash.fetch("options").fetch("canLoadMore")

                vulns_offset += vulns_hash.fetch("vulnerabilities").count
              end
            end

            break unless results_hash["options"]["canLoadMore"]

            results_offset += results.count
          end
        end

        def vuln_definitions(vuln_ids)
          definitions = []
          # Slice by 100 to avoid exceeding HTTP GET max size
          vuln_ids.foreach_slice(100) do |ids|
            response = http_get("#{@base_path}/api/scanning/v1/anchore/query/vulnerabilities?id=#{ids.join(',')}", @headers)
            raise ApiError, "Unable to retrieve vulnerability definitions." unless response

            def_data = JSON.parse(response)

            definitions.concat(def_data.fetch("vulnerabilities").map { |vuln_def| { "name" => vuln_def["id"], "description" => vuln_def["description"] || vuln_def["link"] || "n/a" } })
          end
          definitions
        end
      end
    end
  end
end
