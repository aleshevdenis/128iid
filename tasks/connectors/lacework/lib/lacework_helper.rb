# frozen_string_literal: true

require "net/http"
require "uri"

module Kenna
  module 128iid
    module LaceworkHelper
      MAX_ATTEMPTS = 3

      def generate_temporary_lacework_api_token(account, api_key, api_secret)
        uri = URI.parse("https://#{account}.lacework.net/api/v1/access/tokens")

        request = Net::HTTP::Post.new(uri)
        request.content_type = "application/json"
        request["X-Lw-Uaks"] = api_secret.to_s
        request.body = JSON.dump({
                                   "keyId" => api_key.to_s,
                                   "expiryTime" => 9999
                                 })

        req_options = {
          use_ssl: uri.scheme == "https"
        }

        response = Net::HTTP.start(uri.hostname, uri.port, req_options) do |http|
          http.request(request)
        end

        if response.code != 200
          print_debug response.message
          return nil
        end

        JSON.parse(response.body)["data"].last["token"]
      end

      def lacework_list_hosts(account, cve_id, temp_api_token)
        raw = call("curl -s 'https://#{account}.lacework.net/api/v1/external/vulnerabilities/host/cveId/#{cve_id}?status=Active' -H 'Authorization: Bearer #{temp_api_token}'")
        JSON.parse(raw)
      end

      def lacework_list_cves(account, temp_api_token)
        raw = call("curl -s 'https://#{account}.lacework.net/api/v1/external/vulnerabilities/host' -H 'Authorization: Bearer #{temp_api_token}'")
        JSON.parse(raw)
      end

      def call(cmd)
        attempts = 0
        loop do
          attempts += 1
          response = `#{cmd}`
          status = $CHILD_STATUS
          break response if status.success?

          warn "#{cmd} failed (attempt #{attempts})."
          raise StandardError, "Retries exhausted for #{cmd}" if attempts == MAX_ATTEMPTS
        end
      end

      def vulns_for(host)
        host["packages"].map do |package|
          {
            "scanner_identifier": package["cve_link"].match(/CVE(.*)$/)[0],
            "scanner_type": "Lacework",
            "scanner_score": package["cvss_score"].to_i,
            "last_seen_at": Time.now.utc,
            "status": package["status"] == "Active" ? "open" : "closed",
            "vuln_def_name": package["cve_link"].match(/CVE(.*)$/)[0]
          }
        end
      end
    end
  end
end
