# frozen_string_literal: true

module Kenna
  module 128iid
    module NozomiHelper
      def nozomi_get_issues(username, password, hostname, node_types, pagesize, pagenum)
        print "Getting issues"
        auth_string = "#{username}:#{password}"

        key = Base64.encode64(auth_string)

        nozomi_query_api = "https://#{hostname}/api/open/query/do?query=node_cves"
        nozomi_query_api = "#{nozomi_query_api}|where node_type == #{node_types.join(' OR node_type == ')}" unless node_types.nil?
        nozomi_query_api = "#{nozomi_query_api}|sort time asc&page=#{pagenum}&count=#{pagesize}"
        headers = { "content-type" => "application/json", "accept" => "application/json", "Authorization" => "Basic #{key}" }

        response = http_get(nozomi_query_api, headers, 5, false)
        return nil unless response

        begin
          json = JSON.parse(response.body)
        rescue JSON::ParserError
          print_error "Unable to process response!"
        end

        json["result"]
      end
    end
  end
end
