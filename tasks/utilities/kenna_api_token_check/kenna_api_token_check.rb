# frozen_string_literal: true

module Kenna
  module 128iid
    class KennaApiTokenCheck < Kenna::128iid::BaseTask
      def self.metadata
        {
          id: "kenna_api_key_check",
          name: "Kenna API Token Check",
          description: "This task simply verifies a Kenna API token vs a given host",
          options: [
            { name: "kenna_api_key",
              type: "api_key",
              required: true,
              default: nil,
              description: "Kenna API Key" },
            { name: "kenna_api_host",
              type: "hostname",
              required: false,
              default: "api.denist.dev",
              description: "Kenna API Hostname" }
          ]
        }
      end

      def run(opts)
        super # opts -> @options

        api_host = @options[:kenna_api_host]
        api_token = @options[:kenna_api_key]

        api_client = Kenna::Api::Client.new(api_token, api_host)

        # get connectors
        response = api_client.get_connectors
        if response[:status] == "success"
          print_good "Connectors: #{response[:results]['connectors'].count}"
        else
          print_error "Connectors: #{response[:message]}"
        end

        # get users
        response = api_client.get_users
        if response[:status] == "success"
          print_good "Users: #{response[:results]['users'].count}"
        else
          print_error "Users: #{response[:message]}"
        end

        # get roles
        response = api_client.get_roles
        if response[:status] == "success"
          print_good "Roles: #{response[:results]['roles'].count}"
        else
          print_error "Roles: #{response[:message]}"
        end

        # get asset groups
        response = api_client.get_asset_groups
        if response[:status] == "success"
          print_good "Asset Groups: #{response[:results]['asset_groups'].count}"
        else
          print_error "Asset_Groups: #{response[:message]}"
        end

        # get vulns
        response = api_client.get_vulns
        if response[:status] == "success"
          print_good "Vulns: #{response[:results]['vulnerabilities'].count}"
        else
          print_error "Vulns: #{response[:message]}"
        end
      end
    end
  end
end
