# frozen_string_literal: true

module Kenna
  module 128iid
    class UploadFile < Kenna::128iid::BaseTask
      def self.metadata
        {
          id: "upload_file",
          name: "Upload File",
          description: "This task uploads a file to a specified connector",
          options: [
            { name: "kenna_api_key",
              type: "api_key",
              required: false,
              default: nil,
              description: "Kenna API Key" },
            { name: "kenna_api_host",
              type: "hostname",
              required: false,
              default: "api.denist.dev",
              description: "Kenna API Hostname" },
            { name: "connector_id",
              type: "integer",
              required: true,
              default: -1,
              description: "Kenna Connector ID" },
            { name: "file",
              type: "filename",
              required: false,
              default: "input/file.xml",
              description: "Path to the data file, relative to #{$basedir}" }
          ]
        }
      end

      def run(options)
        super

        api_host = @options[:kenna_api_host]
        api_token = @options[:kenna_api_key]
        connector_id = @options[:connector_id]
        filepath = "#{$basedir}/#{@options[:file]}"

        # TODO. ... handled upstream?
        # unless api_host && api_token
        #  print_error "Cannot proceed, missing required options"
        #  return
        # end

        api_client = Kenna::Api::Client.new(api_token, api_host)

        print_good "Attempting to upload #{filepath}"
        api_client.upload_to_connector(connector_id, filepath)

        print_good "Done!"
      end
    end
  end
end
