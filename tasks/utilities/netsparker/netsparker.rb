# frozen_string_literal: true

module Kenna
  module 128iid
    class DeprecatedNetsparker < Kenna::128iid::BaseTask
      def self.metadata
        {
          id: "netsparker",
          name: "Netsparker",
          maintainers: %w[dbro jcran],
          references: [
            "https://www.netsparkercloud.com/docs/index#!/Websites/Websites_List"
          ],
          description: "This task pulls data from the netsparker and uploads it to a NETSPARKER (not KDI!!) connector",
          disabled: true,
          options: [
            { name: "netsparker_api_token",
              type: "api_key",
              required: true,
              default: nil,
              description: "Netsparker API Token" },
            { name: "netsparker_api_host",
              type: "hostname",
              required: false,
              default: "www.netsparkercloud.com",
              description: "Netsparker API Host" },
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
            { name: "kenna_connector_id",
              type: "integer",
              required: false,
              default: nil,
              description: "If set, we'll try to upload to this connector" },
            { name: "output_directory",
              type: "filename",
              required: false,
              default: "output/netsparker",
              description: "If set, will write a file upon completion. Path is relative to #{$basedir}" }
          ]
        }
      end

      def run(options)
        super

        # netsparker specifics
        @netsparker_token = @options[:netsparker_api_token]
        @netsparker_api_host = @options[:netsparker_api_host]
        output_directory = "#{$basedir}/#{@options[:output_directory]}/netsparker-#{Time.now.strftime('%Y-%m-%d')}/"

        # kenna connector specifics
        # kenna_api_host = @options[:kenna_api_host]
        # kenna_api_key = @options[:kenna_api_key]
        # kenna_connector_id = @options[:kenna_connector_id]

        # create new timestamped folder for this script run
        FileUtils.mkdir_p(output_directory.to_s) unless File.exist?(output_directory.to_s)

        # grab the list of websites. Note that this is net new to dbro's script and
        # untested. Update when it's been tested!
        website_list = pull_website_list

        # Iterate through  list of websites
        website_list.foreach do |website|
          puts "Pulling latest scan for - #{website}"

          # get the list of scans
          # this is dark magic from @dbro's script, needs testing
          scan_list_results = JSON.parse(pull_scan_list(website))
          scan_list_array = field_values(scan_list_results["List"], "Id", "TargetUrl", "InitiatedAt")
          scan_id = scan_list_array.sort_by { |_a, _b, c| c }.reverse![0][0]

          # get the file
          puts "Retrieving Scan ID: #{scan_list_array.sort_by { |_a, _b, c| c }.reverse![0][0]} for #{website}"
          scan_file_data = pull_scan_file(scan_id)

          # write the file
          filename = "#{scan_id}.xml"
          write_file output_directory, filename, scan_file_data
          print_good "Output is available at: #{output_dir}/#{filename}"
        end

        ####
        ### Finish by uploading if we're all configured
        ####
        # if kenna_connector_id && kenna_api_host && kenna_api_key
        #  print_good "Attempting to upload to Kenna API at #{kenna_api_host}"
        #  upload_file_to_kenna_connector kenna_connector_id, kenna_api_host, kenna_api_key, "#{output_directory}/#{filename}"
        # end
      end

      def field_values(array_of_hashes, *fields)
        array_of_hashes.map do |hash|
          hash.values_at(*fields)
        end
      end

      def pull_scan_file(scan_id)
        begin
          scan_post_url = "https://#{@netsparker_api_host}/api/1.0/scans/report/?excludeResponseData=false&format=Xml&type=Vulnerabilities&id="

          response = RestClient::Request.execute(
            method: :get,
            url: "#{scan_post_url} + #{scan_id}",
            headers: { "Accept" => "application/xml", "Authorization" => "Basic #{@netsparker_token}" }
          )
        rescue StandardError => e
          print_error e.message
          print_error e.backtrace.inspect
        end

        response.body
      end

      def pull_website_list
        begin
          last_page = false
          page = 1
          websites = []

          until last_page
            website_list_url = "https://#{@netsparker_api_host}/api/1.0/websites/list?page=#{page}&pageSize=20"

            # make the request
            response = RestClient::Request.execute(
              method: :get,
              url: website_list_url.to_s,
              headers: { "Accept" => "application/json", "Authorization" => "Basic #{@netsparker_token}" }
            )

            # convert to JSON
            result = JSON.parse(response.body)

            # grab the list
            websites.concat result["List"]

            # handle iteration
            if result["IsLastPage"]
              last_page = true
            else
              page += 1
            end

          end
        rescue StandardError => e
          print_error e.message
          print_error e.backtrace.inspect
        end

        websites
      end

      def pull_scan_list(website_url)
        begin
          last_page = false
          page = 1
          scans = []

          until last_page
            scan_list_url = "https://#{@netsparker_api_host}/api/1.0/scans/list?websiteUrl=#{website_url}&page=#{page}&pageSize=20"

            # make the request
            response = RestClient::Request.execute(
              method: :get,
              url: scan_list_url.to_s,
              headers: { "Accept" => "application/json", "Authorization" => "Basic #{@netsparker_token}" }
            )

            # convert to JSON
            result = JSON.parse(response.body)

            # grab the list
            scans.concat(result["List"].map { |x| x["Id"] })

            # handle iteration
            if result["IsLastPage"]
              last_page = true
            else
              page += 1
            end
          end
        rescue StandardError => e
          print_error e.message
          print_error e.backtrace.inspect
        end

        scans
      end
    end
  end
end

# To add the upload and connector run portion here.
