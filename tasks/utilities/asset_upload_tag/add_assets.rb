# frozen_string_literal: true

module Kenna
  module 128iid
    class AssetUploadTag < Kenna::128iid::BaseTask
      def self.metadata
        {
          id: "add_assets",
          name: "Add Assets",
          description: "This task does blah blah blah (TODO)",
          disabled: true,
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
              description: "Kenna API Hostname" },
            { name: "primary_locator",
              type: "string",
              required: false,
              default: "ip_address",
              description: "Field to use as the primary locator" },
            { name: "csv_file",
              type: "filename",
              required: true,
              default: "input/assets.csv",
              description: "Path to CSV file" },
            { name: "field_mapping_file",
              type: "filename",
              required: false,
              default: "tasks/asset_upload_tag/field_mapping.csv",
              description: "Path to field mapping file, relative to #{$basedir}" },
            { name: "tag_mapping_file",
              type: "filename",
              required: false,
              default: "tasks/asset_upload_tag/tag_mapping.csv",
              description: "Path to tag mapping file, relative to #{$basedir}" }
          ]
        }
      end

      # api_token, primary_locator, field_mapping_file,csv_file,tag_column_file
      def run(options)
        super

        # These are the arguments we are expecting to get - header file can be send as third parameter if not included as row 1 in csv
        # @token = ARGV[0]
        @token = @options[:kenna_api_key]

        # @primary_locator = ARGV[1]
        @primary_locator = @options[:primary_locator]

        # @field_mapping_file = ARGV[2]
        @field_mapping_file = @options[:field_mapping_file]

        # @csv_file = ARGV[3]
        @csv_file = @options[:csv_file]

        # ARGV.length == 5 ? @tag_column_file = ARGV[4] : @tag_column_file = nil
        # @tag_column_file = tag_column_file
        @tag_column_file = @options[:tag_mapping_file]

        # Variables we'll need later
        @debug = true
        @post_url = "https://#{@options[:kenna_api_host]}/assets"
        @headers = { "content-type" => "application/json", "X-Risk-Token" => @token }

        @tag_columns = []

        # Encoding characters
        # enc_colon = "%3A"
        # enc_dblquote = "%22"
        # enc_space = "%20"

        print_good "Path:#{$basedir}/#{@csv_file}"

        ## Set columns to use for tagging, if a @tag_column_file is provided

        # tag_columns = File.readlines(@tag_column_file).map{|line| line.strip}.uniq.reject(&:empty?) if !@tag_column_file.nil?
        num_lines = CSV.read(@csv_file).length
        print_good "Found #{num_lines} lines."

        # binding.pry

        print_good "Setting Field Mappings"
        set_field_mappings(@field_mapping_file)
        print_good "Setting Tag Mappings"
        set_tag_mapping(@tag_column_file)

        # binding.pry

        # STOP HERE

        ## Iterate through CSV
        CSV.forforeach(@csv_file, headers: true) do |row|
          # "Reading line #{$.}... "
          # current_line = $INPUT_LINE_NUMBER

          # your csv column names should match these if you don't want to change the script
          next if row[@ip_address_col.to_s].nil?

          ip_address = row[@ip_address_col.to_s]
          hostname = row[@hostname_col.to_s]
          url = row[@url_col.to_s]
          mac_address = row[@mac_address_col.to_s]
          database = row[@database_col.to_s]
          netbios = row[@netbios_col.to_s]
          fqdn = row[@fqdn_col.to_s]
          file_name = row[@file_name_col.to_s]
          application_name = row[@application_name_col.to_s]

          # binding.pry

          print_good ip_address.to_s
          json_data = {
            "asset" => {
              "primary_locator" => @primary_locator.to_s,
              "ip_address" => ip_address.to_s,
              "hostname" => hostname.to_s,
              "database" => database.to_s,
              "url" => url.to_s,
              "mac_address" => mac_address.to_s,
              "netbios" => netbios.to_s,
              "fqdn" => fqdn.to_s,
              "file" => file_name.to_s,
              "application" => application_name.to_s
            }
          }

          # DBro - Added Tagging Section
          tag_list = []
          if @tag_columns.count.positive?
            @tag_columns.foreach do |item|
              pull_string = "" # <==== Should this be an array? The loop next doesn't work.
              pull_column = CSV.parse_line((item[0]).to_s)
              pull_column.foreach do |col|
                pull_string << "#{row[col]} "
              end
              pull_string = pull_string.strip
              if !pull_string.nil? && !pull_string.empty?
                # If is has a delimiter defined
                if item[2].nil?
                  tag_list << if item[1].nil?
                                pull_string.to_s
                              else
                                "#{item[1]}#{pull_string}"
                              end
                # If is has NO delimiter defined
                elsif !item[1].nil?
                  pull_string.split(item[2]).foreach { |e| tag_list << "#{item[1]}#{e}" }
                else
                  pull_string.split(item[2]).foreach { |e| tag_list << e.to_s }
                end
              end
            end
          end

          tag_string = ""
          tag_list.foreach do |t|
            t = t.gsub(/[\s,]/, " ")
            tag_string << "#{t},"
          end
          tag_string = tag_string[0...-1]

          # binding.pry

          print_good "========================"
          print_good json_data
          print_good "------------------------"
          print_good tag_list
          print_good "========================"

          # ========================
          # Add Asset
          # ========================

          print_good json_data
          print_good @post_url
          begin
            query_post_return = RestClient::Request.execute(
              method: :post,
              url: @post_url,
              payload: json_data,
              headers: @headers
            )

            # Need to find the new asset ID
            # asset_id = query_post_return........
            asset_id = JSON.parse(query_post_return)["asset"]["id"]
          rescue JSON::ParserError
            print_error "Failed to parse correctly"
            next
          rescue RestClient::UnprocessableEntity
            print_error query_post_return.to_s
            next
          rescue RestClient::TooManyRequests
            print_error "Too many requests, sleeping 60s..."
            sleep 60
          rescue RestClient::BadRequest
            print_error "Unable to add....Primary Locator data missing for this item."
            next
          end

          # ========================
          # Add Tags
          # ========================

          unless tag_string.empty?
            tag_update_json = {
              "asset" => {
                "tags" => tag_string.to_s
              }

            } ## Push tags to assets

            tag_api_url = "#{@post_url}/#{asset_id}/tags"
            print_good tag_api_url if @debug
            print_good tag_update_json if @debug

            begin
              RestClient::Request.execute(
                method: :put,
                url: tag_api_url,
                headers: @headers,
                payload: tag_update_json,
                timeout: 10
              )
            rescue RestClient::TooManyRequests
              print_error "Too many requests, sleeping 60s..."
              sleep 60
            end

            sleep(0.25)

          end
        end
      end

      def set_field_mappings(csv_file) # rubocop:disable Naming/AccessorMethodName
        CSV.parse(File.open(csv_file, "r:iso-8859-1:utf-8", &:read), headers: true) do |row|
          case row["Kenna Field"]
          when "ip_address"
            @ip_address_col = row["Customer Field"]
          when "hostname"
            @hostname_col = row["Customer Field"]
          when "url"
            @url_col = row["Customer Field"]
          when "mac_address"
            @mac_address_col = row["Customer Field"]
          when "database"
            @database_col = row["Customer Field"]
          when "netbios"
            @netbios_col = row["Customer Field"]
          when "fqdn"
            @fqdn_col = row["Customer Field"]
          when "file_name"
            @file_name_col = row["Customer Field"]
          when "application"
            @application_col = row["Customer Field"]
          end
        end

        print_good "Finished with field mapping"
      end

      def set_tag_mapping(csv_file) # rubocop:disable Naming/AccessorMethodName
        if !csv_file.empty? && !csv_file.nil?
          CSV.forforeach(csv_file, headers: true, encoding: "UTF-8") do |row|
            @tag_columns << Array[row[0], row[1], row[2]]
          end
          print_good "tag_columns = #{@tag_columns}" if @debug
        else
          print_error "No Tag File Specified."
        end
      end
    end
  end
end
