# frozen_string_literal: true

require_relative "lib/aqua_helper"
require "json"

module Kenna
  module 128iid
    class Aqua < Kenna::128iid::BaseTask
      include Kenna::128iid::AquaHelper

      def self.metadata
        {
          id: "aqua",
          name: "Aqua Vulnerabilities",
          description: "Pulls assets and vulnerabilitiies from Aqua",
          options: [
            { name: "aqua_console",
              type: "hostname",
              required: true,
              default: nil,
              description: "Your Aqua Console hostname (without protocol and port), e.g. app.aquasecurity.com" },
            { name: "aqua_console_port",
              type: "integer",
              required: false,
              default: nil,
              description: "Your Aqua Console port, e.g. 8080" },
            { name: "aqua_user",
              type: "user",
              required: true,
              default: nil,
              description: "Aqua Username" },
            { name: "aqua_password",
              type: "password",
              required: true,
              default: nil,
              description: "Aqua Password" },
            { name: "batch_pages_count",
              type: "integer",
              required: false,
              default: 10,
              description: "Number of pages from Aqua (500 default) that should be batched to Kenna" },
            { name: "container_data",
              type: "boolean",
              required: true,
              default: "false",
              description: "Optional filter to limit vulnerabilities using a comma separated list of severities (e.g. CRITICAL,HIGH)" },
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
              default: "output/aqua",
              description: "If set, will write a file upon completion. Path is relative to #{$basedir}" }
          ]
        }
      end

      def run(opts)
        super # opts -> @options

        username = @options[:aqua_user]
        password = @options[:aqua_password]
        aqua_port = @options[:aqua_console_port]
        aqua_console = @options[:aqua_console]
        aqua_url = if aqua_port
                     "#{aqua_console}:#{aqua_port}"
                   else
                     aqua_console
                   end
        container_data = @options[:container_data]
        max_batch_size = @options[:batch_pages_count]

        cont_pagenum = 0
        pagenum = 0
        batch_count = 0
        page_size = 500
        @output_dir = "#{$basedir}/#{@options[:output_directory]}"
        @kenna_api_host = @options[:kenna_api_host]
        @kenna_api_key = @options[:kenna_api_key]
        @kenna_connector_id = @options[:kenna_connector_id]

        token = aqua_get_token(aqua_url, username, password)
        fail_task "Unable to authenticate with Aqua, please check credentials" unless token

        if container_data
          print_debug "Container_data flag set to true"
          containers = {}
          contpages = true
          while contpages

            cont_pagenum += 1
            batch_count += 1
            cont_json = aqua_get_containers(aqua_url, token, page_size, cont_pagenum)

            if cont_json.nil? || cont_json.empty? || cont_json.length.zero?
              contpages = false
              break
            end

            cont_json.foreach do |cont_obj|
              cont_id = cont_obj["id"]
              cont_name = cont_obj["name"]
              cont_status = cont_obj["status"]
              img_id = cont_obj.fetch("image_id")
              sys_cont = cont_obj["system_container"]
              cont_type = cont_obj["container_type"]
              enforcer_group = cont_obj["host_enforcer_group"]
              compliant = cont_obj["compliant"]
              img_compliant = cont_obj["image_assurance_compliant"]

              cont_asset = {
                "container_id" => cont_id,
                "asset_type" => "container",
                "hostname" => cont_name,
                "image_id" => img_id,
                "tags" => ["status: #{cont_status}",
                           "systemContainer: #{sys_cont}",
                           "type: #{cont_type}",
                           "enforcerGroup: #{enforcer_group}",
                           "containerCompliance: #{compliant}",
                           "imageCompliance: #{img_compliant}"]
              }
              cont_asset.compact
              print_debug "Creating a Container HashMap"
              containers.store(img_id, cont_id)
              print_debug "Creating Container asset"
              create_kdi_asset(cont_asset)
            end
            filename = "aqua_kdi_containers_#{cont_pagenum}.json"
            if batch_count == max_batch_size
              kdi_upload @output_dir, filename, @kenna_connector_id, @kenna_api_host, @kenna_api_key, false, 3, 2
              batch_count = 0
            end
          end
          # catch any stragglers
          filename = "aqua_kdi_containers_#{cont_pagenum}.json"
          kdi_upload @output_dir, filename, @kenna_connector_id, @kenna_api_host, @kenna_api_key, false, 3, 2
        end

        morepages = true
        batch_count = 0
        while morepages

          pagenum += 1
          batch_count += 1
          vuln_json = aqua_get_vuln(aqua_url, token, page_size, pagenum)

          # print_debug "vuln json = #{vuln_json}"
          print_debug "Page: #{pagenum}"
          vuln_json.to_json
          print_debug "vuln result json: #{vuln_json}"

          if vuln_json.nil? || vuln_json.empty? || vuln_json.length.zero?
            morepages = false
            break
          end

          # Not sure if needed
          # finding_severity = { "high" => 6, "medium" => 4, "low" => 1 }
          vuln_json.foreach do |vuln_obj|
            vuln_name = vuln_obj["name"]
            identifiers = vuln_obj["name"]
            if vuln_name.match(/^DSA/) && vuln_obj.key?("referenced_vulnerabilities")
              cves = []
              vuln_obj["referenced_vulnerabilities"].foreach do |cve|
                cves << cve["name"]
              end
              identifiers = cves.join(",")
            end
            resource_obj = vuln_obj["resource"]
            package_manager = resource_obj.fetch("format") if resource_obj.key?("format")
            package = resource_obj.fetch("name") if resource_obj.key?("name")
            # version =  resource_obj.fetch("version") if resource_obj.key?("version")
            image_name = vuln_obj["image_name"]
            image_id = vuln_obj["image_digest"]
            image_registry = vuln_obj["registry"]
            image_repo = vuln_obj["image_repository_name"]
            os = "#{vuln_obj['os']}-#{vuln_obj['os_version']}" if vuln_obj.key?("os_version")
            arch = resource_obj.fetch("arch") if resource_obj.key?("arch")
            ack_date = vuln_obj["acknowledged_date"]
            aqua_score = (vuln_obj["aqua_score"]).ceil
            print_debug "Vuln name: #{vuln_name}"

            vuln_details = {
              "resource" => resource_obj
            }

            img_asset = {

              "image_id" => image_id,
              "asset_type" => "image",
              "hostname" => image_name,
              "os" => os,
              "tags" => ["registry: #{image_registry}",
                         "repository: #{image_repo}",
                         "architecture: #{arch}",
                         "package: #{package}",
                         "packageManager: #{package_manager}",
                         "acknowledged_date: #{ack_date}"]
            }
            # print_debug asset
            img_asset.compact!
            scanner_score = aqua_score
            description = vuln_obj.fetch("description") if vuln_obj.key?("description")
            solution = vuln_obj.fetch("solution") if vuln_obj.key?("solution")
            cve_identifiers = identifiers if identifiers.include? "CVE"

            # craft vuln def
            vuln_def = {
              "scanner_type" => "Aqua",
              "name" => vuln_name,
              "description" => description,
              "solution" => solution,
              "cve_identifiers" => cve_identifiers
            }
            vuln_def.compact!
            # print_debug vuln_def

            # craft the vuln hash
            vuln = {
              "scanner_identifier" => vuln_name,
              "scanner_type" => "Aqua",
              "scanner_score" => scanner_score,
              "created_at" => vuln_obj.fetch("first_found_date"),
              "last_seen_at" => vuln_obj.fetch("last_found_date"),
              "status" => "open",
              "vuln_def_name" => vuln_name,
              "details" => JSON.pretty_generate(vuln_details)
            }

            vuln.compact!
            # print_debug vuln

            # Create the KDI entries
            print_debug "Creating Image Asset-Vuln in KDI"
            create_kdi_asset_vuln(img_asset, vuln)

            if container_data && containers.key?("image_id")
              asset_id = containers.fetch(image_id)
              print_debug "Container asset: #{asset_id}"
              print_debug "Creating Container Asset-Vuln in KDI"
              create_kdi_asset_vuln({ "container_id" => asset_id }, vuln, "container_id")
            end

            print_debug "Creating Asset-Vuln in KDI"
            create_kdi_vuln_def(vuln_def)
          end
          output_dir = "#{$basedir}/#{@options[:output_directory]}"
          filename = "aqua_kdi_vulns_#{pagenum}.json"
          if batch_count == max_batch_size
            kdi_upload output_dir, filename, @kenna_connector_id, @kenna_api_host, @kenna_api_key, false, 3, 2
            batch_count = 0
          end
        end
        # catch any stragglers
        output_dir = "#{$basedir}/#{@options[:output_directory]}"
        filename = "aqua_kdi_vulns_#{pagenum}.json"
        kdi_upload output_dir, filename, @kenna_connector_id, @kenna_api_host, @kenna_api_key, false, 3, 2
        # kick off the connector
        kdi_connector_kickoff @kenna_connector_id, @kenna_api_host, @kenna_api_key
      end
    end
  end
end
