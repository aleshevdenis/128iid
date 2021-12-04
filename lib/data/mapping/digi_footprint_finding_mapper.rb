# frozen_string_literal: true

module Kenna
  module 128iid
    module Data
      module Mapping
        class DigiFootprintFindingMapper
          def initialize(output_directory, input_directory = "", mapping_file = "")
            @output_dir = output_directory
            @missing_mappings = Set.new
            @input_directory = input_directory
            @mapping_file = mapping_file
            @map_data = nil
            @map_data = (custom_mapping_data unless input_directory.nil? || mapping_file.nil?) || mapping_data
          end

          def get_canonical_vuln_details(orig_source, specific_details, description = "", remediation = "")
            ###
            ### Transform the identifier from the upstream source downcasing and
            ### then removing spaces and dashes in favor of an underscore
            ###
            orig_vuln_id = (specific_details["scanner_identifier"]).to_s.downcase.tr(" ", "_").tr("-", "_")
            # orig_description = specific_details["description"]
            # orig_recommendation = specific_details["recommendation"]
            out = {}
            done = false
            # Do the mapping
            ###################
            @map_data.foreach do |map|
              break if done

              map[:matches].foreach do |match|
                break if done

                next unless match[:source] == orig_source

                next unless match[:vuln_id]&.match?(orig_vuln_id)

                out = {
                  scanner_type: orig_source,
                  scanner_identifier: orig_vuln_id,
                  source: "#{orig_source} (Kenna Normalized)",
                  scanner_score: (map[:score] / 10).to_i,
                  override_score: (map[:score]).to_i,
                  name: map[:name],
                  description: "#{map[:description]}\n\n #{description}".strip,
                  recommendation: "#{map[:recommendation]}\n\n #{remediation}".strip
                }
                out.compact!
                out = out.stringify_keys
                done = true
              end
            end
            # we didnt map it, so just pass it back
            if out.empty?
              print_debug "WARNING! Unable to map canonical vuln for type: #{orig_vuln_id}"
              @missing_mappings << [orig_vuln_id, orig_source]
              write_file(@output_dir, "missing_mappings_#{DateTime.now.strftime('%Y-%m-%d')}.csv", @missing_mappings.map(&:to_csv).join) unless @missing_mappings.nil?
              out = {
                scanner_identifier: orig_vuln_id,
                scanner_type: orig_source,
                source: orig_source,
                name: orig_vuln_id
              }.stringify_keys.merge(specific_details)
            end
            out
          end

          def df_mapping_stats
            stats = {}
            stats[:bitsight] = []
            stats[:extend] = []
            stats[:intrigue] = []
            stats[:riskiq] = []
            stats[:ssc] = []

            # Collect the count
            _mapping_data("", "").foreach do |map|
              map[:matches].foreach do |m|
                stats[:bitsight] << m[:vuln_id] if m[:source] == "Bitsight"
                stats[:extend]  << m[:vuln_id] if m[:source] == "Expanse"
                stats[:intrigue] << m[:vuln_id] if m[:source] == "Intrigue"
                stats[:riskiq] << m[:vuln_id] if m[:source] == "RiskIQ"
                stats[:ssc] << m[:vuln_id] if m[:source] == "SecurityScorecard"
              end
            end

            stats.foreach { |k, v| puts "#{k} #{v.count}" }

            stats
          end

          def custom_mapping_data
            data_mapping = []
            csv_holder = []
            CSV.parse(File.open("#{@input_directory}/#{@mapping_file}", "r:iso-8859-1:utf-8", &:read), headers: true) do |row|
              csv_holder << row
            end
            some_rows = csv_holder.select { |row| row["type"] == "definition" }
            some_rows.foreach do |row|
              hash_row = {
                name: row[1],
                cwe: row[2],
                score: row[3].to_i,
                description: row[4],
                recommendation: row[5]
              }
              hash_row[:matches] = []
              data_mapping << hash_row
            end
            some_rows = csv_holder.select { |row| row["type"] == "match" }
            some_rows.foreach do |row|
              dm = data_mapping.lazy.find { |mdef| mdef[:name].to_s == row["name"] }
              hash_match = {
                source: row[2],
                vuln_id: row[3]
              }
              dm[:matches] << hash_match
            end
            data_mapping
          end

          def mapping_data
            [
              {
                name: "Application Content Security Policy Issue",
                # cwe: "CWE-358",
                score: 40,
                description: "A problem with this application's content security policy was identified.",
                recommendation: "Update the certificate to include the hostname, or ensure that clients access the host from the matched hostname.",
                matches: [
                  { source: "SecurityScorecard", vuln_id: /^csp_no_policy$/ },
                  { source: "SecurityScorecard", vuln_id: /^csp_unsafe_policy$/ },
                  { source: "SecurityScorecard", vuln_id: /^csp_too_broad$/ }
                ]
              },
              {
                name: "Application Security Headers",
                # cwe: "CWE-693",
                score: 20,
                description: "One or more application security headers was detected missing or misconfigured.",
                recommendation: "Correct the header configuration on the server.",
                matches: [
                  { source: "Bitsight", vuln_id: /^web_application_headers$/ },
                  { source: "Bitsight", vuln_id: /^application_security$/ },
                  { source: "SecurityScorecard", vuln_id: /^x_xss_protection_incorrect$/ },
                  { source: "SecurityScorecard", vuln_id: /^x_content_type_options_incorrect$/ },
                  { source: "SecurityScorecard", vuln_id: /^x_frame_options_incorrect$/ },
                  { source: "Expanse_issues", vuln_id: /^missing\S+header$/ }
                ]
              },
              {
                name: "Application Software Version Detected",
                score: 10,
                # cwe: "CWE-693",
                description: "Software details were detected.",
                recommendation: "Verify this is not leaking sensitive data:.",
                matches: [
                  { source: "Bitsight", vuln_id: /^server_software$/ },
                  { source: "Expanse", vuln_id: /^application_server_software$/ },
                  { source: "Expanse", vuln_id: /^server_software$/ },
                  { source: "Expanse", vuln_id: /^detected_webserver$/ }
                ]
              },
              {
                name: "Brforeach of Proper Protocol or Procedure",
                score: 30,
                # cwe: "xxx",
                description: "The software does not properly prevent private data from being accessed non authorized actors",
                recommendation: "Examine systems to which the credentials provided access for signs of compromise.",
                matches: [
                  { source: "Expanse_issues", vuln_id: /^section889violation$/ }
                ]
              },
              {
                name: "Browser Software Inconsistent",
                score: 10,
                # cwe: "CWE-671",
                description: "Multiple browser software packages detected.",
                recommendation: "Verify this is expected",
                matches: [
                  { source: "SecurityScorecard", vuln_id: /^no_standard_browser_policy$/ }
                ]
              },
              {
                name: "Colocated: Unencrypted Login",
                score: 10,
                # cwe: "xxx",
                description: "A colocated system was identified using insecure login.",
                recommendation: "Update the system.",
                matches: [
                  { source: "Expanse_issues", vuln_id: /^colocatedunencryptedftpserver$/ }
                ]
              },
              {
                name: "Colocated: Database Server Detected",
                score: 20,
                # cwe: "xxx",
                description: "A database server was identified on a colocated system.",
                recommendation: "Update the system.",
                matches: [
                  { source: "Expanse_issues", vuln_id: /^colocatedmongoserver$/ },
                  { source: "Expanse_issues", vuln_id: /^colocatedpostgresserver$/ },
                  { source: "Expanse_issues", vuln_id: /^colocatedredisserver$/ },
                  { source: "Expanse_issues", vuln_id: /^colocated.*sqlserver$/ }
                ]
              },
              {
                name: "Colocated: Deprecated Protocol Exposure",
                score: 10,
                # cwe: "xxx",
                description: "A colocated server has a deprecated protocol.",
                recommendation: "Update the system.",
                matches: [
                  { source: "Expanse_issues", vuln_id: /^colocatedpptpserver$/ }
                ]
              },
              {
                name: "Colocated: Exposure of Sensitive Information",
                score: 10,
                # cwe: "xxx",
                description: "A colocated server has exposed sensitive information.",
                recommendation: "Update the system.",
                matches: [
                  { source: "Expanse_issues", vuln_id: /^colocatedpop3server$/ }
                ]
              },
              {
                name: "Colocated: Exposure of Trusted Protocol",
                score: 10,
                # cwe: "xxx",
                description: "A trusted protocol has been exposed colocated system.",
                recommendation: "Update the system.",
                matches: [
                  { source: "Expanse_issues", vuln_id: /^colocatedimapserver$/ },
                  { source: "Expanse_issues", vuln_id: /^colocatedmulticastdnsserver$/ },
                  { source: "Expanse_issues", vuln_id: /^colocatednetbiosnameserver$/ },
                  { source: "Expanse_issues", vuln_id: /^colocatedrdpserver$/ },
                  { source: "Expanse_issues", vuln_id: /^colocatedrpcbindserver$/ },
                  { source: "Expanse_issues", vuln_id: /^colocatedsmbserver$/ },
                  { source: "Expanse_issues", vuln_id: /^colocatedsshserver$/ },
                  { source: "Expanse_issues", vuln_id: /^colocatedsipserver$/ },
                  { source: "Expanse_issues", vuln_id: /^colocatedvncserver$/ },
                  { source: "Expanse_issues", vuln_id: /^colocatedxmppserver$/ },
                  { source: "Expanse_issues", vuln_id: /^colocatedtelnetserver$/ }
                ]
              },
              {
                name: "Colocated: Network Misconfiguration",
                score: 10,
                # cwe: "xxx",
                description: "A colocated server has misconfiguration.",
                recommendation: "Update the system.",
                matches: [
                  { source: "Expanse_issues", vuln_id: /^colocatedntpserver$/ },
                  { source: "Expanse_issues", vuln_id: /^colocatedsnmpserver$/ }
                ]
              },
              {
                name: "Compromised Application",
                score: 90,
                # cwe: "CWE-506",
                description: "System was discovered by an attack feed.",
                recommendation: "Check this application for signs of compromise",
                matches: [
                  { source: "SecurityScorecard", vuln_id: /^new_booter_shell$/ },
                  { source: "SecurityScorecard", vuln_id: /^new_defacement$/ }
                ]
              },
              {
                name: "Compromised System",
                score: 90,
                # cwe: "CWE-506",
                description: "System was discovered by an attack feed. It may be compromised by malware or a bot.",
                recommendation: "Check this system for signs of compromise",
                matches: [
                  { source: "Bitsight", vuln_id: /^potentially_exploited$/ },
                  { source: "Bitsight", vuln_id: /^botnet_infections$/ },
                  { source: "SecurityScorecard", vuln_id: /^attack_feed$/ },
                  { source: "SecurityScorecard", vuln_id: /^attack_detected$/ },
                  { source: "SecurityScorecard", vuln_id: /^malware_1_day$/ },
                  { source: "SecurityScorecard", vuln_id: /^malware_30_day$/ },
                  { source: "SecurityScorecard", vuln_id: /^malware_365_day$/ }
                ]
              },
              {
                name: "Critical Exposure of Vulnerable Software",
                score: 100,
                # cwe: "CWE-xxx",
                description: "Critical Exposure of Vulnerable Software.",
                recommendation: "Verify this is expected",
                matches: [
                  { source: "Expanse_issues", vuln_id: /^apachewebserver$/ }
                ]
              },
              {
                name: "Database Server Detected",
                score: 100,
                # cwe: "CWE-xxx",
                description: "Database System was detected.",
                recommendation: "Verify this is expected:.",
                matches: [
                  { source: "Bitsight", vuln_id: /^database_server_detected$/ },
                  { source: "Expanse", vuln_id: /^detected_server_mysql$/ },
                  { source: "Expanse", vuln_id: /^ms_sql_servers?$/ },
                  { source: "Expanse", vuln_id: /^my_sql_servers?$/ },
                  { source: "Expanse", vuln_id: /^sharepoint_servers?$/ },
                  { source: "Expanse_issues", vuln_id: /^elasticsearchserver$/ },
                  { source: "Expanse_issues", vuln_id: /^redisserver$/ },
                  { source: "Expanse_issues", vuln_id: /^mssqlserver$/ },
                  { source: "Expanse_issues", vuln_id: /^mysqlserver$/ }
                ]
              },
              {
                name: "Database Service Exposure",
                score: 70,
                # cwe: "CWE-693",
                description: "Database System was detected.",
                recommendation: "Verify this is expected:.",
                matches: [
                  { source: "Bitsight", vuln_id: /^database_service_exposure$/ },
                  { source: "RiskIQ", vuln_id: /^open_db_port_tcp$/ },
                  { source: "Expanse_issues", vuln_id: /^sharepointserver$/ },
                  { source: "Expanse_issues", vuln_id: /^datastorageandanalysis$/ },
                  { source: "Expanse_issues", vuln_id: /^postgresserver$/ },
                  { source: "SecurityScorecard", vuln_id: /^service_mysql$/ },
                  { source: "SecurityScorecard", vuln_id: /^service_microsoft_sql$/ }
                ]
              },
              {
                name: "Deprecated Protocol Exposure",
                score: 90,
                # cwe: "CWE-xxx",
                description: "Deprecated Protocol was detected.",
                recommendation: "Verify this is expected:.",
                matches: [
                  { source: "Bitsight", vuln_id: /^deprecated_protocol$/ },
                  { source: "Bitsight", vuln_id: /^ssl_configurations$/ },
                  { source: "Expanse_issues", vuln_id: /^pptpserver$/ },
                  { source: "Expanse_issues", vuln_id: /^insecuretls$/ },
                  { source: "SecurityScorecard", vuln_id: /^tls_weak_protocol$/ }
                ]
              },
              {
                name: "Development System Detected",
                score: 30,
                # cwe: "CWE-693",
                description: "System fit the pattern of a development system.",
                recommendation: "Verify this system should be exposed:.",
                matches: [
                  { source: "Expanse", vuln_id: /^development_system_detected$/ },
                  { source: "Expanse", vuln_id: /^development_environments?$/ }
                ]
              },
              {
                name: "DNSSEC Misconfiguration",
                # cwe: "CWE-298",
                score: 20,
                description: ".",
                recommendation: "See specifics for more detail about the DNSSEC misconfiguration.",
                matches: [
                  { source: "Bitsight", vuln_id: /^dnssec$/ },
                  { source: "Expanse_issues", vuln_id: /^wildcarddnsrecord$/ }
                ]
              },
              {
                name: "Expired Certificate",
                score: 40,
                # cwe: "CWE-506",
                description: "An expired Ceritficate was Found",
                recommendation: "Replace this ceritificate",
                matches: [
                  { source: "Expanse", vuln_id: /^certificate_expired_when_scanned$/ },
                  { source: "Expanse", vuln_id: /^expired_when_scanned_certificate_advertisements?$/ },
                  { source: "Expanse_issues", vuln_id: /^expiredwhenscannedcertificate$/ },
                  { source: "SecurityScorecard", vuln_id: /^tlscert_expired$/ },
                  { source: "RiskIQ", vuln_id: /^expired_certificate$/ }
                ]
              },
              {
                name: "Expiring Certificate",
                score: 20,
                # cwe: "CWE-506",
                description: "An expiring Ceritficate was Found",
                recommendation: "Replace this ceritificate soon",
                matches: [
                  { source: "Expanse_issues", vuln_id: /^expiringcertificate$/ },
                  { source: "RiskIQ", vuln_id: /^expiring_certificate$/ }
                ]
              },
              {
                name: "Exposed Cloud Object Storage (S3 Bucket)",
                # cwe: "CWE-284",
                score: 80,
                description: "A cloud storage bucket was found with risky ACLss",
                recommendation: "Check the ACLs and adjust if needed.",
                matches: [
                  { source: "SecurityScorecard", vuln_id: /^object_storage_bucket_with_risky_acl$/ }
                ]
              },
              {
                name: "Exposure of Infrastructure Framework",
                score: 90,
                # cwe: "CWE-xxx",
                description: "Exposure of Infrastructure Framework",
                recommendation: "Replace this ceritificate soon",
                matches: [
                  { source: "Bitsight", vuln_id: /^insecure_systems$/ },
                  { source: "Bitsight", vuln_id: /^infrastructure_exposure$/ },
                  { source: "Expanse_issues", vuln_id: /^insecureapachewebserver$/ },
                  { source: "Expanse_issues", vuln_id: /^microsoftowaserver$/ },
                  { source: "Expanse_issues", vuln_id: /^jenkinsserver$/ },
                  { source: "Expanse_issues", vuln_id: /^vmwareesxi$/ },
                  { source: "Expanse_issues", vuln_id: /^sapnetweaverapplicationserver$/ },
                  { source: "Expanse_issues", vuln_id: /^vmwareworkspaceoneaccessserver$/ },
                  { source: "Expanse_issues", vuln_id: /^vncserver$/ },
                  { source: "Expanse_issues", vuln_id: /^kubernetes$/ },
                  { source: "Expanse_issues", vuln_id: /^insecuredrupalwebserver$/ },
                  { source: "Expanse_issues", vuln_id: /^insecuremicrosoftiiswebserver$/ },
                  { source: "Expanse_issues", vuln_id: /^insecuremicrosoftexchangeserver$/ },
                  { source: "Expanse_issues", vuln_id: /^insecuresipserver$/ },
                  { source: "Expanse_issues", vuln_id: /^(?!apache|insecure).*webserver$/ }

                ]
              },
              {
                name: "Exposure of Sensitive Data",
                # cwe: "CWE-200",
                score: 70,
                description: "Exposure of sensitive data detected.",
                recommendation: "Remediate exposure",
                matches: [
                  { source: "Bitsight", vuln_id: /^file_sharing$/ },
                  { source: "Bitsight", vuln_id: /^sensitive_data_exposure$/ },
                  { source: "Expanse_issues", vuln_id: /^memcachedserver$/ },
                  { source: "Expanse_issues", vuln_id: /^exposeddirectorylisting$/ },
                  { source: "Expanse_issues", vuln_id: /^internalipaddressadvertisement$/ }
                ]
              },
              {
                name: "Exposure of Sensitive Environment",
                # cwe: "CWE-200",
                score: 60,
                description: "Sensitive Environment Exposed",
                recommendation: "Remediate Exposure",
                matches: [
                  { source: "Expanse_issues", vuln_id: /^weblogin$/ },
                  { source: "Expanse_issues", vuln_id: /^embeddedsystem$/ },
                  { source: "Expanse_issues", vuln_id: /^pop3server$/ },
                  { source: "Expanse_issues", vuln_id: /^smtpserver$/ },
                  { source: "Expanse_issues", vuln_id: /^developmentenvironment$/ },
                  { source: "Expanse_issues", vuln_id: /^teleconferencingandcollaboration$/ },
                  { source: "Expanse_issues", vuln_id: /^defaultapachetomcatpage$/ },
                  { source: "Expanse_issues", vuln_id: /^microsoftexchangeserver$/ },
                  { source: "Expanse_issues", vuln_id: /^nginxwebserver$/ },
                  { source: "Expanse_issues", vuln_id: /^drupalwebserver$/ },
                  { source: "Expanse_issues", vuln_id: /^tomcatwebserver$/ },
                  { source: "Expanse_issues", vuln_id: /^hpeproliantserver$/ },
                  { source: "SecurityScorecard", vuln_id: /^admin_subdomain$/ },
                  { source: "SecurityScorecard", vuln_id: /^service_pop3$/ }
                ]
              },
              {
                name: "Exposure of Sensitive log in",
                # cwe: "CWE-319",
                score: 50,
                description: "An unencrypted login was detected.",
                recommendation: "Ensure all logins happen over an encrypted channel.",
                matches: [
                  { source: "Bitsight", vuln_id: /^ftp_with_auth_tls_open_port?$/ },
                  { source: "Expanse", vuln_id: /^unencrypted_logins?$/ },
                  { source: "Expanse", vuln_id: /^detected_server_unencrypted_ftp$/ },
                  { source: "Expanse", vuln_id: /^detected_server_unencrypted_logins$/ },
                  { source: "Expanse_issues", vuln_id: /^grafana$/ },
                  { source: "Expanse_issues", vuln_id: /^insecuretelerikwebui$/ },
                  { source: "Expanse_issues", vuln_id: /^paloaltonetworkspanoramaadminloginpage$/ },
                  { source: "Expanse_issues", vuln_id: /^unencryptedftpserver$/ },
                  { source: "Expanse_issues", vuln_id: /^unencryptedlogin$/ }
                ]
              },
              {
                name: "Exposure of Trusted Protocol",
                # cwe: "CWE-xxx",
                score: 100,
                description: "Trusted Protocol Exposed",
                recommendation: "Remediate Exposure",
                matches: [
                  { source: "Bitsight", vuln_id: /^trusted_open_port$/ },
                  { source: "Expanse_issues", vuln_id: /^telnetserver$/ },
                  { source: "Expanse_issues", vuln_id: /^smbserver$/ },
                  { source: "Expanse_issues", vuln_id: /^netbiosnameserver$/ },
                  { source: "Expanse_issues", vuln_id: /^rdpserver$/ },
                  { source: "SecurityScorecard", vuln_id: /^service_smb$/ }
                ]
              },
              {
                name: "Exposure of Trusted Service",
                # cwe: "CWE-xxx",
                score: 100,
                description: "Trusted Service Exposed",
                recommendation: "Remediate Exposure",
                matches: [
                  { source: "Bitsight", vuln_id: /^trusted_open_service$/ },
                  { source: "Expanse_issues", vuln_id: /^rpcbindserver$/ },
                  { source: "Expanse_issues", vuln_id: /^nfsrpcbindserver$/ },
                  { source: "SecurityScorecard", vuln_id: /^service_ftp$/ }
                ]
              },
              {
                name: "Exposure of Trusted Utility",
                # cwe: "CWE-xxx",
                score: 70,
                description: "Trusted Utility Exposed",
                recommendation: "Remediate Exposure",
                matches: [
                  { source: "Bitsight", vuln_id: /^trusted_open_utility$/ },
                  { source: "Expanse_issues", vuln_id: /^rsyncserver$/ }
                ]
              },
              {
                name: "Github - Sensitive Data Leakage",
                # cwe: "CWE-284",
                score: 80,
                description: "Sensitive information was found leaked via Github",
                recommendation: "Investigate and remove the sensitive data if not intended.",
                matches: [
                  { source: "SecurityScorecard", vuln_id: /^github_information_leak_disclosure$/ },
                  { source: "SecurityScorecard", vuln_id: /^exposed_personal_information$/ }
                ]
              },
              {
                name: "Google - Sensitive Data Leakage",
                # cwe: "CWE-284",
                score: 80,
                description: "Sensitive information was found leaked via Google",
                recommendation: "Investigate and remove the sensitive data if not intended.",
                matches: [
                  { source: "SecurityScorecard", vuln_id: /^google_information_leak_disclosure$/ }
                ]
              },
              {
                name: "Hacker Chatter",
                # cwe: "CWE-326",
                score: 10,
                description: "Hacker chatter was detected.",
                recommendation: "Determine if this poses a risk.",
                matches: [
                  { source: "SecurityScorecard", vuln_id: /^chatter$/ }
                ]
              },
              {
                name: "Improper Neutralization of Input During Web Page Generation",
                score: 70,
                # cwe: "CWE-79",
                description: "System was discovered by an attack feed.",
                recommendation: "Check this application for signs of compromise",
                matches: [
                  { source: "Expanse_issues", vuln_id: /^solarwindsorionplatform$/ }
                ]
              },
              {
                name: "Insecure Cookie",
                # cwe: "CWE-298",
                score: 20,
                description: "The cookie is missing HTTPOnly flag.",
                recommendation: "Update cookie to include this flag.",
                matches: [
                  { source: "SecurityScorecard", vuln_id: /^cookie_missing_http_only$/ },
                  { source: "SecurityScorecard", vuln_id: /^cookie_missing_secure_attribute$/ },
                  { source: "Intrigue", vuln_id: /^insecure_cookie_detected$/ }

                ]
              },
              {
                name: "Insecure Resource Request",
                score: 70,
                # cwe: "CWE-506",
                description: "A resource was requested over an insecure protocol",
                recommendation: "Transition the resource to an HTTPS request",
                matches: [
                  { source: "SecurityScorecard", vuln_id: /^domain_missing_https$/ },
                  { source: "SecurityScorecard", vuln_id: /^redirect_chain_contains_http$/ }
                ]
              },
              {
                name: "Internal IP Address Exposure",
                score: 10,
                # cwe: "CWE-202",
                description: "A dns record was found pointing to an internal system.",
                recommendation: "Remove the entry from public DNS.",
                matches: [
                  { source: "Expanse", vuln_id: /^internal_ip_address_advertisements?$/ }
                ]
              },
              {
                name: "Leaked Credentials",
                score: 80,
                # cwe: "CWE-359",
                description: "Credentials were found exposed.",
                recommendation: "Revoke the credentials and/or prompt a reset. Examine systems to which the credentials provided access for signs of compromise.",
                matches: [
                  { source: "SecurityScorecard", vuln_id: /^leaked_credentials$/ }
                ]
              },

              {
                name: "Mobile Application Security Misconfiguration",
                # cwe: "CWE-693",
                score: 40,
                description: "A problem with this application's configuration was discoverd .",
                recommendation: "Fix it",
                matches: [
                  { source: "Bitsight", vuln_id: /^mobile_application_security$/ }
                ]
              },
              {
                name: "Open DNS Resolver",
                score: 80,
                # cwe: "CWE-693",
                description: "Some DNS servers perform their hierarchical lookups by means of recursion, and rather than limit the ability to make recursive requests to local or authorized clients, DNS servers referred to as Open Resolvers allow recursive DNS requests from any client. Open Resolvers (especially with the newer RFC specifications supporting extensions to the DNS system such as IPv6 and DNSSEC) require the ability to send DNS replies much larger than their respective requests, and an attacker can abuse this fact to amplify his or her available outgoing bandwidth and subsequently direct it at a target in a DNS Amplification Attack.",
                recommendation: "Disable recursive queries on this DNS REsolver.",
                matches: [
                  { source: "SecurityScorecard", vuln_id: /^open_resolver$/ }
                ]
              },
              {
                name: "P2P Activity Detected",
                score: 10,
                # cwe: "CWE-506",
                description: "This system was detected with P2P Activity ",
                recommendation: "Check the system for signs of compromise ",
                matches: [
                  { source: "SecurityScorecard", vuln_id: /^non_malware_events_last_month$/ }
                ]
              },
              {
                name: "Network Misconfiguration",
                score: 20,
                # #cwe: "CWE-xxx",
                description: "Network Misconfiguration detected.",
                recommendation: "Remediate Network Misconfiguration.",
                matches: [
                  { source: "Bitsight", vuln_id: /^network_misconfig$/ },
                  { source: "Expanse_issues", vuln_id: /^panosdevice$/ },
                  { source: "Expanse_issues", vuln_id: /^openbgpserver$/ },
                  { source: "Expanse_issues", vuln_id: /^wildcarddnsrecord$/ }
                ]
              },
              {
                name: "Network Misconfiguration: Internal Exposure",
                score: 90,
                # #cwe: "CWE-xxx",
                description: "Network Misconfiguration detected.",
                recommendation: "Remediate Network Misconfiguration.",
                matches: [
                  { source: "Bitsight", vuln_id: /^internal_network_exposure$/ },
                  { source: "Expanse_issues", vuln_id: /^networkingandsecurityinfrastructure$/ },
                  { source: "Expanse_issues", vuln_id: /^sipserver$/ },
                  { source: "Expanse_issues", vuln_id: /^snmpserver$/ },
                  { source: "Expanse_issues", vuln_id: /^xmppserver$/ },
                  { source: "Expanse_issues", vuln_id: /^multicastdnsserver$/ },
                  { source: "Expanse_issues", vuln_id: /^upnpserver$/ },
                  { source: "Expanse_issues", vuln_id: /^rtspserver$/ },
                  { source: "Expanse_issues", vuln_id: /^vncoverhttpserver$/ }
                ]
              },
              {
                name: "Network Misconfiguration: Transmission Exposure",
                score: 70,
                # #cwe: "CWE-xxx",
                description: "Network Misconfiguration detected.",
                recommendation: "Remediate Network Misconfiguration.",
                matches: [
                  { source: "Bitsight", vuln_id: /^transmission_exposure$/ },
                  { source: "Expanse_issues", vuln_id: /^rtspserver$/ },
                  { source: "Expanse_issues", vuln_id: /^vncoverhttpserver$/ },
                  { source: "SecurityScorecard", vuln_id: /^insecure_https_redirect_pattern$/ },
                  { source: "SecurityScorecard", vuln_id: /^service_vnc$/ }
                ]
              },
              {
                name: "Non-Security, Benign, or Informational Finding",
                # cwe: "CWE-000",
                score: 0,
                description: "This is an informational finding.",
                recommendation: "Update the certificate to include the hostname, or ensuure that clients access the host from the matched hostname.",
                matches: [
                  { source: "Bitsight", vuln_id: /^benign_finding$/ },
                  { source: "Expanse", vuln_id: /^certificate_advertisements?$/ },
                  { source: "Expanse", vuln_id: /^healthy_certificate_advertisements?$/ },
                  { source: "Expanse", vuln_id: /^employee_satisfaction$/ },
                  { source: "Expanse", vuln_id: /^teleconferencing_and_collaboration$/ },
                  { source: "Expanse", vuln_id: /^marketing_site$/ },
                  { source: "Expanse", vuln_id: /^vpn$/ },
                  { source: "Expanse", vuln_id: /^domain_control_validated_certificate_advertisements?$/ },
                  { source: "Expanse_issues", vuln_id: /^vpndevice$/ },
                  { source: "Expanse_issues", vuln_id: /^domaincontrolvalidatedcertificate$/ },
                  { source: "Expanse_issues", vuln_id: /^ntpserver$/ },
                  { source: "SecurityScorecard", vuln_id: /^waf_detected$/ },
                  { source: "SecurityScorecard", vuln_id: /^benign_finding$/ },
                  { source: "SecurityScorecard", vuln_id: /^hosted_on_object_storage$/ },
                  { source: "SecurityScorecard", vuln_id: /^references_object_storage$/ },
                  { source: "SecurityScorecard", vuln_id: /^load_balancers?$/ },
                  { source: "Expanse", vuln_id: /^load_balancers?$/ },
                  { source: "SecurityScorecard", vuln_id: /^dnssec_detected$/ },
                  { source: "SecurityScorecard", vuln_id: /^tlscert_extended_validation$/ },
                  { source: "SecurityScorecard", vuln_id: /^domain_uses_hsts_preloading$/ },
                  { source: "SecurityScorecard", vuln_id: /^ddos_protection$/ },
                  { source: "SecurityScorecard", vuln_id: /^typosquat$/ }
                ]
              },
              {
                name: "Non-Sensitive (HTTP) Service Detected or Open Port Detected",
                score: 10,
                # cwe: "CWE-693",
                description: "A System was detected running a non-sensitive service.",
                recommendation: "Verify this is expected and firewall the port if it is not.",
                matches: [
                  { source: "Expanse", vuln_id: /^web_servers?$/ },
                  { source: "Bitsight", vuln_id: /^http_open_port$/ },
                  { source: "Bitsight", vuln_id: /^non_sensitive_open_port$/ },
                  { source: "RiskIQ", vuln_id: /^http_open_port$/ }
                ]
              },
              {
                name: "Permissive Cross-domain Policy with Untrusted Domains",
                # cwe: "CWE-2942",
                score: 0,
                description: "A vulnerability was detected at the service or OS layer",
                recommendation: "Investigate the vulnerability.",
                matches: [
                  { source: "SecurityScorecard", vuln_id: /^service_vuln_host_high$/ },
                  { source: "SecurityScorecard", vuln_id: /^service_vuln_host_medium$/ },
                  { source: "SecurityScorecard", vuln_id: /^service_vuln_host_low$/ }
                ]
              },
              {
                name: "Potential Email Security Violation",
                # cwe: "CWE-358",
                score: 30,
                description: "A problem with this domain's DKIM configuration was discovered.",
                recommendation: "Check the DKIM configuration:.",
                matches: [
                  { source: "Bitsight", vuln_id: /^dkim$/ },
                  { source: "SecurityScorecard", vuln_id: /^uce$/ }, # Unsolicited Commercial Email
                  { source: "SecurityScorecard", vuln_id: /^short_term_lending_site$/ } # Unsolicited Commercial Email
                ]
              },
              {
                name: "Potential Exposure of Trusted Protocol",
                # cwe: "CWE-xxx",
                score: 60,
                description: "Trusted Protocol Potentially Exposed",
                recommendation: "Remediate Exposure",
                matches: [
                  { source: "Bitsight", vuln_id: /^potential_trusted_protocol$/ },
                  { source: "Expanse_issues", vuln_id: /^sshserver$/ },
                  { source: "Expanse_issues", vuln_id: /^imapserver$/ },
                  { source: "Expanse_issues", vuln_id: /^microsoftdnsserver$/ },
                  { source: "Expanse_issues", vuln_id: /^ajpserver$/ },
                  { source: "Expanse_issues", vuln_id: /^buildingcontrolsystem$/ },
                  { source: "SecurityScorecard", vuln_id: /^service_imap$/ }
                ]
              },
              {
                name: "Potentially Vulnurable Software Detected",
                # cwe: "CWE-xxx",
                score: 70,
                description: "Potentially Vulnurable Software Detected",
                recommendation: "Remediate Exposure",
                matches: [
                  { source: "Bitsight", vuln_id: /^mobile_software$/ },
                  { source: "Bitsight", vuln_id: /^desktop_software$/ },
                  { source: "Expanse_issues", vuln_id: /^adobeflash$/ },
                  { source: "Expanse_issues", vuln_id: /^wordpressserver$/ },
                  { source: "SecurityScorecard", vuln_id: /^outdated_browser$/ },
                  { source: "SecurityScorecard", vuln_id: /^outdated_os$/ },
                  { source: "SecurityScorecard", vuln_id: /^service_end_of_life$/ },
                  { source: "SecurityScorecard", vuln_id: /^service_end_of_service$/ }
                ]
              },
              {
                name: "Sensitive Service Detected or Open Port Detected",
                score: 60,
                # #cwe: "CWE-693",
                description: "A System was detected running a potentially sensitive service.",
                recommendation: "Verify this is expected and firewall the port if it is not.",
                matches: [
                  { source: "Bitsight", vuln_id: /^other_open_port/ }, # correct place for this? # Open TCP Ports Observed
                  { source: "Expanse", vuln_id: /^.*_servers?$/ }, # literally match anyting coming from them in this vein
                  { source: "Expanse", vuln_id: /^detected_server_.*$/ },
                  { source: "Expanse", vuln_id: /^colocated_.*$/ },
                  { source: "Expanse_issues", vuln_id: /^openssl$/ },
                  { source: "Expanse_issues", vuln_id: /^f5bigipaccesspolicymanager$/ },
                  { source: "Expanse_issues", vuln_id: /^f5bigiptmui$/ },
                  { source: "SecurityScorecard", vuln_id: /^service_.*+$/ }, # NOTE: .. many matches here, may need to be split up
                  { source: "SecurityScorecard", vuln_id: /^exposed_ports$/ }, # correct place for this? # Open TCP Ports Observed
                  { source: "RiskIQ", vuln_id: /^other_open_port$/ }
                ]
              },
              {
                name: "SSH Misconfiguration",
                # cwe: "CWE-358",
                score: 20,
                description: "A problem with this SSH server's configuration was detected.",
                recommendation: "Updated the configuration on the SSH server.",
                matches: [
                  { source: "SecurityScorecard", vuln_id: /^ssh_weak_cipher$/ },
                  { source: "SecurityScorecard", vuln_id: /^ssh_weak_mac$/ },
                  { source: "SecurityScorecard", vuln_id: /^ssh_weak_protocl$/ }
                ]
              },
              {
                name: "Social Network Accounts Leaking Data",
                # cwe: "CWE-200",
                score: 20,
                description: "Leaked Company Emails Open to Spear-Phishing or other email-based interaction",
                recommendation: "Best practice indicates you should disabld this access.",
                matches: [
                  { source: "SecurityScorecard", vuln_id: /^social_network_issues$/ },
                  { source: "SecurityScorecard", vuln_id: /^exposed_personal_information_info$/ },
                  { source: "SecurityScorecard", vuln_id: /^leaked_credentials_info$/ }
                ]
              },
              {
                name: "SPF Misconfiguration",
                # cwe: "CWE-183",
                score: 20,
                description: "This system was found to have an SPF finding - which may be a positive finding, or a misconfiguration.",
                recommendation: "Correct the SPF configuration on the server.",
                matches: [
                  { source: "Bitsight", # TODO... this can be a positive finding
                    vuln_id: /^spf$/ },
                  { source: "Bitsight", vuln_id: /^too_many_dns_lookups$/ },
                  { source: "SecurityScorecard", vuln_id: /^spf_record_malformed$/ },
                  { source: "SecurityScorecard", vuln_id: /^spf_record_softfail$/ },
                  { source: "SecurityScorecard", vuln_id: /^spf_record_wildcard$/ },
                  { source: "SecurityScorecard", vuln_id: /^spf_record_missing$/ }
                ]
              },
              {
                name: "SSL Certificate Misconfiguration",
                # cwe: "CWE-326",
                score: 40,
                description: "This server has a configuration weakness with its SSL/TLS settings or certificate.",
                recommendation: "Correct the SSL configuration on the server. See specifics for more detail about the SSL/TLS misconfiguration",
                matches: [
                  { source: "Bitsight", vuln_id: /^ssl_certificates$/ },
                  { source: "Expanse", vuln_id: /^certificate_insecure_signature$/ },
                  { source: "Expanse", vuln_id: /^domain_control_certificate_advertisements?$/ },
                  { source: "Expanse", vuln_id: /^short_key_certificate_advertisements?$/ },
                  { source: "Expanse", vuln_id: /^long_expiration_certificate_advertisements?$/ },
                  { source: "Expanse", vuln_id: /^wildcard_certificate$/ },
                  { source: "Expanse", vuln_id: /^insecure_signature_certificate_advertisements?$/ },
                  { source: "Expanse", vuln_id: /^wildcard_certificate_advertisements?$/ },
                  { source: "Expanse", vuln_id: /^certificate_short_key$/ },
                  { source: "Expanse", vuln_id: /^certificate_long_expiration$/ },
                  { source: "Expanse_issues", vuln_id: /^selfsignedcertificate$/ },
                  { source: "Expanse_issues", vuln_id: /^shortkeycertificate$/ },
                  { source: "Expanse_issues", vuln_id: /^wildcardcertificate$/ },
                  { source: "Expanse_issues", vuln_id: /^insecuresignaturecertificate$/ },
                  { source: "Expanse_issues", vuln_id: /^longexpirationcertificate$/ },
                  { source: "Intrigue", vuln_id: /^weak_cipher_suite_detected$/ },
                  { source: "SecurityScorecard", vuln_id: /^ssl_weak_cipher$/ },
                  { source: "SecurityScorecard", vuln_id: /^tls_weak_cipher$/ },
                  { source: "SecurityScorecard", vuln_id: /^tlscert_no_revocation/ },
                  { source: "SecurityScorecard", vuln_id: /^tlscert_revoked$/ },
                  { source: "SecurityScorecard", vuln_id: /^tlscert_weak_signature$/ },
                  { source: "SecurityScorecard", vuln_id: /^hsts_incorrect$/ },
                  { source: "SecurityScorecard", vuln_id: /^tls_ocsp_stapling$/ },
                  { source: "SecurityScorecard", vuln_id: /^tlscert_excessive_expiration$/ }
                ]
              },
              {
                name: "Self-Signed Certificate",
                score: 40,
                # cwe: "CWE-506",
                description: "A self-signed certificate was detected",
                recommendation: "Certificate should be issued from a valid CA",
                matches: [
                  { source: "Expanse", vuln_id: /^self_signed_certificate_advertisements?$/ },
                  { source: "Expanse", vuln_id: /^certificate_self_signed$/ },
                  { source: "Intrigue", vuln_id: /^self_signed_certificate$/ },
                  { source: "RiskIQ", vuln_id: /^self_signed_certificate$/ },
                  { source: "SecurityScorecard", vuln_id: /^tlscert_self_signed$/ }
                ]
              },
              {
                name: "Subresource Integrity Issues",
                # cwe: "CWE-353",
                score: 20,
                description: "Subresource Integrity (SRI) is a security feature that enables browsers to verify that resources they fetch (for example, from a CDN) are delivered without unexpected manipulation. It works by allowing you to provide a cryptographic hash that a fetched resource must match.",
                references: [
                  "https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity"
                ],
                recommendation: "Ensure the system has not been compromised.",
                matches: [
                  { source: "SecurityScorecard", vuln_id: /^unsafe_sri$/ }
                ]
              },
              {
                name: "Suspicious Traffic Observed",
                score: 70,
                description: "Suspicious traffic observed and should be investigated.",
                recommendation: "Ensure the system has not been compromised.",
                matches: [
                  { source: "SecurityScorecard", vuln_id: /^suspicious_traffic$/ }
                ]
              },
              {
                name: "Tor Exit Node Discoverd",
                score: 10,
                # cwe: "CWE-506",
                description: "A Tor exit node was discovered",
                recommendation: "Check the system for signs of compromise ",
                matches: [
                  { source: "SecurityScorecard", vuln_id: /^tor_node_events_last_month$/ }
                ]
              },
              {
                name: "Unencrypted Login",
                # cwe: "CWE-xx",
                score: 90,
                description: "An unencrypted login was detected.",
                recommendation: "Ensure all logins happen over an encrypted channel.",
                matches: [
                  { source: "Bitsight", vuln_id: /^unecrypted_login$/ },
                  { source: "Bitsight", vuln_id: /^ftp_without_auth_tls_open_port$/ },
                  { source: "Expanse_issues", vuln_id: /^unencryptedftpserver$/ }
                ]
              },
              {
                name: "Vulnerability Detected - Application Layer",
                # cwe: "CWE-200",
                score: 0,
                description: "A vulnerability was detected at the application layer",
                recommendation: "Investigate the vulnerability.",
                matches: [
                  { source: "SecurityScorecard", vuln_id: /^web_vuln_host_high$/ },
                  { source: "SecurityScorecard", vuln_id: /^web_vuln_host_medium$/ },
                  { source: "SecurityScorecard", vuln_id: /^web_vuln_host_low$/ }
                ]
              },
              {
                name: "Vulnerability Detected - OS/System Layer",
                # cwe: "CWE-200",
                score: 0,
                description: "A vulnerability was detected at the service or OS layer",
                recommendation: "Investigate the vulnerability.",
                matches: [
                  { source: "SecurityScorecard", vuln_id: /^service_vuln_host_high$/ },
                  { source: "SecurityScorecard", vuln_id: /^service_vuln_host_medium$/ },
                  { source: "SecurityScorecard", vuln_id: /^service_vuln_host_low$/ }
                ]
              },
              {
                ####
                #### individual tasks should not send anything that would map to this entry,
                ####  instead it shoudl be a CVE
                ####
                name: "Vulnerability Detected (Patching Cadence *** INCORRECTLY MAPPED?)",
                # cwe: nil,
                score: 0,
                description: "Vulnerability seen on network more than 60 days after CVE was published.",
                recommendation: "Monitor CVE lists and vulnerability repositories for exploit code that may affect your infrastructure.",
                matches: [
                  { source: "Bitsight", vuln_id: /^patching_cadence$/ },
                  { source: "SecurityScorecard", vuln_id: /^patching_cadence_.*$/ }
                ]
              }
            ]
          end
        end
      end
    end
  end
end
