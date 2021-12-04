# frozen_string_literal: true

# included by mapper

module Kenna
  module 128iid
    module Expanse
      module CloudExposureMapping
        ###
        ### Each entry (type) should have a set of mappings for foreach KDI section:
        ###   Asset
        ###   Vuln
        ###   VulnDef
        ###
        ### Also, foreach mapping should be one of the following types:
        ###   calc - just copies data from the source
        ###   copy - just copies data from the source
        ###   data - static data, use directly without worrying about source data
        ###

        def field_mapping_for_cloud_exposures
          {
            "application_server_software" => {
              "asset" => [],
              "vuln" => [
                { action: "proc",
                  target: "details",
                  proc: lambda { |x|
                          "Exposed App Server Software: #{x['firstObservation']['configuration']['applicationServerSoftware']}"
                        }                                                      }
              ],
              "vuln_def" => []
            },
            "bacnet_servers" => {},
            "building_control_system" => {},
            "certificate_advertisements" => {},
            "colocated_ajp_server" => {},
            "colocated_bacnet_server" => {},
            "colocated_bgp_server" => {},
            "colocated_cassandra_server" => {},
            "colocated_couch_db_server" => {},
            "colocated_dns_server" => {},
            "colocated_ethernet_ip_server" => {},
            "colocated_ftps_server" => {},
            "colocated_ike2_server" => {},
            "colocated_imap_server" => {},
            "colocated_internal_ip_address_advertisement" => {},
            "colocated_memcached_server" => {},
            "colocated_modbus_server" => {},
            "colocated_mongo_server" => {},
            "colocated_ms_sql_server" => {},
            "colocated_multicast_dns_server" => {},
            "colocated_my_sql_server" => {},
            "colocated_nat_pmp_server" => {},
            "colocated_net_bios_name_server" => {},
            "colocated_ntp_server" => {},
            "colocated_pc_anywhere_server" => {},
            "colocated_pop3_server" => {},
            "colocated_postgres_server" => {},
            "colocated_rdp_server" => {},
            "colocated_redis_server" => {},
            "colocated_rpcbind_server" => {},
            "colocated_rsync_server" => {},
            "colocated_salt_stack_server" => {},
            "colocated_sharepoint_server" => {},
            "colocated_sip_server" => {},
            "colocated_smb_server" => {},
            "colocated_smtp_server" => {},
            "colocated_snmp_server" => {},
            "colocated_ssh_server" => {},
            "colocated_telnet_server" => {},
            "colocated_unencrypted_ftp_server" => {},
            "colocated_upnp_server" => {},
            "colocated_vnc_server" => {},
            "colocated_vx_works_server" => {},
            "colocated_xmpp_server" => {},
            "data_storage_and_analysis" => {},
            "development_environments" => {},
            "dns_servers" => {},
            "domain_control_validated_certificate_advertisements" => {
              "asset" => [],
              "vuln" => [
                { action: "proc",
                  target: "details",
                  proc: lambda { |x|
                          "Domain Control Validated Certificate: #{JSON.pretty_generate(x['certificate'])}"
                        }                                                      }
              ],
              "vuln_def" => []
            },
            "embedded_system" => {},
            "ethernet_ip_servers" => {},
            "expired_when_scanned_certificate_advertisements" => {
              "asset" => [],
              "vuln" => [
                { action: "proc",
                  target: "details",
                  proc: lambda { |x|
                          "Expired Certificate: #{JSON.pretty_generate(x['certificate'])}"
                        }                                                      }
              ],
              "vuln_def" => []
            },
            "ftp_servers" => {},
            "ftps_servers" => {},
            "_healthy_certificate_advertisements" => {
              "asset" => [],
              "vuln" => [
                { action: "proc",
                  target: "details",
                  proc: lambda { |x|
                          "Healthy Certificate Advertisement: #{JSON.pretty_generate(x['certificate'])}"
                        }                                                      }
              ],
              "vuln_def" => []
            },
            "insecure_signature_certificate_advertisements" => {
              "asset" => [],
              "vuln" => [
                { action: "proc",
                  target: "details",
                  proc: lambda { |x|
                          "Insecure Signature Certificate: #{JSON.pretty_generate(x['certificate'])}"
                        }                                                      }
              ],
              "vuln_def" => []
            },
            "internal_ip_address_advertisements" => {
              "asset" => [],
              "vuln" => [

                { action: "proc",
                  target: "details",
                  proc: lambda { |x|
                          "Detected Internal IP advertisement with configuration: #{JSON.pretty_generate(x['firstObservation']['configuration'])}"
                        }                                                      }

              ],
              "vuln_def" => []
            },
            "jenkins_server" => {},
            "load_balancers" => {},
            "long_expiration_certificate_advertisements" => {
              "asset" => [],
              "vuln" => [
                { action: "proc",
                  target: "details",
                  proc: lambda { |x|
                          "Long Expiration Certificate: #{JSON.pretty_generate(x['certificate'])}"
                        }                                                      }
              ],
              "vuln_def" => []
            },
            "memcached_servers" => {},
            "modbus_servers" => {},
            "ms_sql_servers" => {},
            "my_sql_servers" => {},
            "net_bios_name_servers" => {},
            "pop3_servers" => {
              "asset" => [],
              "vuln" => [
                { action: "proc",
                  target: "details",
                  proc: lambda { |x|
                          "Detected Pop3 Server with configuration: #{JSON.pretty_generate(x['firstObservation']['configuration'])}"
                        }                                                      }
              ],
              "vuln_def" => []
            },
            "rdp_servers" => {},
            "self_signed_certificate_advertisements" => {
              "asset" => [],
              "vuln" => [
                { action: "proc",
                  target: "details",
                  proc: lambda { |x|
                          "Self Signed Certificate: #{JSON.pretty_generate(x['certificate'])}"
                        }                                                      }

              ],
              "vuln_def" => []
            },
            "server_software" => {
              "asset" => [],
              "vuln" => [
                { action: "proc",
                  target: "details",
                  proc: lambda { |x|
                          "Exposed Server Software: #{x['firstObservation']['configuration']['serverSoftware']}"
                        }                                                      }
              ],
              "vuln_def" => []
            },
            "short_key_certificate_advertisements" => {
              "asset" => [],
              "vuln" => [
                { action: "proc",
                  target: "details",
                  proc: lambda { |x|
                          "Short Key Certificate: #{JSON.pretty_generate(x['certificate'])}"
                        }                                                      }
              ],
              "vuln_def" => []
            },
            "sip_servers" => {},
            "smb_servers" => {},
            "smtp_servers" => {},
            "snmp_servers" => {},
            "ssh_servers" => {},
            "telnet_servers" => {},
            "upnp_servers" => {},
            "unencrypted_logins" => {},
            "unencrypted_ftp_servers" => {},
            "web_servers" => {},
            "wildcard_certificate_advertisements" => {
              "asset" => [],
              "vuln" => [
                { action: "proc",
                  target: "details",
                  proc: lambda { |x|
                          "Wildcard Certificate: #{JSON.pretty_generate(x['certificate'])}"
                        }                                                      }
              ],
              "vuln_def" => []
            },
            "vnc_servers" => {},
            "vpn" => {},
            "vx_works_servers" => {}
          }
        end
      end
    end
  end
end
