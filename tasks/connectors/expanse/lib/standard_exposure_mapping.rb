# frozen_string_literal: true

# included by mapper

module Kenna
  module 128iid
    module Expanse
      module StandardExposureMapping
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
        def field_mapping_for_standard_exposures
          {
            "AJP_SERVER" => {},
            "APPLICATION_SERVER_SOFTWARE" => {},
            "BACNET_SERVER" => {},
            "BUILDING_CONTROL_SYSTEM" => {},
            "CASSANDRA_SERVER" => {},
            "CERTIFICATE_ADVERTISEMENT" => {},
            "COUCH_DB_SERVER" => {},
            "DATA_STORAGE_AND_ANALYSIS" => {},
            "DEVELOPMENT_ENVIRONMENT" => {},
            "DNS_SERVER" => {},
            "DOMAIN_CONTROL_VALIDATED_CERTIFICATE_ADVERTISEMENT" => {},
            "ELASTICSEARCH_SERVER" => {},
            "EMBEDDED_SYSTEM" => {},
            "ETHERNET_IP_SERVER" => {},
            "EXPIRED_WHEN_SCANNED_CERTIFICATE_ADVERTISEMENT" => {},
            "FTP_SERVER" => {},
            "FTPS_SERVER" => {},
            "HADOOP_SERVER" => {},
            "HEALTHY_CERTIFICATE_ADVERTISEMENT" => {},
            "IKE2_SERVER" => {},
            "IMAP_SERVER" => {},
            "INSECURE_SIGNATURE_CERTIFICATE_ADVERTISEMENT" => {},
            "INTERNAL_IP_ADDRESS_ADVERTISEMENT" => {},
            "LOAD_BALANCER" => {},
            "LONG_EXPIRATION_CERTIFICATE_ADVERTISEMENT" => {},
            "MEMCACHED_SERVER" => {},
            "MODBUS_SERVER" => {},
            "MONGO_SERVER" => {},
            "MS_SQL_SERVER" => {},
            "MULTICAST_DNS_SERVER" => {},
            "MY_SQL_SERVER" => {},
            "NAT_PMP_SERVER" => {},
            "NET_BIOS_NAME_SERVER" => {},
            "NETWORKING_AND_SECURITY_INFRASTRUCTURE" => {},
            "NTP_SERVER" => {},
            "PC_ANYWHERE_SERVER" => {},
            "POP3_SERVER" => {},
            "POSTGRES_SERVER" => {},
            "RDP_SERVER" => {},
            "REDIS_SERVER" => {},
            "RPC_BIND_SERVER" => {},
            "RSYNC_SERVER" => {},
            "SELF_SIGNED_CERTIFICATE_ADVERTISEMENT" => {},
            "SERVER_SOFTWARE" => {},
            "SHAREPOINT_SERVER" => {},
            "SHORT_KEY_CERTIFICATE_ADVERTISEMENT" => {},
            "SIP_SERVER" => {},
            "SMB_SERVER" => {},
            "SMTP_SERVER" => {},
            "SNMP_SERVER" => {},
            "SSH_SERVER" => {},
            "TELECONFERENCING_AND_COLLABORATION" => {},
            "TELNET_SERVER" => {},
            "UNENCRYPTED_FTP_SERVER" => {},
            "UNENCRYPTED_LOGIN" => {},
            "UPNP_SERVER" => {},
            "VNC_OVER_HTTP_SERVER" => {},
            "VNC_SERVER" => {},
            "VPN" => {},
            "VX_WORKS_SERVER" => {},
            "WEB_SERVER" => {},
            "WILDCARD_CERTIFICATE_ADVERTISEMENT" => {},
            "XMPP_SERVER" => {}
          }
        end
      end
    end
  end
end
