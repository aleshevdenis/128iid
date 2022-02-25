# frozen_string_literal: true

module Kenna
  module 128iid
    module Ordr
      class Mapper
        SCANNER_TYPE = "Ordr"
        attr_reader :device, :alarm

        def initialize(device, alarm)
          @device = device
          @alarm = alarm
        end

        def extract_asset
          {
            "mac_address" => device.fetch("MacAddress"),
            "ip_address" => device["IpAddress"],
            "hostname" => device["dhcpHostname"],
            "os" => device["OsType"],
            "os_version" => [device["OsVersion"], device["SwVersion"]].compact.join(", "),
            "tags" => ["Ordr:DeviceType:#{device.fetch('DeviceType')}"]
          }.compact
        end

        def extract_vuln
          {
            "scanner_type" => SCANNER_TYPE,
            "scanner_identifier" => alarm.fetch("alarmHash"),
            "vuln_def_name" => alarm.fetch("alarm_type"),
            "scanner_score" => alarm.fetch("riskScore").to_i,
            "details" => JSON.pretty_generate(extract_additional_fields)
          }.compact
        end

        def extract_definition
          cve = alarm.fetch("alarm_type").scan(/CVE-\d*-\d*/).join(", ")
          {
            "name" => alarm.fetch("alarm_type"),
            "scanner_type" => SCANNER_TYPE,
            "cve_identifiers" => (cve if cve.present?)
          }.compact
        end

        def extract_additional_fields
          {
            "Device Group" => device["Group"],
            "Device Profile" => device["Profile"],
            "Device ModelNameNo" => device["ModelNameNo"],
            "Device SerialNo" => device["SerialNo"],
            "Device Subnet" => device["Subnet"],
            "Device EndpointType" => device["endpointType"],
            "Alarm Category" => alarm["category"],
            "Alarm Severity Level" => alarm["severityLevel"],
            "Alarm Incident Type" => alarm["incidentType"]
          }.compact
        end
      end
    end
  end
end
