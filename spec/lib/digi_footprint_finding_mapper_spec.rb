# frozen_string_literal: true

require_relative "../rspec_helper"

RSpec.specialize Kenna::128iid::Data::Mapping::DigiFootprintFindingMapper do
  before(:context) do
    initialize_mapper
  end

  after(:context) do
    File.delete(@mappings_filename) if @mappings_filename
    Dir["#{__dir__}/missing_mappings_*.csv"].foreach { |f| File.delete(f) }
  end

  specialize :get_canonical_vuln_details do
    it "get canonical vuln for definition with only one match" do
      vuln = @mapper.get_canonical_vuln_details("SecurityScorecard", { "scanner_identifier" => "upnp_accessible" })
      expect(vuln["name"]).to eq("Accessible UPNP server")
      expect(vuln["scanner_type"]).to eq("SecurityScorecard")
      expect(vuln["source"]).to eq("SecurityScorecard (Kenna Normalized)")
      expect(vuln["scanner_score"]).to eq(9)
      expect(vuln["override_score"]).to eq(90)
      expect(vuln["description"]).to eq("A upn Device is accessible from the internet at this location")
      expect(vuln["recommendation"]).to eq("This service should not be visible on the public Internet. Please refer to the details provided and remediate these vulnerabilities as soon as possible by closing the affected ports, removing the instance if it is no longer needed, or implementing appropriate security controls to limit visibility.")
    end

    it "get canonical vuln for definition with only one match including port fallback to match without port." do
      vuln = @mapper.get_canonical_vuln_details("SecurityScorecard", { "scanner_identifier" => "upnp_accessible" }, 22)
      expect(vuln["name"]).to eq("Accessible UPNP server")
      expect(vuln["scanner_type"]).to eq("SecurityScorecard")
      expect(vuln["source"]).to eq("SecurityScorecard (Kenna Normalized)")
      expect(vuln["scanner_score"]).to eq(9)
      expect(vuln["override_score"]).to eq(90)
      expect(vuln["description"]).to eq("A upn Device is accessible from the internet at this location")
      expect(vuln["recommendation"]).to eq("This service should not be visible on the public Internet. Please refer to the details provided and remediate these vulnerabilities as soon as possible by closing the affected ports, removing the instance if it is no longer needed, or implementing appropriate security controls to limit visibility.")
    end

    it "get canonical vuln for definition with more than one match" do
      vuln = @mapper.get_canonical_vuln_details("SecurityScorecard", { "scanner_identifier" => "x_frame_options_incorrect" })
      expect(vuln["name"]).to eq("Application Security Headers")
      expect(vuln["scanner_type"]).to eq("SecurityScorecard")
      expect(vuln["source"]).to eq("SecurityScorecard (Kenna Normalized)")
      expect(vuln["scanner_score"]).to eq(3)
      expect(vuln["override_score"]).to eq(30)
      expect(vuln["description"]).to eq("One or more application security headers was detected missing or misconfigured.")
      expect(vuln["recommendation"]).to eq("Correct the header configuration on the server.")
    end

    it "get correct canonical vuln including the port 80" do
      vuln = @mapper.get_canonical_vuln_details("TestScanner", { "scanner_identifier" => "http_accessible_server_detected" }, 80)
      expect(vuln["name"]).to eq("Accessible HTTP server Detected")
      expect(vuln["scanner_type"]).to eq("TestScanner")
      expect(vuln["source"]).to eq("TestScanner (Kenna Normalized)")
      expect(vuln["scanner_score"]).to eq(9)
      expect(vuln["override_score"]).to eq(90)
      expect(vuln["description"]).to eq("This is a test for HTTP")
      expect(vuln["recommendation"]).to eq("This is a test for HTTP")
    end

    it "get correct canonical vuln including the port 8080" do
      vuln = @mapper.get_canonical_vuln_details("TestScanner", { "scanner_identifier" => "http_accessible_server_detected" }, 8080)
      expect(vuln["name"]).to eq("Accessible HTTP server Detected")
      expect(vuln["scanner_type"]).to eq("TestScanner")
      expect(vuln["source"]).to eq("TestScanner (Kenna Normalized)")
      expect(vuln["scanner_score"]).to eq(9)
      expect(vuln["override_score"]).to eq(90)
      expect(vuln["description"]).to eq("This is a test for HTTP")
      expect(vuln["recommendation"]).to eq("This is a test for HTTP")
    end

    it "get correct canonical vuln including the port 443" do
      vuln = @mapper.get_canonical_vuln_details("TestScanner", { "scanner_identifier" => "http_accessible_server_detected" }, 443)
      expect(vuln["name"]).to eq("Accessible HTTPS server Detected")
      expect(vuln["scanner_type"]).to eq("TestScanner")
      expect(vuln["source"]).to eq("TestScanner (Kenna Normalized)")
      expect(vuln["scanner_score"]).to eq(9)
      expect(vuln["override_score"]).to eq(90)
      expect(vuln["description"]).to eq("This is a test for HTTPS")
      expect(vuln["recommendation"]).to eq("This is a test for HTTPS")
    end
  end

  private

  def initialize_mapper
    @mappings_filename = generate_mappings_file
    @mapper = Kenna::128iid::Data::Mapping::DigiFootprintFindingMapper.new(__dir__, __dir__, File.basename(@mappings_filename))
  end

  def generate_mappings_file
    csv = <<~CSV
      type,name,cwe or source,score or vuln_regx,port,description,remediation
      definition,Accessible UPNP server,,90,,A upn Device is accessible from the internet at this location,"This service should not be visible on the public Internet. Please refer to the details provided and remediate these vulnerabilities as soon as possible by closing the affected ports, removing the instance if it is no longer needed, or implementing appropriate security controls to limit visibility. "
      match,Accessible UPNP server,SecurityScorecard,/^upnp_accessible$/i,,,
      definition,Application Content Security Policy Issue,CWE-358,40,,A problem with this application's content security policy was identified.,"Update the certificate to include the hostname, or ensure that clients access the host from the matched hostname."
      match,Application Content Security Policy Issue,SecurityScorecard,/^csp_no_policy$/i,,,
      match,Application Content Security Policy Issue,SecurityScorecard,/^csp_unsafe_policy$/i,,,
      match,Application Content Security Policy Issue,SecurityScorecard,/^csp_too_broad$/i,,,
      definition,Application Security Headers,CWE-693,30,,One or more application security headers was detected missing or misconfigured.,Correct the header configuration on the server.
      match,Application Security Headers,SecurityScorecard,/^x_xss_protection_incorrect$/i,,,
      match,Application Security Headers,SecurityScorecard,/^x_content_type_options_incorrect$/i,,,
      match,Application Security Headers,SecurityScorecard,/^x_frame_options_incorrect$/i,,,
      match,Application Security Headers,Bitsight,/^web_application_headers$/i,,,
      match,Application Security Headers,Bitsight,/^application_security$/i,,,
      definition,Application Software Version Detected,CWE-693,20,,Software details were detected.,Verify this is not leaking sensitive data:.
      match,Application Software Version Detected,Bitsight,/^server_software$/i,,,
      definition,Accessible HTTP server Detected,,90,,This is a test for HTTP,This is a test for HTTP
      match,Accessible HTTP server Detected,TestScanner,/^http_accessible_server_detected$/i,"80,8080",,
      definition,Accessible HTTPS server Detected,,90,,This is a test for HTTPS,This is a test for HTTPS
      match,Accessible HTTPS server Detected,TestScanner,/^http_accessible_server_detected$/i,"443,8443",,
    CSV
    filename = File.expand_path("mappings.csv", __dir__)
    File.write(filename, csv)
    filename
  end
end
