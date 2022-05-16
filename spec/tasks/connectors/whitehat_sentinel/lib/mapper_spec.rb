# frozen_string_literal: true

require "rspec_helper"

RSpec.specialize Kenna::128iid::NTTSentinelDynamic::Mapper do
  let(:scoring_system) { :legacy }

  subject(:mapper) { specialized_class.new(scoring_system) }

  specialize "#finding_hash" do
    let(:node) { { id: node_id, found: found.iso8601, closed: closed&.iso8601, class: node_class, status:, severity: severity.to_s, risk:, attack_vectors: } }
    let(:node_id) { 10_085 }
    let(:found) { Time.new(2021, 10, 22, 12, 13, 14).utc }
    let(:closed) { nil }
    let(:node_class) { "Insufficient Transport Layer Protection" }
    let(:status) { "new" }
    let(:severity) { 4 }
    let(:risk) { 3 }
    let(:attack_vectors) { [] }

    subject(:finding_hash) { mapper.finding_hash(node) }

    it { is_expected.to include(scanner_identifier: node_id) }
    it { is_expected.to include(scanner_type: "NTT Sentinel Dynamic") }
    it { is_expected.to include(created_at: found) }
    it { is_expected.to_not include(:last_fixed_on) }
    it { is_expected.to_not include(:closed_at) }
    it { is_expected.to include(vuln_def_name: node_class) }

    it "sets last_seen_at to now" do
      now = Time.new(2021, 10, 30, 8, 9, 10).utc

      Timecop.freeze(now) do
        expect(mapper.finding_hash(node)).to include(last_seen_at: now)
      end
    end

    context "when the node has a closed attribute" do
      let(:closed) { Time.new(2021, 10, 23, 11, 12, 13).utc }

      it { is_expected.to include(last_seen_at: closed) }
      it { is_expected.to include(last_fixed_on: closed) }
      it { is_expected.to include(closed_at: closed) }
    end

    context "when the node's status is open" do
      let(:status) { "open" }

      it { is_expected.to include(triage_state: "in_progress") }
    end

    context "when the node's status is closed" do
      let(:status) { "closed" }

      it { is_expected.to include(triage_state: "resolved") }
    end

    context "when the node's status is accepted" do
      let(:status) { "accepted" }

      it { is_expected.to include(triage_state: "risk_accepted") }
    end

    context "when the node's status is invalid" do
      let(:status) { "invalid" }

      it { is_expected.to include(triage_state: "not_a_security_issue") }
    end

    context "when the node's status is an unrecognized value" do
      let(:status) { "bogus" }

      it { is_expected.to include(triage_state: "new") }
    end

    it { is_expected.to include(severity: severity * 2) }

    context "when using advanced scoring" do
      let(:scoring_system) { :advanced }

      it { is_expected.to include(severity: risk * 2) }
    end

    context "when using an unknown scoring system" do
      it "raises an ArgumentError" do
        expect { specialized_class.new(:bogus) }.to raise_error(ArgumentError)
      end
    end

    context "when there is an attack vector" do
      let(:attack_vectors) { [vector] }
      let(:vector) { { request: { method:, url: vector_url, headers: request_headers }, response: { status: response_status, headers: response_headers } } }
      let(:method) { "GET" }
      let(:vector_url) { "http://vector.example.com" }
      let(:response_status) { 200 }
      let(:request_headers) { [{ name: "User-Agent", value: "chrome" }, { name: "Cookie", value: "oreo" }] }
      let(:response_headers) { [{ name: "ETag", value: "0xdeadbeef" }, { name: "X-Token", value: "this is a token" }] }

      it { is_expected.to include(additional_fields: hash_including(request_method: method)) }
      it { is_expected.to include(additional_fields: hash_including(request_url: vector_url)) }
      it { is_expected.to include(additional_fields: hash_including(response_status: response_status.to_s)) }

      it "combines the request headers into a single string" do
        headers_string = "User-Agent=chrome Cookie=oreo"
        expect(finding_hash[:additional_fields]).to include(request_headers: headers_string)
      end

      it "combines the response headers into a single string" do
        headers_string = "ETag=0xdeadbeef X-Token=this is a token"
        expect(finding_hash[:additional_fields]).to include(response_headers: headers_string)
      end
    end

    context "when there are multiple attack vectors" do
      let(:attack_vectors) { [vector0, vector1] }
      let(:vector0) { { request: { method: "GET", url: vector_url, headers: request_headers }, response: { status: response_status, headers: response_headers } } }
      let(:vector1) { { request: { method: "POST", url: vector_url, headers: request_headers }, response: { status: response_status, headers: response_headers } } }
      let(:vector_url) { "http://vector.example.com" }
      let(:response_status) { 200 }
      let(:request_headers) { [{ name: "User-Agent", value: "chrome" }, { name: "Cookie", value: "oreo" }] }
      let(:response_headers) { [{ name: "ETag", value: "0xdeadbeef" }, { name: "X-Token", value: "this is a token" }] }

      it "includes all vectors" do
        expect(finding_hash[:additional_fields]).to include(request_0_method: "GET", request_1_method: "POST")
      end
    end
  end

  specialize "#asset_hash" do
    let(:node) { { site: site_id.to_s, site_name: } }
    let(:site_id) { 12 }
    let(:site_name) { "Example dot com" }
    let(:url) { "http://foo.example.com/path" }

    subject(:asset_hash) { mapper.asset_hash(node, url) }

    it { is_expected.to include(url:) }
    it { is_expected.to include(application: site_name) }
    it { is_expected.to include(tags: []) }

    context "when an asset has been registered" do
      let(:asset) do
        {
          asset: {
            id: site_id,
            custom_asset_id: whitehat_custom_id,
            label: whitehat_label,
            asset_owner_name: whitehat_owner,
            tags: whitehat_tags
          }
        }
      end
      let(:whitehat_custom_id) { "custom id" }
      let(:whitehat_tags) { %w[tag_one tag_two] }
      let(:whitehat_label) { "label" }
      let(:whitehat_owner) { "owner" }

      before do
        mapper.register_asset(asset)
      end

      it "includes the asset's tags from Whitehat" do
        expect(asset_hash[:tags]).to include(*whitehat_tags)
      end

      it "includes the asset's label from Whitehat" do
        expect(asset_hash[:tags]).to include(whitehat_label)
      end

      it "includes the asset's owner name from Whitehat" do
        expect(asset_hash[:tags]).to include(whitehat_owner)
      end

      it "includes the asset's custom id from Whitehat" do
        expect(asset_hash[:tags]).to include(whitehat_custom_id)
      end

      context "when there are no tags" do
        let(:whitehat_tags) { [] }

        it "includes the other fields" do
          expect(asset_hash[:tags]).to contain_exactly(whitehat_label, whitehat_owner, whitehat_custom_id)
        end
      end

      context "when a field is blank" do
        let(:whitehat_owner) { "" }

        it "excludes the empty string" do
          expect(asset_hash[:tags]).to_not include("")
        end
      end

      context "when a field is nil" do
        let(:whitehat_label) { nil }

        it "excludes the nil" do
          expect(asset_hash[:tags]).to_not include(nil)
        end
      end

      context "when a field is missing" do
        let(:asset) do
          {
            asset: {
              id: site_id,
              label: whitehat_label,
              asset_owner_name: whitehat_owner,
              tags: whitehat_tags
            }
          }
        end

        it "includes the other fields" do
          expect(asset_hash[:tags]).to contain_exactly(*[whitehat_tags, whitehat_label, whitehat_owner].flatten)
        end
      end
    end
  end

  specialize "#vuln_def_hash" do
    let(:node) { { class: node_class, solution: solution_node, description: description_node } }
    let(:node_class) { "Insufficient Transport Layer Protection" }
    let(:solution_node) { { solution: solution_text } }
    let(:description_node) { { description: description_text } }
    let(:description_text) { "description text" }
    let(:solution_text) { "solution text" }

    subject(:asset_hash) { mapper.vuln_def_hash(node) }

    it { is_expected.to_not include(:cwe_identifiers) }

    context "when the description references a CWE" do
      let(:description_text) do
        "<p>description text</p>\r\n\r\n<h2>References</h2>\r\n\r\n<p><a href=\"https://owasp.org/www-community/attacks/xss/\">owasp.org/www-community/attacks/xss/</a></p>\r\n\r\n<p><a href=\"https://webappsec.pbworks.com/w/page/13246920/Cross%20Site%20Scripting\">webappsec.pbworks.com/w/page/13246920/Cross%20Site%20Scripting</a></p>\r\n\r\n<p><a href=\"https://cwe.mitre.org/data/definitions/79.html\">cwe.mitre.org/data/definitions/79.html</a></p>\r\n\r\n<p>&nbsp;</p>\r\n"
      end

      it { is_expected.to include(cwe_identifiers: "CWE-79") }
    end

    context "when the description references a CWE without TLS" do
      let(:description_text) do
        "<p>description text</p>\r\n\r\n<h2>References</h2>\r\n\r\n<p><a href=\"https://owasp.org/www-community/attacks/xss/\">owasp.org/www-community/attacks/xss/</a></p>\r\n\r\n<p><a href=\"https://webappsec.pbworks.com/w/page/13246920/Cross%20Site%20Scripting\">webappsec.pbworks.com/w/page/13246920/Cross%20Site%20Scripting</a></p>\r\n\r\n<p><a href=\"http://cwe.mitre.org/data/definitions/79.html\">cwe.mitre.org/data/definitions/79.html</a></p>\r\n\r\n<p>&nbsp;</p>\r\n"
      end

      it { is_expected.to include(cwe_identifiers: "CWE-79") }
    end

    context "when the description references multiple CWEs" do
      let(:description_text) do
        "<p>description text</p>\r\n\r\n<h2>References</h2>\r\n\r\n<div><a href=\"https://owasp.org/www-project-top-ten/OWASP_Top_Ten_2017/Top_10-2017_A3-Sensitive_Data_Exposure\">https://owasp.org/www-project-top-ten/OWASP_Top_Ten_2017/Top_10-2017_A3-Sensitive_Data_Exposure</a></div>\r\n\r\n<div><a href=\"https://owasp-aasvs.readthedocs.io/en/latest/requirement-8.1.html\">https://owasp-aasvs.readthedocs.io/en/latest/requirement-8.1.html</a></div>\r\n\r\n<div><a href=\"https://cwe.mitre.org/data/definitions/200.html\">https://cwe.mitre.org/data/definitions/200.html</a></div>\r\n\r\n<div><a href=\"https://cwe.mitre.org/data/definitions/209.html\">cwe.mitre.org/data/definitions/209.html</a></div>\r\n\r\n<div><a href=\"https://capec.mitre.org/data/definitions/118.html\">capec.mitre.org/data/definitions/118.html</a></div>\r\n"
      end

      it { is_expected.to include(cwe_identifiers: "CWE-200,CWE-209") }
    end

    context "when the solution references a CWE" do
      let(:solution_text) do
        "<p>solution text</p>\r\n\r\n<h2>References</h2>\r\n\r\n<p><a href=\"https://owasp.org/www-community/attacks/xss/\">owasp.org/www-community/attacks/xss/</a></p>\r\n\r\n<p><a href=\"https://webappsec.pbworks.com/w/page/13246920/Cross%20Site%20Scripting\">webappsec.pbworks.com/w/page/13246920/Cross%20Site%20Scripting</a></p>\r\n\r\n<p><a href=\"https://cwe.mitre.org/data/definitions/79.html\">cwe.mitre.org/data/definitions/79.html</a></p>\r\n\r\n<p>&nbsp;</p>\r\n"
      end

      it { is_expected.to include(cwe_identifiers: "CWE-79") }
    end

    context "when the solution references a CWE without TLS" do
      let(:solution_text) do
        "<p>solution text</p>\r\n\r\n<h2>References</h2>\r\n\r\n<p><a href=\"https://owasp.org/www-community/attacks/xss/\">owasp.org/www-community/attacks/xss/</a></p>\r\n\r\n<p><a href=\"https://webappsec.pbworks.com/w/page/13246920/Cross%20Site%20Scripting\">webappsec.pbworks.com/w/page/13246920/Cross%20Site%20Scripting</a></p>\r\n\r\n<p><a href=\"http://cwe.mitre.org/data/definitions/79.html\">cwe.mitre.org/data/definitions/79.html</a></p>\r\n\r\n<p>&nbsp;</p>\r\n"
      end

      it { is_expected.to include(cwe_identifiers: "CWE-79") }
    end

    context "when the solution references multiple CWEs" do
      let(:solution_text) do
        "<p>solution text</p>\r\n\r\n<h2>References</h2>\r\n\r\n<div><a href=\"https://owasp.org/www-project-top-ten/OWASP_Top_Ten_2017/Top_10-2017_A3-Sensitive_Data_Exposure\">https://owasp.org/www-project-top-ten/OWASP_Top_Ten_2017/Top_10-2017_A3-Sensitive_Data_Exposure</a></div>\r\n\r\n<div><a href=\"https://owasp-aasvs.readthedocs.io/en/latest/requirement-8.1.html\">https://owasp-aasvs.readthedocs.io/en/latest/requirement-8.1.html</a></div>\r\n\r\n<div><a href=\"https://cwe.mitre.org/data/definitions/200.html\">https://cwe.mitre.org/data/definitions/200.html</a></div>\r\n\r\n<div><a href=\"https://cwe.mitre.org/data/definitions/209.html\">cwe.mitre.org/data/definitions/209.html</a></div>\r\n\r\n<div><a href=\"https://capec.mitre.org/data/definitions/118.html\">capec.mitre.org/data/definitions/118.html</a></div>\r\n"
      end

      it { is_expected.to include(cwe_identifiers: "CWE-200,CWE-209") }
    end

    context "when the description and solution reference CWEs" do
      let(:description_text) do
        "<p>description text</p>\r\n\r\n<h2>References</h2>\r\n\r\n<p><a href=\"https://owasp.org/www-community/attacks/xss/\">owasp.org/www-community/attacks/xss/</a></p>\r\n\r\n<p><a href=\"https://webappsec.pbworks.com/w/page/13246920/Cross%20Site%20Scripting\">webappsec.pbworks.com/w/page/13246920/Cross%20Site%20Scripting</a></p>\r\n\r\n<p><a href=\"https://cwe.mitre.org/data/definitions/79.html\">cwe.mitre.org/data/definitions/79.html</a></p>\r\n\r\n<p>&nbsp;</p>\r\n"
      end

      let(:solution_text) do
        "<p>solution text</p>\r\n\r\n<h2>References</h2>\r\n\r\n<p><a href=\"https://owasp.org/www-community/attacks/xss/\">owasp.org/www-community/attacks/xss/</a></p>\r\n\r\n<p><a href=\"https://webappsec.pbworks.com/w/page/13246920/Cross%20Site%20Scripting\">webappsec.pbworks.com/w/page/13246920/Cross%20Site%20Scripting</a></p>\r\n\r\n<p><a href=\"https://cwe.mitre.org/data/definitions/479.html\">cwe.mitre.org/data/definitions/479.html</a></p>\r\n\r\n<p>&nbsp;</p>\r\n"
      end

      it { is_expected.to include(cwe_identifiers: "CWE-79,CWE-479") }
    end

    context "when the description and solution reference the same CWE" do
      let(:description_text) do
        "<p>description text</p>\r\n\r\n<h2>References</h2>\r\n\r\n<p><a href=\"https://owasp.org/www-community/attacks/xss/\">owasp.org/www-community/attacks/xss/</a></p>\r\n\r\n<p><a href=\"https://webappsec.pbworks.com/w/page/13246920/Cross%20Site%20Scripting\">webappsec.pbworks.com/w/page/13246920/Cross%20Site%20Scripting</a></p>\r\n\r\n<p><a href=\"https://cwe.mitre.org/data/definitions/79.html\">cwe.mitre.org/data/definitions/79.html</a></p>\r\n\r\n<p>&nbsp;</p>\r\n"
      end

      let(:solution_text) do
        "<p>solution text</p>\r\n\r\n<h2>References</h2>\r\n\r\n<p><a href=\"https://owasp.org/www-community/attacks/xss/\">owasp.org/www-community/attacks/xss/</a></p>\r\n\r\n<p><a href=\"https://webappsec.pbworks.com/w/page/13246920/Cross%20Site%20Scripting\">webappsec.pbworks.com/w/page/13246920/Cross%20Site%20Scripting</a></p>\r\n\r\n<p><a href=\"https://cwe.mitre.org/data/definitions/79.html\">cwe.mitre.org/data/definitions/79.html</a></p>\r\n\r\n<p>&nbsp;</p>\r\n"
      end

      it { is_expected.to include(cwe_identifiers: "CWE-79") }
    end
  end
end
