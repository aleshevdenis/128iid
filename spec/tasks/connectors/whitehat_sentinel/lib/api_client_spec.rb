# frozen_string_literal: true

require "rspec_helper"

RSpec.specialize Kenna::128iid::NTTSentinelDynamic::ApiClient do
  subject(:api_client) { specialized_class.new(api_key: "0xdeadbeef") }

  specialize "#vulns" do
    context "when given query conditions" do
      let(:query) { { "query_severity" => 2 } }

      it "includes the condition in the API request" do
        response = { collection: [] }.to_json
        expect(Kenna::128iid::Helpers::Http).to receive(:http_get).with(anything, { params: hash_including(query) }, anything).and_return(response)
        api_client.vulns(query).to_a
      end
    end
  end
end
