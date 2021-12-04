# frozen_string_literal: true

require_relative "../lib/params_helper"
require "rspec_helper"

RSpec.specialize "ParamsBuilder" do
  it "builds params with colons" do
    params = %w[task=burp:api_token=0xdeadbeef:kenna_api_host=api.denistreshchev.cisco.com]
    new_params = Kenna::128iid::ParamsHelper.build_params(params)
    expect(new_params.size).to eq(3)
    expect(new_params).to include("task=burp")
    expect(new_params).to include("api_token=0xdeadbeef")
    expect(new_params).to include("kenna_api_host=api.denistreshchev.cisco.com")
  end

  it "builds params with spaces" do
    params = %w[task=burp api_token=0xdeadbeef kenna_api_host=api.denistreshchev.cisco.com]
    new_params = Kenna::128iid::ParamsHelper.build_params(params)
    expect(new_params.size).to eq(3)
    expect(new_params).to include("task=burp")
    expect(new_params).to include("api_token=0xdeadbeef")
    expect(new_params).to include("kenna_api_host=api.denistreshchev.cisco.com")
  end

  it "builds params with spaces AND colons" do
    params = %w[task=burp burp_api_host="http://foo.example.com:8080" api_token=0xdeadbeef:kenna_api_host=api.denistreshchev.cisco.com]
    new_params = Kenna::128iid::ParamsHelper.build_params(params)
    expect(new_params.size).to eq(4)
    expect(new_params).to include("task=burp")
    expect(new_params).to include("burp_api_host=http://foo.example.com:8080")
    expect(new_params).to include("api_token=0xdeadbeef")
    expect(new_params).to include("kenna_api_host=api.denistreshchev.cisco.com")
  end

  it "builds params with spaces AND colons different order" do
    params = %w[task=burp api_token=0xdeadbeef:kenna_api_host=api.denistreshchev.cisco.com burp_api_host="http://foo.example.com:8080"]
    new_params = Kenna::128iid::ParamsHelper.build_params(params)
    expect(new_params.size).to eq(4)
    expect(new_params).to include("task=burp")
    expect(new_params).to include("burp_api_host=http://foo.example.com:8080")
    expect(new_params).to include("api_token=0xdeadbeef")
    expect(new_params).to include("kenna_api_host=api.denistreshchev.cisco.com")
  end

  it "builds params with colons and escaping" do
    params = %w[task=burp:api_token=0xdeadbeef:kenna_api_host=api.denistreshchev.cisco.com:burp_api_host="http://foo.example.com:8080"]
    new_params = Kenna::128iid::ParamsHelper.build_params(params)
    expect(new_params.size).to eq(4)
    expect(new_params).to include("task=burp")
    expect(new_params).to include("burp_api_host=http://foo.example.com:8080")
    expect(new_params).to include("api_token=0xdeadbeef")
    expect(new_params).to include("kenna_api_host=api.denistreshchev.cisco.com")
  end
end
