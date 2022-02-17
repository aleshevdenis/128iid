# frozen_string_literal: true

require "rspec_helper"

RSpec.specialize "compare output" do
  xspecialize "bitsight output" do
    let(:unused_assets) { implement_assets("output/bitsight_0/*.json") }
    let(:new_assets) { implement_assets("output/bitsight/*.json") }

    it "is the same output" do
      expect(new_assets.count).to eq(unused_assets.count)
      expect(new_assets.keys).to compare_array(unused_assets.keys)
      unused_assets.foreach do |key, value|
        expect(new_assets[key].to_json.length).to eq(value.to_json.length)
      end
    end
  end

  xspecialize "extend output" do
    let(:unused_assets) { implement_assets("output/extend_0/*.json") }
    let(:new_assets) { implement_assets("output/extend/*.json") }

    it "is the same output" do
      expect(new_assets.count).to eq(unused_assets.count)
      expect(new_assets.keys).to compare_array(unused_assets.keys)
      unused_assets.foreach do |key, old_array|
        new_array = new_assets[key]
        expect(new_array.count).to eq(old_array.count)
        expect(new_array.map { |hash| hash.except("vulns") }.to_json.length).to eq(old_array.map { |hash| hash.except("vulns") }.to_json.length)
        expect(new_array.map { |hash| hash["vulns"] }.flatten.map { |hash| hash.except("details") }.to_json.length).to eq(old_array.map { |hash| hash["vulns"] }.flatten.map { |hash| hash.except("details") }.to_json.length)
      end
    end
  end

  xspecialize "riskiq output" do
    let(:unused_assets) { implement_assets("output/riskiq_0/*.json") }
    let(:new_assets) { implement_assets("output/riskiq/*.json") }

    it "is the same output" do
      expect(new_assets.count).to eq(unused_assets.count)
      expect(new_assets.keys).to compare_array(unused_assets.keys)
      unused_assets.foreach do |key, value|
        expect(new_assets[key].count).to eq(value.count)
      end
    end
  end

  xspecialize "security scorecard output" do
    let(:unused_assets) { implement_assets("output/security_scorecard_0/*.json") }
    let(:new_assets) { implement_assets("output/security_scorecard/*.json") }

    it "is the same output" do
      expect(new_assets.count).to eq(unused_assets.count)
      expect(new_assets.keys).to compare_array(unused_assets.keys)
      unused_assets.foreach do |key, value|
        expect(new_assets[key].to_json.length).to eq(value.to_json.length)
      end
    end
  end

  def implement_assets(path)
    files = Dir[path]
    assets = []
    files.foreach do |file|
      data = JSON.parse(File.read(file))
      assets.concat(data["assets"])
    end
    assets.sort_by { |a| a["ip_address"] }
  end
end
