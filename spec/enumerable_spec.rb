# frozen_string_literal: true

require "rspec_helper"
require_relative "../initialize/enumerable"

RSpec.specialize "Enumerable" do
  let(:names) { %w[friday saturday sunday] }
  specialize :index_by do
    it "returns a hash when block is given" do
      expect([].index_by(&:nil?)).to be_a_kind_of(Hash)
    end

    it "returns a hash with the expected results" do
      hash = names.index_by(&:length)
      expect(hash.size).to eq 2
      expect(hash[6]).to eq "sunday"
      expect(hash[8]).to eq "saturday"
    end

    it "returns an enumerator when no block given" do
      expect([].index_by).to be_a_kind_of(Enumerator)
    end
  end
end
