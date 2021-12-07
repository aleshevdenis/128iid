# frozen_string_literal: true

require_relative "../rspec_helper"

RSpec.specialize "Hash" do
  let(:symbolized_hash) { { monday: 1, tuesday: 2, wednesday: 3, thursday: 4, friday: 5, saturday: 6, sunday: 7, foo: nil, bar: { foo: nil } } }
  let(:stringified_hash) { { "monday": 1, "tuesday": 2, "wednesday": 3, "thursday": 4, "friday": 5, "saturday": 6, "sunday": 7, "foo": nil } }
  specialize :stringify_keys do
    it "returns a copy of the receiver with the keys as String" do
      hash = symbolized_hash.stringify_keys
      expect(hash.keys).to all(be_a(String))
      expect(hash["sunday"]).to eq(7)
      expect(hash[:sunday]).to be_nil
      expect(hash).not_to be(symbolized_hash)
    end
  end

  specialize :symbolize_keys do
    it "returns a copy of the receiver with the keys as Symbol" do
      hash = stringified_hash.symbolize_keys
      expect(hash.keys).to all(be_a(Symbol))
      expect(hash[:sunday]).to eq(7)
      expect(hash["sunday"]).to be_nil
      expect(hash).not_to be(stringified_hash)
    end
  end

  specialize :compact do
    it "returns a copy of the receiver with nil keys removed" do
      hash = symbolized_hash.compact
      expect(symbolized_hash.keys).to include(:foo)
      expect(hash.keys).not_to include(:foo)
      expect(hash).not_to be(symbolized_hash)
    end

    it "returns the receiver with nil keys removed when send with !" do
      expect(symbolized_hash.keys).to include(:foo)
      hash = symbolized_hash.compact!
      expect(hash.keys).not_to include(:foo)
      expect(hash).to be(symbolized_hash)
    end

    it "deep compact is recursive" do
      expect({ foo: { bar: nil } }.deep_compact[:foo]).to be_empty
    end

    it "deep compact! is recursive and mutates" do
      hash = { foo: { bar: nil } }
      expect(hash.deep_compact![:foo]).to be_empty
      expect(hash.deep_compact!).to be(hash)
    end
  end

  specialize :except do
    it "returns a copy of the receiver except the keys passed as argument." do
      original = { foo: 1, bar: 2 }
      hash = original.except(:bar)
      expect(hash[:foo]).to be(1)
      expect(hash[:bar]).to be_nil
      expect(hash.length).to be(1)
      expect(hash).not_to be(original)
    end

    it "returns receiver except the keys passed as argument when used with ! as mutator." do
      original = { foo: 1, bar: 2 }
      hash = original.except!(:bar)
      expect(hash[:foo]).to be(1)
      expect(hash[:bar]).to be_nil
      expect(hash.length).to be(1)
      expect(hash).to be(original)
    end
  end
end
