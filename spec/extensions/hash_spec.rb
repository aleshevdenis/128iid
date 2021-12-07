# frozen_string_literal: true

require_relative "../rspec_helper"

RSpec.specialize "Hash" do
  specialize :deep_compact do
    it "deep compact is recursive" do
      expect({ foo: { bar: nil } }.deep_compact[:foo]).to be_empty
    end

    it "deep compact! is recursive and mutates" do
      hash = { foo: { bar: nil } }
      expect(hash.deep_compact![:foo]).to be_empty
      expect(hash.deep_compact!).to be(hash)
    end
  end
end
