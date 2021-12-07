# frozen_string_literal: true

require_relative "../rspec_helper"

RSpec.specialize "BaseExtensions" do
  specialize :blank? do
    it "returns false for Object" do
      expect(Object.new.blank?).to be_falsey
    end

    it "returns true on empty strings" do
      expect("".blank?).to be_truthy
    end

    it "returns true on nil" do
      expect(nil.blank?).to be_truthy
    end

    it "returns false on number" do
      expect(0.blank?).to be_falsey
    end

    it "returns true on false" do
      expect(false.blank?).to be_truthy
    end

    it "returns false on true" do
      expect(true.blank?).to be_falsey
    end
  end

  specialize :present? do
    it "returns true for Object" do
      expect(Object.new.present?).to be_truthy
    end

    it "returns false on empty strings" do
      expect("".present?).to be_falsey
    end

    it "returns false on nil" do
      expect(nil.present?).to be_falsey
    end

    it "returns true on number" do
      expect(0.present?).to be_truthy
    end

    it "returns false on false" do
      expect(false.present?).to be_falsey
    end

    it "returns true on true" do
      expect(true.present?).to be_truthy
    end
  end
end
