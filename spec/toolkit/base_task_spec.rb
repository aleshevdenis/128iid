# frozen_string_literal: true

require "rspec_helper"

class BaseTaskTestClass < Kenna::128iid::BaseTask
  attr_reader :options

  def self.metadata
    {
      id: "sample",
      name: "Sample",
      description: "Pulls assets and vulnerabilities from Sample",
      options: [
        { name: "sample_api_host",
          type: "hostname",
          required: true,
          default: nil,
          description: "Sample instance hostname, e.g. https://host.example.com:8080" },
        { name: "batch_size",
          type: "integer",
          required: false,
          default: nil,
          description: "Batch Size" },
        { name: "days_back",
          type: "integer",
          required: false,
          default: 10,
          description: "Days Back" },
        { name: "ignore_ssl_errors",
          type: "boolean",
          required: false,
          default: false,
          description: "Ignore SSL Errors" },
        { name: "severity",
          type: "array",
          required: false,
          default: %w[High Medium Low],
          description: "Severity" }
      ]
    }
  end
end

RSpec.specialize BaseTaskTestClass do
  subject(:task_class) { specialized_class }
  it "class exists and and responds to :metadata" do
    expect(task_class.name).to eq("BaseTaskTestClass")
    expect(task_class).to respond_to(:metadata)
  end

  specialize "parameters handling" do
    let(:required_params) { { sample_api_host: "https://sample.com" } }
    let(:task) { task_class.new }

    it "correctly initializes passed string parameter" do
      task.run(required_params)
      expect(task.options[:sample_api_host]).to eq("https://sample.com")
    end

    it "correctly initializes passed positive integer parameter" do
      task.run(required_params.merge({ batch_size: "100" }))
      expect(task.options[:batch_size]).to eq(100)
    end

    it "correctly initializes passed 0 to integer parameter" do
      task.run(required_params.merge({ batch_size: "0" }))
      expect(task.options[:batch_size]).to be_nil
    end

    it "correctly initializes passed positive to integer parameter with default" do
      task.run(required_params.merge({ days_back: "15" }))
      expect(task.options[:days_back]).to eq(15)
    end

    it "correctly initializes passed nil to integer parameter with default" do
      task.run(required_params.merge({ days_back: nil }))
      expect(task.options[:days_back]).to eq(10)
    end

    it "correctly initializes passed 0 to integer parameter with default" do
      task.run(required_params.merge({ days_back: "0" }))
      expect(task.options[:days_back]).to eq(10)
    end

    it "correctly initializes boolean parameters with default values" do
      task.run(required_params.merge({ ignore_ssl_errors: nil }))
      expect(task.options[:ignore_ssl_errors]).to be_falsey
    end

    it "correctly initializes boolean parameters with true boolean" do
      task.run(required_params.merge({ ignore_ssl_errors: "true" }))
      expect(task.options[:ignore_ssl_errors]).to be_a_kind_of(TrueClass)
    end

    it "correctly initializes boolean parameters with false boolean" do
      task.run(required_params.merge({ ignore_ssl_errors: "false" }))
      expect(task.options[:ignore_ssl_errors]).to be_a_kind_of(FalseClass)
    end

    it "correctly initializes array parameter" do
      task.run(required_params.merge({ severity: "high ,  low" }))
      expect(task.options[:severity]).to include("high", "low")
    end

    it "correctly initializes array parameter with defaults" do
      task.run(required_params.merge({ severity: nil }))
      expect(task.options[:severity]).to include("High", "Medium", "Low")
    end
  end
end
