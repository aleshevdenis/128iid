# frozen_string_literal: true

module Kenna
  module 128iid
    module Wiz
      class Mapper
        SCANNER_TYPE = "Wiz"
        SEVERITY_MAP = {
          "info" => 0,
          "low" => 3,
          "medium" => 6,
          "high" => 8,
          "critical" => 10
        }.freeze
      end
    end
  end
end
