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

        def initialize(external_id_attr = "id", hostname_attr = "name")
          super()
          @external_id_attr = external_id_attr
          @hostname_attr = hostname_attr
        end
      end
    end
  end
end
