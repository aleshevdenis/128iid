# frozen_string_literal: true

class String
  def sanitize_unicode
    encode("UTF-8", {
             undef: :replace,
             invalid: :replace,
             replace: "?"
           }).delete("\u0000")
  end

  def to_string_identifier
    tr!(".", "_")
    tr!("~", "_")
    tr!("/", "_")
    tr!("\\", "_")
    tr!("+", "_")
    tr!("-", "_")
    downcase
  end
end
