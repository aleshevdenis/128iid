# frozen_string_literal: true

class Object
  def blank?
    false
  end

  def present?
    !blank?
  end
end

class NilClass
  def blank?
    true
  end
end

class String
  def blank?
    empty?
  end
end

class FalseClass
  def blank?
    true
  end
end
