module Umrdr
  module GenericWorkBehavior
    extend ActiveSupport::Concern

    # Dirty dirty trick to ensure all have 'open' visibility.
    # Can leave all the rest of the Sufia machinery in place.
    def visibility=(value)
      super('open')
    end

  end
end
