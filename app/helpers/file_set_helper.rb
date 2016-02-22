# -*- coding: utf-8 -*-
module FileSetHelper
  def display_title(fs)
    fs.to_s
  end

  def present_terms(presenter, terms = :all, &block)
    terms = presenter.terms if terms == :all
    Sufia::PresenterRenderer.new(presenter, self).fields(terms, &block)
  end

  def display_multiple(value)
    return if value.nil?
    auto_link(html_escape(value.join(" | ")))
  end

  private

  def render_visibility_badge(presenter)
    # if can? :edit, presenter.solr_document
    #   render_visibility_link presenter.solr_document
    # else
      render_visibility_label presenter.solr_document
    # end
  end
end
