# -*- encoding: utf-8 -*-
# stub: jekyll-theme-clean-blog 4.0.10 ruby lib

Gem::Specification.new do |s|
  s.name = "jekyll-theme-clean-blog".freeze
  s.version = "4.0.10"

  s.required_rubygems_version = Gem::Requirement.new(">= 0".freeze) if s.respond_to? :required_rubygems_version=
  s.require_paths = ["lib".freeze]
  s.authors = ["Start Bootstrap".freeze]
  s.date = "2020-06-18"
  s.email = ["feedback@startbootstrap.com".freeze]
  s.homepage = "https://github.com/StartBootstrap/startbootstrap-clean-blog-jekyll".freeze
  s.licenses = ["MIT".freeze]
  s.rubygems_version = "2.7.6.2".freeze
  s.summary = "A simple blog theme based on Bootstrap 4 by Start Bootstrap.".freeze

  s.installed_by_version = "2.7.6.2" if s.respond_to? :installed_by_version

  if s.respond_to? :specification_version then
    s.specification_version = 4

    if Gem::Version.new(Gem::VERSION) >= Gem::Version.new('1.2.0') then
      s.add_runtime_dependency(%q<jekyll>.freeze, [">= 3.8.5"])
      s.add_development_dependency(%q<bundler>.freeze, ["~> 2.0.1"])
      s.add_development_dependency(%q<rake>.freeze, ["~> 12.0"])
    else
      s.add_dependency(%q<jekyll>.freeze, [">= 3.8.5"])
      s.add_dependency(%q<bundler>.freeze, ["~> 2.0.1"])
      s.add_dependency(%q<rake>.freeze, ["~> 12.0"])
    end
  else
    s.add_dependency(%q<jekyll>.freeze, [">= 3.8.5"])
    s.add_dependency(%q<bundler>.freeze, ["~> 2.0.1"])
    s.add_dependency(%q<rake>.freeze, ["~> 12.0"])
  end
end
