#! /your/favourite/path/to/gem
# -*- mode: ruby; coding: utf-8; indent-tabs-mode: nil; ruby-indent-level: 2 -*-
# -*- frozen_string_literal: true -*-
# -*- warn_indent: true -*-

# Copyright (c) 2018 Urabe, Shyouhei
#
# Permission is hereby granted, free of  charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction,  including without limitation the rights
# to use,  copy, modify,  merge, publish,  distribute, sublicense,  and/or sell
# copies  of the  Software,  and to  permit  persons to  whom  the Software  is
# furnished to do so, subject to the following conditions:
#
#       The above copyright notice and this permission notice shall be
#       included in all copies or substantial portions of the Software.
#
# THE SOFTWARE  IS PROVIDED "AS IS",  WITHOUT WARRANTY OF ANY  KIND, EXPRESS OR
# IMPLIED,  INCLUDING BUT  NOT LIMITED  TO THE  WARRANTIES OF  MERCHANTABILITY,
# FITNESS FOR A  PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO  EVENT SHALL THE
# AUTHORS  OR COPYRIGHT  HOLDERS  BE LIABLE  FOR ANY  CLAIM,  DAMAGES OR  OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

Gem::Specification.new do |spec|
  spec.name          = 'crypt_checkpass'
  spec.version       = 2
  spec.author        = 'Urabe, Shyouhei'
  spec.email         = 'shyouhei@ruby-lang.org'
  spec.summary       = 'provides crypt_checkpass / crypt_newhash'
  spec.description   = <<-"end".gsub(/\s+/, ' ').strip
    Check password hash, like OpenBSD's crypt_checkpass(3) / PHP's
    password_verify()
  end
  spec.homepage      = 'https://github.com/shyouhei/crypt_checkpass'
  spec.license       = 'MIT'
  spec.files         = `git ls-files -z`.split("\x0").reject { |f|
    f.match(%r'^(test|spec|features|samples)/')
  }
  spec.require_paths = %w'lib'

  spec.add_development_dependency 'bundler'
  spec.add_development_dependency 'pry-byebug'
  spec.add_development_dependency 'rake'
  spec.add_development_dependency 'rdoc'
  spec.add_development_dependency 'redcarpet'
  spec.add_development_dependency 'rubocop', '~> 0.49.0' # support for 2.0
  spec.add_development_dependency 'simplecov'
# spec.add_development_dependency 'stackprof' # needs ruby 2.1+
  spec.add_development_dependency 'test-unit', '>= 3'
  spec.add_development_dependency 'yard'
  spec.required_ruby_version =    '>= 2.0.0'
  spec.add_runtime_dependency     'consttime_memequal'
  spec.add_runtime_dependency     'phc_string_format'
end
