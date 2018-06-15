#! /your/favourite/path/to/ruby
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

# Mother of all KDF classes.
#
# Subclasses of this are expected to implement the following 4 class methods:
#
# - `subclass.provide?(id)`
# - `subclass.newhash(pass, id: id, ...)`
# - `subclass.understand?(hash)`
# - `subclass.checkpass?(pass, hash)`
#
# If  a subclass's  `provide?` returns  `true` for  an id,  then that  class is
# responsible for  generating new hash  of that id.  Likewise  if `understand?`
# returns `true` for a hash, that should be able to checkpass.
#
# Caveats:
#
# - You  don't  have  to  provide  all of  those  methods.   It  is  completely
#   reasonable to  have a hash  that is unable to  generate new one,  but still
#   able to check existing ones.
class CryptCheckpass
  @kdfs = [] # see below
end

class << CryptCheckpass
  public

  # @!group API entry points

  # (see ::#crypt_checkpass?)
  def crypt_checkpass? pass, hash
    kdf = find_kdf_by_string hash
    return kdf.checkpass? pass, hash
  end

  # (see ::#crypt_newhash)
  def crypt_newhash password, pref = nil, id: nil, **kwargs
    raise ArgumentError, <<-"end".strip if pref && id
      wrong number of arguments (given 2, expected 1)
    end
    raise ArgumentError, <<-"end".strip, kwargs.keys if pref &&! kwargs.empty?
      unknown key: %p
    end

    if pref then
      require_relative 'bcrypt'
      return CryptCheckpass::Bcrypt.new_with_openbsd_pref password, pref
    else
      kdf = find_kdf_by_id id
      return kdf.newhash password, id: id, **kwargs
    end
  end

  # @!endgroup

  # @!group Inteacts with subclasses

  # Checks if the given ID can be handled by this class.  A class is
  # free to handle several IDs, like 'argon2i', 'argon2d', ...
  #
  # @param id [String] hash function ID.
  # @return   [true]   it does.
  # @return   [false]  it desn't.
  def provide? id
    return false # default false
  end

  # Checks if the given hash string can be handled by this class.
  #
  # @param str [String] a good hashed string.
  # @return    [true]   it does.
  # @return    [false]  it desn't.
  def understand? str
    return false # default false
  end

  # Checks if the given password matches the hash.
  #
  # @param pass [String]              a password to test.
  # @param hash [String]              a good hash digest string.
  # @return     [true]                they are identical.
  # @return     [false]               they are distinct.
  # @raise      [NotImplementedError] don't know how to parse _hash_.
  def checkpass? pass, hash
    return false # default false
  end

  # Generate a new password hash string.
  #
  # @note   There is no way to specify salt.  That's a bad idea.
  # @return [String] hashed digest string of password.
  def newhash *;
    raise 'NOTREACHED'
  end

  private

  undef :new

  # @!group @shyouhei's "angry extension to core" corner

  # Utility raise +  printf function.  It is quite hard  to think of exceptions
  # that only concern  fixed strings.  @shyouhei really  doesn't understand why
  # this is not a canon.
  #
  # @overload raise(klass, fmt, *va_args)
  #   @param klass   [Class]  exception class.
  #   @param fmt     [String] printf-format string.
  #   @param va_args [Array]  anything.
  #   @raise         [klass]  always raises a klass instance.
  #
  # @overload raise(fmt, *va_args)
  #   @param fmt     [String]       printf-format string.
  #   @param va_args [Array]        anything.
  #   @raise         [RuntimeError] always raises a RuntimeError.
  def raise class_or_string, *argv
    case class_or_string
    when Class, Exception then
      klass  = class_or_string
      string = sprintf(*argv)
    when String then
      klass  = RuntimeError
      string = class_or_string % argv
    else # recursion
      raise TypeError, <<-"end".strip
        wrong argument type %p (%p expected)
      end
    end
    return super klass, string, caller
  end

  # Utility gem +  require function.  It is  often the case a library  is a gem
  # and  calling  gem  before  require is  desirable.@shyouhei  really  doesn't
  # understand why this is not a canon.
  #
  # @return      [void]
  # @param gem   [String]         gem name.
  # @param lib   [String]         library name.
  # @raise       [Gem::LoadError] gem not found.
  # @raise       [LoadError]      lib not found.
  def require gem, lib = gem
    Kernel.gem gem
    Kernel.require lib
  end

  if defined? %r/match?/.match? then
    # Fallback routine counterpart.
    # @param re  [Regexp] the language to accept.
    # @param str [String] target string to test.
    # @return    [true]   accepted.
    # @return    [false]  otherwise.
    def match? re, str
      return re.match? str
    end
  else
    # Fallback routine for ruby versions without Regexp#match?
    # @param re  [Regexp] the language to accept.
    # @param str [String] target string to test.
    # @return    [true]   accepted.
    # @return    [false]  otherwise.
    def match? re, str
      md = re.match str
      return !!md
    end
  end

  # @!endgroup

  def inherited klass
    super
    @kdfs.push klass
  end

  def find_kdf_by_id id
    kdf = @kdfs.find {|i| i.provide? id }
    return kdf if kdf
    raise ArgumentError, <<-"end".strip, id
      don't know how to generate %s hash.
    end
  end

  def find_kdf_by_string str
    kdf = @kdfs.find {|i| i.understand? str }
    return kdf if kdf
    raise ArgumentError, <<-"end".strip, str
      don't know how to parse %p, maybe clobbered?
    end
  end
end
