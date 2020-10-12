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


# BCrypt is a  blowfish based password hash function.  BSD  devs and users tend
# to love  this function.  As  of writing this is  the only hash  function that
# OpenBSD's crypt(3) understands.   Also, because `ActiveModel::SecurePassword`
# is backended by this algorithm, Ruby on Rails users tends to use it.
#
# ### Newhash:
#
# In addition to  the OpenBSD-ish usage described in  {file:README.md}, you can
# also use `crypto_newhash` to create a new password hash using bcrypt:
#
# ```ruby
# crypt_newhash(password, id: 'bcrypt', rounds: 4, ident: '2b')
# ```
#
# where:
#
#   - `password` is the raw binary password that you want to digest.
#
#   - `id` is "bcrypt" when you want a bcrypt hash.
#
#   - `rounds` is an integer ranging 4 to  31 inclusive, which is the number of
#     iterations.
#
#   - `ident` is  the name  of the  variant. Variants  of bcrypt  are described
#     below.  Note  however that what  we don't  support old variants  that are
#     known to be  problematic.  This parameter changes the name  of the output
#     but not the contents.
#
# The generated password hash has following format.
#
# ### Format:
#
# A bcrypt hashed string has following structure:
#
# ```ruby
# %r{
#   (?<id>     [2] [abxy]?       ){0}
#   (?<cost>   [0-9]{2}          ){0}
#   (?<salt>   [A-Za-z0-9./]{22} ){0}
#   (?<csum>   [A-Za-z0-9./]{31} ){0}
#
#   \A [$] \g<id>
#      [$] \g<cost>
#      [$] \g<salt>
#          \g<csum>
#   \z
# }x
# ```
#
#   - `id` is 2-something that denotes the variant of the hash. See below.
#
#   - `cost`  is  a  zero-padded  decimal  integer  that  specifies  number  of
#     iterations in logs,
#
#   - `salt` and `csum` are the salt and checksum strings.  Both are encoded in
#     base64-like strings  that do  not strictly follow  RFC4648.  There  is no
#     separating `$` sign  is between them so you have  to count the characters
#     to  tell which  is  which.   Also, because  they  are  base64, there  are
#     "unused" bits at the end of each.
#
# ### Variants:
#
# According to Wikipedia entry, there are 5 variants of bcrypt output:
#
#   - Variant `$2$`:  This was the initial  version.  It did not  take Unicodes
#     into account.  Not currently active.
#
#   - Variant  `$2a$`:  Unicode problem  fixed,  but  suffered wraparound  bug.
#     OpenBSD people decided to abandon this  to move to `$2b$`.  Also suffered
#     CVE-2011-2483.  The people behind that CVE requested sysadmins to replace
#     their `$2a$`  with `$2x`, indicating  the data is broken.   Not currently
#     active.
#
#   - Variant `$2b$`: updated algorithm to fix wraparound bug.  Now active.
#
#   - Variant `$2x$`: see above.  No new password hash shall generate this one.
#
#   - Variant `$2y$`: updated algorithm to fix CVE-2011-2483.  Now active.
#
# ### Fun facts:
#
#   - It is by spec that the algorithm ignores password longer than 72 octets.
#
#   - According to Python Passlib, variant  `$2b$` and `$2y$` are "identical in
#     all but name."
#
#   - Rails (bcrypt-ruby) reportedly uses `$2a$` even today.  However they seem
#     fixed  known  flaws by  themselves,  without  changing names.   So  their
#     algorithm  is arguably  safe.  Maybe  this can  be seen  as a  synonym of
#     `$2b$` / `$2y`.
#
# @see https://en.wikipedia.org/wiki/Bcrypt
# @see https://www.usenix.org/legacy/event/usenix99/provos/provos_html/
# @example
#   crypt_newhash 'password', id: 'bcrypt'
#   # => "$2b$10$JlxIYWbT2EUDNvIwrIYcxuKf8pzf58IV4xVWk9yPy5J/ni0LCmz7G"
# @example
#   crypt_checkpass? 'password', '$2b$10$JlxIYWbT2EUDNvIwrIYcxuKf8pzf58IV4xVWk9yPy5J/ni0LCmz7G'
#   # => true

class CryptCheckpass::Bcrypt < CryptCheckpass

  # (see CryptCheckpass.understand?)
  def self.understand? str
    return match? str, %r{
      (?<id>     [2] [abxy]?       ){0}
      (?<cost>   [0-9]{2}          ){0}
      (?<remain> [A-Za-z0-9./]{53} ){0}
      \A [$] \g<id>
         [$] \g<cost>
         [$] \g<remain>
      \z
    }x
  end

  # (see CryptCheckpass.checkpass?)
  def self.checkpass? pass, hash
    __require

    obj      = BCrypt::Password.new hash
    actual   = BCrypt::Engine.hash_secret pass, obj.salt
    return consttime_memequal? hash, actual.b.to_str
  end

  # (see CryptCheckpass.provide?)
  def self.provide? id
    return id == 'bcrypt'
  end

  # (see CryptCheckpass.newhash)
  #
  # @param pass   [String]  raw binary password string.
  # @param id     [String]  name of the algorithm (ignored)
  # @param rounds [Integer] 4 to 31, inclusive.
  # @param ident  [String]  "2b" or "2y" or something like that.
  def self.newhash pass, id: 'bcrypt', rounds: nil, ident: '2b'
    __require
    len = pass.bytesize
    raise ArgumentError, <<-"end", len if len > 72
      password is %d bytes, which is too long (up to 72)
    end

    rounds ||= BCrypt::Engine::DEFAULT_COST
    case rounds when 4..31 then
      return __generate pass, rounds, ident
    else
      raise ArgumentError, <<-"end", rounds
        integer %d out of range of (4..31)
      end
    end
  end

  # This is to implement OpenBSD-style `crypt_newhash()` function.
  #
  # @param pass [String]              bare, unhashed binary password.
  # @param pref [String]              algorithm preference specifier.
  # @return     [String]              hashed digest string of password.
  # @raise      [NotImplementedError] pref not understandable.
  # @see https://github.com/libressl-portable/openbsd/blob/master/src/lib/libc/crypt/cryptutil.c
  def self.new_with_openbsd_pref pass, pref
    require 'bcrypt'

    func, rounds = pref.split ',', 2
    unless match? func, /\A(bcrypt|blowfish)\z/ then
      raise NotImplementedError, <<-"end".strip, func
        hash algorithm %p not supported right now.
      end
    end

    cost = nil
    case rounds
    when NilClass                      then cost = BCrypt::Engine::DEFAULT_COST
    when "a"                           then cost = BCrypt::Engine::DEFAULT_COST
    when /\A([12][0-9]|3[01]|[4-9])\z/ then cost = rounds.to_i
    else
      raise NotImplementedError, <<-"end".strip, rounds
        cost function %p not supported right now.
      end
    end
    return __generate pass, cost, '2b'
  end

  def self.__generate pass, cost, ident
    salt = BCrypt::Engine.generate_salt(cost)
    ret  = BCrypt::Engine.hash_secret pass, salt
    return ret.sub %r/\A\$2.?\$/, "$#{ident}$"
  end
  private_class_method :__generate

  def self.__require
    require 'consttime_memequal'
    require 'bcrypt', 'bcrypt', '>= 3.1.13'
  end
  private_class_method :__require
end
