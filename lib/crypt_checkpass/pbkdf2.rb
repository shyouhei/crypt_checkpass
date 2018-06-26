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

# PBKDF2 is the most beloved algorithm by security professionals.
#
# ### Newhash:
#
# You can use `crypto_newhash` to create a new password hash using PBKDF2:
#
# ```ruby
# crypt_newhash(password, id: 'pbkdf2-sha1', rounds: 1024)
# ```
#
# where:
#
#   - `password` is the raw binary password that you want to digest.
#
#   - `id`  is "pbkdf2-{digest}".   You can  specify  sha1 /  sha256 /  sha512.
#     Unlike plain SHA1, PBKDF2 + SHA1  combination still has no known weakness
#     as of writing so specifying pbkdf-sha1 should just suffice normally.
#
#   - `rounds` is for iteration rounds.
#
# The generated password hash has following format.
#
# ### Format:
#
# This algorithm does not have a standard hash format.  Here we follow npm's
# @phc/pbkdf2.
#
# ```ruby
# %r{
#   (?<id>   pbkdf2-[\w\d]+ ){0}
#   (?<i>    i=[1-9][0-9]*  ){0}
#   (?<salt> [a-zA-Z0-9+/]* ){0}
#   (?<csum> [a-zA-Z0-9+/]* ){0}
#
#   \A [$] \g<id>
#      [$] \g<i>
#      [$] \g<salt>
#      [$] \g<csum>
#   \z
# }x
# ```
#
# - This is a strict PHC string format. See also
#   {CryptCheckpass::PHCStringFormat}
#
# - The `id` can either be "pbkdf2-sha1", "pbkdf2-sha256", or "pbkdf2-sha512".
#
# - The only parameter `i` is the iteration (rounds) of the calculation.
#
# ### Other formats:
#
# Python Passlib generates something different, in the same `$pbkdf2-{digest}$`
# id.  Passlib's and @phc/pbkdf2's are distinguishable because Passlib does not
# follow PHC String Format.
#
# @see https://en.wikipedia.org/wiki/PBKDF2
# @see https://tools.ietf.org/html/rfc2898
# @example
#   crypt_newhash 'password', id: 'pbkdf2-sha1'
#   # => "$pbkdf2-sha1$i=1024$a9b0ggwILmLgiAwV34bpzA$nJ+GYjlNDao8BJedGVc8UROXpcU"
# @example
#   crypt_checkpass? 'password', '$pbkdf2-sha1$i=1024$a9b0ggwILmLgiAwV34bpzA$nJ+GYjlNDao8BJedGVc8UROXpcU'
#   # => true
class CryptCheckpass::PBKDF2 < CryptCheckpass

  # (see CryptCheckpass.understand?)
  def self.understand? str
    return match? str, %r{
      (?<id>   pbkdf2-sha(1|256|512) ){0}
      (?<i>    i=[1-9][0-9]*         ){0}
      (?<salt> [a-zA-Z0-9+/]*        ){0}
      (?<csum> [a-zA-Z0-9+/]*        ){0}

      \A [$] \g<id>
         [$] \g<i>
         [$] \g<salt>
         [$] \g<csum>
      \z
    }x
  end

  # (see CryptCheckpass.checkpass?)
  def self.checkpass? pass, hash
    require 'consttime_memequal'

    json     = phcdecode hash
    id       = json[:id]
    i        = json[:params]['i'].to_i
    salt     = json[:salt]
    expected = json[:hash]
    dklen    = expected.bytesize
    actual   = __derive_key id, i, salt, pass, dklen

    return consttime_memequal? expected, actual
  end

  # (see CryptCheckpass.provide?)
  def self.provide? id
    case id when 'pbkdf2-sha1', 'pbkdf2-sha256', 'pbkdf2-sha512' then
      return true
    else
      return false
    end
  end

  # (see CryptCheckpass.newhash)
  #
  # @param pass   [String]  raw binary password string.
  # @param id     [String]  name of the algorithm
  # @param rounds [Integer] iteration rounds
  def self.newhash pass, id: 'pbkdf2-sha1', rounds: 1024
    salt = SecureRandom.random_bytes 16
    csum = __derive_key id, rounds, salt, pass
    return phcencode id, { i: rounds }, salt, csum
  end
end

# helper routines
class << CryptCheckpass::PBKDF2
  private

  if RUBY_VERSION >= '2.3.0'
    def __load_openssl
      require 'openssl'
    end
  else
    def __load_openssl
      Kernel.require 'openssl'
    end
  end

  def __default_dklen_for digest
    case digest
    when 'pbkdf2-sha1'   then return 20, 'sha1'
    when 'pbkdf2-sha256' then return 32, 'sha256'
    when 'pbkdf2-sha512' then return 64, 'sha512'
    else raise "NOTREACHED: %s", id
    end
  end

  def __derive_key id, iter, salt, pass, dklen = nil
    __load_openssl

    n, d    = __default_dklen_for id
    dklen ||= n
    return OpenSSL::PKCS5.pbkdf2_hmac pass, salt, iter, dklen, d
  end
end
