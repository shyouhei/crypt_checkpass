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

require 'securerandom'

# This class is to support RFC7914-related hash variants.
#
# ### Format:
#
# Life gets extremely hard here because Ruby's `scrypt` gem does not follow the
# Modular Crypt Format.  You cannot tell if a string is scrypt-generated or not
# by looking at its beginning.
#
# ```ruby
# %r{
#   (?<N>    [0-9a-f]+ ){0}
#   (?<r>    [0-9a-f]+ ){0}
#   (?<p>    [0-9a-f]+ ){0}
#   (?<salt> [0-9a-f]+ ){0}
#   (?<csum> [0-9a-f]+ ){0}
#
#   \A     \g<N>
#      [$] \g<r>
#      [$] \g<p>
#      [$] \g<salt>
#      [$] \g<csum>
#   \z
# }x
# ```
#
#   - `N` is the CPU/Memory cost parameter N ("costParameter").
#
#   - `r` is the block size parameter r ("blockSize").
#
#   - `p` is the parallelization parameter p ("parallelizationParameter").
#
#   - `salt` is the salt string.
#
#   - `csum` is the checksum string.
#
# All of above fields are represented as hexadecimal numbers.
#
# This is  too different from other  password hashs.  To ease  the situation we
# also follow extra  format that is compatible with Python's  Passlib and npm's
# @phc/scrypt generates.
#
# ```ruby
# %r{
#   (?<id>   scrypt         ){0}
#   (?<ln>   ln=[1-9][0-9]* ){0}
#   (?<r>    r=[1-9][0-9]*  ){0}
#   (?<p>    p=[1-9][0-9]*  ){0}
#   (?<salt> [a-zA-Z0-9+/]* ){0}
#   (?<csum> [a-zA-Z0-9+/]* ){0}
#
#   \A [$] \g<id>
#      [$] \g<ln>
#      [,] \g<r>
#      [,] \g<p>
#      [$] \g<salt>
#      [$] \g<csum>
#   \z
# }x
# ```
#
# - Parameters are `ln`, `r`, and `p` where `ln` deontes log2(N).
#
# ### Other formats:
#
# Seems there are no such thing  like a standard way to encode scrypt-generated
# passwords.  Lots  of wild formats  are seen.  We  could support them  if they
# have actual usage and to be migrated to another format.
#
# - variant  `$7$`: seem in  http://mail.tarsnap.com/scrypt/msg00063.html.  Not
#   sure if it has actual applications.
#
# - variant `$s1$`: https://github.com/technion/libscrypt generates this.
#
# - variant `$$scrypt-mcf$`: the default output of https://libpasta.github.io
#
# - Recent  OpenSSL  (1.1.0+)  does   have  EVP_PBE_scrypt()  implemented,  but
#   generates pure-binary raw checksums without any formats.
#
# @see https://en.wikipedia.org/wiki/Scrypt
# @see https://tools.ietf.org/html/rfc7914
# @see https://blog.ircmaxell.com/2014/03/why-i-dont-recommend-scrypt.html
# @example
#   crypt_newhash 'password', id: 'scrypt'
#   # => "$scrypt$ln=8,r=8,p=1$aL2uvFKrfoVkxAgy1j/Y4OAJ8D0p1yP/uqFg3UU8t64$/xZGQyALLQrKzaBRGwzGCw+FGgRqFwyCfZddC5qvZYA"
# @example
#   crypt_checkpass? 'password', '$scrypt$ln=8,r=8,p=1$aL2uvFKrfoVkxAgy1j/Y4OAJ8D0p1yP/uqFg3UU8t64$/xZGQyALLQrKzaBRGwzGCw+FGgRqFwyCfZddC5qvZYA'
#   # => true

class CryptCheckpass::Scrypt < CryptCheckpass

  # (see CryptCheckpass.understand?)
  def self.understand? str
    return match? str, understander
  end

  # (see CryptCheckpass.checkpass?)
  def self.checkpass? pass, hash
    __require

    case hash
    when /\A\$scrypt\$/ then return checkpass_phc pass, hash
    else                     return checkpass_gem pass, hash
    end
  end

  # (see CryptCheckpass.provide?)
  def self.provide? id
    return id == 'scrypt'
  end

  # (see CryptCheckpass.newhash)
  #
  # @param pass   [String]  raw binary password string.
  # @param id     [String]  name of the algorithm (ignored)
  # @param ln     [Integer] cost parameter in log2.
  # @param r      [Integer] block size.
  # @param p      [Integer] parallelism parameter.
  def self.newhash pass, id: 'scrypt', ln: 8, r: 8, p: 1
    __require

    salt = SecureRandom.random_bytes ::SCrypt::Engine::DEFAULTS[:salt_size]
    klen = ::SCrypt::Engine::DEFAULTS[:key_len]
    csum = ::SCrypt::Engine.scrypt pass, salt, 2 ** ln, r, p, klen
    return phcencode 'scrypt', { ln: ln, r: r, p: p }, salt, csum
  end
end

# helper routines
class << CryptCheckpass::Scrypt
  private

  def checkpass_phc pass, hash
    __require

    json     = phcdecode hash
    ln, r, p = json[:params].values_at("ln", "r", "p").map(&:to_i)
    expected = json[:hash]
    salt     = json[:salt]
    klen     = ::SCrypt::Engine::DEFAULTS[:key_len]
    actual   = ::SCrypt::Engine.scrypt pass, salt, 2 ** ln, r, p, klen
    return consttime_memequal? actual, expected
  end

  def checkpass_gem pass, hash
    obj = ::SCrypt::Password.new hash
    return obj == pass
  end

  def understander
    return %r{
      (?<n1>    [0-9a-f]+          ){0}
      (?<r1>    [0-9a-f]+          ){0}
      (?<p1>    [0-9a-f]+          ){0}
      (?<salt1> [0-9a-f]+          ){0}
      (?<csum1> [0-9a-f]+          ){0}

      (?<id2>   scrypt             ){0}
      (?<ln2>   ln=[1-9][0-9]*     ){0}
      (?<r2>    r=[1-9][0-9]*      ){0}
      (?<p2>    p=[1-9][0-9]*      ){0}
      (?<salt2> [a-zA-Z0-9+/]*     ){0}
      (?<csum2> [a-zA-Z0-9+/]*     ){0}

      \A (?:
             \g<n1>
         [$] \g<r1>
         [$] \g<p1>
         [$] \g<salt1>
         [$] \g<csum1>

      |
         [$] \g<id2>
         [$] \g<ln2>
         [,] \g<r2>
         [,] \g<p2>
         [$] \g<salt2>
         [$] \g<csum2>
      ) \z
    }x
  end

  def __require
    require 'consttime_memequal'
    require 'scrypt'
  end
end
