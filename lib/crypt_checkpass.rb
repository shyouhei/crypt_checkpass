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

# Parses what the  given _hash_ is, apply the same  hasing against _pass_, then
# compares the hashed _pass_ and the given _hash_.
#
# @param pass [String]              password string.
# @param hash [String]              hashed string.
# @return     [true]                they are identical.
# @return     [false]               they are distinct.
# @raise      [NotImplementedError] don't know how to parse _hash_.
def crypt_checkpass? pass, hash
  return CryptCheckpass::crypt_checkpass? pass, hash
end

# Generates new password hashes. The provided password is randomly salted, then
# hashed using the parameter.
#
# @overload crypt_newhash(password, perf)
#   The  pref   argument  identifies   the  preferred  hashing   algorithm  and
#   parameters. Possible values are:
#
#   - `"bcrypt,<rounds>"`
#   - `"blowfish,<rounds>"`
#
#   where "rounds" can be a number between 4 and 31, or "a" for default.
#
#   @note                    This usage is for OpenBSD fans.
#   @see   https://man.openbsd.org/crypt_newhash.3 crypt_newhash(3)
#   @param password [String]              bare, unhashed binary password.
#   @param pref     [String]              algorithm preference specifier.
#   @raise          [NotImplementedError] pref not understandable.
#   @return         [String]              hashed digest string of password.
#
# @overload crypt_newhash(password, id:, **kwargs)
#   At least `:id`  argument must be provided  this case, which is  the name of
#   key deliveration function (the ID that the PHC string format says).
#
#   @param password [String]                 bare, unhashed binary password.
#   @param id       [String]                 name of the function.
#   @param kwargs   [Symbol=>String,Integer] passed to the KDF.
#   @return         [String]                 hashed digest string of password.
#   @raise          [NotImplementedError]    unknown KDF is specified.
def crypt_newhash password, pref = nil, id: nil, **kwargs
  return CryptCheckpass::crypt_newhash password, pref, id: id, **kwargs
end

require_relative 'crypt_checkpass/api'
require_relative 'crypt_checkpass/argon2'
require_relative 'crypt_checkpass/bcrypt'
require_relative 'crypt_checkpass/pbkdf2'
require_relative 'crypt_checkpass/scrypt'
require_relative 'crypt_checkpass/sha2'
