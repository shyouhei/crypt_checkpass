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

# Argon2 the Password Hashing Competition winner.
#
# ### Newhash:
#
# You can use `crypto_newhash` to create a new password hash using argon2:
#
# ```ruby
# crypt_newhash(password, id: 'argon2i', m_cost: 12, t_cost: 3)
# ```
#
# where:
#
#   - `password` is the raw binary password that you want to digest.
#
#   - `id`  is "argon2i"  when  you want  an argon2  hash.   Due to  underlying
#     ruby-argon2 gem's restriction we do not support other argon2 variants.
#
#   - `m_cost` and `t_cost` are both integer parameter to the algorithm.
#
# The generated password hash has following format.
#
# ### Format:
#
# Argon2  specifies its  hash structure  in detail  named "PHC  String Format",
# **then ignored  the format  by itself**.  See  also [1].   Empirical findings
# show that the algorithm now has the following output format:
#
# ```ruby
# %r{
#   (?<digits> 0|[1-9]\d*      ){0}
#   (?<b64>    [a-zA-Z0-9+/]   ){0}
#   (?<id>     argon2 (i|d|id) ){0}
#   (?<v>      v=19            ){0}
#   (?<m>      m=\g<digits>    ){0}
#   (?<t>      t=\g<digits>    ){0}
#   (?<p>      p=\g<digits>    ){0}
#   (?<salt>   \g<b64>+        ){0}
#   (?<csum>   \g<b64>+        ){0}
#
#   \A     [$] \g<id>
#      (?: [$] \g<v> )?
#          [$] \g<m>
#          [,] \g<t>
#          [,] \g<p>
#          [$] \g<salt>
#          [$] \g<csum>
#   \z
# }x
# ```
#
#   - `id`  is   "argon2"  +  something   that  denotes  the  variant   of  the
#     hash. Variant "argon2i" seems most widely adopted.
#
#   - `v` is, when  available, a number 19.  That doesn't  mean anything.  What
#     is important is the _absence_ of that parameter, which means the hash was
#     generated using old argon2 1.0 and shall be out of date.
#
#   - `m` is the  amount of memory filled by the  algorithm (2**m KiB).  Memory
#     consumption depends on this parameter.
#
#   - `t` is  the number of passes  over the memory.  The  running time depends
#     linearly on this parameter.
#
#   - `p` is the degree of parallelism, called "lanes" in the C implementation.
#
#   - `salt` and `csum` are the salt and checksum strings.  Both are encoded in
#     base64-like strings that  do not strictly follow RFC4648.   They both can
#     be arbitrary length.  In case there are "unused" bits at the end of those
#     fields, they shall be zero-filled.
#
# [1]: https://github.com/P-H-C/phc-winner-argon2/issues/157
#
# ### Implementation limitations:
#
# Ruby binding of argon2 library (ruby-argon2)  is pretty well designed and can
# be recommended for  daily uses.  You really should use  it whenever possible.
# The  big  problem  is  however,  that it  only  supports  argon2i.   That  is
# definitely OK for hash generation.  However  in verifying, it is desirable to
# support other variants.
#
# In order to reroute this problem we load the ruby-argon2 gem, then ignore its
# ruby part and directly call the canonical C implementation via FFI.
#
# @see https://en.wikipedia.org/wiki/Argon2
# @see https://www.cryptolux.org/index.php/Argon2
# @example
#   crypt_newhash 'password', id: 'argon2i'
#   # => "$argon2i$v=19$m=4096,t=3,p=1$b9AqucWUJADOdNMW8fW+0A$s3+Yno9+X7rpA2AsaG7KnoBtjQiE+AUevLvT7u1lXeA"
# @example
#   crypt_checkpass? 'password', '$argon2i$v=19$m=4096,t=3,p=1$b9AqucWUJADOdNMW8fW+0A$s3+Yno9+X7rpA2AsaG7KnoBtjQiE+AUevLvT7u1lXeA'
#   # => true
class CryptCheckpass::Argon2 < CryptCheckpass

  # (see CryptCheckpass.understand?)
  def self.understand? str
    return match? str, %r{
      (?<id>     argon2 (i|d|id) ){0}
      (?<digits> 0|[1-9]\d*      ){0}
      (?<b64>    [a-zA-Z0-9+/]   ){0}
      (?<v>      v=19            ){0}
      (?<m>      m=\g<digits>    ){0}
      (?<t>      t=\g<digits>    ){0}
      (?<p>      p=\g<digits>    ){0}
      (?<salt>   \g<b64>+        ){0}
      (?<csum>   \g<b64>+        ){0}

      \A     [$] \g<id>
         (?: [$] \g<v> )?
             [$] \g<m>
             [,] \g<t>
             [,] \g<p>
             [$] \g<salt>
             [$] \g<csum>
      \z
    }x
  end

  # (see CryptCheckpass.checkpass?)
  def self.checkpass? pass, hash
    h = hash
    p = pass
    n = pass.bytesize

    __load_argon2_dll

    case hash
    when /\A\$argon2i\$/  then ret = @dll.argon2i_verify  h, p, n
    when /\A\$argon2d\$/  then ret = @dll.argon2d_verify  h, p, n
    when /\A\$argon2id\$/ then ret = @dll.argon2id_verify h, p, n
    else raise ArgumentError, "unknown hash format %p", hash
    end

    case ret
    when 0   then return true
    when -35 then return false # ARGON2_VERIFY_MISMATCH
    else
      errstr = ::Argon2::ERRORS[ret.abs] || ret.to_s
      raise ::Argon2::ArgonHashFail, "got %s", errstr
    end
  end

  # (see CryptCheckpass.provide?)
  # @note we don't support generating argon2d hashs.
  def self.provide? id
    return id == 'argon2i'
  end

  # (see CryptCheckpass.newhash)
  #
  # @param pass   [String]  raw binary password string.
  # @param id     [String]  name of the algorithm (ignored)
  # @param m_cost [Integer] argon2 memory usage (2^m KiB)
  # @param t_cost [Integer] argon2 iterations.
  def self.newhash pass, id: 'argon2i', m_cost: 12, t_cost: 3
    require 'argon2'

    argon2 = ::Argon2::Password.new m_cost: m_cost, t_cost: t_cost
    return argon2.create pass
  end

  @m = Thread::Mutex.new

  def self.__load_argon2_dll
    @m.synchronize do
      next if defined? @dll
      require 'argon2'
      @dll = Module.new do
        extend FFI::Library
        lib = FFI::Compiler::Loader.find 'argon2_wrap'
        fun = %i[argon2i_verify argon2d_verify argon2id_verify]
        ffi_lib lib
        fun.each do |f|
          attach_function f, %i[pointer pointer size_t], :int, blocking: true
        end
      end
    end
  end
  private_class_method :__load_argon2_dll
end
