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

# Helper module to handle PHC String Format-compatible strings
#
# @note Argon2, which  is the winner of  PHC, ignores this format  and go wild.
#       It is  highly skeptical  that any  other hash  authors would  switch to
#       PHC's recommendation.
#
# ### Format
#
# This is how we understand the PHC String Format:
#
# ```ruby
# %r{
#   (?<name>    [a-z0-9-]{,32}              ){0}
#   (?<decimal> 0|-?[1-9][0-9]*             ){0}
#   (?<b64>     [a-zA-Z0-9/+.-]*            ){0}
#
#   (?<id>      \g<name>                    ){0}
#   (?<param>   \g<name>                    ){0}
#   (?<value>   \g<decimal> | \g<b64>       ){0}
#   (?<salt>    \g<b64>                     ){0}
#   (?<csum>    \g<b64>                     ){0}
#   (?<pair>    \g<param> = \g<value>       ){0}
#   (?<pairs>   \g<pair> (?:[,] \g<pair> )* ){0}
#
#   \A [$] \g<id>
#      [$] \g<pairs>
#      [$] \g<salt>
#      [$] \g<csum>
#   \z
# }x
# ```
# 
#   - `id` is the name of the algorithm.
#
#   - `pairs` is a set of key-value pair, that are parameters to the
#      algorithm.  Keys should be human-readable, while values need not be.
#
#   - `salt` and `csum` are the salt and checksum strings.  Both are encoded in
#     what the spec says the "B64"  encoding, which is a very slightly modified
#     version  of  RFC4648 (no  trailing  ==...  padding).   They both  can  be
#     arbitrary length.
#
# @see https://github.com/P-H-C/phc-string-format/blob/master/phc-sf-spec.md
module CryptCheckpass::PHCStringFormat
  private

  # B64 encoder
  # @param str [String] arbitrary binary string.
  # @return    [String] str, encoded in B64.
  def b64encode str
    var = [ str ].pack 'm0'
    var.delete! '='
    return var
  end

  if RUBY_VERSION >= '2.4.0' then
    def malloc n
      String.new capacity: n
    end
  else
    def malloc n
      String.new
    end
  end

  # B64 decoder
  # @param str [String]        str, encoded in B64.
  # @return    [String]        decoded binary string
  # @raise     [ArgumentError] str not in B64 encoding.
  def b64decode str
    return nil if str.nil? 
    n, m = str.length.divmod 4
    raise ArgumentError, <<-"end".strip, str.length if m == 1
      malformed string of %d octets passed.
    end
    buf = malloc(n * 4)
    buf << str
    buf << ('=' * ((4 - m) % 4))
    return buf.unpack('m0').first
  end

  # Form a PHC String Formatted string.
  # @return        [String]              a PHC String Formatted string.
  # @param  id     [String]              name of hash algorithm.
  # @param  params [<<String, Integer>>] hash algorithm parameters.
  # @param  salt   [String]              raw binary salt.
  # @param  csum   [String]              raw binary checksum
  # @note   The spec says:
  #
  #         > The  function MUST  specify  the order  in  which parameters  may
  #         > appear.  Producers MUST  NOT allow  parameters to  appear in  any
  #         > other order.
  #
  #         Ensuring that property is up to the caller of this method.
  def phcencode id, params, salt, csum
    return [
      '',
      id,
      params.map {|a| a.join '=' }.join(','),
      b64encode(salt),
      b64encode(csum)
    ].join('$')
  end

  # Decompose a PHC String Formatted string.
  # @param str [String]        str, encoded in PHC's format.
  # @return    [Hash]          decoded JSON.
  def phcdecode str
    grammar = %r{
      (?<name>    [a-z0-9-]{,32}              ){0}
      (?<decimal> 0|-?[1-9][0-9]*             ){0}
      (?<b64>     [a-zA-Z0-9/+.-]*            ){0}

      (?<id>      \g<name>                    ){0}
      (?<param>   \g<name>                    ){0}
      (?<value>   \g<decimal> | \g<b64>       ){0}
      (?<salt>    \g<b64>                     ){0}
      (?<csum>    \g<b64>                     ){0}
      (?<pair>    \g<param> = \g<value>       ){0}
      (?<pairs>   \g<pair> (?:[,] \g<pair> )* ){0}
    }x

    md = %r{
      #{grammar}

      \A [$] \g<id>
         [$] \g<pairs>
         [$] \g<salt>
         [$] \g<csum>
      \z
    }xo.match str
    raise "not in PHC String Format: %p", str unless md

    return {
      id:     md['id'],
      params: md['pairs']     \
              . split(',', -1) \
              . map {|i|
                  m = /#{grammar}\A\g<pair>\z/o.match i
                  next [
                    m['param'],
                    m['decimal'] ? m['decimal'].to_i : m['b64']
                  ]
              }.each_with_object({}) {|(k, v), h|
                  h.update(k.to_s.to_sym => v) { |_, w, _|
                    raise <<-"end".strip, md['params'], k, v, w
                      %p includes conflicting values for %p: %p versus %p
                    end
                  }
              }, 
      salt:   b64decode(md['salt']),
      csum:   b64decode(md['csum']),
    }
  end
end
