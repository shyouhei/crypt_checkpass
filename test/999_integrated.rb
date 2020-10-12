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

require_relative 'test_helper'

# Note: view this file using a large display equipment.

class TC999_Integrated < Test::Unit::TestCase
  # from: https://bitbucket.org/ecollins/passlib/src/849ab1e6b5d4ace4c727a63d4adec928d6d72c13/passlib/tests/test_handlers.py
  UPASS_WAV       = '\u0399\u03c9\u03b1\u03bd\u03bd\u03b7\u03c2'
  UPASS_USD       = "\u20AC\u00A5$"
  UPASS_TABLE     = "t\u00e1\u0411\u2113\u0259"
  PASS_TABLE_UTF8 = "t\xc3\xa1\xd0\x91\xe2\x84\x93\xc9\x99".b # utf-8

  sub_test_case 'crypt_checkpass?' do
    vector = [
      #  --------
      # from: http://cvsweb.openwall.com/cgi/cvsweb.cgi/Owl/packages/glibc/crypt_blowfish/wrapper.c

      # Some $2a$ tests are commented out because bcrypt-ruby generates what is
      # identical to $2y$ for them (which is safe).

      ["$2a$05$CCCCCCCCCCCCCCCCCCCCC.E5YPO9kmyuRGyh0XouQYb4YMJKvyOeW", "U*U"],
      ["$2a$05$CCCCCCCCCCCCCCCCCCCCC.VGOzA784oUp/Z0DY336zx7pLYAy0lwK", "U*U*"],
      ["$2a$05$XXXXXXXXXXXXXXXXXXXXXOAcXxm9kjPGEMsLznoKqmqw7tc8WCx4a", "U*U*U"],
      ["$2a$05$abcdefghijklmnopqrstuu5s2v8.iXieOjg/.AySBTTZIIVFJeBui",
       "0123456789abcdefghijklmnopqrstuvwxyz" \
       "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789" \
       "chars after 72 are ignored"],
      ["$2x$05$/OK.fbVrR/bpIqNJ5ianF.CE5elHaaO4EbggVDjb8P19RukzXSM3e", "\xa3"],
      ["$2x$05$/OK.fbVrR/bpIqNJ5ianF.CE5elHaaO4EbggVDjb8P19RukzXSM3e", "\xff\xff\xa3"],
      ["$2y$05$/OK.fbVrR/bpIqNJ5ianF.CE5elHaaO4EbggVDjb8P19RukzXSM3e", "\xff\xff\xa3"],
#     ["$2a$05$/OK.fbVrR/bpIqNJ5ianF.nqd1wy.pTMdcvrRWxyiGL2eMz.2a85.", "\xff\xff\xa3"],
      ["$2b$05$/OK.fbVrR/bpIqNJ5ianF.CE5elHaaO4EbggVDjb8P19RukzXSM3e", "\xff\xff\xa3"],
      ["$2y$05$/OK.fbVrR/bpIqNJ5ianF.Sa7shbm4.OzKpvFnX1pQLmQW96oUlCq", "\xa3"],
      ["$2a$05$/OK.fbVrR/bpIqNJ5ianF.Sa7shbm4.OzKpvFnX1pQLmQW96oUlCq", "\xa3"],
      ["$2b$05$/OK.fbVrR/bpIqNJ5ianF.Sa7shbm4.OzKpvFnX1pQLmQW96oUlCq", "\xa3"],
      ["$2x$05$/OK.fbVrR/bpIqNJ5ianF.o./n25XVfn6oAPaUvHe.Csk4zRfsYPi", "1\xa3" "345"],
      ["$2x$05$/OK.fbVrR/bpIqNJ5ianF.o./n25XVfn6oAPaUvHe.Csk4zRfsYPi", "\xff\xa3" "345"],
      ["$2x$05$/OK.fbVrR/bpIqNJ5ianF.o./n25XVfn6oAPaUvHe.Csk4zRfsYPi", "\xff\xa3" "34" "\xff\xff\xff\xa3" "345"],
      ["$2y$05$/OK.fbVrR/bpIqNJ5ianF.o./n25XVfn6oAPaUvHe.Csk4zRfsYPi", "\xff\xa3" "34" "\xff\xff\xff\xa3" "345"],
#     ["$2a$05$/OK.fbVrR/bpIqNJ5ianF.ZC1JEJ8Z4gPfpe1JOr/oyPXTWl9EFd.", "\xff\xa3" "34" "\xff\xff\xff\xa3" "345"],
      ["$2y$05$/OK.fbVrR/bpIqNJ5ianF.nRht2l/HRhr6zmCp9vYUvvsqynflf9e", "\xff\xa3" "345"],
      ["$2a$05$/OK.fbVrR/bpIqNJ5ianF.nRht2l/HRhr6zmCp9vYUvvsqynflf9e", "\xff\xa3" "345"],
      ["$2a$05$/OK.fbVrR/bpIqNJ5ianF.6IflQkJytoRVc1yuaNtHfiuq.FRlSIS", "\xa3" "ab"],
      ["$2x$05$/OK.fbVrR/bpIqNJ5ianF.6IflQkJytoRVc1yuaNtHfiuq.FRlSIS", "\xa3" "ab"],
      ["$2y$05$/OK.fbVrR/bpIqNJ5ianF.6IflQkJytoRVc1yuaNtHfiuq.FRlSIS", "\xa3" "ab"],
      ["$2x$05$6bNw2HLQYeqHYyBfLMsv/OiwqTymGIGzFsA4hOTWebfehXHNprcAS", "\xd1\x91"],
      ["$2x$05$6bNw2HLQYeqHYyBfLMsv/O9LIGgn8OMzuDoHfof8AQimSGfcSWxnS", "\xd0\xc1\xd2\xcf\xcc\xd8"],
      ["$2a$05$/OK.fbVrR/bpIqNJ5ianF.swQOIzjOiJ9GHEPuhEkvqrUyvWhEMx6",
       "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa" \
       "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa" \
       "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa" \
       "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa" \
       "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa" \
       "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa" \
       "chars after 72 are ignored as usual"],
      ["$2a$05$/OK.fbVrR/bpIqNJ5ianF.R9xrDjiycxMbQE2bp.vgqlYpW5wx2yy",
       "\xaa\x55\xaa\x55\xaa\x55\xaa\x55\xaa\x55\xaa\x55" \
       "\xaa\x55\xaa\x55\xaa\x55\xaa\x55\xaa\x55\xaa\x55" \
       "\xaa\x55\xaa\x55\xaa\x55\xaa\x55\xaa\x55\xaa\x55" \
       "\xaa\x55\xaa\x55\xaa\x55\xaa\x55\xaa\x55\xaa\x55" \
       "\xaa\x55\xaa\x55\xaa\x55\xaa\x55\xaa\x55\xaa\x55" \
       "\xaa\x55\xaa\x55\xaa\x55\xaa\x55\xaa\x55\xaa\x55"],
      ["$2a$05$/OK.fbVrR/bpIqNJ5ianF.9tQZzcJfm3uj2NvJ/n5xkhpqLrMpWCe",
       "\x55\xaa\xff\x55\xaa\xff\x55\xaa\xff\x55\xaa\xff" \
       "\x55\xaa\xff\x55\xaa\xff\x55\xaa\xff\x55\xaa\xff" \
       "\x55\xaa\xff\x55\xaa\xff\x55\xaa\xff\x55\xaa\xff" \
       "\x55\xaa\xff\x55\xaa\xff\x55\xaa\xff\x55\xaa\xff" \
       "\x55\xaa\xff\x55\xaa\xff\x55\xaa\xff\x55\xaa\xff" \
       "\x55\xaa\xff\x55\xaa\xff\x55\xaa\xff\x55\xaa\xff"],
      ["$2a$05$CCCCCCCCCCCCCCCCCCCCC.7uG0VCzI2bS7j6ymqJi9CdcdxiRTWNy", ""],

      #  --------
      # from: https://bitbucket.org/ecollins/passlib/src/849ab1e6b5d4ace4c727a63d4adec928d6d72c13/passlib/tests/test_handlers_bcrypt.py

      # test_handlers_bcrypt.py: known_correct_hashes
      ['$2a$05$c92SVSfjeiCD6F2nAD6y0uBpJDjdRkt0EgeC4/31Rf2LUZbDRDE.O', 'U*U*U*U*'],
      ['$2a$05$WY62Xk2TXZ7EvVDQ5fmjNu7b0GEzSzUXUh2cllxJwhtOeMtWV3Ujq', 'U*U***U'],
      ['$2a$05$Fa0iKV3E2SYVUlMknirWU.CFYGvJ67UwVKI1E2FP6XeLiZGcH3MJi', 'U*U***U*'],
      ['$2a$05$.WRrXibc1zPgIdRXYfv.4uu6TD1KWf0VnHzq/0imhUhuxSxCyeBs2', '*U*U*U*U'],
      ['$2a$05$Otz9agnajgrAe0.kFVF9V.tzaStZ2s1s4ZWi/LY4sw2k/MTVFj/IO', ''],
      ['$2a$04$R1lJ2gkNaoPGdafE.H.16.1MKHPvmKwryeulRe225LKProWYwt9Oi', ("0123456789"*26)[0, 254]],
      ['$2a$04$R1lJ2gkNaoPGdafE.H.16.1MKHPvmKwryeulRe225LKProWYwt9Oi', ("0123456789"*26)[0, 255]],
      ['$2a$04$R1lJ2gkNaoPGdafE.H.16.1MKHPvmKwryeulRe225LKProWYwt9Oi', ("0123456789"*26)[0, 256]],
      ['$2a$04$R1lJ2gkNaoPGdafE.H.16.1MKHPvmKwryeulRe225LKProWYwt9Oi', ("0123456789"*26)[0, 257]],
      ['$2a$06$DCq7YPn5Rq63x1Lad4cll.TV4S6ytwfsfvkgY8jIucDrjc8deX1s.', ''],
      ['$2a$10$k87L/MF28Q673VKh8/cPi.SUl7MU/rWuSiIDDFayrKk/1tBsSQu4u', 'a'],
      ['$2a$10$WvvTPHKwdBJ3uk0Z37EMR.hLA2W6N9AEBhEgrAOljy2Ae5MtaSIUi', 'abc'],
      ['$2a$10$fVH8e28OQRj9tqiDXs1e1uxpsjN0c7II7YPKXua2NAKYvM6iQk7dq', 'abcdefghijklmnopqrstuvwxyz'],
      ['$2a$10$LgfYWkbzEvQ4JakH7rOvHe0y8pHKF9OaFgwUZ2q7W2FFZmZzJYlfS', '~!@#$%^&*()      ~!@#$%^&*()PNBFRD'],
      ['$2a$05$Z17AXnnlpzddNUvnC6cZNOSwMA/8oNiKnHTHTwLlBijfucQQlHjaG', UPASS_TABLE],
      ['$2b$05$Z17AXnnlpzddNUvnC6cZNOSwMA/8oNiKnHTHTwLlBijfucQQlHjaG', UPASS_TABLE],

      # test_handlers_bcrypt.py: known_correct_configs
      ['$2a$04$uM6csdM8R9SXTex/gbTayezuvzFEufYGd2uB6of7qScLjQ4GwcD4G', UPASS_TABLE],

      # test_handlers_bcrypt.py: known_unidentified_hashes
      ["$2f$12$EXRkfkdmXnagzds2SSitu.MW9.gAVqa9eLS1//RYtYCmB1eLHg.9q", 'sutb', ArgumentError],
      ["$2`$12$EXRkfkdmXnagzds2SSitu.MW9.gAVqa9eLS1//RYtYCmB1eLHg.9q", 'stub', ArgumentError],

      # test_handlers_bcrypt.py: known_malformed_hashes
      # bad char in otherwise correct hash
      #                  \/
      ["$2a$12$EXRkfkdmXn!gzds2SSitu.MW9.gAVqa9eLS1//RYtYCmB1eLHg.9q", 'stub', ArgumentError],
      # unsupported (but recognized) minor version
#     ["$2x$12$EXRkfkdmXnagzds2SSitu.MW9.gAVqa9eLS1//RYtYCmB1eLHg.9q", 'stub', ArgumentError], # we DO supprt this
      # rounds not zero-padded (py-bcrypt rejects this, therefore so do we)
      ['$2a$6$DCq7YPn5Rq63x1Lad4cll.TV4S6ytwfsfvkgY8jIucDrjc8deX1s.',  'stub', ArgumentError],

      # test_handlers_bcrypt.py: known_incorrect_padding
      # 2 bits of salt padding set
      #                             \/
      ['$2a$04$oaQbBqq8JnSM1NHRPQGXORY4Vw3bdHKLIXTecPDRAcJ98cz1ilveO', "test", false],
      ['$2a$04$oaQbBqq8JnSM1NHRPQGXOOY4Vw3bdHKLIXTecPDRAcJ98cz1ilveO', "test"],
      # all 4 bits of salt padding set
      #                             \/
      ["$2a$04$yjDgE74RJkeqC0/1NheSScrvKeu9IbKDpcQf/Ox3qsrRS/Kw42qIS", "test", false],
      ["$2a$04$yjDgE74RJkeqC0/1NheSSOrvKeu9IbKDpcQf/Ox3qsrRS/Kw42qIS", "test"],
      # bad checksum padding
      #                                                            \/
      ["$2a$04$yjDgE74RJkeqC0/1NheSSOrvKeu9IbKDpcQf/Ox3qsrRS/Kw42qIV", "test", false],

      #  --------
      # from: https://www.akkadia.org/drepper/SHA-crypt.txt
      ["$5$saltstring$5B8vYYiY.CVt1RlTTf8KbXBH3hsxY/GNooZaBBGWEc5", "Hello world!"],
      ["$5$rounds=10000$saltstringsaltst$3xv.VbSHBb41AL9AvLeujZkZRBAwqFMz2.opqey6IcA", "Hello world!"],
      ["$5$rounds=5000$toolongsaltstrin$Un/5jzAHMgOGZ5.mWJpuVolil07guHPvOW8mGRcvxa5", "This is just a test"],
      ["$5$rounds=1400$anotherlongsalts$Rx.j8H.h8HjEDGomFU8bDkXm3XIUnzyxf12oP84Bnq1", "a very much longer text to encrypt.  This one even stretches over more" "than one line."],
      ["$5$rounds=77777$short$JiO1O3ZpDAxGJeaDIuqCoEFysAe1mZNJRs3pw0KQRd/", "we have a short salt string but not a short password"],
      ["$5$rounds=123456$asaltof16chars..$gP3VQ/6X7UUEW3HkBn2w1/Ptq2jxPyzV/cZKmF/wJvD", "a short string"],
      ["$5$rounds=1000$roundstoolow$yfvwcWrQ8l/K0DAWyuPMDNHpIVlTQebY9l/gL972bIC", "the minimum number is still observed"],

      #  --------
      # from: https://bitbucket.org/ecollins/passlib/src/849ab1e6b5d4ace4c727a63d4adec928d6d72c13/passlib/tests/test_handlers.py

      # _sha256_crypt_test: known_correct_hashes
      ['$5$LKO/Ute40T3FNF95$U0prpBQd4PloSGU0pnpM4z9wKn4vZ1.jsrzQfPqxph9', 'U*U*U*U*'],
      ['$5$LKO/Ute40T3FNF95$fdgfoJEBoMajNxCv3Ru9LyQ0xZgv0OBMQoq80LQ/Qd.', 'U*U***U'],
      ['$5$LKO/Ute40T3FNF95$8Ry82xGnnPI/6HtFYnvPBTYgOL23sdMXn8C29aO.x/A', 'U*U***U*'],
      ['$5$9mx1HkCz7G1xho50$O7V7YgleJKLUhcfk9pgzdh3RapEaWqMtEp9UUBAKIPA', '*U*U*U*U'],
      ['$5$kc7lRD1fpYg0g.IP$d7CMTcEqJyTXyeq8hTdu/jB/I6DGkoo62NXbHIR7S43', ''],
      ['$5$rounds=10428$uy/jIAhCetNCTtb0$YWvUOXbkqlqhyoPMpN8BMe.ZGsGx2aBvxTvDFI613c3', ''],
      ['$5$rounds=10376$I5lNtXtRmf.OoMd8$Ko3AI1VvTANdyKhBPavaRjJzNpSatKU6QVN9uwS9MH.', ' '],
      ['$5$rounds=11858$WH1ABM5sKhxbkgCK$aTQsjPkz0rBsH3lQlJxw9HDTDXPKBxC0LlVeV69P.t1', 'test'],
      ['$5$rounds=10350$o.pwkySLCzwTdmQX$nCMVsnF3TXWcBPOympBUUSQi6LGGloZoOsVJMGJ09UB', 'Compl3X AlphaNu3meric'],
      ['$5$rounds=11944$9dhlu07dQMRWvTId$LyUI5VWkGFwASlzntk1RLurxX54LUhgAcJZIt0pYGT7', '4lpHa N|_|M3r1K W/ Cur5Es: #$%(*)(*%#'],
      ['$5$rounds=1000$IbG0EuGQXw5EkMdP$LQ5AfPf13KufFsKtmazqnzSGZ4pxtUNw3woQ.ELRDF4', "with unic\u00D6de"],
      ['$5$rounds=1004$nacl$oiWPbm.kQ7.jTCZoOtdv7/tO5mWv/vxw5yTqlBagVR7', 'secret'],
      ['$5$rounds=1005$nacl$6Mo/TmGDrXxg.bMK9isRzyWH3a..6HnSVVsJMEX7ud/', 'secret'],
      ['$5$rounds=1006$nacl$I46VwuAiUBwmVkfPFakCtjVxYYaOJscsuIeuZLbfKID', 'secret'],
      ['$5$rounds=1007$nacl$9fY4j1AV3N/dV/YMUn1enRHKH.7nEL4xf1wWB6wfDD4', 'secret'],
      ['$5$rounds=1008$nacl$CiFWCfn8ODmWs0I1xAdXFo09tM8jr075CyP64bu3by9', 'secret'],
      ['$5$rounds=1009$nacl$QtpFX.CJHgVQ9oAjVYStxAeiU38OmFILWm684c6FyED', 'secret'],
      ['$5$rounds=1010$nacl$ktAwXuT5WbjBW/0ZU1eNMpqIWY1Sm4twfRE1zbZyo.B', 'secret'],
      ['$5$rounds=1011$nacl$QJWLBEhO9qQHyMx4IJojSN9sS41P1Yuz9REddxdO721', 'secret'],
      ['$5$rounds=1012$nacl$mmf/k2PkbBF4VCtERgky3bEVavmLZKFwAcvxD1p3kV2', 'secret'],

      #  --------
      # from: https://www.akkadia.org/drepper/SHA-crypt.txt
      ["$6$saltstring$svn8UoSVapNtMuq1ukKS4tPQd8iKwSMHWjl/O817G3uBnIFNjnQJuesI68u4OTLiBFdcbYEdFCoEOfaS35inz1", "Hello world!"],
      ["$6$rounds=10000$saltstringsaltst$OW1/O6BYHV6BcXZu8QVeXbDWra3Oeqh0sbHbbMCVNSnCM/UrjmM0Dp8vOuZeHBy/YTBmSK6H9qs/y3RnOaw5v.", "Hello world!"],
      ["$6$rounds=5000$toolongsaltstrin$lQ8jolhgVRVhY4b5pZKaysCLi0QBxGoNeKQzQ3glMhwllF7oGDZxUhx1yxdYcz/e1JSbq3y6JMxxl8audkUEm0", "This is just a test"],
      ["$6$rounds=1400$anotherlongsalts$POfYwTEok97VWcjxIiSOjiykti.o/pQs.wPvMxQ6Fm7I6IoYN3CmLs66x9t0oSwbtEW7o7UmJEiDwGqd8p4ur1", "a very much longer text to encrypt.  This one even stretches over more" "than one line."],
      ["$6$rounds=77777$short$WuQyW2YR.hBNpjjRhpYD/ifIw05xdfeEyQoMxIXbkvr0gge1a1x3yRULJ5CCaUeOxFmtlcGZelFl5CxtgfiAc0", "we have a short salt string but not a short password"],
      ["$6$rounds=123456$asaltof16chars..$BtCwjqMJGx5hrJhZywWvt0RLE8uZ4oPwcelCjmw2kSYu.Ec6ycULevoBK25fs2xXgMNrCzIMVcgEJAstJeonj1", "a short string"],
      ["$6$rounds=1000$roundstoolow$kUMsbe306n21p9R.FRkW3IGn.S9NPN0x50YhH1xhLsPuWGsUSklZt58jaTfF4ZEQpyUNGc0dqbpBYYBaHHrsX.", "the minimum number is still observed"],

      #  --------
      # from: https://bitbucket.org/ecollins/passlib/src/849ab1e6b5d4ace4c727a63d4adec928d6d72c13/passlib/tests/test_handlers.py

      # _sha512_crypt_test: known_correct_hashes
      ['$6$LKO/Ute40T3FNF95$6S/6T2YuOIHY0N3XpLKABJ3soYcXD9mB7uVbtEZDj/LNscVhZoZ9DEH.sBciDrMsHOWOoASbNLTypH/5X26gN0', 'U*U*U*U*'],
      ['$6$LKO/Ute40T3FNF95$wK80cNqkiAUzFuVGxW6eFe8J.fSVI65MD5yEm8EjYMaJuDrhwe5XXpHDJpwF/kY.afsUs1LlgQAaOapVNbggZ1', 'U*U***U'],
      ['$6$LKO/Ute40T3FNF95$YS81pp1uhOHTgKLhSMtQCr2cDiUiN03Ud3gyD4ameviK1Zqz.w3oXsMgO6LrqmIEcG3hiqaUqHi/WEE2zrZqa/', 'U*U***U*'],
      ['$6$OmBOuxFYBZCYAadG$WCckkSZok9xhp4U1shIZEV7CCVwQUwMVea7L3A77th6SaE9jOPupEMJB.z0vIWCDiN9WLh2m9Oszrj5G.gt330', '*U*U*U*U'],
      ['$6$ojWH1AiTee9x1peC$QVEnTvRVlPRhcLQCk/HnHaZmlGAAjCfrAN0FtOsOnUk5K5Bn/9eLHHiRzrTzaIKjW9NTLNIBUCtNVOowWS2mN.', ''],
      ['$6$rounds=11021$KsvQipYPWpr93wWP$v7xjI4X6vyVptJjB1Y02vZC5SaSijBkGmq1uJhPr3cvqvvkd42Xvo48yLVPFt8dvhCsnlUgpX.//Cxn91H4qy1', ''],
      ['$6$rounds=11104$ED9SA4qGmd57Fq2m$q/.PqACDM/JpAHKmr86nkPzzuR5.YpYa8ZJJvI8Zd89ZPUYTJExsFEIuTYbM7gAGcQtTkCEhBKmp1S1QZwaXx0', ' '],
      ['$6$rounds=11531$G/gkPn17kHYo0gTF$Kq.uZBHlSBXyzsOJXtxJruOOH4yc0Is13uY7yK0PvAvXxbvc1w8DO1RzREMhKsc82K/Jh8OquV8FZUlreYPJk1', 'test'],
      ['$6$rounds=10787$wakX8nGKEzgJ4Scy$X78uqaX1wYXcSCtS4BVYw2trWkvpa8p7lkAtS9O/6045fK4UB2/Jia0Uy/KzCpODlfVxVNZzCCoV9s2hoLfDs/', 'Compl3X AlphaNu3meric'],
      ['$6$rounds=11065$5KXQoE1bztkY5IZr$Jf6krQSUKKOlKca4hSW07MSerFFzVIZt/N3rOTsUgKqp7cUdHrwV8MoIVNCk9q9WL3ZRMsdbwNXpVk0gVxKtz1', '4lpHa N|_|M3r1K W/ Cur5Es: #$%(*)(*%#'],
      ['$6$rounds=40000$PEZTJDiyzV28M3.m$GTlnzfzGB44DGd1XqlmC4erAJKCP.rhvLvrYxiT38htrNzVGBnplFOHjejUGVrCfusGWxLQCc3pFO0A/1jYYr0', UPASS_TABLE],

      #  --------
      # from: https://github.com/P-H-C/phc-winner-argon2/blob/master/src/test.c
      ["$argon2i$m=65536,t=2,p=1$c29tZXNhbHQ$9sTbSlTio3Biev89thdrlKKiCaYsjjYVJxGAL3swxpQ",  "password"],
      ["$argon2i$m=262144,t=2,p=1$c29tZXNhbHQ$Pmiaqj0op3zyvHKlGsUxZnYXURgvHuKS4/Z3p9pMJGc", "password"],
      ["$argon2i$m=256,t=2,p=1$c29tZXNhbHQ$/U3YPXYsSb3q9XxHvc0MLxur+GP960kN9j7emXX8zwY",    "password"],
      ["$argon2i$m=256,t=2,p=2$c29tZXNhbHQ$tsEVYKap1h6scGt5ovl9aLRGOqOth+AMB+KwHpDFZPs",    "password"],
      ["$argon2i$m=65536,t=1,p=1$c29tZXNhbHQ$gWMFUrjzsfSM2xmSxMZ4ZD1JCytetP9sSzQ4tWIXJLI",  "password"],
      ["$argon2i$m=65536,t=4,p=1$c29tZXNhbHQ$8hLwFhXm6110c03D70Ct4tUdBSRo2MaUQKOh8sHChHs",  "password"],
      ["$argon2i$m=65536,t=2,p=1$c29tZXNhbHQ$6ckCB0tnVFMaOgvlGeW69ASzDOabPwGsO/ISKZYBCaM",  "differentpassword"],
      ["$argon2i$m=65536,t=2,p=1$ZGlmZnNhbHQ$eaEDuQ/orvhXDLMfyLIiWXeJFvgza3vaw4kladTxxJc",  "password"],

      # Handle an invalid encoding correctly (it is missing a $)
      ["$argon2i$m=65536,t=2,p=1c29tZXNhbHQ$9sTbSlTio3Biev89thdrlKKiCaYsjjYVJxGAL3swxpQ", 'password', ArgumentError],
      # Handle an invalid encoding correctly (it is missing a $)
      ["$argon2i$m=65536,t=2,p=1$c29tZXNhbHQ9sTbSlTio3Biev89thdrlKKiCaYsjjYVJxGAL3swxpQ", 'password', ArgumentError],
      # Handle an invalid encoding correctly (salt is too short)
      ["$argon2i$m=65536,t=2,p=1$$9sTbSlTio3Biev89thdrlKKiCaYsjjYVJxGAL3swxpQ", "password", ArgumentError],
      # Handle an mismatching hash (the encoded password is "passwore")
      ["$argon2i$m=65536,t=2,p=1$c29tZXNhbHQ$b2G3seW+uPzerwQQC+/E1K50CLLO7YXy0JRcaTuswRo", "password", false],

      ["$argon2i$v=19$m=1048576,t=2,p=1$c29tZXNhbHQ$0Vh6ygkiw7XWqD7asxvuPE667zQu1hJ6VdGbI1GtH0E", "password"],
      ["$argon2i$v=19$m=262144,t=2,p=1$c29tZXNhbHQ$KW266AuAfNzqrUSudBtQbxTbCVkmexg7EY+bJCKbx8s",  "password"],
      ["$argon2i$v=19$m=256,t=2,p=1$c29tZXNhbHQ$iekCn0Y3spW+sCcFanM2xBT63UP2sghkUoHLIUpWRS8",     "password"],
      ["$argon2i$v=19$m=256,t=2,p=2$c29tZXNhbHQ$T/XOJ2mh1/TIpJHfCdQan76Q5esCFVoT5MAeIM1Oq2E",     "password"],
      ["$argon2i$v=19$m=65536,t=1,p=1$c29tZXNhbHQ$0WgHXE2YXhPr6uVgz4uUw7XYoWxRkWtvSsLaOsEbvs8",   "password"],
      ["$argon2i$v=19$m=65536,t=4,p=1$c29tZXNhbHQ$qqlT1YrzcGzj3xrv1KZKhOMdf1QXUjHxKFJZ+IF0zls",   "password"],
      ["$argon2i$v=19$m=65536,t=2,p=1$c29tZXNhbHQ$FK6NoBr+qHAMI1jc73xTWNkCEoK9iGY6RWL1n7dNIu4",   "differentpassword"],
      ["$argon2i$v=19$m=65536,t=2,p=1$ZGlmZnNhbHQ$sDV8zPvvkfOGCw26RHsjSMvv7K2vmQq/6cxAcmxSEnE",   "password"],

      # Handle an invalid encoding correctly (it is missing a $)
      ["$argon2i$v=19$m=65536,t=2,p=1c29tZXNhbHQ$wWKIMhR9lyDFvRz9YTZweHKfbftvj+qf+YFY4NeBbtA", 'password', ArgumentError],
      ["$argon2i$v=19$m=65536,t=2,p=1$c29tZXNhbHQwWKIMhR9lyDFvRz9YTZweHKfbftvj+qf+YFY4NeBbtA", 'password', ArgumentError],
      # Handle an invalid encoding correctly (salt is too short)
      ["$argon2i$v=19$m=65536,t=2,p=1$$9sTbSlTio3Biev89thdrlKKiCaYsjjYVJxGAL3swxpQ", "password", ArgumentError],
      # Handle an mismatching hash (the encoded password is "passwore")
      ["$argon2i$v=19$m=65536,t=2,p=1$c29tZXNhbHQ$8iIuixkI73Js3G1uMbezQXD0b8LG4SXGsOwoQkdAQIM", "password", false],

      #  --------
      # from: https://bitbucket.org/ecollins/passlib/src/849ab1e6b5d4ace4c727a63d4adec928d6d72c13/passlib/tests/test_handlers_argon2.py

      # test_handlers_argon2.py: known_correct_hashes
      ['$argon2i$v=19$m=256,t=1,p=1$c29tZXNhbHQ$AJFIsNZTMKTAewB4+ETN1A', 'password'],
      ['$argon2i$v=19$m=380,t=2,p=2$c29tZXNhbHQ$SrssP8n7m/12VWPM8dvNrw', 'password'],
      ['$argon2i$v=19$m=512,t=2,p=2$1sV0O4PWLtc12Ypv1f7oGw$z+yqzlKtrq3SaNfXDfIDnQ', UPASS_TABLE],
      ['$argon2i$v=19$m=512,t=2,p=2$1sV0O4PWLtc12Ypv1f7oGw$z+yqzlKtrq3SaNfXDfIDnQ', PASS_TABLE_UTF8],
      ['$argon2i$v=19$m=512,t=2,p=2$c29tZXNhbHQ$Fb5+nPuLzZvtqKRwqUEtUQ', "password\x00"],

      # test_handlers_argon2.py: known_malformed_hashes
      # missing 'm' param
      ["$argon2i$v=19$t=2,p=4$c29tZXNhbHQAAAAAAAAAAA$QWLzI4TY9HkL2ZTLc8g6SinwdhZewYrzz9zxCo0bkGY", 'password', ArgumentError],
      # 't' param > max uint32
      ["$argon2i$v=19$m=65536,t=8589934592,p=4$c29tZXNhbHQAAAAAAAAAAA$QWLzI4TY9HkL2ZTLc8g6SinwdhZewYrzz9zxCo0bkGY", 'password', (require 'argon2'; Argon2::ArgonHashFail)],
      # unexpected param
      ["$argon2i$v=19$m=65536,t=2,p=4,q=5$c29tZXNhbHQAAAAAAAAAAA$QWLzI4TY9HkL2ZTLc8g6SinwdhZewYrzz9zxCo0bkGY", 'password', ArgumentError],
      # wrong param order
      ["$argon2i$v=19$t=2,m=65536,p=4,q=5$c29tZXNhbHQAAAAAAAAAAA$QWLzI4TY9HkL2ZTLc8g6SinwdhZewYrzz9zxCo0bkGY", 'password', ArgumentError],
      # constraint violation: m < 8 * p
      ["$argon2i$v=19$m=127,t=2,p=16$c29tZXNhbHQ$IMit9qkFULCMA/ViizL57cnTLOa5DiVM9eMwpAvPwr4", 'password', Argon2::ArgonHashFail],

      # test_handlers_argon2.py: test_keyid_parameter
      ["$argon2i$v=19$m=65536,t=2,p=4,keyid=ABCD$c29tZXNhbHQ$IMit9qkFULCMA/ViizL57cnTLOa5DiVM9eMwpAvPwr4", "password", ArgumentError],

      # test_handlers_argon2.py: test_data_parameter
      ['$argon2i$v=19$m=512,t=2,p=2,data=c29tZWRhdGE$c29tZXNhbHQ$KgHyCesFyyjkVkihZ5VNFw', 'password', ArgumentError],
      ['$argon2i$v=19$m=512,t=2,p=2,data=c29tZWRhdGE$c29tZXNhbHQ$uEeXt1dxN1iFKGhklseW4w', 'password', ArgumentError],
      ['$argon2i$v=19$m=512,t=2,p=2$c29tZXNhbHQ$uEeXt1dxN1iFKGhklseW4w', 'password'],

      # test_handlers_argon2.py: test_keyid_and_data_parameters
      ["$argon2i$v=19$m=65536,t=2,p=4,keyid=ABCD,data=EFGH$c29tZXNhbHQ$IMit9qkFULCMA/ViizL57cnTLOa5DiVM9eMwpAvPwr4", 'stub', ArgumentError],

      # test_handlers_argon2.py: test_argon_byte_encoding
#     ["$argon2i$v=19$m=256,t=2,p=2$c29tZXNhbHQ$T/XOJ2mh1/TIpJHfCdQan76Q5esCFVoT5MAeIM1Oq2E", 'password'], # we have seen this before
      ["$argon2i$v=19$m=256,t=2,p=2$c29tZXNhbHQAAAAAAAAAAA$rqnbEp1/jFDUEKZZmw+z14amDsFqMDC53dIe57ZHD38", 'password'],

      # test_handlers_argon2.py: argon2_argon2_cffi_test
      ["$argon2i$m=65536,t=2,p=4$c29tZXNhbHQAAAAAAAAAAA$QWLzI4TY9HkL2ZTLc8g6SinwdhZewYrzz9zxCo0bkGY", 'password'],
      ["$argon2i$v=19$m=65536,t=2,p=4$c29tZXNhbHQ$IMit9qkFULCMA/ViizL57cnTLOa5DiVM9eMwpAvPwr4", 'password'],
      ["$argon2d$v=19$m=65536,t=2,p=4$c29tZXNhbHQ$cZn5d+rFh+ZfuRhm2iGUGgcrW5YLeM6q7L3vBsdmFA0", 'password'],
      ["$argon2i$v=19$m=65536,t=2,p=4$c29tZXNhbHQ$Vpzuc0v0SrP88LcVvmg+z5RoOYpMDKH/lt6O+CZabIQ", "password\x00"],

      #  --------
      # from: https://github.com/simonepri/phc-scrypt/blob/master/test/vectors.js

      ['$scrypt$ln=4,r=1,p=1$$d9ZXYjhleyA7GcpCwYoEl/FrSETjB0ro39/6P+3iFEL80Aad7QlI+DJqdToPyB8X6NPg+y4NNijPNeIMONGJBg', ''],
      ['$scrypt$ln=10,r=8,p=16$TmFDbA$/bq+HJ00cgB4VucZDQHp/nxq18vII3gw53N2Y0s3MWIurzDZLiKjiG/xCSedmDDaxyevuUqD7m2DYMvfoswGQA', 'password'],
      ['$scrypt$ln=14,r=8,p=1$U29kaXVtQ2hsb3JpZGU$cCO9yzr9c0hGHAbNgf046/2o+7qQT44+qbVD9lRdofLVQylVYT8Pz2LUlwUkKpr55h6F3A1lHkDfzwF7RVdYhw', 'pleaseletmein'],
      ['$scrypt$ln=20,r=8,p=1$U29kaXVtQ2hsb3JpZGU$IQHLm2pRGq6t274Jz3D4gexWjVdKL/1Nq+XumCCtqkeOVv2PS6XQn/ocbZJ8QPTDNzBASeipUvvL9Fxvp3pBpA', 'pleaseletmein'],

      #  --------
      # from: https://github.com/simonepri/phc-scrypt/blob/master/test/vectors.js

      ['$scrypt$ln=16,r=8,p=1$aM15713r3Xsvxbi31lqr1Q$nFNh2CVHVjNldFVKDHDlm4CbdRSCdEBsjjJxD+iCs5E', 'password'],
      ['$script$ln=16,r=8,p=1$aM15713r3Xsvxbi31lqr1Q$nFNh2CVHVjNldFVKDHDlm4CbdRSCdEBsjjJxD+iCs5E', 'password', ArgumentError],
      ['$scrypt$r=8,p=1$aM15713r3Xsvxbi31lqr1Q$nFNh2CVHVjNldFVKDHDlm4CbdRSCdEBsjjJxD+iCs5E', 'password', ArgumentError],
      ['$scrypt$ln=0,r=8,p=1$aM15713r3Xsvxbi31lqr1Q$nFNh2CVHVjNldFVKDHDlm4CbdRSCdEBsjjJxD+iCs5E', 'password', ArgumentError],
      ['$scrypt$ln=256,r=8,p=1$aM15713r3Xsvxbi31lqr1Q$nFNh2CVHVjNldFVKDHDlm4CbdRSCdEBsjjJxD+iCs5E', 'password', RangeError],
      ['$scrypt$ln=16,p=1$aM15713r3Xsvxbi31lqr1Q$nFNh2CVHVjNldFVKDHDlm4CbdRSCdEBsjjJxD+iCs5E', 'password', ArgumentError],
      ['$scrypt$ln=16,r=-1,p=1$aM15713r3Xsvxbi31lqr1Q$nFNh2CVHVjNldFVKDHDlm4CbdRSCdEBsjjJxD+iCs5E', 'password', ArgumentError],
      ['$scrypt$ln=16,r=4294967296,p=1$aM15713r3Xsvxbi31lqr1Q$nFNh2CVHVjNldFVKDHDlm4CbdRSCdEBsjjJxD+iCs5E', 'password', RangeError],
      ['$scrypt$ln=16,r=8$aM15713r3Xsvxbi31lqr1Q$nFNh2CVHVjNldFVKDHDlm4CbdRSCdEBsjjJxD+iCs5E', 'password', ArgumentError],
      ['$scrypt$ln=16,r=8,p=0$aM15713r3Xsvxbi31lqr1Q$nFNh2CVHVjNldFVKDHDlm4CbdRSCdEBsjjJxD+iCs5E', 'password', ArgumentError],
      ['$scrypt$ln=16,r=8,p=4294967296$aM15713r3Xsvxbi31lqr1Q$nFNh2CVHVjNldFVKDHDlm4CbdRSCdEBsjjJxD+iCs5E', 'password', RangeError],

      #  --------
      # from: https://bitbucket.org/ecollins/passlib/src/849ab1e6b5d4ace4c727a63d4adec928d6d72c13/passlib/tests/test_handlers_scrypt.py

      ["$scrypt$ln=4,r=1,p=1$$d9ZXYjhleyA7GcpCwYoEl/FrSETjB0ro39/6P+3iFEI", ''],
      ["$scrypt$ln=10,r=8,p=16$TmFDbA$/bq+HJ00cgB4VucZDQHp/nxq18vII3gw53N2Y0s3MWI", "password"],
      ['$scrypt$ln=8,r=8,p=1$wlhLyXmP8b53bm1NKYVQqg$mTpvG8lzuuDk+DWz8HZIB6Vum6erDuUm0As5yU+VxWA', "test"],
      ['$scrypt$ln=8,r=2,p=1$dO6d0xoDoLT2PofQGoNQag$g/Wf2A0vhHhaJM+addK61QPBthSmYB6uVTtQzh8CM3o', "password"],
      ['$scrypt$ln=7,r=8,p=1$jjGmtDamdA4BQAjBeA9BSA$OiWRHhQtpDx7M/793x6UXK14AD512jg/qNm/hkWZG4M', UPASS_TABLE],
      ['$scrypt$ln=7,r=8,p=1$jjGmtDamdA4BQAjBeA9BSA$OiWRHhQtpDx7M/793x6UXK14AD512jg/qNm/hkWZG4M', PASS_TABLE_UTF8],
      ['$scrypt$ln=1,r=4,p=2$yhnD+J+Tci4lZCwFgHCuVQ$fAsEWmxSHuC0cHKMwKVFPzrQukgvK09Sj+NueTSxKds', "nacl"],

      # test_handlers_scrypt.py: known_malformed_hashes
      ['$scrypt$ln=10,r=1$wvif8/4fg1Cq9V7L2dv73w$bJcLia1lyfQ1X2x0xflehwVXPzWIUQWWdnlGwfVzBeQ', 'stub', ArgumentError],
      ['$scrypt$ln=0,r=1,p=1$wvif8/4fg1Cq9V7L2dv73w$bJcLia1lyfQ1X2x0xflehwVXPzWIUQWWdnlGwfVzBeQ', 'stub', ArgumentError],
      ['$scrypt$ln=10,r=A,p=1$wvif8/4fg1Cq9V7L2dv73w$bJcLia1lyfQ1X2x0xflehwVXPzWIUQWWdnlGwfVzBeQ', 'stub', ArgumentError],
      ['$scrypt$ln=10,r=134217728,p=8$wvif8/4fg1Cq9V7L2dv73w$bJcLia1lyfQ1X2x0xflehwVXPzWIUQWWdnlGwfVzBeQ', 'stub', RuntimeError],

      #  --------
      # from: https://github.com/pbhogan/scrypt/blob/master/spec/scrypt/password_spec.rb

      ["400$8$d$173a8189751c095a29b933789560b73bf17b2e01$9bf66d74bd6f3ebcf99da3b379b689b89db1cb07", "my secret"],

      #  --------
      # from: https://github.com/simonepri/phc-pbkdf2/blob/master/test/vectors.js

      ['$pbkdf2-sha1$i=2$c2FsdA$6mwBTcctb4zNHtkqzh1B8NjeiVc', 'password'],
      ['$pbkdf2-sha1$i=4096$c2FsdA$SwB5AbdlSJq+rUnZJvch0GWkKcE', 'password'],
      ['$pbkdf2-sha1$i=16777216$c2FsdA$7v49Yc1NpOTplFs9a6IVjCY06YQ', 'password'],
      ['$pbkdf2-sha1$i=4096$c2FsdFNBTFRzYWx0U0FMVHNhbHRTQUxUc2FsdFNBTFRzYWx0$PS7sT+QchJuAyNg2YsDkSospGpZM8vBwOA', 'passwordPASSWORDpassword'],
      ['$pbkdf2-sha1$i=4096$c2EAbHQ$Vvpqp1VICZ3MN9fwNCXgww', "pass\x0word".b],

      #  --------
      # from: https://github.com/simonepri/phc-pbkdf2/blob/master/test/verify.js

      ['$pbkdf2-sha256$i=6400$0ZrzXitFSGltTQnBWOsdAw$Y11AchqV4b0sUisdZd0Xr97KWoymNE0LNNrnEgY4H9M', 'password'],
      ['$pbkdf2$i=6400$0ZrzXitFSGltTQnBWOsdAw$Y11AchqV4b0sUisdZd0Xr97KWoymNE0LNNrnEgY4H9M', 'password', ArgumentError],
      ['$pbkdf2-sha368$i=6400$0ZrzXitFSGltTQnBWOsdAw$Y11AchqV4b0sUisdZd0Xr97KWoymNE0LNNrnEgY4H9M', 'password', ArgumentError],
      ['$pbkdf2-sha256$it=6400$0ZrzXitFSGltTQnBWOsdAw$Y11AchqV4b0sUisdZd0Xr97KWoymNE0LNNrnEgY4H9M', 'password', ArgumentError],
      ['$pbkdf2-sha256$i=-1$0ZrzXitFSGltTQnBWOsdAw$Y11AchqV4b0sUisdZd0Xr97KWoymNE0LNNrnEgY4H9M', 'password', ArgumentError],
      ['$pbkdf2-sha256$i=4294967296$0ZrzXitFSGltTQnBWOsdAw$Y11AchqV4b0sUisdZd0Xr97KWoymNE0LNNrnEgY4H9M', 'password', RangeError],
      ['$pbkdf2-sha256$i=6400', 'password', ArgumentError],
      ['$pbkdf2-sha256$i=6400$Y11AchqV4b0sUisdZd0Xr97KWoymNE0LNNrnEgY4H9M', 'password', ArgumentError],
      ['$pbkdf2-sha256$6400$0ZrzXitFSGltTQnBWOsdAw$Y11AchqV4b0sUisdZd0Xr97KWoymNE0LNNrnEgY4H9M', 'password', ArgumentError],
    ]

    def self.raises hash, pass, klass
      name = sprintf "%p renders %p", hash, klass
      test name do
        assert_raises(klass) { crypt_checkpass? pass, hash }
      end
    end

    def self.refutes hash, pass
      name = sprintf "%p versus %p is false", hash,  pass
      test name do
        actual = crypt_checkpass? pass, hash
        refute actual
      end
    end

    def self.asserts hash, pass
      name = sprintf "%p versus %p", hash, pass
      test name do
        assert { crypt_checkpass? pass, hash }
      end
    end

    vector.each do |(hash, pass, *rest)|
      obj ,=* rest

      case obj
      when NilClass   then asserts hash, pass
      when FalseClass then refutes hash, pass
      when Class      then raises  hash, pass, obj
      else raise 'TBW'
      end
    end
  end

  sub_test_case "crypt_newhash" do
    vector = [
      [["U*U", "bcrypt,4"], {}, /\A\$2b\$04\$[A-Za-z0-9.\/]{53}\z/],
      [["U*U", "bcrypt,a"], {}, /\A\$2b\$\d\d\$[A-Za-z0-9.\/]{53}\z/],
      [["U*U", "blowfish"], {}, /\A\$2b\$\d\d\$[A-Za-z0-9.\/]{53}\z/],
      [["U*U"], {id: 'bcrypt'}, /\A\$2b\$\d\d\$[A-Za-z0-9.\/]{53}\z/],
      [["U*U"], {id: 'bcrypt', ident: '2y'}, /\A\$2y\$\d\d\$[A-Za-z0-9.\/]{53}\z/],
      [["U*U"], {id: 'sha256'}, /\A\$5\$/],
      [["U*U"], {id: 'sha256', rounds: 32768}, /\A\$5\$rounds=32768\$/],
      [["U*U"], {id: 'sha512'}, /\A\$6\$/],
      [["U*U"], {id: 'sha512', rounds: 32768}, /\A\$6\$rounds=32768\$/],
      [["U*U"], {id: 'argon2id'}, /\A\$argon2id\$v=19\$/],
      [["U*U"], {id: 'argon2id', m_cost: 12}, /\A\$argon2id\$v=19\$m=4096/],
      [["U*U"], {id: 'argon2id', m_cost: 12, t_cost: 1}, /\A\$argon2id\$v=19\$m=4096,t=1/],
      [["U*U"], {id: 'pbkdf2-sha1'}, /\A\$pbkdf2-sha1\$/],
      [["U*U"], {id: 'pbkdf2-sha256'}, /\A\$pbkdf2-sha256\$/],
      [["U*U"], {id: 'pbkdf2-sha512'}, /\A\$pbkdf2-sha512\$/],
      [["U*U"], {id: 'scrypt'}, /\A\$scrypt\$ln=\d+,r=\d+,p=\d+\$/],
      [["U*U"], {id: 'scrypt', ln: 7}, /\A\$scrypt\$ln=7,r=\d+,p=\d+\$/],
      [["U*U"], {id: 'scrypt', r: 7}, /\A\$scrypt\$ln=\d+,r=7,p=\d+\$/],
      [["U*U"], {id: 'scrypt', p: 2}, /\A\$scrypt\$ln=\d+,r=\d+,p=2\$/],
    ]
    vector.each do |(argv, argh, matcher)|
      name = sprintf "%p versus %p", [argv, argh], matcher
      test name do
        actual = crypt_newhash(*argv, **argh)
        assert_match matcher, actual
        pass = argv[0]
        assert { crypt_checkpass? pass, actual }
      end
    end
  end
end
