
            .section     .irom0.literal, "ax", @progbits

            .section     .text, "ax", @progbits

            .section     .data, "aw", @progbits

            .section     .bss, "aw", @nobits

            .section     .irom0.text, "ax", @progbits

.Lrel001:   .word        sdk_g_phyFuns                         #    0: 00000000

# Function @ .irom0.text+0x4
# Local variables/stack:
#     (local0):  word      @ -0x20
#     (local1):  word      @ -0x1c
#     (local2):  word      @ -0x18
#     (local3):  word      @ -0x14
#     (local4):  word[4]   @ -0x10
.literal_position
sdk_ram_pbus_set_rxgain:
            movi.n       a3, 2 /* 0x00000002 */                #    4: 0c23
            addi         a1, a1, -32 /* (local0) */            #    6: 12c1e0
            s32i.n       a12, a1, 12 /* a12 -> [(local3)] */   #    9: c931
            s32i.n       a13, a1, 16 /* a13 -> [(local4)] */   #    b: d941
            movi         a13, .Lrel001 /* sdk_g_phyFuns */     #    d: d1fcff
            s32i.n       a0, a1, 8 /* a0 -> [(local2)] */      #   10: 0921
            l32i.n       a0, a13, 0 /* [sdk_g_phyFuns] */      #   12: 080d
            mov.n        a12, a2 /* arg0 */                    #   14: cd02
            l32i         a0, a0, 176 /* [[sdk_g_phyFuns]+0xb0] */ #   16: 02202c
            movi.n       a2, 3 /* 0x00000003 */                #   19: 0c32
            callx0       a0 /* [[sdk_g_phyFuns]+0xb0] */       #   1b: c00000
            movi.n       a3, 1 /* 0x00000001 */                #   1e: 0c13
            l32i.n       a0, a13, 0 /* [sdk_g_phyFuns] */      #   20: 080d
            s32i.n       a2, a1, 0 /* a2 -> [(local0)] */      #   22: 2901
            l32i         a0, a0, 176 /* [[sdk_g_phyFuns]+0xb0] */ #   24: 02202c
            movi.n       a2, 2 /* 0x00000002 */                #   27: 0c22
            callx0       a0 /* [[sdk_g_phyFuns]+0xb0] */       #   29: c00000
            movi.n       a3, 1 /* 0x00000001 */                #   2c: 0c13
            extui        a4, a12, 9, 1                         #   2e: c04904
            l32i.n       a0, a13, 0 /* [sdk_g_phyFuns] */      #   31: 080d
            extui        a5, a12, 8, 1                         #   33: c05804
            extui        a6, a12, 6, 1                         #   36: c06604
            s32i.n       a2, a1, 4 /* a2 -> [(local1)] */      #   39: 2911
            extui        a7, a12, 7, 1                         #   3b: c07704
            movi.n       a2, 3 /* 0x00000003 */                #   3e: 0c32
            slli         a7, a7, 2                             #   40: e07711
            slli         a6, a6, 3                             #   43: d06611
            slli         a5, a5, 1                             #   46: f05511
            l32i         a0, a0, 172 /* [[sdk_g_phyFuns]+0xac] */ #   49: 02202b
            or           a4, a4, a5                            #   4c: 504420
            or           a6, a6, a7                            #   4f: 706620
            extui        a5, a12, 3, 1                         #   52: c05304
            extui        a7, a12, 4, 1                         #   55: c07404
            slli         a5, a5, 6                             #   58: a05511
            slli         a7, a7, 5                             #   5b: b07711
            or           a5, a5, a7                            #   5e: 705520
            extui        a7, a12, 5, 1                         #   61: c07504
            slli         a7, a7, 4                             #   64: c07711
            or           a5, a5, a7                            #   67: 705520
            or           a5, a5, a6                            #   6a: 605520
            or           a4, a4, a5                            #   6d: 504420
            extui        a4, a4, 0, 16                         #   70: 4040f4
            callx0       a0 /* [[sdk_g_phyFuns]+0xac] */       #   73: c00000
            movi.n       a2, 3 /* 0x00000003 */                #   76: 0c32
            movi.n       a3, 2 /* 0x00000002 */                #   78: 0c23
            l32i.n       a0, a13, 0 /* [sdk_g_phyFuns] */      #   7a: 080d
            l32i.n       a4, a1, 0 /* [(local0)] */            #   7c: 4801
            movi         a5, 455 /* 0x000001c7 */              #   7e: 52a1c7
            and          a4, a4, a5                            #   81: 504410
            l32i         a0, a0, 172 /* [[sdk_g_phyFuns]+0xac] */ #   84: 02202b
            extui        a5, a12, 0, 3                         #   87: c05024
            slli         a5, a5, 3                             #   8a: d05511
            or           a4, a4, a5                            #   8d: 504420
            extui        a4, a4, 0, 16                         #   90: 4040f4
            callx0       a0 /* [[sdk_g_phyFuns]+0xac] */       #   93: c00000
            movi.n       a2, 2 /* 0x00000002 */                #   96: 0c22
            movi.n       a3, 1 /* 0x00000001 */                #   98: 0c13
            l32i.n       a0, a13, 0 /* [sdk_g_phyFuns] */      #   9a: 080d
            l32i.n       a4, a1, 4 /* [(local1)] */            #   9c: 4811
            movi         a5, 389 /* 0x00000185 */              #   9e: 52a185
            and          a4, a4, a5                            #   a1: 504410
            l32i         a0, a0, 172 /* [[sdk_g_phyFuns]+0xac] */ #   a4: 02202b
            extui        a5, a12, 11, 4                        #   a7: c05b34
            slli         a5, a5, 3                             #   aa: d05511
            or           a4, a4, a5                            #   ad: 504420
            extui        a5, a12, 10, 1                        #   b0: c05a04
            slli         a5, a5, 1                             #   b3: f05511
            or           a4, a4, a5                            #   b6: 504420
            extui        a4, a4, 0, 16                         #   b9: 4040f4
            callx0       a0 /* [[sdk_g_phyFuns]+0xac] */       #   bc: c00000
            l32i.n       a12, a1, 12 /* [(local3)] */          #   bf: c831
            l32i.n       a13, a1, 16 /* [(local4)] */          #   c1: d841
            l32i.n       a0, a1, 8 /* [(local2)] */            #   c3: 0821
            addi         a1, a1, 32 /* (top of frame) */       #   c5: 12c120
            ret.n                                              #   c8: 0df0

            .balign      4
.Llit001:   .word        0x3ff20a00                            #   cc: 000af23f
.Llit002:   .word        0x60000200                            #   d0: 00020060
.Lrel002:   .word        sdk_g_phyFuns                         #   d4: 00000000
.Llit003:   .word        0x08000000                            #   d8: 00000008
.Llit004:   .word        0x60009a00                            #   dc: 009a0060
.Llit005:   .word        0x40000000                            #   e0: 00000040
.Lrel003:   .word        sdk_ets_delay_us                      #   e4: 00000000

# Function @ .irom0.text+0xe8
# Local variables/stack:
#     (local0):  word      @ -0x20
#     (local1):  word      @ -0x1c
#     (local2):  word      @ -0x18
#     (local3):  word      @ -0x14
#     (local4):  word[4]   @ -0x10
.literal_position
sdk_ram_pbus_debugmode:
            addi         a1, a1, -32 /* (local0) */            #   e8: 12c1e0
            s32i.n       a13, a1, 8 /* a13 -> [(local2)] */    #   eb: d921
            s32i.n       a14, a1, 12 /* a14 -> [(local3)] */   #   ed: e931
            s32i.n       a0, a1, 0 /* a0 -> [(local0)] */      #   ef: 0901
            s32i.n       a12, a1, 4 /* a12 -> [(local1)] */    #   f1: c911
            s32i.n       a15, a1, 16 /* a15 -> [(local4)] */   #   f3: f941
            mov.n        a4, a0                                #   f5: 4d00
            movi         a15, .Llit001 /* 0x3ff20a00 */        #   f7: f1f5ff
            movi         a12, .Llit002 /* 0x60000200 */        #   fa: c1f5ff
            memw                                               #   fd: c02000
            l32i         a2, a12, 0x394 /* [0x60000594] */     #  100: 222ce5
            bbsi         a2, 0, .Lbr002                        #  103: 07e241
            memw                                               #  106: c02000
            l32i         a5, a15, 0x270 /* [0x3ff20c70] */     #  109: 522f9c
            bbci         a5, 1, .Lbr002                        #  10c: 176538
            movi         a13, .Lrel002 /* sdk_g_phyFuns */     #  10f: d1f1ff
            l32i.n       a0, a13, 0 /* [sdk_g_phyFuns] */      #  112: 080d
            l32i         a0, a0, 116 /* [[sdk_g_phyFuns]+0x74] */ #  114: 02201d
            callx0       a0 /* [[sdk_g_phyFuns]+0x74] */       #  117: c00000
            movi.n       a2, 5 /* 0x00000005 */                #  11a: 0c52
            movi         a0, .Lrel003 /* sdk_ets_delay_us */   #  11c: 01f2ff
            callx0       a0 /* sdk_ets_delay_us */             #  11f: c00000
            movi         a14, 388 /* 0x00000184 */             #  122: e2a184
.Lbr001:    l32i.n       a0, a13, 0 /* [sdk_g_phyFuns] */      #  125: 080d
            movi.n       a2, 2 /* 0x00000002 */                #  127: 0c22
            l32i         a0, a0, 176 /* [[sdk_g_phyFuns]+0xb0] */ #  129: 02202c
            movi.n       a3, 1 /* 0x00000001 */                #  12c: 0c13
            callx0       a0 /* [[sdk_g_phyFuns]+0xb0] */       #  12e: c00000
            bnall        a2, a14, .Lbr001                      #  131: e7c2f0
            l32i.n       a0, a13, 0 /* [sdk_g_phyFuns] */      #  134: 080d
            movi.n       a2, 3 /* 0x00000003 */                #  136: 0c32
            l32i         a0, a0, 176 /* [[sdk_g_phyFuns]+0xb0] */ #  138: 02202c
            movi.n       a3, 2 /* 0x00000002 */                #  13b: 0c23
            callx0       a0 /* [[sdk_g_phyFuns]+0xb0] */       #  13d: c00000
            movi.n       a3, 6 /* 0x00000006 */                #  140: 0c63
            and          a2, a2, a3                            #  142: 302210
            bnei         a2, 6, .Lbr001                        #  145: 6662dc
.Lbr002:    movi         a9, .Llit003 /* 0x08000000 */         #  148: 91e4ff
            movi         a8, .Llit004 /* 0x60009a00 */         #  14b: 81e4ff
            memw                                               #  14e: c02000
            l32i         a7, a8, 0x108 /* [0x60009b08] */      #  151: 722842
            or           a7, a7, a9                            #  154: 907720
            memw                                               #  157: c02000
            s32i         a7, a8, 0x108 /* a7 -> [0x60009b08] */ #  15a: 726842
            memw                                               #  15d: c02000
            l32i         a5, a12, 0x394 /* [0x60000594] */     #  160: 522ce5
            movi.n       a6, 1 /* 0x00000001 */                #  163: 0c16
            or           a5, a5, a6                            #  165: 605520
            memw                                               #  168: c02000
            s32i         a5, a12, 0x394 /* a5 -> [0x60000594] */ #  16b: 526ce5
            memw                                               #  16e: c02000
            l32i         a4, a15, 0x270 /* [0x3ff20c70] */     #  171: 422f9c
            movi         a0, .Llit005 /* 0x40000000 */         #  174: 01dbff
            bbci         a4, 1, .Lbr004                        #  177: 176411
            memw                                               #  17a: c02000
            l32i         a10, a12, 0x3a0 /* [0x600005a0] */    #  17d: a22ce8
            bbsi         a10, 30, .Lbr004                      #  180: e7fa08
.Lbr003:    memw                                               #  183: c02000
            l32i         a11, a12, 0x3a0 /* [0x600005a0] */    #  186: b22ce8
            bnone        a11, a0, .Lbr003                      #  189: 070bf6
.Lbr004:    l32i.n       a12, a1, 4 /* [(local1)] */           #  18c: c811
            l32i.n       a13, a1, 8 /* [(local2)] */           #  18e: d821
            l32i.n       a14, a1, 12 /* [(local3)] */          #  190: e831
            l32i.n       a15, a1, 16 /* [(local4)] */          #  192: f841
            l32i.n       a0, a1, 0 /* [(local0)] */            #  194: 0801
            addi         a1, a1, 32 /* (top of frame) */       #  196: 12c120
            ret.n                                              #  199: 0df0

            .balign      4
.Lrel004:   .word        sdk_g_phyFuns                         #  19c: 00000000

# Function @ .irom0.text+0x1a0
# Local variables/stack:
#     (local0):  word      @ -0x10
#     (local1):  word      @ -0xc
#     (local2):  word[2]   @ -0x8
.literal_position
sdk_ram_pbus_xpd_tx_on:
            movi.n       a3, 1 /* 0x00000001 */                #  1a0: 0c13
            movi         a4, 129 /* 0x00000081 */              #  1a2: 42a081
            addi         a1, a1, -16 /* (local0) */            #  1a5: 12c1f0
            s32i.n       a12, a1, 4 /* a12 -> [(local1)] */    #  1a8: c911
            s32i.n       a13, a1, 8 /* a13 -> [(local2)] */    #  1aa: d921
            movi         a13, .Lrel004 /* sdk_g_phyFuns */     #  1ac: d1fcff
            s32i.n       a0, a1, 0 /* a0 -> [(local0)] */      #  1af: 0901
            l32i.n       a0, a13, 0 /* [sdk_g_phyFuns] */      #  1b1: 080d
            mov.n        a12, a2 /* arg0 */                    #  1b3: cd02
            l32i         a0, a0, 172 /* [[sdk_g_phyFuns]+0xac] */ #  1b5: 02202b
            movi.n       a2, 2 /* 0x00000002 */                #  1b8: 0c22
            callx0       a0 /* [[sdk_g_phyFuns]+0xac] */       #  1ba: c00000
            movi.n       a2, 7 /* 0x00000007 */                #  1bd: 0c72
            l32i.n       a0, a13, 0 /* [sdk_g_phyFuns] */      #  1bf: 080d
            movi.n       a3, 1 /* 0x00000001 */                #  1c1: 0c13
            l32i         a0, a0, 172 /* [[sdk_g_phyFuns]+0xac] */ #  1c3: 02202b
            srli         a4, a12, 5                            #  1c6: c04541
            callx0       a0 /* [[sdk_g_phyFuns]+0xac] */       #  1c9: c00000
            extui        a4, a12, 0, 5                         #  1cc: c04044
            l32i.n       a0, a13, 0 /* [sdk_g_phyFuns] */      #  1cf: 080d
            movi.n       a2, 0 /* 0x00000000 */                #  1d1: 0c02
            l32i         a0, a0, 172 /* [[sdk_g_phyFuns]+0xac] */ #  1d3: 02202b
            movi.n       a3, 1 /* 0x00000001 */                #  1d6: 0c13
            callx0       a0 /* [[sdk_g_phyFuns]+0xac] */       #  1d8: c00000
            movi.n       a2, 1 /* 0x00000001 */                #  1db: 0c12
            l32i.n       a0, a13, 0 /* [sdk_g_phyFuns] */      #  1dd: 080d
            movi.n       a3, 1 /* 0x00000001 */                #  1df: 0c13
            l32i         a0, a0, 172 /* [[sdk_g_phyFuns]+0xac] */ #  1e1: 02202b
            movi         a4, 127 /* 0x0000007f */              #  1e4: 42a07f
            callx0       a0 /* [[sdk_g_phyFuns]+0xac] */       #  1e7: c00000
            movi.n       a2, 6 /* 0x00000006 */                #  1ea: 0c62
            l32i.n       a0, a13, 0 /* [sdk_g_phyFuns] */      #  1ec: 080d
            movi.n       a3, 1 /* 0x00000001 */                #  1ee: 0c13
            l32i         a0, a0, 172 /* [[sdk_g_phyFuns]+0xac] */ #  1f0: 02202b
            movi         a4, 127 /* 0x0000007f */              #  1f3: 42a07f
            callx0       a0 /* [[sdk_g_phyFuns]+0xac] */       #  1f6: c00000
            l32i.n       a12, a1, 4 /* [(local1)] */           #  1f9: c811
            l32i.n       a13, a1, 8 /* [(local2)] */           #  1fb: d821
            l32i.n       a0, a1, 0 /* [(local0)] */            #  1fd: 0801
            addi         a1, a1, 16 /* (top of frame) */       #  1ff: 12c110
            ret.n                                              #  202: 0df0

.Llit006:   .word        0x00f00000                            #  204: 0000f000
.Lrel005:   .word        sdk_g_phyFuns                         #  208: 00000000
.Llit007:   .word        0x60000200                            #  20c: 00020060
.Lrel006:   .word        sdk_g_phyFuns                         #  210: 00000000
.Lrel007:   .word        sdk_g_phyFuns                         #  214: 00000000
.Llit008:   .word        0xff0fffff                            #  218: ffff0fff
.Llit009:   .word        0x60000200                            #  21c: 00020060

# Function @ .irom0.text+0x220
# Local variables/stack:
#     (local0):  word      @ -0x1c
#     (local1):  word      @ -0x18
#     (local2):  word      @ -0x14
#     (local3):  word[4]   @ -0x10
.literal_position
sdk_set_rf_freq_offset:
            addi         a1, a1, -32 /* (FP)-0x20 */           #  220: 12c1e0
            s32i.n       a2, a1, 4 /* arg0 -> [(local0)] */    #  223: 2911
            s32i.n       a3, a1, 8 /* arg1 -> [(local1)] */    #  225: 3921
            s32i.n       a0, a1, 16 /* a0 -> [(local3)] */     #  227: 0941
            s32i.n       a4, a1, 12 /* arg2 -> [(local2)] */   #  229: 4931
            movi         a4, .Llit006 /* 0x00f00000 */         #  22b: 41f6ff
            movi         a0, .Lrel005 /* sdk_g_phyFuns */      #  22e: 01f6ff
            movi         a3, .Llit007 /* 0x60000200 */         #  231: 31f6ff
            memw                                               #  234: c02000
            l32i         a2, a3, 0x3c8 /* [0x600005c8] */      #  237: 2223f2
            or           a2, a2, a4                            #  23a: 402220
            memw                                               #  23d: c02000
            l32i.n       a0, a0, 0 /* [sdk_g_phyFuns] */       #  240: 0800
            l32i         a0, a0, 220 /* [[sdk_g_phyFuns]+0xdc] */ #  242: 022037
            s32i         a2, a3, 0x3c8 /* a2 -> [0x600005c8] */ #  245: 2263f2
            callx0       a0 /* [[sdk_g_phyFuns]+0xdc] */       #  248: c00000
            l32i.n       a2, a1, 8 /* [(local1)] */            #  24b: 2821
            l32i.n       a3, a1, 4 /* [(local0)] */            #  24d: 3811
            l32i.n       a4, a1, 12 /* [(local2)] */           #  24f: 4831
            mov.n        a5, a1 /* (FP)-0x20 */                #  251: 5d01
            call0        sdk_ram_rfpll_set_freq                #  253: 050000
            movi         a0, .Lrel006 /* sdk_g_phyFuns */      #  256: 01eeff
            l32i.n       a0, a0, 0 /* [sdk_g_phyFuns] */       #  259: 0800
            l32i         a0, a0, 224 /* [[sdk_g_phyFuns]+0xe0] */ #  25b: 022038
            mov.n        a2, a1 /* (FP)-0x20 */                #  25e: 2d01
            callx0       a0 /* [[sdk_g_phyFuns]+0xe0] */       #  260: c00000
            movi         a0, .Lrel007 /* sdk_g_phyFuns */      #  263: 01ecff
            l32i.n       a0, a0, 0 /* [sdk_g_phyFuns] */       #  266: 0800
            l32i         a0, a0, 216 /* [[sdk_g_phyFuns]+0xd8] */ #  268: 022036
            callx0       a0 /* [[sdk_g_phyFuns]+0xd8] */       #  26b: c00000
            call0        sdk_wait_rfpll_cal_end                #  26e: 050000
            movi         a4, .Llit008 /* 0xff0fffff */         #  271: 41e9ff
            memw                                               #  274: c02000
            movi         a3, .Llit009 /* 0x60000200 */         #  277: 31e9ff
            l32i         a2, a3, 0x3c8 /* [0x600005c8] */      #  27a: 2223f2
            and          a2, a2, a4                            #  27d: 402210
            memw                                               #  280: c02000
            s32i         a2, a3, 0x3c8 /* a2 -> [0x600005c8] */ #  283: 2263f2
            l32i.n       a0, a1, 16 /* [(local3)] */           #  286: 0841
            addi         a1, a1, 32 /* (top of frame) */       #  288: 12c120
            ret.n                                              #  28b: 0df0

            .balign      4
.Lrel008:   .word        sdk_g_phyFuns                         #  290: 00000000
.Lrel009:   .word        __divsi3                              #  294: 00000000
.Lrel010:   .word        __divsi3                              #  298: 00000000

# Function @ .irom0.text+0x29c
# Local variables/stack:
#     (local0):  word      @ -0x20
#     (local1):  word      @ -0x1c
#     (local2):  word      @ -0x18
#     (local3):  word      @ -0x14
#     (local4):  word[4]   @ -0x10
.literal_position
sdk_chip_v6_rxmax_ext_ana:
            movi.n       a3, 1 /* 0x00000001 */                #  29c: 0c13
            movi.n       a4, 5 /* 0x00000005 */                #  29e: 0c54
            movi.n       a5, 7 /* 0x00000007 */                #  2a0: 0c75
            movi.n       a6, 0 /* 0x00000000 */                #  2a2: 0c06
            addi         a1, a1, -32 /* (local0) */            #  2a4: 12c1e0
            s32i.n       a13, a1, 8 /* a13 -> [(local2)] */    #  2a7: d921
            s32i.n       a15, a1, 16 /* a15 -> [(local4)] */   #  2a9: f941
            s32i.n       a12, a1, 4 /* a12 -> [(local1)] */    #  2ab: c911
            s32i.n       a14, a1, 12 /* a14 -> [(local3)] */   #  2ad: e931
            movi         a14, .Lrel008 /* sdk_g_phyFuns */     #  2af: e1f8ff
            s32i.n       a0, a1, 0 /* a0 -> [(local0)] */      #  2b2: 0901
            l32i.n       a0, a14, 0 /* [sdk_g_phyFuns] */      #  2b4: 080e
            mov.n        a12, a2 /* arg0 */                    #  2b6: cd02
            l32i         a0, a0, 148 /* [[sdk_g_phyFuns]+0x94] */ #  2b8: 022025
            movi         a2, 98 /* 0x00000062 */               #  2bb: 22a062
            callx0       a0 /* [[sdk_g_phyFuns]+0x94] */       #  2be: c00000
            movi.n       a13, 0 /* 0x00000000 */               #  2c1: 0c0d
            mov.n        a15, a2                               #  2c3: fd02
            movi         a3, -340 /* 0xfffffeac */             #  2c5: 32aeac
            addx2        a2, a2, a2                            #  2c8: 202290
            addx8        a2, a2, a3                            #  2cb: 3022b0
            movi         a3, 227 /* 0x000000e3 */              #  2ce: 32a0e3
            movi         a0, .Lrel009 /* __divsi3 */           #  2d1: 01f0ff
            callx0       a0 /* __divsi3 */                     #  2d4: c00000
            slli         a5, a2, 16                            #  2d7: 005211
            movi.n       a4, 15 /* 0x0000000f */               #  2da: 0cf4
            mov.n        a0, a4 /* 0x0000000f */               #  2dc: 0d04
            srai         a5, a5, 16                            #  2de: 505031
            mov.n        a2, a13 /* 0x00000000 */              #  2e1: 2d0d
            movgez       a2, a5, a5                            #  2e3: 5025b3
            bgei         a2, 16, .Lbr005                       #  2e6: e6b201
            mov.n        a0, a2                                #  2e9: 0d02
.Lbr005:    movi         a3, 207 /* 0x000000cf */              #  2eb: 32a0cf
            addx2        a2, a15, a15                          #  2ee: f02f90
            subx8        a2, a2, a15                           #  2f1: f022f0
            addi         a2, a2, 29                            #  2f4: 22c21d
            slli         a15, a0, 16                           #  2f7: 00f011
            srai         a15, a15, 16                          #  2fa: f0f031
            movi         a0, .Lrel010 /* __divsi3 */           #  2fd: 01e6ff
            callx0       a0 /* __divsi3 */                     #  300: c00000
            l32i.n       a9, a14, 0 /* [sdk_g_phyFuns] */      #  303: 980e
            slli         a4, a2, 16                            #  305: 004211
            movi.n       a3, 15 /* 0x0000000f */               #  308: 0cf3
            mov.n        a0, a3 /* 0x0000000f */               #  30a: 0d03
            srai         a4, a4, 16                            #  30c: 404031
            l32i         a9, a9, 156 /* [[sdk_g_phyFuns]+0x9c] */ #  30f: 922927
            movgez       a13, a4, a4                           #  312: 40d4b3
            bgei         a13, 16, .Lbr006                      #  315: e6bd01
            mov.n        a0, a13                               #  318: 0d0d
.Lbr006:    slli         a13, a0, 16                           #  31a: 00d011
            srai         a13, a13, 16                          #  31d: d0d031
            bltui        a12, 3, .Lbr008                       #  320: b63c1c
            movi.n       a2, 8 /* 0x00000008 */                #  323: 0c82
            blti         a15, 8, .Lbr007                       #  325: a68f01
            movi.n       a2, -8 /* 0xfffffff8 */               #  328: 7c82
.Lbr007:    movi.n       a3, 0 /* 0x00000000 */                #  32a: 0c03
            movi.n       a4, 4 /* 0x00000004 */                #  32c: 0c44
            movi.n       a5, 3 /* 0x00000003 */                #  32e: 0c35
            movi.n       a6, 0 /* 0x00000000 */                #  330: 0c06
            add.n        a7, a15, a2                           #  332: 2a7f
            extui        a7, a7, 0, 8                          #  334: 707074
            movi         a2, 100 /* 0x00000064 */              #  337: 22a064
            callx0       a9 /* [[sdk_g_phyFuns]+0x9c] */       #  33a: c00900
            j            .Lbr009                               #  33d: 060400
.Lbr008:    extui        a7, a15, 0, 8                         #  340: f07074
            movi         a2, 100 /* 0x00000064 */              #  343: 22a064
            movi.n       a3, 0 /* 0x00000000 */                #  346: 0c03
            movi.n       a4, 4 /* 0x00000004 */                #  348: 0c44
            movi.n       a5, 3 /* 0x00000003 */                #  34a: 0c35
            movi.n       a6, 0 /* 0x00000000 */                #  34c: 0c06
            callx0       a9 /* [[sdk_g_phyFuns]+0x9c] */       #  34e: c00900
.Lbr009:    l32i.n       a9, a14, 0 /* [sdk_g_phyFuns] */      #  351: 980e
            movi.n       a0, 8 /* 0x00000008 */                #  353: 0c80
            l32i         a9, a9, 156 /* [[sdk_g_phyFuns]+0x9c] */ #  355: 922927
            bltui        a12, 2, .Lbr011                       #  358: b62c1a
            blti         a13, 8, .Lbr010                       #  35b: a68d01
            movi.n       a0, -8 /* 0xfffffff8 */               #  35e: 7c80
.Lbr010:    movi         a2, 100 /* 0x00000064 */              #  360: 22a064
            movi.n       a3, 0 /* 0x00000000 */                #  363: 0c03
            movi.n       a4, 7 /* 0x00000007 */                #  365: 0c74
            movi.n       a5, 3 /* 0x00000003 */                #  367: 0c35
            movi.n       a6, 0 /* 0x00000000 */                #  369: 0c06
            add.n        a7, a13, a0                           #  36b: 0a7d
            extui        a7, a7, 0, 8                          #  36d: 707074
            callx0       a9 /* [[sdk_g_phyFuns]+0x9c] */       #  370: c00900
            j            .Lbr012                               #  373: 060400
.Lbr011:    extui        a7, a13, 0, 8                         #  376: d07074
            movi         a2, 100 /* 0x00000064 */              #  379: 22a064
            movi.n       a3, 0 /* 0x00000000 */                #  37c: 0c03
            movi.n       a4, 7 /* 0x00000007 */                #  37e: 0c74
            movi.n       a5, 3 /* 0x00000003 */                #  380: 0c35
            movi.n       a6, 0 /* 0x00000000 */                #  382: 0c06
            callx0       a9 /* [[sdk_g_phyFuns]+0x9c] */       #  384: c00900
.Lbr012:    l32i.n       a9, a14, 0 /* [sdk_g_phyFuns] */      #  387: 980e
            l32i         a9, a9, 156 /* [[sdk_g_phyFuns]+0x9c] */ #  389: 922927
            beqz.n       a12, .Lbr013                          #  38c: ac6c
            movi         a2, 97 /* 0x00000061 */               #  38e: 22a061
            movi.n       a3, 1 /* 0x00000001 */                #  391: 0c13
            movi.n       a4, 5 /* 0x00000005 */                #  393: 0c54
            movi.n       a5, 3 /* 0x00000003 */                #  395: 0c35
            movi.n       a6, 2 /* 0x00000002 */                #  397: 0c26
            movi.n       a7, 3 /* 0x00000003 */                #  399: 0c37
            callx0       a9 /* [[sdk_g_phyFuns]+0x9c] */       #  39b: c00900
            movi         a2, 97 /* 0x00000061 */               #  39e: 22a061
            movi.n       a3, 1 /* 0x00000001 */                #  3a1: 0c13
            movi.n       a4, 5 /* 0x00000005 */                #  3a3: 0c54
            movi.n       a5, 1 /* 0x00000001 */                #  3a5: 0c15
            l32i.n       a0, a14, 0 /* [sdk_g_phyFuns] */      #  3a7: 080e
            movi.n       a6, 0 /* 0x00000000 */                #  3a9: 0c06
            l32i         a0, a0, 156 /* [[sdk_g_phyFuns]+0x9c] */ #  3ab: 022027
            movi.n       a7, 3 /* 0x00000003 */                #  3ae: 0c37
            callx0       a0 /* [[sdk_g_phyFuns]+0x9c] */       #  3b0: c00000
            j            .Lbr014                               #  3b3: 060900
.Lbr013:    movi         a2, 97 /* 0x00000061 */               #  3b6: 22a061
            movi.n       a3, 1 /* 0x00000001 */                #  3b9: 0c13
            movi.n       a4, 5 /* 0x00000005 */                #  3bb: 0c54
            movi.n       a5, 3 /* 0x00000003 */                #  3bd: 0c35
            movi.n       a6, 2 /* 0x00000002 */                #  3bf: 0c26
            movi.n       a7, 0 /* 0x00000000 */                #  3c1: 0c07
            callx0       a9 /* [[sdk_g_phyFuns]+0x9c] */       #  3c3: c00900
            movi         a2, 97 /* 0x00000061 */               #  3c6: 22a061
            movi.n       a3, 1 /* 0x00000001 */                #  3c9: 0c13
            movi.n       a4, 5 /* 0x00000005 */                #  3cb: 0c54
            movi.n       a5, 1 /* 0x00000001 */                #  3cd: 0c15
            l32i.n       a0, a14, 0 /* [sdk_g_phyFuns] */      #  3cf: 080e
            movi.n       a6, 0 /* 0x00000000 */                #  3d1: 0c06
            l32i         a0, a0, 156 /* [[sdk_g_phyFuns]+0x9c] */ #  3d3: 022027
            movi.n       a7, 0 /* 0x00000000 */                #  3d6: 0c07
            callx0       a0 /* [[sdk_g_phyFuns]+0x9c] */       #  3d8: c00000
.Lbr014:    l32i.n       a12, a1, 4 /* [(local1)] */           #  3db: c811
            l32i.n       a13, a1, 8 /* [(local2)] */           #  3dd: d821
            l32i.n       a14, a1, 12 /* [(local3)] */          #  3df: e831
            l32i.n       a15, a1, 16 /* [(local4)] */          #  3e1: f841
            l32i.n       a0, a1, 0 /* [(local0)] */            #  3e3: 0801
            addi         a1, a1, 32 /* (top of frame) */       #  3e5: 12c120
            ret.n                                              #  3e8: 0df0

            .balign      4
.Lrel011:   .word        sdk_g_phyFuns                         #  3ec: 00000000

# Function @ .irom0.text+0x3f0
# Local variables/stack:
#     (local0):  word[4]   @ -0x10
.literal_position
sdk_ram_chip_v6_rx_init:
            movi         a2, 97 /* 0x00000061 */               #  3f0: 22a061
            addi         a1, a1, -16 /* (local0) */            #  3f3: 12c1f0
            s32i.n       a0, a1, 0 /* a0 -> [(local0)] */      #  3f6: 0901
            movi         a0, .Lrel011 /* sdk_g_phyFuns */      #  3f8: 01fdff
            movi.n       a3, 1 /* 0x00000001 */                #  3fb: 0c13
            l32i.n       a0, a0, 0 /* [sdk_g_phyFuns] */       #  3fd: 0800
            movi.n       a4, 8 /* 0x00000008 */                #  3ff: 0c84
            l32i         a0, a0, 152 /* [[sdk_g_phyFuns]+0x98] */ #  401: 022026
            movi.n       a5, 17 /* 0x00000011 */               #  404: 1c15
            callx0       a0 /* [[sdk_g_phyFuns]+0x98] */       #  406: c00000
            movi.n       a2, 0 /* 0x00000000 */                #  409: 0c02
            call0        sdk_chip_v6_rxmax_ext_ana             #  40b: 050000
            l32i.n       a0, a1, 0 /* [(local0)] */            #  40e: 0801
            addi         a1, a1, 16 /* (top of frame) */       #  410: 12c110
            ret.n                                              #  413: 0df0

            .balign      4
.Llit010:   .word        0x60000a00                            #  418: 000a0060
.Llit011:   .word        0x00200000                            #  41c: 00002000
.Llit012:   .word        0xff7fffff                            #  420: ffff7fff
.Lrel012:   .word        sdk_g_phyFuns                         #  424: 00000000
.Lrel013:   .word        sdk_g_phyFuns                         #  428: 00000000
.Llit013:   .word        0x60000a00                            #  42c: 000a0060
.Lrel014:   .word        sdk_g_phyFuns                         #  430: 00000000
.Lrel015:   .word        sdk_ets_delay_us                      #  434: 00000000

# Function @ .irom0.text+0x438
# Local variables/stack:
#     (local0):  word[4]   @ -0x10
.literal_position
sdk_tsen_meas:
            addi         a1, a1, -16 /* (local0) */            #  438: 12c1f0
            s32i.n       a0, a1, 0 /* a0 -> [(local0)] */      #  43b: 0901
            movi         a7, -33 /* 0xffffffdf */              #  43d: 72afdf
            movi         a2, .Llit010 /* 0x60000a00 */         #  440: 21f6ff
            memw                                               #  443: c02000
            l32i         a6, a2, 0x350 /* [0x60000d50] */      #  446: 6222d4
            and          a6, a6, a7                            #  449: 706610
            memw                                               #  44c: c02000
            s32i         a6, a2, 0x350 /* a6 -> [0x60000d50] */ #  44f: 6262d4
            movi         a5, .Llit011 /* 0x00200000 */         #  452: 51f2ff
            memw                                               #  455: c02000
            l32i         a4, a2, 0x35c /* [0x60000d5c] */      #  458: 4222d7
            or           a4, a4, a5                            #  45b: 504420
            memw                                               #  45e: c02000
            s32i         a4, a2, 0x35c /* a4 -> [0x60000d5c] */ #  461: 4262d7
            movi         a3, .Llit012 /* 0xff7fffff */         #  464: 31efff
            memw                                               #  467: c02000
            l32i         a0, a2, 0x35c /* [0x60000d5c] */      #  46a: 0222d7
            and          a0, a0, a3                            #  46d: 300010
            memw                                               #  470: c02000
            s32i         a0, a2, 0x35c /* a0 -> [0x60000d5c] */ #  473: 0262d7
            movi         a2, 200 /* 0x000000c8 */              #  476: 22a0c8
            movi         a0, .Lrel015 /* sdk_ets_delay_us */   #  479: 01eeff
            callx0       a0 /* sdk_ets_delay_us */             #  47c: c00000
            movi         a2, 108 /* 0x0000006c */              #  47f: 22a06c
            movi.n       a3, 2 /* 0x00000002 */                #  482: 0c23
            movi.n       a4, 0 /* 0x00000000 */                #  484: 0c04
            movi         a0, .Lrel012 /* sdk_g_phyFuns */      #  486: 01e7ff
            movi.n       a5, 6 /* 0x00000006 */                #  489: 0c65
            l32i.n       a0, a0, 0 /* [sdk_g_phyFuns] */       #  48b: 0800
            movi.n       a6, 6 /* 0x00000006 */                #  48d: 0c66
            l32i         a0, a0, 156 /* [[sdk_g_phyFuns]+0x9c] */ #  48f: 022027
            movi.n       a7, 0 /* 0x00000000 */                #  492: 0c07
            callx0       a0 /* [[sdk_g_phyFuns]+0x9c] */       #  494: c00000
            movi         a2, 108 /* 0x0000006c */              #  497: 22a06c
            movi.n       a3, 2 /* 0x00000002 */                #  49a: 0c23
            movi.n       a4, 0 /* 0x00000000 */                #  49c: 0c04
            movi         a0, .Lrel013 /* sdk_g_phyFuns */      #  49e: 01e2ff
            movi.n       a5, 6 /* 0x00000006 */                #  4a1: 0c65
            l32i.n       a0, a0, 0 /* [sdk_g_phyFuns] */       #  4a3: 0800
            movi.n       a6, 6 /* 0x00000006 */                #  4a5: 0c66
            l32i         a0, a0, 156 /* [[sdk_g_phyFuns]+0x9c] */ #  4a7: 022027
            movi.n       a7, 1 /* 0x00000001 */                #  4aa: 0c17
            callx0       a0 /* [[sdk_g_phyFuns]+0x9c] */       #  4ac: c00000
            movi.n       a4, 32 /* 0x00000020 */               #  4af: 2c04
            memw                                               #  4b1: c02000
            movi         a3, .Llit013 /* 0x60000a00 */         #  4b4: 31deff
            l32i         a2, a3, 0x350 /* [0x60000d50] */      #  4b7: 2223d4
            or           a2, a2, a4                            #  4ba: 402220
            memw                                               #  4bd: c02000
            movi.n       a4, 2 /* 0x00000002 */                #  4c0: 0c24
            movi.n       a5, 7 /* 0x00000007 */                #  4c2: 0c75
            movi         a0, .Lrel014 /* sdk_g_phyFuns */      #  4c4: 01dbff
            movi.n       a6, 0 /* 0x00000000 */                #  4c7: 0c06
            l32i.n       a0, a0, 0 /* [sdk_g_phyFuns] */       #  4c9: 0800
            s32i         a2, a3, 0x350 /* a2 -> [0x60000d50] */ #  4cb: 2263d4
            movi         a2, 108 /* 0x0000006c */              #  4ce: 22a06c
            l32i         a0, a0, 148 /* [[sdk_g_phyFuns]+0x94] */ #  4d1: 022025
            movi.n       a3, 2 /* 0x00000002 */                #  4d4: 0c23
            callx0       a0 /* [[sdk_g_phyFuns]+0x94] */       #  4d6: c00000
            l32i.n       a0, a1, 0 /* [(local0)] */            #  4d9: 0801
            addi         a1, a1, 16 /* (top of frame) */       #  4db: 12c110
            ret.n                                              #  4de: 0df0

.Lrel016:   .word        sdk_g_phyFuns                         #  4e0: 00000000
.Llit014:   .word        0x00800000                            #  4e4: 00008000
.Llit015:   .word        0x60000a00                            #  4e8: 000a0060
.Llit016:   .word        0xffdfffff                            #  4ec: ffffdfff
.Lrel017:   .word        sdk_ets_delay_us                      #  4f0: 00000000
.Lrel018:   .word        sdk_read_sar_dout                     #  4f4: 00000000

# Function @ .irom0.text+0x4f8
# Local variables/stack:
#     (local0):  word      @ -0x20
#     (local1):  word      @ -0x1c
#     (local2):  word      @ -0x18
#     (local3):  word      @ -0x14
#     (local4):  word      @ -0x10
#     (local5):  word[3]   @ -0xc
.literal_position
sdk_readvdd33:
            addi         a1, a1, -48 /* (FP)-0x30 */           #  4f8: 12c1d0
            s32i.n       a13, a1, 28 /* a13 -> [(local3)] */   #  4fb: d971
            movi         a13, .Lrel016 /* sdk_g_phyFuns */     #  4fd: d1f8ff
            s32i.n       a0, a1, 20 /* a0 -> [(local1)] */     #  500: 0951
            l32i.n       a0, a13, 0 /* [sdk_g_phyFuns] */      #  502: 080d
            s32i.n       a12, a1, 24 /* a12 -> [(local2)] */   #  504: c961
            l32i         a0, a0, 160 /* [[sdk_g_phyFuns]+0xa0] */ #  506: 022028
            s32i.n       a14, a1, 32 /* a14 -> [(local4)] */   #  509: e981
            callx0       a0 /* [[sdk_g_phyFuns]+0xa0] */       #  50b: c00000
            l32i.n       a0, a13, 0 /* [sdk_g_phyFuns] */      #  50e: 080d
            movi.n       a2, 6 /* 0x00000006 */                #  510: 0c62
            l32i         a0, a0, 176 /* [[sdk_g_phyFuns]+0xb0] */ #  512: 02202c
            movi.n       a3, 1 /* 0x00000001 */                #  515: 0c13
            callx0       a0 /* [[sdk_g_phyFuns]+0xb0] */       #  517: c00000
            movi.n       a3, 2 /* 0x00000002 */                #  51a: 0c23
            movi.n       a4, 9 /* 0x00000009 */                #  51c: 0c94
            movi.n       a5, 2 /* 0x00000002 */                #  51e: 0c25
            movi.n       a6, 0 /* 0x00000000 */                #  520: 0c06
            l32i.n       a0, a13, 0 /* [sdk_g_phyFuns] */      #  522: 080d
            mov.n        a14, a2                               #  524: ed02
            l32i         a0, a0, 148 /* [[sdk_g_phyFuns]+0x94] */ #  526: 022025
            movi         a2, 107 /* 0x0000006b */              #  529: 22a06b
            callx0       a0 /* [[sdk_g_phyFuns]+0x94] */       #  52c: c00000
            movi.n       a3, 2 /* 0x00000002 */                #  52f: 0c23
            movi.n       a4, 0 /* 0x00000000 */                #  531: 0c04
            movi.n       a5, 5 /* 0x00000005 */                #  533: 0c55
            movi.n       a6, 5 /* 0x00000005 */                #  535: 0c56
            l32i.n       a0, a13, 0 /* [sdk_g_phyFuns] */      #  537: 080d
            s32i.n       a2, a1, 16 /* a2 -> [(local0)] */     #  539: 2941
            l32i         a0, a0, 148 /* [[sdk_g_phyFuns]+0x94] */ #  53b: 022025
            movi         a2, 108 /* 0x0000006c */              #  53e: 22a06c
            callx0       a0 /* [[sdk_g_phyFuns]+0x94] */       #  541: c00000
            movi.n       a3, 1 /* 0x00000001 */                #  544: 0c13
            l32i.n       a0, a13, 0 /* [sdk_g_phyFuns] */      #  546: 080d
            mov.n        a12, a2                               #  548: cd02
            movi.n       a4, 2 /* 0x00000002 */                #  54a: 0c24
            movi.n       a2, 6 /* 0x00000006 */                #  54c: 0c62
            or           a4, a14, a4                           #  54e: 404e20
            l32i         a0, a0, 172 /* [[sdk_g_phyFuns]+0xac] */ #  551: 02202b
            extui        a4, a4, 0, 16                         #  554: 4040f4
            callx0       a0 /* [[sdk_g_phyFuns]+0xac] */       #  557: c00000
            movi         a2, 107 /* 0x0000006b */              #  55a: 22a06b
            movi.n       a3, 2 /* 0x00000002 */                #  55d: 0c23
            movi.n       a4, 9 /* 0x00000009 */                #  55f: 0c94
            movi.n       a5, 7 /* 0x00000007 */                #  561: 0c75
            movi.n       a6, 7 /* 0x00000007 */                #  563: 0c76
            l32i.n       a0, a13, 0 /* [sdk_g_phyFuns] */      #  565: 080d
            movi.n       a7, 1 /* 0x00000001 */                #  567: 0c17
            l32i         a0, a0, 156 /* [[sdk_g_phyFuns]+0x9c] */ #  569: 022027
            s32i.n       a12, a1, 36 /* a12 -> [(local5)] */   #  56c: c991
            callx0       a0 /* [[sdk_g_phyFuns]+0x9c] */       #  56e: c00000
            movi         a2, 107 /* 0x0000006b */              #  571: 22a06b
            movi.n       a3, 2 /* 0x00000002 */                #  574: 0c23
            movi.n       a4, 9 /* 0x00000009 */                #  576: 0c94
            movi.n       a5, 2 /* 0x00000002 */                #  578: 0c25
            l32i.n       a0, a13, 0 /* [sdk_g_phyFuns] */      #  57a: 080d
            movi.n       a6, 0 /* 0x00000000 */                #  57c: 0c06
            l32i         a0, a0, 156 /* [[sdk_g_phyFuns]+0x9c] */ #  57e: 022027
            movi.n       a7, 0 /* 0x00000000 */                #  581: 0c07
            callx0       a0 /* [[sdk_g_phyFuns]+0x9c] */       #  583: c00000
            movi.n       a12, 2 /* 0x00000002 */               #  586: 0c2c
            movi         a2, 108 /* 0x0000006c */              #  588: 22a06c
            movi.n       a3, 2 /* 0x00000002 */                #  58b: 0c23
            movi.n       a4, 0 /* 0x00000000 */                #  58d: 0c04
            movi.n       a5, 5 /* 0x00000005 */                #  58f: 0c55
            l32i.n       a0, a13, 0 /* [sdk_g_phyFuns] */      #  591: 080d
            movi.n       a6, 5 /* 0x00000005 */                #  593: 0c56
            l32i         a0, a0, 156 /* [[sdk_g_phyFuns]+0x9c] */ #  595: 022027
            movi.n       a7, 1 /* 0x00000001 */                #  598: 0c17
            callx0       a0 /* [[sdk_g_phyFuns]+0x9c] */       #  59a: c00000
            movi         a9, .Llit014 /* 0x00800000 */         #  59d: 91d1ff
            movi         a3, .Llit015 /* 0x60000a00 */         #  5a0: 31d2ff
            memw                                               #  5a3: c02000
            l32i         a8, a3, 0x35c /* [0x60000d5c] */      #  5a6: 8223d7
            or           a8, a8, a9                            #  5a9: 908820
            memw                                               #  5ac: c02000
            s32i         a8, a3, 0x35c /* a8 -> [0x60000d5c] */ #  5af: 8263d7
            movi         a7, .Llit016 /* 0xffdfffff */         #  5b2: 71ceff
            memw                                               #  5b5: c02000
            l32i         a6, a3, 0x35c /* [0x60000d5c] */      #  5b8: 6223d7
            and          a6, a6, a7                            #  5bb: 706610
            memw                                               #  5be: c02000
            s32i         a6, a3, 0x35c /* a6 -> [0x60000d5c] */ #  5c1: 6263d7
            movi.n       a5, -3 /* 0xfffffffd */               #  5c4: 7cd5
            memw                                               #  5c6: c02000
            l32i         a4, a3, 0x350 /* [0x60000d50] */      #  5c9: 4223d4
            and          a4, a4, a5                            #  5cc: 504410
            memw                                               #  5cf: c02000
            s32i         a4, a3, 0x350 /* a4 -> [0x60000d50] */ #  5d2: 4263d4
            memw                                               #  5d5: c02000
            l32i         a2, a3, 0x350 /* [0x60000d50] */      #  5d8: 2223d4
            or           a2, a2, a12                           #  5db: c02220
            memw                                               #  5de: c02000
            s32i         a2, a3, 0x350 /* a2 -> [0x60000d50] */ #  5e1: 2263d4
            movi.n       a2, 25 /* 0x00000019 */               #  5e4: 1c92
            movi         a0, .Lrel017 /* sdk_ets_delay_us */   #  5e6: 01c2ff
            callx0       a0 /* sdk_ets_delay_us */             #  5e9: c00000
            mov.n        a2, a1 /* (FP)-0x30 */                #  5ec: 2d01
            movi         a0, .Lrel018 /* sdk_read_sar_dout */  #  5ee: 01c1ff
            callx0       a0 /* sdk_read_sar_dout */            #  5f1: c00000
            movi.n       a0, 0 /* 0x00000000 */                #  5f4: 0c00
            movi.n       a12, 0 /* 0x00000000 */               #  5f6: 0c0c
            mov.n        a2, a1 /* (FP)-0x30 */                #  5f8: 2d01
.Lbr015:    addi.n       a4, a0, 1                             #  5fa: 1b40
            addx2        a3, a0, a2                            #  5fc: 203090
            l16ui        a3, a3, 0                             #  5ff: 321300
            extui        a0, a4, 0, 8                          #  602: 400074
            add.n        a12, a3, a12                          #  605: cac3
            extui        a12, a12, 0, 16                       #  607: c0c0f4
            bnei         a0, 8, .Lbr015                        #  60a: 6680ec
            extui        a4, a14, 0, 16                        #  60d: e040f4
            l32i.n       a0, a13, 0 /* [sdk_g_phyFuns] */      #  610: 080d
            movi.n       a2, 6 /* 0x00000006 */                #  612: 0c62
            l32i         a0, a0, 172 /* [[sdk_g_phyFuns]+0xac] */ #  614: 02202b
            movi.n       a3, 1 /* 0x00000001 */                #  617: 0c13
            callx0       a0 /* [[sdk_g_phyFuns]+0xac] */       #  619: c00000
            movi         a2, 107 /* 0x0000006b */              #  61c: 22a06b
            movi.n       a3, 2 /* 0x00000002 */                #  61f: 0c23
            movi.n       a4, 9 /* 0x00000009 */                #  621: 0c94
            movi.n       a5, 7 /* 0x00000007 */                #  623: 0c75
            l32i.n       a0, a13, 0 /* [sdk_g_phyFuns] */      #  625: 080d
            movi.n       a6, 7 /* 0x00000007 */                #  627: 0c76
            l32i         a0, a0, 156 /* [[sdk_g_phyFuns]+0x9c] */ #  629: 022027
            movi.n       a7, 0 /* 0x00000000 */                #  62c: 0c07
            callx0       a0 /* [[sdk_g_phyFuns]+0x9c] */       #  62e: c00000
            l32i.n       a14, a1, 36 /* [(local5)] */          #  631: e891
            movi         a2, 107 /* 0x0000006b */              #  633: 22a06b
            movi.n       a3, 2 /* 0x00000002 */                #  636: 0c23
            movi.n       a4, 9 /* 0x00000009 */                #  638: 0c94
            movi.n       a5, 2 /* 0x00000002 */                #  63a: 0c25
            movi.n       a6, 0 /* 0x00000000 */                #  63c: 0c06
            l32i.n       a0, a13, 0 /* [sdk_g_phyFuns] */      #  63e: 080d
            l32i.n       a7, a1, 16 /* [(local0)] */           #  640: 7841
            l32i         a0, a0, 156 /* [[sdk_g_phyFuns]+0x9c] */ #  642: 022027
            extui        a7, a7, 0, 8                          #  645: 707074
            callx0       a0 /* [[sdk_g_phyFuns]+0x9c] */       #  648: c00000
            extui        a7, a14, 0, 8                         #  64b: e07074
            movi         a2, 108 /* 0x0000006c */              #  64e: 22a06c
            movi.n       a3, 2 /* 0x00000002 */                #  651: 0c23
            movi.n       a4, 0 /* 0x00000000 */                #  653: 0c04
            l32i.n       a0, a13, 0 /* [sdk_g_phyFuns] */      #  655: 080d
            movi.n       a5, 5 /* 0x00000005 */                #  657: 0c55
            l32i         a0, a0, 156 /* [[sdk_g_phyFuns]+0x9c] */ #  659: 022027
            movi.n       a6, 5 /* 0x00000005 */                #  65c: 0c56
            callx0       a0 /* [[sdk_g_phyFuns]+0x9c] */       #  65e: c00000
            l32i.n       a0, a13, 0 /* [sdk_g_phyFuns] */      #  661: 080d
            l32i         a0, a0, 188 /* [[sdk_g_phyFuns]+0xbc] */ #  663: 02202f
            callx0       a0 /* [[sdk_g_phyFuns]+0xbc] */       #  666: c00000
            l32i.n       a0, a1, 20 /* [(local1)] */           #  669: 0851
            l32i.n       a13, a1, 28 /* [(local3)] */          #  66b: d871
            slli         a2, a12, 10                           #  66d: 602c11
            l32i.n       a14, a1, 32 /* [(local4)] */          #  670: e881
            l32i.n       a12, a1, 24 /* [(local2)] */          #  672: c861
            addmi        a2, a2, 2048                          #  674: 22d208
            extui        a2, a2, 12, 16                        #  677: 202cf4
            addi         a1, a1, 48 /* (top of frame) */       #  67a: 12c130
            ret.n                                              #  67d: 0df0

            .balign      4
.Llit017:   .word        0x00000d33                            #  680: 330d0000
.Lrel019:   .word        sdk_chip6_phy_init_ctrl               #  684: 00000000
.Llit018:   .word        0x00000d33                            #  688: 330d0000
.Lrel020:   .word        sdk_g_phyFuns                         #  68c: 00000000
.Llit019:   .word        0x00000d33                            #  690: 330d0000
.Lrel021:   .word        sdk_chip6_sleep_params                #  694: 00000000

# Function @ .irom0.text+0x698
# Local variables/stack:
#     (local0):  word      @ -0x20
#     (local1):  word      @ -0x1c
#     (local2):  word      @ -0x18
#     (local3):  word      @ -0x14
#     (local4):  word[4]   @ -0x10
.literal_position
sdk_txpwr_offset:
            movi         a3, .Llit018 /* 0x00000d33 */         #  698: 31fcff
            addi         a1, a1, -32 /* (local0) */            #  69b: 12c1e0
            s32i.n       a2, a1, 0 /* arg0 -> [(local0)] */    #  69e: 2901
            s32i.n       a12, a1, 8 /* a12 -> [(local2)] */    #  6a0: c921
            s32i.n       a14, a1, 16 /* a14 -> [(local4)] */   #  6a2: e941
            s32i.n       a0, a1, 4 /* a0 -> [(local1)] */      #  6a4: 0911
            s32i.n       a13, a1, 12 /* a13 -> [(local3)] */   #  6a6: d931
            movi         a13, .Lrel019 /* sdk_chip6_phy_init_ctrl */ #  6a8: d1f7ff
            movi         a0, .Llit017 /* 0x00000d33 */         #  6ab: 01f5ff
            l8ui         a4, a13, 108 /* [sdk_chip6_phy_init_ctrl+0x6c] */ #  6ae: 420d6c
            movi         a14, 102 /* 0x00000066 */             #  6b1: e2a066
            mul16s       a14, a4, a14                          #  6b4: e0e4d1
            extui        a14, a14, 0, 16                       #  6b7: e0e0f4
            moveqz       a14, a3, a4                           #  6ba: 40e383
            bltu         a14, a0, .Lbr016                      #  6bd: 073e04
            movi.n       a12, 0 /* 0x00000000 */               #  6c0: 0c0c
            j            .Lbr017                               #  6c2: 060b00
.Lbr016:    movi         a12, .Lrel020 /* sdk_g_phyFuns */     #  6c5: c1f1ff
            l32i.n       a0, a12, 0 /* [sdk_g_phyFuns] */      #  6c8: 080c
            mov.n        a2, a14                               #  6ca: 2d0e
            l32i.n       a0, a0, 56 /* [[sdk_g_phyFuns]+0x38] */ #  6cc: 08e0
            movi.n       a3, 3 /* 0x00000003 */                #  6ce: 0c33
            callx0       a0 /* [[sdk_g_phyFuns]+0x38] */       #  6d0: c00000
            movi.n       a3, 3 /* 0x00000003 */                #  6d3: 0c33
            l32i.n       a0, a12, 0 /* [sdk_g_phyFuns] */      #  6d5: 080c
            mov.n        a12, a2                               #  6d7: cd02
            l32i.n       a0, a0, 56 /* [[sdk_g_phyFuns]+0x38] */ #  6d9: 08e0
            movi         a2, .Llit019 /* 0x00000d33 */         #  6db: 21edff
            callx0       a0 /* [[sdk_g_phyFuns]+0x38] */       #  6de: c00000
            sub          a12, a12, a2                          #  6e1: 20ccc0
            slli         a12, a12, 1                           #  6e4: f0cc11
            slli         a12, a12, 16                          #  6e7: 00cc11
            srai         a12, a12, 16                          #  6ea: c0c031
            addi.n       a12, a12, 2                           #  6ed: 2bcc
            srai         a12, a12, 2                           #  6ef: c0c221
.Lbr017:    call0        sdk_tsen_meas                         #  6f2: 050000
            movi.n       a0, 0 /* 0x00000000 */                #  6f5: 0c00
            l32i.n       a3, a1, 0 /* [(local0)] */            #  6f7: 3801
            movi         a5, .Lrel021 /* .Lrel021 */           #  6f9: 51e6ff
            add.n        a12, a3, a12                          #  6fc: cac3
            slli         a12, a12, 16                          #  6fe: 00cc11
            srai         a12, a12, 16                          #  701: c0c031
.Lbr018:    add.n        a6, a0, a5                            #  704: 5a60
            addi.n       a7, a0, 1                             #  706: 1b70
            add.n        a4, a0, a13                           #  708: da40
            l8ui         a4, a4, 36                            #  70a: 420424
            extui        a0, a7, 0, 8                          #  70d: 700074
            add.n        a4, a12, a4                           #  710: 4a4c
            s8i          a4, a6, 104                           #  712: 424668
            bnei         a0, 6, .Lbr018                        #  715: 6660eb
            l32i.n       a13, a1, 12 /* [(local3)] */          #  718: d831
            movi         a0, -127 /* 0xffffff81 */             #  71a: 02af81
            slli         a7, a14, 16                           #  71d: 007e11
            slli         a6, a2, 8                             #  720: 806211
            l32i.n       a14, a1, 16 /* [(local4)] */          #  723: e841
            mov.n        a2, a12                               #  725: 2d0c
            add.n        a6, a6, a7                            #  727: 7a66
            blt          a12, a0, .Lbr019                      #  729: 072c01
            mov.n        a0, a12                               #  72c: 0d0c
.Lbr019:    extui        a7, a0, 0, 8                          #  72e: 007074
            l32i.n       a12, a1, 8 /* [(local2)] */           #  731: c821
            l32i.n       a0, a1, 4 /* [(local1)] */            #  733: 0811
            add.n        a6, a6, a7                            #  735: 7a66
            s32i         a6, a5, 112                           #  737: 62651c
            addi         a1, a1, 32 /* (top of frame) */       #  73a: 12c120
            ret.n                                              #  73d: 0df0

            .balign      4
.Lrel022:   .word        sdk_g_phyFuns                         #  740: 00000000
.Lrel023:   .word        sdk_g_phyFuns                         #  744: 00000000
.Lrel024:   .word        sdk_g_phyFuns                         #  748: 00000000

# Function @ .irom0.text+0x74c
# Local variables/stack:
#     (local0):  word      @ -0x10
#     (local1):  word      @ -0xc
#     (local2):  word[2]   @ -0x8
.literal_position
sdk_set_txcap_reg:
            addi         a1, a1, -16 /* (local0) */            #  74c: 12c1f0
            s32i.n       a0, a1, 0 /* a0 -> [(local0)] */      #  74f: 0901
            s32i.n       a12, a1, 4 /* a12 -> [(local1)] */    #  751: c911
            s32i.n       a13, a1, 8 /* a13 -> [(local2)] */    #  753: d921
            mov.n        a12, a2 /* arg0 */                    #  755: cd02
            movi.n       a13, 0 /* 0x00000000 */               #  757: 0c0d
.Lbr020:    beqz         a13, .Lbr022                          #  759: 161d04
            beqi         a13, 1, .Lbr021                       #  75c: 261d20
            bnei         a13, 2, .Lbr023                       #  75f: 662d56
            movi         a2, 107 /* 0x0000006b */              #  762: 22a06b
            movi.n       a3, 2 /* 0x00000002 */                #  765: 0c23
            movi.n       a4, 2 /* 0x00000002 */                #  767: 0c24
            movi.n       a5, 6 /* 0x00000006 */                #  769: 0c65
            movi         a0, .Lrel022 /* .Lrel022 */           #  76b: 01f5ff
            movi.n       a6, 4 /* 0x00000004 */                #  76e: 0c46
            l32i.n       a0, a0, 0                             #  770: 0800
            add.n        a7, a12, a13                          #  772: da7c
            l32i         a0, a0, 156                           #  774: 022027
            l8ui         a7, a7, 0                             #  777: 720700
            callx0       a0                                    #  77a: c00000
            j            .Lbr023                               #  77d: 060e00
.Lbr021:    movi         a2, 107 /* 0x0000006b */              #  780: 22a06b
            movi.n       a3, 2 /* 0x00000002 */                #  783: 0c23
            movi.n       a4, 2 /* 0x00000002 */                #  785: 0c24
            movi.n       a5, 3 /* 0x00000003 */                #  787: 0c35
            movi         a0, .Lrel023 /* sdk_g_phyFuns */      #  789: 01eeff
            movi.n       a6, 0 /* 0x00000000 */                #  78c: 0c06
            l32i.n       a0, a0, 0 /* [sdk_g_phyFuns] */       #  78e: 0800
            add.n        a7, a12, a13                          #  790: da7c
            l32i         a0, a0, 156 /* [[sdk_g_phyFuns]+0x9c] */ #  792: 022027
            l8ui         a7, a7, 0                             #  795: 720700
            callx0       a0 /* [[sdk_g_phyFuns]+0x9c] */       #  798: c00000
            j            .Lbr023                               #  79b: 860600
.Lbr022:    movi         a2, 107 /* 0x0000006b */              #  79e: 22a06b
            movi.n       a3, 2 /* 0x00000002 */                #  7a1: 0c23
            movi.n       a4, 1 /* 0x00000001 */                #  7a3: 0c14
            movi.n       a5, 3 /* 0x00000003 */                #  7a5: 0c35
            movi         a0, .Lrel024 /* sdk_g_phyFuns */      #  7a7: 01e8ff
            movi.n       a6, 0 /* 0x00000000 */                #  7aa: 0c06
            l32i.n       a0, a0, 0 /* [sdk_g_phyFuns] */       #  7ac: 0800
            add.n        a7, a12, a13                          #  7ae: da7c
            l32i         a0, a0, 156 /* [[sdk_g_phyFuns]+0x9c] */ #  7b0: 022027
            l8ui         a7, a7, 0                             #  7b3: 720700
            callx0       a0 /* [[sdk_g_phyFuns]+0x9c] */       #  7b6: c00000
.Lbr023:    addi.n       a13, a13, 1                           #  7b9: 1bdd
            extui        a13, a13, 0, 8                        #  7bb: d0d074
            bnei         a13, 3, .Lbr020                       #  7be: 663d97
            l32i.n       a12, a1, 4 /* [(local1)] */           #  7c1: c811
            l32i.n       a13, a1, 8 /* [(local2)] */           #  7c3: d821
            l32i.n       a0, a1, 0 /* [(local0)] */            #  7c5: 0801
            addi         a1, a1, 16 /* (top of frame) */       #  7c7: 12c110
            ret.n                                              #  7ca: 0df0

.Lrel025:   .word        sdk_g_phyFuns                         #  7cc: 00000000

# Function @ .irom0.text+0x7d0
# Local variables/stack:
#     (local0):  word      @ -0x10
#     (local1):  word[3]   @ -0xc
.literal_position
sdk_ram_restart_cal:
            movi         a2, 98 /* 0x00000062 */               #  7d0: 22a062
            movi.n       a3, 1 /* 0x00000001 */                #  7d3: 0c13
            movi.n       a4, 0 /* 0x00000000 */                #  7d5: 0c04
            movi.n       a5, 6 /* 0x00000006 */                #  7d7: 0c65
            addi         a1, a1, -16 /* (local0) */            #  7d9: 12c1f0
            s32i.n       a12, a1, 4 /* a12 -> [(local1)] */    #  7dc: c911
            movi         a12, .Lrel025 /* sdk_g_phyFuns */     #  7de: c1fbff
            s32i.n       a0, a1, 0 /* a0 -> [(local0)] */      #  7e1: 0901
            l32i.n       a0, a12, 0 /* [sdk_g_phyFuns] */      #  7e3: 080c
            movi.n       a6, 6 /* 0x00000006 */                #  7e5: 0c66
            l32i         a0, a0, 156 /* [[sdk_g_phyFuns]+0x9c] */ #  7e7: 022027
            movi.n       a7, 1 /* 0x00000001 */                #  7ea: 0c17
            callx0       a0 /* [[sdk_g_phyFuns]+0x9c] */       #  7ec: c00000
            movi         a2, 98 /* 0x00000062 */               #  7ef: 22a062
            movi.n       a3, 1 /* 0x00000001 */                #  7f2: 0c13
            movi.n       a4, 0 /* 0x00000000 */                #  7f4: 0c04
            movi.n       a5, 5 /* 0x00000005 */                #  7f6: 0c55
            l32i.n       a0, a12, 0 /* [sdk_g_phyFuns] */      #  7f8: 080c
            movi.n       a6, 5 /* 0x00000005 */                #  7fa: 0c56
            l32i         a0, a0, 156 /* [[sdk_g_phyFuns]+0x9c] */ #  7fc: 022027
            movi.n       a7, 0 /* 0x00000000 */                #  7ff: 0c07
            callx0       a0 /* [[sdk_g_phyFuns]+0x9c] */       #  801: c00000
            movi         a2, 98 /* 0x00000062 */               #  804: 22a062
            movi.n       a3, 1 /* 0x00000001 */                #  807: 0c13
            movi.n       a4, 0 /* 0x00000000 */                #  809: 0c04
            movi.n       a5, 5 /* 0x00000005 */                #  80b: 0c55
            l32i.n       a0, a12, 0 /* [sdk_g_phyFuns] */      #  80d: 080c
            movi.n       a6, 5 /* 0x00000005 */                #  80f: 0c56
            l32i         a0, a0, 156 /* [[sdk_g_phyFuns]+0x9c] */ #  811: 022027
            movi.n       a7, 1 /* 0x00000001 */                #  814: 0c17
            callx0       a0 /* [[sdk_g_phyFuns]+0x9c] */       #  816: c00000
            movi         a2, 98 /* 0x00000062 */               #  819: 22a062
            movi.n       a3, 1 /* 0x00000001 */                #  81c: 0c13
            movi.n       a4, 0 /* 0x00000000 */                #  81e: 0c04
            movi.n       a5, 6 /* 0x00000006 */                #  820: 0c65
            l32i.n       a0, a12, 0 /* [sdk_g_phyFuns] */      #  822: 080c
            movi.n       a6, 6 /* 0x00000006 */                #  824: 0c66
            l32i         a0, a0, 156 /* [[sdk_g_phyFuns]+0x9c] */ #  826: 022027
            movi.n       a7, 0 /* 0x00000000 */                #  829: 0c07
            callx0       a0 /* [[sdk_g_phyFuns]+0x9c] */       #  82b: c00000
            l32i.n       a12, a1, 4 /* [(local1)] */           #  82e: c811
            l32i.n       a0, a1, 0 /* [(local0)] */            #  830: 0801
            addi         a1, a1, 16 /* (top of frame) */       #  832: 12c110
            ret.n                                              #  835: 0df0

            .balign      4
.Lrel026:   .word        sdk_g_phyFuns                         #  838: 00000000
.Lrel027:   .word        .rodata.str1.4                        #  83c: 00000000
.Lrel028:   .word        sdk_ets_delay_us                      #  840: 00000000
.Lrel029:   .word        ets_printf                            #  844: 00000000

# Function @ .irom0.text+0x848
# Local variables/stack:
#     (local0):  word      @ -0x20
#     (local1):  word      @ -0x1c
#     (local2):  word      @ -0x18
#     (local3):  word      @ -0x14
#     (local4):  word[4]   @ -0x10
.literal_position
sdk_wait_rfpll_cal_end:
            addi         a1, a1, -32 /* (local0) */            #  848: 12c1e0
            s32i.n       a0, a1, 0 /* a0 -> [(local0)] */      #  84b: 0901
            s32i.n       a13, a1, 8 /* a13 -> [(local2)] */    #  84d: d921
            s32i.n       a14, a1, 12 /* a14 -> [(local3)] */   #  84f: e931
            s32i.n       a12, a1, 4 /* a12 -> [(local1)] */    #  851: c911
            s32i.n       a15, a1, 16 /* a15 -> [(local4)] */   #  853: f941
            movi.n       a12, 0 /* 0x00000000 */               #  855: 0c0c
            movi         a15, 99 /* 0x00000063 */              #  857: f2a063
            movi         a14, 100 /* 0x00000064 */             #  85a: e2a064
            movi         a13, .Lrel026 /* sdk_g_phyFuns */     #  85d: d1f6ff
.Lbr024:    movi.n       a2, 20 /* 0x00000014 */               #  860: 1c42
            movi         a0, .Lrel028 /* .Lrel028 */           #  862: 01f7ff
            callx0       a0                                    #  865: c00000
            movi         a2, 98 /* 0x00000062 */               #  868: 22a062
            movi.n       a3, 1 /* 0x00000001 */                #  86b: 0c13
            movi.n       a4, 7 /* 0x00000007 */                #  86d: 0c74
            l32i.n       a0, a13, 0 /* [sdk_g_phyFuns] */      #  86f: 080d
            movi.n       a5, 7 /* 0x00000007 */                #  871: 0c75
            l32i         a0, a0, 148 /* [[sdk_g_phyFuns]+0x94] */ #  873: 022025
            movi.n       a6, 7 /* 0x00000007 */                #  876: 0c76
            callx0       a0 /* [[sdk_g_phyFuns]+0x94] */       #  878: c00000
            bnez.n       a2, .Lbr026                           #  87b: dc22
            bne          a12, a15, .Lbr025                     #  87d: f79c08
            movi         a2, .Lrel027 /* .Lrel027 */           #  880: 21efff
            movi         a0, .Lrel029 /* .Lrel029 */           #  883: 01f0ff
            callx0       a0                                    #  886: c00000
.Lbr025:    addi.n       a12, a12, 1                           #  889: 1bcc
            extui        a12, a12, 0, 8                        #  88b: c0c074
            bne          a12, a14, .Lbr024                     #  88e: e79cce
.Lbr026:    l32i.n       a12, a1, 4 /* [(local1)] */           #  891: c811
            l32i.n       a13, a1, 8 /* [(local2)] */           #  893: d821
            l32i.n       a14, a1, 12 /* [(local3)] */          #  895: e831
            l32i.n       a15, a1, 16 /* [(local4)] */          #  897: f841
            l32i.n       a0, a1, 0 /* [(local0)] */            #  899: 0801
            addi         a1, a1, 32 /* (top of frame) */       #  89b: 12c120
            ret.n                                              #  89e: 0df0

.Llit020:   .word        0x42200000                            #  8a0: 00002042
.Llit021:   .word        0x41c00000                            #  8a4: 0000c041
.Llit022:   .word        0x41d00000                            #  8a8: 0000d041
.Llit023:   .word        0x43800000                            #  8ac: 00008043
.Llit024:   .word        0x40080000                            #  8b0: 00000840
.Llit025:   .word        0x44800000                            #  8b4: 00008044
.Llit026:   .word        0xc2000000                            #  8b8: 000000c2
.Lrel030:   .word        __floatunsidf                         #  8bc: 00000000
.Lrel031:   .word        __divdf3                              #  8c0: 00000000
.Lrel032:   .word        __truncdfsf2                          #  8c4: 00000000
.Lrel033:   .word        __mulsf3                              #  8c8: 00000000
.Lrel034:   .word        __divsf3                              #  8cc: 00000000
.Lrel035:   .word        __addsf3                              #  8d0: 00000000
.Lrel036:   .word        __fixunssfsi                          #  8d4: 00000000
.Lrel037:   .word        __floatsisf                           #  8d8: 00000000
.Lrel038:   .word        __subsf3                              #  8dc: 00000000
.Lrel039:   .word        __mulsf3                              #  8e0: 00000000
.Lrel040:   .word        __fixunssfsi                          #  8e4: 00000000
.Lrel041:   .word        __floatsisf                           #  8e8: 00000000
.Lrel042:   .word        __subsf3                              #  8ec: 00000000
.Lrel043:   .word        __mulsf3                              #  8f0: 00000000
.Lrel044:   .word        __fixunssfsi                          #  8f4: 00000000

# Function @ .irom0.text+0x8f8
# Local variables/stack:
#     (local0):  word      @ -0x20
#     (local1):  word      @ -0x1c
#     (local2):  word      @ -0x18
#     (local3):  word      @ -0x14
#     (local4):  word[4]   @ -0x10
.literal_position
sdk_ram_rfpll_set_freq:
            addi         a1, a1, -32 /* (local0) */            #  8f8: 12c1e0
            s32i.n       a13, a1, 12 /* a13 -> [(local3)] */   #  8fb: d931
            s32i.n       a0, a1, 4 /* a0 -> [(local1)] */      #  8fd: 0911
            s32i.n       a12, a1, 8 /* a12 -> [(local2)] */    #  8ff: c921
            s32i.n       a14, a1, 16 /* a14 -> [(local4)] */   #  901: e941
            mov.n        a12, a5 /* arg3 */                    #  903: cd05
            movi         a14, .Llit020 /* 0x42200000 */        #  905: e1e6ff
            beqz.n       a3, .Lbr028                           #  908: 8cd3
            beqi         a3, 1, .Lbr027                        #  90a: 261308
            bnei         a3, 2, .Lbr028                        #  90d: 662308
            movi         a14, .Llit021 /* 0x41c00000 */        #  910: e1e5ff
            j            .Lbr028                               #  913: 860000
.Lbr027:    movi         a14, .Llit022 /* 0x41d00000 */        #  916: e1e4ff
.Lbr028:    movi         a13, .Llit023 /* 0x43800000 */        #  919: d1e4ff
            slli         a2, a2, 10                            #  91c: 602211
            add.n        a2, a4, a2                            #  91f: 2a24
            slli         a2, a2, 2                             #  921: e02211
            movi         a0, .Lrel030 /* __floatunsidf */      #  924: 01e6ff
            callx0       a0 /* __floatunsidf */                #  927: c00000
            movi         a5, .Llit024 /* 0x40080000 */         #  92a: 51e1ff
            movi.n       a4, 0 /* 0x00000000 */                #  92d: 0c04
            movi         a0, .Lrel031 /* __divdf3 */           #  92f: 01e4ff
            callx0       a0 /* __divdf3 */                     #  932: c00000
            movi         a0, .Lrel032 /* __truncdfsf2 */       #  935: 01e3ff
            callx0       a0 /* __truncdfsf2 */                 #  938: c00000
            s32i.n       a2, a1, 0 /* a2 -> [(local0)] */      #  93b: 2901
            movi         a3, .Llit025 /* 0x44800000 */         #  93d: 31ddff
            mov.n        a2, a14                               #  940: 2d0e
            movi         a0, .Lrel033 /* __mulsf3 */           #  942: 01e1ff
            callx0       a0 /* __mulsf3 */                     #  945: c00000
            mov.n        a3, a2                                #  948: 3d02
            l32i.n       a2, a1, 0 /* [(local0)] */            #  94a: 2801
            movi         a0, .Lrel034 /* __divsf3 */           #  94c: 01e0ff
            callx0       a0 /* __divsf3 */                     #  94f: c00000
            movi         a3, .Llit026 /* 0xc2000000 */         #  952: 31d9ff
            movi         a0, .Lrel035 /* __addsf3 */           #  955: 01deff
            callx0       a0 /* __addsf3 */                     #  958: c00000
            mov.n        a14, a2                               #  95b: ed02
            movi         a0, .Lrel036 /* __fixunssfsi */       #  95d: 01ddff
            callx0       a0 /* __fixunssfsi */                 #  960: c00000
            s8i          a2, a12, 0 /* a2 -> [arg3] */         #  963: 224c00
            extui        a2, a2, 0, 8                          #  966: 202074
            movi         a0, .Lrel037 /* __floatsisf */        #  969: 01dbff
            callx0       a0 /* __floatsisf */                  #  96c: c00000
            mov.n        a3, a2                                #  96f: 3d02
            mov.n        a2, a14                               #  971: 2d0e
            movi         a0, .Lrel038 /* __subsf3 */           #  973: 01daff
            callx0       a0 /* __subsf3 */                     #  976: c00000
            mov.n        a3, a13 /* 0x43800000 */              #  979: 3d0d
            movi         a0, .Lrel039 /* __mulsf3 */           #  97b: 01d9ff
            callx0       a0 /* __mulsf3 */                     #  97e: c00000
            mov.n        a14, a2                               #  981: ed02
            movi         a0, .Lrel040 /* __fixunssfsi */       #  983: 01d8ff
            callx0       a0 /* __fixunssfsi */                 #  986: c00000
            s8i          a2, a12, 1 /* a2 -> [arg3+0x1] */     #  989: 224c01
            extui        a2, a2, 0, 8                          #  98c: 202074
            movi         a0, .Lrel041 /* __floatsisf */        #  98f: 01d6ff
            callx0       a0 /* __floatsisf */                  #  992: c00000
            mov.n        a3, a2                                #  995: 3d02
            mov.n        a2, a14                               #  997: 2d0e
            movi         a0, .Lrel042 /* __subsf3 */           #  999: 01d4ff
            callx0       a0 /* __subsf3 */                     #  99c: c00000
            mov.n        a3, a13 /* 0x43800000 */              #  99f: 3d0d
            movi         a0, .Lrel043 /* __mulsf3 */           #  9a1: 01d3ff
            callx0       a0 /* __mulsf3 */                     #  9a4: c00000
            movi         a0, .Lrel044 /* __fixunssfsi */       #  9a7: 01d3ff
            callx0       a0 /* __fixunssfsi */                 #  9aa: c00000
            l32i.n       a0, a1, 4 /* [(local1)] */            #  9ad: 0811
            l32i.n       a13, a1, 12 /* [(local3)] */          #  9af: d831
            s8i          a2, a12, 2 /* a2 -> [arg3+0x2] */     #  9b1: 224c02
            l32i.n       a14, a1, 16 /* [(local4)] */          #  9b4: e841
            l32i.n       a12, a1, 8 /* [(local2)] */           #  9b6: c821
            addi         a1, a1, 32 /* (top of frame) */       #  9b8: 12c120
            ret.n                                              #  9bb: 0df0

            .balign      4
.Llit027:   .word        0x00f00000                            #  9c0: 0000f000
.Lrel045:   .word        sdk_g_phyFuns                         #  9c4: 00000000
.Llit028:   .word        0x60000200                            #  9c8: 00020060
.Lrel046:   .word        .Lfunc001                             #  9cc: 790a0000
.Llit029:   .word        0x000009b4                            #  9d0: b4090000
.Lrel047:   .word        .Lfunc002                             #  9d4: d70a0000
.Lrel048:   .word        sdk_g_phyFuns                         #  9d8: 00000000
.Llit030:   .word        0xff0fffff                            #  9dc: ffff0fff
.Llit031:   .word        0x60000200                            #  9e0: 00020060
.Lrel049:   .word        .Lfunc003                             #  9e4: 900b0000
.Llit032:   .word        0x0000096c                            #  9e8: 6c090000
.Llit033:   .word        0x000009a8                            #  9ec: a8090000
.Llit034:   .word        0x000009a3                            #  9f0: a3090000
.Llit035:   .word        0x0000099e                            #  9f4: 9e090000
.Llit036:   .word        0x00000999                            #  9f8: 99090000
.Llit037:   .word        0x00000994                            #  9fc: 94090000
.Llit038:   .word        0x0000098f                            #  a00: 8f090000
.Llit039:   .word        0x0000098a                            #  a04: 8a090000
.Llit040:   .word        0x00000985                            #  a08: 85090000
.Llit041:   .word        0x00000980                            #  a0c: 80090000
.Llit042:   .word        0x0000097b                            #  a10: 7b090000
.Llit043:   .word        0x00000976                            #  a14: 76090000
.Llit044:   .word        0x00000971                            #  a18: 71090000

# Function @ .irom0.text+0xa1c
# Local variables/stack:
#     (local0):  byte      @ -0x30
#     (local1):  byte      @ -0x2f
#     (local2):  byte[2]   @ -0x2e
#     (local3):  word      @ -0x2c
#     (local4):  word      @ -0x28
#     (local5):  word      @ -0x24
#     (local6):  word      @ -0x20
#     (local7):  word      @ -0x1c
#     (local8):  word      @ -0x18
#     (local9):  word      @ -0x14
#     (local10): word[4]   @ -0x10
.literal_position
sdk_ram_set_channel_freq:
            addi         a1, a1, -48 /* (local0) */            #  a1c: 12c1d0
            s32i.n       a12, a1, 16 /* a12 -> [(local6)] */   #  a1f: c941
            s32i.n       a4, a1, 32 /* arg2 -> [(local10)] */  #  a21: 4981
            s32i.n       a6, a1, 8 /* arg4 -> [(local4)] */    #  a23: 6921
            s32i.n       a0, a1, 12 /* a0 -> [(local5)] */     #  a25: 0931
            s32i.n       a15, a1, 28 /* a15 -> [(local9)] */   #  a27: f971
            s32i.n       a13, a1, 20 /* a13 -> [(local7)] */   #  a29: d951
            s32i.n       a14, a1, 24 /* a14 -> [(local8)] */   #  a2b: e961
            mov.n        a13, a2 /* arg0 */                    #  a2d: dd02
            mov.n        a14, a3 /* arg1 */                    #  a2f: ed03
            mov.n        a15, a4 /* arg2 */                    #  a31: fd04
            blti         a2, 1, .Lbr029                        #  a33: a6120e
            movi.n       a0, 13 /* 0x0000000d */               #  a36: 0cd0
            blt          a0, a2, .Lbr029                       #  a38: 272009
            addi.n       a2, a2, -1 /* arg0-0x1 */             #  a3b: 0b22
            extui        a2, a2, 0, 8                          #  a3d: 202074
            s32i.n       a2, a1, 4 /* a2 -> [(local3)] */      #  a40: 2911
            j            .Lbr030                               #  a42: c60000
.Lbr029:    movi.n       a3, 13 /* 0x0000000d */               #  a45: 0cd3
            s32i.n       a3, a1, 4 /* 0x0000000d -> [(local3)] */ #  a47: 3911
.Lbr030:    movi         a4, .Llit027 /* .Llit027 */           #  a49: 41ddff
            movi         a12, .Lrel045 /* .Lrel045 */          #  a4c: c1deff
            movi         a3, .Llit028 /* .Llit028 */           #  a4f: 31deff
            memw                                               #  a52: c02000
            l32i         a2, a3, 0x3c8                         #  a55: 2223f2
            or           a2, a2, a4                            #  a58: 402220
            memw                                               #  a5b: c02000
            l32i.n       a0, a12, 0                            #  a5e: 080c
            l32i         a0, a0, 220                           #  a60: 022037
            s32i         a2, a3, 0x3c8                         #  a63: 2263f2
            callx0       a0                                    #  a66: c00000
            movi.n       a5, 14 /* 0x0000000e */               #  a69: 0ce5
            bgeu         a13, a5, .Lbr031                      #  a6b: 57bd34
            movi         a7, .Lrel046 /* .Lrel046 */           #  a6e: 71d7ff
            addx2        a6, a13, a13                          #  a71: d06d90
            add.n        a6, a6, a7                            #  a74: 7a66
            jx           a6                                    #  a76: a00600
.Lfunc001:  j            .Lbr031                               #  a79: 860900
            j            .Lbr047                               #  a7c: 465b00
            j            .Lbr059                               #  a7f: 866c00
            j            .Lbr058                               #  a82: 466a00
            j            .Lbr057                               #  a85: 066800
            j            .Lbr056                               #  a88: c66500
            j            .Lbr055                               #  a8b: 866300
            j            .Lbr054                               #  a8e: 466100
            j            .Lbr053                               #  a91: 065f00
            j            .Lbr052                               #  a94: c65c00
            j            .Lbr051                               #  a97: 865a00
            j            .Lbr050                               #  a9a: 465800
            j            .Lbr049                               #  a9d: 065600
            j            .Lbr048                               #  aa0: c65300
.Lbr031:    movi         a12, .Llit029 /* 0x000009b4 */        #  aa3: c1cbff
.Lbr032:    bnez         a15, .Lbr034                          #  aa6: 567f05
            bgeui        a14, 2, .Lbr034                       #  aa9: f62e54
            movi.n       a0, 59 /* 0x0000003b */               #  aac: 3cb0
            addi.n       a8, a14, -1 /* arg1-0x1 */            #  aae: 0b8e
            bnez         a8, .Lbr037                           #  ab0: 56980b
            movi         a4, -73 /* 0xffffffb7 */              #  ab3: 42afb7
            movi         a11, -125 /* 0xffffff83 */            #  ab6: b2af83
            movi         a10, 118 /* 0x00000076 */             #  ab9: a2a076
            movi.n       a3, 94 /* 0x0000005e */               #  abc: 5ce3
            movi.n       a9, 93 /* 0x0000005d */               #  abe: 5cd9
            movi.n       a6, 92 /* 0x0000005c */               #  ac0: 5cc6
            movi.n       a8, 91 /* 0x0000005b */               #  ac2: 5cb8
            movi.n       a14, 14 /* 0x0000000e */              #  ac4: 0cee
            bltu         a13, a14, .Lbr033                     #  ac6: e73d02
            j            .Lbr063                               #  ac9: 865f00
.Lbr033:    movi         a2, .Lrel047 /* .Lfunc002 */          #  acc: 21c2ff
            addx2        a15, a13, a13                         #  acf: d0fd90
            add.n        a15, a15, a2                          #  ad2: 2aff
            jx           a15                                   #  ad4: a00f00
.Lfunc002:  j            .Lbr063                               #  ad7: 065c00
            j            .Lbr044                               #  ada: 064000
            j            .Lbr064                               #  add: 865e00
            j            .Lbr083                               #  ae0: 468900
            j            .Lbr082                               #  ae3: c68500
            j            .Lbr081                               #  ae6: 068200
            j            .Lbr065                               #  ae9: 065f00
            j            .Lbr080                               #  aec: 867e00
            j            .Lbr078                               #  aef: 467a00
            j            .Lbr077                               #  af2: 467600
            j            .Lbr075                               #  af5: c67200
            j            .Lbr074                               #  af8: 866e00
            j            .Lbr073                               #  afb: 066b00
            j            .Lbr072                               #  afe: 866700
.Lbr034:    mov.n        a4, a15 /* arg2 */                    #  b01: 4d0f
            mov.n        a3, a14 /* arg1 */                    #  b03: 3d0e
            l32i.n       a13, a1, 4 /* [(local3)] */           #  b05: d811
            mov.n        a2, a12 /* 0x000009b4 */              #  b07: 2d0c
            mov.n        a5, a1 /* (local0) */                 #  b09: 5d01
            call0        sdk_ram_rfpll_set_freq                #  b0b: 050000
            l8ui         a3, a1, 2 /* [(local2)] */            #  b0e: 320102
            l8ui         a5, a1, 0 /* [(local0)] */            #  b11: 520100
            l32i.n       a4, a1, 8 /* [(local4)] */            #  b14: 4821
            l8ui         a6, a1, 1 /* [(local1)] */            #  b16: 620101
            addx4        a4, a13, a4                           #  b19: 404da0
            slli         a6, a6, 8                             #  b1c: 806611
            slli         a5, a5, 16                            #  b1f: 005511
            or           a5, a5, a6                            #  b22: 605520
            or           a3, a3, a5                            #  b25: 503320
            s32i.n       a3, a4, 0                             #  b28: 3904
.Lbr035:    movi         a13, .Lrel048 /* .Lrel048 */          #  b2a: d1abff
            l32i.n       a0, a13, 0                            #  b2d: 080d
            l32i         a0, a0, 224                           #  b2f: 022038
            mov.n        a2, a1 /* (local0) */                 #  b32: 2d01
            callx0       a0                                    #  b34: c00000
            l32i.n       a0, a13, 0                            #  b37: 080d
            l32i         a0, a0, 216                           #  b39: 022036
            callx0       a0                                    #  b3c: c00000
            l8ui         a2, a1, 48 /* [(local11)] */          #  b3f: 220130
            beqz.n       a2, .Lbr036                           #  b42: 8c12
            call0        sdk_wait_rfpll_cal_end                #  b44: 050000
.Lbr036:    mov.n        a2, a12 /* 0x000009b4 */              #  b47: 2d0c
            movi         a5, .Llit030 /* .Llit030 */           #  b49: 51a4ff
            memw                                               #  b4c: c02000
            movi         a4, .Llit031 /* .Llit031 */           #  b4f: 41a4ff
            l32i         a3, a4, 0x3c8                         #  b52: 3224f2
            and          a3, a3, a5                            #  b55: 503310
            memw                                               #  b58: c02000
            s32i         a3, a4, 0x3c8                         #  b5b: 3264f2
            l32i.n       a12, a1, 16 /* [(local6)] */          #  b5e: c841
            l32i.n       a13, a1, 20 /* [(local7)] */          #  b60: d851
            l32i.n       a14, a1, 24 /* [(local8)] */          #  b62: e861
            l32i.n       a15, a1, 28 /* [(local9)] */          #  b64: f871
            l32i.n       a0, a1, 12 /* [(local5)] */           #  b66: 0831
            addi         a1, a1, 48 /* (local11) */            #  b68: 12c130
            ret.n         /* 0x000009b4 */                     #  b6b: 0df0
.Lbr037:    movi.n       a4, 48 /* 0x00000030 */               #  b6d: 3c04
            movi.n       a10, 49 /* 0x00000031 */              #  b6f: 3c1a
            movi.n       a2, 50 /* 0x00000032 */               #  b71: 3c22
            movi         a3, 102 /* 0x00000066 */              #  b73: 32a066
            movi         a11, -111 /* 0xffffff91 */            #  b76: b2af91
            movi         a6, -69 /* 0xffffffbb */              #  b79: 62afbb
            movi.n       a9, -26 /* 0xffffffe6 */              #  b7c: 6c69
            movi.n       a8, 17 /* 0x00000011 */               #  b7e: 1c18
            movi.n       a7, 14 /* 0x0000000e */               #  b80: 0ce7
            bgeu         a13, a7, .Lbr038                      #  b82: 77bd34
            movi         a15, .Lrel049 /* .Lfunc003 */         #  b85: f197ff
            addx2        a14, a13, a13                         #  b88: d0ed90
            add.n        a14, a14, a15                         #  b8b: faee
            jx           a14                                   #  b8d: a00e00
.Lfunc003:  j            .Lbr038                               #  b90: 860900
            j            .Lbr042                               #  b93: 060f00
            j            .Lbr039                               #  b96: c60900
            j            .Lbr068                               #  b99: 063a00
            j            .Lbr069                               #  b9c: 463a00
            j            .Lbr071                               #  b9f: 863d00
            j            .Lbr040                               #  ba2: 460800
            j            .Lbr060                               #  ba5: 862400
            j            .Lbr061                               #  ba8: c62400
            j            .Lbr070                               #  bab: c63800
            j            .Lbr062                               #  bae: 462400
            j            .Lbr066                               #  bb1: 863000
            j            .Lbr067                               #  bb4: c63000
            j            .Lbr041                               #  bb7: 860500
.Lbr038:    mov.n        a4, a2 /* 0x00000032 */               #  bba: 4d02
            movi         a8, -52 /* 0xffffffcc */              #  bbc: 82afcc
            mov.n        a11, a8 /* 0xffffffcc */              #  bbf: bd08
.Lbr039:    mov.n        a6, a8 /* 0xffffffcc */               #  bc1: 6d08
            mov.n        a0, a11 /* 0xffffffcc */              #  bc3: 0d0b
            mov.n        a10, a4 /* 0x00000032 */              #  bc5: ad04
.Lbr040:    mov.n        a3, a6 /* 0xffffffcc */               #  bc7: 3d06
            mov.n        a4, a10 /* 0x00000032 */              #  bc9: 4d0a
            s8i          a0, a1, 1 /* 0xcc -> [(local1)] */    #  bcb: 024101
            j            .Lbr043                               #  bce: 060100
.Lbr041:    mov.n        a4, a2                                #  bd1: 4d02
.Lbr042:    s8i          a3, a1, 1                             #  bd3: 324101
.Lbr043:    mov.n        a0, a3 /* 0xffffffcc */               #  bd6: 0d03
            s8i          a4, a1, 0 /* 0x32 -> [(local0)] */    #  bd8: 424100
            j            .Lbr046                               #  bdb: 060200
.Lbr044:    s8i          a8, a1, 0                             #  bde: 824100
            movi         a2, -79                               #  be1: 22afb1
.Lbr045:    s8i          a2, a1, 1                             #  be4: 224101
.Lbr046:    s8i          a0, a1, 2 /* a0 -> [(local2)] */      #  be7: 024102
            j            .Lbr035                               #  bea: 06cfff
.Lbr047:    l32r         a12, .Llit032                         #  bed: c17eff
            j            .Lbr032                               #  bf0: 86acff
.Lbr048:    l32r         a12, .Llit033                         #  bf3: c17eff
            j            .Lbr032                               #  bf6: 06abff
.Lbr049:    l32r         a12, .Llit034                         #  bf9: c17dff
            j            .Lbr032                               #  bfc: 86a9ff
.Lbr050:    l32r         a12, .Llit035                         #  bff: c17dff
            j            .Lbr032                               #  c02: 06a8ff
.Lbr051:    l32r         a12, .Llit036                         #  c05: c17cff
            j            .Lbr032                               #  c08: 86a6ff
.Lbr052:    l32r         a12, .Llit037                         #  c0b: c17cff
            j            .Lbr032                               #  c0e: 06a5ff
.Lbr053:    l32r         a12, .Llit038                         #  c11: c17bff
            j            .Lbr032                               #  c14: 86a3ff
.Lbr054:    l32r         a12, .Llit039                         #  c17: c17bff
            j            .Lbr032                               #  c1a: 06a2ff
.Lbr055:    l32r         a12, .Llit040                         #  c1d: c17aff
            j            .Lbr032                               #  c20: 86a0ff
.Lbr056:    l32r         a12, .Llit041                         #  c23: c17aff
            j            .Lbr032                               #  c26: 069fff
.Lbr057:    l32r         a12, .Llit042                         #  c29: c179ff
            j            .Lbr032                               #  c2c: 869dff
.Lbr058:    l32r         a12, .Llit043                         #  c2f: c179ff
            j            .Lbr032                               #  c32: 069cff
.Lbr059:    l32r         a12, .Llit044                         #  c35: c178ff
            j            .Lbr032                               #  c38: 869aff
.Lbr060:    mov.n        a8, a3                                #  c3b: 8d03
            mov.n        a11, a8                               #  c3d: bd08
.Lbr061:    mov.n        a3, a8                                #  c3f: 3d08
            mov.n        a9, a11                               #  c41: 9d0b
.Lbr062:    mov.n        a4, a10                               #  c43: 4d0a
            s8i          a9, a1, 1                             #  c45: 924101
            j            .Lbr043                               #  c48: 86e2ff
.Lbr063:    mov.n        a0, a10 /* 0x00000076 */              #  c4b: 0d0a
            movi         a2, 98 /* 0x00000062 */               #  c4d: 22a062
            movi.n       a3, 95 /* 0x0000005f */               #  c50: 5cf3
            s8i          a3, a1, 0 /* 0x5f -> [(local0)] */    #  c52: 324100
            s8i          a2, a1, 1 /* 0x62 -> [(local1)] */    #  c55: 224101
            j            .Lbr046                               #  c58: c6e2ff
.Lbr064:    s8i          a8, a1, 0                             #  c5b: 824100
            movi         a0, -33                               #  c5e: 02afdf
            movi.n       a4, -14                               #  c61: 7c24
            s8i          a4, a1, 1                             #  c63: 424101
            j            .Lbr046                               #  c66: 46dfff
.Lbr065:    s8i          a6, a1, 0                             #  c69: 624100
            movi         a0, 111                               #  c6c: 02a06f
            movi.n       a5, -7                                #  c6f: 7c95
            s8i          a5, a1, 1                             #  c71: 524101
            j            .Lbr046                               #  c74: c6dbff
.Lbr066:    mov.n        a6, a8                                #  c77: 6d08
            mov.n        a0, a6                                #  c79: 0d06
.Lbr067:    mov.n        a3, a6                                #  c7b: 3d06
            mov.n        a4, a2                                #  c7d: 4d02
            s8i          a0, a1, 1                             #  c7f: 024101
            j            .Lbr043                               #  c82: 06d4ff
.Lbr068:    mov.n        a3, a6                                #  c85: 3d06
            mov.n        a9, a3                                #  c87: 9d03
.Lbr069:    mov.n        a6, a3                                #  c89: 6d03
            mov.n        a0, a9                                #  c8b: 0d09
            mov.n        a10, a4                               #  c8d: ad04
            j            .Lbr040                               #  c8f: 06cdff
.Lbr070:    mov.n        a3, a6                                #  c92: 3d06
            mov.n        a9, a3                                #  c94: 9d03
            j            .Lbr062                               #  c96: 46eaff
.Lbr071:    mov.n        a6, a8                                #  c99: 6d08
            mov.n        a0, a6                                #  c9b: 0d06
            j            .Lbr040                               #  c9d: 86c9ff
.Lbr072:    s8i          a3, a1, 0                             #  ca0: 324100
            movi         a2, -60                               #  ca3: 22afc4
            movi.n       a0, -20                               #  ca6: 6cc0
            j            .Lbr045                               #  ca8: 06ceff
.Lbr073:    s8i          a3, a1, 0                             #  cab: 324100
            s8i          a11, a1, 1                            #  cae: b24101
            movi.n       a0, 72                                #  cb1: 4c80
            j            .Lbr046                               #  cb3: 06ccff
.Lbr074:    s8i          a3, a1, 0                             #  cb6: 324100
            movi         a0, -92                               #  cb9: 02afa4
            movi.n       a6, 65                                #  cbc: 4c16
            s8i          a6, a1, 1                             #  cbe: 624101
            j            .Lbr046                               #  cc1: 86c8ff
.Lbr075:    movi.n       a0, 0                                 #  cc4: 0c00
            s8i          a0, a1, 1                             #  cc6: 024101
.Lbr076:    s8i          a3, a1, 0                             #  cc9: 324100
            j            .Lbr046                               #  ccc: c6c5ff
.Lbr077:    mov.n        a0, a8                                #  ccf: 0d08
            mov.n        a3, a9                                #  cd1: 3d09
            movi         a7, -66                               #  cd3: 72afbe
            s8i          a7, a1, 1                             #  cd6: 724101
            j            .Lbr076                               #  cd9: 06fbff
.Lbr078:    s8i          a9, a1, 0                             #  cdc: 924100
            movi         a0, 124                               #  cdf: 02a07c
.Lbr079:    s8i          a0, a1, 1                             #  ce2: 024101
            mov.n        a0, a4                                #  ce5: 0d04
            j            .Lbr046                               #  ce7: 06bfff
.Lbr080:    s8i          a9, a1, 0                             #  cea: 924100
            movi.n       a4, 19                                #  ced: 1c34
            j            .Lbr079                               #  cef: c6fbff
.Lbr081:    s8i          a6, a1, 0                             #  cf2: 624100
            s8i          a4, a1, 1                             #  cf5: 424101
            movi         a0, -53                               #  cf8: 02afcb
            j            .Lbr046                               #  cfb: 06baff
.Lbr082:    s8i          a6, a1, 0                             #  cfe: 624100
            s8i          a10, a1, 1                            #  d01: a24101
            movi.n       a0, 39                                #  d04: 2c70
            j            .Lbr046                               #  d06: 46b7ff
.Lbr083:    mov.n        a0, a11                               #  d09: 0d0b
            s8i          a6, a1, 0                             #  d0b: 624100
            movi.n       a8, 52                                #  d0e: 3c48
            s8i          a8, a1, 1                             #  d10: 824101
            j            .Lbr046                               #  d13: 06b4ff

            .balign      4
.Lrel050:   .word        sdk_chip6_sleep_params                #  d18: 00000000
.Lrel051:   .word        .Lfunc004                             #  d1c: 660d0000
.Llit045:   .word        0x00005208                            #  d20: 08520000
.Llit046:   .word        0x00006000                            #  d24: 00600000
.Llit047:   .word        0x60009a00                            #  d28: 009a0060
.Lrel052:   .word        sdk_phy_dig_spur_set                  #  d2c: 00000000
.Lrel053:   .word        sdk_phy_dig_spur_prot                 #  d30: 00000000

# Function @ .irom0.text+0xd34
# Local variables/stack:
#     (local0):  word[4]   @ -0x20
#     (local1):  word      @ -0x10
#     (local2):  word[3]   @ -0xc
.literal_position
sdk_chip_60_set_channel:
            movi         a8, .Lrel050 /* sdk_chip6_sleep_params */ #  d34: 81f9ff
            mov.n        a4, a5 /* arg3 */                     #  d37: 4d05
            addi         a1, a1, -32 /* (local0) */            #  d39: 12c1e0
            s32i.n       a0, a1, 16 /* a0 -> [(local1)] */     #  d3c: 0941
            s32i.n       a12, a1, 20 /* a12 -> [(local2)] */   #  d3e: c951
            mov.n        a5, a6 /* arg4 */                     #  d40: 5d06
            mov.n        a12, a2 /* arg0 */                    #  d42: cd02
            s8i          a2, a8, 78 /* arg0 -> [sdk_chip6_sleep_params+0x4e] */ #  d44: 22484e
            mov.n        a6, a7 /* arg5 */                     #  d47: 6d07
            l8ui         a0, a1, 36 /* [(FP)+0x4] */           #  d49: 020124
            l16ui        a7, a1, 32 /* [(local3)] */           #  d4c: 721110
            s32i.n       a0, a1, 0 /* [(FP)+0x4] -> [(local0)] */ #  d4f: 0901
            call0        sdk_ram_set_channel_freq              #  d51: 050000
            mov.n        a3, a2                                #  d54: 3d02
            movi.n       a9, 14 /* 0x0000000e */               #  d56: 0ce9
            bgeu         a12, a9, .Lbr084                      #  d58: 97bc34
            movi         a11, .Lrel051 /* .Lfunc004 */         #  d5b: b1f0ff
            addx2        a10, a12, a12                         #  d5e: c0ac90
            add.n        a10, a10, a11                         #  d61: baaa
            jx           a10                                   #  d63: a00a00
.Lfunc004:  j            .Lbr084                               #  d66: 860900
            j            .Lbr086                               #  d69: 061800
            j            .Lbr098                               #  d6c: 462900
            j            .Lbr097                               #  d6f: 062700
            j            .Lbr096                               #  d72: c62400
            j            .Lbr095                               #  d75: 862200
            j            .Lbr094                               #  d78: 462000
            j            .Lbr093                               #  d7b: 061e00
            j            .Lbr092                               #  d7e: c61b00
            j            .Lbr091                               #  d81: 861900
            j            .Lbr090                               #  d84: 461700
            j            .Lbr089                               #  d87: 061500
            j            .Lbr088                               #  d8a: c61200
            j            .Lbr087                               #  d8d: 861000
.Lbr084:    movi         a0, 106 /* 0x0000006a */              #  d90: 02a06a
.Lbr085:    movi         a4, .Llit046 /* 0x00006000 */         #  d93: 41e4ff
            movi         a5, .Llit045 /* 0x00005208 */         #  d96: 51e2ff
            movi         a2, .Llit047 /* 0x60009a00 */         #  d99: 21e3ff
            add.n        a5, a0, a5 /* 0x00005272 */           #  d9c: 5a50
            slli         a5, a5, 17                            #  d9e: f05501
            memw                                               #  da1: c02000
            l32i         a0, a2, 0x114 /* [0x60009b14] */      #  da4: 022245
            extui        a0, a0, 0, 13                         #  da7: 0000c4
            or           a0, a0, a5                            #  daa: 500020
            or           a0, a0, a4                            #  dad: 400020
            memw                                               #  db0: c02000
            s32i         a0, a2, 0x114 /* a0 -> [0x60009b14] */ #  db3: 026245
            mov.n        a2, a12 /* arg0 */                    #  db6: 2d0c
            movi         a0, .Lrel052 /* sdk_phy_dig_spur_set */ #  db8: 01ddff
            callx0       a0 /* sdk_phy_dig_spur_set */         #  dbb: c00000
            movi         a0, .Lrel053 /* sdk_phy_dig_spur_prot */ #  dbe: 01dcff
            callx0       a0 /* sdk_phy_dig_spur_prot */        #  dc1: c00000
            l32i.n       a12, a1, 20 /* [(local2)] */          #  dc4: c851
            l32i.n       a0, a1, 16 /* [(local1)] */           #  dc6: 0841
            addi         a1, a1, 32 /* (local3) */             #  dc8: 12c120
            ret.n                                              #  dcb: 0df0
.Lbr086:    movi         a0, 737                               #  dcd: 02a2e1
            j            .Lbr085                               #  dd0: c6efff
.Lbr087:    movi         a0, 209                               #  dd3: 02a0d1
            j            .Lbr085                               #  dd6: 46eeff
.Lbr088:    movi         a0, 252                               #  dd9: 02a0fc
            j            .Lbr085                               #  ddc: c6ecff
.Lbr089:    movi         a0, 295                               #  ddf: 02a127
            j            .Lbr085                               #  de2: 46ebff
.Lbr090:    movi         a0, 339                               #  de5: 02a153
            j            .Lbr085                               #  de8: c6e9ff
.Lbr091:    movi         a0, 382                               #  deb: 02a17e
            j            .Lbr085                               #  dee: 46e8ff
.Lbr092:    movi         a0, 426                               #  df1: 02a1aa
            j            .Lbr085                               #  df4: c6e6ff
.Lbr093:    movi         a0, 470                               #  df7: 02a1d6
            j            .Lbr085                               #  dfa: 46e5ff
.Lbr094:    movi         a0, 514                               #  dfd: 02a202
            j            .Lbr085                               #  e00: c6e3ff
.Lbr095:    movi         a0, 558                               #  e03: 02a22e
            j            .Lbr085                               #  e06: 46e2ff
.Lbr096:    movi         a0, 602                               #  e09: 02a25a
            j            .Lbr085                               #  e0c: c6e0ff
.Lbr097:    movi         a0, 647                               #  e0f: 02a287
            j            .Lbr085                               #  e12: 46dfff
.Lbr098:    movi         a0, 692                               #  e15: 02a2b4
            j            .Lbr085                               #  e18: c6ddff

            .balign      4
.Lrel054:   .word        sdk_chip6_sleep_params                #  e1c: 00000000
.Lrel055:   .word        .Lstr002                              #  e20: 20000000
.Lrel056:   .word        sdk_chip6_phy_init_ctrl               #  e24: 00000000
.Lrel057:   .word        sdk_chip6_sleep_params                #  e28: 00000000
.Lrel058:   .word        sdk_chip6_sleep_params+0x16c          #  e2c: 00000000
.Lrel059:   .word        ets_printf                            #  e30: 00000000
.Lrel060:   .word        sdk_chip_v6_set_chan_misc             #  e34: 00000000

# Function @ .irom0.text+0xe38
# Local variables/stack:
#     (local0):  word      @ -0x20
#     (local1):  word[3]   @ -0x1c
#     (local2):  word      @ -0x10
#     (local3):  word      @ -0xc
#     (local4):  word[2]   @ -0x8
.literal_position
sdk_chip_v6_set_chan_offset:
            addi.n       a4, a2, -1 /* arg0-0x1 */             #  e38: 0b42
            addi         a1, a1, -32 /* (local0) */            #  e3a: 12c1e0
            s32i.n       a0, a1, 16 /* a0 -> [(local2)] */     #  e3d: 0941
            s32i.n       a13, a1, 24 /* a13 -> [(local4)] */   #  e3f: d961
            ssl          a4                                    #  e41: 001440
            s32i.n       a12, a1, 20 /* a12 -> [(local3)] */   #  e44: c951
            movi.n       a4, -1 /* 0xffffffff */               #  e46: 7cf4
            mov.n        a12, a2 /* arg0 */                    #  e48: cd02
            mov.n        a13, a3 /* arg1 */                    #  e4a: dd03
            movi         a2, .Lrel054 /* sdk_chip6_sleep_params */ #  e4c: 21f4ff
            movi.n       a3, 1 /* 0x00000001 */                #  e4f: 0c13
            sll          a3, a3                                #  e51: 0033a1
            xor          a3, a3, a4                            #  e54: 403330
            l32i.n       a0, a2, 0 /* [sdk_chip6_sleep_params] */ #  e57: 0802
            mov.n        a4, a13 /* arg1 */                    #  e59: 4d0d
            and          a0, a0, a3                            #  e5b: 300010
            s32i.n       a0, a2, 0 /* a0 -> [sdk_chip6_sleep_params] */ #  e5e: 0902
            mov.n        a3, a12 /* arg0 */                    #  e60: 3d0c
            movi         a2, .Lrel055 /* .Lstr002 */           #  e62: 21efff
            movi         a0, .Lrel059 /* ets_printf */         #  e65: 01f2ff
            callx0       a0 /* ets_printf */                   #  e68: c00000
            mov.n        a5, a13 /* arg1 */                    #  e6b: 5d0d
            movi         a6, .Lrel057 /* sdk_chip6_sleep_params */ #  e6d: 61eeff
            mov.n        a2, a12 /* arg0 */                    #  e70: 2d0c
            movi.n       a4, 0 /* 0x00000000 */                #  e72: 0c04
            movi         a8, 100 /* 0x00000064 */              #  e74: 82a064
            movi         a3, .Lrel056 /* sdk_chip6_phy_init_ctrl */ #  e77: 31ebff
            movi.n       a7, 1 /* 0x00000001 */                #  e7a: 0c17
            l8ui         a3, a3, 1 /* [sdk_chip6_phy_init_ctrl+0x1] */ #  e7c: 320301
            s32i.n       a7, a1, 4 /* 0x00000001 -> [(local1)] */ #  e7f: 7911
            s32i.n       a8, a1, 0 /* 0x00000064 -> [(local0)] */ #  e81: 8901
            movi         a7, .Lrel058 /* sdk_chip6_sleep_params+0x16c */ #  e83: 71eaff
            call0        sdk_chip_60_set_channel               #  e86: 050000
            mov.n        a2, a12 /* arg0 */                    #  e89: 2d0c
            movi         a0, .Lrel060 /* sdk_chip_v6_set_chan_misc */ #  e8b: 01eaff
            callx0       a0 /* sdk_chip_v6_set_chan_misc */    #  e8e: c00000
            l32i.n       a12, a1, 20 /* [(local3)] */          #  e91: c851
            l32i.n       a13, a1, 24 /* [(local4)] */          #  e93: d861
            l32i.n       a0, a1, 16 /* [(local2)] */           #  e95: 0841
            addi         a1, a1, 32 /* (top of frame) */       #  e97: 12c120
            ret.n                                              #  e9a: 0df0

.Lrel061:   .word        sdk_tx_pwctrl_set_chan_flag           #  e9c: 00000000
.Lrel062:   .word        sdk_chip6_sleep_params                #  ea0: 00000000
.Lrel063:   .word        sdk_phy_freq_offset                   #  ea4: 00000000
.Lrel064:   .word        sdk_chip6_phy_init_ctrl               #  ea8: 00000000
.Lrel065:   .word        sdk_chip6_sleep_params                #  eac: 00000000
.Lrel066:   .word        sdk_chip6_sleep_params+0x16c          #  eb0: 00000000
.Lrel067:   .word        sdk_chip6_sleep_params                #  eb4: 00000000
.Lrel068:   .word        sdk_pm_set_sleep_mode                 #  eb8: 00000000
.Lrel069:   .word        sdk_stop_dig_rx                       #  ebc: 00000000
.Lrel070:   .word        sdk_chip_v6_set_chan_misc             #  ec0: 00000000
.Lrel071:   .word        sdk_pm_wakeup_init                    #  ec4: 00000000
.Lrel072:   .word        sdk_start_dig_rx                      #  ec8: 00000000

# Function @ .irom0.text+0xecc
# Local variables/stack:
#     (local0):  word      @ -0x20
#     (local1):  word[3]   @ -0x1c
#     (local2):  word      @ -0x10
#     (local3):  word      @ -0xc
#     (local4):  word[2]   @ -0x8
.literal_position
sdk_chip_v6_set_chan:
            movi         a4, .Lrel061 /* sdk_tx_pwctrl_set_chan_flag */ #  ecc: 41f4ff
            movi.n       a3, 1 /* 0x00000001 */                #  ecf: 0c13
            addi         a1, a1, -32 /* (local0) */            #  ed1: 12c1e0
            s32i.n       a12, a1, 24 /* a12 -> [(local4)] */   #  ed4: c961
            s32i.n       a0, a1, 20 /* a0 -> [(local3)] */     #  ed6: 0951
            movi         a0, .Lrel062 /* sdk_chip6_sleep_params */ #  ed8: 01f2ff
            mov.n        a12, a2 /* arg0 */                    #  edb: cd02
            l32i.n       a0, a0, 0 /* [sdk_chip6_sleep_params] */ #  edd: 0800
            s8i          a3, a4, 0 /* 0x01 -> [sdk_tx_pwctrl_set_chan_flag] */ #  edf: 324400
            bbci         a0, 21, .Lbr099                       #  ee2: 57700a
            movi.n       a2, 4 /* 0x00000004 */                #  ee5: 0c42
            movi         a0, .Lrel068 /* sdk_pm_set_sleep_mode */ #  ee7: 01f4ff
            callx0       a0 /* sdk_pm_set_sleep_mode */        #  eea: c00000
            j            .Lbr100                               #  eed: c60100
.Lbr099:    movi         a0, .Lrel069 /* sdk_stop_dig_rx */    #  ef0: 01f3ff
            callx0       a0 /* sdk_stop_dig_rx */              #  ef3: c00000
            s32i.n       a2, a1, 16 /* a2 -> [(local2)] */     #  ef6: 2941
.Lbr100:    movi         a6, .Lrel065 /* sdk_chip6_sleep_params */ #  ef8: 61edff
            movi         a7, .Lrel066 /* sdk_chip6_sleep_params+0x16c */ #  efb: 71edff
            movi         a4, 100 /* 0x00000064 */              #  efe: 42a064
            movi.n       a2, 1 /* 0x00000001 */                #  f01: 0c12
            movi         a5, .Lrel063 /* sdk_phy_freq_offset */ #  f03: 51e8ff
            movi         a3, .Lrel064 /* sdk_chip6_phy_init_ctrl */ #  f06: 31e8ff
            l16si        a5, a5, 0 /* [sdk_phy_freq_offset] */ #  f09: 529500
            l8ui         a3, a3, 1 /* [sdk_chip6_phy_init_ctrl+0x1] */ #  f0c: 320301
            s32i.n       a2, a1, 4 /* 0x00000001 -> [(local1)] */ #  f0f: 2911
            s32i.n       a4, a1, 0 /* 0x00000064 -> [(local0)] */ #  f11: 4901
            mov.n        a2, a12 /* arg0 */                    #  f13: 2d0c
            movi.n       a4, 0 /* 0x00000000 */                #  f15: 0c04
            call0        sdk_chip_60_set_channel               #  f17: 050000
            mov.n        a2, a12 /* arg0 */                    #  f1a: 2d0c
            movi         a0, .Lrel070 /* sdk_chip_v6_set_chan_misc */ #  f1c: 01e9ff
            callx0       a0 /* sdk_chip_v6_set_chan_misc */    #  f1f: c00000
            movi         a6, .Lrel067 /* sdk_chip6_sleep_params */ #  f22: 61e4ff
            l32i.n       a6, a6, 0 /* [sdk_chip6_sleep_params] */ #  f25: 6806
            bbci         a6, 21, .Lbr101                       #  f27: 57760c
            movi.n       a2, 4 /* 0x00000004 */                #  f2a: 0c42
            movi.n       a3, 0 /* 0x00000000 */                #  f2c: 0c03
            movi         a0, .Lrel071 /* sdk_pm_wakeup_init */ #  f2e: 01e5ff
            callx0       a0 /* sdk_pm_wakeup_init */           #  f31: c00000
            j            .Lbr102                               #  f34: c60100
.Lbr101:    l32i.n       a2, a1, 16 /* [(local2)] */           #  f37: 2841
            movi         a0, .Lrel072 /* sdk_start_dig_rx */   #  f39: 01e3ff
            callx0       a0 /* sdk_start_dig_rx */             #  f3c: c00000
.Lbr102:    l32i.n       a12, a1, 24 /* [(local4)] */          #  f3f: c861
            l32i.n       a0, a1, 20 /* [(local3)] */           #  f41: 0851
            addi         a1, a1, 32 /* (top of frame) */       #  f43: 12c120
            ret.n                                              #  f46: 0df0

.Llit048:   .word        0x60000a00                            #  f48: 000a0060
.Lrel073:   .word        sdk_phy_freq_offset                   #  f4c: 00000000
.Lrel074:   .word        sdk_chip6_phy_init_ctrl               #  f50: 00000000
.Lrel075:   .word        sdk_chip6_sleep_params                #  f54: 00000000
.Lrel076:   .word        sdk_chip6_sleep_params+0x16c          #  f58: 00000000
.Lrel077:   .word        sdk_chip6_sleep_params+0x1d           #  f5c: 00000000
.Lrel078:   .word        sdk_tx_atten_set_interp               #  f60: 00000000

# Function @ .irom0.text+0xf64
# Local variables/stack:
#     (local0):  word      @ -0x20
#     (local1):  word[5]   @ -0x1c
#     (local2):  word      @ -0x8
#     (local3):  word      @ -0x4
.literal_position
sdk_chip_v6_set_chan_wakeup:
            addi         a1, a1, -32 /* (local0) */            #  f64: 12c1e0
            s32i.n       a0, a1, 24 /* a0 -> [(local2)] */     #  f67: 0961
            s32i.n       a12, a1, 28 /* a12 -> [(local3)] */   #  f69: c971
            movi         a8, 1024 /* 0x00000400 */             #  f6b: 82a400
            movi         a7, .Llit048 /* 0x60000a00 */         #  f6e: 71f6ff
            mov.n        a12, a2 /* arg0 */                    #  f71: cd02
            memw                                               #  f73: c02000
            l32i         a6, a7, 0x340 /* [0x60000d40] */      #  f76: 6227d0
            or           a6, a6, a8                            #  f79: 806620
            memw                                               #  f7c: c02000
            movi.n       a4, 0 /* 0x00000000 */                #  f7f: 0c04
            movi.n       a0, 0 /* 0x00000000 */                #  f81: 0c00
            movi         a2, 100 /* 0x00000064 */              #  f83: 22a064
            movi         a3, .Lrel074 /* sdk_chip6_phy_init_ctrl */ #  f86: 31f2ff
            s32i         a6, a7, 0x340 /* a6 -> [0x60000d40] */ #  f89: 6267d0
            movi         a5, .Lrel073 /* sdk_phy_freq_offset */ #  f8c: 51f0ff
            movi         a6, .Lrel075 /* sdk_chip6_sleep_params */ #  f8f: 61f1ff
            movi         a7, .Lrel076 /* sdk_chip6_sleep_params+0x16c */ #  f92: 71f1ff
            l16si        a5, a5, 0 /* [sdk_phy_freq_offset] */ #  f95: 529500
            l8ui         a3, a3, 1 /* [sdk_chip6_phy_init_ctrl+0x1] */ #  f98: 320301
            s32i.n       a2, a1, 0 /* 0x00000064 -> [(local0)] */ #  f9b: 2901
            s32i.n       a0, a1, 4 /* 0x00000000 -> [(local1)] */ #  f9d: 0911
            mov.n        a2, a12 /* arg0 */                    #  f9f: 2d0c
            call0        sdk_chip_60_set_channel               #  fa1: 050000
            movi         a3, .Lrel077 /* sdk_chip6_sleep_params+0x1d */ #  fa4: 31eeff
            addx2        a2, a12, a12                          #  fa7: c02c90
            add.n        a2, a2, a3                            #  faa: 3a22
            call0        sdk_set_txcap_reg                     #  fac: 050000
            extui        a2, a12, 0, 8                         #  faf: c02074
            addi         a3, a1, 16 /* (FP)-0x10 */            #  fb2: 32c110
            movi         a0, .Lrel078 /* sdk_tx_atten_set_interp */ #  fb5: 01eaff
            callx0       a0 /* sdk_tx_atten_set_interp */      #  fb8: c00000
            l32i.n       a12, a1, 28 /* [(local3)] */          #  fbb: c871
            l32i.n       a0, a1, 24 /* [(local2)] */           #  fbd: 0861
            addi         a1, a1, 32 /* (top of frame) */       #  fbf: 12c120
            ret.n                                              #  fc2: 0df0

.Llit049:   .word        0xf7ffffff                            #  fc4: fffffff7
.Llit050:   .word        0x60000600                            #  fc8: 00060060
.Lrel079:   .word        sdk_g_phyFuns                         #  fcc: 00000000
.Llit051:   .word        0x60000200                            #  fd0: 00020060
.Llit052:   .word        0x02000000                            #  fd4: 00000002
.Llit053:   .word        0x30000000                            #  fd8: 00000030
.Llit054:   .word        0x3ff20a00                            #  fdc: 000af23f
.Llit055:   .word        0xe0ffffff                            #  fe0: ffffffe0
.Llit056:   .word        0x1c000000                            #  fe4: 0000001c
.Llit057:   .word        0x60000200                            #  fe8: 00020060
.Llit058:   .word        0xcfffffff                            #  fec: ffffffcf
.Llit059:   .word        0x10000000                            #  ff0: 00000010
.Llit060:   .word        0x0c000000                            #  ff4: 0000000c
.Llit061:   .word        0x60000a00                            #  ff8: 000a0060
.Lrel080:   .word        sdk_chip6_sleep_params                #  ffc: 00000000
.Lrel081:   .word        sdk_ets_delay_us                      # 1000: 00000000

# Function @ .irom0.text+0x1004
# Local variables/stack:
#     (local0):  word      @ -0x10
#     (local1):  word      @ -0xc
#     (local2):  word      @ -0x8
#     (local3):  word      @ -0x4
.literal_position
sdk_chip_v6_rf_init:
            movi         a6, .Llit049 /* 0xf7ffffff */         # 1004: 61f0ff
            addi         a1, a1, -16 /* (local0) */            # 1007: 12c1f0
            s32i.n       a0, a1, 4 /* a0 -> [(local1)] */      # 100a: 0911
            s32i.n       a2, a1, 0 /* arg0 -> [(local0)] */    # 100c: 2901
            s32i.n       a12, a1, 8 /* a12 -> [(local2)] */    # 100e: c921
            s32i.n       a13, a1, 12 /* a13 -> [(local3)] */   # 1010: d931
            movi         a5, .Llit051 /* 0x60000200 */         # 1012: 51efff
            movi         a13, .Llit050 /* 0x60000600 */        # 1015: d1ecff
            movi         a12, .Lrel079 /* sdk_g_phyFuns */     # 1018: c1edff
            memw                                               # 101b: c02000
            l32i         a4, a5, 0x3e8 /* [0x600005e8] */      # 101e: 4225fa
            and          a4, a4, a6                            # 1021: 604410
            memw                                               # 1024: c02000
            s32i         a4, a5, 0x3e8 /* a4 -> [0x600005e8] */ # 1027: 4265fa
            movi         a3, .Llit052 /* 0x02000000 */         # 102a: 31eaff
            memw                                               # 102d: c02000
            l32i         a2, a13, 0x110 /* [0x60000710] */     # 1030: 222d44
            or           a2, a2, a3                            # 1033: 302220
            memw                                               # 1036: c02000
            movi.n       a3, 2 /* 0x00000002 */                # 1039: 0c23
            movi.n       a4, 0 /* 0x00000000 */                # 103b: 0c04
            movi.n       a5, 39 /* 0x00000027 */               # 103d: 2c75
            l32i.n       a0, a12, 0 /* [sdk_g_phyFuns] */      # 103f: 080c
            s32i         a2, a13, 0x110 /* a2 -> [0x60000710] */ # 1041: 226d44
            l32i         a0, a0, 152 /* [[sdk_g_phyFuns]+0x98] */ # 1044: 022026
            movi         a2, 106 /* 0x0000006a */              # 1047: 22a06a
            callx0       a0 /* [[sdk_g_phyFuns]+0x98] */       # 104a: c00000
            movi         a7, .Llit053 /* 0x30000000 */         # 104d: 71e2ff
            movi         a8, .Llit054 /* 0x3ff20a00 */         # 1050: 81e3ff
            memw                                               # 1053: c02000
            l32i         a6, a13, 0x110 /* [0x60000710] */     # 1056: 622d44
            or           a6, a6, a7                            # 1059: 706620
            memw                                               # 105c: c02000
            s32i         a6, a13, 0x110 /* a6 -> [0x60000710] */ # 105f: 626d44
            movi         a5, .Llit055 /* 0xe0ffffff */         # 1062: 51dfff
            movi         a4, .Llit056 /* 0x1c000000 */         # 1065: 41dfff
            memw                                               # 1068: c02000
            movi         a11, .Llit057 /* 0x60000200 */        # 106b: b1dfff
            l32i         a3, a11, 0x3a0 /* [0x600005a0] */     # 106e: 322be8
            and          a3, a3, a5                            # 1071: 503310
            or           a3, a3, a4                            # 1074: 403320
            memw                                               # 1077: c02000
            s32i         a3, a11, 0x3a0 /* a3 -> [0x600005a0] */ # 107a: 326be8
            movi         a2, .Llit058 /* 0xcfffffff */         # 107d: 21dbff
            movi         a0, .Llit059 /* 0x10000000 */         # 1080: 01dcff
            memw                                               # 1083: c02000
            l32i         a10, a11, 0x398 /* [0x60000598] */    # 1086: a22be6
            and          a10, a10, a2                          # 1089: 20aa10
            or           a10, a10, a0                          # 108c: 00aa20
            memw                                               # 108f: c02000
            s32i         a10, a11, 0x398 /* a10 -> [0x60000598] */ # 1092: a26be6
            movi.n       a9, -3 /* 0xfffffffd */               # 1095: 7cd9
            memw                                               # 1097: c02000
            l32i         a7, a8, 0x270 /* [0x3ff20c70] */      # 109a: 72289c
            and          a7, a7, a9                            # 109d: 907710
            memw                                               # 10a0: c02000
            s32i         a7, a8, 0x270 /* a7 -> [0x3ff20c70] */ # 10a3: 72689c
            movi.n       a2, 2 /* 0x00000002 */                # 10a6: 0c22
            movi         a0, .Lrel081 /* sdk_ets_delay_us */   # 10a8: 01d6ff
            callx0       a0 /* sdk_ets_delay_us */             # 10ab: c00000
            l32i.n       a0, a12, 0 /* [sdk_g_phyFuns] */      # 10ae: 080c
            l32i         a0, a0, 160 /* [[sdk_g_phyFuns]+0xa0] */ # 10b0: 022028
            callx0       a0 /* [[sdk_g_phyFuns]+0xa0] */       # 10b3: c00000
            movi.n       a2, 2 /* 0x00000002 */                # 10b6: 0c22
            l32i.n       a0, a12, 0 /* [sdk_g_phyFuns] */      # 10b8: 080c
            movi.n       a3, 1 /* 0x00000001 */                # 10ba: 0c13
            l32i         a0, a0, 172 /* [[sdk_g_phyFuns]+0xac] */ # 10bc: 02202b
            movi         a4, 129 /* 0x00000081 */              # 10bf: 42a081
            callx0       a0 /* [[sdk_g_phyFuns]+0xac] */       # 10c2: c00000
            movi         a3, .Llit060 /* 0x0c000000 */         # 10c5: 31cbff
            memw                                               # 10c8: c02000
            l32i         a2, a13, 0x110 /* [0x60000710] */     # 10cb: 222d44
            or           a2, a2, a3                            # 10ce: 302220
            memw                                               # 10d1: c02000
            l32i.n       a0, a12, 0 /* [sdk_g_phyFuns] */      # 10d4: 080c
            l32i         a0, a0, 200 /* [[sdk_g_phyFuns]+0xc8] */ # 10d6: 022032
            s32i         a2, a13, 0x110 /* a2 -> [0x60000710] */ # 10d9: 226d44
            callx0       a0 /* [[sdk_g_phyFuns]+0xc8] */       # 10dc: c00000
            movi         a2, 106 /* 0x0000006a */              # 10df: 22a06a
            movi.n       a3, 2 /* 0x00000002 */                # 10e2: 0c23
            l32i.n       a0, a12, 0 /* [sdk_g_phyFuns] */      # 10e4: 080c
            movi.n       a4, 0 /* 0x00000000 */                # 10e6: 0c04
            l32i         a0, a0, 152 /* [[sdk_g_phyFuns]+0x98] */ # 10e8: 022026
            movi.n       a5, 36 /* 0x00000024 */               # 10eb: 2c45
            callx0       a0 /* [[sdk_g_phyFuns]+0x98] */       # 10ed: c00000
            l32i.n       a0, a12, 0 /* [sdk_g_phyFuns] */      # 10f0: 080c
            l32i         a0, a0, 196 /* [[sdk_g_phyFuns]+0xc4] */ # 10f2: 022031
            callx0       a0 /* [[sdk_g_phyFuns]+0xc4] */       # 10f5: c00000
            movi         a2, 106 /* 0x0000006a */              # 10f8: 22a06a
            movi.n       a3, 2 /* 0x00000002 */                # 10fb: 0c23
            l32i.n       a0, a12, 0 /* [sdk_g_phyFuns] */      # 10fd: 080c
            movi.n       a4, 0 /* 0x00000000 */                # 10ff: 0c04
            l32i         a0, a0, 152 /* [[sdk_g_phyFuns]+0x98] */ # 1101: 022026
            movi.n       a5, 37 /* 0x00000025 */               # 1104: 2c55
            callx0       a0 /* [[sdk_g_phyFuns]+0x98] */       # 1106: c00000
            l32i.n       a0, a12, 0 /* [sdk_g_phyFuns] */      # 1109: 080c
            l32i         a0, a0, 188 /* [[sdk_g_phyFuns]+0xbc] */ # 110b: 02202f
            callx0       a0 /* [[sdk_g_phyFuns]+0xbc] */       # 110e: c00000
            movi         a4, -1537 /* 0xfffff9ff */            # 1111: 42a9ff
            movi         a3, .Llit061 /* 0x60000a00 */         # 1114: 31b9ff
            memw                                               # 1117: c02000
            l32i         a2, a3, 0x340 /* [0x60000d40] */      # 111a: 2223d0
            and          a2, a2, a4                            # 111d: 402210
            memw                                               # 1120: c02000
            movi.n       a4, 0 /* 0x00000000 */                # 1123: 0c04
            movi.n       a5, 4 /* 0x00000004 */                # 1125: 0c45
            movi.n       a6, 0 /* 0x00000000 */                # 1127: 0c06
            movi.n       a7, 8 /* 0x00000008 */                # 1129: 0c87
            l32i.n       a0, a12, 0 /* [sdk_g_phyFuns] */      # 112b: 080c
            s32i         a2, a3, 0x340 /* a2 -> [0x60000d40] */ # 112d: 2263d0
            movi         a2, 98 /* 0x00000062 */               # 1130: 22a062
            l32i         a0, a0, 156 /* [[sdk_g_phyFuns]+0x9c] */ # 1133: 022027
            movi.n       a3, 1 /* 0x00000001 */                # 1136: 0c13
            callx0       a0 /* [[sdk_g_phyFuns]+0x9c] */       # 1138: c00000
            movi         a0, .Lrel080 /* sdk_chip6_sleep_params */ # 113b: 01b0ff
            l32i.n       a5, a0, 0 /* [sdk_chip6_sleep_params] */ # 113e: 5800
            bbsi         a5, 27, .Lbr103                       # 1140: b7f507
            l32i.n       a2, a1, 0 /* [(local0)] */            # 1143: 2801
            call0        sdk_chip_v6_set_chan                  # 1145: 050000
            j            .Lbr104                               # 1148: c60200
.Lbr103:    l8ui         a2, a0, 78 /* [sdk_chip6_sleep_params+0x4e] */ # 114b: 22004e
            slli         a2, a2, 24                            # 114e: 802201
            srai         a2, a2, 24                            # 1151: 202831
            call0        sdk_chip_v6_set_chan_wakeup           # 1154: 050000
.Lbr104:    l32i.n       a0, a12, 0 /* [sdk_g_phyFuns] */      # 1157: 080c
            l32i         a0, a0, 140 /* [[sdk_g_phyFuns]+0x8c] */ # 1159: 022023
            callx0       a0 /* [[sdk_g_phyFuns]+0x8c] */       # 115c: c00000
            movi         a2, 107 /* 0x0000006b */              # 115f: 22a06b
            movi.n       a3, 2 /* 0x00000002 */                # 1162: 0c23
            l32i.n       a0, a12, 0 /* [sdk_g_phyFuns] */      # 1164: 080c
            movi.n       a4, 1 /* 0x00000001 */                # 1166: 0c14
            l32i         a0, a0, 152 /* [[sdk_g_phyFuns]+0x98] */ # 1168: 022026
            movi.n       a5, 72 /* 0x00000048 */               # 116b: 4c85
            callx0       a0 /* [[sdk_g_phyFuns]+0x98] */       # 116d: c00000
            l32i.n       a0, a12, 0 /* [sdk_g_phyFuns] */      # 1170: 080c
            l32i         a0, a0, 136 /* [[sdk_g_phyFuns]+0x88] */ # 1172: 022022
            callx0       a0 /* [[sdk_g_phyFuns]+0x88] */       # 1175: c00000
            movi         a2, 108 /* 0x0000006c */              # 1178: 22a06c
            movi.n       a3, 2 /* 0x00000002 */                # 117b: 0c23
            movi.n       a4, 0 /* 0x00000000 */                # 117d: 0c04
            movi.n       a5, 0 /* 0x00000000 */                # 117f: 0c05
            l32i.n       a0, a12, 0 /* [sdk_g_phyFuns] */      # 1181: 080c
            movi.n       a6, 0 /* 0x00000000 */                # 1183: 0c06
            l32i         a0, a0, 156 /* [[sdk_g_phyFuns]+0x9c] */ # 1185: 022027
            movi.n       a7, 1 /* 0x00000001 */                # 1188: 0c17
            callx0       a0 /* [[sdk_g_phyFuns]+0x9c] */       # 118a: c00000
            movi         a2, 108 /* 0x0000006c */              # 118d: 22a06c
            movi.n       a3, 2 /* 0x00000002 */                # 1190: 0c23
            movi.n       a4, 0 /* 0x00000000 */                # 1192: 0c04
            movi.n       a5, 2 /* 0x00000002 */                # 1194: 0c25
            l32i.n       a0, a12, 0 /* [sdk_g_phyFuns] */      # 1196: 080c
            movi.n       a6, 2 /* 0x00000002 */                # 1198: 0c26
            l32i         a0, a0, 156 /* [[sdk_g_phyFuns]+0x9c] */ # 119a: 022027
            movi.n       a7, 1 /* 0x00000001 */                # 119d: 0c17
            callx0       a0 /* [[sdk_g_phyFuns]+0x9c] */       # 119f: c00000
            l32i.n       a0, a12, 0 /* [sdk_g_phyFuns] */      # 11a2: 080c
            l32i         a0, a0, 76 /* [[sdk_g_phyFuns]+0x4c] */ # 11a4: 022013
            callx0       a0 /* [[sdk_g_phyFuns]+0x4c] */       # 11a7: c00000
            movi         a2, 119 /* 0x00000077 */              # 11aa: 22a077
            movi.n       a3, 0 /* 0x00000000 */                # 11ad: 0c03
            movi.n       a4, 26 /* 0x0000001a */               # 11af: 1ca4
            movi.n       a5, 4 /* 0x00000004 */                # 11b1: 0c45
            l32i.n       a0, a12, 0 /* [sdk_g_phyFuns] */      # 11b3: 080c
            movi.n       a6, 4 /* 0x00000004 */                # 11b5: 0c46
            l32i         a0, a0, 156 /* [[sdk_g_phyFuns]+0x9c] */ # 11b7: 022027
            movi.n       a7, 0 /* 0x00000000 */                # 11ba: 0c07
            callx0       a0 /* [[sdk_g_phyFuns]+0x9c] */       # 11bc: c00000
            movi         a2, 119 /* 0x00000077 */              # 11bf: 22a077
            movi.n       a3, 0 /* 0x00000000 */                # 11c2: 0c03
            movi.n       a4, 26 /* 0x0000001a */               # 11c4: 1ca4
            movi.n       a5, 5 /* 0x00000005 */                # 11c6: 0c55
            l32i.n       a0, a12, 0 /* [sdk_g_phyFuns] */      # 11c8: 080c
            movi.n       a6, 5 /* 0x00000005 */                # 11ca: 0c56
            l32i         a0, a0, 156 /* [[sdk_g_phyFuns]+0x9c] */ # 11cc: 022027
            movi.n       a7, 0 /* 0x00000000 */                # 11cf: 0c07
            callx0       a0 /* [[sdk_g_phyFuns]+0x9c] */       # 11d1: c00000
            movi         a2, 119 /* 0x00000077 */              # 11d4: 22a077
            movi.n       a3, 0 /* 0x00000000 */                # 11d7: 0c03
            movi.n       a4, 26 /* 0x0000001a */               # 11d9: 1ca4
            movi.n       a5, 4 /* 0x00000004 */                # 11db: 0c45
            l32i.n       a0, a12, 0 /* [sdk_g_phyFuns] */      # 11dd: 080c
            movi.n       a6, 4 /* 0x00000004 */                # 11df: 0c46
            l32i         a0, a0, 156 /* [[sdk_g_phyFuns]+0x9c] */ # 11e1: 022027
            movi.n       a7, 1 /* 0x00000001 */                # 11e4: 0c17
            callx0       a0 /* [[sdk_g_phyFuns]+0x9c] */       # 11e6: c00000
            movi         a2, 119 /* 0x00000077 */              # 11e9: 22a077
            movi.n       a3, 0 /* 0x00000000 */                # 11ec: 0c03
            movi.n       a4, 26 /* 0x0000001a */               # 11ee: 1ca4
            movi.n       a5, 5 /* 0x00000005 */                # 11f0: 0c55
            l32i.n       a0, a12, 0 /* [sdk_g_phyFuns] */      # 11f2: 080c
            movi.n       a6, 5 /* 0x00000005 */                # 11f4: 0c56
            l32i         a0, a0, 156 /* [[sdk_g_phyFuns]+0x9c] */ # 11f6: 022027
            movi.n       a7, 1 /* 0x00000001 */                # 11f9: 0c17
            callx0       a0 /* [[sdk_g_phyFuns]+0x9c] */       # 11fb: c00000
            movi.n       a2, 0 /* 0x00000000 */                # 11fe: 0c02
            l32i.n       a12, a1, 8 /* [(local2)] */           # 1200: c821
            l32i.n       a13, a1, 12 /* [(local3)] */          # 1202: d831
            l32i.n       a0, a1, 4 /* [(local1)] */            # 1204: 0811
            addi         a1, a1, 16 /* (top of frame) */       # 1206: 12c110
            ret.n         /* 0x00000000 */                     # 1209: 0df0

            .balign      4
.Lrel082:   .word        sdk_chip6_sleep_params                # 120c: 00000000
.Llit062:   .word        0x60000200                            # 1210: 00020060
.Llit063:   .word        0xfffe1f00                            # 1214: 001ffeff
.Lrel083:   .word        sdk_chip6_sleep_params                # 1218: 00000000

# Function @ .irom0.text+0x121c
.literal_position
sdk_low_power_set:
            movi         a6, .Lrel082 /* sdk_chip6_sleep_params */ # 121c: 61fcff
            movi.n       a11, 24 /* 0x00000018 */              # 121f: 1c8b
            l8ui         a9, a6, 120 /* [sdk_chip6_sleep_params+0x78] */ # 1221: 920678
            movi         a7, .Llit062 /* 0x60000200 */         # 1224: 71fbff
            slli         a9, a9, 24                            # 1227: 809901
            srai         a9, a9, 24                            # 122a: 909831
            sub          a9, a4, a9                            # 122d: 9094c0
            beqz.n       a2, .Lbr106                           # 1230: bc22
            movi.n       a2, 0 /* 0x00000000 */                # 1232: 0c02
            slli         a10, a3, 13                           # 1234: 30a311
            movi         a3, .Llit063 /* 0xfffe1f00 */         # 1237: 31f7ff
.Lbr105:    addx4        a6, a2, a7                            # 123a: 7062a0
            memw                                               # 123d: c02000
            l32i         a8, a6, 0x304                         # 1240: 8226c1
            and          a5, a8, a3                            # 1243: 305810
            sub          a8, a8, a9                            # 1246: 9088c0
            or           a5, a10, a5                           # 1249: 505a20
            extui        a8, a8, 0, 8                          # 124c: 808074
            or           a5, a5, a8                            # 124f: 805520
            memw                                               # 1252: c02000
            s32i         a5, a6, 0x304                         # 1255: 5266c1
            addi.n       a2, a2, 1                             # 1258: 1b22
            extui        a2, a2, 0, 8                          # 125a: 202074
            bne          a2, a11, .Lbr105                      # 125d: b792d9
            movi         a9, .Lrel083 /* sdk_chip6_sleep_params */ # 1260: 91eeff
            s8i          a4, a9, 120 /* arg2 -> [sdk_chip6_sleep_params+0x78] */ # 1263: 424978
.Lbr106:    ret.n                                              # 1266: 0df0

.Llit064:   .word        0x60000200                            # 1268: 00020060
.Llit065:   .word        0x3feffe00                            # 126c: 00feef3f
.Llit066:   .word        0xfe000000                            # 1270: 000000fe
.Llit067:   .word        0x60000600                            # 1274: 00060060
.Llit068:   .word        0x038f0000                            # 1278: 00008f03
.Llit069:   .word        0xfe000000                            # 127c: 000000fe
.Lrel084:   .word        sdk_g_phyFuns                         # 1280: 00000000
.Lrel085:   .word        sdk_g_phyFuns                         # 1284: 00000000
.Llit070:   .word        0x01800000                            # 1288: 00008001
.Lrel086:   .word        sdk_g_phyFuns                         # 128c: 00000000
.Llit071:   .word        0x00200000                            # 1290: 00002000
.Llit072:   .word        0x60000a00                            # 1294: 000a0060
.Lrel087:   .word        .Lstr003                              # 1298: 40000000
.Lrel088:   .word        sdk_g_phyFuns                         # 129c: 00000000
.Llit073:   .word        0xfe000000                            # 12a0: 000000fe
.Llit074:   .word        0xffdfffff                            # 12a4: ffffdfff
.Llit075:   .word        0xfe7fffff                            # 12a8: ffff7ffe
.Llit076:   .word        0x00800000                            # 12ac: 00008000
.Llit077:   .word        0x60000200                            # 12b0: 00020060
.Llit078:   .word        0x60000600                            # 12b4: 00060060
.Llit079:   .word        0x3feffe00                            # 12b8: 00feef3f
.Lrel089:   .word        sdk_ets_delay_us                      # 12bc: 00000000
.Lrel090:   .word        sdk_ets_delay_us                      # 12c0: 00000000
.Lrel091:   .word        sdk_pm_set_sleep_mode                 # 12c4: 00000000
.Lrel092:   .word        sdk_ets_delay_us                      # 12c8: 00000000
.Lrel093:   .word        sdk_read_sar_dout                     # 12cc: 00000000
.Lrel094:   .word        ets_printf                            # 12d0: 00000000
.Lrel095:   .word        sdk_pm_wakeup_init                    # 12d4: 00000000

# Function @ .irom0.text+0x12d8
# Local variables/stack:
#     (local0):  word      @ -0x30
#     (local1):  word      @ -0x2c
#     (local2):  word      @ -0x28
#     (local3):  word      @ -0x24
#     (local4):  word      @ -0x20
#     (local5):  word      @ -0x1c
#     (local6):  word      @ -0x18
#     (local7):  word      @ -0x14
#     (local8):  word[4]   @ -0x10
.literal_position
sdk_test_tout:
            addi         a1, a1, -64 /* (FP)-0x40 */           # 12d8: 12c1c0
            s32i.n       a13, a1, 36 /* a13 -> [(local5)] */   # 12db: d991
            s32i.n       a14, a1, 40 /* a14 -> [(local6)] */   # 12dd: e9a1
            s32i.n       a0, a1, 28 /* a0 -> [(local3)] */     # 12df: 0971
            s32i.n       a15, a1, 44 /* a15 -> [(local7)] */   # 12e1: f9b1
            s32i.n       a12, a1, 32 /* a12 -> [(local4)] */   # 12e3: c981
            movi         a15, .Llit064 /* 0x60000200 */        # 12e5: f1e0ff
            movi         a12, .Llit065 /* 0x3feffe00 */        # 12e8: c1e1ff
            movi         a0, .Llit066 /* 0xfe000000 */         # 12eb: 01e1ff
            movi         a14, .Llit067 /* 0x60000600 */        # 12ee: e1e1ff
            memw                                               # 12f1: c02000
            l32i         a13, a14, 0x110 /* [0x60000710] */    # 12f4: d22e44
            s32i.n       a2, a1, 48 /* arg0 -> [(local8)] */   # 12f7: 29c1
            and          a3, a13, a0                           # 12f9: 003d10
            s32i.n       a3, a1, 24 /* a3 -> [(local2)] */     # 12fc: 3961
            ball         a13, a0, .Lbr107                      # 12fe: 074d6d
            memw                                               # 1301: c02000
            l32i         a5, a12, 0x218 /* [0x3ff00018] */     # 1304: 522c86
            s32i.n       a5, a1, 16 /* [0x3ff00018] -> [(local0)] */ # 1307: 5941
            movi         a4, .Llit068 /* 0x038f0000 */         # 1309: 41dbff
            memw                                               # 130c: c02000
            l32i         a3, a12, 0x218 /* [0x3ff00018] */     # 130f: 322c86
            or           a3, a3, a4                            # 1312: 403320
            memw                                               # 1315: c02000
            s32i         a3, a12, 0x218 /* a3 -> [0x3ff00018] */ # 1318: 326c86
            movi         a2, .Llit069 /* 0xfe000000 */         # 131b: 21d8ff
            or           a2, a13, a2                           # 131e: 202d20
            memw                                               # 1321: c02000
            movi.n       a3, 1 /* 0x00000001 */                # 1324: 0c13
            movi.n       a4, 3 /* 0x00000003 */                # 1326: 0c34
            movi.n       a5, 7 /* 0x00000007 */                # 1328: 0c75
            movi.n       a6, 4 /* 0x00000004 */                # 132a: 0c46
            movi         a0, .Lrel084 /* sdk_g_phyFuns */      # 132c: 01d5ff
            movi.n       a7, 15 /* 0x0000000f */               # 132f: 0cf7
            l32i.n       a0, a0, 0 /* [sdk_g_phyFuns] */       # 1331: 0800
            s32i         a2, a14, 0x110 /* a2 -> [0x60000710] */ # 1333: 226e44
            l32i         a0, a0, 156 /* [[sdk_g_phyFuns]+0x9c] */ # 1336: 022027
            movi         a2, 98 /* 0x00000062 */               # 1339: 22a062
            callx0       a0 /* [[sdk_g_phyFuns]+0x9c] */       # 133c: c00000
            movi         a0, .Lrel085 /* sdk_g_phyFuns */      # 133f: 01d1ff
            l32i.n       a0, a0, 0 /* [sdk_g_phyFuns] */       # 1342: 0800
            l32i         a0, a0, 76 /* [[sdk_g_phyFuns]+0x4c] */ # 1344: 022013
            callx0       a0 /* [[sdk_g_phyFuns]+0x4c] */       # 1347: c00000
            movi.n       a2, 2 /* 0x00000002 */                # 134a: 0c22
            movi         a0, .Lrel089 /* sdk_ets_delay_us */   # 134c: 01dcff
            callx0       a0 /* sdk_ets_delay_us */             # 134f: c00000
            movi         a3, .Llit070 /* 0x01800000 */         # 1352: 31cdff
            memw                                               # 1355: c02000
            l32i         a2, a15, 0x3e8 /* [0x600005e8] */     # 1358: 222ffa
            or           a2, a2, a3                            # 135b: 302220
            memw                                               # 135e: c02000
            s32i         a2, a15, 0x3e8 /* a2 -> [0x600005e8] */ # 1361: 226ffa
            movi.n       a2, 2 /* 0x00000002 */                # 1364: 0c22
            movi         a0, .Lrel090 /* sdk_ets_delay_us */   # 1366: 01d6ff
            callx0       a0 /* sdk_ets_delay_us */             # 1369: c00000
            j            .Lbr108                               # 136c: c60100
.Lbr107:    movi.n       a2, 4 /* 0x00000004 */                # 136f: 0c42
            movi         a0, .Lrel091 /* sdk_pm_set_sleep_mode */ # 1371: 01d4ff
            callx0       a0 /* sdk_pm_set_sleep_mode */        # 1374: c00000
.Lbr108:    movi         a2, 108 /* 0x0000006c */              # 1377: 22a06c
            movi.n       a3, 2 /* 0x00000002 */                # 137a: 0c23
            movi.n       a4, 0 /* 0x00000000 */                # 137c: 0c04
            movi         a0, .Lrel086 /* sdk_g_phyFuns */      # 137e: 01c3ff
            movi.n       a5, 5 /* 0x00000005 */                # 1381: 0c55
            l32i.n       a0, a0, 0 /* [sdk_g_phyFuns] */       # 1383: 0800
            movi.n       a6, 5 /* 0x00000005 */                # 1385: 0c56
            l32i         a0, a0, 156 /* [[sdk_g_phyFuns]+0x9c] */ # 1387: 022027
            movi.n       a7, 1 /* 0x00000001 */                # 138a: 0c17
            callx0       a0 /* [[sdk_g_phyFuns]+0x9c] */       # 138c: c00000
            movi         a5, .Llit071 /* 0x00200000 */         # 138f: 51c0ff
            movi.n       a2, 7 /* 0x00000007 */                # 1392: 0c72
            movi         a12, .Llit072 /* 0x60000a00 */        # 1394: c1c0ff
            memw                                               # 1397: c02000
            l32i         a4, a12, 0x35c /* [0x60000d5c] */     # 139a: 422cd7
            or           a4, a4, a5                            # 139d: 504420
            memw                                               # 13a0: c02000
            s32i         a4, a12, 0x35c /* a4 -> [0x60000d5c] */ # 13a3: 426cd7
            memw                                               # 13a6: c02000
            l32i         a3, a12, 0x350 /* [0x60000d50] */     # 13a9: 322cd4
            extui        a3, a3, 24, 8                         # 13ac: 303875
            bnone        a2, a3, .Lbr110                       # 13af: 37020b
.Lbr109:    memw                                               # 13b2: c02000
            l32i         a6, a12, 0x350 /* [0x60000d50] */     # 13b5: 622cd4
            extui        a6, a6, 24, 3                         # 13b8: 606825
            bnez         a6, .Lbr109                           # 13bb: 5636ff
.Lbr110:    movi.n       a9, -3 /* 0xfffffffd */               # 13be: 7cd9
            memw                                               # 13c0: c02000
            l32i         a8, a12, 0x350 /* [0x60000d50] */     # 13c3: 822cd4
            and          a8, a8, a9                            # 13c6: 908810
            memw                                               # 13c9: c02000
            s32i         a8, a12, 0x350 /* a8 -> [0x60000d50] */ # 13cc: 826cd4
            movi.n       a2, 2 /* 0x00000002 */                # 13cf: 0c22
            memw                                               # 13d1: c02000
            l32i         a7, a12, 0x350 /* [0x60000d50] */     # 13d4: 722cd4
            or           a7, a7, a2                            # 13d7: 207720
            memw                                               # 13da: c02000
            s32i         a7, a12, 0x350 /* a7 -> [0x60000d50] */ # 13dd: 726cd4
            movi         a0, .Lrel092 /* sdk_ets_delay_us */   # 13e0: 01baff
            callx0       a0 /* sdk_ets_delay_us */             # 13e3: c00000
            memw                                               # 13e6: c02000
            l32i         a11, a12, 0x350 /* [0x60000d50] */    # 13e9: b22cd4
            movi.n       a10, 7 /* 0x00000007 */               # 13ec: 0c7a
            extui        a11, a11, 24, 8                       # 13ee: b0b875
            bnone        a10, a11, .Lbr112                     # 13f1: b70a0b
.Lbr111:    memw                                               # 13f4: c02000
            l32i         a0, a12, 0x350 /* [0x60000d50] */     # 13f7: 022cd4
            extui        a0, a0, 24, 3                         # 13fa: 000825
            bnez         a0, .Lbr111                           # 13fd: 5630ff
.Lbr112:    mov.n        a2, a1 /* (FP)-0x40 */                # 1400: 2d01
            s32i.n       a13, a1, 20 /* [0x60000710] -> [(local1)] */ # 1402: d951
            movi         a0, .Lrel093 /* sdk_read_sar_dout */  # 1404: 01b2ff
            callx0       a0 /* sdk_read_sar_dout */            # 1407: c00000
            l32i.n       a15, a1, 48 /* [(local8)] */          # 140a: f8c1
            movi.n       a13, 0 /* 0x00000000 */               # 140c: 0c0d
            movi.n       a14, 0 /* 0x00000000 */               # 140e: 0c0e
            mov.n        a0, a1 /* (FP)-0x40 */                # 1410: 0d01
.Lbr113:    addx2        a3, a13, a0                           # 1412: 003d90
            l16ui        a3, a3, 0                             # 1415: 321300
            add.n        a14, a3, a14                          # 1418: eae3
            extui        a14, a14, 0, 16                       # 141a: e0e0f4
            beqz.n       a15, .Lbr114                          # 141d: 8c9f
            movi         a2, .Lrel087 /* .Lrel087 */           # 141f: 219eff
            movi         a0, .Lrel094 /* .Lrel094 */           # 1422: 01abff
            callx0       a0                                    # 1425: c00000
            mov.n        a0, a1 /* (FP)-0x40 */                # 1428: 0d01
.Lbr114:    addi.n       a13, a13, 1                           # 142a: 1bdd
            extui        a13, a13, 0, 8                        # 142c: d0d074
            bnei         a13, 8, .Lbr113                       # 142f: 668ddf
            movi         a2, 108 /* 0x0000006c */              # 1432: 22a06c
            movi.n       a3, 2 /* 0x00000002 */                # 1435: 0c23
            movi.n       a4, 0 /* 0x00000000 */                # 1437: 0c04
            movi         a13, .Lrel088 /* sdk_g_phyFuns */     # 1439: d198ff
            movi.n       a5, 5 /* 0x00000005 */                # 143c: 0c55
            l32i.n       a0, a13, 0 /* [sdk_g_phyFuns] */      # 143e: 080d
            movi.n       a6, 5 /* 0x00000005 */                # 1440: 0c56
            l32i         a0, a0, 156 /* [[sdk_g_phyFuns]+0x9c] */ # 1442: 022027
            movi.n       a7, 0 /* 0x00000000 */                # 1445: 0c07
            callx0       a0 /* [[sdk_g_phyFuns]+0x9c] */       # 1447: c00000
            movi         a0, .Llit073 /* 0xfe000000 */         # 144a: 0195ff
            l32i.n       a2, a1, 24 /* [(local2)] */           # 144d: 2861
            memw                                               # 144f: c02000
            l32i         a4, a12, 0x350 /* [0x60000d50] */     # 1452: 422cd4
            movi.n       a3, 7 /* 0x00000007 */                # 1455: 0c73
            extui        a4, a4, 24, 8                         # 1457: 404875
            bnone        a3, a4, .Lbr116                       # 145a: 47030b
.Lbr115:    memw                                               # 145d: c02000
            l32i         a5, a12, 0x350 /* [0x60000d50] */     # 1460: 522cd4
            extui        a5, a5, 24, 3                         # 1463: 505825
            bnez         a5, .Lbr115                           # 1466: 5635ff
.Lbr116:    movi         a11, .Llit074 /* 0xffdfffff */        # 1469: b18eff
            memw                                               # 146c: c02000
            l32i         a10, a12, 0x35c /* [0x60000d5c] */    # 146f: a22cd7
            and          a10, a10, a11                         # 1472: b0aa10
            memw                                               # 1475: c02000
            s32i         a10, a12, 0x35c /* a10 -> [0x60000d5c] */ # 1478: a26cd7
            movi.n       a9, -2 /* 0xfffffffe */               # 147b: 7ce9
            memw                                               # 147d: c02000
            l32i         a8, a12, 0x360 /* [0x60000d60] */     # 1480: 822cd8
            and          a8, a8, a9                            # 1483: 908810
            memw                                               # 1486: c02000
            s32i         a8, a12, 0x360 /* a8 -> [0x60000d60] */ # 1489: 826cd8
            movi.n       a7, 1 /* 0x00000001 */                # 148c: 0c17
            memw                                               # 148e: c02000
            l32i         a6, a12, 0x360 /* [0x60000d60] */     # 1491: 622cd8
            or           a6, a6, a7                            # 1494: 706620
            memw                                               # 1497: c02000
            s32i         a6, a12, 0x360 /* a6 -> [0x60000d60] */ # 149a: 626cd8
            beq          a2, a0, .Lbr117                       # 149d: 071248
            l32i.n       a12, a1, 16 /* [(local0)] */          # 14a0: c841
            movi         a5, .Llit075 /* 0xfe7fffff */         # 14a2: 5181ff
            movi         a4, .Llit076 /* 0x00800000 */         # 14a5: 4181ff
            memw                                               # 14a8: c02000
            movi         a3, .Llit077 /* 0x60000200 */         # 14ab: 3181ff
            l32i         a2, a3, 0x3e8 /* [0x600005e8] */      # 14ae: 2223fa
            and          a2, a2, a5                            # 14b1: 502210
            or           a2, a2, a4                            # 14b4: 402220
            memw                                               # 14b7: c02000
            movi.n       a4, 3 /* 0x00000003 */                # 14ba: 0c34
            movi.n       a5, 7 /* 0x00000007 */                # 14bc: 0c75
            movi.n       a6, 4 /* 0x00000004 */                # 14be: 0c46
            movi.n       a7, 0 /* 0x00000000 */                # 14c0: 0c07
            l32i.n       a0, a13, 0 /* [sdk_g_phyFuns] */      # 14c2: 080d
            s32i         a2, a3, 0x3e8 /* a2 -> [0x600005e8] */ # 14c4: 2263fa
            movi         a2, 98 /* 0x00000062 */               # 14c7: 22a062
            l32i         a0, a0, 156 /* [[sdk_g_phyFuns]+0x9c] */ # 14ca: 022027
            movi.n       a3, 1 /* 0x00000001 */                # 14cd: 0c13
            callx0       a0 /* [[sdk_g_phyFuns]+0x9c] */       # 14cf: c00000
            memw                                               # 14d2: c02000
            movi         a8, .Llit078 /* 0x60000600 */         # 14d5: 8177ff
            l32i.n       a7, a1, 20 /* [(local1)] */           # 14d8: 7851
            s32i         a7, a8, 0x110 /* [(local1)] -> [0x60000710] */ # 14da: 726844
            memw                                               # 14dd: c02000
            movi         a6, .Llit079 /* 0x3feffe00 */         # 14e0: 6176ff
            s32i         a12, a6, 0x218 /* [(local0)] -> [0x3ff00018] */ # 14e3: c26686
            j            .Lbr118                               # 14e6: 460200
.Lbr117:    movi.n       a2, 4 /* 0x00000004 */                # 14e9: 0c42
            movi.n       a3, 0 /* 0x00000000 */                # 14eb: 0c03
            movi         a0, .Lrel095 /* sdk_pm_wakeup_init */ # 14ed: 0179ff
            callx0       a0 /* sdk_pm_wakeup_init */           # 14f0: c00000
.Lbr118:    l32i.n       a0, a1, 28 /* [(local3)] */           # 14f3: 0871
            l32i.n       a12, a1, 32 /* [(local4)] */          # 14f5: c881
            l32i.n       a13, a1, 36 /* [(local5)] */          # 14f7: d891
            addi.n       a2, a14, 8                            # 14f9: 8b2e
            l32i.n       a15, a1, 44 /* [(local7)] */          # 14fb: f8b1
            l32i.n       a14, a1, 40 /* [(local6)] */          # 14fd: e8a1
            extui        a2, a2, 4, 16                         # 14ff: 2024f4
            addi         a1, a1, 64 /* (top of frame) */       # 1502: 12c140
            ret.n                                              # 1505: 0df0

            .balign      4
# Function @ .irom0.text+0x1508
.literal_position
sdk_check_data_flag:
            mov.n        a9, a2 /* arg0 */                     # 1508: 9d02
            mov.n        a2, a5 /* arg3 */                     # 150a: 2d05
            blt          a9, a3, .Lbr119                       # 150c: 372902
            bge          a4, a9, .Lbr120                       # 150f: 97a40a
.Lbr119:    ssl          a6                                    # 1512: 001640
            movi.n       a3, 1 /* 0x00000001 */                # 1515: 0c13
            sll          a3, a3                                # 1517: 0033a1
            or           a2, a2, a3                            # 151a: 302220
.Lbr120:    ret.n                                              # 151d: 0df0

            .balign      4
.Lrel096:   .word        sdk_chip6_sleep_params                # 1520: 00000000
.Lrel097:   .word        sdk_chip6_sleep_params                # 1524: 00000000
.Llit080:   .word        0x00000ff4                            # 1528: f40f0000
.Llit081:   .word        0x00000ff4                            # 152c: f40f0000
.Lrel098:   .word        sdk_chip6_sleep_params                # 1530: 00000000
.Lrel099:   .word        sdk_chip6_sleep_params                # 1534: 00000000
.Lrel100:   .word        sdk_chip6_sleep_params+0xf0           # 1538: 00000000

# Function @ .irom0.text+0x153c
# Local variables/stack:
#     (local0):  word      @ -0x20
#     (local1):  word      @ -0x1c
#     (local2):  word      @ -0x18
#     (local3):  word      @ -0x14
#     (local4):  word      @ -0x10
#     (local5):  word[3]   @ -0xc
.literal_position
sdk_get_check_flag:
            movi.n       a5, 0 /* 0x00000000 */                # 153c: 0c05
            addi         a1, a1, -32 /* (local0) */            # 153e: 12c1e0
            s32i.n       a15, a1, 16 /* a15 -> [(local4)] */   # 1541: f941
            s32i.n       a0, a1, 0 /* a0 -> [(local0)] */      # 1543: 0901
            s32i.n       a13, a1, 8 /* a13 -> [(local2)] */    # 1545: d921
            s32i.n       a12, a1, 4 /* a12 -> [(local1)] */    # 1547: c911
            movi         a13, .Lrel096 /* sdk_chip6_sleep_params */ # 1549: d1f5ff
            s32i.n       a14, a1, 12 /* a14 -> [(local3)] */   # 154c: e931
            mov.n        a12, a13 /* sdk_chip6_sleep_params */ # 154e: cd0d
            addi.n       a14, a13, 8 /* sdk_chip6_sleep_params+0x8 */ # 1550: 8bed
.Lbr121:    movi.n       a3, 0 /* 0x00000000 */                # 1552: 0c03
            movi.n       a4, 12 /* 0x0000000c */               # 1554: 0cc4
            movi.n       a6, 0 /* 0x00000000 */                # 1556: 0c06
            l16si        a2, a12, 12                           # 1558: 229c06
            call0        sdk_check_data_flag                   # 155b: 050000
            mov.n        a5, a2                                # 155e: 5d02
            addi.n       a12, a12, 2                           # 1560: 2bcc
            bne          a12, a14, .Lbr121                     # 1562: e79cec
            movi.n       a13, 1 /* 0x00000001 */               # 1565: 0c1d
            movi         a0, .Llit080 /* .Llit080 */           # 1567: 01f0ff
            movi         a7, .Lrel097 /* .Lrel097 */           # 156a: 71eeff
            movi         a6, 996 /* 0x000003e4 */              # 156d: 62a3e4
            l16ui        a15, a7, 118                          # 1570: f2173b
            addi.n       a12, a7, 6                            # 1573: 6bc7
.Lbr122:    beq          a15, a6, .Lbr123                      # 1575: 671f02
            bne          a15, a0, .Lbr124                      # 1578: 079f1c
.Lbr123:    movi.n       a3, 12 /* 0x0000000c */               # 157b: 0cc3
            movi.n       a4, 60 /* 0x0000003c */               # 157d: 3cc4
            l8ui         a2, a12, 79                           # 157f: 220c4f
            movi.n       a6, 1 /* 0x00000001 */                # 1582: 0c16
            slli         a2, a2, 24                            # 1584: 802201
            srai         a2, a2, 24                            # 1587: 202831
            call0        sdk_check_data_flag                   # 158a: 050000
            mov.n        a5, a2                                # 158d: 5d02
            movi         a0, .Llit081 /* .Llit081 */           # 158f: 01e7ff
            movi         a6, 996 /* 0x000003e4 */              # 1592: 62a3e4
            movi         a7, .Lrel098 /* .Lrel098 */           # 1595: 71e6ff
.Lbr124:    addi.n       a12, a12, 6                           # 1598: 6bcc
            addi.n       a13, a13, 1                           # 159a: 1bdd
            bnei         a13, 5, .Lbr122                       # 159c: 665dd5
            l16ui        a0, a7, 20                            # 159f: 02170a
            extui        a4, a0, 8, 8                          # 15a2: 004874
            mov.n        a2, a4                                # 15a5: 2d04
            extui        a0, a0, 0, 8                          # 15a7: 000074
            mov.n        a13, a0                               # 15aa: dd00
            blti         a4, 16, .Lbr125                       # 15ac: a6b402
            addi         a2, a4, -32                           # 15af: 22c4e0
.Lbr125:    blti         a0, 32, .Lbr126                       # 15b2: a6c002
            addi         a13, a0, -64                          # 15b5: d2c0c0
.Lbr126:    movi.n       a3, -13 /* 0xfffffff3 */              # 15b8: 7c33
            movi.n       a4, 13 /* 0x0000000d */               # 15ba: 0cd4
            movi.n       a6, 2 /* 0x00000002 */                # 15bc: 0c26
            call0        sdk_check_data_flag                   # 15be: 050000
            movi.n       a3, -27 /* 0xffffffe5 */              # 15c1: 6c53
            movi.n       a4, 27 /* 0x0000001b */               # 15c3: 1cb4
            mov.n        a5, a2                                # 15c5: 5d02
            movi.n       a6, 2 /* 0x00000002 */                # 15c7: 0c26
            mov.n        a2, a13                               # 15c9: 2d0d
            call0        sdk_check_data_flag                   # 15cb: 050000
            movi         a15, .Lrel099 /* .Lrel099 */          # 15ce: f1d9ff
            mov.n        a5, a2                                # 15d1: 5d02
            mov.n        a12, a15                              # 15d3: cd0f
            addi.n       a3, a15, 10                           # 15d5: ab3f
            s32i.n       a3, a1, 20 /* a3 -> [(local5)] */     # 15d7: 3951
.Lbr127:    l16ui        a0, a12, 22                           # 15d9: 021c0b
            extui        a4, a0, 6, 5                          # 15dc: 004644
            mov.n        a2, a4                                # 15df: 2d04
            extui        a0, a0, 0, 6                          # 15e1: 000054
            mov.n        a13, a0                               # 15e4: dd00
            blti         a4, 16, .Lbr128                       # 15e6: a6b402
            addi         a2, a4, -32                           # 15e9: 22c4e0
.Lbr128:    blti         a0, 32, .Lbr129                       # 15ec: a6c002
            addi         a13, a0, -64                          # 15ef: d2c0c0
.Lbr129:    movi.n       a3, -13 /* 0xfffffff3 */              # 15f2: 7c33
            movi.n       a4, 13 /* 0x0000000d */               # 15f4: 0cd4
            movi.n       a6, 3 /* 0x00000003 */                # 15f6: 0c36
            call0        sdk_check_data_flag                   # 15f8: 050000
            movi.n       a3, -27 /* 0xffffffe5 */              # 15fb: 6c53
            movi.n       a4, 27 /* 0x0000001b */               # 15fd: 1cb4
            mov.n        a5, a2                                # 15ff: 5d02
            movi.n       a6, 3 /* 0x00000003 */                # 1601: 0c36
            mov.n        a2, a13                               # 1603: 2d0d
            call0        sdk_check_data_flag                   # 1605: 050000
            mov.n        a5, a2                                # 1608: 5d02
            l32i.n       a4, a1, 20 /* [(local5)] */           # 160a: 4851
            addi.n       a12, a12, 2                           # 160c: 2bcc
            bne          a12, a4, .Lbr127                      # 160e: 479cc7
            mov.n        a12, a15                              # 1611: cd0f
.Lbr130:    movi.n       a3, 3 /* 0x00000003 */                # 1613: 0c33
            movi         a4, 124 /* 0x0000007c */              # 1615: 42a07c
            l16ui        a2, a12, 4                            # 1618: 221c02
            movi.n       a6, 4 /* 0x00000004 */                # 161b: 0c46
            extui        a13, a2, 8, 8                         # 161d: 20d874
            extui        a2, a2, 0, 8                          # 1620: 202074
            call0        sdk_check_data_flag                   # 1623: 050000
            movi.n       a3, 3 /* 0x00000003 */                # 1626: 0c33
            movi         a4, 124 /* 0x0000007c */              # 1628: 42a07c
            mov.n        a5, a2                                # 162b: 5d02
            movi.n       a6, 4 /* 0x00000004 */                # 162d: 0c46
            mov.n        a2, a13                               # 162f: 2d0d
            call0        sdk_check_data_flag                   # 1631: 050000
            mov.n        a5, a2                                # 1634: 5d02
            addi.n       a12, a12, 2                           # 1636: 2bcc
            bne          a12, a14, .Lbr130                     # 1638: e79cd7
            mov.n        a12, a15                              # 163b: cd0f
            movi         a14, .Lrel100 /* .Lrel100 */          # 163d: e1beff
.Lbr131:    movi         a3, 128 /* 0x00000080 */              # 1640: 32a080
            movi         a4, 384 /* 0x00000180 */              # 1643: 42a180
            l32i         a2, a12, 124                          # 1646: 222c1f
            movi.n       a6, 5 /* 0x00000005 */                # 1649: 0c56
            extui        a13, a2, 0, 9                         # 164b: 20d084
            extui        a2, a2, 9, 9                          # 164e: 202984
            call0        sdk_check_data_flag                   # 1651: 050000
            movi         a3, 128 /* 0x00000080 */              # 1654: 32a080
            movi         a4, 384 /* 0x00000180 */              # 1657: 42a180
            mov.n        a5, a2                                # 165a: 5d02
            movi.n       a6, 5 /* 0x00000005 */                # 165c: 0c56
            mov.n        a2, a13                               # 165e: 2d0d
            call0        sdk_check_data_flag                   # 1660: 050000
            mov.n        a5, a2                                # 1663: 5d02
            addi.n       a12, a12, 4                           # 1665: 4bcc
            bne          a12, a14, .Lbr131                     # 1667: e79cd5
            extui        a2, a2, 0, 16                         # 166a: 2020f4
            l32i.n       a0, a1, 0 /* [(local0)] */            # 166d: 0801
            l32i.n       a12, a1, 4 /* [(local1)] */           # 166f: c811
            l32i.n       a13, a1, 8 /* [(local2)] */           # 1671: d821
            l32i.n       a14, a1, 12 /* [(local3)] */          # 1673: e831
            l8ui         a3, a15, 121                          # 1675: 320f79
            l32i.n       a15, a1, 16 /* [(local4)] */          # 1678: f841
            slli         a3, a3, 24                            # 167a: 803301
            srai         a3, a3, 24                            # 167d: 303831
            srai         a3, a3, 3                             # 1680: 303321
            addi         a1, a1, 32 /* (top of frame) */       # 1683: 12c120
            slli         a3, a3, 16                            # 1686: 003311
            or           a2, a2, a3                            # 1689: 302220
            ret.n                                              # 168c: 0df0

            .section     .rodata.str1.4, "MSa", @progbits, 1

.Lstr001:   .asciz       "error: pll_cal exceeds 2ms!!!\n"     #    0: 6572726f
                                                               #    4: 723a2070
                                                               #    8: 6c6c5f63
                                                               #    c: 616c2065
                                                               #   10: 78636565
                                                               #   14: 64732032
                                                               #   18: 6d732121
                                                               #   1c: 210a00
            .balign      4
.Lstr002:   .asciz       "channel=%d, freq_offset=%d, "        #   20: 6368616e
                                                               #   24: 6e656c3d
                                                               #   28: 25642c20
                                                               #   2c: 66726571
                                                               #   30: 5f6f6666
                                                               #   34: 7365743d
                                                               #   38: 25642c20
                                                               #   3c: 00
            .balign      4
.Lstr003:   .asciz       "%d, "                                #   40: 25642c20
                                                               #   44: 00

            .section     .rodata, "a", @progbits

            .byte        0x00, 0x00, 0x20, 0x42, 0x00, 0x00, 0x80, 0x43
