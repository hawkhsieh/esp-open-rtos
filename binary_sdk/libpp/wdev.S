
            .section     .literal, "ax", @progbits

            .section     .irom0.literal, "ax", @progbits

            .section     .text, "ax", @progbits

.Lrel001:   .word        .data                                 #    0: 00000000
.Llit001:   .word        0x3ff1fe00                            #    4: 00fef13f
.Llit002:   .word        0x0fffffff                            #    8: ffffff0f
.Llit003:   .word        0x3ff20a00                            #    c: 000af23f

# Function @ .text+0x10
.literal_position
.Lfunc001:  movi         a5, .Lrel001 /* .Lrel143 */           #   10: 51fcff
            l32i.n       a5, a5, 0 /* [.Lrel143] */            #   13: 5805
            l16ui        a4, a5, 0 /* [[.Lrel143]] */          #   15: 421500
            l16ui        a10, a5, 2 /* [[.Lrel143]+0x2] */     #   18: a21501
            sub          a4, a4, a2                            #   1b: 2044c0
            s16i         a4, a5, 0 /* a4 -> [[.Lrel143]] */    #   1e: 425500
            l16ui        a6, a5, 0 /* [[.Lrel143]] */          #   21: 621500
            movi.n       a2, 0 /* 0x00000000 */                #   24: 0c02
            bltui        a6, 2, .Lbr001                        #   26: b62608
            l32i.n       a6, a3, 8 /* [arg1+0x8] */            #   29: 6823
            s32i.n       a6, a5, 8 /* [arg1+0x8] -> [[.Lrel143]+0x8] */ #   2b: 6925
            s32i.n       a2, a3, 8 /* 0x00000000 -> [arg1+0x8] */ #   2d: 2923
            j            .Lbr004                               #   2f: 060f00
.Lbr001:    bnei         a6, 1, .Lbr002                        #   32: 66160f
            l32i.n       a9, a3, 8 /* [arg1+0x8] */            #   35: 9823
            s32i.n       a9, a5, 8 /* [arg1+0x8] -> [[.Lrel143]+0x8] */ #   37: 9925
            s32i.n       a2, a3, 8 /* 0x00000000 -> [arg1+0x8] */ #   39: 2923
            l32i.n       a8, a5, 12 /* [[.Lrel143]+0xc] */     #   3b: 8835
            addi         a7, a5, 24 /* [.Lrel143]+0x18 */      #   3d: 72c518
            s32i.n       a7, a8, 8 /* [.Lrel143]+0x18 -> [[[.Lrel143]+0xc]+0x8] */ #   40: 7928
            j            .Lbr004                               #   42: 460a00
.Lbr002:    s16i         a2, a5, 2 /* 0x0000 -> [[.Lrel143]+0x2] */ #   45: 225501
            s16i         a10, a5, 0 /* [[.Lrel143]+0x2] -> [[.Lrel143]] */ #   48: a25500
            l32i.n       a6, a5, 20 /* [[.Lrel143]+0x14] */    #   4b: 6855
            l32i.n       a11, a5, 16 /* [[.Lrel143]+0x10] */   #   4d: b845
            s32i.n       a11, a5, 8 /* [[.Lrel143]+0x10] -> [[.Lrel143]+0x8] */ #   4f: b925
            s32i.n       a2, a5, 16 /* 0x00000000 -> [[.Lrel143]+0x10] */ #   51: 2945
            s32i.n       a6, a5, 12 /* [[.Lrel143]+0x14] -> [[.Lrel143]+0xc] */ #   53: 6935
            s32i.n       a2, a5, 20 /* 0x00000000 -> [[.Lrel143]+0x14] */ #   55: 2955
            extui        a10, a10, 0, 16                       #   57: a0a0f4
            bnei         a10, 1, .Lbr003                       #   5a: 661a04
            addi         a4, a5, 24 /* [.Lrel143]+0x18 */      #   5d: 42c518
            s32i.n       a4, a6, 8 /* [.Lrel143]+0x18 -> [[[.Lrel143]+0x14]+0x8] */ #   60: 4926
.Lbr003:    s32i.n       a2, a3, 8 /* 0x00000000 -> [arg1+0x8] */ #   62: 2923
            movi         a7, .Llit001 /* 0x3ff1fe00 */         #   64: 71e8ff
            l32i.n       a6, a5, 8 /* [[.Lrel143]+0x8] */      #   67: 6825
            memw                                               #   69: c02000
            s32i         a6, a7, 0x208 /* [[.Lrel143]+0x8] -> [0x3ff20008] */ #   6c: 626782
.Lbr004:    l16ui        a9, a5, 2 /* [[.Lrel143]+0x2] */      #   6f: 921501
            l16ui        a8, a5, 0 /* [[.Lrel143]] */          #   72: 821500
            movi         a2, .Llit002 /* .Llit002 */           #   75: 21e4ff
            add.n        a8, a8, a9                            #   78: 9a88
            bgei         a8, 2, .Lbr005                        #   7a: e62820
            movi         a11, .Llit003 /* .Llit003 */          #   7d: b1e3ff
            memw                                               #   80: c02000
            l32i         a3, a11, 0x2a8                        #   83: 322baa
            and          a3, a3, a2                            #   86: 203310
            memw                                               #   89: c02000
            s32i         a3, a11, 0x2a8                        #   8c: 326baa
            memw                                               #   8f: c02000
            l32i         a10, a11, 0x2ac                       #   92: a22bab
            and          a10, a10, a2                          #   95: 20aa10
            memw                                               #   98: c02000
            s32i         a10, a11, 0x2ac                       #   9b: a26bab
.Lbr005:    ret.n                                              #   9e: 0df0

.Lrel002:   .word        .data                                 #   a0: 00000000
.Lrel003:   .word        sdk_esf_rx_buf_alloc                  #   a4: 00000000
.Lrel004:   .word        .Lfunc003                             #   a8: 2c010000
.Lrel005:   .word        sdk_lmacRxDone                        #   ac: 00000000

# Function @ .text+0xb0
# Local variables/stack:
#     (local0):  word      @ -0x20
#     (local1):  word      @ -0x1c
#     (local2):  word      @ -0x18
#     (local3):  word      @ -0x14
#     (local4):  word      @ -0x10
#     (local5):  word[3]   @ -0xc
.literal_position
.Lfunc002:  mov.n        a8, a2 /* arg0 */                     #   b0: 8d02
            addi         a1, a1, -32 /* (local0) */            #   b2: 12c1e0
            s32i.n       a12, a1, 12 /* a12 -> [(local3)] */   #   b5: c931
            movi.n       a2, 7 /* 0x00000007 */                #   b7: 0c72
            s32i.n       a6, a1, 0 /* arg4 -> [(local0)] */    #   b9: 6901
            s32i.n       a0, a1, 8 /* a0 -> [(local2)] */      #   bb: 0921
            s32i.n       a13, a1, 16 /* a13 -> [(local4)] */   #   bd: d941
            s32i.n       a14, a1, 20 /* a14 -> [(local5)] */   #   bf: e951
            mov.n        a13, a5 /* arg3 */                    #   c1: dd05
            mov.n        a14, a4 /* arg2 */                    #   c3: ed04
            s32i.n       a8, a1, 4 /* arg0 -> [(local1)] */    #   c5: 8911
            movi         a0, .Lrel003 /* sdk_esf_rx_buf_alloc */ #   c7: 01f7ff
            callx0       a0 /* sdk_esf_rx_buf_alloc */         #   ca: c00000
            mov.n        a12, a2                               #   cd: cd02
            bnez.n       a2, .Lbr006                           #   cf: ccb2
            mov.n        a3, a13 /* arg3 */                    #   d1: 3d0d
            mov.n        a2, a14 /* arg2 */                    #   d3: 2d0e
            movi         a0, .Lrel004 /* .Lfunc003 */          #   d5: 01f4ff
            callx0       a0 /* .Lfunc003 */                    #   d8: c00000
            j            .Lbr007                               #   db: 060f00
.Lbr006:    movi         a3, .Lrel002 /* .Lrel143 */           #   de: 31f0ff
            l32i.n       a5, a2, 32                            #   e1: 5882
            l32i.n       a4, a1, 0 /* [(local0)] */            #   e3: 4801
            s32i.n       a4, a5, 4                             #   e5: 4915
            l32i.n       a3, a3, 0 /* [.Lrel143] */            #   e7: 3803
            l32i.n       a4, a1, 4 /* [(local1)] */            #   e9: 4811
            s32i.n       a4, a5, 8                             #   eb: 4925
            l32i.n       a3, a3, 8 /* [[.Lrel143]+0x8] */      #   ed: 3823
            s32i.n       a14, a2, 8                            #   ef: e922
            s32i.n       a3, a2, 4                             #   f1: 3912
            s16i         a13, a2, 12                           #   f3: d25206
            l32i.n       a3, a3, 4 /* [[[.Lrel143]+0x8]+0x4] */ #   f6: 3813
            s32i.n       a3, a2, 16                            #   f8: 3942
            mov.n        a3, a14 /* arg2 */                    #   fa: 3d0e
            movi         a2, 191 /* 0x000000bf */              #   fc: 22a0bf
            memw                                               #   ff: c02000
            l8ui         a0, a14, 3 /* [arg2+0x3] */           #  102: 020e03
            and          a0, a0, a2                            #  105: 200010
            mov.n        a2, a13 /* arg3 */                    #  108: 2d0d
            memw                                               #  10a: c02000
            s8i          a0, a14, 3 /* a0 -> [arg2+0x3] */     #  10d: 024e03
            call0        .Lfunc001                             #  110: c5efff
            mov.n        a2, a12                               #  113: 2d0c
            movi         a0, .Lrel005 /* sdk_lmacRxDone */     #  115: 01e5ff
            callx0       a0 /* sdk_lmacRxDone */               #  118: c00000
.Lbr007:    l32i.n       a12, a1, 12 /* [(local3)] */          #  11b: c831
            l32i.n       a13, a1, 16 /* [(local4)] */          #  11d: d841
            l32i.n       a14, a1, 20 /* [(local5)] */          #  11f: e851
            l32i.n       a0, a1, 8 /* [(local2)] */            #  121: 0821
            addi         a1, a1, 32 /* (top of frame) */       #  123: 12c120
            ret.n                                              #  126: 0df0

.Lrel006:   .word        .bss                                  #  128: 00000000

# Function @ .text+0x12c
# Local variables/stack:
#     (local0):  word      @ -0x10
#     (local1):  word      @ -0xc
#     (local2):  word      @ -0x8
#     (local3):  word      @ -0x4
.literal_position
.Lfunc003:  addi         a1, a1, -16 /* (local0) */            #  12c: 12c1f0
            s32i.n       a0, a1, 4 /* a0 -> [(local1)] */      #  12f: 0911
            s32i.n       a12, a1, 8 /* a12 -> [(local2)] */    #  131: c921
            s32i.n       a13, a1, 12 /* a13 -> [(local3)] */   #  133: d931
            mov.n        a12, a3 /* arg1 */                    #  135: cd03
            mov.n        a13, a2 /* arg0 */                    #  137: dd02
            movi         a0, .Lrel006 /* sdk_wDevCtrl */       #  139: 01fbff
            mov.n        a2, a3 /* arg1 */                     #  13c: 2d03
            l32i.n       a0, a0, 8 /* [.Ldata005] */           #  13e: 0820
            mov.n        a3, a13 /* arg0 */                    #  140: 3d0d
            s32i.n       a0, a1, 0 /* [.Ldata005] -> [(local0)] */ #  142: 0901
            call0        .Lfunc001                             #  144: 85ecff
            mov.n        a4, a12 /* arg1 */                    #  147: 4d0c
            mov.n        a3, a13 /* arg0 */                    #  149: 3d0d
            l32i.n       a2, a1, 0 /* [(local0)] */            #  14b: 2801
            call0        sdk_wDev_AppendRxBlocks               #  14d: 050000
            l32i.n       a12, a1, 8 /* [(local2)] */           #  150: c821
            l32i.n       a13, a1, 12 /* [(local3)] */          #  152: d831
            l32i.n       a0, a1, 4 /* [(local1)] */            #  154: 0811
            addi         a1, a1, 16 /* (top of frame) */       #  156: 12c110
            ret.n                                              #  159: 0df0

            .balign      4
.Lrel007:   .word        .bss                                  #  15c: 00000000
.Lrel008:   .word        .data                                 #  160: 00000000

# Function @ .text+0x164
# Local variables/stack:
#     (local0):  word[4]   @ -0x10
.literal_position
.Lfunc004:  mov.n        a6, a2 /* arg0 */                     #  164: 6d02
            movi         a7, .Lrel007 /* sdk_wDevCtrl */       #  166: 71fdff
            mov.n        a4, a3 /* arg1 */                     #  169: 4d03
            addi         a1, a1, -16 /* (local0) */            #  16b: 12c1f0
            s32i.n       a0, a1, 0 /* a0 -> [(local0)] */      #  16e: 0901
            l32i.n       a5, a2, 8 /* [arg0+0x8] */            #  170: 5822
            movi         a3, .Lrel008 /* .Lrel143 */           #  172: 31fbff
            l32i.n       a2, a7, 48 /* [.Ldata006] */          #  175: 28c7
            l32i.n       a3, a3, 0 /* [.Lrel143] */            #  177: 3803
            s32i.n       a5, a7, 48 /* [arg0+0x8] -> [.Ldata006] */ #  179: 59c7
            movi.n       a5, 0 /* 0x00000000 */                #  17b: 0c05
            s32i.n       a5, a6, 8 /* 0x00000000 -> [arg0+0x8] */ #  17d: 5926
            l8ui         a0, a3, 4 /* [[.Lrel143]+0x4] */      #  17f: 020304
            sub          a0, a0, a4                            #  182: 4000c0
            s8i          a0, a3, 4 /* a0 -> [[.Lrel143]+0x4] */ #  185: 024304
            mov.n        a3, a6 /* arg0 */                     #  188: 3d06
            call0        sdk_wDev_AppendRxAmpduLensBlocks      #  18a: 050000
            l32i.n       a0, a1, 0 /* [(local0)] */            #  18d: 0801
            addi         a1, a1, 16 /* (top of frame) */       #  18f: 12c110
            ret.n                                              #  192: 0df0

.Lrel009:   .word        .data                                 #  194: 00000000
.Lrel010:   .word        .rodata.str1.4                        #  198: 00000000
.Lrel011:   .word        .Lstr002                              #  19c: 08000000
.Lrel012:   .word        .bss                                  #  1a0: 00000000
.Lrel013:   .word        .data                                 #  1a4: 00000000
.Llit004:   .word        0x00ffffff                            #  1a8: ffffff00
.Lrel014:   .word        .rodata.str1.4                        #  1ac: 00000000
.Lrel015:   .word        .Lstr002                              #  1b0: 08000000
.Lrel016:   .word        sdk_g_ic+0x180                        #  1b4: 00000000
.Lrel017:   .word        sdk_chm_get_current_channel           #  1b8: 00000000
.Lrel018:   .word        printf                                #  1bc: 00000000
.Lrel019:   .word        printf                                #  1c0: 00000000
.Lrel020:   .word        sdk_rcUpdateDataRxDone                #  1c4: 00000000

# Function @ .text+0x1c8
# Local variables/stack:
#     (local0):  word      @ -0x20
#     (local1):  word      @ -0x1c
#     (local2):  word      @ -0x18
#     (local3):  word      @ -0x14
#     (local4):  word      @ -0x10
#     (local5):  word      @ -0xc
#     (local6):  word[2]   @ -0x8
.literal_position
.Lfunc005:  addi         a1, a1, -32 /* (local0) */            #  1c8: 12c1e0
            s32i.n       a4, a1, 4 /* arg2 -> [(local1)] */    #  1cb: 4911
            s32i.n       a14, a1, 20 /* a14 -> [(local5)] */   #  1cd: e951
            s32i.n       a0, a1, 8 /* a0 -> [(local2)] */      #  1cf: 0921
            movi         a14, .Lrel009 /* .Lrel143 */          #  1d1: e1f0ff
            s32i.n       a13, a1, 16 /* a13 -> [(local4)] */   #  1d4: d941
            l32i.n       a14, a14, 0 /* [.Lrel143] */          #  1d6: e80e
            s32i.n       a15, a1, 24 /* a15 -> [(local6)] */   #  1d8: f961
            l32i.n       a14, a14, 8 /* [[.Lrel143]+0x8] */    #  1da: e82e
            s32i.n       a12, a1, 12 /* a12 -> [(local3)] */   #  1dc: c931
            l32i.n       a14, a14, 4 /* [[[.Lrel143]+0x8]+0x4] */ #  1de: e81e
            mov.n        a12, a3 /* arg1 */                    #  1e0: cd03
            l8ui         a15, a14, 7 /* [[[[.Lrel143]+0x8]+0x4]+0x7] */ #  1e2: f20e07
            mov.n        a13, a2 /* arg0 */                    #  1e5: dd02
            extui        a15, a15, 3, 1                        #  1e7: f0f304
            movi         a0, .Lrel017 /* sdk_chm_get_current_channel */ #  1ea: 01f3ff
            callx0       a0 /* sdk_chm_get_current_channel */  #  1ed: c00000
            bnez.n       a2, .Lbr009                           #  1f0: dc02
            movi         a2, .Lrel010 /* .Lstr001 */           #  1f2: 21e9ff
            movi         a3, .Lrel011 /* .Lstr002 */           #  1f5: 31e9ff
            movi         a4, 367 /* 0x0000016f */              #  1f8: 42a16f
            movi         a0, .Lrel018 /* printf */             #  1fb: 01f0ff
            callx0       a0 /* printf */                       #  1fe: c00000
.Lbr008:    j            .Lbr008 /* (halt) */                  #  201: 06ffff
.Lbr009:    l16ui        a3, a14, 12 /* [[[[.Lrel143]+0x8]+0x4]+0xc] */ #  204: 321e06
            movi         a10, 240 /* 0x000000f0 */             #  207: a2a0f0
            s32i.n       a2, a1, 0 /* a2 -> [(local0)] */      #  20a: 2901
            l8ui         a4, a14, 10 /* [[[[.Lrel143]+0x8]+0x4]+0xa] */ #  20c: 420e0a
            l8ui         a2, a2, 6                             #  20f: 220206
            and          a4, a4, a10                           #  212: a04410
            extui        a2, a2, 0, 4                          #  215: 202034
            or           a2, a2, a4                            #  218: 402220
            s8i          a2, a14, 10 /* a2 -> [[[[.Lrel143]+0x8]+0x4]+0xa] */ #  21b: 224e0a
            bnez.n       a15, .Lbr011                          #  21e: ecaf
            l8ui         a8, a14, 3 /* [[[[.Lrel143]+0x8]+0x4]+0x3] */ #  220: 820e03
            movi         a0, .Lrel012 /* sdk_wDevCtrl */       #  223: 01dfff
            extui        a9, a8, 4, 1                          #  226: 809404
            bbsi         a8, 4, .Lbr010                        #  229: 47e805
            extui        a4, a8, 5, 1                          #  22c: 804504
            beqz         a4, .Lbr022                           #  22f: 165409
.Lbr010:    extui        a5, a3, 0, 4                          #  232: 305034
            beqz         a5, .Lbr029                           #  235: 16a50c
            addi         a6, a5, -4                            #  238: 62c5fc
            beqz         a6, .Lbr031                           #  23b: 16860d
            addi         a7, a5, -8                            #  23e: 72c5f8
            beqz         a7, .Lbr037                           #  241: 16d710
            l32i         a8, a0, 0x18c /* [.Ldata017] */       #  244: 822063
            addi.n       a8, a8, 1 /* [.Ldata017]+0x1 */       #  247: 1b88
            s32i         a8, a0, 0x18c /* [.Ldata017]+0x1 -> [.Ldata017] */ #  249: 826063
.Lbr011:    movi.n       a5, 0 /* 0x00000000 */                #  24c: 0c05
            movi.n       a3, 1 /* 0x00000001 */                #  24e: 0c13
            j            .Lbr014                               #  250: c60200
.Lbr012:    movi.n       a3, 1 /* 0x00000001 */                #  253: 0c13
.Lbr013:    l32i         a9, a0, 0x17c /* [.Ldata013] */       #  255: 92205f
            movi.n       a5, 1 /* 0x00000001 */                #  258: 0c15
            addi.n       a9, a9, 1 /* [.Ldata013]+0x1 */       #  25a: 1b99
            s32i         a9, a0, 0x17c /* [.Ldata013]+0x1 -> [.Ldata013] */ #  25c: 92605f
.Lbr014:    movi         a10, .Lrel013 /* .Lrel013 */          #  25f: a1d1ff
            l32i.n       a10, a10, 0                           #  262: a80a
            l16ui        a10, a10, 0                           #  264: a21a00
            bnei         a10, 1, .Lbr015                       #  267: 661a01
            beqz.n       a5, .Lbr016                           #  26a: 8c15
.Lbr015:    bltui        a12, 2, .Lbr017                       #  26c: b62c01
.Lbr016:    movi.n       a3, 1 /* 0x00000001 */                #  26f: 0c13
.Lbr017:    beqz.n       a3, .Lbr018                           #  271: 8c83
            mov.n        a3, a12 /* arg1 */                    #  273: 3d0c
            mov.n        a2, a13 /* arg0 */                    #  275: 2d0d
            call0        .Lfunc003                             #  277: 45ebff
            j            .Lbr021                               #  27a: c60e00
.Lbr018:    movi         a14, .Llit004 /* .Llit004 */          #  27d: e1caff
            memw                                               #  280: c02000
            l16ui        a11, a13, 2 /* [arg0+0x2] */          #  283: b21d01
            slli         a11, a11, 16                          #  286: 00bb11
            memw                                               #  289: c02000
            l16ui        a0, a13, 0 /* [arg0] */               #  28c: 021d00
            or           a11, a11, a0                          #  28f: 00bb20
            and          a11, a11, a14                         #  292: e0bb10
            srli         a11, a11, 12                          #  295: b0bc41
            bnez.n       a11, .Lbr020                          #  298: dc0b
            movi         a2, .Lrel014 /* .Lrel014 */           #  29a: 21c4ff
            movi         a3, .Lrel015 /* .Lrel015 */           #  29d: 31c4ff
            movi         a4, 570 /* 0x0000023a */              #  2a0: 42a23a
            movi         a0, .Lrel019 /* .Lrel019 */           #  2a3: 01c7ff
            callx0       a0                                    #  2a6: c00000
.Lbr019:    j            .Lbr019 /* (halt) */                  #  2a9: 06ffff
.Lbr020:    mov.n        a5, a12 /* arg1 */                    #  2ac: 5d0c
            mov.n        a4, a13 /* arg0 */                    #  2ae: 4d0d
            mov.n        a3, a15                               #  2b0: 3d0f
            l32i.n       a2, a1, 0 /* [(local0)] */            #  2b2: 2801
            l32i.n       a6, a1, 4 /* [(local1)] */            #  2b4: 6811
            call0        .Lfunc002                             #  2b6: 85dfff
.Lbr021:    l32i.n       a12, a1, 12 /* [(local3)] */          #  2b9: c831
            l32i.n       a13, a1, 16 /* [(local4)] */          #  2bb: d841
            l32i.n       a14, a1, 20 /* [(local5)] */          #  2bd: e851
            l32i.n       a15, a1, 24 /* [(local6)] */          #  2bf: f861
            l32i.n       a0, a1, 8 /* [(local2)] */            #  2c1: 0821
            addi         a1, a1, 32 /* (top of frame) */       #  2c3: 12c120
            ret.n                                              #  2c6: 0df0
.Lbr022:    bbsi         a8, 6, .Lbr023                        #  2c8: 67e805
            srli         a14, a8, 7                            #  2cb: 80e741
            beqz         a14, .Lbr038                          #  2ce: 167e09
.Lbr023:    l32i         a4, a0, 0x184 /* [.Ldata015] */       #  2d1: 422061
            extui        a5, a3, 0, 4                          #  2d4: 305034
            addi.n       a4, a4, 1 /* [.Ldata015]+0x1 */       #  2d7: 1b44
            beqz         a5, .Lbr034                           #  2d9: 16b505
            beqi         a5, 4, .Lbr024                        #  2dc: 26450a
            beqi         a5, 8, .Lbr036                        #  2df: 268568
            l32i         a2, a0, 0x18c /* [.Ldata017] */       #  2e2: 222063
            addi.n       a2, a2, 1 /* [.Ldata017]+0x1 */       #  2e5: 1b22
            s32i         a2, a0, 0x18c /* [.Ldata017]+0x1 -> [.Ldata017] */ #  2e7: 226063
.Lbr024:    movi.n       a5, 0 /* 0x00000000 */                #  2ea: 0c05
            movi.n       a3, 1 /* 0x00000001 */                #  2ec: 0c13
            j            .Lbr028                               #  2ee: c60200
.Lbr025:    l32i         a3, a0, 0x188 /* [.Ldata016] */       #  2f1: 322062
            addi.n       a3, a3, 1 /* [.Ldata016]+0x1 */       #  2f4: 1b33
            s32i         a3, a0, 0x188 /* [.Ldata016]+0x1 -> [.Ldata016] */ #  2f6: 326062
.Lbr026:    movi.n       a3, 0 /* 0x00000000 */                #  2f9: 0c03
.Lbr027:    movi.n       a5, 1 /* 0x00000001 */                #  2fb: 0c15
.Lbr028:    s32i         a4, a0, 0x184 /* [.Ldata015]+0x1 -> [.Ldata015] */ #  2fd: 426061
            j            .Lbr014                               #  300: c6d6ff
.Lbr029:    and          a5, a3, a10                           #  303: a05310
            bnei         a5, 128, .Lbr030                      #  306: 66e508
            beqz         a9, .Lbr012                           #  309: 1669f4
            extui        a6, a8, 6, 1                          #  30c: 806604
            beqz         a6, .Lbr012                           #  30f: 1606f4
.Lbr030:    movi.n       a3, 0 /* 0x00000000 */                #  312: 0c03
            j            .Lbr013                               #  314: 46cfff
.Lbr031:    and          a3, a3, a10                           #  317: a03310
            beqi         a3, 128, .Lbr039                      #  31a: 26e35d
            movi         a7, 144 /* 0x00000090 */              #  31d: 72a090
            beq          a3, a7, .Lbr041                       #  320: 77136f
            movi         a8, 160 /* 0x000000a0 */              #  323: 82a0a0
            beq          a3, a8, .Lbr040                       #  326: 87135c
            l32i         a9, a0, 0x178 /* [.Ldata012] */       #  329: 92205e
            addi.n       a9, a9, 1 /* [.Ldata012]+0x1 */       #  32c: 1b99
            s32i         a9, a0, 0x178 /* [.Ldata012]+0x1 -> [.Ldata012] */ #  32e: 92605e
.Lbr032:    movi.n       a3, 1 /* 0x00000001 */                #  331: 0c13
.Lbr033:    movi.n       a5, 0 /* 0x00000000 */                #  333: 0c05
            j            .Lbr014                               #  335: 86c9ff
.Lbr034:    extui        a3, a3, 0, 8                          #  338: 303074
            beqi         a3, 64, .Lbr026                       #  33b: 26d3ba
            movi.n       a10, 80 /* 0x00000050 */              #  33e: 5c0a
            beq          a3, a10, .Lbr035                      #  340: a71302
            beqi         a3, 128, .Lbr025                      #  343: 26e3aa
.Lbr035:    movi.n       a3, 1 /* 0x00000001 */                #  346: 0c13
            j            .Lbr027                               #  348: c6ebff
.Lbr036:    movi.n       a5, 0 /* 0x00000000 */                #  34b: 0c05
            movi.n       a3, 0 /* 0x00000000 */                #  34d: 0c03
            j            .Lbr028                               #  34f: 86eaff
.Lbr037:    l32i         a11, a0, 0x180 /* [.Ldata014] */      #  352: b22060
            mov.n        a2, a14 /* [[[.Lrel143]+0x8]+0x4] */  #  355: 2d0e
            addi.n       a11, a11, 1 /* [.Ldata014]+0x1 */     #  357: 1bbb
            s32i         a11, a0, 0x180 /* [.Ldata014]+0x1 -> [.Ldata014] */ #  359: b26060
            movi         a0, .Lrel020 /* sdk_rcUpdateDataRxDone */ #  35c: 019aff
            callx0       a0 /* sdk_rcUpdateDataRxDone */       #  35f: c00000
            movi.n       a5, 0 /* 0x00000000 */                #  362: 0c05
            movi.n       a3, 0 /* 0x00000000 */                #  364: 0c03
            j            .Lbr014                               #  366: 46bdff
.Lbr038:    movi         a3, .Lrel016 /* sdk_g_ic+0x180 */     #  369: 3192ff
            movi.n       a5, 0 /* 0x00000000 */                #  36c: 0c05
            l8ui         a3, a3, 84 /* [sdk_g_ic+0x1d4] */     #  36e: 320354
            movi.n       a14, 1 /* 0x00000001 */               #  371: 0c1e
            addi.n       a3, a3, -1 /* [sdk_g_ic+0x1d4]-0x1 */ #  373: 0b33
            movnez       a3, a14, a3                           #  375: 303e93
            j            .Lbr014                               #  378: c6b8ff
.Lbr039:    l32i         a4, a0, 0x16c /* [.Ldata009] */       #  37b: 42205b
            addi.n       a4, a4, 1 /* [.Ldata009]+0x1 */       #  37e: 1b44
            s32i         a4, a0, 0x16c /* [.Ldata009]+0x1 -> [.Ldata009] */ #  380: 42605b
            j            .Lbr032                               #  383: 86eaff
.Lbr040:    l32i         a5, a0, 0x174 /* [.Ldata011] */       #  386: 52205d
            movi.n       a3, 0 /* 0x00000000 */                #  389: 0c03
            addi.n       a5, a5, 1 /* [.Ldata011]+0x1 */       #  38b: 1b55
            s32i         a5, a0, 0x174 /* [.Ldata011]+0x1 -> [.Ldata011] */ #  38d: 52605d
            j            .Lbr033                               #  390: c6e7ff
.Lbr041:    l32i         a6, a0, 0x170 /* [.Ldata010] */       #  393: 62205c
            addi.n       a6, a6, 1 /* [.Ldata010]+0x1 */       #  396: 1b66
            s32i         a6, a0, 0x170 /* [.Ldata010]+0x1 -> [.Ldata010] */ #  398: 62605c
            j            .Lbr032                               #  39b: 86e4ff

            .balign      4
.Llit005:   .word        0x80000000                            #  3a0: 00000080
.Llit006:   .word        0x3ff20e00                            #  3a4: 000ef23f
.Lrel021:   .word        .data                                 #  3a8: 00000000

# Function @ .text+0x3ac
.literal_position
sdk_wDev_MacTimSetFunc:
            movi         a6, .Llit005 /* 0x80000000 */         #  3ac: 61fdff
            movi         a5, .Llit006 /* 0x3ff20e00 */         #  3af: 51fdff
            memw                                               #  3b2: c02000
            l32i         a4, a5, 0x214 /* [0x3ff21014] */      #  3b5: 422585
            or           a4, a4, a6                            #  3b8: 604420
            memw                                               #  3bb: c02000
            movi         a3, .Lrel021 /* .Lrel143 */           #  3be: 31faff
            s32i         a4, a5, 0x214 /* a4 -> [0x3ff21014] */ #  3c1: 426585
            s32i.n       a2, a3, 8 /* arg0 -> [.Ldata002] */   #  3c4: 2923
            ret.n         /* arg0 */                           #  3c6: 0df0

.Lrel022:   .word        .Label001                             #  3c8: 24010000
.Llit007:   .word        0x3feffe00                            #  3cc: 00feef3f
.Lrel023:   .word        .Label001                             #  3d0: 24010000
.Llit008:   .word        0x3ff20e00                            #  3d4: 000ef23f
.Llit009:   .word        0x80000000                            #  3d8: 00000080
.Lrel024:   .word        vPortEnterCritical                    #  3dc: 00000000
.Lrel025:   .word        vPortExitCritical                     #  3e0: 00000000

# Function @ .text+0x3e4
# Local variables/stack:
#     (local0):  word      @ -0x10
#     (local1):  word      @ -0xc
#     (local2):  word[2]   @ -0x8
.literal_position
sdk_wDev_MacTimArm:
            movi         a5, .Lrel022 /* .Label001 */          #  3e4: 51f9ff
            addi         a1, a1, -16 /* (local0) */            #  3e7: 12c1f0
            s32i.n       a2, a1, 8 /* arg0 -> [(local2)] */    #  3ea: 2921
            s32i.n       a0, a1, 0 /* a0 -> [(local0)] */      #  3ec: 0901
            s32i.n       a12, a1, 4 /* a12 -> [(local1)] */    #  3ee: c911
            movi.n       a0, -32 /* 0xffffffe0 */              #  3f0: 6c00
            l8ui         a3, a5, 128 /* [sdk_NMIIrqIsOn] */    #  3f2: 320580
            movi         a12, .Llit007 /* 0x3feffe00 */        #  3f5: c1f5ff
            bnez.n       a3, .Lbr043                           #  3f8: ec33
            movi         a0, .Lrel024 /* vPortEnterCritical */ #  3fa: 01f8ff
            callx0       a0 /* vPortEnterCritical */           #  3fd: c00000
            movi.n       a0, -32 /* 0xffffffe0 */              #  400: 6c00
.Lbr042:    memw                                               #  402: c02000
            l32i         a6, a12, 0x200 /* [0x3ff00000] */     #  405: 622c80
            and          a6, a6, a0                            #  408: 006610
            memw                                               #  40b: c02000
            s32i         a6, a12, 0x200 /* a6 -> [0x3ff00000] */ #  40e: 626c80
            memw                                               #  411: c02000
            l32i         a5, a12, 0x200 /* [0x3ff00000] */     #  414: 522c80
            bbsi         a5, 0, .Lbr042                        #  417: 07e5e7
            l32i.n       a2, a1, 8 /* [(local2)] */            #  41a: 2821
            movi         a5, .Lrel023 /* .Label001 */          #  41c: 51edff
.Lbr043:    movi         a8, .Llit008 /* 0x3ff20e00 */         #  41f: 81edff
            memw                                               #  422: c02000
            l32i         a6, a8, 0x208 /* [0x3ff21008] */      #  425: 622882
            memw                                               #  428: c02000
            l32i         a7, a8, 0x204 /* [0x3ff21004] */      #  42b: 722881
            memw                                               #  42e: c02000
            l32i         a9, a8, 0x208 /* [0x3ff21008] */      #  431: 922882
            beq          a6, a9, .Lbr044                       #  434: 971607
            mov.n        a6, a9 /* [0x3ff21008] */             #  437: 6d09
            memw                                               #  439: c02000
            l32i         a7, a8, 0x204 /* [0x3ff21004] */      #  43c: 722881
.Lbr044:    add.n        a2, a2, a7                            #  43f: 7a22
            bltu         a7, a2, .Lbr045                       #  441: 273701
            addi.n       a6, a6, 1 /* [0x3ff21008]+0x1 */      #  444: 1b66
.Lbr045:    memw                                               #  446: c02000
            s32i         a2, a8, 0x29c /* a2 -> [0x3ff2109c] */ #  449: 2268a7
            memw                                               #  44c: c02000
            s32i         a6, a8, 0x2a0 /* a6 -> [0x3ff210a0] */ #  44f: 6268a8
            movi         a10, .Llit009 /* 0x80000000 */        #  452: a1e1ff
            memw                                               #  455: c02000
            l32i         a9, a8, 0x298 /* [0x3ff21098] */      #  458: 9228a6
            or           a9, a9, a10                           #  45b: a09920
            memw                                               #  45e: c02000
            s32i         a9, a8, 0x298 /* a9 -> [0x3ff21098] */ #  461: 9268a6
            l8ui         a7, a5, 128 /* [sdk_NMIIrqIsOn] */    #  464: 720580
            bnez.n       a7, .Lbr046                           #  467: dc87
            memw                                               #  469: c02000
            l32i         a11, a12, 0x200 /* [0x3ff00000] */    #  46c: b22c80
            and          a11, a11, a0                          #  46f: 00bb10
            movi.n       a0, 1 /* 0x00000001 */                #  472: 0c10
            or           a11, a11, a0                          #  474: 00bb20
            memw                                               #  477: c02000
            s32i         a11, a12, 0x200 /* a11 -> [0x3ff00000] */ #  47a: b26c80
            movi         a0, .Lrel025 /* vPortExitCritical */  #  47d: 01d8ff
            callx0       a0 /* vPortExitCritical */            #  480: c00000
.Lbr046:    l32i.n       a12, a1, 4 /* [(local1)] */           #  483: c811
            l32i.n       a0, a1, 0 /* [(local0)] */            #  485: 0801
            addi         a1, a1, 16 /* (top of frame) */       #  487: 12c110
            ret.n                                              #  48a: 0df0

.Lrel026:   .word        .Label001                             #  48c: 24010000
.Llit010:   .word        0x3feffe00                            #  490: 00feef3f
.Lrel027:   .word        .Label001                             #  494: 24010000
.Llit011:   .word        0x3ff20e00                            #  498: 000ef23f
.Llit012:   .word        0x80000000                            #  49c: 00000080
.Lrel028:   .word        vPortEnterCritical                    #  4a0: 00000000
.Lrel029:   .word        vPortExitCritical                     #  4a4: 00000000

# Function @ .text+0x4a8
# Local variables/stack:
#     (local0):  word      @ -0x10
#     (local1):  word      @ -0xc
#     (local2):  word[2]   @ -0x8
.literal_position
sdk_wDev_MacTim1Arm:
            movi         a5, .Lrel026 /* .Label001 */          #  4a8: 51f9ff
            addi         a1, a1, -16 /* (local0) */            #  4ab: 12c1f0
            s32i.n       a2, a1, 8 /* arg0 -> [(local2)] */    #  4ae: 2921
            s32i.n       a0, a1, 0 /* a0 -> [(local0)] */      #  4b0: 0901
            s32i.n       a12, a1, 4 /* a12 -> [(local1)] */    #  4b2: c911
            movi.n       a0, -32 /* 0xffffffe0 */              #  4b4: 6c00
            l8ui         a3, a5, 128 /* [sdk_NMIIrqIsOn] */    #  4b6: 320580
            movi         a12, .Llit010 /* 0x3feffe00 */        #  4b9: c1f5ff
            bnez.n       a3, .Lbr048                           #  4bc: ec33
            movi         a0, .Lrel028 /* vPortEnterCritical */ #  4be: 01f8ff
            callx0       a0 /* vPortEnterCritical */           #  4c1: c00000
            movi.n       a0, -32 /* 0xffffffe0 */              #  4c4: 6c00
.Lbr047:    memw                                               #  4c6: c02000
            l32i         a6, a12, 0x200 /* [0x3ff00000] */     #  4c9: 622c80
            and          a6, a6, a0                            #  4cc: 006610
            memw                                               #  4cf: c02000
            s32i         a6, a12, 0x200 /* a6 -> [0x3ff00000] */ #  4d2: 626c80
            memw                                               #  4d5: c02000
            l32i         a5, a12, 0x200 /* [0x3ff00000] */     #  4d8: 522c80
            bbsi         a5, 0, .Lbr047                        #  4db: 07e5e7
            l32i.n       a2, a1, 8 /* [(local2)] */            #  4de: 2821
            movi         a5, .Lrel027 /* .Label001 */          #  4e0: 51edff
.Lbr048:    movi         a8, .Llit011 /* 0x3ff20e00 */         #  4e3: 81edff
            memw                                               #  4e6: c02000
            l32i         a6, a8, 0x24c /* [0x3ff2104c] */      #  4e9: 622893
            memw                                               #  4ec: c02000
            l32i         a7, a8, 0x248 /* [0x3ff21048] */      #  4ef: 722892
            memw                                               #  4f2: c02000
            l32i         a9, a8, 0x24c /* [0x3ff2104c] */      #  4f5: 922893
            beq          a6, a9, .Lbr049                       #  4f8: 971607
            mov.n        a6, a9 /* [0x3ff2104c] */             #  4fb: 6d09
            memw                                               #  4fd: c02000
            l32i         a7, a8, 0x248 /* [0x3ff21048] */      #  500: 722892
.Lbr049:    add.n        a2, a2, a7                            #  503: 7a22
            bltu         a7, a2, .Lbr050                       #  505: 273701
            addi.n       a6, a6, 1 /* [0x3ff2104c]+0x1 */      #  508: 1b66
.Lbr050:    memw                                               #  50a: c02000
            s32i         a2, a8, 0x2cc /* a2 -> [0x3ff210cc] */ #  50d: 2268b3
            memw                                               #  510: c02000
            s32i         a6, a8, 0x2d0 /* a6 -> [0x3ff210d0] */ #  513: 6268b4
            movi         a10, .Llit012 /* 0x80000000 */        #  516: a1e1ff
            memw                                               #  519: c02000
            l32i         a9, a8, 0x2c8 /* [0x3ff210c8] */      #  51c: 9228b2
            or           a9, a9, a10                           #  51f: a09920
            memw                                               #  522: c02000
            s32i         a9, a8, 0x2c8 /* a9 -> [0x3ff210c8] */ #  525: 9268b2
            l8ui         a7, a5, 128 /* [sdk_NMIIrqIsOn] */    #  528: 720580
            bnez.n       a7, .Lbr051                           #  52b: dc87
            memw                                               #  52d: c02000
            l32i         a11, a12, 0x200 /* [0x3ff00000] */    #  530: b22c80
            and          a11, a11, a0                          #  533: 00bb10
            movi.n       a0, 1 /* 0x00000001 */                #  536: 0c10
            or           a11, a11, a0                          #  538: 00bb20
            memw                                               #  53b: c02000
            s32i         a11, a12, 0x200 /* a11 -> [0x3ff00000] */ #  53e: b26c80
            movi         a0, .Lrel029 /* vPortExitCritical */  #  541: 01d8ff
            callx0       a0 /* vPortExitCritical */            #  544: c00000
.Lbr051:    l32i.n       a12, a1, 4 /* [(local1)] */           #  547: c811
            l32i.n       a0, a1, 0 /* [(local0)] */            #  549: 0801
            addi         a1, a1, 16 /* (top of frame) */       #  54b: 12c110
            ret.n                                              #  54e: 0df0

.Lrel030:   .word        .Ldata002                             #  550: 08000000

# Function @ .text+0x554
# Local variables/stack:
#     (local0):  word[4]   @ -0x10
.literal_position
.Lfunc006:  addi         a1, a1, -16 /* (local0) */            #  554: 12c1f0
            s32i.n       a0, a1, 0 /* a0 -> [(local0)] */      #  557: 0901
            movi         a0, .Lrel030 /* .Ldata002 */          #  559: 01fdff
            addx4        a0, a2, a0                            #  55c: 0002a0
            l32i.n       a2, a0, 0                             #  55f: 2800
            beqz.n       a2, .Lbr052                           #  561: 8c12
            callx0       a2                                    #  563: c00200
.Lbr052:    l32i.n       a0, a1, 0 /* [(local0)] */            #  566: 0801
            addi         a1, a1, 16 /* (top of frame) */       #  568: 12c110
            ret.n                                              #  56b: 0df0

            .balign      4
.Llit013:   .word        0x3feffe00                            #  570: 00feef3f
.Llit014:   .word        0x3ff20a00                            #  574: 000af23f
.Lrel031:   .word        .Label001                             #  578: 24010000
.Lrel032:   .word        .Ldata023                             #  57c: 20470000
.Lrel033:   .word        .Label001                             #  580: 24010000
.Lrel034:   .word        .rodata.str1.4                        #  584: 00000000
.Lrel035:   .word        .Lstr002                              #  588: 08000000
.Lrel036:   .word        .bss                                  #  58c: 00000000
.Llit015:   .word        0x3ff1fe00                            #  590: 00fef13f
.Llit016:   .word        0x3ff1fe00                            #  594: 00fef13f
.Llit017:   .word        0x3ff20e00                            #  598: 000ef23f
.Lrel037:   .word        .rodata.str1.4                        #  59c: 00000000
.Lrel038:   .word        .Lstr002                              #  5a0: 08000000
.Lrel039:   .word        .rodata.str1.4                        #  5a4: 00000000
.Lrel040:   .word        .Lstr002                              #  5a8: 08000000
.Lrel041:   .word        .rodata.str1.4                        #  5ac: 00000000
.Lrel042:   .word        .Lstr002                              #  5b0: 08000000
.Lrel043:   .word        .bss                                  #  5b4: 00000000
.Lrel044:   .word        .bss                                  #  5b8: 00000000
.Lrel045:   .word        .bss                                  #  5bc: 00000000
.Llit018:   .word        0x00030000                            #  5c0: 00000300
.Llit019:   .word        0x3ff20e00                            #  5c4: 000ef23f
.Lrel046:   .word        .rodata.str1.4                        #  5c8: 00000000
.Lrel047:   .word        .Lstr002                              #  5cc: 08000000
.Llit020:   .word        0x00040000                            #  5d0: 00000400
.Lrel048:   .word        .rodata.str1.4                        #  5d4: 00000000
.Lrel049:   .word        .Lstr002                              #  5d8: 08000000
.Lrel050:   .word        .bss                                  #  5dc: 00000000
.Lrel051:   .word        .rodata.str1.4                        #  5e0: 00000000
.Lrel052:   .word        .Lstr002                              #  5e4: 08000000
.Lrel053:   .word        .bss                                  #  5e8: 00000000
.Lrel054:   .word        .bss                                  #  5ec: 00000000
.Llit021:   .word        0x00040000                            #  5f0: 00000400
.Llit022:   .word        0x00040000                            #  5f4: 00000400
.Llit023:   .word        0xfffbffff                            #  5f8: fffffbff
.Llit024:   .word        0x00040000                            #  5fc: 00000400
.Lrel055:   .word        .rodata.str1.4                        #  600: 00000000
.Lrel056:   .word        .Lstr002                              #  604: 08000000
.Llit025:   .word        0x3ff1fe00                            #  608: 00fef13f
.Llit026:   .word        0x3ff20e00                            #  60c: 000ef23f
.Lrel057:   .word        .rodata.str1.4                        #  610: 00000000
.Lrel058:   .word        .Lstr002                              #  614: 08000000
.Lrel059:   .word        .rodata.str1.4                        #  618: 00000000
.Lrel060:   .word        .Lstr002                              #  61c: 08000000
.Lrel061:   .word        .rodata.str1.4                        #  620: 00000000
.Lrel062:   .word        .Lstr002                              #  624: 08000000
.Lrel063:   .word        .rodata.str1.4                        #  628: 00000000
.Lrel064:   .word        .Lstr002                              #  62c: 08000000
.Lrel065:   .word        .Ldata007                             #  630: 40000000
.Lrel066:   .word        printf                                #  634: 00000000
.Lrel067:   .word        .Lfunc009                             #  638: 14110000
.Lrel068:   .word        .Lfunc008                             #  63c: 10100000
.Lrel069:   .word        printf                                #  640: 00000000
.Lrel070:   .word        printf                                #  644: 00000000
.Lrel071:   .word        printf                                #  648: 00000000
.Lrel072:   .word        .Lfunc010                             #  64c: 88120000
.Lrel073:   .word        sdk_lmacProcessRtsStart               #  650: 00000000
.Lrel074:   .word        printf                                #  654: 00000000
.Lrel075:   .word        printf                                #  658: 00000000
.Lrel076:   .word        printf                                #  65c: 00000000
.Lrel077:   .word        sdk_lmacProcessTXStartData            #  660: 00000000
.Lrel078:   .word        sdk_lmacProcessCollisions             #  664: 00000000
.Lrel079:   .word        sdk_lmacIsActive                      #  668: 00000000
.Lrel080:   .word        sdk_lmacProcessTXStartData            #  66c: 00000000
.Lrel081:   .word        printf                                #  670: 00000000
.Lrel082:   .word        lldesc_num2link                       #  674: 00000000
.Lrel083:   .word        printf                                #  678: 00000000
.Lrel084:   .word        printf                                #  67c: 00000000
.Lrel085:   .word        printf                                #  680: 00000000
.Lrel086:   .word        printf                                #  684: 00000000
.Lrel087:   .word        sdk_lmacProcessAckTimeout             #  688: 00000000
.Lrel088:   .word        sdk_lmacProcessTxSuccess              #  68c: 00000000
.Lrel089:   .word        sdk_lmacProcessTxRtsError             #  690: 00000000
.Lrel090:   .word        sdk_lmacProcessCtsTimeout             #  694: 00000000
.Lrel091:   .word        sdk_lmacProcessTxError                #  698: 00000000

# Function @ .text+0x69c
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
sdk_wDev_ProcessFiq:
            movi.n       a3, -32 /* 0xffffffe0 */              #  69c: 6c03
            movi.n       a2, 1 /* 0x00000001 */                #  69e: 0c12
            addi         a1, a1, -48 /* (local0) */            #  6a0: 12c1d0
            s32i.n       a12, a1, 16 /* a12 -> [(local4)] */   #  6a3: c941
            s32i.n       a13, a1, 20 /* a13 -> [(local5)] */   #  6a5: d951
            s32i.n       a14, a1, 24 /* a14 -> [(local6)] */   #  6a7: e961
            s32i.n       a15, a1, 28 /* a15 -> [(local7)] */   #  6a9: f971
            s32i.n       a0, a1, 12 /* a0 -> [(local3)] */     #  6ab: 0931
            movi         a0, .Llit013 /* 0x3feffe00 */         #  6ad: 01b0ff
.Lbr053:    memw                                               #  6b0: c02000
            l32i         a5, a0, 0x200 /* [0x3ff00000] */      #  6b3: 522080
            and          a5, a5, a3                            #  6b6: 305510
            memw                                               #  6b9: c02000
            s32i         a5, a0, 0x200 /* a5 -> [0x3ff00000] */ #  6bc: 526080
            memw                                               #  6bf: c02000
            l32i         a4, a0, 0x200 /* [0x3ff00000] */      #  6c2: 422080
            bbsi         a4, 0, .Lbr053                        #  6c5: 07e4e7
            movi         a15, .Llit014 /* 0x3ff20a00 */        #  6c8: f1abff
            movi         a7, .Lrel032 /* .Ldata023 */          #  6cb: 71acff
            movi         a9, .Lrel031 /* .Label001 */          #  6ce: 91aaff
            l8ui         a6, a7, 0 /* [.Ldata023] */           #  6d1: 620700
            s8i          a2, a9, 128 /* 0x01 -> [sdk_NMIIrqIsOn] */ #  6d4: 224980
            addi.n       a6, a6, 1 /* [.Ldata023]+0x1 */       #  6d7: 1b66
            s8i          a6, a7, 0 /* [.Ldata023]+0x1 -> [.Ldata023] */ #  6d9: 624700
.Lbr054:    memw                                               #  6dc: c02000
            l32i         a12, a15, 0x220 /* [0x3ff20c20] */    #  6df: c22f88
            bnez.n       a12, .Lbr055                          #  6e2: dc5c
            l32i.n       a0, a1, 12 /* [(local3)] */           #  6e4: 0831
            l32i.n       a12, a1, 16 /* [(local4)] */          #  6e6: c841
            l32i.n       a13, a1, 20 /* [(local5)] */          #  6e8: d851
            l32i.n       a14, a1, 24 /* [(local6)] */          #  6ea: e861
            l32i.n       a15, a1, 28 /* [(local7)] */          #  6ec: f871
            movi         a5, .Lrel033 /* .Lrel033 */           #  6ee: 51a4ff
            movi.n       a4, 0 /* 0x00000000 */                #  6f1: 0c04
            s8i          a4, a5, 128                           #  6f3: 424580
            addi         a1, a1, 48 /* (top of frame) */       #  6f6: 12c130
            ret.n                                              #  6f9: 0df0
.Lbr055:    memw                                               #  6fb: c02000
            l32i         a0, a15, 0x284 /* [0x3ff20c84] */     #  6fe: 022fa1
            memw                                               #  701: c02000
            s32i         a12, a15, 0x224 /* [0x3ff20c20] -> [0x3ff20c24] */ #  704: c26f89
            bbci         a12, 28, .Lbr057                      #  707: c77c11
            movi         a2, .Lrel034 /* .Lrel034 */           #  70a: 219eff
            movi         a3, .Lrel035 /* .Lrel035 */           #  70d: 319eff
            movi         a4, 1113 /* 0x00000459 */             #  710: 42a459
            movi         a0, .Lrel066 /* .Lrel066 */           #  713: 01c8ff
            callx0       a0                                    #  716: c00000
.Lbr056:    j            .Lbr056 /* (halt) */                  #  719: 06ffff
.Lbr057:    s32i.n       a0, a1, 4 /* [0x3ff20c84] -> [(local1)] */ #  71c: 0911
            bbci         a12, 27, .Lbr058                      #  71e: b77c04
            movi.n       a2, 0 /* 0x00000000 */                #  721: 0c02
            call0        .Lfunc006                             #  723: 05e3ff
.Lbr058:    bbci         a12, 26, .Lbr059                      #  726: a77c04
            movi.n       a2, 1 /* 0x00000001 */                #  729: 0c12
            call0        .Lfunc006                             #  72b: 85e2ff
.Lbr059:    movi.n       a0, 4 /* 0x00000004 */                #  72e: 0c40
            and          a0, a12, a0                           #  730: 000c10
            bbci         a12, 3, .Lbr060                       #  733: 376c13
            movi.n       a3, 4 /* 0x00000004 */                #  736: 0c43
            bany         a12, a3, .Lbr060                      #  738: 378c0e
            movi         a0, .Lrel067 /* .Lfunc009 */          #  73b: 01bfff
            callx0       a0 /* .Lfunc009 */                    #  73e: c00000
            movi         a13, 256 /* 0x00000100 */             #  741: d2a100
            and          a13, a12, a13                         #  744: d0dc10
            j            .Lbr061                               #  747: c60400
.Lbr060:    movi         a13, 256 /* 0x00000100 */             #  74a: d2a100
            and          a13, a12, a13                         #  74d: d0dc10
            beqz.n       a0, .Lbr061                           #  750: 8ca0
            movi         a14, 256 /* 0x00000100 */             #  752: e2a100
            bany         a12, a14, .Lbr061                     #  755: e78c05
            movi         a0, .Lrel068 /* .Lfunc008 */          #  758: 01b9ff
            callx0       a0 /* .Lfunc008 */                    #  75b: c00000
.Lbr061:    beqz         a13, .Lbr073                          #  75e: 16dd0c
            memw                                               #  761: c02000
            movi         a0, .Lrel036 /* sdk_wDevCtrl */       #  764: 018aff
            movi         a2, .Llit015 /* 0x3ff1fe00 */         #  767: 218aff
            l8ui         a0, a0, 5 /* [.Ldata004] */           #  76a: 020005
            l32i         a2, a2, 0x21c /* [0x3ff2001c] */      #  76d: 222287
            beqz         a0, .Lbr083                           #  770: 16a013
            memw                                               #  773: c02000
            movi         a3, .Llit016 /* 0x3ff1fe00 */         #  776: 3187ff
            l32i         a14, a3, 0x214 /* [0x3ff20014] */     #  779: e22385
            memw                                               #  77c: c02000
            movi         a4, .Llit017 /* 0x3ff20e00 */         #  77f: 4186ff
            l32i         a4, a4, 0x2fc /* [0x3ff210fc] */      #  782: 4224bf
            memw                                               #  785: c02000
            l32i         a3, a3, 0x218 /* [0x3ff20018] */      #  788: 322386
            bnez.n       a14, .Lbr063                          #  78b: dc0e
            movi         a2, .Lrel037 /* .Lstr001 */           #  78d: 2183ff
            movi         a3, .Lrel038 /* .Lstr002 */           #  790: 3184ff
            movi         a4, 1147 /* 0x0000047b */             #  793: 42a47b
            movi         a0, .Lrel069 /* printf */             #  796: 01aaff
            callx0       a0 /* printf */                       #  799: c00000
.Lbr062:    j            .Lbr062 /* (halt) */                  #  79c: 06ffff
.Lbr063:    l32i.n       a5, a14, 8 /* [[0x3ff20014]+0x8] */   #  79f: 582e
            bnez.n       a5, .Lbr065                           #  7a1: dc05
            movi         a2, .Lrel039 /* .Lstr001 */           #  7a3: 2180ff
            movi         a3, .Lrel040 /* .Lstr002 */           #  7a6: 3180ff
            movi         a4, 1148 /* 0x0000047c */             #  7a9: 42a47c
            movi         a0, .Lrel070 /* printf */             #  7ac: 01a6ff
            callx0       a0 /* printf */                       #  7af: c00000
.Lbr064:    j            .Lbr064 /* (halt) */                  #  7b2: 06ffff
.Lbr065:    memw                                               #  7b5: c02000
            l8ui         a6, a14, 3 /* [[0x3ff20014]+0x3] */   #  7b8: 620e03
            extui        a6, a6, 0, 7                          #  7bb: 606064
            srli         a6, a6, 6                             #  7be: 606641
            beqi         a6, 1, .Lbr067                        #  7c1: 261611
            movi         a2, .Lrel041 /* .Lstr001 */           #  7c4: 217aff
            movi         a3, .Lrel042 /* .Lstr002 */           #  7c7: 317aff
            movi         a4, 1149 /* 0x0000047d */             #  7ca: 42a47d
            movi         a0, .Lrel071 /* printf */             #  7cd: 019eff
            callx0       a0 /* printf */                       #  7d0: c00000
.Lbr066:    j            .Lbr066 /* (halt) */                  #  7d3: 06ffff
.Lbr067:    movi         a2, .Lrel043 /* sdk_wDevCtrl */       #  7d6: 2177ff
            l32i.n       a2, a2, 8 /* [.Ldata005] */           #  7d9: 2822
            beqz         a2, .Lbr073                           #  7db: 160205
.Lbr068:    mov.n        a13, a2                               #  7de: dd02
            memw                                               #  7e0: c02000
            l8ui         a3, a2, 3                             #  7e3: 320203
            extui        a3, a3, 0, 7                          #  7e6: 303064
            srli         a3, a3, 6                             #  7e9: 303641
            bnez.n       a3, .Lbr070                           #  7ec: ccf3
.Lbr069:    l32i.n       a13, a13, 8                           #  7ee: d82d
            memw                                               #  7f0: c02000
            l8ui         a4, a13, 3                            #  7f3: 420d03
            extui        a4, a4, 0, 7                          #  7f6: 404064
            srli         a4, a4, 6                             #  7f9: 404641
            beqz         a4, .Lbr069                           #  7fc: 16e4fe
.Lbr070:    movi         a0, .Lrel072 /* .Lrel072 */           #  7ff: 0193ff
            callx0       a0                                    #  802: c00000
            movi         a6, .Lrel044 /* sdk_wDevCtrl */       #  805: 616cff
            l32i         a5, a6, 0x164 /* [.Ldata008] */       #  808: 522659
            addi.n       a5, a5, 1 /* [.Ldata008]+0x1 */       #  80b: 1b55
            s32i         a5, a6, 0x164 /* [.Ldata008]+0x1 -> [.Ldata008] */ #  80d: 526659
            beq          a14, a13, .Lbr073                     #  810: d71e1b
            l32i.n       a2, a13, 8                            #  813: 282d
            bnez         a2, .Lbr068                           #  815: 5652fc
            j            .Lbr073                               #  818: c60400
.Lbr071:    mov.n        a3, a13                               #  81b: 3d0d
            mov.n        a2, a14 /* [0x3ff20014] */            #  81d: 2d0e
            l32i.n       a4, a1, 8 /* [(local2)] */            #  81f: 4821
            call0        .Lfunc005                             #  821: 459aff
.Lbr072:    movi         a7, .Lrel045 /* sdk_wDevCtrl */       #  824: 7166ff
            l32i         a6, a7, 0x164 /* [.Ldata008] */       #  827: 622759
            addi.n       a6, a6, 1 /* [.Ldata008]+0x1 */       #  82a: 1b66
            s32i         a6, a7, 0x164 /* [.Ldata008]+0x1 -> [.Ldata008] */ #  82c: 626759
.Lbr073:    movi         a7, .Llit018 /* 0x00030000 */         #  82f: 7164ff
            bnone        a7, a12, .Lbr074                      #  832: c70719
            l32i.n       a2, a1, 4 /* [(local1)] */            #  835: 2811
            movi.n       a9, -24 /* 0xffffffe8 */              #  837: 6c89
            extui        a2, a2, 12, 4                         #  839: 202c34
            mull         a9, a2, a9                            #  83c: 909282
            add.n        a9, a9, a15                           #  83f: fa99
            memw                                               #  841: c02000
            movi.n       a8, 0 /* 0x00000000 */                #  844: 0c08
            s32i         a8, a9, 0x3c0                         #  846: 8269f0
            movi         a0, .Lrel073 /* sdk_lmacProcessRtsStart */ #  849: 0181ff
            callx0       a0 /* sdk_lmacProcessRtsStart */      #  84c: c00000
.Lbr074:    bbci         a12, 19, .Lbr080                      #  84f: 377c36
            memw                                               #  852: c02000
            movi         a14, .Llit019 /* 0x3ff20e00 */        #  855: e15bff
            l32i.n       a14, a14, 4 /* [0x3ff20e04] */        #  858: e81e
            bbci         a14, 24, .Lbr075                      #  85a: 877e05
            extui        a14, a14, 16, 8                       #  85d: e0e075
            j            .Lbr076                               #  860: 860000
.Lbr075:    movi         a14, 127 /* 0x0000007f */             #  863: e2a07f
.Lbr076:    l32i.n       a13, a1, 4 /* [(local1)] */           #  866: d811
            extui        a13, a13, 12, 4                       #  868: d0dc34
            bgeui        a13, 8, .Lbr077                       #  86b: f68d02
            j            .Lbr090                               #  86e: 862200
.Lbr077:    bnei         a13, 10, .Lbr078                      #  871: 669d02
            j            .Lbr090                               #  874: 062100
.Lbr078:    movi         a2, .Lrel046 /* .Lstr001 */           #  877: 2154ff
            movi         a3, .Lrel047 /* .Lstr002 */           #  87a: 3154ff
            movi         a4, 1214 /* 0x000004be */             #  87d: 42a4be
            movi         a0, .Lrel074 /* printf */             #  880: 0175ff
            callx0       a0 /* printf */                       #  883: c00000
.Lbr079:    j            .Lbr079 /* (halt) */                  #  886: 06ffff
.Lbr080:    movi         a0, .Llit020 /* 0x00040000 */         #  889: 0151ff
            and          a0, a12, a0                           #  88c: 000c10
.Lbr081:    beqz.n       a0, .Lbr087                           #  88f: bce0
            l32i.n       a2, a1, 4 /* [(local1)] */            #  891: 2811
            extui        a2, a2, 12, 4                         #  893: 202c34
            bltui        a2, 8, .Lbr086                        #  896: b68231
            beqi         a2, 10, .Lbr086                       #  899: 26922e
            movi         a2, .Lrel048 /* .Lrel048 */           #  89c: 214eff
            movi         a3, .Lrel049 /* .Lrel049 */           #  89f: 314eff
            movi         a4, 1253 /* 0x000004e5 */             #  8a2: 42a4e5
            movi         a0, .Lrel075 /* .Lrel075 */           #  8a5: 016cff
            callx0       a0                                    #  8a8: c00000
.Lbr082:    j            .Lbr082 /* (halt) */                  #  8ab: 06ffff
.Lbr083:    movi         a3, .Lrel050 /* sdk_wDevCtrl */       #  8ae: 314bff
            l32i.n       a3, a3, 8 /* [.Ldata005] */           #  8b1: 3823
            bne          a3, a2, .Lbr084                       #  8b3: 279302
            j            .Lbr093                               #  8b6: c62700
.Lbr084:    movi         a2, .Lrel051 /* .Lstr001 */           #  8b9: 2149ff
            movi         a3, .Lrel052 /* .Lstr002 */           #  8bc: 314aff
            movi         a4, 1166 /* 0x0000048e */             #  8bf: 42a48e
            movi         a0, .Lrel076 /* printf */             #  8c2: 0166ff
            callx0       a0 /* printf */                       #  8c5: c00000
.Lbr085:    j            .Lbr085 /* (halt) */                  #  8c8: 06ffff
.Lbr086:    movi         a0, .Lrel077 /* .Lrel077 */           #  8cb: 0165ff
            callx0       a0                                    #  8ce: c00000
.Lbr087:    bbci         a12, 20, .Lbr088                      #  8d1: 477c05
            movi         a0, .Lrel078 /* .Lrel078 */           #  8d4: 0164ff
            callx0       a0                                    #  8d7: c00000
.Lbr088:    bbci         a12, 9, .Lbr089                       #  8da: 976c0a
            movi         a5, .Lrel053 /* .Lrel053 */           #  8dd: 5142ff
            l32i         a4, a5, 0x194                         #  8e0: 422565
            addi.n       a4, a4, 1                             #  8e3: 1b44
            s32i         a4, a5, 0x194                         #  8e5: 426565
.Lbr089:    extui        a5, a12, 23, 1                        #  8e8: c05705
            beqz         a5, .Lbr054                           #  8eb: 16d5de
            movi         a7, .Lrel054 /* .Lrel054 */           #  8ee: 713fff
            l32i         a6, a7, 0x198                         #  8f1: 622766
            addi.n       a6, a6, 1                             #  8f4: 1b66
            s32i         a6, a7, 0x198                         #  8f6: 626766
            j            .Lbr054                               #  8f9: c677ff
.Lbr090:    movi         a0, .Lrel079 /* sdk_lmacIsActive */   #  8fc: 015bff
            callx0       a0 /* sdk_lmacIsActive */             #  8ff: c00000
            movi         a8, .Llit021 /* 0x00040000 */         #  902: 813bff
            and          a8, a12, a8                           #  905: 808c10
            s32i.n       a8, a1, 0 /* a8 -> [(local0)] */      #  908: 8901
            bnez.n       a2, .Lbr091                           #  90a: dca2
            movi         a9, .Llit022 /* 0x00040000 */         #  90c: 913aff
            bnone        a12, a9, .Lbr091                      #  90f: 970c15
            mov.n        a2, a13                               #  912: 2d0d
            movi         a0, .Lrel080 /* sdk_lmacProcessTXStartData */ #  914: 0156ff
            callx0       a0 /* sdk_lmacProcessTXStartData */   #  917: c00000
            movi         a11, .Llit023 /* 0xfffbffff */        #  91a: b137ff
            movi         a10, .Llit024 /* 0x00040000 */        #  91d: a137ff
            and          a12, a12, a11                         #  920: b0cc10
            and          a10, a12, a10                         #  923: a0ac10
            s32i.n       a10, a1, 0 /* a10 -> [(local0)] */    #  926: a901
.Lbr091:    l32i.n       a0, a1, 4 /* [(local1)] */            #  928: 0811
            extui        a0, a0, 28, 4                         #  92a: 000c35
            beqz         a0, .Lbr105                           #  92d: 16800d
            addi.n       a3, a0, -1                            #  930: 0b30
            beqz         a3, .Lbr106                           #  932: 16330e
            addi         a4, a0, -2                            #  935: 42c0fe
            beqz         a4, .Lbr107                           #  938: 16f40e
            addi         a5, a0, -4                            #  93b: 52c0fc
            beqz         a5, .Lbr108                           #  93e: 16650f
            addi         a6, a0, -5                            #  941: 62c0fb
            beqz         a6, .Lbr103                           #  944: 16660a
            movi         a2, .Lrel055 /* .Lstr001 */           #  947: 212eff
            movi         a3, .Lrel056 /* .Lstr002 */           #  94a: 312eff
            movi         a4, 1241 /* 0x000004d9 */             #  94d: 42a4d9
            movi         a0, .Lrel081 /* printf */             #  950: 0148ff
            callx0       a0 /* printf */                       #  953: c00000
.Lbr092:    j            .Lbr092 /* (halt) */                  #  956: 06ffff
.Lbr093:    memw                                               #  959: c02000
            movi         a13, .Llit025 /* 0x3ff1fe00 */        #  95c: d12bff
            l32i         a14, a13, 0x214 /* [0x3ff20014] */    #  95f: e22d85
            memw                                               #  962: c02000
            movi         a0, .Llit026 /* 0x3ff20e00 */         #  965: 0129ff
            l32i         a0, a0, 0x2fc /* [0x3ff210fc] */      #  968: 0220bf
            s32i.n       a0, a1, 8 /* [0x3ff210fc] -> [(local2)] */ #  96b: 0921
            memw                                               #  96d: c02000
            l32i         a13, a13, 0x218 /* [0x3ff20018] */    #  970: d22d86
            extui        a13, a13, 0, 8                        #  973: d0d074
            mov.n        a3, a13                               #  976: 3d0d
            movi         a0, .Lrel082 /* lldesc_num2link */    #  978: 013fff
            callx0       a0 /* lldesc_num2link */              #  97b: c00000
            beq          a2, a14, .Lbr095                      #  97e: e71211
            movi         a2, .Lrel057 /* .Lstr001 */           #  981: 2123ff
            movi         a3, .Lrel058 /* .Lstr002 */           #  984: 3124ff
            movi         a4, 1171 /* 0x00000493 */             #  987: 42a493
            movi         a0, .Lrel083 /* printf */             #  98a: 013bff
            callx0       a0 /* printf */                       #  98d: c00000
.Lbr094:    j            .Lbr094 /* (halt) */                  #  990: 06ffff
.Lbr095:    bnez.n       a14, .Lbr097                          #  993: dc0e
            movi         a2, .Lrel059 /* .Lstr001 */           #  995: 2120ff
            movi         a3, .Lrel060 /* .Lstr002 */           #  998: 3121ff
            movi         a4, 1179 /* 0x0000049b */             #  99b: 42a49b
            movi         a0, .Lrel084 /* printf */             #  99e: 0137ff
            callx0       a0 /* printf */                       #  9a1: c00000
.Lbr096:    j            .Lbr096 /* (halt) */                  #  9a4: 06ffff
.Lbr097:    l32i.n       a2, a14, 8 /* [[0x3ff20014]+0x8] */   #  9a7: 282e
            bnez.n       a2, .Lbr099                           #  9a9: dc02
            movi         a2, .Lrel061 /* .Lstr001 */           #  9ab: 211dff
            movi         a3, .Lrel062 /* .Lstr002 */           #  9ae: 311dff
            movi         a4, 1180 /* 0x0000049c */             #  9b1: 42a49c
            movi         a0, .Lrel085 /* printf */             #  9b4: 0133ff
            callx0       a0 /* printf */                       #  9b7: c00000
.Lbr098:    j            .Lbr098 /* (halt) */                  #  9ba: 06ffff
.Lbr099:    memw                                               #  9bd: c02000
            l8ui         a3, a14, 3 /* [[0x3ff20014]+0x3] */   #  9c0: 320e03
            extui        a3, a3, 0, 7                          #  9c3: 303064
            srli         a3, a3, 6                             #  9c6: 303641
            beqi         a3, 1, .Lbr101                        #  9c9: 261311
            movi         a2, .Lrel063 /* .Lstr001 */           #  9cc: 2117ff
            movi         a3, .Lrel064 /* .Lstr002 */           #  9cf: 3117ff
            movi         a4, 1181 /* 0x0000049d */             #  9d2: 42a49d
            movi         a0, .Lrel086 /* printf */             #  9d5: 012bff
            callx0       a0 /* printf */                       #  9d8: c00000
.Lbr100:    j            .Lbr100 /* (halt) */                  #  9db: 06ffff
.Lbr101:    bgeui        a13, 2, .Lbr102                       #  9de: f62d02
            j            .Lbr071                               #  9e1: 868dff
.Lbr102:    mov.n        a3, a13                               #  9e4: 3d0d
            mov.n        a2, a14 /* [0x3ff20014] */            #  9e6: 2d0e
            call0        .Lfunc003                             #  9e8: 0574ff
            j            .Lbr072                               #  9eb: 468dff
.Lbr103:    s32i.n       a13, a1, 32 /* a13 -> [(local8)] */   #  9ee: d981
            movi         a0, .Lrel087 /* sdk_lmacProcessAckTimeout */ #  9f0: 0126ff
            callx0       a0 /* sdk_lmacProcessAckTimeout */    #  9f3: c00000
.Lbr104:    movi         a6, .Lrel065 /* .Ldata007 */          #  9f6: 610eff
            l32i.n       a5, a1, 32 /* [(local8)] */           #  9f9: 5881
            addx4        a5, a5, a6                            #  9fb: 6055a0
            l32i.n       a4, a5, 48                            #  9fe: 48c5
            l32i.n       a0, a1, 0 /* [(local0)] */            #  a00: 0801
            addi.n       a4, a4, 1                             #  a02: 1b44
            s32i.n       a4, a5, 48                            #  a04: 49c5
            j            .Lbr081                               #  a06: 46a1ff
.Lbr105:    extui        a3, a14, 0, 8                         #  a09: e03074
            mov.n        a2, a13                               #  a0c: 2d0d
            movi         a0, .Lrel088 /* sdk_lmacProcessTxSuccess */ #  a0e: 011fff
            callx0       a0 /* sdk_lmacProcessTxSuccess */     #  a11: c00000
            s32i.n       a13, a1, 32 /* a13 -> [(local8)] */   #  a14: d981
            j            .Lbr104                               #  a16: 06f7ff
.Lbr106:    l32i.n       a2, a1, 4 /* [(local1)] */            #  a19: 2811
            mov.n        a3, a13                               #  a1b: 3d0d
            extui        a2, a2, 16, 8                         #  a1d: 202075
            movi         a0, .Lrel089 /* sdk_lmacProcessTxRtsError */ #  a20: 011cff
            callx0       a0 /* sdk_lmacProcessTxRtsError */    #  a23: c00000
            s32i.n       a13, a1, 32 /* a13 -> [(local8)] */   #  a26: d981
            j            .Lbr104                               #  a28: 86f2ff
.Lbr107:    mov.n        a2, a13                               #  a2b: 2d0d
            movi         a0, .Lrel090 /* sdk_lmacProcessCtsTimeout */ #  a2d: 0119ff
            callx0       a0 /* sdk_lmacProcessCtsTimeout */    #  a30: c00000
            s32i.n       a13, a1, 32 /* a13 -> [(local8)] */   #  a33: d981
            j            .Lbr104                               #  a35: 46efff
.Lbr108:    l32i.n       a2, a1, 4 /* [(local1)] */            #  a38: 2811
            extui        a2, a2, 16, 8                         #  a3a: 202075
            movi         a0, .Lrel091 /* sdk_lmacProcessTxError */ #  a3d: 0116ff
            callx0       a0 /* sdk_lmacProcessTxError */       #  a40: c00000
            s32i.n       a13, a1, 32 /* a13 -> [(local8)] */   #  a43: d981
            j            .Lbr104                               #  a45: 46ebff

.Llit027:   .word        0x3ff20a00                            #  a48: 000af23f
.Llit028:   .word        0xc0000000                            #  a4c: 000000c0
.Lrel092:   .word        .Ldata007                             #  a50: 40000000

# Function @ .text+0xa54
.literal_position
sdk_wDev_EnableTransmit:
            movi         a9, .Llit027 /* 0x3ff20a00 */         #  a54: 91fdff
            movi.n       a8, -24 /* 0xffffffe8 */              #  a57: 6c88
            extui        a10, a3, 0, 4                         #  a59: 30a034
            extui        a11, a4, 0, 10                        #  a5c: 40b094
            slli         a11, a11, 12                          #  a5f: 40bb11
            slli         a10, a10, 24                          #  a62: 80aa01
            mul16s       a8, a8, a2                            #  a65: 2088d1
            add.n        a8, a8, a9                            #  a68: 9a88
            or           a10, a10, a11                         #  a6a: b0aa20
            memw                                               #  a6d: c02000
            s32i         a10, a8, 0x3c0                        #  a70: a268f0
            movi         a9, .Llit028 /* 0xc0000000 */         #  a73: 91f6ff
            memw                                               #  a76: c02000
            l32i         a7, a8, 0x3c4                         #  a79: 7228f1
            or           a7, a7, a9                            #  a7c: 907720
            memw                                               #  a7f: c02000
            movi         a6, .Lrel092 /* .Ldata007 */          #  a82: 61f3ff
            addx4        a6, a2, a6                            #  a85: 6062a0
            l32i.n       a5, a6, 0                             #  a88: 5806
            s32i         a7, a8, 0x3c4                         #  a8a: 7268f1
            addi.n       a5, a5, 1                             #  a8d: 1b55
            s32i.n       a5, a6, 0                             #  a8f: 5906
            ret.n         /* arg0 */                           #  a91: 0df0

            .balign      4
.Llit029:   .word        0x3ff20a00                            #  a94: 000af23f
.Llit030:   .word        0x3fffffff                            #  a98: ffffff3f

# Function @ .text+0xa9c
.literal_position
sdk_wDev_DisableTransmit:
            movi.n       a4, -24 /* 0xffffffe8 */              #  a9c: 6c84
            movi         a5, .Llit029 /* 0x3ff20a00 */         #  a9e: 51fdff
            mul16s       a4, a4, a2                            #  aa1: 2044d1
            add.n        a4, a4, a5                            #  aa4: 5a44
            movi         a5, .Llit030 /* 0x3fffffff */         #  aa6: 51fcff
            memw                                               #  aa9: c02000
            l32i         a3, a4, 0x3c4                         #  aac: 3224f1
            and          a3, a3, a5                            #  aaf: 503310
            memw                                               #  ab2: c02000
            s32i         a3, a4, 0x3c4                         #  ab5: 3264f1
            ret.n         /* arg0 */                           #  ab8: 0df0

            .balign      4
.Llit031:   .word        0x3ff20a00                            #  abc: 000af23f
.Llit032:   .word        0x3fffffff                            #  ac0: ffffff3f

# Function @ .text+0xac4
.literal_position
sdk_Tx_Copy2Queue:
            movi         a7, .Llit032 /* 0x3fffffff */         #  ac4: 71ffff
            movi.n       a4, -24 /* 0xffffffe8 */              #  ac7: 6c84
            movi         a3, .Llit031 /* 0x3ff20a00 */         #  ac9: 31fcff
            mul16s       a4, a4, a2                            #  acc: 2044d1
            add.n        a4, a4, a3                            #  acf: 3a44
            memw                                               #  ad1: c02000
            l32i         a8, a3, 0x2dc /* [0x3ff20cdc] */      #  ad4: 8223b7
            and          a8, a8, a7                            #  ad7: 708810
            memw                                               #  ada: c02000
            s32i         a8, a4, 0x3c4                         #  add: 8264f1
            memw                                               #  ae0: c02000
            l32i         a6, a3, 0x2e0 /* [0x3ff20ce0] */      #  ae3: 6223b8
            and          a6, a6, a7                            #  ae6: 706610
            memw                                               #  ae9: c02000
            s32i         a6, a4, 0x3c8                         #  aec: 6264f2
            memw                                               #  aef: c02000
            l32i         a5, a3, 0x2e4 /* [0x3ff20ce4] */      #  af2: 5223b9
            memw                                               #  af5: c02000
            s32i         a5, a4, 0x3cc                         #  af8: 5264f3
            memw                                               #  afb: c02000
            l32i         a3, a3, 0x2e8 /* [0x3ff20ce8] */      #  afe: 3223ba
            memw                                               #  b01: c02000
            s32i         a3, a4, 0x3d0                         #  b04: 3264f4
            ret.n         /* arg0 */                           #  b07: 0df0

            .balign      4
.Lrel093:   .word        .Ldata007                             #  b0c: 40000000

# Function @ .text+0xb10
# Local variables/stack:
#     (local0):  word      @ -0x10
#     (local1):  word[3]   @ -0xc
.literal_position
sdk_wDev_ProcessCollision:
            addi         a1, a1, -16 /* (local0) */            #  b10: 12c1f0
            s32i.n       a12, a1, 4 /* a12 -> [(local1)] */    #  b13: c911
            s32i.n       a0, a1, 0 /* a0 -> [(local0)] */      #  b15: 0901
            mov.n        a12, a2 /* arg0 */                    #  b17: cd02
            call0        sdk_wDev_DisableTransmit              #  b19: 050000
            movi         a2, .Lrel093 /* .Ldata007 */          #  b1c: 21fcff
            addx4        a2, a12, a2                           #  b1f: 202ca0
            l32i         a0, a2, 96                            #  b22: 022218
            l32i.n       a12, a1, 4 /* [(local1)] */           #  b25: c811
            addi.n       a0, a0, 1                             #  b27: 1b00
            s32i         a0, a2, 96                            #  b29: 026218
            l32i.n       a0, a1, 0 /* [(local0)] */            #  b2c: 0801
            addi         a1, a1, 16 /* (top of frame) */       #  b2e: 12c110
            ret.n                                              #  b31: 0df0

            .balign      4
.Llit033:   .word        0x3ff20a00                            #  b34: 000af23f

# Function @ .text+0xb38
.literal_position
sdk_wDev_GetTxqCollisions:
            movi         a2, .Llit033 /* 0x3ff20a00 */         #  b38: 21ffff
            memw                                               #  b3b: c02000
            l32i         a2, a2, 0x2c0 /* [0x3ff20cc0] */      #  b3e: 2222b0
            extui        a2, a2, 0, 12                         #  b41: 2020b4
            ret.n                                              #  b44: 0df0

            .balign      4
.Llit034:   .word        0xfffff000                            #  b48: 00f0ffff
.Llit035:   .word        0x3ff20a00                            #  b4c: 000af23f

# Function @ .text+0xb50
.literal_position
sdk_wDev_ClearTxqCollisions:
            movi         a4, .Llit034 /* 0xfffff000 */         #  b50: 41feff
            movi         a3, .Llit035 /* 0x3ff20a00 */         #  b53: 31feff
            memw                                               #  b56: c02000
            l32i         a2, a3, 0x2c0 /* [0x3ff20cc0] */      #  b59: 2223b0
            and          a2, a2, a4                            #  b5c: 402210
            memw                                               #  b5f: c02000
            s32i         a2, a3, 0x2c0 /* a2 -> [0x3ff20cc0] */ #  b62: 2263b0
            ret.n                                              #  b65: 0df0

            .balign      4
.Llit036:   .word        0x3ff20a00                            #  b68: 000af23f
.Llit037:   .word        0x7fffffff                            #  b6c: ffffff7f
.Llit038:   .word        0x40000000                            #  b70: 00000040

# Function @ .text+0xb74
.literal_position
sdk_wDev_SetWaitingQueue:
            movi.n       a8, -16 /* 0xfffffff0 */              #  b74: 7c08
            extui        a7, a2, 0, 4                          #  b76: 207034
            movi         a5, .Llit036 /* 0x3ff20a00 */         #  b79: 51fbff
            memw                                               #  b7c: c02000
            l32i         a6, a5, 0x2b0 /* [0x3ff20cb0] */      #  b7f: 6225ac
            and          a6, a6, a8                            #  b82: 806610
            or           a6, a6, a7                            #  b85: 706620
            memw                                               #  b88: c02000
            s32i         a6, a5, 0x2b0 /* a6 -> [0x3ff20cb0] */ #  b8b: 6265ac
            movi.n       a4, -20 /* 0xffffffec */              #  b8e: 6cc4
            mul16s       a4, a4, a2                            #  b90: 2044d1
            movi         a7, .Llit037 /* 0x7fffffff */         #  b93: 71f6ff
            add.n        a4, a4, a5                            #  b96: 5a44
            memw                                               #  b98: c02000
            l32i         a6, a4, 0x3a4                         #  b9b: 6224e9
            and          a6, a6, a7                            #  b9e: 706610
            memw                                               #  ba1: c02000
            s32i         a6, a4, 0x3a4                         #  ba4: 6264e9
            movi         a5, .Llit038 /* 0x40000000 */         #  ba7: 51f2ff
            memw                                               #  baa: c02000
            l32i         a3, a4, 0x3a4                         #  bad: 3224e9
            or           a3, a3, a5                            #  bb0: 503320
            memw                                               #  bb3: c02000
            s32i         a3, a4, 0x3a4                         #  bb6: 3264e9
            ret.n         /* arg0 */                           #  bb9: 0df0

            .balign      4
.Llit039:   .word        0x3ff20a00                            #  bbc: 000af23f
.Llit040:   .word        0xbfffffff                            #  bc0: ffffffbf

# Function @ .text+0xbc4
.literal_position
sdk_wDev_ClearWaitingQueue:
            movi.n       a4, -20 /* 0xffffffec */              #  bc4: 6cc4
            movi         a5, .Llit039 /* 0x3ff20a00 */         #  bc6: 51fdff
            mul16s       a4, a4, a2                            #  bc9: 2044d1
            add.n        a4, a4, a5                            #  bcc: 5a44
            movi         a5, .Llit040 /* 0xbfffffff */         #  bce: 51fcff
            memw                                               #  bd1: c02000
            l32i         a3, a4, 0x3a4                         #  bd4: 3224e9
            and          a3, a3, a5                            #  bd7: 503310
            memw                                               #  bda: c02000
            s32i         a3, a4, 0x3a4                         #  bdd: 3264e9
            ret.n         /* arg0 */                           #  be0: 0df0

            .balign      4
.Llit041:   .word        0x3ff20000                            #  be4: 0000f23f

# Function @ .text+0xbe8
.literal_position
sdk_wDev_SetFrameAckType:
            extui        a8, a2, 4, 4                          #  be8: 208434
            extui        a7, a2, 2, 2                          #  beb: 207214
            srli         a8, a8, 3                             #  bee: 808341
            addx2        a7, a7, a8                            #  bf1: 807790
            movi         a8, .Llit041 /* 0x3ff20000 */         #  bf4: 81fcff
            extui        a7, a7, 0, 8                          #  bf7: 707074
            slli         a7, a7, 2                             #  bfa: e07711
            add.n        a7, a7, a8                            #  bfd: 8a77
            addmi        a4, a7, 3072                          #  bff: 42d70c
            movi.n       a8, 15 /* 0x0000000f */               #  c02: 0cf8
            memw                                               #  c04: c02000
            addmi        a7, a7, 3072                          #  c07: 72d70c
            l32i         a4, a4, 152                           #  c0a: 422426
            movi.n       a9, -1 /* 0xffffffff */               #  c0d: 7cf9
            extui        a6, a2, 4, 3                          #  c0f: 206424
            movi.n       a5, 28 /* 0x0000001c */               #  c12: 1cc5
            slli         a6, a6, 2                             #  c14: e06611
            sub          a5, a5, a6                            #  c17: 6055c0
            extui        a5, a5, 0, 8                          #  c1a: 505074
            ssl          a5                                    #  c1d: 001540
            sll          a8, a8                                #  c20: 0088a1
            ssl          a5                                    #  c23: 001540
            xor          a8, a8, a9                            #  c26: 908830
            and          a8, a4, a8                            #  c29: 808410
            sll          a6, a3                                #  c2c: 0063a1
            or           a6, a6, a8                            #  c2f: 806620
            memw                                               #  c32: c02000
            s32i         a6, a7, 152                           #  c35: 626726
            ssr          a5                                    #  c38: 000540
            srl          a2, a4                                #  c3b: 402091
            extui        a2, a2, 0, 4                          #  c3e: 202034
            ret.n                                              #  c41: 0df0

            .balign      4
.Llit042:   .word        0xff000fff                            #  c44: ff0f00ff
.Lrel094:   .word        .rodata.str1.4                        #  c48: 00000000
.Lrel095:   .word        .Lstr002                              #  c4c: 08000000
.Lrel096:   .word        .Label001                             #  c50: 24010000
.Llit043:   .word        0x3feffe00                            #  c54: 00feef3f
.Lrel097:   .word        .Label001                             #  c58: 24010000
.Lrel098:   .word        .data                                 #  c5c: 00000000
.Llit044:   .word        0x3ff1fe00                            #  c60: 00fef13f
.Llit045:   .word        0x10000000                            #  c64: 00000010
.Llit046:   .word        0x0fffffff                            #  c68: ffffff0f
.Llit047:   .word        0x3ff20a00                            #  c6c: 000af23f
.Llit048:   .word        0x50000000                            #  c70: 00000050
.Llit049:   .word        0x3feffe00                            #  c74: 00feef3f
.Lrel099:   .word        printf                                #  c78: 00000000
.Lrel100:   .word        vPortEnterCritical                    #  c7c: 00000000
.Lrel101:   .word        vPortExitCritical                     #  c80: 00000000

# Function @ .text+0xc84
# Local variables/stack:
#     (local0):  word      @ -0x10
#     (local1):  word      @ -0xc
#     (local2):  word      @ -0x8
#     (local3):  word      @ -0x4
.literal_position
sdk_wDev_AppendRxBlocks:
            addi         a1, a1, -16 /* (local0) */            #  c84: 12c1f0
            s32i.n       a0, a1, 0 /* a0 -> [(local0)] */      #  c87: 0901
            s32i.n       a13, a1, 8 /* a13 -> [(local2)] */    #  c89: d921
            s32i.n       a12, a1, 4 /* a12 -> [(local1)] */    #  c8b: c911
            mov.n        a13, a2 /* arg0 */                    #  c8d: dd02
            mov.n        a12, a4 /* arg2 */                    #  c8f: cd04
            mov.n        a2, a3 /* arg1 */                     #  c91: 2d03
            mov.n        a3, a13 /* arg0 */                    #  c93: 3d0d
            beqz         a13, .Lbr110                          #  c95: 165d08
            movi.n       a8, 0 /* 0x00000000 */                #  c98: 0c08
            movi         a9, 223 /* 0x000000df */              #  c9a: 92a0df
            movi         a10, 191 /* 0x000000bf */             #  c9d: a2a0bf
            movi         a11, 128 /* 0x00000080 */             #  ca0: b2a080
            movi         a6, .Llit042 /* 0xff000fff */         #  ca3: 61e8ff
            movi.n       a0, 0 /* 0x00000000 */                #  ca6: 0c00
.Lbr109:    memw                                               #  ca8: c02000
            l8ui         a5, a3, 3                             #  cab: 520303
            extui        a5, a5, 0, 7                          #  cae: 505064
            or           a5, a5, a11                           #  cb1: b05520
            memw                                               #  cb4: c02000
            s8i          a5, a3, 3                             #  cb7: 524303
            memw                                               #  cba: c02000
            l8ui         a4, a3, 3                             #  cbd: 420303
            and          a4, a4, a10                           #  cc0: a04410
            or           a4, a4, a8                            #  cc3: 804420
            memw                                               #  cc6: c02000
            s8i          a4, a3, 3                             #  cc9: 424303
            memw                                               #  ccc: c02000
            l8ui         a7, a3, 3                             #  ccf: 720303
            and          a7, a7, a9                            #  cd2: 907710
            or           a7, a7, a8                            #  cd5: 807720
            memw                                               #  cd8: c02000
            s8i          a7, a3, 3                             #  cdb: 724303
            memw                                               #  cde: c02000
            l16ui        a5, a3, 0                             #  ce1: 521300
            extui        a5, a5, 0, 12                         #  ce4: 5050b4
            slli         a5, a5, 12                            #  ce7: 405511
            memw                                               #  cea: c02000
            l16ui        a4, a3, 2                             #  ced: 421301
            slli         a4, a4, 16                            #  cf0: 004411
            memw                                               #  cf3: c02000
            l16ui        a7, a3, 0                             #  cf6: 721300
            or           a4, a4, a7                            #  cf9: 704420
            and          a4, a4, a6                            #  cfc: 604410
            or           a4, a4, a5                            #  cff: 504420
            memw                                               #  d02: c02000
            s16i         a4, a3, 0                             #  d05: 425300
            extui        a4, a4, 16, 16                        #  d08: 4040f5
            memw                                               #  d0b: c02000
            addi.n       a0, a0, 1                             #  d0e: 1b00
            s16i         a4, a3, 2                             #  d10: 425301
            l32i.n       a3, a3, 8                             #  d13: 3823
            extui        a0, a0, 0, 16                         #  d15: 0000f4
            bnez         a3, .Lbr109                           #  d18: 56c3f8
            j            .Lbr111                               #  d1b: 460000
.Lbr110:    movi.n       a0, 0 /* 0x00000000 */                #  d1e: 0c00
.Lbr111:    beq          a12, a0, .Lbr113                      #  d20: 071c11
            movi         a2, .Lrel094 /* .Lrel094 */           #  d23: 21c9ff
            movi         a3, .Lrel095 /* .Lrel095 */           #  d26: 31c9ff
            movi         a4, 1494 /* 0x000005d6 */             #  d29: 42a5d6
            movi         a0, .Lrel099 /* .Lrel099 */           #  d2c: 01d3ff
            callx0       a0                                    #  d2f: c00000
.Lbr112:    j            .Lbr112 /* (halt) */                  #  d32: 06ffff
.Lbr113:    movi         a8, .Lrel096 /* .Lrel096 */           #  d35: 81c6ff
            l8ui         a6, a8, 128                           #  d38: 620880
            s32i.n       a2, a1, 12 /* arg1 -> [(local3)] */   #  d3b: 2931
            bnez.n       a6, .Lbr115                           #  d3d: ec66
            movi         a0, .Lrel100 /* .Lrel100 */           #  d3f: 01cfff
            callx0       a0                                    #  d42: c00000
            l32i.n       a2, a1, 12 /* [(local3)] */           #  d45: 2831
            movi         a4, .Llit043 /* 0x3feffe00 */         #  d47: 41c3ff
            movi.n       a7, -32 /* 0xffffffe0 */              #  d4a: 6c07
            movi         a8, .Lrel097 /* .Label001 */          #  d4c: 81c3ff
.Lbr114:    memw                                               #  d4f: c02000
            l32i         a10, a4, 0x200 /* [0x3ff00000] */     #  d52: a22480
            and          a10, a10, a7                          #  d55: 70aa10
            memw                                               #  d58: c02000
            s32i         a10, a4, 0x200 /* a10 -> [0x3ff00000] */ #  d5b: a26480
            memw                                               #  d5e: c02000
            l32i         a9, a4, 0x200 /* [0x3ff00000] */      #  d61: 922480
            bbsi         a9, 0, .Lbr114                        #  d64: 07e9e7
.Lbr115:    movi         a0, .Lrel098 /* .Lrel098 */           #  d67: 01bdff
            l32i.n       a0, a0, 0                             #  d6a: 0800
            l16ui        a3, a0, 0                             #  d6c: 321000
            l32i.n       a6, a0, 12                            #  d6f: 6830
            bnez.n       a3, .Lbr116                           #  d71: ec33
            s32i.n       a13, a0, 8                            #  d73: d920
            movi         a6, .Llit044 /* .Llit044 */           #  d75: 61baff
            memw                                               #  d78: c02000
            l16ui        a5, a0, 0                             #  d7b: 521000
            s32i         a13, a6, 0x208                        #  d7e: d26682
            add.n        a5, a5, a12                           #  d81: ca55
            s16i         a5, a0, 0                             #  d83: 525000
            l16ui        a3, a0, 0                             #  d86: 321000
            s32i.n       a2, a0, 12                            #  d89: 2930
            bnei         a3, 1, .Lbr119                        #  d8b: 661326
            l32i.n       a10, a0, 12                           #  d8e: a830
            addi         a9, a0, 24                            #  d90: 92c018
            s32i.n       a9, a10, 8                            #  d93: 992a
            j            .Lbr119                               #  d95: 060700
.Lbr116:    bnei         a3, 1, .Lbr118                        #  d98: 661310
            l32i.n       a11, a0, 16                           #  d9b: b840
            l32i.n       a10, a0, 20                           #  d9d: a850
            bnez         a11, .Lbr122                          #  d9f: 56cb07
            s32i.n       a13, a0, 16                           #  da2: d940
.Lbr117:    s32i.n       a2, a0, 20                            #  da4: 2950
            s16i         a12, a0, 2                            #  da6: c25001
            j            .Lbr119                               #  da9: 060200
.Lbr118:    add.n        a5, a3, a12                           #  dac: ca53
            s32i.n       a13, a6, 8                            #  dae: d926
            s32i.n       a2, a0, 12                            #  db0: 2930
            s16i         a5, a0, 0                             #  db2: 525000
.Lbr119:    l16ui        a10, a0, 2                            #  db5: a21001
            l16ui        a9, a0, 0                             #  db8: 921000
            movi         a0, .Llit046 /* .Llit046 */           #  dbb: 01abff
            add.n        a9, a9, a10                           #  dbe: aa99
            blti         a9, 2, .Lbr120                        #  dc0: a6292c
            movi         a3, .Llit045 /* .Llit045 */           #  dc3: 31a8ff
            movi         a12, .Llit047 /* .Llit047 */          #  dc6: c1a9ff
            memw                                               #  dc9: c02000
            l32i         a2, a12, 0x2a8                        #  dcc: 222caa
            and          a2, a2, a0                            #  dcf: 002210
            or           a2, a2, a3                            #  dd2: 302220
            memw                                               #  dd5: c02000
            s32i         a2, a12, 0x2a8                        #  dd8: 226caa
            movi         a13, .Llit048 /* .Llit048 */          #  ddb: d1a5ff
            memw                                               #  dde: c02000
            l32i         a11, a12, 0x2ac                       #  de1: b22cab
            and          a11, a11, a0                          #  de4: 00bb10
            or           a11, a11, a13                         #  de7: d0bb20
            memw                                               #  dea: c02000
            s32i         a11, a12, 0x2ac                       #  ded: b26cab
.Lbr120:    l8ui         a3, a8, 128                           #  df0: 320880
            bnez.n       a3, .Lbr121                           #  df3: dcd3
            memw                                               #  df5: c02000
            movi         a5, .Llit049 /* .Llit049 */           #  df8: 519fff
            l32i         a4, a5, 0x200                         #  dfb: 422580
            movi.n       a6, -32 /* 0xffffffe0 */              #  dfe: 6c06
            and          a4, a4, a6                            #  e00: 604410
            movi.n       a6, 1 /* 0x00000001 */                #  e03: 0c16
            or           a4, a4, a6                            #  e05: 604420
            memw                                               #  e08: c02000
            s32i         a4, a5, 0x200                         #  e0b: 426580
            movi         a0, .Lrel101 /* .Lrel101 */           #  e0e: 019cff
            callx0       a0                                    #  e11: c00000
.Lbr121:    l32i.n       a12, a1, 4 /* [(local1)] */           #  e14: c811
            l32i.n       a13, a1, 8 /* [(local2)] */           #  e16: d821
            l32i.n       a0, a1, 0 /* [(local0)] */            #  e18: 0801
            addi         a1, a1, 16 /* (top of frame) */       #  e1a: 12c110
            ret.n                                              #  e1d: 0df0
.Lbr122:    l16ui        a9, a0, 2                             #  e1f: 921001
            s32i.n       a13, a10, 8                           #  e22: d92a
            add.n        a12, a9, a12                          #  e24: cac9
            j            .Lbr117                               #  e26: 86deff

            .balign      4
.Llit050:   .word        0xff000fff                            #  e2c: ff0f00ff
.Lrel102:   .word        .rodata.str1.4                        #  e30: 00000000
.Lrel103:   .word        .Lstr002                              #  e34: 08000000
.Lrel104:   .word        .Label001                             #  e38: 24010000
.Llit051:   .word        0x3feffe00                            #  e3c: 00feef3f
.Lrel105:   .word        .Label001                             #  e40: 24010000
.Lrel106:   .word        .data                                 #  e44: 00000000
.Llit052:   .word        0x3ff1fe00                            #  e48: 00fef13f
.Llit053:   .word        0x3feffe00                            #  e4c: 00feef3f
.Lrel107:   .word        printf                                #  e50: 00000000
.Lrel108:   .word        vPortEnterCritical                    #  e54: 00000000
.Lrel109:   .word        vPortExitCritical                     #  e58: 00000000

# Function @ .text+0xe5c
# Local variables/stack:
#     (local0):  word      @ -0x10
#     (local1):  word      @ -0xc
#     (local2):  word      @ -0x8
#     (local3):  word      @ -0x4
.literal_position
sdk_wDev_AppendRxAmpduLensBlocks:
            addi         a1, a1, -16 /* (local0) */            #  e5c: 12c1f0
            s32i.n       a0, a1, 4 /* a0 -> [(local1)] */      #  e5f: 0911
            s32i.n       a12, a1, 8 /* a12 -> [(local2)] */    #  e61: c921
            s32i.n       a3, a1, 0 /* arg1 -> [(local0)] */    #  e63: 3901
            mov.n        a12, a2 /* arg0 */                    #  e65: cd02
            mov.n        a2, a4 /* arg2 */                     #  e67: 2d04
            mov.n        a4, a12 /* arg0 */                    #  e69: 4d0c
            beqz         a12, .Lbr124                          #  e6b: 165c08
            movi.n       a9, 0 /* 0x00000000 */                #  e6e: 0c09
            movi         a10, 223 /* 0x000000df */             #  e70: a2a0df
            movi         a11, 191 /* 0x000000bf */             #  e73: b2a0bf
            movi         a3, 128 /* 0x00000080 */              #  e76: 32a080
            movi         a7, .Llit050 /* 0xff000fff */         #  e79: 71ecff
            movi.n       a0, 0 /* 0x00000000 */                #  e7c: 0c00
.Lbr123:    memw                                               #  e7e: c02000
            l8ui         a6, a4, 3                             #  e81: 620403
            extui        a6, a6, 0, 7                          #  e84: 606064
            or           a6, a6, a3                            #  e87: 306620
            memw                                               #  e8a: c02000
            s8i          a6, a4, 3                             #  e8d: 624403
            memw                                               #  e90: c02000
            l8ui         a5, a4, 3                             #  e93: 520403
            and          a5, a5, a11                           #  e96: b05510
            or           a5, a5, a9                            #  e99: 905520
            memw                                               #  e9c: c02000
            s8i          a5, a4, 3                             #  e9f: 524403
            memw                                               #  ea2: c02000
            l8ui         a8, a4, 3                             #  ea5: 820403
            and          a8, a8, a10                           #  ea8: a08810
            or           a8, a8, a9                            #  eab: 908820
            memw                                               #  eae: c02000
            s8i          a8, a4, 3                             #  eb1: 824403
            memw                                               #  eb4: c02000
            l16ui        a6, a4, 0                             #  eb7: 621400
            extui        a6, a6, 0, 12                         #  eba: 6060b4
            slli         a6, a6, 12                            #  ebd: 406611
            memw                                               #  ec0: c02000
            l16ui        a5, a4, 2                             #  ec3: 521401
            slli         a5, a5, 16                            #  ec6: 005511
            memw                                               #  ec9: c02000
            l16ui        a8, a4, 0                             #  ecc: 821400
            or           a5, a5, a8                            #  ecf: 805520
            and          a5, a5, a7                            #  ed2: 705510
            or           a5, a5, a6                            #  ed5: 605520
            memw                                               #  ed8: c02000
            s16i         a5, a4, 0                             #  edb: 525400
            extui        a5, a5, 16, 16                        #  ede: 5050f5
            memw                                               #  ee1: c02000
            addi.n       a0, a0, 1                             #  ee4: 1b00
            s16i         a5, a4, 2                             #  ee6: 525401
            l32i.n       a4, a4, 8                             #  ee9: 4824
            extui        a0, a0, 0, 16                         #  eeb: 0000f4
            bnez         a4, .Lbr123                           #  eee: 56c4f8
            j            .Lbr125                               #  ef1: 460000
.Lbr124:    movi.n       a0, 0 /* 0x00000000 */                #  ef4: 0c00
.Lbr125:    beq          a2, a0, .Lbr127                       #  ef6: 071211
            movi         a2, .Lrel102 /* .Lrel102 */           #  ef9: 21cdff
            movi         a3, .Lrel103 /* .Lrel103 */           #  efc: 31ceff
            movi         a4, 1568 /* 0x00000620 */             #  eff: 42a620
            movi         a0, .Lrel107 /* .Lrel107 */           #  f02: 01d3ff
            callx0       a0                                    #  f05: c00000
.Lbr126:    j            .Lbr126 /* (halt) */                  #  f08: 06ffff
.Lbr127:    movi         a4, .Lrel104 /* .Lrel104 */           #  f0b: 41cbff
            l8ui         a8, a4, 128                           #  f0e: 820480
            s32i.n       a2, a1, 12 /* arg2 -> [(local3)] */   #  f11: 2931
            bnez.n       a8, .Lbr129                           #  f13: ec68
            movi         a0, .Lrel108 /* .Lrel108 */           #  f15: 01cfff
            callx0       a0                                    #  f18: c00000
            movi         a6, .Llit051 /* 0x3feffe00 */         #  f1b: 61c8ff
            movi.n       a7, -32 /* 0xffffffe0 */              #  f1e: 6c07
.Lbr128:    memw                                               #  f20: c02000
            l32i         a11, a6, 0x200 /* [0x3ff00000] */     #  f23: b22680
            and          a11, a11, a7                          #  f26: 70bb10
            memw                                               #  f29: c02000
            s32i         a11, a6, 0x200 /* a11 -> [0x3ff00000] */ #  f2c: b26680
            memw                                               #  f2f: c02000
            l32i         a10, a6, 0x200 /* [0x3ff00000] */     #  f32: a22680
            bbsi         a10, 0, .Lbr128                       #  f35: 07eae7
            l32i.n       a2, a1, 12 /* [(local3)] */           #  f38: 2831
            movi         a4, .Lrel105 /* .Label001 */          #  f3a: 41c1ff
.Lbr129:    movi         a0, .Lrel106 /* .Lrel106 */           #  f3d: 01c1ff
            l32i.n       a0, a0, 0                             #  f40: 0800
            l32i.n       a3, a0, 48                            #  f42: 38c0
            l32i.n       a5, a0, 52                            #  f44: 58d0
            bnez.n       a3, .Lbr130                           #  f46: ccc3
            s32i.n       a12, a0, 48                           #  f48: c9c0
            movi         a3, .Llit052 /* .Llit052 */           #  f4a: 31bfff
            memw                                               #  f4d: c02000
            s32i         a12, a3, 0x20c                        #  f50: c26383
            j            .Lbr131                               #  f53: 460000
.Lbr130:    s32i.n       a12, a5, 8                            #  f56: c925
.Lbr131:    l32i.n       a10, a1, 0 /* [(local0)] */           #  f58: a801
            l8ui         a9, a0, 4                             #  f5a: 920004
            s32i.n       a10, a0, 52                           #  f5d: a9d0
            add.n        a9, a9, a2                            #  f5f: 2a99
            s8i          a9, a0, 4                             #  f61: 924004
            l8ui         a8, a4, 128                           #  f64: 820480
            bnez.n       a8, .Lbr132                           #  f67: dcd8
            memw                                               #  f69: c02000
            movi         a12, .Llit053 /* .Llit053 */          #  f6c: c1b8ff
            l32i         a11, a12, 0x200                       #  f6f: b22c80
            movi.n       a0, -32 /* 0xffffffe0 */              #  f72: 6c00
            and          a11, a11, a0                          #  f74: 00bb10
            movi.n       a0, 1 /* 0x00000001 */                #  f77: 0c10
            or           a11, a11, a0                          #  f79: 00bb20
            memw                                               #  f7c: c02000
            s32i         a11, a12, 0x200                       #  f7f: b26c80
            movi         a0, .Lrel109 /* .Lrel109 */           #  f82: 01b5ff
            callx0       a0                                    #  f85: c00000
.Lbr132:    l32i.n       a12, a1, 8 /* [(local2)] */           #  f88: c821
            l32i.n       a0, a1, 4 /* [(local1)] */            #  f8a: 0811
            addi         a1, a1, 16 /* (top of frame) */       #  f8c: 12c110
            ret.n                                              #  f8f: 0df0

            .balign      4
.Llit054:   .word        0x3ff1fe00                            #  f94: 00fef13f

# Function @ .text+0xf98
.literal_position
sdk_wDev_GetBAInfo:
            movi         a6, .Llit054 /* 0x3ff1fe00 */         #  f98: 61ffff
            memw                                               #  f9b: c02000
            l32i         a9, a6, 0x374 /* [0x3ff20174] */      #  f9e: 9226dd
            extui        a9, a9, 12, 4                         #  fa1: 909c34
            s8i          a9, a2, 0 /* a9 -> [arg0] */          #  fa4: 924200
            memw                                               #  fa7: c02000
            l32i         a8, a6, 0x374 /* [0x3ff20174] */      #  faa: 8226dd
            extui        a8, a8, 0, 12                         #  fad: 8080b4
            s16i         a8, a3, 0 /* a8 -> [arg1] */          #  fb0: 825300
            memw                                               #  fb3: c02000
            l32i         a7, a6, 0x368 /* [0x3ff20168] */      #  fb6: 7226da
            s32i.n       a7, a4, 0 /* [0x3ff20168] -> [arg2] */ #  fb9: 7904
            memw                                               #  fbb: c02000
            l32i         a6, a6, 0x364 /* [0x3ff20164] */      #  fbe: 6226d9
            s32i.n       a6, a5, 0 /* [0x3ff20164] -> [arg3] */ #  fc1: 6905
            ret.n         /* arg0 */                           #  fc3: 0df0

            .balign      4
.Llit055:   .word        0xdeadbeef                            #  fc8: efbeadde

# Function @ .text+0xfcc
.literal_position
.Lfunc007:  l32i.n       a6, a2, 4 /* [arg0+0x4] */            #  fcc: 6812
            movi         a3, .Llit055 /* 0xdeadbeef */         #  fce: 31feff
            s32i.n       a3, a6, 0 /* 0xdeadbeef -> [[arg0+0x4]] */ #  fd1: 3906
            memw                                               #  fd3: c02000
            l16ui        a5, a2, 0 /* [arg0] */                #  fd6: 521200
            l32i.n       a4, a2, 4 /* [arg0+0x4] */            #  fd9: 4812
            extui        a5, a5, 0, 12                         #  fdb: 5050b4
            add.n        a4, a4, a5                            #  fde: 5a44
            s32i.n       a3, a4, 0                             #  fe0: 3904
            ret.n         /* arg0 */                           #  fe2: 0df0

.Llit056:   .word        0x3ff1fe00                            #  fe4: 00fef13f
.Lrel110:   .word        .data                                 #  fe8: 00000000
.Lrel111:   .word        .rodata.str1.4                        #  fec: 00000000
.Lrel112:   .word        .Lstr002                              #  ff0: 08000000
.Lrel113:   .word        pvPortMalloc                          #  ff4: 00000000
.Lrel114:   .word        memcpy                                #  ff8: 00000000
.Lrel115:   .word        sdk_chm_get_current_channel           #  ffc: 00000000
.Lrel116:   .word        printf                                # 1000: 00000000
.Lrel117:   .word        sdk_pp_post                           # 1004: 00000000
.Lrel118:   .word        vPortFree                             # 1008: 00000000
.Lrel119:   .word        vPortFree                             # 100c: 00000000

# Function @ .text+0x1010
# Local variables/stack:
#     (local0):  word      @ -0x10
#     (local1):  word[3]   @ -0xc
.literal_position
.Lfunc008:  addi         a1, a1, -16 /* (local0) */            # 1010: 12c1f0
            s32i.n       a12, a1, 4 /* a12 -> [(local1)] */    # 1013: c911
            s32i.n       a0, a1, 0 /* a0 -> [(local0)] */      # 1015: 0901
            movi         a0, .Llit056 /* 0x3ff1fe00 */         # 1017: 01f3ff
            memw                                               # 101a: c02000
            l32i         a0, a0, 0x238 /* [0x3ff20038] */      # 101d: 02208e
            movi.n       a2, 65 /* 0x00000041 */               # 1020: 4c12
            extui        a0, a0, 0, 8                          # 1022: 000074
            bgeu         a2, a0, .Lbr133                       # 1025: 07b205
            extui        a2, a0, 7, 1                          # 1028: 002704
            beqz         a2, .Lbr138                           # 102b: 16c209
.Lbr133:    movi         a12, .Lrel110 /* .Lrel143 */          # 102e: c1eeff
            l32i.n       a12, a12, 0 /* [.Lrel143] */          # 1031: c80c
            l32i.n       a12, a12, 8 /* [[.Lrel143]+0x8] */    # 1033: c82c
            l32i.n       a12, a12, 4 /* [[[.Lrel143]+0x8]+0x4] */ # 1035: c81c
            l8ui         a3, a12, 1 /* [[[[.Lrel143]+0x8]+0x4]+0x1] */ # 1037: 320c01
            l8ui         a0, a12, 4 /* [[[[.Lrel143]+0x8]+0x4]+0x4] */ # 103a: 020c04
            srli         a3, a3, 6                             # 103d: 303641
            beqz         a3, .Lbr138                           # 1040: 167308
            srli         a2, a0, 7                             # 1043: 002741
            bnez.n       a2, .Lbr134                           # 1046: cca2
            extui        a3, a0, 0, 7                          # 1048: 003064
            bgei         a3, 8, .Lbr134                        # 104b: e68305
            l8ui         a4, a12, 7 /* [[[[.Lrel143]+0x8]+0x4]+0x7] */ # 104e: 420c07
            bbci         a4, 6, .Lbr138                        # 1051: 676476
.Lbr134:    movi.n       a2, 12 /* 0x0000000c */               # 1054: 0cc2
            movi         a0, .Lrel113 /* pvPortMalloc */       # 1056: 01e7ff
            callx0       a0 /* pvPortMalloc */                 # 1059: c00000
            mov.n        a3, a12 /* [[[.Lrel143]+0x8]+0x4] */  # 105c: 3d0c
            movi.n       a4, 12 /* 0x0000000c */               # 105e: 0cc4
            mov.n        a12, a2                               # 1060: cd02
            movi         a0, .Lrel114 /* memcpy */             # 1062: 01e5ff
            callx0       a0 /* memcpy */                       # 1065: c00000
            movi         a0, .Lrel115 /* sdk_chm_get_current_channel */ # 1068: 01e5ff
            callx0       a0 /* sdk_chm_get_current_channel */  # 106b: c00000
            bnez.n       a2, .Lbr136                           # 106e: dc02
            movi         a2, .Lrel111 /* .Lstr001 */           # 1070: 21dfff
            movi         a3, .Lrel112 /* .Lstr002 */           # 1073: 31dfff
            movi         a4, 1900 /* 0x0000076c */             # 1076: 42a76c
            movi         a0, .Lrel116 /* printf */             # 1079: 01e1ff
            callx0       a0 /* printf */                       # 107c: c00000
.Lbr135:    j            .Lbr135 /* (halt) */                  # 107f: 06ffff
.Lbr136:    l8ui         a6, a2, 6                             # 1082: 620206
            movi         a8, 240 /* 0x000000f0 */              # 1085: 82a0f0
            l8ui         a5, a12, 1                            # 1088: 520c01
            l8ui         a7, a12, 10                           # 108b: 720c0a
            srli         a5, a5, 6                             # 108e: 505641
            and          a7, a7, a8                            # 1091: 807710
            extui        a6, a6, 0, 4                          # 1094: 606034
            or           a6, a6, a7                            # 1097: 706620
            s8i          a6, a12, 10                           # 109a: 624c0a
            beqz.n       a5, .Lbr139                           # 109d: bc35
            l8ui         a6, a12, 4                            # 109f: 620c04
            extui        a0, a6, 0, 7                          # 10a2: 600064
            srli         a6, a6, 7                             # 10a5: 606741
            bnez.n       a6, .Lbr137                           # 10a8: cc76
            bgei         a0, 8, .Lbr137                        # 10aa: e68005
            l8ui         a7, a12, 7                            # 10ad: 720c07
            bbci         a7, 6, .Lbr139                        # 10b0: 676720
.Lbr137:    bgei         a0, 32, .Lbr139                       # 10b3: e6c01d
            movi.n       a2, 9 /* 0x00000009 */                # 10b6: 0c92
            mov.n        a3, a12                               # 10b8: 3d0c
            movi         a0, .Lrel117 /* sdk_pp_post */        # 10ba: 01d2ff
            callx0       a0 /* sdk_pp_post */                  # 10bd: c00000
            bnei         a2, 1, .Lbr138                        # 10c0: 661207
            mov.n        a2, a12                               # 10c3: 2d0c
            movi         a0, .Lrel118 /* vPortFree */          # 10c5: 01d0ff
            callx0       a0 /* vPortFree */                    # 10c8: c00000
.Lbr138:    l32i.n       a12, a1, 4 /* [(local1)] */           # 10cb: c811
            l32i.n       a0, a1, 0 /* [(local0)] */            # 10cd: 0801
            addi         a1, a1, 16 /* (top of frame) */       # 10cf: 12c110
            ret.n                                              # 10d2: 0df0
.Lbr139:    mov.n        a2, a12                               # 10d4: 2d0c
            movi         a0, .Lrel119 /* vPortFree */          # 10d6: 01cdff
            callx0       a0 /* vPortFree */                    # 10d9: c00000
            j            .Lbr138                               # 10dc: c6faff

            .balign      4
.Llit057:   .word        0x3ff20a00                            # 10e0: 000af23f
.Llit058:   .word        0x3ff20e00                            # 10e4: 000ef23f
.Llit059:   .word        0x3ff1fe00                            # 10e8: 00fef13f
.Lrel120:   .word        .data                                 # 10ec: 00000000
.Lrel121:   .word        .rodata.str1.4                        # 10f0: 00000000
.Lrel122:   .word        .Lstr002                              # 10f4: 08000000
.Lrel123:   .word        pvPortMalloc                          # 10f8: 00000000
.Lrel124:   .word        memcpy                                # 10fc: 00000000
.Lrel125:   .word        sdk_chm_get_current_channel           # 1100: 00000000
.Lrel126:   .word        printf                                # 1104: 00000000
.Lrel127:   .word        sdk_pp_post                           # 1108: 00000000
.Lrel128:   .word        vPortFree                             # 110c: 00000000
.Lrel129:   .word        vPortFree                             # 1110: 00000000

# Function @ .text+0x1114
# Local variables/stack:
#     (local0):  word      @ -0x10
#     (local1):  word      @ -0xc
#     (local2):  word[2]   @ -0x8
.literal_position
.Lfunc009:  movi.n       a3, 29 /* 0x0000001d */               # 1114: 1cd3
            addi         a1, a1, -16 /* (local0) */            # 1116: 12c1f0
            s32i.n       a13, a1, 8 /* a13 -> [(local2)] */    # 1119: d921
            s32i.n       a0, a1, 0 /* a0 -> [(local0)] */      # 111b: 0901
            s32i.n       a12, a1, 4 /* a12 -> [(local1)] */    # 111d: c911
            movi.n       a2, 4 /* 0x00000004 */                # 111f: 0c42
            movi         a12, .Llit057 /* 0x3ff20a00 */        # 1121: c1efff
            movi         a0, .Llit058 /* 0x3ff20e00 */         # 1124: 01f0ff
            memw                                               # 1127: c02000
            l32i         a0, a0, 0x2fc /* [0x3ff210fc] */      # 112a: 0220bf
            memw                                               # 112d: c02000
            l32i         a4, a12, 0x200 /* [0x3ff20c00] */     # 1130: 422c80
            sub          a4, a4, a0                            # 1133: 0044c0
            bltu         a3, a4, .Lbr141                       # 1136: 473317
.Lbr140:    memw                                               # 1139: c02000
            l32i         a4, a12, 0x21c /* [0x3ff20c1c] */     # 113c: 422c87
            extui        a4, a4, 2, 1                          # 113f: 404204
            bnez         a4, .Lbr150                           # 1142: 56940e
            memw                                               # 1145: c02000
            l32i         a5, a12, 0x200 /* [0x3ff20c00] */     # 1148: 522c80
            sub          a5, a5, a0                            # 114b: 0055c0
            bgeu         a3, a5, .Lbr140                       # 114e: 57b3e7
.Lbr141:    movi         a7, -256 /* 0xffffff00 */             # 1151: 72af00
            movi         a3, .Llit059 /* 0x3ff1fe00 */         # 1154: 31e5ff
            memw                                               # 1157: c02000
            l32i         a6, a3, 0x3d4 /* [0x3ff201d4] */      # 115a: 6223f5
            movi.n       a10, -3 /* 0xfffffffd */              # 115d: 7cda
            and          a6, a6, a7                            # 115f: 706610
            extui        a6, a6, 8, 8                          # 1162: 606874
            bgeui        a6, 8, .Lbr142                        # 1165: f68602
            j            .Lbr150                               # 1168: c63000
.Lbr142:    memw                                               # 116b: c02000
            l32i         a9, a12, 0x270 /* [0x3ff20c70] */     # 116e: 922c9c
            and          a9, a9, a10                           # 1171: a09910
            memw                                               # 1174: c02000
            s32i         a9, a12, 0x270 /* a9 -> [0x3ff20c70] */ # 1177: 926c9c
            memw                                               # 117a: c02000
            l32i         a8, a12, 0x21c /* [0x3ff20c1c] */     # 117d: 822c87
            bbsi         a8, 2, .Lbr144                        # 1180: 27e808
.Lbr143:    memw                                               # 1183: c02000
            l32i         a11, a12, 0x21c /* [0x3ff20c1c] */    # 1186: b22c87
            bnone        a11, a2, .Lbr143                      # 1189: 270bf6
.Lbr144:    memw                                               # 118c: c02000
            s32i         a2, a12, 0x224 /* 0x00000004 -> [0x3ff20c24] */ # 118f: 226c89
            memw                                               # 1192: c02000
            l32i         a0, a3, 0x238 /* [0x3ff20038] */      # 1195: 02238e
            movi.n       a13, 65 /* 0x00000041 */              # 1198: 4c1d
            extui        a0, a0, 0, 8                          # 119a: 000074
            bgeu         a13, a0, .Lbr145                      # 119d: 07bd02
            bbci         a0, 7, .Lbr149                        # 11a0: 77607a
.Lbr145:    movi         a13, .Lrel120 /* .Lrel143 */          # 11a3: d1d2ff
            l32i.n       a13, a13, 0 /* [.Lrel143] */          # 11a6: d80d
            l32i.n       a13, a13, 8 /* [[.Lrel143]+0x8] */    # 11a8: d82d
            movi.n       a2, 12 /* 0x0000000c */               # 11aa: 0cc2
            l32i.n       a13, a13, 4 /* [[[.Lrel143]+0x8]+0x4] */ # 11ac: d81d
            movi         a0, .Lrel123 /* pvPortMalloc */       # 11ae: 01d2ff
            callx0       a0 /* pvPortMalloc */                 # 11b1: c00000
            mov.n        a3, a13 /* [[[.Lrel143]+0x8]+0x4] */  # 11b4: 3d0d
            movi.n       a4, 12 /* 0x0000000c */               # 11b6: 0cc4
            mov.n        a13, a2                               # 11b8: dd02
            movi         a0, .Lrel124 /* memcpy */             # 11ba: 01d0ff
            callx0       a0 /* memcpy */                       # 11bd: c00000
            movi         a0, .Lrel125 /* sdk_chm_get_current_channel */ # 11c0: 01d0ff
            callx0       a0 /* sdk_chm_get_current_channel */  # 11c3: c00000
            bnez.n       a2, .Lbr147                           # 11c6: dc02
            movi         a2, .Lrel121 /* .Lstr001 */           # 11c8: 21caff
            movi         a3, .Lrel122 /* .Lstr002 */           # 11cb: 31caff
            movi         a4, 1958 /* 0x000007a6 */             # 11ce: 42a7a6
            movi         a0, .Lrel126 /* printf */             # 11d1: 01ccff
            callx0       a0 /* printf */                       # 11d4: c00000
.Lbr146:    j            .Lbr146 /* (halt) */                  # 11d7: 06ffff
.Lbr147:    l8ui         a3, a2, 6                             # 11da: 320206
            movi         a5, 240 /* 0x000000f0 */              # 11dd: 52a0f0
            l8ui         a0, a13, 1                            # 11e0: 020d01
            l8ui         a4, a13, 10                           # 11e3: 420d0a
            srli         a0, a0, 6                             # 11e6: 000641
            and          a4, a4, a5                            # 11e9: 504410
            extui        a3, a3, 0, 4                          # 11ec: 303034
            or           a3, a3, a4                            # 11ef: 403320
            s8i          a3, a13, 10                           # 11f2: 324d0a
            beqz         a0, .Lbr151                           # 11f5: 161004
            l8ui         a2, a13, 4                            # 11f8: 220d04
            extui        a0, a2, 0, 7                          # 11fb: 200064
            srli         a2, a2, 7                             # 11fe: 202741
            bnez.n       a2, .Lbr148                           # 1201: cc12
            blti         a0, 8, .Lbr151                        # 1203: a68033
.Lbr148:    bgei         a0, 32, .Lbr151                       # 1206: e6c030
            movi.n       a2, 9 /* 0x00000009 */                # 1209: 0c92
            mov.n        a3, a13                               # 120b: 3d0d
            movi         a0, .Lrel127 /* sdk_pp_post */        # 120d: 01beff
            callx0       a0 /* sdk_pp_post */                  # 1210: c00000
            bnei         a2, 1, .Lbr149                        # 1213: 661207
            mov.n        a2, a13                               # 1216: 2d0d
            movi         a0, .Lrel128 /* vPortFree */          # 1218: 01bdff
            callx0       a0 /* vPortFree */                    # 121b: c00000
.Lbr149:    movi.n       a4, 2 /* 0x00000002 */                # 121e: 0c24
            memw                                               # 1220: c02000
            l32i         a3, a12, 0x270 /* [0x3ff20c70] */     # 1223: 322c9c
            or           a3, a3, a4                            # 1226: 403320
            memw                                               # 1229: c02000
            s32i         a3, a12, 0x270 /* a3 -> [0x3ff20c70] */ # 122c: 326c9c
.Lbr150:    l32i.n       a12, a1, 4 /* [(local1)] */           # 122f: c811
            l32i.n       a13, a1, 8 /* [(local2)] */           # 1231: d821
            l32i.n       a0, a1, 0 /* [(local0)] */            # 1233: 0801
            addi         a1, a1, 16 /* (top of frame) */       # 1235: 12c110
            ret.n                                              # 1238: 0df0
.Lbr151:    mov.n        a2, a13                               # 123a: 2d0d
            movi         a0, .Lrel129 /* vPortFree */          # 123c: 01b5ff
            callx0       a0 /* vPortFree */                    # 123f: c00000
            j            .Lbr149                               # 1242: 06f6ff

            .balign      4
.Lrel130:   .word        .data                                 # 1248: 00000000
.Lrel131:   .word        .bss                                  # 124c: 00000000
.Llit060:   .word        0x00ffffff                            # 1250: ffffff00
.Lrel132:   .word        .data                                 # 1254: 00000000
.Llit061:   .word        0x00ffffff                            # 1258: ffffff00
.Llit062:   .word        0x0000fffc                            # 125c: fcff0000
.Lrel133:   .word        .data                                 # 1260: 00000000
.Lrel134:   .word        .data                                 # 1264: 00000000
.Lrel135:   .word        pvPortMalloc                          # 1268: 00000000
.Lrel136:   .word        memcpy                                # 126c: 00000000
.Lrel137:   .word        memcpy                                # 1270: 00000000
.Lrel138:   .word        memcpy                                # 1274: 00000000
.Lrel139:   .word        sdk_pp_post                           # 1278: 00000000
.Lrel140:   .word        vPortFree                             # 127c: 00000000
.Lrel141:   .word        pvPortMalloc                          # 1280: 00000000
.Lrel142:   .word        memcpy                                # 1284: 00000000

# Function @ .text+0x1288
# Local variables/stack:
#     (local0):  word      @ -0x30
#     (local1):  word      @ -0x2c
#     (local2):  word      @ -0x28
#     (local3):  word      @ -0x24
#     (local4):  word      @ -0x20
#     (local5):  word      @ -0x1c
#     (local6):  word      @ -0x18
#     (local7):  word      @ -0x14
#     (local8):  word      @ -0x10
#     (local9):  word[3]   @ -0xc
.literal_position
.Lfunc010:  addi         a1, a1, -48 /* (local0) */            # 1288: 12c1d0
            s32i.n       a13, a1, 24 /* a13 -> [(local6)] */   # 128b: d961
            s32i.n       a0, a1, 16 /* a0 -> [(local4)] */     # 128d: 0941
            movi         a0, .Lrel130 /* .Lrel143 */           # 128f: 01eeff
            s32i.n       a15, a1, 32 /* a15 -> [(local8)] */   # 1292: f981
            l32i.n       a2, a0, 0 /* [.Lrel143] */            # 1294: 2800
            s32i.n       a14, a1, 28 /* a14 -> [(local7)] */   # 1296: e971
            l32i.n       a2, a2, 8 /* [[.Lrel143]+0x8] */      # 1298: 2822
            s32i.n       a12, a1, 20 /* a12 -> [(local5)] */   # 129a: c951
            l32i.n       a12, a2, 4 /* [[[.Lrel143]+0x8]+0x4] */ # 129c: c812
            movi.n       a14, 1 /* 0x00000001 */               # 129e: 0c1e
            l8ui         a3, a12, 7 /* [[[[.Lrel143]+0x8]+0x4]+0x7] */ # 12a0: 320c07
            addi.n       a15, a12, 12 /* [[[.Lrel143]+0x8]+0x4]+0xc */ # 12a3: cbfc
            extui        a3, a3, 3, 1                          # 12a5: 303304
            beqz         a3, .Lbr166                           # 12a8: 16b319
            mov.n        a14, a2 /* [[.Lrel143]+0x8] */        # 12ab: ed02
            memw                                               # 12ad: c02000
            l8ui         a3, a2, 3 /* [[[.Lrel143]+0x8]+0x3] */ # 12b0: 320203
            movi.n       a13, 1 /* 0x00000001 */               # 12b3: 0c1d
            extui        a3, a3, 0, 7                          # 12b5: 303064
            srli         a3, a3, 6                             # 12b8: 303641
            bnez.n       a3, .Lbr153                           # 12bb: dc93
            movi.n       a13, 1 /* 0x00000001 */               # 12bd: 0c1d
.Lbr152:    l32i.n       a14, a14, 8                           # 12bf: e82e
            addi.n       a13, a13, 1                           # 12c1: 1bdd
            extui        a13, a13, 0, 16                       # 12c3: d0d0f4
            memw                                               # 12c6: c02000
            l8ui         a4, a14, 3                            # 12c9: 420e03
            extui        a4, a4, 0, 7                          # 12cc: 404064
            srli         a4, a4, 6                             # 12cf: 404641
            beqz         a4, .Lbr152                           # 12d2: 1694fe
            j            .Lbr153                               # 12d5: c6ffff
.Lbr153:    l8ui         a2, a12, 9 /* [[[[.Lrel143]+0x8]+0x4]+0x9] */ # 12d8: 220c09
            movi         a3, .Lrel131 /* sdk_wDevCtrl */       # 12db: 31dcff
            addx4        a2, a2, a2                            # 12de: 2022a0
            l32i.n       a3, a3, 48 /* [.Ldata006] */          # 12e1: 38c3
            s32i.n       a3, a1, 0 /* [.Ldata006] -> [(local0)] */ # 12e3: 3901
            slli         a2, a2, 1                             # 12e5: f02211
            addi         a2, a2, 50                            # 12e8: 22c232
            movi         a0, .Lrel135 /* pvPortMalloc */       # 12eb: 01dfff
            callx0       a0 /* pvPortMalloc */                 # 12ee: c00000
            s32i.n       a2, a1, 36 /* a2 -> [(local9)] */     # 12f1: 2991
            mov.n        a3, a12 /* [[[.Lrel143]+0x8]+0x4] */  # 12f3: 3d0c
            movi.n       a4, 60 /* 0x0000003c */               # 12f5: 3cc4
            s32i.n       a2, a1, 12 /* a2 -> [(local3)] */     # 12f7: 2931
            s32i.n       a15, a1, 8 /* [[[.Lrel143]+0x8]+0x4]+0xc -> [(local2)] */ # 12f9: f921
            movi         a0, .Lrel136 /* memcpy */             # 12fb: 01dcff
            callx0       a0 /* memcpy */                       # 12fe: c00000
            l32i.n       a9, a1, 8 /* [(local2)] */            # 1301: 9821
            movi         a11, 224 /* 0x000000e0 */             # 1303: b2a0e0
            movi         a6, .Llit060 /* 0x00ffffff */         # 1306: 61d2ff
            movi.n       a8, 0 /* 0x00000000 */                # 1309: 0c08
            l32i.n       a10, a1, 12 /* [(local3)] */          # 130b: a831
            l32i.n       a0, a1, 0 /* [(local0)] */            # 130d: 0801
            addi         a7, a10, 50 /* [(local3)]+0x32 */     # 130f: 72ca32
            l32i.n       a15, a0, 4 /* [[(local0)]+0x4] */     # 1312: f810
            s16i         a8, a10, 48 /* 0x0000 -> [[(local3)]+0x30] */ # 1314: 825a18
.Lbr154:    memw                                               # 1317: c02000
            l16ui        a5, a0, 2 /* [[(local0)]+0x2] */      # 131a: 521001
            slli         a5, a5, 16                            # 131d: 005511
            memw                                               # 1320: c02000
            l16ui        a8, a0, 0 /* [[(local0)]] */          # 1323: 821000
            l32i.n       a4, a0, 4 /* [[(local0)]+0x4] */      # 1326: 4810
            or           a5, a5, a8                            # 1328: 805520
            and          a5, a5, a6                            # 132b: 605510
            srli         a5, a5, 12                            # 132e: 505c41
            add.n        a4, a4, a5                            # 1331: 5a44
            bltu         a15, a4, .Lbr155                      # 1333: 473f02
            j            .Lbr161                               # 1336: 862800
.Lbr155:    l32i.n       a10, a1, 36 /* [(local9)] */          # 1339: a891
            l8ui         a8, a12, 9 /* [[[[.Lrel143]+0x8]+0x4]+0x9] */ # 133b: 820c09
            l16ui        a10, a10, 48 /* [[(local9)]+0x30] */  # 133e: a21a18
            bltu         a10, a8, .Lbr156                      # 1341: 873a02
            j            .Lbr161                               # 1344: 062500
.Lbr156:    l8ui         a8, a15, 0                            # 1347: 820f00
            movi         a3, .Lrel132 /* .Lrel132 */           # 134a: 31c2ff
            beqz.n       a8, .Lbr158                           # 134d: 8ca8
            bltu         a11, a8, .Lbr157                      # 134f: 873b02
            j            .Lbr160                               # 1352: 462000
.Lbr157:    movi         a2, 252 /* 0x000000fc */              # 1355: 22a0fc
            bltu         a2, a8, .Lbr160                       # 1358: 87327b
.Lbr158:    s32i.n       a9, a1, 8 /* a9 -> [(local2)] */      # 135b: 9921
            l32i.n       a3, a3, 0                             # 135d: 3803
            addi         a4, a9, 24                            # 135f: 42c918
            l32i.n       a5, a3, 8                             # 1362: 5823
            memw                                               # 1364: c02000
            s32i.n       a7, a1, 4 /* a7 -> [(local1)] */      # 1367: 7911
            l32i.n       a3, a3, 8                             # 1369: 3823
            l16ui        a5, a5, 0                             # 136b: 521500
            l32i.n       a3, a3, 4                             # 136e: 3813
            extui        a5, a5, 0, 12                         # 1370: 5050b4
            add.n        a3, a3, a5                            # 1373: 5a33
            bltu         a3, a4, .Lbr161                       # 1375: 473363
            l32i.n       a3, a1, 8 /* [(local2)] */            # 1378: 3821
            l32i.n       a2, a1, 4 /* [(local1)] */            # 137a: 2811
            l32i.n       a7, a1, 36 /* [(local9)] */           # 137c: 7891
            addi.n       a6, a10, 1 /* [[(local9)]+0x30]+0x1 */ # 137e: 1b6a
            s16i         a6, a7, 48 /* [[(local9)]+0x30]+0x1 -> [[(local9)]+0x30] */ # 1380: 625718
            l16ui        a5, a15, 2                            # 1383: 521f01
            l16ui        a6, a15, 0                            # 1386: 621f00
            slli         a5, a5, 16                            # 1389: 005511
            or           a5, a5, a6                            # 138c: 605520
            extui        a5, a5, 8, 12                         # 138f: 5058b4
            s16i         a5, a2, 0 /* a5 -> [[(local1)]] */    # 1392: 525200
            l16ui        a4, a3, 22 /* [[(local2)]+0x16] */    # 1395: 42130b
            s16i         a4, a2, 2 /* [[(local2)]+0x16] -> [[(local1)]+0x2] */ # 1398: 425201
            addi         a3, a3, 16 /* [(local2)]+0x10 */      # 139b: 32c310
            addi.n       a2, a2, 4 /* [(local1)]+0x4 */        # 139e: 4b22
            movi.n       a4, 6 /* 0x00000006 */                # 13a0: 0c64
            movi         a0, .Lrel137 /* .Lrel137 */           # 13a2: 01b3ff
            callx0       a0                                    # 13a5: c00000
            movi         a6, .Llit061 /* 0x00ffffff */         # 13a8: 61acff
            movi.n       a10, 28 /* 0x0000001c */              # 13ab: 1cca
            movi.n       a0, 34 /* 0x00000022 */               # 13ad: 2c20
            l32i.n       a9, a1, 8 /* [(local2)] */            # 13af: 9821
            l32i.n       a7, a1, 4 /* [(local1)] */            # 13b1: 7811
            l8ui         a8, a9, 1 /* [[(local2)]+0x1] */      # 13b3: 820901
            addi.n       a7, a7, 10 /* [(local1)]+0xa */       # 13b6: ab77
            extui        a11, a8, 0, 2                         # 13b8: 80b014
            addi         a11, a11, -3                          # 13bb: b2cbfd
            movnez       a0, a10, a11                          # 13be: b00a93
            addi.n       a5, a0, 2                             # 13c1: 2b50
            movi         a11, 224 /* 0x000000e0 */             # 13c3: b2a0e0
            bbci         a8, 7, .Lbr159                        # 13c6: 776801
            addi.n       a5, a0, 6                             # 13c9: 6b50
.Lbr159:    l32i.n       a0, a1, 0 /* [(local0)] */            # 13cb: 0801
            movi         a3, .Llit062 /* 0x0000fffc */         # 13cd: 31a3ff
            addi.n       a2, a5, 3                             # 13d0: 3b25
            and          a2, a2, a3                            # 13d2: 302210
            add.n        a9, a9, a2                            # 13d5: 2a99
.Lbr160:    addi.n       a15, a15, 4                           # 13d7: 4bff
            j            .Lbr154                               # 13d9: 86ceff
.Lbr161:    mov.n        a3, a13                               # 13dc: 3d0d
            mov.n        a2, a14                               # 13de: 2d0e
            call0        .Lfunc003                             # 13e0: 85d4fe
            movi         a2, .Lrel133 /* .Lrel133 */           # 13e3: 219fff
            l32i.n       a13, a1, 12 /* [(local3)] */          # 13e6: d831
            l32i.n       a2, a2, 0                             # 13e8: 2802
            movi.n       a3, 1 /* 0x00000001 */                # 13ea: 0c13
            l32i.n       a2, a2, 48                            # 13ec: 28c2
            call0        .Lfunc004                             # 13ee: 45d7fe
            j            .Lbr164                               # 13f1: 860b00
.Lbr162:    l16ui        a2, a12, 4 /* [[[[.Lrel143]+0x8]+0x4]+0x4] */ # 13f4: 221c02
            slli         a0, a0, 16                            # 13f7: 000011
            or           a0, a0, a2                            # 13fa: 200020
            srli         a0, a0, 8                             # 13fd: 000841
.Lbr163:    addi         a3, a12, 28 /* [[[.Lrel143]+0x8]+0x4]+0x1c */ # 1400: 32cc1c
            s16i         a0, a13, 50                           # 1403: 025d19
            movi.n       a4, 6 /* 0x00000006 */                # 1406: 0c64
            l16ui        a2, a12, 34 /* [[[[.Lrel143]+0x8]+0x4]+0x22] */ # 1408: 221c11
            s16i         a2, a13, 52                           # 140b: 225d1a
            addi         a2, a13, 54                           # 140e: 22cd36
            movi         a0, .Lrel138 /* memcpy */             # 1411: 0198ff
            callx0       a0 /* memcpy */                       # 1414: c00000
            movi         a2, .Lrel134 /* .Lrel143 */           # 1417: 2193ff
            l32i.n       a2, a2, 0 /* [.Lrel143] */            # 141a: 2802
            movi.n       a3, 1 /* 0x00000001 */                # 141c: 0c13
            l32i.n       a2, a2, 8 /* [[.Lrel143]+0x8] */      # 141e: 2822
            call0        .Lfunc003                             # 1420: 85d0fe
.Lbr164:    movi.n       a2, 9 /* 0x00000009 */                # 1423: 0c92
            mov.n        a3, a13                               # 1425: 3d0d
            movi         a0, .Lrel139 /* .Lrel139 */           # 1427: 0194ff
            callx0       a0                                    # 142a: c00000
            bnei         a2, 1, .Lbr165                        # 142d: 661207
            mov.n        a2, a13                               # 1430: 2d0d
            movi         a0, .Lrel140 /* .Lrel140 */           # 1432: 0192ff
            callx0       a0                                    # 1435: c00000
.Lbr165:    l32i.n       a12, a1, 20 /* [(local5)] */          # 1438: c851
            l32i.n       a13, a1, 24 /* [(local6)] */          # 143a: d861
            l32i.n       a14, a1, 28 /* [(local7)] */          # 143c: e871
            l32i.n       a15, a1, 32 /* [(local8)] */          # 143e: f881
            l32i.n       a0, a1, 16 /* [(local4)] */           # 1440: 0841
            addi         a1, a1, 48 /* (top of frame) */       # 1442: 12c130
            ret.n                                              # 1445: 0df0
.Lbr166:    movi.n       a2, 60 /* 0x0000003c */               # 1447: 3cc2
            movi         a0, .Lrel141 /* pvPortMalloc */       # 1449: 018dff
            callx0       a0 /* pvPortMalloc */                 # 144c: c00000
            mov.n        a13, a2                               # 144f: dd02
            mov.n        a3, a12 /* [[[.Lrel143]+0x8]+0x4] */  # 1451: 3d0c
            movi.n       a4, 60 /* 0x0000003c */               # 1453: 3cc4
            movi         a0, .Lrel142 /* memcpy */             # 1455: 018bff
            callx0       a0 /* memcpy */                       # 1458: c00000
            s16i         a14, a13, 48                          # 145b: e25d18
            l8ui         a3, a12, 1 /* [[[[.Lrel143]+0x8]+0x4]+0x1] */ # 145e: 320c01
            l16ui        a0, a12, 6 /* [[[[.Lrel143]+0x8]+0x4]+0x6] */ # 1461: 021c03
            srli         a3, a3, 6                             # 1464: 303641
            bnez         a3, .Lbr162                           # 1467: 5693f8
            l16ui        a0, a12, 2 /* [[[[.Lrel143]+0x8]+0x4]+0x2] */ # 146a: 021c01
            extui        a0, a0, 0, 12                         # 146d: 0000b4
            j            .Lbr163                               # 1470: 06e3ff

            .section     .data, "aw", @progbits

.Lrel143:   .word        sdk_wDevCtrl                          #    0: 00000000
.Ldata001:  .word        0x00019000                            #    4: 00900100
.Ldata002:  .word        0x00000000                            #    8: 00000000
.Ldata003:  .word        0x00000000                            #    c: 00000000

            .section     .bss, "aw", @nobits

sdk_wDevCtrl:
            .space       5
.Ldata004:  .byte        0x00
            .balign      4
.Ldata005:  .word        0x00000000                            #    8: 00000000

# NOTE: 36 non-alignment zero bytes skipped.

            .skip        36
.Ldata006:  .word        0x00000000                            #   30: 00000000

# NOTE: 12 non-alignment zero bytes skipped.

            .skip        12
.Ldata007:  .space       228
.Label001:  .space       64
.Ldata008:  .word        0x00000000                            #  164: 00000000

# NOTE: 4 non-alignment zero bytes skipped.

            .skip        4
.Ldata009:  .word        0x00000000                            #  16c: 00000000
.Ldata010:  .word        0x00000000                            #  170: 00000000
.Ldata011:  .word        0x00000000                            #  174: 00000000
.Ldata012:  .word        0x00000000                            #  178: 00000000
.Ldata013:  .word        0x00000000                            #  17c: 00000000
.Ldata014:  .word        0x00000000                            #  180: 00000000
.Ldata015:  .word        0x00000000                            #  184: 00000000
.Ldata016:  .word        0x00000000                            #  188: 00000000
.Ldata017:  .word        0x00000000                            #  18c: 00000000

# NOTE: 16 non-alignment zero bytes skipped.

            .skip        16
.Ldata018:  .word        0x00000000                            #  1a0: 00000000
sdk_NMIIrqIsOn:
            .byte        0x00
            .byte        0x00, 0x00, 0x00
sdk_WdevTimOffSet:
            .word        0x00000000                            #  1a8: 00000000
            .word        0x00000000                            #  1ac: 00000000
.Ldata019:  .space       60
            .word        0x00000000                            #  1ec: 00000000
            .space       8020
.Ldata020:  .space       12
.Ldata021:  .space       60
            .word        0x00000000                            # 218c: 00000000
            .space       8000
.Ldata022:  .space       72
            .space       8
            .space       1536
.Ldata023:  .byte        0x00

            .section     .irom0.text, "ax", @progbits

# NOTE: The following is apparently unreferenced code/data
.Llit063:   .word        0x0080a000                            #    0: 00a08000
.Llit064:   .word        0x3ff20e00                            #    4: 000ef23f
.Llit065:   .word        0x3ff20a00                            #    8: 000af23f
.Llit066:   .word        0x7fdfbff7                            #    c: f7bfdf7f
.Llit067:   .word        0xffff00ff                            #   10: ff00ffff
.Llit068:   .word        0xfffff000                            #   14: 00f0ffff
.Llit069:   .word        0x80000000                            #   18: 00000080
.Llit070:   .word        0x40000000                            #   1c: 00000040

# Function @ .irom0.text+0x20
.literal_position
sdk_wDev_Option_Init:
            movi         a9, .Llit063 /* 0x0080a000 */         #   20: 91f8ff
            movi         a8, .Llit064 /* 0x3ff20e00 */         #   23: 81f8ff
            movi         a3, .Llit065 /* 0x3ff20a00 */         #   26: 31f8ff
            memw                                               #   29: c02000
            l32i         a7, a3, 0x288 /* [0x3ff20c88] */      #   2c: 7223a2
            or           a7, a7, a9                            #   2f: 907720
            memw                                               #   32: c02000
            s32i         a7, a3, 0x288 /* a7 -> [0x3ff20c88] */ #   35: 7263a2
            movi         a6, .Llit066 /* 0x7fdfbff7 */         #   38: 61f5ff
            memw                                               #   3b: c02000
            l32i         a5, a3, 0x288 /* [0x3ff20c88] */      #   3e: 5223a2
            and          a5, a5, a6                            #   41: 605510
            memw                                               #   44: c02000
            s32i         a5, a3, 0x288 /* a5 -> [0x3ff20c88] */ #   47: 5263a2
            movi.n       a4, 8 /* 0x00000008 */                #   4a: 0c84
            memw                                               #   4c: c02000
            l32i         a2, a3, 0x290 /* [0x3ff20c90] */      #   4f: 2223a4
            or           a2, a2, a4                            #   52: 402220
            memw                                               #   55: c02000
            s32i         a2, a3, 0x290 /* a2 -> [0x3ff20c90] */ #   58: 2263a4
            movi.n       a11, 3 /* 0x00000003 */               #   5b: 0c3b
            memw                                               #   5d: c02000
            l32i         a10, a3, 0x294 /* [0x3ff20c94] */     #   60: a223a5
            or           a10, a10, a11                         #   63: b0aa20
            memw                                               #   66: c02000
            s32i         a10, a3, 0x294 /* a10 -> [0x3ff20c94] */ #   69: a263a5
            movi         a9, -241 /* 0xffffff0f */             #   6c: 92af0f
            memw                                               #   6f: c02000
            l32i.n       a7, a8, 8 /* [0x3ff20e08] */          #   72: 7828
            and          a7, a7, a9                            #   74: 907710
            memw                                               #   77: c02000
            s32i.n       a7, a8, 8 /* a7 -> [0x3ff20e08] */    #   7a: 7928
            movi         a6, -256 /* 0xffffff00 */             #   7c: 62af00
            movi.n       a5, 4 /* 0x00000004 */                #   7f: 0c45
            memw                                               #   81: c02000
            l32i         a4, a3, 0x26c /* [0x3ff20c6c] */      #   84: 42239b
            and          a4, a4, a6                            #   87: 604410
            or           a4, a4, a5                            #   8a: 504420
            memw                                               #   8d: c02000
            s32i         a4, a3, 0x26c /* a4 -> [0x3ff20c6c] */ #   90: 42639b
            movi         a2, .Llit067 /* 0xffff00ff */         #   93: 21dfff
            movi         a11, 1024 /* 0x00000400 */            #   96: b2a400
            memw                                               #   99: c02000
            l32i         a10, a3, 0x26c /* [0x3ff20c6c] */     #   9c: a2239b
            and          a10, a10, a2                          #   9f: 20aa10
            or           a10, a10, a11                         #   a2: b0aa20
            memw                                               #   a5: c02000
            s32i         a10, a3, 0x26c /* a10 -> [0x3ff20c6c] */ #   a8: a2639b
            movi         a9, .Llit068 /* 0xfffff000 */         #   ab: 91daff
            movi         a8, 240 /* 0x000000f0 */              #   ae: 82a0f0
            memw                                               #   b1: c02000
            l32i         a7, a3, 0x214 /* [0x3ff20c14] */      #   b4: 722385
            and          a7, a7, a9                            #   b7: 907710
            or           a7, a7, a8                            #   ba: 807720
            memw                                               #   bd: c02000
            s32i         a7, a3, 0x214 /* a7 -> [0x3ff20c14] */ #   c0: 726385
            movi         a6, .Llit069 /* 0x80000000 */         #   c3: 61d5ff
            memw                                               #   c6: c02000
            l32i         a5, a3, 0x214 /* [0x3ff20c14] */      #   c9: 522385
            or           a5, a5, a6                            #   cc: 605520
            memw                                               #   cf: c02000
            s32i         a5, a3, 0x214 /* a5 -> [0x3ff20c14] */ #   d2: 526385
            movi         a4, .Llit070 /* 0x40000000 */         #   d5: 41d1ff
            memw                                               #   d8: c02000
            l32i         a2, a3, 0x214 /* [0x3ff20c14] */      #   db: 222385
            or           a2, a2, a4                            #   de: 402220
            memw                                               #   e1: c02000
            s32i         a2, a3, 0x214 /* a2 -> [0x3ff20c14] */ #   e4: 226385
            ret.n                                              #   e7: 0df0

# NOTE: The following is apparently unreferenced code/data
            .balign      4
.Llit071:   .word        0xc4000000                            #   ec: 000000c4
.Llit072:   .word        0x3ff20e00                            #   f0: 000ef23f

# Function @ .irom0.text+0xf4
.literal_position
sdk_wDev_Enable_Beacon_Tsf:
            movi         a4, .Llit071 /* 0xc4000000 */         #   f4: 41feff
            movi         a3, .Llit072 /* 0x3ff20e00 */         #   f7: 31feff
            memw                                               #   fa: c02000
            l32i         a2, a3, 0x258 /* [0x3ff21058] */      #   fd: 222396
            or           a2, a2, a4                            #  100: 402220
            memw                                               #  103: c02000
            s32i         a2, a3, 0x258 /* a2 -> [0x3ff21058] */ #  106: 226396
            ret.n                                              #  109: 0df0

# NOTE: The following is apparently unreferenced code/data
            .balign      4
.Llit073:   .word        0x3bffffff                            #  10c: ffffff3b
.Llit074:   .word        0x3ff20e00                            #  110: 000ef23f

# Function @ .irom0.text+0x114
.literal_position
sdk_wDev_Disable_Beacon_Tsf:
            movi         a4, .Llit073 /* 0x3bffffff */         #  114: 41feff
            movi         a3, .Llit074 /* 0x3ff20e00 */         #  117: 31feff
            memw                                               #  11a: c02000
            l32i         a2, a3, 0x258 /* [0x3ff21058] */      #  11d: 222396
            and          a2, a2, a4                            #  120: 402210
            memw                                               #  123: c02000
            s32i         a2, a3, 0x258 /* a2 -> [0x3ff21058] */ #  126: 226396
            ret.n                                              #  129: 0df0

            .balign      4
.Lrel144:   .word        .data                                 #  12c: 00000000

# Function @ .irom0.text+0x130
.literal_position
sdk_wDev_Set_Beacon_Int:
            movi         a3, .Lrel144 /* .Lrel143 */           #  130: 31ffff
            s32i.n       a2, a3, 4 /* arg0 -> [.Ldata001] */   #  133: 2913
            ret.n         /* arg0 */                           #  135: 0df0

            .balign      4
.Lrel145:   .word        .bss                                  #  138: 00000000

# NOTE: The following is apparently unreferenced code/data
.Llit075:   .word        0x3ff20e00                            #  13c: 000ef23f

.Lrel146:   .word        sdk_PPWdtReset                        #  140: 00000000

# Function @ .irom0.text+0x144
# Local variables/stack:
#     (local0):  word[4]   @ -0x10
.literal_position
sdk_wDev_Reset_TBTT:
            addi         a1, a1, -16 /* (local0) */            #  144: 12c1f0
            s32i.n       a0, a1, 0 /* a0 -> [(local0)] */      #  147: 0901
            call0        sdk_wDev_Disable_Beacon_Tsf           #  149: 050000
            movi         a0, .Lrel146 /* sdk_PPWdtReset */     #  14c: 01fdff
            callx0       a0 /* sdk_PPWdtReset */               #  14f: c00000
            movi         a3, .Lrel145 /* sdk_wDevCtrl */       #  152: 31f9ff
            movi.n       a0, 0 /* 0x00000000 */                #  155: 0c00
            s32i         a0, a3, 0x1a0 /* 0x00000000 -> [.Ldata018] */ #  157: 026368
            movi         a2, .Llit075 /* 0x3ff20e00 */         #  15a: 21f8ff
            memw                                               #  15d: c02000
            s32i         a0, a2, 0x25c /* 0x00000000 -> [0x3ff2105c] */ #  160: 026297
            memw                                               #  163: c02000
            s32i         a0, a2, 0x260 /* 0x00000000 -> [0x3ff21060] */ #  166: 026298
            call0        sdk_wDev_Enable_Beacon_Tsf            #  169: 050000
            l32i.n       a0, a1, 0 /* [(local0)] */            #  16c: 0801
            addi         a1, a1, 16 /* (top of frame) */       #  16e: 12c110
            ret.n                                              #  171: 0df0

# NOTE: The following is apparently unreferenced code/data
            .balign      4
.Llit076:   .word        0x3ff20e00                            #  174: 000ef23f

.Lrel147:   .word        .data                                 #  178: 00000000
.Lrel148:   .word        .bss                                  #  17c: 00000000
.Lrel149:   .word        __udivsi3                             #  180: 00000000

# Function @ .irom0.text+0x184
# Local variables/stack:
#     (local0):  word[4]   @ -0x10
.literal_position
sdk_wDev_Get_Next_TBTT:
            movi         a5, .Llit076 /* 0x3ff20e00 */         #  184: 51fcff
            movi         a7, .Lrel148 /* sdk_wDevCtrl */       #  187: 71fdff
            movi         a6, .Lrel147 /* .Lrel143 */           #  18a: 61fbff
            addi         a1, a1, -16 /* (local0) */            #  18d: 12c1f0
            s32i.n       a0, a1, 0 /* a0 -> [(local0)] */      #  190: 0901
            l32i.n       a6, a6, 4 /* [.Ldata001] */           #  192: 6816
            l32i         a0, a7, 0x1a0 /* [.Ldata018] */       #  194: 022768
.Lbr167:    add.n        a0, a0, a6                            #  197: 6a00
            memw                                               #  199: c02000
            l32i         a2, a5, 0x248 /* [0x3ff21048] */      #  19c: 222592
            sub          a2, a0, a2                            #  19f: 2020c0
            bltu         a6, a2, .Lbr167                       #  1a2: 2736f1
            movi         a3, 1000 /* 0x000003e8 */             #  1a5: 32a3e8
            s32i         a0, a7, 0x1a0 /* a0 -> [.Ldata018] */ #  1a8: 026768
            movi         a0, .Lrel149 /* __udivsi3 */          #  1ab: 01f5ff
            callx0       a0 /* __udivsi3 */                    #  1ae: c00000
            l32i.n       a0, a1, 0 /* [(local0)] */            #  1b1: 0801
            addi         a1, a1, 16 /* (top of frame) */       #  1b3: 12c110
            ret.n                                              #  1b6: 0df0

# NOTE: The following is apparently unreferenced code/data
.Llit077:   .word        0x00001f54                            #  1b8: 541f0000

.Lrel150:   .word        .Ldata019                             #  1bc: b0010000
.Lrel151:   .word        .data                                 #  1c0: 00000000

# NOTE: The following is apparently unreferenced code/data
.Llit078:   .word        0x0000f000                            #  1c4: 00f00000
.Llit079:   .word        0xff000fff                            #  1c8: ff0f00ff

.Lrel152:   .word        .Ldata021                             #  1cc: 50210000

# NOTE: The following is apparently unreferenced code/data
.Llit080:   .word        0x00001f40                            #  1d0: 401f0000

.Lrel153:   .word        .Ldata022                             #  1d4: d0400000

# NOTE: The following is apparently unreferenced code/data
.Llit081:   .word        0x3ff1fe00                            #  1d8: 00fef13f

.Lrel154:   .word        .Ldata019                             #  1dc: b0010000
.Lrel155:   .word        .Ldata020                             #  1e0: 44210000
.Lrel156:   .word        .Ldata023                             #  1e4: 20470000

# NOTE: The following is apparently unreferenced code/data
.Llit082:   .word        0xdfffffff                            #  1e8: ffffffdf

.Lrel157:   .word        lldesc_build_chain                    #  1ec: 00000000
.Lrel158:   .word        .Lfunc007                             #  1f0: cc0f0000
.Lrel159:   .word        lldesc_build_chain                    #  1f4: 00000000
.Lrel160:   .word        lldesc_build_chain                    #  1f8: 00000000

# Function @ .irom0.text+0x1fc
# Local variables/stack:
#     (local0):  word      @ -0x30
#     (local1):  word[3]   @ -0x2c
#     (local2):  word      @ -0x20
#     (local3):  word      @ -0x1c
#     (local4):  word      @ -0x18
#     (local5):  word      @ -0x14
#     (local6):  word[4]   @ -0x10
.literal_position
.Lfunc011:  movi.n       a3, 60 /* 0x0000003c */               #  1fc: 3cc3
            movi         a5, .Llit077 /* 0x00001f54 */         #  1fe: 51eeff
            movi         a6, 1604 /* 0x00000644 */             #  201: 62a644
            movi.n       a7, 1 /* 0x00000001 */                #  204: 0c17
            movi         a4, .Lrel150 /* .Ldata019 */          #  206: 41edff
            addi         a1, a1, -48 /* (local0) */            #  209: 12c1d0
            s32i.n       a12, a1, 20 /* a12 -> [(local3)] */   #  20c: c951
            s32i.n       a13, a1, 24 /* a13 -> [(local4)] */   #  20e: d961
            s32i.n       a14, a1, 28 /* a14 -> [(local5)] */   #  210: e971
            s32i.n       a15, a1, 32 /* a15 -> [(local6)] */   #  212: f981
            s32i.n       a0, a1, 16 /* a0 -> [(local2)] */     #  214: 0941
            movi         a15, .Lrel151 /* .Lrel143 */          #  216: f1eaff
            mov.n        a2, a4 /* .Ldata019 */                #  219: 2d04
            l32i.n       a8, a15, 0 /* [.Lrel143] */           #  21b: 880f
            addi         a4, a4, 64 /* .bss+0x1f0 */           #  21d: 42c440
            addi.n       a0, a8, 12 /* [.Lrel143]+0xc */       #  220: cb08
            s32i.n       a0, a1, 4 /* [.Lrel143]+0xc -> [(local1)] */ #  222: 0911
            addi.n       a8, a8, 8 /* [.Lrel143]+0x8 */        #  224: 8b88
            s32i.n       a8, a1, 0 /* [.Lrel143]+0x8 -> [(local0)] */ #  226: 8901
            movi         a0, .Lrel157 /* lldesc_build_chain */ #  228: 01f1ff
            callx0       a0 /* lldesc_build_chain */           #  22b: c00000
            movi         a12, .Llit078 /* 0x0000f000 */        #  22e: c1e5ff
            l32i.n       a0, a15, 0 /* [.Lrel143] */           #  231: 080f
            movi.n       a5, 5 /* 0x00000005 */                #  233: 0c55
            l32i.n       a13, a0, 8 /* [[.Lrel143]+0x8] */     #  235: d820
            s16i         a5, a0, 0 /* 0x0005 -> [[.Lrel143]] */ #  237: 525000
            beqz         a13, .Lbr169                          #  23a: 165d06
            movi         a14, .Llit079 /* 0xff000fff */        #  23d: e1e2ff
.Lbr168:    memw                                               #  240: c02000
            l16ui        a9, a13, 0                            #  243: 921d00
            extui        a9, a9, 0, 12                         #  246: 9090b4
            addi         a9, a9, -4                            #  249: 92c9fc
            extui        a9, a9, 0, 12                         #  24c: 9090b4
            memw                                               #  24f: c02000
            l16ui        a8, a13, 0                            #  252: 821d00
            and          a8, a8, a12                           #  255: c08810
            or           a8, a8, a9                            #  258: 908820
            memw                                               #  25b: c02000
            s16i         a8, a13, 0                            #  25e: 825d00
            memw                                               #  261: c02000
            l16ui        a7, a13, 0                            #  264: 721d00
            extui        a7, a7, 0, 12                         #  267: 7070b4
            slli         a7, a7, 12                            #  26a: 407711
            memw                                               #  26d: c02000
            l16ui        a6, a13, 2                            #  270: 621d01
            slli         a6, a6, 16                            #  273: 006611
            memw                                               #  276: c02000
            l16ui        a8, a13, 0                            #  279: 821d00
            or           a6, a6, a8                            #  27c: 806620
            and          a6, a6, a14                           #  27f: e06610
            or           a6, a6, a7                            #  282: 706620
            memw                                               #  285: c02000
            s16i         a6, a13, 0                            #  288: 625d00
            extui        a6, a6, 16, 16                        #  28b: 6060f5
            memw                                               #  28e: c02000
            s16i         a6, a13, 2                            #  291: 625d01
            mov.n        a2, a13                               #  294: 2d0d
            movi         a0, .Lrel158 /* .Lrel158 */           #  296: 01d6ff
            callx0       a0                                    #  299: c00000
            l32i.n       a13, a13, 8                           #  29c: d82d
            bnez         a13, .Lbr168                          #  29e: 56edf9
            l32i.n       a0, a15, 0 /* [.Lrel143] */           #  2a1: 080f
.Lbr169:    movi.n       a3, 60 /* 0x0000003c */               #  2a3: 3cc3
            movi         a5, .Llit080 /* 0x00001f40 */         #  2a5: 51caff
            movi         a6, 1600 /* 0x00000640 */             #  2a8: 62a640
            movi.n       a7, 0 /* 0x00000000 */                #  2ab: 0c07
            movi         a2, .Lrel152 /* .Ldata021 */          #  2ad: 21c7ff
            addi         a10, a0, 44 /* [.Lrel143]+0x2c */     #  2b0: a2c02c
            addi         a11, a0, 40 /* [.Lrel143]+0x28 */     #  2b3: b2c028
            s32i.n       a11, a1, 0 /* [.Lrel143]+0x28 -> [(local0)] */ #  2b6: b901
            s32i.n       a10, a1, 4 /* [.Lrel143]+0x2c -> [(local1)] */ #  2b8: a911
            addi         a4, a2, 64 /* .bss+0x2190 */          #  2ba: 42c240
            movi         a0, .Lrel159 /* lldesc_build_chain */ #  2bd: 01cdff
            callx0       a0 /* lldesc_build_chain */           #  2c0: c00000
            l32i.n       a0, a15, 0 /* [.Lrel143] */           #  2c3: 080f
            movi.n       a14, 0 /* 0x00000000 */               #  2c5: 0c0e
            s32i.n       a14, a0, 32 /* 0x00000000 -> [[.Lrel143]+0x20] */ #  2c7: e980
            addi         a9, a0, 36 /* [.Lrel143]+0x24 */      #  2c9: 92c024
            s16i         a14, a0, 2 /* 0x0000 -> [[.Lrel143]+0x2] */ #  2cc: e25001
            s32i.n       a9, a0, 28 /* [.Lrel143]+0x24 -> [[.Lrel143]+0x1c] */ #  2cf: 9970
            movi         a13, .Lrel153 /* .Ldata022 */         #  2d1: d1c0ff
            movi.n       a9, 4 /* 0x00000004 */                #  2d4: 0c49
            memw                                               #  2d6: c02000
            l16ui        a8, a0, 24 /* [[.Lrel143]+0x18] */    #  2d9: 82100c
            and          a8, a8, a12                           #  2dc: c08810
            or           a8, a8, a9                            #  2df: 908820
            memw                                               #  2e2: c02000
            s16i         a8, a0, 24 /* a8 -> [[.Lrel143]+0x18] */ #  2e5: 82500c
            movi         a8, 128 /* 0x00000080 */              #  2e8: 82a080
            memw                                               #  2eb: c02000
            l8ui         a7, a0, 27 /* [[.Lrel143]+0x1b] */    #  2ee: 72001b
            extui        a7, a7, 0, 7                          #  2f1: 707064
            or           a7, a7, a8                            #  2f4: 807720
            memw                                               #  2f7: c02000
            s8i          a7, a0, 27 /* a7 -> [[.Lrel143]+0x1b] */ #  2fa: 72401b
            movi         a6, 191 /* 0x000000bf */              #  2fd: 62a0bf
            memw                                               #  300: c02000
            l8ui         a5, a0, 27 /* [[.Lrel143]+0x1b] */    #  303: 52001b
            and          a5, a5, a6                            #  306: 605510
            memw                                               #  309: c02000
            s8i          a5, a0, 27 /* a5 -> [[.Lrel143]+0x1b] */ #  30c: 52401b
            movi         a4, 223 /* 0x000000df */              #  30f: 42a0df
            memw                                               #  312: c02000
            l8ui         a3, a0, 27 /* [[.Lrel143]+0x1b] */    #  315: 32001b
            and          a3, a3, a4                            #  318: 403310
            memw                                               #  31b: c02000
            addi         a4, a13, 80 /* .bss+0x4120 */         #  31e: 42cd50
            movi         a5, 1536 /* 0x00000600 */             #  321: 52a600
            movi         a6, 256 /* 0x00000100 */              #  324: 62a100
            movi.n       a7, 1 /* 0x00000001 */                #  327: 0c17
            s8i          a3, a0, 27 /* a3 -> [[.Lrel143]+0x1b] */ #  329: 32401b
            addi         a2, a0, 48 /* [.Lrel143]+0x30 */      #  32c: 22c030
            movi.n       a3, 72 /* 0x00000048 */               #  32f: 4c83
            s32i.n       a2, a1, 0 /* [.Lrel143]+0x30 -> [(local0)] */ #  331: 2901
            addi         a0, a0, 52 /* [.Lrel143]+0x34 */      #  333: 02c034
            mov.n        a2, a13 /* .Ldata022 */               #  336: 2d0d
            s32i.n       a0, a1, 4 /* [.Lrel143]+0x34 -> [(local1)] */ #  338: 0911
            movi         a0, .Lrel160 /* lldesc_build_chain */ #  33a: 01afff
            callx0       a0 /* lldesc_build_chain */           #  33d: c00000
            l32i.n       a15, a15, 0 /* [.Lrel143] */          #  340: f80f
            movi.n       a8, 6 /* 0x00000006 */                #  342: 0c68
            s8i          a8, a15, 4 /* 0x06 -> [[.Lrel143]+0x4] */ #  344: 824f04
            movi         a11, .Llit081 /* 0x3ff1fe00 */        #  347: b1a4ff
            memw                                               #  34a: c02000
            movi         a7, .Lrel154 /* .Ldata019 */          #  34d: 71a3ff
            s32i         a7, a11, 0x280 /* .Ldata019 -> [0x3ff20080] */ #  350: 726ba0
            movi         a6, .Lrel155 /* .Ldata020 */          #  353: 61a3ff
            memw                                               #  356: c02000
            s32i         a6, a11, 0x27c /* .Ldata020 -> [0x3ff2007c] */ #  359: 626b9f
            memw                                               #  35c: c02000
            s32i         a13, a11, 0x288 /* .Ldata022 -> [0x3ff20088] */ #  35f: d26ba2
            movi         a5, .Lrel156 /* .Ldata023 */          #  362: 51a0ff
            memw                                               #  365: c02000
            s32i         a5, a11, 0x284 /* .Ldata023 -> [0x3ff20084] */ #  368: 526ba1
            movi         a4, -256 /* 0xffffff00 */             #  36b: 42af00
            memw                                               #  36e: c02000
            l32i         a3, a11, 0x200 /* [0x3ff20000] */     #  371: 322b80
            and          a3, a3, a4                            #  374: 403310
            memw                                               #  377: c02000
            s32i         a3, a11, 0x200 /* a3 -> [0x3ff20000] */ #  37a: 326b80
            l32i.n       a2, a15, 8 /* [[.Lrel143]+0x8] */     #  37d: 282f
            memw                                               #  37f: c02000
            s32i         a2, a11, 0x208 /* [[.Lrel143]+0x8] -> [0x3ff20008] */ #  382: 226b82
            l32i.n       a0, a15, 48 /* [[.Lrel143]+0x30] */   #  385: 08cf
            memw                                               #  387: c02000
            s32i         a0, a11, 0x20c /* [[.Lrel143]+0x30] -> [0x3ff2000c] */ #  38a: 026b83
            s8i          a14, a15, 5 /* 0x00 -> [[.Lrel143]+0x5] */ #  38d: e24f05
            memw                                               #  390: c02000
            s32i         a14, a11, 0x210 /* 0x00000000 -> [0x3ff20010] */ #  393: e26b84
            movi         a12, .Llit082 /* 0xdfffffff */        #  396: c194ff
            memw                                               #  399: c02000
            l32i         a10, a11, 0x200 /* [0x3ff20000] */    #  39c: a22b80
            and          a10, a10, a12                         #  39f: c0aa10
            memw                                               #  3a2: c02000
            s32i         a10, a11, 0x200 /* a10 -> [0x3ff20000] */ #  3a5: a26b80
            l32i.n       a12, a1, 20 /* [(local3)] */          #  3a8: c851
            l32i.n       a13, a1, 24 /* [(local4)] */          #  3aa: d861
            l32i.n       a14, a1, 28 /* [(local5)] */          #  3ac: e871
            l32i.n       a15, a1, 32 /* [(local6)] */          #  3ae: f881
            l32i.n       a0, a1, 16 /* [(local2)] */           #  3b0: 0841
            addi         a1, a1, 48 /* (top of frame) */       #  3b2: 12c130
            ret.n         /* [[.Lrel143]+0x8] */               #  3b5: 0df0

# NOTE: The following is apparently unreferenced code/data
            .balign      4
.Llit083:   .word        0x76503210                            #  3b8: 10325076
.Llit084:   .word        0xbbbbbbbb                            #  3bc: bbbbbbbb
.Llit085:   .word        0x3ff20200                            #  3c0: 0002f23f

# Function @ .irom0.text+0x3c4
.literal_position
.Lfunc012:  movi         a4, .Llit083 /* 0x76503210 */         #  3c4: 41fdff
            movi         a2, .Llit084 /* 0xbbbbbbbb */         #  3c7: 21fdff
            movi         a3, .Llit085 /* 0x3ff20200 */         #  3ca: 31fdff
            memw                                               #  3cd: c02000
            s32i         a4, a3, 0x200 /* 0x76503210 -> [0x3ff20400] */ #  3d0: 426380
            memw                                               #  3d3: c02000
            s32i         a2, a3, 0x204 /* 0xbbbbbbbb -> [0x3ff20404] */ #  3d6: 226381
            memw                                               #  3d9: c02000
            s32i         a2, a3, 0x208 /* 0xbbbbbbbb -> [0x3ff20408] */ #  3dc: 226382
            ret.n         /* 0xbbbbbbbb */                     #  3df: 0df0

# NOTE: The following is apparently unreferenced code/data
            .balign      4
.Llit086:   .word        0x3ff1fe00                            #  3e4: 00fef13f
.Llit087:   .word        0xffffefff                            #  3e8: ffefffff

# Function @ .irom0.text+0x3ec
# Local variables/stack:
#     (local0):  word[4]   @ -0x10
.literal_position
.Lfunc013:  addi         a1, a1, -16 /* (local0) */            #  3ec: 12c1f0
            s32i.n       a0, a1, 0 /* a0 -> [(local0)] */      #  3ef: 0901
            movi         a7, 1799 /* 0x00000707 */             #  3f1: 72a707
            movi         a2, .Llit086 /* 0x3ff1fe00 */         #  3f4: 21fcff
            memw                                               #  3f7: c02000
            l32i         a6, a2, 0x26c /* [0x3ff2006c] */      #  3fa: 62229b
            or           a6, a6, a7                            #  3fd: 706620
            memw                                               #  400: c02000
            s32i         a6, a2, 0x26c /* a6 -> [0x3ff2006c] */ #  403: 62629b
            movi.n       a5, -17 /* 0xffffffef */              #  406: 6cf5
            memw                                               #  408: c02000
            l32i         a4, a2, 0x26c /* [0x3ff2006c] */      #  40b: 42229b
            and          a4, a4, a5                            #  40e: 504410
            memw                                               #  411: c02000
            s32i         a4, a2, 0x26c /* a4 -> [0x3ff2006c] */ #  414: 42629b
            movi         a3, .Llit087 /* 0xffffefff */         #  417: 31f4ff
            memw                                               #  41a: c02000
            l32i         a0, a2, 0x26c /* [0x3ff2006c] */      #  41d: 02229b
            and          a0, a0, a3                            #  420: 300010
            memw                                               #  423: c02000
            movi.n       a3, 0 /* 0x00000000 */                #  426: 0c03
            s32i         a0, a2, 0x26c /* a0 -> [0x3ff2006c] */ #  428: 02629b
            movi.n       a4, 0 /* 0x00000000 */                #  42b: 0c04
            movi.n       a2, 0 /* 0x00000000 */                #  42d: 0c02
            call0        sdk_wDev_SetRxPolicy                  #  42f: 050000
            movi.n       a2, 0 /* 0x00000000 */                #  432: 0c02
            movi.n       a3, 1 /* 0x00000001 */                #  434: 0c13
            movi.n       a4, 0 /* 0x00000000 */                #  436: 0c04
            call0        sdk_wDev_SetRxPolicy                  #  438: 050000
            l32i.n       a0, a1, 0 /* [(local0)] */            #  43b: 0801
            addi         a1, a1, 16 /* (top of frame) */       #  43d: 12c110
            ret.n                                              #  440: 0df0

# NOTE: The following is apparently unreferenced code/data
            .balign      4
.Llit088:   .word        0x80000000                            #  444: 00000080
.Llit089:   .word        0x3ff20e00                            #  448: 000ef23f

.Lrel161:   .word        .data                                 #  44c: 00000000

# Function @ .irom0.text+0x450
.literal_position
sdk_wDev_MacTim1SetFunc:
            movi         a6, .Llit088 /* 0x80000000 */         #  450: 61fdff
            movi         a5, .Llit089 /* 0x3ff20e00 */         #  453: 51fdff
            memw                                               #  456: c02000
            l32i         a4, a5, 0x258 /* [0x3ff21058] */      #  459: 422596
            or           a4, a4, a6                            #  45c: 604420
            memw                                               #  45f: c02000
            movi         a3, .Lrel161 /* .Lrel143 */           #  462: 31faff
            s32i         a4, a5, 0x258 /* a4 -> [0x3ff21058] */ #  465: 426596
            s32i.n       a2, a3, 12 /* arg0 -> [.Ldata003] */  #  468: 2933
            ret.n         /* arg0 */                           #  46a: 0df0

# NOTE: The following is apparently unreferenced code/data
.Llit090:   .word        0x3ff20a00                            #  46c: 000af23f
.Llit091:   .word        0x0c9f0300                            #  470: 00039f0c
.Llit092:   .word        0x3ff1fe00                            #  474: 00fef13f
.Llit093:   .word        0x3ff20a00                            #  478: 000af23f
.Llit094:   .word        0x7fffffff                            #  47c: ffffff7f

# Function @ .irom0.text+0x480
# Local variables/stack:
#     (local0):  word[4]   @ -0x10
.literal_position
sdk_wDev_Initialize:
            addi         a1, a1, -16 /* (local0) */            #  480: 12c1f0
            s32i.n       a0, a1, 0 /* a0 -> [(local0)] */      #  483: 0901
            movi.n       a3, 0 /* 0x00000000 */                #  485: 0c03
            movi         a2, .Llit090 /* 0x3ff20a00 */         #  487: 21f9ff
            memw                                               #  48a: c02000
            s32i         a3, a2, 0x218 /* 0x00000000 -> [0x3ff20c18] */ #  48d: 326286
            movi.n       a0, -1 /* 0xffffffff */               #  490: 7cf0
            memw                                               #  492: c02000
            s32i         a0, a2, 0x224 /* 0xffffffff -> [0x3ff20c24] */ #  495: 026289
            call0        sdk_wDev_Option_Init                  #  498: 050000
            call0        .Lfunc014                             #  49b: 054200
            call0        .Lfunc011                             #  49e: c5d5ff
            call0        .Lfunc012                             #  4a1: 05f2ff
            call0        .Lfunc013                             #  4a4: 45f4ff
            movi         a9, .Llit091 /* 0x0c9f0300 */         #  4a7: 91f2ff
            movi         a5, .Llit092 /* 0x3ff1fe00 */         #  4aa: 51f2ff
            memw                                               #  4ad: c02000
            movi         a10, .Llit093 /* 0x3ff20a00 */        #  4b0: a1f2ff
            s32i         a9, a10, 0x218 /* 0x0c9f0300 -> [0x3ff20c18] */ #  4b3: 926a86
            movi.n       a8, 2 /* 0x00000002 */                #  4b6: 0c28
            memw                                               #  4b8: c02000
            l32i         a7, a5, 0x378 /* [0x3ff20178] */      #  4bb: 7225de
            or           a7, a7, a8                            #  4be: 807720
            memw                                               #  4c1: c02000
            s32i         a7, a5, 0x378 /* a7 -> [0x3ff20178] */ #  4c4: 7265de
            movi         a6, .Llit094 /* 0x7fffffff */         #  4c7: 61edff
            memw                                               #  4ca: c02000
            l32i         a4, a5, 0x204 /* [0x3ff20004] */      #  4cd: 422581
            and          a4, a4, a6                            #  4d0: 604410
            memw                                               #  4d3: c02000
            s32i         a4, a5, 0x204 /* a4 -> [0x3ff20004] */ #  4d6: 426581
            l32i.n       a0, a1, 0 /* [(local0)] */            #  4d9: 0801
            addi         a1, a1, 16 /* (top of frame) */       #  4db: 12c110
            ret.n                                              #  4de: 0df0

# NOTE: The following is apparently unreferenced code/data
.Llit095:   .word        0x3ff20200                            #  4e0: 0002f23f
.Llit096:   .word        0x00070b00                            #  4e4: 000b0700
.Llit097:   .word        0x00070c07                            #  4e8: 070c0700

# Function @ .irom0.text+0x4ec
.literal_position
sdk_wDevForceAck6M:
            movi         a4, .Llit095 /* 0x3ff20200 */         #  4ec: 41fdff
            beqz.n       a2, .Lbr170                           #  4ef: 8c92
            movi         a3, .Llit096 /* 0x00070b00 */         #  4f1: 31fcff
            memw                                               #  4f4: c02000
            s32i         a3, a4, 0x20c /* 0x00070b00 -> [0x3ff2040c] */ #  4f7: 326483
            ret.n         /* arg0 */                           #  4fa: 0df0
.Lbr170:    movi         a2, .Llit097 /* 0x00070c07 */         #  4fc: 21fbff
            memw                                               #  4ff: c02000
            s32i         a2, a4, 0x20c /* 0x00070c07 -> [0x3ff2040c] */ #  502: 226483
            ret.n         /* 0x00070c07 */                     #  505: 0df0

# NOTE: The following is apparently unreferenced code/data
            .balign      4
.Llit098:   .word        0x00010000                            #  508: 00000100
.Llit099:   .word        0x0000ffff                            #  50c: ffff0000
.Llit100:   .word        0x3ff20a00                            #  510: 000af23f

# Function @ .irom0.text+0x514
.literal_position
sdk_wDev_SetMacAddress:
            movi.n       a9, -1 /* 0xffffffff */               #  514: 7cf9
            movi         a8, .Llit098 /* 0x00010000 */         #  516: 81fcff
            l8ui         a7, a3, 3 /* [arg1+0x3] */            #  519: 720303
            l8ui         a5, a3, 1 /* [arg1+0x1] */            #  51c: 520301
            l8ui         a6, a3, 0 /* [arg1] */                #  51f: 620300
            slli         a5, a5, 8                             #  522: 805511
            or           a5, a5, a6                            #  525: 605520
            l8ui         a6, a3, 2 /* [arg1+0x2] */            #  528: 620302
            slli         a7, a7, 24                            #  52b: 807701
            slli         a6, a6, 16                            #  52e: 006611
            or           a6, a6, a7                            #  531: 706620
            movi         a7, .Llit099 /* 0x0000ffff */         #  534: 71f6ff
            or           a5, a5, a6                            #  537: 605520
            movi         a6, .Llit100 /* 0x3ff20a00 */         #  53a: 61f5ff
            beqz.n       a2, .Lbr171                           #  53d: bc32
            memw                                               #  53f: c02000
            s32i         a5, a6, 0x250 /* a5 -> [0x3ff20c50] */ #  542: 526694
            l8ui         a11, a3, 5 /* [arg1+0x5] */           #  545: b20305
            l8ui         a10, a3, 4 /* [arg1+0x4] */           #  548: a20304
            slli         a11, a11, 8                           #  54b: 80bb11
            or           a10, a10, a11                         #  54e: b0aa20
            memw                                               #  551: c02000
            s32i         a10, a6, 0x254 /* a10 -> [0x3ff20c54] */ #  554: a26695
            memw                                               #  557: c02000
            s32i         a9, a6, 0x260 /* 0xffffffff -> [0x3ff20c60] */ #  55a: 926698
            memw                                               #  55d: c02000
            s32i         a7, a6, 0x264 /* 0x0000ffff -> [0x3ff20c64] */ #  560: 726699
            memw                                               #  563: c02000
            l32i         a4, a6, 0x264 /* [0x3ff20c64] */      #  566: 422699
            or           a4, a4, a8                            #  569: 804420
            memw                                               #  56c: c02000
            s32i         a4, a6, 0x264 /* a4 -> [0x3ff20c64] */ #  56f: 426699
            ret.n         /* arg0 */                           #  572: 0df0
.Lbr171:    memw                                               #  574: c02000
            s32i         a5, a6, 0x248 /* a5 -> [0x3ff20c48] */ #  577: 526692
            l8ui         a2, a3, 5 /* [arg1+0x5] */            #  57a: 220305
            l8ui         a11, a3, 4 /* [arg1+0x4] */           #  57d: b20304
            slli         a2, a2, 8                             #  580: 802211
            or           a11, a11, a2                          #  583: 20bb20
            memw                                               #  586: c02000
            s32i         a11, a6, 0x24c /* a11 -> [0x3ff20c4c] */ #  589: b26693
            memw                                               #  58c: c02000
            s32i         a9, a6, 0x258 /* 0xffffffff -> [0x3ff20c58] */ #  58f: 926696
            memw                                               #  592: c02000
            s32i         a7, a6, 0x25c /* 0x0000ffff -> [0x3ff20c5c] */ #  595: 726697
            memw                                               #  598: c02000
            l32i         a10, a6, 0x25c /* [0x3ff20c5c] */     #  59b: a22697
            or           a10, a10, a8                          #  59e: 80aa20
            memw                                               #  5a1: c02000
            s32i         a10, a6, 0x25c /* a10 -> [0x3ff20c5c] */ #  5a4: a26697
            ret.n                                              #  5a7: 0df0

# NOTE: The following is apparently unreferenced code/data
            .balign      4
.Llit101:   .word        0x3ff20a00                            #  5ac: 000af23f
.Llit102:   .word        0xfffeffff                            #  5b0: fffffeff

.Lrel162:   .word        sdk_ieee80211_addr_bcast              #  5b4: 00000000

# Function @ .irom0.text+0x5b8
# Local variables/stack:
#     (local0):  word[4]   @ -0x10
.literal_position
sdk_wDev_SetRxPolicy:
            addi         a1, a1, -16 /* (local0) */            #  5b8: 12c1f0
            s32i.n       a0, a1, 0 /* a0 -> [(local0)] */      #  5bb: 0901
            bnez.n       a2, .Lbr172                           #  5bd: dc82
            movi         a0, .Llit102 /* 0xfffeffff */         #  5bf: 01fcff
            movi         a2, .Llit101 /* 0x3ff20a00 */         #  5c2: 21faff
            bnez.n       a3, .Lbr175                           #  5c5: fc13
            memw                                               #  5c7: c02000
            l32i         a3, a2, 0x23c /* [0x3ff20c3c] */      #  5ca: 32228f
            and          a3, a3, a0                            #  5cd: 003310
            memw                                               #  5d0: c02000
            s32i         a3, a2, 0x23c /* a3 -> [0x3ff20c3c] */ #  5d3: 32628f
            j            .Lbr174                               #  5d6: 460600
.Lbr172:    bnei         a2, 1, .Lbr173                        #  5d9: 66120a
            mov.n        a2, a3 /* arg1 */                     #  5dc: 2d03
            movi         a3, .Lrel162 /* sdk_ieee80211_addr_bcast */ #  5de: 31f5ff
            call0        sdk_wDev_SetBssid                     #  5e1: 050000
            j            .Lbr174                               #  5e4: c60200
.Lbr173:    bnei         a2, 2, .Lbr174                        #  5e7: 662208
            beqz.n       a4, .Lbr174                           #  5ea: 8c54
            mov.n        a2, a3 /* arg1 */                     #  5ec: 2d03
            mov.n        a3, a4 /* arg2 */                     #  5ee: 3d04
            call0        sdk_wDev_SetBssid                     #  5f0: 050000
.Lbr174:    l32i.n       a0, a1, 0 /* [(local0)] */            #  5f3: 0801
            addi         a1, a1, 16 /* (top of frame) */       #  5f5: 12c110
            ret.n                                              #  5f8: 0df0
.Lbr175:    memw                                               #  5fa: c02000
            l32i         a4, a2, 0x244 /* [0x3ff20c44] */      #  5fd: 422291
            and          a4, a4, a0                            #  600: 004410
            memw                                               #  603: c02000
            s32i         a4, a2, 0x244 /* a4 -> [0x3ff20c44] */ #  606: 426291
            j            .Lbr174                               #  609: 86f9ff

# NOTE: The following is apparently unreferenced code/data
.Llit103:   .word        0x00010000                            #  60c: 00000100
.Llit104:   .word        0x0000ffff                            #  610: ffff0000
.Llit105:   .word        0x3ff20a00                            #  614: 000af23f
.Llit106:   .word        0xfffeffff                            #  618: fffffeff

# Function @ .irom0.text+0x61c
.literal_position
sdk_wDev_SetBssid:
            movi.n       a10, -1 /* 0xffffffff */              #  61c: 7cfa
            movi         a8, .Llit103 /* 0x00010000 */         #  61e: 81fbff
            movi         a7, .Llit104 /* 0x0000ffff */         #  621: 71fbff
            movi         a5, .Llit106 /* 0xfffeffff */         #  624: 51fdff
            movi         a6, .Llit105 /* 0x3ff20a00 */         #  627: 61fbff
            beqz         a2, .Lbr176                           #  62a: 161206
            memw                                               #  62d: c02000
            l32i         a11, a6, 0x244 /* [0x3ff20c44] */     #  630: b22691
            and          a11, a11, a5                          #  633: 50bb10
            memw                                               #  636: c02000
            s32i         a11, a6, 0x244 /* a11 -> [0x3ff20c44] */ #  639: b26691
            l8ui         a11, a3, 3 /* [arg1+0x3] */           #  63c: b20303
            l8ui         a9, a3, 1 /* [arg1+0x1] */            #  63f: 920301
            l8ui         a4, a3, 0 /* [arg1] */                #  642: 420300
            slli         a9, a9, 8                             #  645: 809911
            or           a4, a4, a9                            #  648: 904420
            l8ui         a9, a3, 2 /* [arg1+0x2] */            #  64b: 920302
            slli         a11, a11, 24                          #  64e: 80bb01
            slli         a9, a9, 16                            #  651: 009911
            or           a9, a9, a11                           #  654: b09920
            or           a4, a4, a9                            #  657: 904420
            memw                                               #  65a: c02000
            s32i         a4, a6, 0x230 /* a4 -> [0x3ff20c30] */ #  65d: 42668c
            l8ui         a2, a3, 5 /* [arg1+0x5] */            #  660: 220305
            l8ui         a11, a3, 4 /* [arg1+0x4] */           #  663: b20304
            slli         a2, a2, 8                             #  666: 802211
            or           a11, a11, a2                          #  669: 20bb20
            memw                                               #  66c: c02000
            s32i         a11, a6, 0x234 /* a11 -> [0x3ff20c34] */ #  66f: b2668d
            memw                                               #  672: c02000
            s32i         a10, a6, 0x240 /* 0xffffffff -> [0x3ff20c40] */ #  675: a26690
            memw                                               #  678: c02000
            s32i         a7, a6, 0x244 /* 0x0000ffff -> [0x3ff20c44] */ #  67b: 726691
            memw                                               #  67e: c02000
            l32i         a9, a6, 0x244 /* [0x3ff20c44] */      #  681: 922691
            or           a9, a9, a8                            #  684: 809920
            memw                                               #  687: c02000
            s32i         a9, a6, 0x244 /* a9 -> [0x3ff20c44] */ #  68a: 926691
            ret.n                                              #  68d: 0df0
.Lbr176:    memw                                               #  68f: c02000
            l32i         a4, a6, 0x23c /* [0x3ff20c3c] */      #  692: 42268f
            and          a4, a4, a5                            #  695: 504410
            memw                                               #  698: c02000
            s32i         a4, a6, 0x23c /* a4 -> [0x3ff20c3c] */ #  69b: 42668f
            l8ui         a4, a3, 3 /* [arg1+0x3] */            #  69e: 420303
            l8ui         a2, a3, 1 /* [arg1+0x1] */            #  6a1: 220301
            l8ui         a11, a3, 0 /* [arg1] */               #  6a4: b20300
            slli         a2, a2, 8                             #  6a7: 802211
            or           a11, a11, a2                          #  6aa: 20bb20
            l8ui         a2, a3, 2 /* [arg1+0x2] */            #  6ad: 220302
            slli         a4, a4, 24                            #  6b0: 804401
            slli         a2, a2, 16                            #  6b3: 002211
            or           a2, a2, a4                            #  6b6: 402220
            or           a11, a11, a2                          #  6b9: 20bb20
            memw                                               #  6bc: c02000
            s32i         a11, a6, 0x228 /* a11 -> [0x3ff20c28] */ #  6bf: b2668a
            l8ui         a9, a3, 5 /* [arg1+0x5] */            #  6c2: 920305
            l8ui         a4, a3, 4 /* [arg1+0x4] */            #  6c5: 420304
            slli         a9, a9, 8                             #  6c8: 809911
            or           a4, a4, a9                            #  6cb: 904420
            memw                                               #  6ce: c02000
            s32i         a4, a6, 0x22c /* a4 -> [0x3ff20c2c] */ #  6d1: 42668b
            memw                                               #  6d4: c02000
            s32i         a10, a6, 0x238 /* 0xffffffff -> [0x3ff20c38] */ #  6d7: a2668e
            memw                                               #  6da: c02000
            s32i         a7, a6, 0x23c /* 0x0000ffff -> [0x3ff20c3c] */ #  6dd: 72668f
            memw                                               #  6e0: c02000
            l32i         a2, a6, 0x23c /* [0x3ff20c3c] */      #  6e3: 22268f
            or           a2, a2, a8                            #  6e6: 802220
            memw                                               #  6e9: c02000
            s32i         a2, a6, 0x23c /* a2 -> [0x3ff20c3c] */ #  6ec: 22668f
            ret.n                                              #  6ef: 0df0

# NOTE: The following is apparently unreferenced code/data
            .balign      4
.Llit107:   .word        0x3ff20a00                            #  6f4: 000af23f
.Llit108:   .word        0xfffeffff                            #  6f8: fffffeff

# Function @ .irom0.text+0x6fc
.literal_position
sdk_wDev_ClearBssid:
            movi         a4, .Llit108 /* 0xfffeffff */         #  6fc: 41ffff
            movi         a5, .Llit107 /* 0x3ff20a00 */         #  6ff: 51fdff
            beqz.n       a2, .Lbr177                           #  702: 8cf2
            memw                                               #  704: c02000
            l32i         a3, a5, 0x244 /* [0x3ff20c44] */      #  707: 322591
            and          a3, a3, a4                            #  70a: 403310
            memw                                               #  70d: c02000
            s32i         a3, a5, 0x244 /* a3 -> [0x3ff20c44] */ #  710: 326591
            ret.n         /* arg0 */                           #  713: 0df0
.Lbr177:    memw                                               #  715: c02000
            l32i         a2, a5, 0x23c /* [0x3ff20c3c] */      #  718: 22258f
            and          a2, a2, a4                            #  71b: 402210
            memw                                               #  71e: c02000
            s32i         a2, a5, 0x23c /* a2 -> [0x3ff20c3c] */ #  721: 22658f
            ret.n                                              #  724: 0df0

# NOTE: The following is apparently unreferenced code/data
            .balign      4
.Llit109:   .word        0x3ff21200                            #  728: 0012f23f
.Llit110:   .word        0x3ff20600                            #  72c: 0006f23f

.Lrel163:   .word        .data                                 #  730: 00000000

# NOTE: The following is apparently unreferenced code/data
.Llit111:   .word        0x3ff21408                            #  734: 0814f23f

.Lrel164:   .word        memcpy                                #  738: 00000000

# Function @ .irom0.text+0x73c
# Local variables/stack:
#     (local0):  word      @ -0x10
#     (local1):  word      @ -0xc
#     (local2):  word[2]   @ -0x8
.literal_position
sdk_wDev_Insert_KeyEntry:
            addi         a1, a1, -16 /* (local0) */            #  73c: 12c1f0
            s32i.n       a0, a1, 0 /* a0 -> [(local0)] */      #  73f: 0901
            l8ui         a11, a5, 5 /* [arg3+0x5] */           #  741: b20505
            l8ui         a10, a5, 4 /* [arg3+0x4] */           #  744: a20504
            slli         a11, a11, 8                           #  747: 80bb11
            add.n        a10, a10, a11                         #  74a: baaa
            bnei         a2, 5, .Lbr178                        #  74c: 665206
            movi.n       a9, 1 /* 0x00000001 */                #  74f: 0c19
            movi.n       a2, 1 /* 0x00000001 */                #  751: 0c12
            j            .Lbr179                               #  753: 460000
.Lbr178:    movi.n       a9, 0 /* 0x00000000 */                #  756: 0c09
.Lbr179:    s32i.n       a7, a1, 8 /* arg5 -> [(local2)] */    #  758: 7921
            movi         a8, .Llit109 /* .Llit109 */           #  75a: 81f3ff
            l8ui         a7, a5, 1 /* [arg3+0x1] */            #  75d: 720501
            l8ui         a11, a5, 0 /* [arg3] */               #  760: b20500
            slli         a7, a7, 8                             #  763: 807711
            add.n        a11, a11, a7                          #  766: 7abb
            l8ui         a7, a5, 3 /* [arg3+0x3] */            #  768: 720503
            l8ui         a5, a5, 2 /* [arg3+0x2] */            #  76b: 520502
            slli         a7, a7, 24                            #  76e: 807701
            slli         a5, a5, 16                            #  771: 005511
            add.n        a5, a5, a7                            #  774: 7a55
            add.n        a11, a11, a5                          #  776: 5abb
            addx4        a5, a6, a6                            #  778: 6056a0
            slli         a5, a5, 3                             #  77b: d05511
            add.n        a8, a5, a8                            #  77e: 8a85
            beqi         a2, 1, .Lbr180                        #  780: 261209
            movi.n       a0, 6 /* 0x00000006 */                #  783: 0c60
            blti         a6, 6, .Lbr181                        #  785: a66606
            movi.n       a0, 2 /* 0x00000002 */                #  788: 0c20
            j            .Lbr181                               #  78a: 460000
.Lbr180:    movi.n       a0, 7 /* 0x00000007 */                #  78d: 0c70
.Lbr181:    memw                                               #  78f: c02000
            slli         a7, a4, 30                            #  792: 207401
            extui        a0, a0, 0, 3                          #  795: 000024
            s32i         a11, a8, 0x200                        #  798: b26880
            extui        a9, a9, 0, 2                          #  79b: 909014
            extui        a11, a10, 0, 16                       #  79e: a0b0f4
            slli         a9, a9, 16                            #  7a1: 009911
            add.n        a9, a9, a11                           #  7a4: ba99
            slli         a0, a0, 21                            #  7a6: b00001
            extui        a11, a2, 0, 3                         #  7a9: 20b024
            slli         a11, a11, 18                          #  7ac: e0bb01
            add.n        a11, a11, a0                          #  7af: 0abb
            add.n        a9, a9, a11                           #  7b1: ba99
            extui        a11, a3, 0, 1                         #  7b3: 30b004
            slli         a11, a11, 24                          #  7b6: 80bb01
            add.n        a7, a7, a11                           #  7b9: ba77
            add.n        a7, a7, a9                            #  7bb: 9a77
            memw                                               #  7bd: c02000
            s32i         a7, a8, 0x204                         #  7c0: 726881
            ssl          a6                                    #  7c3: 001640
            movi.n       a0, 1 /* 0x00000001 */                #  7c6: 0c10
            sll          a0, a0                                #  7c8: 0000a1
            memw                                               #  7cb: c02000
            movi         a8, .Llit110 /* .Llit110 */           #  7ce: 81d7ff
            l32i         a7, a8, 0x20c                         #  7d1: 722883
            or           a7, a7, a0                            #  7d4: 007720
            memw                                               #  7d7: c02000
            s32i         a7, a8, 0x20c                         #  7da: 726883
            l32i.n       a9, a1, 4 /* [(local1)] */            #  7dd: 9811
            l32i.n       a7, a1, 8 /* [(local2)] */            #  7df: 7821
            bgeui        a3, 2, .Lbr182                        #  7e1: f62311
            blti         a6, 2, .Lbr182                        #  7e4: a6260e
            movi         a9, .Lrel163 /* .Lrel163 */           #  7e7: 91d2ff
            l32i.n       a9, a9, 0                             #  7ea: 9809
            addx4        a9, a3, a9                            #  7ec: 9093a0
            l32i.n       a8, a9, 56                            #  7ef: 88e9
            or           a8, a0, a8                            #  7f1: 808020
            s32i.n       a8, a9, 56                            #  7f4: 89e9
.Lbr182:    mov.n        a3, a7 /* [(local2)] */               #  7f6: 3d07
            movi         a2, .Llit111 /* .Llit111 */           #  7f8: 21cfff
            l32i.n       a4, a1, 16 /* [(local3)] */           #  7fb: 4841
            add.n        a2, a5, a2                            #  7fd: 2a25
            movi         a0, .Lrel164 /* memcpy */             #  7ff: 01ceff
            callx0       a0 /* memcpy */                       #  802: c00000
            l32i.n       a0, a1, 0 /* [(local0)] */            #  805: 0801
            addi         a1, a1, 16 /* (local3) */             #  807: 12c110
            ret.n                                              #  80a: 0df0

# NOTE: The following is apparently unreferenced code/data
.Llit112:   .word        0x3ff20600                            #  80c: 0006f23f
.Llit113:   .word        0x3ff21200                            #  810: 0012f23f
.Llit114:   .word        0xff1fffff                            #  814: ffff1fff

# Function @ .irom0.text+0x818
.literal_position
sdk_wDev_remove_KeyEntry:
            movi         a7, .Llit112 /* 0x3ff20600 */         #  818: 71fdff
            ssl          a2                                    #  81b: 001240
            movi.n       a8, 1 /* 0x00000001 */                #  81e: 0c18
            movi.n       a9, -1 /* 0xffffffff */               #  820: 7cf9
            sll          a8, a8                                #  822: 0088a1
            xor          a8, a8, a9                            #  825: 908830
            memw                                               #  828: c02000
            l32i         a6, a7, 0x20c /* [0x3ff2080c] */      #  82b: 622783
            and          a6, a6, a8                            #  82e: 806610
            memw                                               #  831: c02000
            s32i         a6, a7, 0x20c /* a6 -> [0x3ff2080c] */ #  834: 626783
            movi         a5, .Llit113 /* 0x3ff21200 */         #  837: 51f6ff
            addx4        a4, a2, a2                            #  83a: 2042a0
            addx8        a4, a4, a5                            #  83d: 5044b0
            movi         a5, .Llit114 /* 0xff1fffff */         #  840: 51f5ff
            memw                                               #  843: c02000
            l32i         a3, a4, 0x204                         #  846: 322481
            and          a3, a3, a5                            #  849: 503310
            memw                                               #  84c: c02000
            s32i         a3, a4, 0x204                         #  84f: 326481
            ret.n                                              #  852: 0df0

# NOTE: The following is apparently unreferenced code/data
.Llit115:   .word        0x00030303                            #  854: 03030300
.Llit116:   .word        0x3ff20600                            #  858: 0006f23f
.Llit117:   .word        0x10000000                            #  85c: 00000010

# Function @ .irom0.text+0x860
.literal_position
sdk_wDev_Crypto_Conf:
            movi         a6, .Llit115 /* 0x00030303 */         #  860: 61fdff
            movi         a7, .Llit117 /* 0x10000000 */         #  863: 71feff
            movi         a5, .Llit116 /* 0x3ff20600 */         #  866: 51fcff
            bnez.n       a2, .Lbr184                           #  869: dcb2
            memw                                               #  86b: c02000
            s32i         a6, a5, 0x200 /* 0x00030303 -> [0x3ff20800] */ #  86e: 626580
            beqi         a3, 1, .Lbr183                        #  871: 261302
            bnei         a3, 5, .Lbr186                        #  874: 66532b
.Lbr183:    memw                                               #  877: c02000
            l32i         a2, a5, 0x200 /* [0x3ff20800] */      #  87a: 222580
            or           a2, a2, a7                            #  87d: 702220
            memw                                               #  880: c02000
            s32i         a2, a5, 0x200 /* a2 -> [0x3ff20800] */ #  883: 226580
            ret.n                                              #  886: 0df0
.Lbr184:    memw                                               #  888: c02000
            s32i         a6, a5, 0x204 /* 0x00030303 -> [0x3ff20804] */ #  88b: 626581
            beqi         a3, 1, .Lbr185                        #  88e: 261302
            bnei         a3, 5, .Lbr186                        #  891: 66530e
.Lbr185:    memw                                               #  894: c02000
            l32i         a3, a5, 0x204 /* [0x3ff20804] */      #  897: 322581
            or           a3, a3, a7                            #  89a: 703320
            memw                                               #  89d: c02000
            s32i         a3, a5, 0x204 /* a3 -> [0x3ff20804] */ #  8a0: 326581
.Lbr186:    ret.n         /* arg0 */                           #  8a3: 0df0

# NOTE: The following is apparently unreferenced code/data
            .balign      4
.Llit118:   .word        0x00030000                            #  8a8: 00000300

.Lrel165:   .word        sdk_ieee80211_addr_bcast              #  8ac: 00000000

# NOTE: The following is apparently unreferenced code/data
.Llit119:   .word        0x3ff20600                            #  8b0: 0006f23f

.Lrel166:   .word        sdk_ieee80211_addr_bcast              #  8b4: 00000000

# NOTE: The following is apparently unreferenced code/data
.Llit120:   .word        0x3ff20600                            #  8b8: 0006f23f

# Function @ .irom0.text+0x8bc
# Local variables/stack:
#     (local0):  word[4]   @ -0x20
#     (local1):  word[4]   @ -0x10
.literal_position
.Lfunc014:  addi         a1, a1, -32 /* (local0) */            #  8bc: 12c1e0
            s32i.n       a0, a1, 16 /* a0 -> [(local1)] */     #  8bf: 0941
            movi         a2, .Llit118 /* 0x00030000 */         #  8c1: 21f9ff
            movi         a7, .Lrel165 /* sdk_ieee80211_addr_bcast */ #  8c4: 71faff
            movi         a3, .Llit119 /* 0x3ff20600 */         #  8c7: 31faff
            memw                                               #  8ca: c02000
            s32i         a2, a3, 0x200 /* 0x00030000 -> [0x3ff20800] */ #  8cd: 226380
            memw                                               #  8d0: c02000
            movi.n       a4, 0 /* 0x00000000 */                #  8d3: 0c04
            mov.n        a5, a7 /* sdk_ieee80211_addr_bcast */ #  8d5: 5d07
            movi.n       a6, 0 /* 0x00000000 */                #  8d7: 0c06
            s32i         a2, a3, 0x204 /* 0x00030000 -> [0x3ff20804] */ #  8d9: 226381
            movi.n       a0, 6 /* 0x00000006 */                #  8dc: 0c60
            movi.n       a2, 3 /* 0x00000003 */                #  8de: 0c32
            movi.n       a3, 0 /* 0x00000000 */                #  8e0: 0c03
            s32i.n       a0, a1, 0 /* 0x00000006 -> [(local0)] */ #  8e2: 0901
            call0        sdk_wDev_Insert_KeyEntry              #  8e4: 050000
            movi.n       a2, 3 /* 0x00000003 */                #  8e7: 0c32
            movi.n       a3, 1 /* 0x00000001 */                #  8e9: 0c13
            movi.n       a6, 1 /* 0x00000001 */                #  8eb: 0c16
            movi         a7, .Lrel166 /* sdk_ieee80211_addr_bcast */ #  8ed: 71f1ff
            movi.n       a4, 6 /* 0x00000006 */                #  8f0: 0c64
            s32i.n       a4, a1, 0 /* 0x00000006 -> [(local0)] */ #  8f2: 4901
            mov.n        a5, a7 /* sdk_ieee80211_addr_bcast */ #  8f4: 5d07
            movi.n       a4, 0 /* 0x00000000 */                #  8f6: 0c04
            call0        sdk_wDev_Insert_KeyEntry              #  8f8: 050000
            movi.n       a5, 0 /* 0x00000000 */                #  8fb: 0c05
            memw                                               #  8fd: c02000
            movi         a6, .Llit120 /* 0x3ff20600 */         #  900: 61eeff
            l32i.n       a0, a1, 16 /* [(local1)] */           #  903: 0841
            addi         a1, a1, 32 /* (top of frame) */       #  905: 12c120
            s32i         a5, a6, 0x208 /* 0x00000000 -> [0x3ff20808] */ #  908: 526682
            ret.n                                              #  90b: 0df0

            .balign      4
.Lrel167:   .word        .data                                 #  910: 00000000

# NOTE: The following is apparently unreferenced code/data
.Llit121:   .word        0x3ff20600                            #  914: 0006f23f
.Llit122:   .word        0x00030000                            #  918: 00000300

# Function @ .irom0.text+0x91c
.literal_position
sdk_wDev_Crypto_Disable:
            movi         a6, .Lrel167 /* .Lrel143 */           #  91c: 61fdff
            movi         a4, .Llit121 /* 0x3ff20600 */         #  91f: 41fdff
            l32i.n       a6, a6, 0 /* [.Lrel143] */            #  922: 6806
            movi         a5, .Llit122 /* 0x00030000 */         #  924: 51fdff
            addx4        a6, a2, a6                            #  927: 6062a0
            l32i.n       a6, a6, 56                            #  92a: 68e6
            bnez.n       a2, .Lbr187                           #  92c: cc72
            memw                                               #  92e: c02000
            s32i         a5, a4, 0x200 /* 0x00030000 -> [0x3ff20800] */ #  931: 526480
            j            .Lbr188                               #  934: 460100
.Lbr187:    memw                                               #  937: c02000
            s32i         a5, a4, 0x204 /* 0x00030000 -> [0x3ff20804] */ #  93a: 526481
.Lbr188:    movi.n       a8, -1 /* 0xffffffff */               #  93d: 7cf8
            xor          a8, a6, a8                            #  93f: 808630
            memw                                               #  942: c02000
            l32i         a7, a4, 0x20c /* [0x3ff2080c] */      #  945: 722483
            and          a7, a7, a8                            #  948: 807710
            memw                                               #  94b: c02000
            s32i         a7, a4, 0x20c /* a7 -> [0x3ff2080c] */ #  94e: 726483
            ret.n         /* arg0 */                           #  951: 0df0

# NOTE: The following is apparently unreferenced code/data
            .balign      4
.Llit123:   .word        0x7fffffff                            #  954: ffffff7f
.Llit124:   .word        0x3ff1fe00                            #  958: 00fef13f

# Function @ .irom0.text+0x95c
.literal_position
sdk_wDevDisableRx:
            movi         a4, .Llit123 /* 0x7fffffff */         #  95c: 41feff
            movi         a3, .Llit124 /* 0x3ff1fe00 */         #  95f: 31feff
            memw                                               #  962: c02000
            l32i         a2, a3, 0x204 /* [0x3ff20004] */      #  965: 222381
            and          a2, a2, a4                            #  968: 402210
            memw                                               #  96b: c02000
            s32i         a2, a3, 0x204 /* a2 -> [0x3ff20004] */ #  96e: 226381
            ret.n                                              #  971: 0df0

# NOTE: The following is apparently unreferenced code/data
            .balign      4
.Llit125:   .word        0x80000000                            #  974: 00000080
.Llit126:   .word        0x3ff1fe00                            #  978: 00fef13f

# Function @ .irom0.text+0x97c
.literal_position
sdk_wDevEnableRx:
            movi         a4, .Llit125 /* 0x80000000 */         #  97c: 41feff
            movi         a3, .Llit126 /* 0x3ff1fe00 */         #  97f: 31feff
            memw                                               #  982: c02000
            l32i         a2, a3, 0x204 /* [0x3ff20004] */      #  985: 222381
            or           a2, a2, a4                            #  988: 402220
            memw                                               #  98b: c02000
            s32i         a2, a3, 0x204 /* a2 -> [0x3ff20004] */ #  98e: 226381
            ret.n                                              #  991: 0df0

# NOTE: The following is apparently unreferenced code/data
            .balign      4
.Llit127:   .word        0x60009a00                            #  994: 009a0060
.Llit128:   .word        0x03000000                            #  998: 00000003
.Llit129:   .word        0x00010000                            #  99c: 00000100

.Lrel168:   .word        .data                                 #  9a0: 00000000

# NOTE: The following is apparently unreferenced code/data
.Llit130:   .word        0x3ff20600                            #  9a4: 0006f23f
.Llit131:   .word        0xfffeffff                            #  9a8: fffffeff
.Llit132:   .word        0x00040000                            #  9ac: 00000400
.Llit133:   .word        0x3ff20a00                            #  9b0: 000af23f
.Llit134:   .word        0xdbffffff                            #  9b4: ffffffdb
.Llit135:   .word        0x00003a98                            #  9b8: 983a0000
.Llit136:   .word        0x3ff20a00                            #  9bc: 000af23f

.Lrel169:   .word        sdk_ets_delay_us                      #  9c0: 00000000

# Function @ .irom0.text+0x9c4
# Local variables/stack:
#     (local0):  word[4]   @ -0x10
.literal_position
sdk_wdev_go_sniffer:
            movi.n       a8, 0 /* 0x00000000 */                #  9c4: 0c08
            movi         a2, .Llit127 /* 0x60009a00 */         #  9c6: 21f3ff
            movi         a3, .Llit128 /* 0x03000000 */         #  9c9: 31f3ff
            movi         a7, .Llit129 /* 0x00010000 */         #  9cc: 71f4ff
            movi         a10, .Llit130 /* 0x3ff20600 */        #  9cf: a1f5ff
            movi.n       a4, 1 /* 0x00000001 */                #  9d2: 0c14
            movi         a5, .Lrel168 /* .Lrel143 */           #  9d4: 51f3ff
            addi         a1, a1, -16 /* (local0) */            #  9d7: 12c1f0
            l32i.n       a5, a5, 0 /* [.Lrel143] */            #  9da: 5805
            s32i.n       a0, a1, 0 /* a0 -> [(local0)] */      #  9dc: 0901
            s8i          a4, a5, 5 /* 0x01 -> [[.Lrel143]+0x5] */ #  9de: 424505
            movi         a11, .Llit131 /* 0xfffeffff */        #  9e1: b1f1ff
            movi         a0, .Llit132 /* 0x00040000 */         #  9e4: 01f2ff
            movi         a5, .Llit133 /* 0x3ff20a00 */         #  9e7: 51f2ff
            memw                                               #  9ea: c02000
            l32i         a9, a5, 0x288 /* [0x3ff20c88] */      #  9ed: 9225a2
            or           a9, a9, a0                            #  9f0: 009920
            memw                                               #  9f3: c02000
            s32i         a9, a5, 0x288 /* a9 -> [0x3ff20c88] */ #  9f6: 9265a2
            memw                                               #  9f9: c02000
            l32i         a6, a10, 0x200 /* [0x3ff20800] */     #  9fc: 622a80
            or           a6, a6, a3                            #  9ff: 306620
            memw                                               #  a02: c02000
            s32i         a6, a10, 0x200 /* a6 -> [0x3ff20800] */ #  a05: 626a80
            memw                                               #  a08: c02000
            l32i         a4, a10, 0x200 /* [0x3ff20800] */     #  a0b: 422a80
            and          a4, a4, a11                           #  a0e: b04410
            memw                                               #  a11: c02000
            s32i         a4, a10, 0x200 /* a4 -> [0x3ff20800] */ #  a14: 426a80
            memw                                               #  a17: c02000
            l32i         a0, a10, 0x204 /* [0x3ff20804] */     #  a1a: 022a81
            or           a0, a0, a3                            #  a1d: 300020
            memw                                               #  a20: c02000
            s32i         a0, a10, 0x204 /* a0 -> [0x3ff20804] */ #  a23: 026a81
            memw                                               #  a26: c02000
            l32i         a9, a10, 0x204 /* [0x3ff20804] */     #  a29: 922a81
            and          a9, a9, a11                           #  a2c: b09910
            memw                                               #  a2f: c02000
            s32i         a9, a10, 0x204 /* a9 -> [0x3ff20804] */ #  a32: 926a81
            memw                                               #  a35: c02000
            s32i         a8, a5, 0x258 /* 0x00000000 -> [0x3ff20c58] */ #  a38: 826596
            memw                                               #  a3b: c02000
            s32i         a7, a5, 0x25c /* 0x00010000 -> [0x3ff20c5c] */ #  a3e: 726597
            memw                                               #  a41: c02000
            s32i         a8, a5, 0x238 /* 0x00000000 -> [0x3ff20c38] */ #  a44: 82658e
            memw                                               #  a47: c02000
            s32i         a7, a5, 0x23c /* 0x00010000 -> [0x3ff20c3c] */ #  a4a: 72658f
            movi.n       a6, 12 /* 0x0000000c */               #  a4d: 0cc6
            memw                                               #  a4f: c02000
            l32i         a4, a5, 0x218 /* [0x3ff20c18] */      #  a52: 422586
            or           a4, a4, a6                            #  a55: 604420
            memw                                               #  a58: c02000
            s32i         a4, a5, 0x218 /* a4 -> [0x3ff20c18] */ #  a5b: 426586
            movi         a3, .Llit134 /* 0xdbffffff */         #  a5e: 31d5ff
            memw                                               #  a61: c02000
            l32i         a0, a2, 0x344 /* [0x60009d44] */      #  a64: 0222d1
            and          a0, a0, a3                            #  a67: 300010
            memw                                               #  a6a: c02000
            s32i         a0, a2, 0x344 /* a0 -> [0x60009d44] */ #  a6d: 0262d1
            movi         a2, .Llit135 /* 0x00003a98 */         #  a70: 21d2ff
            movi         a0, .Lrel169 /* sdk_ets_delay_us */   #  a73: 01d3ff
            callx0       a0 /* sdk_ets_delay_us */             #  a76: c00000
            movi.n       a8, -2 /* 0xfffffffe */               #  a79: 7ce8
            memw                                               #  a7b: c02000
            movi         a7, .Llit136 /* 0x3ff20a00 */         #  a7e: 71cfff
            l32i         a6, a7, 0x294 /* [0x3ff20c94] */      #  a81: 6227a5
            and          a6, a6, a8                            #  a84: 806610
            memw                                               #  a87: c02000
            s32i         a6, a7, 0x294 /* a6 -> [0x3ff20c94] */ #  a8a: 6267a5
            l32i.n       a0, a1, 0 /* [(local0)] */            #  a8d: 0801
            addi         a1, a1, 16 /* (top of frame) */       #  a8f: 12c110
            ret.n                                              #  a92: 0df0

.Lrel170:   .word        .data                                 #  a94: 00000000

# NOTE: The following is apparently unreferenced code/data
.Llit137:   .word        0xfcffffff                            #  a98: fffffffc
.Llit138:   .word        0x3ff20600                            #  a9c: 0006f23f
.Llit139:   .word        0x00010000                            #  aa0: 00000100
.Llit140:   .word        0x60009a00                            #  aa4: 009a0060
.Llit141:   .word        0x3ff20a00                            #  aa8: 000af23f
.Llit142:   .word        0x24000000                            #  aac: 00000024
.Llit143:   .word        0x0001ffff                            #  ab0: ffff0100
.Llit144:   .word        0x0000ffff                            #  ab4: ffff0000
.Llit145:   .word        0xfffbffff                            #  ab8: fffffbff

# Function @ .irom0.text+0xabc
.literal_position
sdk_wdev_exit_sniffer:
            movi         a3, .Lrel170 /* .Lrel143 */           #  abc: 31f6ff
            movi.n       a8, -1 /* 0xffffffff */               #  abf: 7cf8
            l32i.n       a3, a3, 0 /* [.Lrel143] */            #  ac1: 3803
            movi.n       a7, 1 /* 0x00000001 */                #  ac3: 0c17
            l8ui         a2, a3, 5 /* [[.Lrel143]+0x5] */      #  ac5: 220305
            movi         a11, .Llit140 /* 0x60009a00 */        #  ac8: b1f7ff
            beqz         a2, .Lbr189                           #  acb: 16e20a
            movi         a10, .Llit139 /* 0x00010000 */        #  ace: a1f4ff
            movi         a2, .Llit137 /* 0xfcffffff */         #  ad1: 21f1ff
            movi         a9, .Llit138 /* 0x3ff20600 */         #  ad4: 91f2ff
            movi         a6, .Llit141 /* 0x3ff20a00 */         #  ad7: 61f4ff
            memw                                               #  ada: c02000
            l32i         a5, a6, 0x294 /* [0x3ff20c94] */      #  add: 5226a5
            or           a5, a5, a7                            #  ae0: 705520
            memw                                               #  ae3: c02000
            s32i         a5, a6, 0x294 /* a5 -> [0x3ff20c94] */ #  ae6: 5266a5
            movi         a4, .Llit142 /* 0x24000000 */         #  ae9: 41f0ff
            memw                                               #  aec: c02000
            l32i         a7, a11, 0x344 /* [0x60009d44] */     #  aef: 722bd1
            or           a7, a7, a4                            #  af2: 407720
            memw                                               #  af5: c02000
            s32i         a7, a11, 0x344 /* a7 -> [0x60009d44] */ #  af8: 726bd1
            movi.n       a5, -13 /* 0xfffffff3 */              #  afb: 7c35
            memw                                               #  afd: c02000
            l32i         a4, a6, 0x218 /* [0x3ff20c18] */      #  b00: 422686
            and          a4, a4, a5                            #  b03: 504410
            memw                                               #  b06: c02000
            s32i         a4, a6, 0x218 /* a4 -> [0x3ff20c18] */ #  b09: 426686
            memw                                               #  b0c: c02000
            s32i         a8, a6, 0x258 /* 0xffffffff -> [0x3ff20c58] */ #  b0f: 826696
            movi         a11, .Llit143 /* 0x0001ffff */        #  b12: b1e7ff
            memw                                               #  b15: c02000
            s32i         a11, a6, 0x25c /* 0x0001ffff -> [0x3ff20c5c] */ #  b18: b26697
            memw                                               #  b1b: c02000
            s32i         a8, a6, 0x238 /* 0xffffffff -> [0x3ff20c38] */ #  b1e: 82668e
            movi         a7, .Llit144 /* 0x0000ffff */         #  b21: 71e4ff
            memw                                               #  b24: c02000
            s32i         a7, a6, 0x23c /* 0x0000ffff -> [0x3ff20c3c] */ #  b27: 72668f
            memw                                               #  b2a: c02000
            l32i         a5, a9, 0x200 /* [0x3ff20800] */      #  b2d: 522980
            and          a5, a5, a2                            #  b30: 205510
            memw                                               #  b33: c02000
            s32i         a5, a9, 0x200 /* a5 -> [0x3ff20800] */ #  b36: 526980
            memw                                               #  b39: c02000
            l32i         a4, a9, 0x200 /* [0x3ff20800] */      #  b3c: 422980
            or           a4, a4, a10                           #  b3f: a04420
            memw                                               #  b42: c02000
            s32i         a4, a9, 0x200 /* a4 -> [0x3ff20800] */ #  b45: 426980
            memw                                               #  b48: c02000
            l32i         a11, a9, 0x204 /* [0x3ff20804] */     #  b4b: b22981
            and          a11, a11, a2                          #  b4e: 20bb10
            memw                                               #  b51: c02000
            s32i         a11, a9, 0x204 /* a11 -> [0x3ff20804] */ #  b54: b26981
            memw                                               #  b57: c02000
            l32i         a8, a9, 0x204 /* [0x3ff20804] */      #  b5a: 822981
            or           a8, a8, a10                           #  b5d: a08820
            memw                                               #  b60: c02000
            s32i         a8, a9, 0x204 /* a8 -> [0x3ff20804] */ #  b63: 826981
            movi         a7, .Llit145 /* 0xfffbffff */         #  b66: 71d4ff
            memw                                               #  b69: c02000
            l32i         a5, a6, 0x288 /* [0x3ff20c88] */      #  b6c: 5226a2
            and          a5, a5, a7                            #  b6f: 705510
            memw                                               #  b72: c02000
            s32i         a5, a6, 0x288 /* a5 -> [0x3ff20c88] */ #  b75: 5266a2
            movi.n       a4, 0 /* 0x00000000 */                #  b78: 0c04
            s8i          a4, a3, 5 /* 0x00 -> [[.Lrel143]+0x5] */ #  b7a: 424305
.Lbr189:    ret.n                                              #  b7d: 0df0

            .section     .rodata.str1.4, "MSa", @progbits, 1

.Lstr001:   .asciz       "%s %u\n"                             #    0: 25732025
                                                               #    4: 750a00
            .balign      4
.Lstr002:   .asciz       "wdev.c"                              #    8: 77646576
                                                               #    c: 2e6300
