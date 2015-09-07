
            .section     .irom0.literal, "ax", @progbits

            .section     .text, "ax", @progbits

            .section     .data, "aw", @progbits

            .section     .bss, "aw", @nobits

            .section     .irom0.text, "ax", @progbits

# NOTE: The following is apparently unreferenced code/data
.Llit001:   .word        0x00015180                            #    0: 80510100
.Llit002:   .word        0x0000ffff                            #    4: ffff0000

# Function @ .irom0.text+0x8
.literal_position
sdk_hostapd_config_defaults_bss:
            movi         a4, .Llit002 /* 0x0000ffff */         #    8: 41ffff
            movi         a3, 300 /* 0x0000012c */              #    b: 32a12c
            movi.n       a5, 4 /* 0x00000004 */                #    e: 0c45
            movi.n       a6, 0 /* 0x00000000 */                #   10: 0c06
            movi         a7, .Llit001 /* 0x00015180 */         #   12: 71fbff
            movi         a8, 600 /* 0x00000258 */              #   15: 82a258
            movi.n       a9, 1 /* 0x00000001 */                #   18: 0c19
            movi.n       a10, 3 /* 0x00000003 */               #   1a: 0c3a
            movi.n       a11, 2 /* 0x00000002 */               #   1c: 0c2b
            s32i         a11, a2, 116 /* 0x00000002 -> [arg0+0x74] */ #   1e: b2621d
            s32i         a11, a2, 132 /* 0x00000002 -> [arg0+0x84] */ #   21: b26221
            s32i         a11, a2, 140 /* 0x00000002 -> [arg0+0x8c] */ #   24: b26223
            s32i         a11, a2, 144 /* 0x00000002 -> [arg0+0x90] */ #   27: b26224
            s32i.n       a11, a2, 4 /* 0x00000002 -> [arg0+0x4] */ #   2a: b912
            s32i.n       a11, a2, 12 /* 0x00000002 -> [arg0+0xc] */ #   2c: b932
            s32i         a10, a2, 124 /* 0x00000003 -> [arg0+0x7c] */ #   2e: a2621f
            s32i         a9, a2, 112 /* 0x00000001 -> [arg0+0x70] */ #   31: 92621c
            s32i         a8, a2, 148 /* 0x00000258 -> [arg0+0x94] */ #   34: 826225
            s32i         a7, a2, 156 /* 0x00015180 -> [arg0+0x9c] */ #   37: 726227
            s32i         a6, a2, 164 /* 0x00000000 -> [arg0+0xa4] */ #   3a: 626229
            s32i.n       a5, a2, 0 /* 0x00000004 -> [arg0] */  #   3d: 5902
            s32i         a3, a2, 108 /* 0x0000012c -> [arg0+0x6c] */ #   3f: 32621b
            s32i         a3, a2, 180 /* 0x0000012c -> [arg0+0xb4] */ #   42: 32622d
            s16i         a4, a2, 202 /* 0xffff -> [arg0+0xca] */ #   45: 425265
            movi.n       a3, -1 /* 0xffffffff */               #   48: 7cf3
            s32i         a3, a2, 188 /* 0xffffffff -> [arg0+0xbc] */ #   4a: 32622f
            ret.n         /* arg0 */                           #   4d: 0df0

            .balign      4
.Lrel001:   .word        zalloc                                #   50: 00000000
.Lrel002:   .word        zalloc                                #   54: 00000000
.Lrel003:   .word        free                                  #   58: 00000000
.Lrel004:   .word        free                                  #   5c: 00000000

# Function @ .irom0.text+0x60
# Local variables/stack:
#     (local0):  word      @ -0x10
#     (local1):  word      @ -0xc
#     (local2):  word[2]   @ -0x8
.literal_position
sdk_hostapd_config_defaults:
            movi         a2, 100 /* 0x00000064 */              #   60: 22a064
            addi         a1, a1, -16 /* (local0) */            #   63: 12c1f0
            s32i.n       a12, a1, 4 /* a12 -> [(local1)] */    #   66: c911
            s32i.n       a13, a1, 8 /* a13 -> [(local2)] */    #   68: d921
            s32i.n       a0, a1, 0 /* a0 -> [(local0)] */      #   6a: 0901
            movi         a0, .Lrel001 /* zalloc */             #   6c: 01f9ff
            callx0       a0 /* zalloc */                       #   6f: c00000
            mov.n        a13, a2                               #   72: dd02
            movi         a2, 204 /* 0x000000cc */              #   74: 22a0cc
            movi         a0, .Lrel002 /* zalloc */             #   77: 01f7ff
            callx0       a0 /* zalloc */                       #   7a: c00000
            mov.n        a12, a2                               #   7d: cd02
            beqz.n       a13, .Lbr002                          #   7f: bc3d
            beqz.n       a2, .Lbr002                           #   81: bc12
            call0        sdk_hostapd_config_defaults_bss       #   83: 050000
            s32i.n       a12, a13, 0                           #   86: c90d
            movi.n       a0, 60 /* 0x0000003c */               #   88: 3cc0
            movi         a2, 255 /* 0x000000ff */              #   8a: 22a0ff
            movi.n       a3, 12 /* 0x0000000c */               #   8d: 0cc3
            movi         a4, 100 /* 0x00000064 */              #   8f: 42a064
            movi.n       a5, 1 /* 0x00000001 */                #   92: 0c15
            movi.n       a6, -1 /* 0xffffffff */               #   94: 7cf6
            s32i.n       a6, a13, 16                           #   96: 694d
            s32i.n       a6, a13, 20                           #   98: 695d
            s32i.n       a5, a13, 8                            #   9a: 592d
            s8i          a5, a13, 24                           #   9c: 524d18
            s16i         a4, a13, 12                           #   9f: 425d06
            s16i         a3, a13, 68                           #   a2: 325d22
            s32i.n       a2, a13, 48                           #   a5: 29cd
            s32i.n       a0, a13, 52                           #   a7: 09dd
.Lbr001:    l32i.n       a0, a1, 0 /* [(local0)] */            #   a9: 0801
            mov.n        a2, a13                               #   ab: 2d0d
            l32i.n       a12, a1, 4 /* [(local1)] */           #   ad: c811
            l32i.n       a13, a1, 8 /* [(local2)] */           #   af: d821
            addi         a1, a1, 16 /* (top of frame) */       #   b1: 12c110
            ret.n                                              #   b4: 0df0
.Lbr002:    mov.n        a2, a13                               #   b6: 2d0d
            movi         a0, .Lrel003 /* free */               #   b8: 01e8ff
            callx0       a0 /* free */                         #   bb: c00000
            mov.n        a2, a12                               #   be: 2d0c
            movi         a0, .Lrel004 /* free */               #   c0: 01e7ff
            callx0       a0 /* free */                         #   c3: c00000
            movi.n       a13, 0 /* 0x00000000 */               #   c6: 0c0d
            j            .Lbr001                               #   c8: 46f7ff

            .balign      4
.Lrel005:   .word        memcmp                                #   cc: 00000000

# Function @ .irom0.text+0xd0
# Local variables/stack:
#     (local0):  word[4]   @ -0x10
.literal_position
sdk_hostapd_mac_comp:
            movi.n       a4, 6 /* 0x00000006 */                #   d0: 0c64
            addi         a1, a1, -16 /* (local0) */            #   d2: 12c1f0
            s32i.n       a0, a1, 0 /* a0 -> [(local0)] */      #   d5: 0901
            movi         a0, .Lrel005 /* memcmp */             #   d7: 01fdff
            callx0       a0 /* memcmp */                       #   da: c00000
            l32i.n       a0, a1, 0 /* [(local0)] */            #   dd: 0801
            addi         a1, a1, 16 /* (top of frame) */       #   df: 12c110
            ret.n                                              #   e2: 0df0

.Lrel006:   .word        .rodata                               #   e4: 00000000
.Lrel007:   .word        memcpy                                #   e8: 00000000
.Lrel008:   .word        memcmp                                #   ec: 00000000

# Function @ .irom0.text+0xf0
# Local variables/stack:
#     (local0):  word      @ -0x8
#     (local1):  word      @ -0x4
.literal_position
sdk_hostapd_mac_comp_empty:
            movi         a3, .Lrel006 /* .Ldata001 */          #   f0: 31fdff
            movi.n       a4, 6 /* 0x00000006 */                #   f3: 0c64
            addi         a1, a1, -16 /* (FP)-0x10 */           #   f5: 12c1f0
            s32i.n       a2, a1, 8 /* arg0 -> [(local0)] */    #   f8: 2921
            s32i.n       a0, a1, 12 /* a0 -> [(local1)] */     #   fa: 0931
            mov.n        a2, a1 /* (FP)-0x10 */                #   fc: 2d01
            movi         a0, .Lrel007 /* memcpy */             #   fe: 01faff
            callx0       a0 /* memcpy */                       #  101: c00000
            l32i.n       a2, a1, 8 /* [(local0)] */            #  104: 2821
            mov.n        a3, a1 /* (FP)-0x10 */                #  106: 3d01
            movi.n       a4, 6 /* 0x00000006 */                #  108: 0c64
            movi         a0, .Lrel008 /* memcmp */             #  10a: 01f8ff
            callx0       a0 /* memcmp */                       #  10d: c00000
            l32i.n       a0, a1, 12 /* [(local1)] */           #  110: 0831
            addi         a1, a1, 16 /* (top of frame) */       #  112: 12c110
            ret.n                                              #  115: 0df0

            .balign      4
.Lrel009:   .word        sdk_g_ic+0x2ed                        #  118: 00000000
.Lrel010:   .word        zalloc                                #  11c: 00000000
.Lrel011:   .word        memcpy                                #  120: 00000000

# Function @ .irom0.text+0x124
# Local variables/stack:
#     (local0):  word      @ -0x10
#     (local1):  word[3]   @ -0xc
.literal_position
.Lfunc001:  addi         a1, a1, -16 /* (local0) */            #  124: 12c1f0
            s32i.n       a2, a1, 0 /* arg0 -> [(local0)] */    #  127: 2901
            s32i.n       a0, a1, 4 /* a0 -> [(local1)] */      #  129: 0911
            movi.n       a2, 48 /* 0x00000030 */               #  12b: 3c02
            movi         a0, .Lrel010 /* zalloc */             #  12d: 01fbff
            callx0       a0 /* zalloc */                       #  130: c00000
            l32i.n       a0, a1, 0 /* [(local0)] */            #  133: 0801
            s32i.n       a2, a0, 40 /* a2 -> [[(local0)]+0x28] */ #  135: 29a0
            bnez.n       a2, .Lbr003                           #  137: cc32
            movi.n       a2, -1 /* 0xffffffff */               #  139: 7cf2
            j            .Lbr004                               #  13b: 860300
.Lbr003:    addi.n       a2, a2, 8                             #  13e: 8b22
            movi         a3, .Lrel009 /* sdk_g_ic+0x2ed */     #  140: 31f6ff
            movi.n       a4, 32 /* 0x00000020 */               #  143: 2c04
            movi         a0, .Lrel011 /* memcpy */             #  145: 01f6ff
            callx0       a0 /* memcpy */                       #  148: c00000
            movi.n       a2, 0 /* 0x00000000 */                #  14b: 0c02
.Lbr004:    l32i.n       a0, a1, 4 /* [(local1)] */            #  14d: 0811
            addi         a1, a1, 16 /* (top of frame) */       #  14f: 12c110
            ret.n                                              #  152: 0df0

# Function @ .irom0.text+0x154
# Local variables/stack:
#     (local0):  word      @ -0x10
#     (local1):  word[3]   @ -0xc
.literal_position
sdk_hostapd_setup_wpa_psk:
            addi         a1, a1, -16 /* (local0) */            #  154: 12c1f0
            s32i.n       a0, a1, 4 /* a0 -> [(local1)] */      #  157: 0911
            l32i.n       a0, a2, 60 /* [arg0+0x3c] */          #  159: 08f2
            beqz.n       a0, .Lbr007                           #  15b: 9ca0
            l32i.n       a0, a2, 56 /* [arg0+0x38] */          #  15d: 08e2
            s32i.n       a2, a1, 0 /* arg0 -> [(local0)] */    #  15f: 2901
            bnez.n       a0, .Lbr006                           #  161: dc00
            addi         a2, a2, 16 /* arg0+0x10 */            #  163: 22c210
            call0        .Lfunc001                             #  166: c5fbff
            bgez         a2, .Lbr005                           #  169: d64200
            movi.n       a2, -1 /* 0xffffffff */               #  16c: 7cf2
            j            .Lbr008                               #  16e: 460200
.Lbr005:    l32i.n       a0, a1, 0 /* [(local0)] */            #  171: 0801
            l32i.n       a0, a0, 56 /* [[(local0)]+0x38] */    #  173: 08e0
.Lbr006:    movi.n       a2, 1 /* 0x00000001 */                #  175: 0c12
            s32i.n       a2, a0, 4                             #  177: 2910
.Lbr007:    movi.n       a2, 0 /* 0x00000000 */                #  179: 0c02
.Lbr008:    l32i.n       a0, a1, 4 /* [(local1)] */            #  17b: 0811
            addi         a1, a1, 16 /* (top of frame) */       #  17d: 12c110
            ret.n                                              #  180: 0df0

            .balign      4
.Lrel012:   .word        memcmp                                #  184: 00000000

# Function @ .irom0.text+0x188
# Local variables/stack:
#     (local0):  word      @ -0x10
#     (local1):  word      @ -0xc
#     (local2):  word      @ -0x8
#     (local3):  word      @ -0x4
.literal_position
sdk_hostapd_wep_key_cmp:
            addi         a1, a1, -16 /* (local0) */            #  188: 12c1f0
            s32i.n       a12, a1, 8 /* a12 -> [(local2)] */    #  18b: c921
            l8ui         a4, a3, 0 /* [arg1] */                #  18d: 420300
            s32i.n       a0, a1, 4 /* a0 -> [(local1)] */      #  190: 0911
            l8ui         a0, a2, 0 /* [arg0] */                #  192: 020200
            s32i.n       a13, a1, 12 /* a13 -> [(local3)] */   #  195: d931
            bne          a0, a4, .Lbr011                       #  197: 479038
            l32i.n       a6, a3, 40 /* [arg1+0x28] */          #  19a: 68a3
            l32i.n       a5, a2, 40 /* [arg0+0x28] */          #  19c: 58a2
            mov.n        a12, a3 /* arg1 */                    #  19e: cd03
            bne          a5, a6, .Lbr011                       #  1a0: 67952f
            mov.n        a13, a2 /* arg0 */                    #  1a3: dd02
            addi         a7, a2, 16 /* arg0+0x10 */            #  1a5: 72c210
            s32i.n       a7, a1, 0 /* arg0+0x10 -> [(local0)] */ #  1a8: 7901
.Lbr009:    l32i.n       a4, a13, 20                           #  1aa: 485d
            l32i.n       a8, a12, 20                           #  1ac: 885c
            bne          a8, a4, .Lbr011                       #  1ae: 479821
            l32i.n       a2, a13, 4                            #  1b1: 281d
            l32i.n       a3, a12, 4                            #  1b3: 381c
            movi         a0, .Lrel012 /* .Lrel012 */           #  1b5: 01f3ff
            callx0       a0                                    #  1b8: c00000
            bnez.n       a2, .Lbr011                           #  1bb: dc42
            addi.n       a12, a12, 4                           #  1bd: 4bcc
            l32i.n       a9, a1, 0 /* [(local0)] */            #  1bf: 9801
            addi.n       a13, a13, 4                           #  1c1: 4bdd
            bne          a13, a9, .Lbr009                      #  1c3: 979de3
            movi.n       a2, 0 /* 0x00000000 */                #  1c6: 0c02
.Lbr010:    l32i.n       a12, a1, 8 /* [(local2)] */           #  1c8: c821
            l32i.n       a13, a1, 12 /* [(local3)] */          #  1ca: d831
            l32i.n       a0, a1, 4 /* [(local1)] */            #  1cc: 0811
            addi         a1, a1, 16 /* (top of frame) */       #  1ce: 12c110
            ret.n                                              #  1d1: 0df0
.Lbr011:    movi.n       a2, 1 /* 0x00000001 */                #  1d3: 0c12
            j            .Lbr010                               #  1d5: c6fbff

.Lrel013:   .word        memcmp                                #  1d8: 00000000

# Function @ .irom0.text+0x1dc
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
sdk_hostapd_maclist_found:
            addi         a1, a1, -48 /* (local0) */            #  1dc: 12c1d0
            s32i.n       a14, a1, 20 /* a14 -> [(local5)] */   #  1df: e951
            s32i.n       a0, a1, 8 /* a0 -> [(local2)] */      #  1e1: 0921
            s32i.n       a4, a1, 32 /* arg2 -> [(local8)] */   #  1e3: 4981
            s32i.n       a13, a1, 16 /* a13 -> [(local4)] */   #  1e5: d941
            s32i.n       a15, a1, 24 /* a15 -> [(local6)] */   #  1e7: f961
            s32i.n       a12, a1, 12 /* a12 -> [(local3)] */   #  1e9: c931
            mov.n        a15, a4 /* arg2 */                    #  1eb: fd04
            addi.n       a12, a3, -1 /* arg1-0x1 */            #  1ed: 0bc3
            bltz         a12, .Lbr017                          #  1ef: 961c04
            movi.n       a13, 0 /* 0x00000000 */               #  1f2: 0c0d
            s32i.n       a5, a1, 4 /* arg3 -> [(local1)] */    #  1f4: 5911
            s32i.n       a2, a1, 0 /* arg0 -> [(local0)] */    #  1f6: 2901
.Lbr012:    movi.n       a4, 6 /* 0x00000006 */                #  1f8: 0c64
            add.n        a0, a12, a13                          #  1fa: da0c
            l32i.n       a3, a1, 0 /* [(local0)] */            #  1fc: 3801
            addi.n       a14, a0, 1                            #  1fe: 1be0
            movgez       a14, a0, a0                           #  200: 00e0b3
            srai         a14, a14, 1                           #  203: e0e121
            addx2        a2, a14, a14                          #  206: e02e90
            addx4        a2, a2, a3                            #  209: 3022a0
            mov.n        a3, a15 /* arg2 */                    #  20c: 3d0f
            s32i.n       a2, a1, 28 /* a2 -> [(local7)] */     #  20e: 2971
            movi         a0, .Lrel013 /* .Lrel013 */           #  210: 01f2ff
            callx0       a0                                    #  213: c00000
            bnez.n       a2, .Lbr014                           #  216: ccd2
            l32i.n       a2, a1, 4 /* [(local1)] */            #  218: 2811
            l32i.n       a3, a1, 28 /* [(local7)] */           #  21a: 3871
            beqz.n       a2, .Lbr013                           #  21c: 8c22
            l32i.n       a3, a3, 8 /* [[(local7)]+0x8] */      #  21e: 3823
            s32i.n       a3, a2, 0 /* [[(local7)]+0x8] -> [[(local1)]] */ #  220: 3902
.Lbr013:    movi.n       a2, 1 /* 0x00000001 */                #  222: 0c12
            j            .Lbr018                               #  224: 860300
.Lbr014:    bgez         a2, .Lbr015                           #  227: d64200
            addi.n       a13, a14, 1                           #  22a: 1bde
            j            .Lbr016                               #  22c: 460000
.Lbr015:    addi.n       a12, a14, -1                          #  22f: 0bce
.Lbr016:    bge          a12, a13, .Lbr012                     #  231: d7acc3
.Lbr017:    movi.n       a2, 0 /* 0x00000000 */                #  234: 0c02
.Lbr018:    l32i.n       a12, a1, 12 /* [(local3)] */          #  236: c831
            l32i.n       a13, a1, 16 /* [(local4)] */          #  238: d841
            l32i.n       a14, a1, 20 /* [(local5)] */          #  23a: e851
            l32i.n       a15, a1, 24 /* [(local6)] */          #  23c: f861
            l32i.n       a0, a1, 8 /* [(local2)] */            #  23e: 0821
            addi         a1, a1, 48 /* (top of frame) */       #  240: 12c130
            ret.n                                              #  243: 0df0

            .balign      4
# Function @ .irom0.text+0x248
.literal_position
sdk_hostapd_rate_found:
            beqz.n       a2, .Lbr021                           #  248: 9c12
            l32i.n       a6, a2, 0 /* [arg0] */                #  24a: 6802
            bltz         a6, .Lbr021                           #  24c: 96d600
.Lbr019:    bne          a6, a3, .Lbr020                       #  24f: 379603
            movi.n       a2, 1 /* 0x00000001 */                #  252: 0c12
            ret.n         /* 0x00000001 */                     #  254: 0df0
.Lbr020:    l32i.n       a6, a2, 4                             #  256: 6812
            addi.n       a2, a2, 4                             #  258: 4b22
            bgez         a6, .Lbr019                           #  25a: d616ff
.Lbr021:    movi.n       a2, 0 /* 0x00000000 */                #  25d: 0c02
            ret.n         /* 0x00000000 */                     #  25f: 0df0

            .balign      4
.Lrel014:   .word        memcmp                                #  264: 00000000

# Function @ .irom0.text+0x268
# Local variables/stack:
#     (local0):  word      @ -0x20
#     (local1):  word      @ -0x1c
#     (local2):  word      @ -0x18
#     (local3):  word      @ -0x14
#     (local4):  word[4]   @ -0x10
.literal_position
sdk_hostapd_get_psk:
            addi         a1, a1, -32 /* (local0) */            #  268: 12c1e0
            s32i.n       a12, a1, 8 /* a12 -> [(local2)] */    #  26b: c921
            s32i.n       a13, a1, 12 /* a13 -> [(local3)] */   #  26d: d931
            s32i.n       a14, a1, 16 /* a14 -> [(local4)] */   #  26f: e941
            s32i.n       a0, a1, 4 /* a0 -> [(local1)] */      #  271: 0911
            mov.n        a14, a4 /* arg2 */                    #  273: ed04
            movi.n       a0, 1 /* 0x00000001 */                #  275: 0c10
            movi.n       a13, 0 /* 0x00000000 */               #  277: 0c0d
            l32i.n       a12, a2, 56 /* [arg0+0x38] */         #  279: c8e2
            moveqz       a13, a0, a4                           #  27b: 40d083
            beqz.n       a12, .Lbr025                          #  27e: ac9c
            s32i.n       a3, a1, 0 /* arg1 -> [(local0)] */    #  280: 3901
.Lbr022:    beqz.n       a13, .Lbr024                          #  282: 9c8d
            l32i.n       a2, a12, 4                            #  284: 281c
            bnez.n       a2, .Lbr023                           #  286: ccf2
            addi         a2, a12, 40                           #  288: 22cc28
            l32i.n       a3, a1, 0 /* [(local0)] */            #  28b: 3801
            movi.n       a4, 6 /* 0x00000006 */                #  28d: 0c64
            movi         a0, .Lrel014 /* .Lrel014 */           #  28f: 01f5ff
            callx0       a0                                    #  292: c00000
            movi.n       a0, 1 /* 0x00000001 */                #  295: 0c10
            bnez.n       a2, .Lbr024                           #  297: cc32
.Lbr023:    addi.n       a2, a12, 8                            #  299: 8b2c
            j            .Lbr026                               #  29b: 860300
.Lbr024:    addi.n       a3, a12, 8                            #  29e: 8b3c
            sub          a3, a14, a3                           #  2a0: 303ec0
            l32i.n       a12, a12, 0                           #  2a3: c80c
            moveqz       a13, a0, a3                           #  2a5: 30d083
            bnez         a12, .Lbr022                          #  2a8: 566cfd
.Lbr025:    movi.n       a2, 0 /* 0x00000000 */                #  2ab: 0c02
.Lbr026:    l32i.n       a12, a1, 8 /* [(local2)] */           #  2ad: c821
            l32i.n       a13, a1, 12 /* [(local3)] */          #  2af: d831
            l32i.n       a14, a1, 16 /* [(local4)] */          #  2b1: e841
            l32i.n       a0, a1, 4 /* [(local1)] */            #  2b3: 0811
            addi         a1, a1, 32 /* (top of frame) */       #  2b5: 12c120
            ret.n                                              #  2b8: 0df0

            .section     .rodata, "a", @progbits

.Ldata001:  .space       6
