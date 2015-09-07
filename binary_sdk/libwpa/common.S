
            .section     .irom0.literal, "ax", @progbits

            .section     .text, "ax", @progbits

            .section     .data, "aw", @progbits

            .section     .bss, "aw", @nobits

            .section     .irom0.text, "ax", @progbits

# Function @ .irom0.text+0x0
.literal_position
sdk_inc_byte_array:
            addi.n       a3, a3, -1 /* arg1-0x1 */             #    0: 0b33
            bltz         a3, .Lbr002                           #    2: 965301
            add.n        a3, a3, a2                            #    5: 2a33
            addi.n       a2, a2, -1 /* arg0-0x1 */             #    7: 0b22
.Lbr001:    l8ui         a4, a3, 0                             #    9: 420300
            addi.n       a4, a4, 1                             #    c: 1b44
            extui        a4, a4, 0, 8                          #    e: 404074
            s8i          a4, a3, 0                             #   11: 424300
            bnez.n       a4, .Lbr002                           #   14: cc34
            addi.n       a3, a3, -1                            #   16: 0b33
            bne          a3, a2, .Lbr001                       #   18: 2793ed
.Lbr002:    ret.n                                              #   1b: 0df0

            .balign      4
# Function @ .irom0.text+0x20
.literal_position
.Lfunc001:  movi.n       a3, 47 /* 0x0000002f */               #   20: 2cf3
            bgeu         a3, a2, .Lbr003                       #   22: 27b309
            movi.n       a4, 57 /* 0x00000039 */               #   25: 3c94
            bltu         a4, a2, .Lbr003                       #   27: 273404
            addi         a2, a2, -48 /* arg0-0x30 */           #   2a: 22c2d0
            ret.n         /* arg0-0x30 */                      #   2d: 0df0
.Lbr003:    movi         a5, 96 /* 0x00000060 */               #   2f: 52a060
            bgeu         a5, a2, .Lbr004                       #   32: 27b50a
            movi         a6, 102 /* 0x00000066 */              #   35: 62a066
            bltu         a6, a2, .Lbr004                       #   38: 273604
            addi         a2, a2, -87 /* arg0-0x57 */           #   3b: 22c2a9
            ret.n         /* arg0-0x57 */                      #   3e: 0df0
.Lbr004:    movi.n       a7, 64 /* 0x00000040 */               #   40: 4c07
            bgeu         a7, a2, .Lbr005                       #   42: 27b709
            movi.n       a8, 70 /* 0x00000046 */               #   45: 4c68
            bltu         a8, a2, .Lbr005                       #   47: 273804
            addi         a2, a2, -55 /* arg0-0x37 */           #   4a: 22c2c9
            ret.n         /* arg0-0x37 */                      #   4d: 0df0
.Lbr005:    movi.n       a2, -1 /* 0xffffffff */               #   4f: 7cf2
            ret.n         /* 0xffffffff */                     #   51: 0df0

            .balign      4
# Function @ .irom0.text+0x54
# Local variables/stack:
#     (local0):  word      @ -0x10
#     (local1):  word      @ -0xc
#     (local2):  word[2]   @ -0x8
.literal_position
sdk_hex2byte:
            addi         a1, a1, -16 /* (local0) */            #   54: 12c1f0
            s32i.n       a12, a1, 8 /* a12 -> [(local2)] */    #   57: c921
            s32i.n       a0, a1, 4 /* a0 -> [(local1)] */      #   59: 0911
            mov.n        a12, a2 /* arg0 */                    #   5b: cd02
            l8ui         a2, a2, 0 /* [arg0] */                #   5d: 220200
            call0        .Lfunc001                             #   60: c5fbff
            s32i.n       a2, a1, 0 /* a2 -> [(local0)] */      #   63: 2901
            bltz         a2, .Lbr007                           #   65: 969201
            l8ui         a2, a12, 1 /* [arg0+0x1] */           #   68: 220c01
            call0        .Lfunc001                             #   6b: 45fbff
            bltz         a2, .Lbr007                           #   6e: 960201
            l32i.n       a0, a1, 0 /* [(local0)] */            #   71: 0801
            slli         a0, a0, 4                             #   73: c00011
            or           a2, a2, a0                            #   76: 002220
.Lbr006:    l32i.n       a12, a1, 8 /* [(local2)] */           #   79: c821
            l32i.n       a0, a1, 4 /* [(local1)] */            #   7b: 0811
            addi         a1, a1, 16 /* (top of frame) */       #   7d: 12c110
            ret.n                                              #   80: 0df0
.Lbr007:    movi.n       a2, -1 /* 0xffffffff */               #   82: 7cf2
            j            .Lbr006                               #   84: 46fcff

            .balign      4
# Function @ .irom0.text+0x88
# Local variables/stack:
#     (local0):  word      @ -0x20
#     (local1):  word      @ -0x1c
#     (local2):  word      @ -0x18
#     (local3):  word      @ -0x14
#     (local4):  word      @ -0x10
#     (local5):  word[3]   @ -0xc
.literal_position
sdk_hexstr2bin:
            addi         a1, a1, -32 /* (local0) */            #   88: 12c1e0
            s32i.n       a0, a1, 0 /* a0 -> [(local0)] */      #   8b: 0901
            s32i.n       a4, a1, 20 /* arg2 -> [(local5)] */   #   8d: 4951
            s32i.n       a14, a1, 12 /* a14 -> [(local3)] */   #   8f: e931
            s32i.n       a15, a1, 16 /* a15 -> [(local4)] */   #   91: f941
            s32i.n       a12, a1, 4 /* a12 -> [(local1)] */    #   93: c911
            s32i.n       a13, a1, 8 /* a13 -> [(local2)] */    #   95: d921
            mov.n        a12, a2 /* arg0 */                    #   97: cd02
            mov.n        a13, a3 /* arg1 */                    #   99: dd03
            mov.n        a15, a4 /* arg2 */                    #   9b: fd04
            beqz.n       a4, .Lbr010                           #   9d: 9c94
            movi.n       a14, 0 /* 0x00000000 */               #   9f: 0c0e
.Lbr008:    mov.n        a2, a12                               #   a1: 2d0c
            call0        sdk_hex2byte                          #   a3: 050000
            bgez         a2, .Lbr009                           #   a6: d64200
            movi.n       a2, -1 /* 0xffffffff */               #   a9: 7cf2
            j            .Lbr011                               #   ab: 460300
.Lbr009:    addi.n       a12, a12, 2                           #   ae: 2bcc
            s8i          a2, a13, 0                            #   b0: 224d00
            addi.n       a14, a14, 1                           #   b3: 1bee
            addi.n       a13, a13, 1                           #   b5: 1bdd
            bne          a15, a14, .Lbr008                     #   b7: e79fe6
.Lbr010:    movi.n       a2, 0 /* 0x00000000 */                #   ba: 0c02
.Lbr011:    l32i.n       a12, a1, 4 /* [(local1)] */           #   bc: c811
            l32i.n       a13, a1, 8 /* [(local2)] */           #   be: d821
            l32i.n       a14, a1, 12 /* [(local3)] */          #   c0: e831
            l32i.n       a15, a1, 16 /* [(local4)] */          #   c2: f841
            l32i.n       a0, a1, 0 /* [(local0)] */            #   c4: 0801
            addi         a1, a1, 32 /* (top of frame) */       #   c6: 12c120
            ret.n                                              #   c9: 0df0

            .balign      4
.Llit001:   .word        0x0000ff00                            #   cc: 00ff0000
.Llit002:   .word        0x83aa7e80                            #   d0: 807eaa83
.Llit003:   .word        0x000010c7                            #   d4: c7100000
.Llit004:   .word        0x0000ff00                            #   d8: 00ff0000
.Lrel001:   .word        sdk_os_get_time                       #   dc: 00000000
.Lrel002:   .word        memcpy                                #   e0: 00000000
.Lrel003:   .word        memcpy                                #   e4: 00000000

# Function @ .irom0.text+0xe8
# Local variables/stack:
#     (local0):  word      @ -0x20
#     (local1):  word      @ -0x1c
#     (local2):  word      @ -0x18
#     (local3):  word      @ -0x14
#     (local4):  word      @ -0x10
#     (local5):  word[3]   @ -0xc
.literal_position
sdk_wpa_get_ntp_timestamp:
            addi         a1, a1, -32 /* (local0) */            #   e8: 12c1e0
            s32i.n       a12, a1, 20 /* a12 -> [(local5)] */   #   eb: c951
            s32i.n       a0, a1, 16 /* a0 -> [(local4)] */     #   ed: 0941
            mov.n        a12, a2 /* arg0 */                    #   ef: cd02
            mov.n        a2, a1 /* (local0) */                 #   f1: 2d01
            movi         a0, .Lrel001 /* sdk_os_get_time */    #   f3: 01faff
            callx0       a0 /* sdk_os_get_time */              #   f6: c00000
            mov.n        a2, a12 /* arg0 */                    #   f9: 2d0c
            addi.n       a3, a1, 8 /* (local2) */              #   fb: 8b31
            movi.n       a4, 4 /* 0x00000004 */                #   fd: 0c44
            movi         a8, .Llit001 /* 0x0000ff00 */         #   ff: 81f3ff
            movi         a6, .Llit003 /* 0x000010c7 */         #  102: 61f4ff
            movi         a5, .Llit002 /* 0x83aa7e80 */         #  105: 51f2ff
            l32i.n       a9, a1, 4 /* [(local1)] */            #  108: 9811
            l32i.n       a0, a1, 0 /* [(local0)] */            #  10a: 0801
            srli         a10, a9, 9                            #  10c: 90a941
            srli         a11, a9, 5                            #  10f: 90b541
            add.n        a0, a0, a5 /* [(local0)]+0x83aa7e80 */ #  112: 5a00
            slli         a5, a0, 24                            #  114: 805001
            mull         a9, a9, a6                            #  117: 609982
            and          a7, a0, a8                            #  11a: 807010
            extui        a6, a0, 24, 8                         #  11d: 006875
            sub          a9, a9, a11                           #  120: b099c0
            slli         a7, a7, 8                             #  123: 807711
            or           a5, a5, a7                            #  126: 705520
            sub          a9, a9, a10                           #  129: a099c0
            s32i.n       a9, a1, 12 /* a9 -> [(local3)] */     #  12c: 9931
            srli         a0, a0, 8                             #  12e: 000841
            and          a0, a0, a8                            #  131: 800010
            or           a0, a0, a6                            #  134: 600020
            or           a0, a0, a5                            #  137: 500020
            s32i.n       a0, a1, 8 /* a0 -> [(local2)] */      #  13a: 0921
            movi         a0, .Lrel002 /* memcpy */             #  13c: 01e9ff
            callx0       a0 /* memcpy */                       #  13f: c00000
            addi.n       a2, a12, 4 /* arg0+0x4 */             #  142: 4b2c
            addi.n       a3, a1, 8 /* (local2) */              #  144: 8b31
            movi.n       a4, 4 /* 0x00000004 */                #  146: 0c44
            l32i.n       a9, a1, 12 /* [(local3)] */           #  148: 9831
            movi         a8, .Llit004 /* 0x0000ff00 */         #  14a: 81e3ff
            srli         a7, a9, 8                             #  14d: 907841
            and          a7, a7, a8                            #  150: 807710
            and          a10, a9, a8                           #  153: 80a910
            slli         a10, a10, 8                           #  156: 80aa11
            slli         a8, a9, 24                            #  159: 808901
            or           a8, a8, a10                           #  15c: a08820
            extui        a9, a9, 24, 8                         #  15f: 909875
            or           a7, a7, a9                            #  162: 907720
            or           a7, a7, a8                            #  165: 807720
            s32i.n       a7, a1, 8 /* a7 -> [(local2)] */      #  168: 7921
            movi         a0, .Lrel003 /* memcpy */             #  16a: 01deff
            callx0       a0 /* memcpy */                       #  16d: c00000
            l32i.n       a12, a1, 20 /* [(local5)] */          #  170: c851
            l32i.n       a0, a1, 16 /* [(local4)] */           #  172: 0841
            addi         a1, a1, 32 /* (top of frame) */       #  174: 12c120
            ret.n                                              #  177: 0df0

            .balign      4
.Lrel004:   .word        strlen                                #  17c: 00000000
.Lrel005:   .word        strlen                                #  180: 00000000
.Lrel006:   .word        strlen                                #  184: 00000000
.Lrel007:   .word        malloc                                #  188: 00000000
.Lrel008:   .word        free                                  #  18c: 00000000
.Lrel009:   .word        malloc                                #  190: 00000000
.Lrel010:   .word        memcpy                                #  194: 00000000
.Lrel011:   .word        strrchr                               #  198: 00000000
.Lrel012:   .word        malloc                                #  19c: 00000000
.Lrel013:   .word        memcpy                                #  1a0: 00000000

# Function @ .irom0.text+0x1a4
# Local variables/stack:
#     (local0):  word      @ -0x20
#     (local1):  word      @ -0x1c
#     (local2):  word      @ -0x18
#     (local3):  word      @ -0x14
#     (local4):  word[4]   @ -0x10
.literal_position
sdk_wpa_config_parse_string:
            addi         a1, a1, -32 /* (local0) */            #  1a4: 12c1e0
            s32i.n       a14, a1, 16 /* a14 -> [(local4)] */   #  1a7: e941
            s32i.n       a0, a1, 4 /* a0 -> [(local1)] */      #  1a9: 0911
            s32i.n       a13, a1, 12 /* a13 -> [(local3)] */   #  1ab: d931
            s32i.n       a12, a1, 8 /* a12 -> [(local2)] */    #  1ad: c921
            mov.n        a13, a3 /* arg1 */                    #  1af: dd03
            mov.n        a12, a2 /* arg0 */                    #  1b1: cd02
            l8ui         a0, a2, 0 /* [arg0] */                #  1b3: 020200
            movi.n       a2, 34 /* 0x00000022 */               #  1b6: 2c22
            bne          a0, a2, .Lbr012                       #  1b8: 27901a
            mov.n        a2, a12 /* arg0 */                    #  1bb: 2d0c
            movi         a0, .Lrel004 /* strlen */             #  1bd: 01efff
            callx0       a0 /* strlen */                       #  1c0: c00000
            addi         a3, a2, -7                            #  1c3: 32c2f9
            beqz         a3, .Lbr018                           #  1c6: 169308
            mov.n        a2, a12 /* arg0 */                    #  1c9: 2d0c
            movi         a0, .Lrel005 /* strlen */             #  1cb: 01edff
            callx0       a0 /* strlen */                       #  1ce: c00000
            movi.n       a4, 15 /* 0x0000000f */               #  1d1: 0cf4
            beq          a2, a4, .Lbr018                       #  1d3: 47127c
.Lbr012:    mov.n        a2, a12 /* arg0 */                    #  1d6: 2d0c
            movi         a0, .Lrel006 /* strlen */             #  1d8: 01ebff
            callx0       a0 /* strlen */                       #  1db: c00000
            beqi         a2, 5, .Lbr017                        #  1de: 26524f
            movi.n       a5, 13 /* 0x0000000d */               #  1e1: 0cd5
            beq          a2, a5, .Lbr017                       #  1e3: 57124a
            beqi         a2, 10, .Lbr013                       #  1e6: 269204
            movi.n       a6, 26 /* 0x0000001a */               #  1e9: 1ca6
            bne          a2, a6, .Lbr014                       #  1eb: 679223
.Lbr013:    srli         a2, a2, 1                             #  1ee: 202141
            s32i.n       a2, a1, 0 /* a2 -> [(local0)] */      #  1f1: 2901
            addi.n       a2, a2, 1                             #  1f3: 1b22
            movi         a0, .Lrel007 /* malloc */             #  1f5: 01e4ff
            callx0       a0 /* malloc */                       #  1f8: c00000
            mov.n        a14, a2                               #  1fb: ed02
            beqz.n       a2, .Lbr014                           #  1fd: 9c12
            mov.n        a2, a12 /* arg0 */                    #  1ff: 2d0c
            mov.n        a3, a14                               #  201: 3d0e
            l32i.n       a4, a1, 0 /* [(local0)] */            #  203: 4801
            call0        sdk_hexstr2bin                        #  205: 050000
            beqz.n       a2, .Lbr015                           #  208: 8cb2
            mov.n        a2, a14                               #  20a: 2d0e
            movi         a0, .Lrel008 /* free */               #  20c: 01e0ff
            callx0       a0 /* free */                         #  20f: c00000
.Lbr014:    movi.n       a14, 0 /* 0x00000000 */               #  212: 0c0e
            j            .Lbr016                               #  214: 860200
.Lbr015:    l32i.n       a3, a1, 0 /* [(local0)] */            #  217: 3801
            movi.n       a4, 0 /* 0x00000000 */                #  219: 0c04
            add.n        a5, a3, a14                           #  21b: ea53
            s8i          a4, a5, 0                             #  21d: 424500
            s32i.n       a3, a13, 0 /* [(local0)] -> [arg1] */ #  220: 390d
.Lbr016:    l32i.n       a0, a1, 4 /* [(local1)] */            #  222: 0811
            l32i.n       a12, a1, 8 /* [(local2)] */           #  224: c821
            mov.n        a2, a14                               #  226: 2d0e
            l32i.n       a13, a1, 12 /* [(local3)] */          #  228: d831
            l32i.n       a14, a1, 16 /* [(local4)] */          #  22a: e841
            addi         a1, a1, 32 /* (top of frame) */       #  22c: 12c120
            ret.n                                              #  22f: 0df0
.Lbr017:    s32i.n       a2, a13, 0 /* a2 -> [arg1] */         #  231: 290d
            addi.n       a2, a2, 1                             #  233: 1b22
            movi         a0, .Lrel009 /* malloc */             #  235: 01d6ff
            callx0       a0 /* malloc */                       #  238: c00000
            mov.n        a3, a12 /* arg0 */                    #  23b: 3d0c
            mov.n        a14, a2                               #  23d: ed02
            l32i.n       a4, a13, 0 /* [arg1] */               #  23f: 480d
            movi         a0, .Lrel010 /* memcpy */             #  241: 01d4ff
            callx0       a0 /* memcpy */                       #  244: c00000
            l32i.n       a7, a13, 0 /* [arg1] */               #  247: 780d
            movi.n       a6, 0 /* 0x00000000 */                #  249: 0c06
            add.n        a7, a7, a14                           #  24b: ea77
            s8i          a6, a7, 0                             #  24d: 624700
            j            .Lbr016                               #  250: 86f3ff
.Lbr018:    movi.n       a3, 34 /* 0x00000022 */               #  253: 2c23
            addi.n       a14, a12, 1 /* arg0+0x1 */            #  255: 1bec
            mov.n        a2, a14 /* arg0+0x1 */                #  257: 2d0e
            movi         a0, .Lrel011 /* strrchr */            #  259: 01cfff
            callx0       a0 /* strrchr */                      #  25c: c00000
            beqz         a2, .Lbr014                           #  25f: 16f2fa
            sub          a2, a2, a12                           #  262: c022c0
            addi.n       a8, a2, -1                            #  265: 0b82
            s32i.n       a8, a13, 0 /* a8 -> [arg1] */         #  267: 890d
            movi         a0, .Lrel012 /* malloc */             #  269: 01ccff
            callx0       a0 /* malloc */                       #  26c: c00000
            mov.n        a12, a2                               #  26f: cd02
            beqz         a2, .Lbr014                           #  271: 16d2f9
            mov.n        a3, a14 /* arg0+0x1 */                #  274: 3d0e
            l32i.n       a4, a13, 0 /* [arg1] */               #  276: 480d
            movi         a0, .Lrel013 /* memcpy */             #  278: 01caff
            callx0       a0 /* memcpy */                       #  27b: c00000
            mov.n        a14, a12                              #  27e: ed0c
            l32i.n       a10, a13, 0 /* [arg1] */              #  280: a80d
            movi.n       a9, 0 /* 0x00000000 */                #  282: 0c09
            add.n        a10, a10, a12                         #  284: caaa
            s8i          a9, a10, 0                            #  286: 924a00
            j            .Lbr016                               #  289: 46e5ff
