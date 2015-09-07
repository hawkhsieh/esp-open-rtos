
            .section     .irom0.literal, "ax", @progbits

            .section     .text, "ax", @progbits

            .section     .data, "aw", @progbits

            .section     .bss, "aw", @nobits

            .section     .irom0.text, "ax", @progbits

.Lrel001:   .word        sdk_sha1_vector                       #    0: 00000000
.Lrel002:   .word        memset                                #    4: 00000000
.Lrel003:   .word        memcpy                                #    8: 00000000
.Lrel004:   .word        sdk_sha1_vector                       #    c: 00000000
.Lrel005:   .word        memset                                #   10: 00000000
.Lrel006:   .word        memcpy                                #   14: 00000000
.Lrel007:   .word        sdk_sha1_vector                       #   18: 00000000

# Function @ .irom0.text+0x1c
# Local variables/stack:
#     (local0):  word      @ -0x80
#     (local1):  word[7]   @ -0x7c
#     (local2):  word      @ -0x60
#     (local3):  word[7]   @ -0x5c
#     (local4):  word      @ -0x40
#     (local5):  word      @ -0x3c
#     (local6):  word      @ -0x38
#     (local7):  word      @ -0x34
#     (local8):  word      @ -0x30
#     (local9):  word[3]   @ -0x2c
#     (local10): word      @ -0x20
#     (local11): word[7]   @ -0x1c
.literal_position
sdk_hmac_sha1_vector:
            movi         a8, 224 /* 0x000000e0 */              #   1c: 82a0e0
            sub          a1, a1, a8 /* (FP)-0xe0 */            #   1f: 8011c0
            s32i         a3, a1, 196 /* arg1 -> [(local11)] */ #   22: 326131
            s32i         a2, a1, 192 /* arg0 -> [(local10)] */ #   25: 226130
            s32i         a0, a1, 164 /* a0 -> [(local5)] */    #   28: 026129
            s32i         a13, a1, 172 /* a13 -> [(local7)] */  #   2b: d2612b
            s32i         a12, a1, 168 /* a12 -> [(local6)] */  #   2e: c2612a
            s32i         a14, a1, 176 /* a14 -> [(local8)] */  #   31: e2612c
            mov.n        a12, a5 /* arg3 */                    #   34: cd05
            mov.n        a14, a4 /* arg2 */                    #   36: ed04
            mov.n        a13, a6 /* arg4 */                    #   38: dd06
            movi         a0, 196 /* 0x000000c4 */              #   3a: 02a0c4
            add.n        a0, a1, a0 /* (local11) */            #   3d: 0a01
            movi         a6, 192 /* 0x000000c0 */              #   3f: 62a0c0
            add.n        a6, a1, a6 /* (local10) */            #   42: 6a61
            bltui        a4, 6, .Lbr001                        #   44: b66402
            j            .Lbr006                               #   47: 062600
.Lbr001:    s32i         a7, a1, 160 /* arg5 -> [(local4)] */  #   4a: 726128
            movi.n       a2, 64 /* 0x00000040 */               #   4d: 4c02
            bgeu         a2, a3, .Lbr002                       #   4f: 37b218
            mov.n        a3, a6 /* (local10) */                #   52: 3d06
            movi.n       a2, 1 /* 0x00000001 */                #   54: 0c12
            mov.n        a5, a1 /* (FP)-0xe0 */                #   56: 5d01
            mov.n        a4, a0 /* (local11) */                #   58: 4d00
            movi         a0, .Lrel001 /* sdk_sha1_vector */    #   5a: 01e9ff
            callx0       a0 /* sdk_sha1_vector */              #   5d: c00000
            bnez         a2, .Lbr006                           #   60: 56f207
            s32i         a1, a1, 192 /* (FP)-0xe0 -> [(local10)] */ #   63: 126130
            movi.n       a6, 20 /* 0x00000014 */               #   66: 1c46
            s32i         a6, a1, 196 /* 0x00000014 -> [(local11)] */ #   68: 626131
.Lbr002:    addi         a2, a1, 32 /* (FP)-0xc0 */            #   6b: 22c120
            movi.n       a3, 0 /* 0x00000000 */                #   6e: 0c03
            movi.n       a4, 64 /* 0x00000040 */               #   70: 4c04
            movi         a0, .Lrel002 /* memset */             #   72: 01e4ff
            callx0       a0 /* memset */                       #   75: c00000
            l32i         a3, a1, 192 /* [(local10)] */         #   78: 322130
            l32i         a4, a1, 196 /* [(local11)] */         #   7b: 422131
            addi         a2, a1, 32 /* (FP)-0xc0 */            #   7e: 22c120
            s32i         a14, a1, 180 /* arg2 -> [(local9)] */ #   81: e2612d
            movi         a0, .Lrel003 /* memcpy */             #   84: 01e1ff
            callx0       a0 /* memcpy */                       #   87: c00000
            l32i         a4, a1, 180 /* [(local9)] */          #   8a: 42212d
            addi         a0, a1, 32 /* (FP)-0xc0 */            #   8d: 02c120
            addi         a14, a1, 96 /* (local0) */            #   90: e2c160
            movi.n       a2, 54 /* 0x00000036 */               #   93: 3c62
            movi.n       a6, 64 /* 0x00000040 */               #   95: 4c06
            s32i         a6, a1, 128 /* 0x00000040 -> [(local2)] */ #   97: 626120
            addi         a6, a1, 32 /* (FP)-0xc0 */            #   9a: 62c120
            s32i         a6, a1, 96 /* (FP)-0xc0 -> [(local0)] */ #   9d: 626118
.Lbr003:    l8ui         a5, a0, 0                             #   a0: 520000
            xor          a5, a5, a2                            #   a3: 205530
            s8i          a5, a0, 0                             #   a6: 524000
            addi.n       a0, a0, 1                             #   a9: 1b00
            bne          a0, a14, .Lbr003                      #   ab: e790f1
            beqz.n       a4, .Lbr005                           #   ae: 9cc4
            addi         a2, a1, 96 /* (local0) */             #   b0: 22c160
            addx4        a3, a4, a12                           #   b3: c034a0
            addi         a0, a1, 127 /* (FP)-0x61 */           #   b6: 02c17f
            addi.n       a0, a0, 1 /* (local2) */              #   b9: 1b00
.Lbr004:    l32i.n       a5, a13, 0                            #   bb: 580d
            l32i.n       a6, a12, 0                            #   bd: 680c
            addi.n       a13, a13, 4                           #   bf: 4bdd
            addi.n       a12, a12, 4                           #   c1: 4bcc
            s32i.n       a6, a2, 4                             #   c3: 6912
            s32i.n       a5, a0, 4                             #   c5: 5910
            addi.n       a2, a2, 4                             #   c7: 4b22
            addi.n       a0, a0, 4                             #   c9: 4b00
            bne          a12, a3, .Lbr004                      #   cb: 379cec
.Lbr005:    addi         a3, a1, 96 /* (local0) */             #   ce: 32c160
            addi.n       a2, a4, 1 /* [(local9)]+0x1 */        #   d1: 1b24
            l32i         a5, a1, 160 /* [(local4)] */          #   d3: 522128
            addi         a4, a1, 127 /* (FP)-0x61 */           #   d6: 42c17f
            addi.n       a4, a4, 1 /* (local2) */              #   d9: 1b44
            movi         a0, .Lrel004 /* sdk_sha1_vector */    #   db: 01ccff
            callx0       a0 /* sdk_sha1_vector */              #   de: c00000
            beqz.n       a2, .Lbr007                           #   e1: 8c32
.Lbr006:    movi.n       a2, -1 /* 0xffffffff */               #   e3: 7cf2
            j            .Lbr009                               #   e5: 061500
.Lbr007:    addi         a2, a1, 32 /* (FP)-0xc0 */            #   e8: 22c120
            movi.n       a3, 0 /* 0x00000000 */                #   eb: 0c03
            movi.n       a4, 64 /* 0x00000040 */               #   ed: 4c04
            movi         a0, .Lrel005 /* memset */             #   ef: 01c8ff
            callx0       a0 /* memset */                       #   f2: c00000
            l32i         a3, a1, 192 /* [(local10)] */         #   f5: 322130
            l32i         a4, a1, 196 /* [(local11)] */         #   f8: 422131
            addi         a2, a1, 32 /* (FP)-0xc0 */            #   fb: 22c120
            movi         a0, .Lrel006 /* memcpy */             #   fe: 01c5ff
            callx0       a0 /* memcpy */                       #  101: c00000
            addi         a0, a1, 32 /* (FP)-0xc0 */            #  104: 02c120
            movi.n       a2, 92 /* 0x0000005c */               #  107: 5cc2
.Lbr008:    l8ui         a5, a0, 0                             #  109: 520000
            xor          a5, a5, a2                            #  10c: 205530
            s8i          a5, a0, 0                             #  10f: 524000
            addi.n       a0, a0, 1                             #  112: 1b00
            bne          a0, a14, .Lbr008                      #  114: e790f1
            movi.n       a2, 2 /* 0x00000002 */                #  117: 0c22
            addi         a3, a1, 96 /* (local0) */             #  119: 32c160
            addi         a4, a1, 127 /* (FP)-0x61 */           #  11c: 42c17f
            movi.n       a6, 20 /* 0x00000014 */               #  11f: 1c46
            l32i         a5, a1, 160 /* [(local4)] */          #  121: 522128
            movi.n       a7, 64 /* 0x00000040 */               #  124: 4c07
            addi         a8, a1, 32 /* (FP)-0xc0 */            #  126: 82c120
            s32i         a8, a1, 96 /* (FP)-0xc0 -> [(local0)] */ #  129: 826118
            s32i         a7, a1, 128 /* 0x00000040 -> [(local2)] */ #  12c: 726120
            s32i         a5, a1, 100 /* [(local4)] -> [(local1)] */ #  12f: 526119
            s32i         a6, a1, 132 /* 0x00000014 -> [(local3)] */ #  132: 626121
            addi.n       a4, a4, 1 /* (local2) */              #  135: 1b44
            movi         a0, .Lrel007 /* .Lrel007 */           #  137: 01b8ff
            callx0       a0                                    #  13a: c00000
.Lbr009:    l32i         a12, a1, 168 /* [(local6)] */         #  13d: c2212a
            l32i         a13, a1, 172 /* [(local7)] */         #  140: d2212b
            l32i         a14, a1, 176 /* [(local8)] */         #  143: e2212c
            movi         a3, 224 /* 0x000000e0 */              #  146: 32a0e0
            l32i         a0, a1, 164 /* [(local5)] */          #  149: 022129
            add.n        a1, a1, a3 /* (top of frame) */       #  14c: 3a11
            ret.n                                              #  14e: 0df0

# Function @ .irom0.text+0x150
# Local variables/stack:
#     (local0):  word[6]   @ -0x30
#     (local1):  word      @ -0x18
#     (local2):  word[5]   @ -0x14
.literal_position
sdk_hmac_sha1:
            mov.n        a7, a6 /* arg4 */                     #  150: 7d06
            mov.n        a9, a5 /* arg3 */                     #  152: 9d05
            addi         a1, a1, -48 /* (local0) */            #  154: 12c1d0
            s32i.n       a0, a1, 0 /* a0 -> [(local0)] */      #  157: 0901
            s32i.n       a4, a1, 24 /* arg2 -> [(local1)] */   #  159: 4961
            addi         a5, a1, 24 /* (local1) */             #  15b: 52c118
            addi         a6, a1, 28 /* (local2) */             #  15e: 62c11c
            s32i.n       a9, a1, 28 /* arg3 -> [(local2)] */   #  161: 9971
            movi.n       a4, 1 /* 0x00000001 */                #  163: 0c14
            call0        sdk_hmac_sha1_vector                  #  165: 050000
            l32i.n       a0, a1, 0 /* [(local0)] */            #  168: 0801
            addi         a1, a1, 48 /* (top of frame) */       #  16a: 12c130
            ret.n                                              #  16d: 0df0

            .balign      4
.Lrel008:   .word        strlen                                #  170: 00000000
.Lrel009:   .word        memcpy                                #  174: 00000000

# Function @ .irom0.text+0x178
# Local variables/stack:
#     (local0):  byte[16]  @ -0x80
#     (local1):  word      @ -0x70
#     (local2):  word      @ -0x6c
#     (local3):  word[2]   @ -0x68
#     (local4):  word      @ -0x60
#     (local5):  word      @ -0x5c
#     (local6):  word[10]  @ -0x58
#     (local7):  word      @ -0x30
#     (local8):  word      @ -0x2c
#     (local9):  word      @ -0x28
#     (local10): word      @ -0x24
#     (local11): word      @ -0x20
#     (local12): word      @ -0x1c
#     (local13): word      @ -0x18
#     (local14): word      @ -0x14
#     (local15): word[4]   @ -0x10
.literal_position
sdk_sha1_prf:
            addi         a1, a1, -128 /* (local0) */           #  178: 12c180
            s32i         a5, a1, 88 /* arg3 -> [(local9)] */   #  17b: 526116
            s32i         a7, a1, 84 /* arg5 -> [(local8)] */   #  17e: 726115
            s32i         a15, a1, 108 /* a15 -> [(local14)] */ #  181: f2611b
            s32i         a0, a1, 92 /* a0 -> [(local10)] */    #  184: 026117
            s32i         a12, a1, 96 /* a12 -> [(local11)] */  #  187: c26118
            s32i         a2, a1, 112 /* arg0 -> [(local15)] */ #  18a: 22611c
            s32i         a13, a1, 100 /* a13 -> [(local12)] */ #  18d: d26119
            s32i         a14, a1, 104 /* a14 -> [(local13)] */ #  190: e2611a
            mov.n        a13, a6 /* arg4 */                    #  193: dd06
            mov.n        a14, a3 /* arg1 */                    #  195: ed03
            mov.n        a2, a4 /* arg2 */                     #  197: 2d04
            mov.n        a12, a4 /* arg2 */                    #  199: cd04
            movi.n       a0, 0 /* 0x00000000 */                #  19b: 0c00
            l32i         a15, a1, 112 /* [(local15)] */        #  19d: f2211c
            s8i          a0, a1, 0 /* 0x00 -> [(local0)] */    #  1a0: 024100
            movi         a0, .Lrel008 /* strlen */             #  1a3: 01f3ff
            callx0       a0 /* strlen */                       #  1a6: c00000
            s32i.n       a1, a1, 24 /* (local0) -> [(local3)] */ #  1a9: 1961
            s32i.n       a12, a1, 16 /* arg2 -> [(local1)] */  #  1ab: c941
            s32i.n       a13, a1, 36 /* arg4 -> [(local5)] */  #  1ad: d991
            addi.n       a2, a2, 1                             #  1af: 1b22
            l32i         a3, a1, 88 /* [(local9)] */           #  1b1: 322116
            s32i.n       a3, a1, 20 /* [(local9)] -> [(local2)] */ #  1b4: 3951
            s32i.n       a2, a1, 32 /* a2 -> [(local4)] */     #  1b6: 2981
            l32i         a13, a1, 128 /* [(local16)] */        #  1b8: d22120
            movi.n       a2, 1 /* 0x00000001 */                #  1bb: 0c12
            s32i.n       a2, a1, 40 /* 0x00000001 -> [(local6)] */ #  1bd: 29a1
            beqz         a13, .Lbr014                          #  1bf: 16fd05
            movi.n       a0, 19 /* 0x00000013 */               #  1c2: 1c30
            movi.n       a12, 0 /* 0x00000000 */               #  1c4: 0c0c
.Lbr010:    sub          a4, a13, a12                          #  1c6: c04dc0
            s32i         a4, a1, 80 /* a4 -> [(local7)] */     #  1c9: 426114
            bgeu         a0, a4, .Lbr011                       #  1cc: 47b028
            mov.n        a2, a15 /* [(local15)] */             #  1cf: 2d0f
            mov.n        a3, a14 /* arg1 */                    #  1d1: 3d0e
            movi.n       a4, 3 /* 0x00000003 */                #  1d3: 0c34
            addi         a5, a1, 16 /* (local1) */             #  1d5: 52c110
            l32i         a7, a1, 84 /* [(local8)] */           #  1d8: 722115
            addi         a6, a1, 32 /* (local4) */             #  1db: 62c120
            add.n        a7, a7, a12                           #  1de: ca77
            call0        sdk_hmac_sha1_vector                  #  1e0: 050000
            bnez.n       a2, .Lbr012                           #  1e3: ec52
            movi.n       a0, 19 /* 0x00000013 */               #  1e5: 1c30
            l8ui         a8, a1, 0 /* [(local0)] */            #  1e7: 820100
            addi         a12, a12, 20                          #  1ea: c2cc14
            addi.n       a8, a8, 1 /* [(local0)]+0x1 */        #  1ed: 1b88
            s8i          a8, a1, 0 /* [(local0)]+0x1 -> [(local0)] */ #  1ef: 824100
            bltu         a12, a13, .Lbr010                     #  1f2: d73cd0
            j            .Lbr014                               #  1f5: 460a00
.Lbr011:    mov.n        a3, a14 /* arg1 */                    #  1f8: 3d0e
            mov.n        a2, a15 /* [(local15)] */             #  1fa: 2d0f
            movi.n       a4, 3 /* 0x00000003 */                #  1fc: 0c34
            addi         a5, a1, 16 /* (local1) */             #  1fe: 52c110
            addi         a6, a1, 32 /* (local4) */             #  201: 62c120
            addi         a7, a1, 48 /* (FP)-0x50 */            #  204: 72c130
            call0        sdk_hmac_sha1_vector                  #  207: 050000
            beqz.n       a2, .Lbr013                           #  20a: 8c32
.Lbr012:    movi.n       a2, -1 /* 0xffffffff */               #  20c: 7cf2
            j            .Lbr015                               #  20e: 860400
.Lbr013:    addi         a3, a1, 48 /* (FP)-0x50 */            #  211: 32c130
            l32i         a2, a1, 84 /* [(local8)] */           #  214: 222115
            l32i         a4, a1, 80 /* [(local7)] */           #  217: 422114
            add.n        a2, a2, a12                           #  21a: ca22
            movi         a0, .Lrel009 /* memcpy */             #  21c: 01d6ff
            callx0       a0 /* memcpy */                       #  21f: c00000
.Lbr014:    movi.n       a2, 0 /* 0x00000000 */                #  222: 0c02
.Lbr015:    l32i         a12, a1, 96 /* [(local11)] */         #  224: c22118
            l32i         a13, a1, 100 /* [(local12)] */        #  227: d22119
            l32i         a14, a1, 104 /* [(local13)] */        #  22a: e2211a
            l32i         a15, a1, 108 /* [(local14)] */        #  22d: f2211b
            movi         a3, 128 /* 0x00000080 */              #  230: 32a080
            l32i         a0, a1, 92 /* [(local10)] */          #  233: 022117
            add.n        a1, a1, a3 /* (local16) */            #  236: 3a11
            ret.n                                              #  238: 0df0
