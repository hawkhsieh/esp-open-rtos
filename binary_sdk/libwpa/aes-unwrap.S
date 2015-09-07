
            .section     .irom0.literal, "ax", @progbits

            .section     .text, "ax", @progbits

            .section     .data, "aw", @progbits

            .section     .bss, "aw", @nobits

            .section     .irom0.text, "ax", @progbits

.Lrel001:   .word        memcpy                                #    0: 00000000
.Lrel002:   .word        memcpy                                #    4: 00000000
.Lrel003:   .word        sdk_aes_decrypt_init                  #    8: 00000000
.Lrel004:   .word        memcpy                                #    c: 00000000
.Lrel005:   .word        memcpy                                #   10: 00000000
.Lrel006:   .word        sdk_aes_decrypt                       #   14: 00000000
.Lrel007:   .word        memcpy                                #   18: 00000000
.Lrel008:   .word        memcpy                                #   1c: 00000000
.Lrel009:   .word        sdk_aes_decrypt_deinit                #   20: 00000000

# Function @ .irom0.text+0x24
# Local variables/stack:
#     (local0):  byte[9]   @ -0x39
#     (local1):  word      @ -0x30
#     (local2):  word      @ -0x2c
#     (local3):  word      @ -0x28
#     (local4):  word      @ -0x24
#     (local5):  word      @ -0x20
#     (local6):  word      @ -0x1c
#     (local7):  word      @ -0x18
#     (local8):  word      @ -0x14
#     (local9):  word[4]   @ -0x10
.literal_position
sdk_aes_unwrap:
            addi         a1, a1, -80 /* (FP)-0x50 */           #   24: 12c1b0
            s32i.n       a15, a1, 48 /* a15 -> [(local5)] */   #   27: f9c1
            s32i.n       a0, a1, 32 /* a0 -> [(local1)] */     #   29: 0981
            s32i.n       a12, a1, 36 /* a12 -> [(local2)] */   #   2b: c991
            s32i.n       a14, a1, 44 /* a14 -> [(local4)] */   #   2d: e9b1
            s32i.n       a13, a1, 40 /* a13 -> [(local3)] */   #   2f: d9a1
            s32i.n       a3, a1, 60 /* arg1 -> [(local8)] */   #   31: 39f1
            mov.n        a13, a5 /* arg3 */                    #   33: dd05
            mov.n        a3, a4 /* arg2 */                     #   35: 3d04
            mov.n        a14, a2 /* arg0 */                    #   37: ed02
            mov.n        a12, a4 /* arg2 */                    #   39: cd04
            mov.n        a2, a1 /* (FP)-0x50 */                #   3b: 2d01
            movi.n       a4, 8 /* 0x00000008 */                #   3d: 0c84
            movi         a0, .Lrel001 /* memcpy */             #   3f: 01f0ff
            callx0       a0 /* memcpy */                       #   42: c00000
            addi.n       a3, a12, 8 /* arg2+0x8 */             #   45: 8b3c
            l32i.n       a12, a1, 60 /* [(local8)] */          #   47: c8f1
            mov.n        a2, a13 /* arg3 */                    #   49: 2d0d
            slli         a12, a12, 3                           #   4b: d0cc11
            mov.n        a4, a12                               #   4e: 4d0c
            movi         a0, .Lrel002 /* memcpy */             #   50: 01edff
            callx0       a0 /* memcpy */                       #   53: c00000
            mov.n        a2, a14 /* arg0 */                    #   56: 2d0e
            movi.n       a3, 16 /* 0x00000010 */               #   58: 1c03
            movi         a0, .Lrel003 /* sdk_aes_decrypt_init */ #   5a: 01ebff
            callx0       a0 /* sdk_aes_decrypt_init */         #   5d: c00000
            mov.n        a0, a2                                #   60: 0d02
            beqz         a2, .Lbr006                           #   62: 16920a
            addi         a14, a1, 24 /* (FP)-0x38 */           #   65: e2c118
            s32i         a0, a1, 64 /* a0 -> [(local9)] */     #   68: 026110
            l32i.n       a15, a1, 60 /* [(local8)] */          #   6b: f8f1
            add.n        a2, a12, a13                          #   6d: da2c
            movi.n       a3, 5 /* 0x00000005 */                #   6f: 0c53
            s32i.n       a3, a1, 56 /* 0x00000005 -> [(local7)] */ #   71: 39e1
            addi         a2, a2, -8                            #   73: 22c2f8
            addx4        a15, a15, a15                         #   76: f0ffa0
            s32i.n       a2, a1, 52 /* a2 -> [(local6)] */     #   79: 29d1
.Lbr001:    l32i.n       a0, a1, 60 /* [(local8)] */           #   7b: 08f1
            l32i.n       a12, a1, 52 /* [(local6)] */          #   7d: c8d1
            blti         a0, 1, .Lbr003                        #   7f: a61052
            add.n        a13, a15, a0                          #   82: 0adf
.Lbr002:    addi         a2, a1, 16 /* (FP)-0x40 */            #   84: 22c110
            mov.n        a3, a1 /* (FP)-0x50 */                #   87: 3d01
            movi.n       a4, 8 /* 0x00000008 */                #   89: 0c84
            movi         a0, .Lrel004 /* .Lrel004 */           #   8b: 01e0ff
            callx0       a0                                    #   8e: c00000
            mov.n        a2, a14 /* (FP)-0x38 */               #   91: 2d0e
            mov.n        a3, a12                               #   93: 3d0c
            l8ui         a0, a1, 23 /* [(local0)] */           #   95: 020117
            movi.n       a4, 8 /* 0x00000008 */                #   98: 0c84
            xor          a0, a13, a0                           #   9a: 000d30
            s8i          a0, a1, 23 /* a0 -> [(local0)] */     #   9d: 024117
            movi         a0, .Lrel005 /* .Lrel005 */           #   a0: 01dcff
            callx0       a0                                    #   a3: c00000
            l32i         a2, a1, 64 /* [(local9)] */           #   a6: 222110
            addi         a3, a1, 16 /* (FP)-0x40 */            #   a9: 32c110
            mov.n        a4, a3 /* (FP)-0x40 */                #   ac: 4d03
            movi         a0, .Lrel006 /* .Lrel006 */           #   ae: 01d9ff
            callx0       a0                                    #   b1: c00000
            mov.n        a2, a1 /* (FP)-0x50 */                #   b4: 2d01
            addi         a3, a1, 16 /* (FP)-0x40 */            #   b6: 32c110
            movi.n       a4, 8 /* 0x00000008 */                #   b9: 0c84
            movi         a0, .Lrel007 /* .Lrel007 */           #   bb: 01d7ff
            callx0       a0                                    #   be: c00000
            mov.n        a2, a12                               #   c1: 2d0c
            mov.n        a3, a14 /* (FP)-0x38 */               #   c3: 3d0e
            movi.n       a4, 8 /* 0x00000008 */                #   c5: 0c84
            movi         a0, .Lrel008 /* .Lrel008 */           #   c7: 01d5ff
            callx0       a0                                    #   ca: c00000
            addi         a12, a12, -8                          #   cd: c2ccf8
            addi.n       a13, a13, -1                          #   d0: 0bdd
            bne          a15, a13, .Lbr002                     #   d2: d79fae
.Lbr003:    l32i.n       a3, a1, 60 /* [(local8)] */           #   d5: 38f1
            l32i.n       a2, a1, 56 /* [(local7)] */           #   d7: 28e1
            sub          a15, a15, a3                          #   d9: 30ffc0
            addi.n       a2, a2, -1 /* [(local7)]-0x1 */       #   dc: 0b22
            s32i.n       a2, a1, 56 /* [(local7)]-0x1 -> [(local7)] */ #   de: 29e1
            bnei         a2, -1, .Lbr001                       #   e0: 660297
            l32i         a2, a1, 64 /* [(local9)] */           #   e3: 222110
            movi         a0, .Lrel009 /* sdk_aes_decrypt_deinit */ #   e6: 01ceff
            callx0       a0 /* sdk_aes_decrypt_deinit */       #   e9: c00000
            mov.n        a0, a1 /* (FP)-0x50 */                #   ec: 0d01
            addi.n       a2, a1, 8 /* (FP)-0x48 */             #   ee: 8b21
            movi         a3, 166 /* 0x000000a6 */              #   f0: 32a0a6
.Lbr004:    l8ui         a4, a0, 0                             #   f3: 420000
            addi.n       a0, a0, 1                             #   f6: 1b00
            bne          a4, a3, .Lbr006                       #   f8: 379413
            bne          a0, a2, .Lbr004                       #   fb: 2790f4
            movi.n       a2, 0 /* 0x00000000 */                #   fe: 0c02
.Lbr005:    l32i.n       a12, a1, 36 /* [(local2)] */          #  100: c891
            l32i.n       a13, a1, 40 /* [(local3)] */          #  102: d8a1
            l32i.n       a14, a1, 44 /* [(local4)] */          #  104: e8b1
            l32i.n       a15, a1, 48 /* [(local5)] */          #  106: f8c1
            l32i.n       a0, a1, 32 /* [(local1)] */           #  108: 0881
            addi         a1, a1, 80 /* (top of frame) */       #  10a: 12c150
            ret.n                                              #  10d: 0df0
.Lbr006:    movi.n       a2, -1 /* 0xffffffff */               #  10f: 7cf2
            j            .Lbr005                               #  111: c6faff
