
            .section     .irom0.literal, "ax", @progbits

            .section     .text, "ax", @progbits

            .section     .data, "aw", @progbits

            .section     .bss, "aw", @nobits

            .section     .irom0.text, "ax", @progbits

.Lrel001:   .word        memset                                #    0: 00000000
.Lrel002:   .word        memcpy                                #    4: 00000000
.Lrel003:   .word        sdk_aes_encrypt_init                  #    8: 00000000
.Lrel004:   .word        memcpy                                #    c: 00000000
.Lrel005:   .word        memcpy                                #   10: 00000000
.Lrel006:   .word        sdk_aes_encrypt                       #   14: 00000000
.Lrel007:   .word        memcpy                                #   18: 00000000
.Lrel008:   .word        memcpy                                #   1c: 00000000
.Lrel009:   .word        sdk_aes_encrypt_deinit                #   20: 00000000

# Function @ .irom0.text+0x24
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
#     (local9):  word      @ -0xc
#     (local10): word      @ -0x8
#     (local11): word      @ -0x4
.literal_position
sdk_aes_wrap:
            addi         a1, a1, -64 /* (FP)-0x40 */           #   24: 12c1c0
            s32i.n       a15, a1, 32 /* a15 -> [(local4)] */   #   27: f981
            s32i.n       a0, a1, 16 /* a0 -> [(local0)] */     #   29: 0941
            s32i.n       a12, a1, 20 /* a12 -> [(local1)] */   #   2b: c951
            s32i.n       a13, a1, 24 /* a13 -> [(local2)] */   #   2d: d961
            s32i.n       a14, a1, 28 /* a14 -> [(local3)] */   #   2f: e971
            s32i.n       a3, a1, 48 /* arg1 -> [(local8)] */   #   31: 39c1
            mov.n        a14, a5 /* arg3 */                    #   33: ed05
            movi         a3, 166 /* 0x000000a6 */              #   35: 32a0a6
            mov.n        a13, a2 /* arg0 */                    #   38: dd02
            mov.n        a12, a4 /* arg2 */                    #   3a: cd04
            mov.n        a2, a5 /* arg3 */                     #   3c: 2d05
            movi.n       a4, 8 /* 0x00000008 */                #   3e: 0c84
            movi         a0, .Lrel001 /* memset */             #   40: 01f0ff
            callx0       a0 /* memset */                       #   43: c00000
            mov.n        a3, a12 /* arg2 */                    #   46: 3d0c
            l32i.n       a4, a1, 48 /* [(local8)] */           #   48: 48c1
            addi.n       a2, a14, 8 /* arg3+0x8 */             #   4a: 8b2e
            s32i.n       a2, a1, 40 /* arg3+0x8 -> [(local6)] */ #   4c: 29a1
            slli         a4, a4, 3                             #   4e: d04411
            movi         a0, .Lrel002 /* memcpy */             #   51: 01ecff
            callx0       a0 /* memcpy */                       #   54: c00000
            mov.n        a2, a13 /* arg0 */                    #   57: 2d0d
            movi.n       a3, 16 /* 0x00000010 */               #   59: 1c03
            movi         a0, .Lrel003 /* sdk_aes_encrypt_init */ #   5b: 01ebff
            callx0       a0 /* sdk_aes_encrypt_init */         #   5e: c00000
            bnez.n       a2, .Lbr001                           #   61: cc32
            movi.n       a2, -1 /* 0xffffffff */               #   63: 7cf2
            j            .Lbr005                               #   65: c62200
.Lbr001:    addi.n       a15, a1, 8 /* (FP)-0x38 */            #   68: 8bf1
            s32i.n       a2, a1, 56 /* a2 -> [(local10)] */    #   6a: 29e1
            l32i.n       a6, a1, 48 /* [(local8)] */           #   6c: 68c1
            movi.n       a5, 0 /* 0x00000000 */                #   6e: 0c05
            movi.n       a7, 0 /* 0x00000000 */                #   70: 0c07
            s32i.n       a7, a1, 52 /* 0x00000000 -> [(local9)] */ #   72: 79d1
            s32i.n       a5, a1, 44 /* 0x00000000 -> [(local7)] */ #   74: 59b1
            addi.n       a6, a6, 1 /* [(local8)]+0x1 */        #   76: 1b66
            s32i.n       a6, a1, 36 /* [(local8)]+0x1 -> [(local5)] */ #   78: 6991
.Lbr002:    l32i.n       a8, a1, 48 /* [(local8)] */           #   7a: 88c1
            l32i.n       a12, a1, 40 /* [(local6)] */          #   7c: c8a1
            blti         a8, 1, .Lbr004                        #   7e: a61857
            l32i.n       a9, a1, 52 /* [(local9)] */           #   81: 98d1
            l32i.n       a10, a1, 36 /* [(local5)] */          #   83: a891
            addi.n       a13, a9, 1 /* [(local9)]+0x1 */       #   85: 1bd9
            add.n        a9, a9, a10                           #   87: aa99
            s32i.n       a9, a1, 60 /* a9 -> [(local11)] */    #   89: 99f1
.Lbr003:    mov.n        a2, a1 /* (FP)-0x40 */                #   8b: 2d01
            mov.n        a3, a14 /* arg3 */                    #   8d: 3d0e
            movi.n       a4, 8 /* 0x00000008 */                #   8f: 0c84
            movi         a0, .Lrel004 /* .Lrel004 */           #   91: 01deff
            callx0       a0                                    #   94: c00000
            mov.n        a2, a15 /* (FP)-0x38 */               #   97: 2d0f
            mov.n        a3, a12                               #   99: 3d0c
            movi.n       a4, 8 /* 0x00000008 */                #   9b: 0c84
            movi         a0, .Lrel005 /* .Lrel005 */           #   9d: 01dcff
            callx0       a0                                    #   a0: c00000
            l32i.n       a2, a1, 56 /* [(local10)] */          #   a3: 28e1
            mov.n        a3, a1 /* (FP)-0x40 */                #   a5: 3d01
            mov.n        a4, a1 /* (FP)-0x40 */                #   a7: 4d01
            movi         a0, .Lrel006 /* .Lrel006 */           #   a9: 01daff
            callx0       a0                                    #   ac: c00000
            mov.n        a2, a14 /* arg3 */                    #   af: 2d0e
            mov.n        a3, a1 /* (FP)-0x40 */                #   b1: 3d01
            movi.n       a4, 8 /* 0x00000008 */                #   b3: 0c84
            movi         a0, .Lrel007 /* .Lrel007 */           #   b5: 01d8ff
            callx0       a0                                    #   b8: c00000
            mov.n        a2, a12                               #   bb: 2d0c
            mov.n        a3, a15 /* (FP)-0x38 */               #   bd: 3d0f
            l8ui         a11, a14, 7 /* [arg3+0x7] */          #   bf: b20e07
            movi.n       a4, 8 /* 0x00000008 */                #   c2: 0c84
            xor          a11, a13, a11                         #   c4: b0bd30
            s8i          a11, a14, 7 /* a11 -> [arg3+0x7] */   #   c7: b24e07
            movi         a0, .Lrel008 /* .Lrel008 */           #   ca: 01d4ff
            callx0       a0                                    #   cd: c00000
            addi.n       a12, a12, 8                           #   d0: 8bcc
            l32i.n       a0, a1, 60 /* [(local11)] */          #   d2: 08f1
            addi.n       a13, a13, 1                           #   d4: 1bdd
            bne          a13, a0, .Lbr003                      #   d6: 079db1
.Lbr004:    l32i.n       a4, a1, 48 /* [(local8)] */           #   d9: 48c1
            l32i.n       a2, a1, 44 /* [(local7)] */           #   db: 28b1
            l32i.n       a3, a1, 52 /* [(local9)] */           #   dd: 38d1
            addi.n       a2, a2, 1 /* [(local7)]+0x1 */        #   df: 1b22
            s32i.n       a2, a1, 44 /* [(local7)]+0x1 -> [(local7)] */ #   e1: 29b1
            add.n        a3, a3, a4                            #   e3: 4a33
            s32i.n       a3, a1, 52 /* a3 -> [(local9)] */     #   e5: 39d1
            bnei         a2, 6, .Lbr002                        #   e7: 66628f
            l32i.n       a2, a1, 56 /* [(local10)] */          #   ea: 28e1
            movi         a0, .Lrel009 /* sdk_aes_encrypt_deinit */ #   ec: 01cdff
            callx0       a0 /* sdk_aes_encrypt_deinit */       #   ef: c00000
            movi.n       a2, 0 /* 0x00000000 */                #   f2: 0c02
.Lbr005:    l32i.n       a12, a1, 20 /* [(local1)] */          #   f4: c851
            l32i.n       a13, a1, 24 /* [(local2)] */          #   f6: d861
            l32i.n       a14, a1, 28 /* [(local3)] */          #   f8: e871
            l32i.n       a15, a1, 32 /* [(local4)] */          #   fa: f881
            l32i.n       a0, a1, 16 /* [(local0)] */           #   fc: 0841
            addi         a1, a1, 64 /* (top of frame) */       #   fe: 12c140
            ret.n                                              #  101: 0df0
