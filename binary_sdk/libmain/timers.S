
            .section     .irom0.literal, "ax", @progbits

            .section     .text, "ax", @progbits

            .section     .data, "aw", @progbits

            .section     .bss, "aw", @nobits

.Ldata001:  .word        0x00000000                            #    0: 00000000
.Ldata002:  .byte        0x00

            .section     .irom0.text, "ax", @progbits

.Lrel001:   .word        .bss                                  #    0: 00000000
.Lrel002:   .word        .rodata.str1.4                        #    4: 00000000
.Lrel003:   .word        xTimerGenericCommand                  #    8: 00000000
.Lrel004:   .word        printf                                #    c: 00000000
.Lrel005:   .word        pvPortMalloc                          #   10: 00000000

# Function @ .irom0.text+0x14
# Local variables/stack:
#     (local0):  word      @ -0x20
#     (local1):  word      @ -0x1c
#     (local2):  word      @ -0x18
#     (local3):  word      @ -0x14
#     (local4):  word      @ -0x10
#     (local5):  word[3]   @ -0xc
.literal_position
sdk_os_timer_setfn:
            addi         a1, a1, -32 /* (local0) */            #   14: 12c1e0
            s32i.n       a0, a1, 0 /* a0 -> [(local0)] */      #   17: 0901
            s32i.n       a14, a1, 12 /* a14 -> [(local3)] */   #   19: e931
            s32i.n       a13, a1, 8 /* a13 -> [(local2)] */    #   1b: d921
            s32i.n       a12, a1, 4 /* a12 -> [(local1)] */    #   1d: c911
            s32i.n       a15, a1, 16 /* a15 -> [(local4)] */   #   1f: f941
            movi         a15, .Lrel001 /* .Ldata001 */         #   21: f1f7ff
            mov.n        a12, a2 /* arg0 */                    #   24: cd02
            l32i.n       a13, a15, 0 /* [.Ldata001] */         #   26: d80f
            mov.n        a14, a4 /* arg2 */                    #   28: ed04
            beqz         a13, .Lbr006                          #   2a: 16fd04
.Lbr001:    l32i.n       a0, a13, 4                            #   2d: 081d
            bne          a0, a12, .Lbr005                      #   2f: c79041
            l32i.n       a2, a12, 24 /* [arg0+0x18] */         #   32: 286c
            l32i.n       a4, a12, 16 /* [arg0+0x10] */         #   34: 484c
            bne          a2, a14, .Lbr002                      #   36: e79202
            beq          a4, a3, .Lbr007                       #   39: 37145f
.Lbr002:    l32i.n       a2, a12, 4 /* [arg0+0x4] */           #   3c: 281c
            s32i.n       a3, a1, 20 /* arg1 -> [(local5)] */   #   3e: 3951
            beqz.n       a2, .Lbr004                           #   40: ac32
            movi.n       a3, 3 /* 0x00000003 */                #   42: 0c33
            movi.n       a4, 0 /* 0x00000000 */                #   44: 0c04
            movi.n       a5, 0 /* 0x00000000 */                #   46: 0c05
            movi.n       a6, 50 /* 0x00000032 */               #   48: 3c26
            movi         a0, .Lrel003 /* .Lrel003 */           #   4a: 01efff
            callx0       a0                                    #   4d: c00000
            l32i.n       a3, a1, 20 /* [(local5)] */           #   50: 3851
            bnez.n       a2, .Lbr003                           #   52: cc92
            movi         a2, .Lrel002 /* .Lrel002 */           #   54: 21ecff
            movi         a0, .Lrel004 /* .Lrel004 */           #   57: 01edff
            callx0       a0                                    #   5a: c00000
            l32i.n       a3, a1, 20 /* [(local5)] */           #   5d: 3851
.Lbr003:    l8ui         a5, a15, 4 /* [.Ldata002] */          #   5f: 520f04
            addi.n       a5, a5, -1 /* [.Ldata002]-0x1 */      #   62: 0b55
            s8i          a5, a15, 4 /* [.Ldata002]-0x1 -> [.Ldata002] */ #   64: 524f04
.Lbr004:    s32i.n       a3, a12, 16 /* a3 -> [arg0+0x10] */   #   67: 394c
            s32i.n       a14, a12, 24 /* arg2 -> [arg0+0x18] */ #   69: e96c
            movi.n       a6, 0 /* 0x00000000 */                #   6b: 0c06
            s32i.n       a6, a12, 4 /* 0x00000000 -> [arg0+0x4] */ #   6d: 691c
            s32i.n       a6, a12, 12 /* 0x00000000 -> [arg0+0xc] */ #   6f: 693c
            j            .Lbr007                               #   71: c60900
.Lbr005:    l32i.n       a0, a13, 0                            #   74: 080d
            beqz.n       a0, .Lbr006                           #   76: 8c30
            mov.n        a13, a0                               #   78: dd00
            bnez         a0, .Lbr001                           #   7a: 56f0fa
.Lbr006:    s32i.n       a3, a12, 16 /* arg1 -> [arg0+0x10] */ #   7d: 394c
            s32i.n       a14, a12, 24 /* arg2 -> [arg0+0x18] */ #   7f: e96c
            movi.n       a2, 8 /* 0x00000008 */                #   81: 0c82
            movi.n       a7, 0 /* 0x00000000 */                #   83: 0c07
            s32i.n       a7, a12, 4 /* 0x00000000 -> [arg0+0x4] */ #   85: 791c
            s32i.n       a7, a12, 12 /* 0x00000000 -> [arg0+0xc] */ #   87: 793c
            movi         a0, .Lrel005 /* pvPortMalloc */       #   89: 01e1ff
            callx0       a0 /* pvPortMalloc */                 #   8c: c00000
            s32i.n       a12, a2, 4                            #   8f: c912
            movi.n       a9, 0 /* 0x00000000 */                #   91: 0c09
            l32i.n       a8, a15, 0 /* [.Ldata001] */          #   93: 880f
            s32i.n       a9, a2, 0                             #   95: 9902
            movnez       a15, a13, a8                          #   97: 80fd93
            s32i.n       a2, a15, 0                            #   9a: 290f
.Lbr007:    l32i.n       a12, a1, 4 /* [(local1)] */           #   9c: c811
            l32i.n       a13, a1, 8 /* [(local2)] */           #   9e: d821
            l32i.n       a14, a1, 12 /* [(local3)] */          #   a0: e831
            l32i.n       a15, a1, 16 /* [(local4)] */          #   a2: f841
            l32i.n       a0, a1, 0 /* [(local0)] */            #   a4: 0801
            addi         a1, a1, 32 /* (top of frame) */       #   a6: 12c120
            ret.n                                              #   a9: 0df0

            .balign      4
.Lrel006:   .word        .bss                                  #   ac: 00000000
.Lrel007:   .word        .Lstr002                              #   b0: 18000000
.Lrel008:   .word        __udivsi3                             #   b4: 00000000
.Lrel009:   .word        xTimerCreate                          #   b8: 00000000
.Lrel010:   .word        __udivsi3                             #   bc: 00000000
.Lrel011:   .word        xTimerGenericCommand                  #   c0: 00000000
.Lrel012:   .word        xTaskGetTickCount                     #   c4: 00000000
.Lrel013:   .word        xTimerGenericCommand                  #   c8: 00000000
.Lrel014:   .word        printf                                #   cc: 00000000

# Function @ .irom0.text+0xd0
# Local variables/stack:
#     (local0):  word      @ -0x20
#     (local1):  word      @ -0x1c
#     (local2):  word      @ -0x18
#     (local3):  word      @ -0x14
#     (local4):  word[4]   @ -0x10
.literal_position
sdk_os_timer_arm:
            addi         a1, a1, -32 /* (local0) */            #   d0: 12c1e0
            s32i.n       a0, a1, 0 /* a0 -> [(local0)] */      #   d3: 0901
            s32i.n       a13, a1, 8 /* a13 -> [(local2)] */    #   d5: d921
            s32i.n       a15, a1, 16 /* a15 -> [(local4)] */   #   d7: f941
            s32i.n       a12, a1, 4 /* a12 -> [(local1)] */    #   d9: c911
            s32i.n       a14, a1, 12 /* a14 -> [(local3)] */   #   db: e931
            mov.n        a12, a2 /* arg0 */                    #   dd: cd02
            mov.n        a14, a3 /* arg1 */                    #   df: ed03
            l32i.n       a15, a2, 4 /* [arg0+0x4] */           #   e1: f812
            mov.n        a13, a4 /* arg2 */                    #   e3: dd04
            bnez.n       a15, .Lbr008                          #   e5: ecff
            s8i          a4, a2, 20 /* arg2 -> [arg0+0x14] */  #   e7: 424214
            s32i.n       a3, a2, 12 /* arg1 -> [arg0+0xc] */   #   ea: 3932
            mov.n        a2, a3 /* arg1 */                     #   ec: 2d03
            movi.n       a3, 10 /* 0x0000000a */               #   ee: 0ca3
            movi         a0, .Lrel008 /* __udivsi3 */          #   f0: 01f1ff
            callx0       a0 /* __udivsi3 */                    #   f3: c00000
            mov.n        a4, a13 /* arg2 */                    #   f6: 4d0d
            l32i.n       a5, a12, 24 /* [arg0+0x18] */         #   f8: 586c
            mov.n        a3, a2                                #   fa: 3d02
            l32i.n       a6, a12, 16 /* [arg0+0x10] */         #   fc: 684c
            movi.n       a2, 0 /* 0x00000000 */                #   fe: 0c02
            movi         a0, .Lrel009 /* xTimerCreate */       #  100: 01eeff
            callx0       a0 /* xTimerCreate */                 #  103: c00000
            movi         a3, .Lrel006 /* .Ldata001 */          #  106: 31e9ff
            mov.n        a15, a2                               #  109: fd02
            l8ui         a0, a3, 4 /* [.Ldata002] */           #  10b: 020304
            s32i.n       a2, a12, 4 /* a2 -> [arg0+0x4] */     #  10e: 291c
            addi.n       a0, a0, 1 /* [.Ldata002]+0x1 */       #  110: 1b00
            s8i          a0, a3, 4 /* [.Ldata002]+0x1 -> [.Ldata002] */ #  112: 024304
            beqz         a2, .Lbr011                           #  115: 16c204
.Lbr008:    l8ui         a3, a12, 20 /* [arg0+0x14] */         #  118: 320c14
            beq          a3, a13, .Lbr009                      #  11b: d71304
            s8i          a13, a12, 20 /* arg2 -> [arg0+0x14] */ #  11e: d24c14
            s32i.n       a13, a15, 28                          #  121: d97f
.Lbr009:    l32i.n       a4, a12, 12 /* [arg0+0xc] */          #  123: 483c
            beq          a4, a14, .Lbr010                      #  125: e7141b
            mov.n        a2, a14 /* arg1 */                    #  128: 2d0e
            s32i.n       a14, a12, 12 /* arg1 -> [arg0+0xc] */ #  12a: e93c
            movi.n       a3, 10 /* 0x0000000a */               #  12c: 0ca3
            movi         a0, .Lrel010 /* __udivsi3 */          #  12e: 01e3ff
            callx0       a0 /* __udivsi3 */                    #  131: c00000
            movi.n       a3, 2 /* 0x00000002 */                #  134: 0c23
            movi.n       a5, 0 /* 0x00000000 */                #  136: 0c05
            mov.n        a4, a2                                #  138: 4d02
            movi.n       a6, 10 /* 0x0000000a */               #  13a: 0ca6
            mov.n        a2, a15                               #  13c: 2d0f
            movi         a0, .Lrel011 /* xTimerGenericCommand */ #  13e: 01e0ff
            callx0       a0 /* xTimerGenericCommand */         #  141: c00000
.Lbr010:    movi         a0, .Lrel012 /* xTaskGetTickCount */  #  144: 01e0ff
            callx0       a0 /* xTaskGetTickCount */            #  147: c00000
            movi.n       a3, 0 /* 0x00000000 */                #  14a: 0c03
            movi.n       a5, 0 /* 0x00000000 */                #  14c: 0c05
            mov.n        a4, a2                                #  14e: 4d02
            movi.n       a6, 50 /* 0x00000032 */               #  150: 3c26
            l32i.n       a2, a12, 4 /* [arg0+0x4] */           #  152: 281c
            movi         a0, .Lrel013 /* xTimerGenericCommand */ #  154: 01ddff
            callx0       a0 /* xTimerGenericCommand */         #  157: c00000
            bnez.n       a2, .Lbr011                           #  15a: cc72
            movi         a2, .Lrel007 /* .Lstr002 */           #  15c: 21d5ff
            movi         a0, .Lrel014 /* printf */             #  15f: 01dbff
            callx0       a0 /* printf */                       #  162: c00000
.Lbr011:    l32i.n       a12, a1, 4 /* [(local1)] */           #  165: c811
            l32i.n       a13, a1, 8 /* [(local2)] */           #  167: d821
            l32i.n       a14, a1, 12 /* [(local3)] */          #  169: e831
            l32i.n       a15, a1, 16 /* [(local4)] */          #  16b: f841
            l32i.n       a0, a1, 0 /* [(local0)] */            #  16d: 0801
            addi         a1, a1, 32 /* (top of frame) */       #  16f: 12c120
            ret.n                                              #  172: 0df0

.Lrel015:   .word        .Lstr003                              #  174: 2c000000
.Lrel016:   .word        xTimerGenericCommand                  #  178: 00000000
.Lrel017:   .word        printf                                #  17c: 00000000

# Function @ .irom0.text+0x180
# Local variables/stack:
#     (local0):  word[4]   @ -0x10
.literal_position
sdk_os_timer_disarm:
            addi         a1, a1, -16 /* (local0) */            #  180: 12c1f0
            l32i.n       a2, a2, 4 /* [arg0+0x4] */            #  183: 2812
            s32i.n       a0, a1, 0 /* a0 -> [(local0)] */      #  185: 0901
            beqz.n       a2, .Lbr012                           #  187: 9c72
            movi.n       a3, 1 /* 0x00000001 */                #  189: 0c13
            movi.n       a4, 0 /* 0x00000000 */                #  18b: 0c04
            movi.n       a5, 0 /* 0x00000000 */                #  18d: 0c05
            movi.n       a6, 50 /* 0x00000032 */               #  18f: 3c26
            movi         a0, .Lrel016 /* xTimerGenericCommand */ #  191: 01f9ff
            callx0       a0 /* xTimerGenericCommand */         #  194: c00000
            bnez.n       a2, .Lbr012                           #  197: cc72
            movi         a2, .Lrel015 /* .Lstr003 */           #  199: 21f6ff
            movi         a0, .Lrel017 /* printf */             #  19c: 01f8ff
            callx0       a0 /* printf */                       #  19f: c00000
.Lbr012:    l32i.n       a0, a1, 0 /* [(local0)] */            #  1a2: 0801
            addi         a1, a1, 16 /* (top of frame) */       #  1a4: 12c110
            ret.n                                              #  1a7: 0df0

            .section     .rodata.str1.4, "MSa", @progbits, 1

.Lstr001:   .asciz       "Timer Delete Failed\n"               #    0: 54696d65
                                                               #    4: 72204465
                                                               #    8: 6c657465
                                                               #    c: 20466169
                                                               #   10: 6c65640a
                                                               #   14: 00
            .balign      4
.Lstr002:   .asciz       "Timer Start Failed\n"                #   18: 54696d65
                                                               #   1c: 72205374
                                                               #   20: 61727420
                                                               #   24: 4661696c
                                                               #   28: 65640a00
.Lstr003:   .asciz       "Timer Stop Failed\n"                 #   2c: 54696d65
                                                               #   30: 72205374
                                                               #   34: 6f702046
                                                               #   38: 61696c65
                                                               #   3c: 640a00
