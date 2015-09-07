
            .section     .irom0.literal, "ax", @progbits

            .section     .literal, "ax", @progbits

            .section     .text, "ax", @progbits

# NOTE: The following is apparently unreferenced code/data
.Llit001:   .word        0x3feffe00                            #    0: 00feef3f

.Lrel001:   .word        .rodata.str1.4                        #    4: 00000000
.Lrel002:   .word        .Lstr002                              #    8: 24000000
.Lrel003:   .word        printf                                #    c: 00000000
.Lrel004:   .word        printf                                #   10: 00000000

# Function @ .text+0x14
# Local variables/stack:
#     (local0):  word[4]   @ -0x10
.literal_position
.Lfunc001:  addi         a1, a1, -16 /* (local0) */            #   14: 12c1f0
            s32i.n       a0, a1, 0 /* a0 -> [(local0)] */      #   17: 0901
            movi         a0, .Llit001 /* 0x3feffe00 */         #   19: 01f9ff
            memw                                               #   1c: c02000
            l32i         a5, a0, 0x25c /* [0x3ff0005c] */      #   1f: 522097
            memw                                               #   22: c02000
            l32i         a6, a0, 0x258 /* [0x3ff00058] */      #   25: 622096
            memw                                               #   28: c02000
            l32i         a4, a0, 0x254 /* [0x3ff00054] */      #   2b: 422095
            memw                                               #   2e: c02000
            l32i         a0, a0, 0x250 /* [0x3ff00050] */      #   31: 022094
            bbsi         a6, 15, .Lbr002                       #   34: f7e60b
            movi         a2, .Lrel001 /* .Lstr001 */           #   37: 21f3ff
            movi         a0, .Lrel003 /* printf */             #   3a: 01f4ff
            callx0       a0 /* printf */                       #   3d: c00000
.Lbr001:    j            .Lbr001 /* (halt) */                  #   40: 06ffff
.Lbr002:    bnez.n       a0, .Lbr004                           #   43: ccc0
            bnez.n       a4, .Lbr004                           #   45: cca4
            movi         a2, .Lrel002 /* .Lstr002 */           #   47: 21f0ff
            movi         a0, .Lrel004 /* printf */             #   4a: 01f1ff
            callx0       a0 /* printf */                       #   4d: c00000
.Lbr003:    j            .Lbr003 /* (halt) */                  #   50: 06ffff
.Lbr004:    extui        a7, a0, 24, 8                         #   53: 007875
            srli         a8, a4, 8                             #   56: 408841
            bbsi         a6, 12, .Lbr006                       #   59: c7e61e
            movi.n       a5, 52 /* 0x00000034 */               #   5c: 3c45
            movi.n       a6, 24 /* 0x00000018 */               #   5e: 1c86
            movi.n       a3, -2 /* 0xfffffffe */               #   60: 7ce3
            s8i          a3, a2, 1 /* 0xfe -> [arg0+0x1] */    #   62: 324201
            s8i          a6, a2, 0 /* 0x18 -> [arg0] */        #   65: 624200
.Lbr005:    s8i          a7, a2, 5 /* a7 -> [arg0+0x5] */      #   68: 724205
            s8i          a4, a2, 4 /* [0x3ff00054] -> [arg0+0x4] */ #   6b: 424204
            s8i          a5, a2, 2 /* a5 -> [arg0+0x2] */      #   6e: 524202
            s8i          a8, a2, 3 /* a8 -> [arg0+0x3] */      #   71: 824203
            l32i.n       a0, a1, 0 /* [(local0)] */            #   74: 0801
            addi         a1, a1, 16 /* (top of frame) */       #   76: 12c110
            ret.n         /* arg0 */                           #   79: 0df0
.Lbr006:    srli         a9, a5, 8                             #   7b: 509841
            extui        a10, a5, 16, 16                       #   7e: 50a0f5
            s8i          a10, a2, 0 /* a10 -> [arg0] */        #   81: a24200
            s8i          a9, a2, 1 /* a9 -> [arg0+0x1] */      #   84: 924201
            j            .Lbr005                               #   87: 46f7ff

# NOTE: The following is apparently unreferenced code/data
            .balign      4
.Llit002:   .word        0x60000200                            #   8c: 00020060
.Llit003:   .word        0x60000600                            #   90: 00060060
.Llit004:   .word        0x00001000                            #   94: 00100000
.Llit005:   .word        0xffffefff                            #   98: ffefffff
.Llit006:   .word        0xfffff000                            #   9c: 00f0ffff

# Function @ .text+0xa0
.literal_position
.Lfunc002:  movi         a4, .Llit002 /* 0x60000200 */         #   a0: 41fbff
            movi         a5, .Llit003 /* 0x60000600 */         #   a3: 51fbff
            bgei         a2, 2, .Lbr007                        #   a6: e62224
            movi         a2, .Llit004 /* 0x00001000 */         #   a9: 21faff
            memw                                               #   ac: c02000
            l32i.n       a7, a4, 8 /* [0x60000208] */          #   af: 7824
            or           a7, a7, a2                            #   b1: 207720
            memw                                               #   b4: c02000
            s32i.n       a7, a4, 8 /* a7 -> [0x60000208] */    #   b7: 7924
            movi         a6, 256 /* 0x00000100 */              #   b9: 62a100
            memw                                               #   bc: c02000
            l32i         a3, a5, 0x200 /* [0x60000800] */      #   bf: 322580
            or           a3, a3, a6                            #   c2: 603320
            memw                                               #   c5: c02000
            s32i         a3, a5, 0x200 /* a3 -> [0x60000800] */ #   c8: 326580
            j            .Lbr008                               #   cb: 460e00
.Lbr007:    movi         a11, .Llit005 /* 0xffffefff */        #   ce: b1f2ff
            addi.n       a3, a2, -1 /* arg0-0x1 */             #   d1: 0b32
            addi.n       a6, a2, 1 /* arg0+0x1 */              #   d3: 1b62
            movgez       a6, a2, a2                            #   d5: 2062b3
            srai         a6, a6, 1                             #   d8: 606121
            slli         a3, a3, 8                             #   db: 803311
            addi.n       a6, a6, -1                            #   de: 0b66
            slli         a6, a6, 4                             #   e0: c06611
            add.n        a3, a3, a6                            #   e3: 6a33
            add.n        a2, a2, a3                            #   e5: 3a22
            addi.n       a2, a2, -1                            #   e7: 0b22
            memw                                               #   e9: c02000
            l32i.n       a10, a4, 8 /* [0x60000208] */         #   ec: a824
            and          a10, a10, a11                         #   ee: b0aa10
            memw                                               #   f1: c02000
            s32i.n       a10, a4, 8 /* a10 -> [0x60000208] */  #   f4: a924
            movi         a9, -257 /* 0xfffffeff */             #   f6: 92aeff
            memw                                               #   f9: c02000
            l32i         a8, a5, 0x200 /* [0x60000800] */      #   fc: 822580
            and          a8, a8, a9                            #   ff: 908810
            memw                                               #  102: c02000
            s32i         a8, a5, 0x200 /* a8 -> [0x60000800] */ #  105: 826580
.Lbr008:    movi         a6, .Llit006 /* .Llit006 */           #  108: 61e5ff
            memw                                               #  10b: c02000
            l32i.n       a5, a4, 8 /* [0x60000208] */          #  10e: 5824
            and          a5, a5, a6                            #  110: 605510
            or           a5, a5, a2                            #  113: 205520
            memw                                               #  116: c02000
            s32i.n       a5, a4, 8 /* a5 -> [0x60000208] */    #  119: 5924
            ret.n                                              #  11b: 0df0

            .balign      4
.Lrel005:   .word        sdk_NMIIrqIsOn                        #  120: 00000000

# NOTE: The following is apparently unreferenced code/data
.Llit007:   .word        0x3feffe00                            #  124: 00feef3f
.Llit008:   .word        0x00ff0000                            #  128: 0000ff00
.Llit009:   .word        0x5ffffe00                            #  12c: 00feff5f
.Llit010:   .word        0x60000e00                            #  130: 000e0060

.Lrel006:   .word        vPortEnterCritical                    #  134: 00000000
.Lrel007:   .word        Cache_Read_Disable                    #  138: 00000000
.Lrel008:   .word        Cache_Read_Enable                     #  13c: 00000000
.Lrel009:   .word        .Lfunc008                             #  140: a0020000
.Lrel010:   .word        sdk_system_restart_in_nmi             #  144: 00000000

# Function @ .text+0x148
# Local variables/stack:
#     (local0):  word[4]   @ -0x10
.literal_position
sdk_user_fatal_exception_handler:
            addi         a1, a1, -16 /* (local0) */            #  148: 12c1f0
            s32i.n       a0, a1, 0 /* a0 -> [(local0)] */      #  14b: 0901
            movi         a0, .Lrel005 /* sdk_NMIIrqIsOn */     #  14d: 01f4ff
            l8ui         a0, a0, 0 /* [sdk_NMIIrqIsOn] */      #  150: 020000
            bnez.n       a0, .Lbr010                           #  153: ec10
            movi         a0, .Lrel006 /* vPortEnterCritical */ #  155: 01f7ff
            callx0       a0 /* vPortEnterCritical */           #  158: c00000
            movi.n       a3, -32 /* 0xffffffe0 */              #  15b: 6c03
            movi         a0, .Llit007 /* 0x3feffe00 */         #  15d: 01f1ff
.Lbr009:    memw                                               #  160: c02000
            l32i         a4, a0, 0x200 /* [0x3ff00000] */      #  163: 422080
            and          a4, a4, a3                            #  166: 304410
            memw                                               #  169: c02000
            s32i         a4, a0, 0x200 /* a4 -> [0x3ff00000] */ #  16c: 426080
            memw                                               #  16f: c02000
            l32i         a2, a0, 0x200 /* [0x3ff00000] */      #  172: 222080
            bbsi         a2, 0, .Lbr009                        #  175: 07e2e7
.Lbr010:    movi         a0, .Lrel007 /* Cache_Read_Disable */ #  178: 01f0ff
            callx0       a0 /* Cache_Read_Disable */           #  17b: c00000
            movi.n       a2, 0 /* 0x00000000 */                #  17e: 0c02
            movi.n       a3, 0 /* 0x00000000 */                #  180: 0c03
            movi.n       a4, 1 /* 0x00000001 */                #  182: 0c14
            movi         a0, .Lrel008 /* Cache_Read_Enable */  #  184: 01eeff
            callx0       a0 /* Cache_Read_Enable */            #  187: c00000
            movi         a0, .Lrel009 /* .Lfunc008 */          #  18a: 01edff
            callx0       a0 /* .Lfunc008 */                    #  18d: c00000
            movi         a0, .Llit008 /* 0x00ff0000 */         #  190: 01e6ff
            movi         a4, .Llit009 /* 0x5ffffe00 */         #  193: 41e6ff
            memw                                               #  196: c02000
            l32i         a5, a4, 0x21c /* [0x6000001c] */      #  199: 522487
            bnone        a0, a5, .Lbr012                       #  19c: 570008
.Lbr011:    memw                                               #  19f: c02000
            l32i         a6, a4, 0x21c /* [0x6000001c] */      #  1a2: 622487
            bany         a6, a0, .Lbr011                       #  1a5: 0786f6
.Lbr012:    movi         a4, .Llit010 /* 0x60000e00 */         #  1a8: 41e2ff
            memw                                               #  1ab: c02000
            l32i         a7, a4, 0x11c /* [0x60000f1c] */      #  1ae: 722447
            bnone        a0, a7, .Lbr014                       #  1b1: 770008
.Lbr013:    memw                                               #  1b4: c02000
            l32i         a8, a4, 0x11c /* [0x60000f1c] */      #  1b7: 822447
            bany         a8, a0, .Lbr013                       #  1ba: 0788f6
.Lbr014:    movi         a0, .Lrel010 /* sdk_system_restart_in_nmi */ #  1bd: 01e1ff
            callx0       a0 /* sdk_system_restart_in_nmi */    #  1c0: c00000
.Lbr015:    j            .Lbr015 /* (halt) */                  #  1c3: 06ffff

# NOTE: The following is apparently unreferenced code/data
            .balign      4
.Llit011:   .word        0x00ff0000                            #  1c8: 0000ff00
.Llit012:   .word        0x5ffffe00                            #  1cc: 00feff5f

# Function @ .text+0x1d0
.literal_position
.Lfunc003:  movi         a6, .Llit011 /* 0x00ff0000 */         #  1d0: 61feff
            movi         a5, .Llit012 /* 0x5ffffe00 */         #  1d3: 51feff
            movi         a7, 125 /* 0x0000007d */              #  1d6: 72a07d
.Lbr016:    memw                                               #  1d9: c02000
            l32i         a3, a5, 0x21c /* [0x6000001c] */      #  1dc: 322587
            and          a3, a3, a6                            #  1df: 603310
            extui        a3, a3, 16, 8                         #  1e2: 303075
            bltu         a7, a3, .Lbr016                       #  1e5: 3737f0
            memw                                               #  1e8: c02000
            s32i         a2, a5, 0x200 /* arg0 -> [0x60000000] */ #  1eb: 226580
            movi.n       a2, 0 /* 0x00000000 */                #  1ee: 0c02
            ret.n         /* 0x00000000 */                     #  1f0: 0df0

            .balign      4
# Function @ .text+0x1f4
# Local variables/stack:
#     (local0):  word[4]   @ -0x10
.literal_position
.Lfunc004:  addi         a1, a1, -16 /* (local0) */            #  1f4: 12c1f0
            s32i.n       a0, a1, 0 /* a0 -> [(local0)] */      #  1f7: 0901
            bnei         a2, 10, .Lbr017                       #  1f9: 66920c
            movi.n       a2, 13 /* 0x0000000d */               #  1fc: 0cd2
            call0        .Lfunc003                             #  1fe: 05fdff
            movi.n       a2, 10 /* 0x0000000a */               #  201: 0ca2
            call0        .Lfunc003                             #  203: c5fcff
            j            .Lbr018                               #  206: c60100
.Lbr017:    movi.n       a0, 13 /* 0x0000000d */               #  209: 0cd0
            beq          a2, a0, .Lbr018                       #  20b: 071202
            call0        .Lfunc003                             #  20e: 05fcff
.Lbr018:    l32i.n       a0, a1, 0 /* [(local0)] */            #  211: 0801
            addi         a1, a1, 16 /* (top of frame) */       #  213: 12c110
            ret.n                                              #  216: 0df0

# NOTE: The following is apparently unreferenced code/data
.Llit013:   .word        0x60000200                            #  218: 00020060

.Lrel011:   .word        sdk_flashchip                         #  21c: 00000000
.Lrel012:   .word        .Lfunc004                             #  220: f4010000

# NOTE: The following is apparently unreferenced code/data
.Llit014:   .word        0x55aa55aa                            #  224: aa55aa55

.Lrel013:   .word        sdk_g_ic+0x1d8                        #  228: 00000000
.Lrel014:   .word        sdk_SPIRead                           #  22c: 00000000
.Lrel015:   .word        sdk_SPIRead                           #  230: 00000000
.Lrel016:   .word        sdk_SPIRead                           #  234: 00000000
.Lrel017:   .word        Cache_Read_Enable                     #  238: 00000000
.Lrel018:   .word        .Lfunc005                             #  23c: 08000000
.Lrel019:   .word        sdk_os_install_putc1                  #  240: 00000000
.Lrel020:   .word        sdk_system_get_checksum               #  244: 00000000
.Lrel021:   .word        .Lfunc011                             #  248: 90070000
.Lrel022:   .word        .Lfunc011                             #  24c: 90070000
.Lrel023:   .word        memcpy                                #  250: 00000000
.Lrel024:   .word        .Lfunc009                             #  254: b4050000

# Function @ .text+0x258
# Local variables/stack:
#     (local0):  byte[877] @ -0x39d
#     (local1):  byte[4]   @ -0x30
#     (local2):  word[6]   @ -0x2c
#     (local3):  word      @ -0x14
#     (local4):  word      @ -0x10
#     (local5):  word      @ -0xc
#     (local6):  word      @ -0x8
#     (local7):  word      @ -0x4
.literal_position
sdk_user_start:
            movi         a2, 928 /* 0x000003a0 */              #  258: 22a3a0
            sub          a1, a1, a2 /* (FP)-0x3a0 */           #  25b: 2011c0
            s32i         a12, a1, 0x39c /* a12 -> [(local7)] */ #  25e: c261e7
            mov.n        a2, a1 /* (FP)-0x3a0 */               #  261: 2d01
            s32i         a0, a1, 0x398 /* a0 -> [(local6)] */  #  263: 0261e6
            call0        .Lfunc001                             #  266: c5daff
            movi.n       a3, 32 /* 0x00000020 */               #  269: 2c03
            movi         a2, .Llit013 /* 0x60000200 */         #  26b: 21ebff
            memw                                               #  26e: c02000
            l32i.n       a0, a2, 28 /* [0x6000021c] */         #  271: 0872
            or           a0, a0, a3                            #  273: 300020
            memw                                               #  276: c02000
            mov.n        a3, a1 /* (FP)-0x3a0 */               #  279: 3d01
            s32i.n       a0, a2, 28 /* a0 -> [0x6000021c] */   #  27b: 0972
            movi.n       a4, 4 /* 0x00000004 */                #  27d: 0c44
            movi.n       a2, 0 /* 0x00000000 */                #  27f: 0c02
            movi         a0, .Lrel014 /* sdk_SPIRead */        #  281: 01eaff
            callx0       a0 /* sdk_SPIRead */                  #  284: c00000
            l8ui         a3, a1, 3 /* [(local0)] */            #  287: 320103
            movi.n       a5, 1 /* 0x00000001 */                #  28a: 0c15
            extui        a0, a3, 0, 4                          #  28c: 300034
            bgeui        a0, 3, .Lbr019                        #  28f: f63004
            addi.n       a2, a0, 2                             #  292: 2b20
            j            .Lbr020                               #  294: c60100
.Lbr019:    addi         a6, a0, -15                           #  297: 62c0f1
            movi.n       a2, 2 /* 0x00000002 */                #  29a: 0c22
            moveqz       a2, a5, a6                            #  29c: 602583
.Lbr020:    extui        a0, a3, 4, 4                          #  29f: 300434
            beqz.n       a0, .Lbr021                           #  2a2: 9c50
            addi.n       a7, a0, -1                            #  2a4: 0b70
            beqz         a7, .Lbr025                           #  2a6: 16b70d
            addi         a8, a0, -2                            #  2a9: 82c0fe
            beqz         a8, .Lbr026                           #  2ac: 16a80d
            addi         a9, a0, -3                            #  2af: 92c0fd
            beqz         a9, .Lbr027                           #  2b2: 16a90d
            addi         a10, a0, -4                           #  2b5: a2c0fc
            beqz         a10, .Lbr028                          #  2b8: 16aa0d
.Lbr021:    movi         a12, 128 /* 0x00000080 */             #  2bb: c2a080
.Lbr022:    movi         a0, .Lrel011 /* .Lrel011 */           #  2be: 01d7ff
            slli         a11, a12, 12                          #  2c1: 40bc11
            s32i         a11, a1, 0x394 /* a11 -> [(local5)] */ #  2c4: b261e5
            s32i.n       a11, a0, 4                            #  2c7: b910
            call0        .Lfunc002                             #  2c9: 45ddff
            movi.n       a4, 28 /* 0x0000001c */               #  2cc: 1cc4
            l32i         a2, a1, 0x394 /* [(local5)] */        #  2ce: 2221e5
            addmi        a3, a1, 768 /* (FP)-0xa0 */           #  2d1: 32d103
            addi         a3, a3, 112 /* (local1) */            #  2d4: 32c370
            addmi        a2, a2, -4096 /* [(local5)]-0x1000 */ #  2d7: 22d2f0
            movi         a0, .Lrel015 /* .Lrel015 */           #  2da: 01d5ff
            callx0       a0                                    #  2dd: c00000
            mov.n        a3, a1 /* (FP)-0x3a0 */               #  2e0: 3d01
            movi.n       a6, 1 /* 0x00000001 */                #  2e2: 0c16
            addmi        a5, a1, 768 /* (FP)-0xa0 */           #  2e4: 52d103
            l8ui         a2, a5, 112 /* [(local1)] */          #  2e7: 220570
            movi         a4, 880 /* 0x00000370 */              #  2ea: 42a370
            movnez       a2, a6, a2                            #  2ed: 202693
            s8i          a2, a5, 112 /* a2 -> [(local1)] */    #  2f0: 224570
            add.n        a2, a2, a12                           #  2f3: ca22
            slli         a2, a2, 12                            #  2f5: 402211
            addmi        a2, a2, -12288                        #  2f8: 22d2d0
            movi         a0, .Lrel016 /* .Lrel016 */           #  2fb: 01ceff
            callx0       a0                                    #  2fe: c00000
            movi.n       a2, 0 /* 0x00000000 */                #  301: 0c02
            movi.n       a3, 0 /* 0x00000000 */                #  303: 0c03
            movi.n       a4, 1 /* 0x00000001 */                #  305: 0c14
            addmi        a8, a1, 768 /* (FP)-0xa0 */           #  307: 82d103
            l8ui         a7, a8, 112 /* [(local1)] */          #  30a: 720870
            addi         a8, a8, 112 /* (local1) */            #  30d: 82c870
            addx4        a7, a7, a8                            #  310: 8077a0
            l32i.n       a8, a7, 20                            #  313: 8857
            s32i         a8, a1, 0x38c /* a8 -> [(local3)] */  #  315: 8261e3
            l32i.n       a7, a7, 12                            #  318: 7837
            s32i         a7, a1, 0x390 /* a7 -> [(local4)] */  #  31a: 7261e4
            movi         a0, .Lrel017 /* .Lrel017 */           #  31d: 01c6ff
            callx0       a0                                    #  320: c00000
            movi         a0, .Lrel018 /* .Lrel018 */           #  323: 01c6ff
            callx0       a0                                    #  326: c00000
            movi         a2, .Lrel012 /* .Lrel012 */           #  329: 21bdff
            movi         a0, .Lrel019 /* .Lrel019 */           #  32c: 01c5ff
            callx0       a0                                    #  32f: c00000
            movi         a9, .Llit014 /* .Llit014 */           #  332: 91bcff
            l32i         a0, a1, 0x374 /* [(local2)] */        #  335: 0221dd
            bne          a0, a9, .Lbr023                       #  338: 97901c
            mov.n        a2, a1 /* (FP)-0x3a0 */               #  33b: 2d01
            l32i         a3, a1, 0x390 /* [(local4)] */        #  33d: 3221e4
            movi         a0, .Lrel020 /* .Lrel020 */           #  340: 01c1ff
            callx0       a0                                    #  343: c00000
            l32i         a10, a1, 0x38c /* [(local3)] */       #  346: a221e3
            beq          a2, a10, .Lbr024                      #  349: a71217
            addi         a2, a12, -4                           #  34c: 22ccfc
            movi         a0, .Lrel021 /* .Lrel021 */           #  34f: 01beff
            callx0       a0                                    #  352: c00000
            j            .Lbr024                               #  355: c60200
.Lbr023:    beqi         a0, -1, .Lbr024                       #  358: 260008
            addi         a2, a12, -4                           #  35b: 22ccfc
            movi         a0, .Lrel022 /* .Lrel022 */           #  35e: 01bbff
            callx0       a0                                    #  361: c00000
.Lbr024:    movi         a2, .Lrel013 /* .Lrel013 */           #  364: 21b1ff
            mov.n        a3, a1 /* (FP)-0x3a0 */               #  367: 3d01
            movi         a4, 880 /* 0x00000370 */              #  369: 42a370
            movi         a0, .Lrel023 /* .Lrel023 */           #  36c: 01b9ff
            callx0       a0                                    #  36f: c00000
            movi         a0, .Lrel024 /* .Lrel024 */           #  372: 01b8ff
            callx0       a0                                    #  375: c00000
            l32i         a12, a1, 0x39c /* [(local7)] */       #  378: c221e7
            movi         a2, 928 /* 0x000003a0 */              #  37b: 22a3a0
            l32i         a0, a1, 0x398 /* [(local6)] */        #  37e: 0221e6
            add.n        a1, a1, a2 /* (top of frame) */       #  381: 2a11
            ret.n         /* 0x000003a0 */                     #  383: 0df0
.Lbr025:    movi.n       a12, 64 /* 0x00000040 */              #  385: 4c0c
            j            .Lbr022                               #  387: c6ccff
.Lbr026:    movi         a12, 256 /* 0x00000100 */             #  38a: c2a100
            j            .Lbr022                               #  38d: 46cbff
.Lbr027:    movi         a12, 512 /* 0x00000200 */             #  390: c2a200
            j            .Lbr022                               #  393: c6c9ff
.Lbr028:    movi         a12, 1024 /* 0x00000400 */            #  396: c2a400
            j            .Lbr022                               #  399: 46c8ff

.Lrel025:   .word        .Lstr021                              #  39c: 24010000
.Lrel026:   .word        uxTaskGetStackHighWaterMark           #  3a0: 00000000
.Lrel027:   .word        printf                                #  3a4: 00000000

# Function @ .text+0x3a8
# Local variables/stack:
#     (local0):  word      @ -0x10
#     (local1):  word[3]   @ -0xc
.literal_position
sdk_vApplicationStackOverflowHook:
            addi         a1, a1, -16 /* (local0) */            #  3a8: 12c1f0
            s32i.n       a3, a1, 0 /* arg1 -> [(local0)] */    #  3ab: 3901
            s32i.n       a0, a1, 4 /* a0 -> [(local1)] */      #  3ad: 0911
            movi         a0, .Lrel026 /* uxTaskGetStackHighWaterMark */ #  3af: 01fcff
            callx0       a0 /* uxTaskGetStackHighWaterMark */  #  3b2: c00000
            mov.n        a4, a2                                #  3b5: 4d02
            l32i.n       a3, a1, 0 /* [(local0)] */            #  3b7: 3801
            movi         a2, .Lrel025 /* .Lstr021 */           #  3b9: 21f8ff
            movi         a0, .Lrel027 /* printf */             #  3bc: 01faff
            callx0       a0 /* printf */                       #  3bf: c00000
            l32i.n       a0, a1, 4 /* [(local1)] */            #  3c2: 0811
            addi         a1, a1, 16 /* (top of frame) */       #  3c4: 12c110
            ret.n                                              #  3c7: 0df0

            .balign      4
.Lrel028:   .word        .Lstr022                              #  3cc: 54010000

# NOTE: The following is apparently unreferenced code/data
.Llit015:   .word        0x3ff20a00                            #  3d0: 000af23f

.Lrel029:   .word        printf                                #  3d4: 00000000

# Function @ .text+0x3d8
# Local variables/stack:
#     (local0):  word[4]   @ -0x10
.literal_position
sdk_vApplicationIdleHook:
            addi         a1, a1, -16 /* (local0) */            #  3d8: 12c1f0
            s32i.n       a0, a1, 0 /* a0 -> [(local0)] */      #  3db: 0901
            movi         a2, .Lrel028 /* .Lstr022 */           #  3dd: 21fbff
            movi         a3, .Llit015 /* 0x3ff20a00 */         #  3e0: 31fcff
            memw                                               #  3e3: c02000
            l32i         a3, a3, 0x200 /* [0x3ff20c00] */      #  3e6: 322380
            movi         a0, .Lrel029 /* printf */             #  3e9: 01faff
            callx0       a0 /* printf */                       #  3ec: c00000
            l32i.n       a0, a1, 0 /* [(local0)] */            #  3ef: 0801
            addi         a1, a1, 16 /* (top of frame) */       #  3f1: 12c110
            ret.n                                              #  3f4: 0df0

            .balign      4
.Lrel030:   .word        .Lstr023                              #  3f8: 60010000

# NOTE: The following is apparently unreferenced code/data
.Llit016:   .word        0x3ff20a00                            #  3fc: 000af23f

.Lrel031:   .word        printf                                #  400: 00000000

# Function @ .text+0x404
# Local variables/stack:
#     (local0):  word[4]   @ -0x10
.literal_position
sdk_vApplicationTickHook:
            addi         a1, a1, -16 /* (local0) */            #  404: 12c1f0
            s32i.n       a0, a1, 0 /* a0 -> [(local0)] */      #  407: 0901
            movi         a2, .Lrel030 /* .Lstr023 */           #  409: 21fbff
            movi         a3, .Llit016 /* 0x3ff20a00 */         #  40c: 31fcff
            memw                                               #  40f: c02000
            l32i         a3, a3, 0x200 /* [0x3ff20c00] */      #  412: 322380
            movi         a0, .Lrel031 /* printf */             #  415: 01faff
            callx0       a0 /* printf */                       #  418: c00000
            l32i.n       a0, a1, 0 /* [(local0)] */            #  41b: 0801
            addi         a1, a1, 16 /* (top of frame) */       #  41d: 12c110
            ret.n                                              #  420: 0df0

            .section     .data, "aw", @progbits

            .section     .bss, "aw", @nobits

sdk_user_init_flag:
            .byte        0x00
            .byte        0x00, 0x00, 0x00
sdk_info:   .word        0x00000000                            #    4: 00000000
.Ldata001:  .word        0x00000000                            #    8: 00000000
.Ldata002:  .word        0x00000000                            #    c: 00000000

# NOTE: 12 non-alignment zero bytes skipped.

            .skip        12
.Label001:  .space       6
.Label002:  .space       6
sdk_xUserTaskHandle:
            .word        0x00000000                            #   28: 00000000
sdk_xWatchDogTaskHandle:
            .word        0x00000000                            #   2c: 00000000

            .section     .irom0.text, "ax", @progbits

.Lrel032:   .word        _bss_end                              #    0: 00000000
.Lrel033:   .word        _bss_start                            #    4: 00000000

# Function @ .irom0.text+0x8
.literal_position
.Lfunc005:  movi         a6, .Lrel032 /* _bss_end */           #    8: 61feff
            movi         a4, .Lrel033 /* _bss_start */         #    b: 41feff
            movi.n       a5, 0 /* 0x00000000 */                #    e: 0c05
            bgeu         a4, a6, .Lbr030                       #   10: 67b406
.Lbr029:    s32i.n       a5, a4, 0                             #   13: 5904
            addi.n       a4, a4, 4                             #   15: 4b44
            bltu         a4, a6, .Lbr029                       #   17: 6734f8
.Lbr030:    ret.n         /* arg0 */                           #   1a: 0df0

.Lrel034:   .word        .Lstr003                              #   1c: 30000000
.Lrel035:   .word        .Lstr004                              #   20: 38000000
.Lrel036:   .word        sdk_g_ic+0x200                        #   24: 00000000
.Lrel037:   .word        sdk_g_ic                              #   28: 00000000
.Llit017:   .word        0x3feffe00                            #   2c: 00feef3f
.Lrel038:   .word        sdk_g_ic                              #   30: 00000000
.Lrel039:   .word        sdk_register_chipv6_phy               #   34: 00000000
.Lrel040:   .word        printf                                #   38: 00000000
.Lrel041:   .word        sdk_uart_div_modify                   #   3c: 00000000
.Lrel042:   .word        sdk_uart_div_modify                   #   40: 00000000
.Lrel043:   .word        sdk_phy_disable_agc                   #   44: 00000000
.Lrel044:   .word        sdk_ieee80211_phy_init                #   48: 00000000
.Lrel045:   .word        sdk_lmacInit                          #   4c: 00000000
.Lrel046:   .word        sdk_wDev_Initialize                   #   50: 00000000
.Lrel047:   .word        sdk_pp_attach                         #   54: 00000000
.Lrel048:   .word        sdk_ieee80211_ifattach                #   58: 00000000
.Lrel049:   .word        sdk__xt_isr_mask                      #   5c: 00000000
.Lrel050:   .word        sdk_pm_attach                         #   60: 00000000
.Lrel051:   .word        sdk_phy_enable_agc                    #   64: 00000000
.Lrel052:   .word        sdk_cnx_attach                        #   68: 00000000
.Lrel053:   .word        sdk_wDevEnableRx                      #   6c: 00000000

# Function @ .irom0.text+0x70
# Local variables/stack:
#     (local0):  word      @ -0x10
#     (local1):  word[3]   @ -0xc
.literal_position
.Lfunc006:  addi         a1, a1, -16 /* (local0) */            #   70: 12c1f0
            s32i.n       a3, a1, 0 /* arg1 -> [(local0)] */    #   73: 3901
            s32i.n       a0, a1, 4 /* a0 -> [(local1)] */      #   75: 0911
            movi         a0, .Lrel039 /* sdk_register_chipv6_phy */ #   77: 01efff
            callx0       a0 /* sdk_register_chipv6_phy */      #   7a: c00000
            beqz.n       a2, .Lbr032                           #   7d: 9c02
            movi         a2, .Lrel034 /* .Lstr003 */           #   7f: 21e7ff
            movi         a3, .Lrel035 /* .Lstr004 */           #   82: 31e7ff
            movi         a4, 137 /* 0x00000089 */              #   85: 42a089
            movi         a0, .Lrel040 /* printf */             #   88: 01ecff
            callx0       a0 /* printf */                       #   8b: c00000
.Lbr031:    j            .Lbr031 /* (halt) */                  #   8e: 06ffff
.Lbr032:    movi.n       a2, 0 /* 0x00000000 */                #   91: 0c02
            movi         a3, 1068 /* 0x0000042c */             #   93: 32a42c
            movi         a0, .Lrel041 /* sdk_uart_div_modify */ #   96: 01e9ff
            callx0       a0 /* sdk_uart_div_modify */          #   99: c00000
            movi.n       a2, 1 /* 0x00000001 */                #   9c: 0c12
            movi         a3, 1068 /* 0x0000042c */             #   9e: 32a42c
            movi         a0, .Lrel042 /* sdk_uart_div_modify */ #   a1: 01e7ff
            callx0       a0 /* sdk_uart_div_modify */          #   a4: c00000
            movi         a0, .Lrel043 /* sdk_phy_disable_agc */ #   a7: 01e7ff
            callx0       a0 /* sdk_phy_disable_agc */          #   aa: c00000
            movi         a2, .Lrel036 /* sdk_g_ic+0x200 */     #   ad: 21ddff
            l32i         a2, a2, 0x31c /* [sdk_g_ic+0x51c] */  #   b0: 2222c7
            movi         a0, .Lrel044 /* sdk_ieee80211_phy_init */ #   b3: 01e5ff
            callx0       a0 /* sdk_ieee80211_phy_init */       #   b6: c00000
            movi         a0, .Lrel045 /* sdk_lmacInit */       #   b9: 01e4ff
            callx0       a0 /* sdk_lmacInit */                 #   bc: c00000
            movi         a0, .Lrel046 /* sdk_wDev_Initialize */ #   bf: 01e4ff
            callx0       a0 /* sdk_wDev_Initialize */          #   c2: c00000
            movi         a0, .Lrel047 /* sdk_pp_attach */      #   c5: 01e3ff
            callx0       a0 /* sdk_pp_attach */                #   c8: c00000
            movi         a2, .Lrel037 /* sdk_g_ic */           #   cb: 21d7ff
            l32i.n       a3, a1, 0 /* [(local0)] */            #   ce: 3801
            movi         a0, .Lrel048 /* sdk_ieee80211_ifattach */ #   d0: 01e2ff
            callx0       a0 /* sdk_ieee80211_ifattach */       #   d3: c00000
            movi.n       a2, 1 /* 0x00000001 */                #   d6: 0c12
            movi         a0, .Lrel049 /* sdk__xt_isr_mask */   #   d8: 01e1ff
            callx0       a0 /* sdk__xt_isr_mask */             #   db: c00000
            movi.n       a6, -32 /* 0xffffffe0 */              #   de: 6c06
            movi.n       a5, 1 /* 0x00000001 */                #   e0: 0c15
            movi         a4, .Llit017 /* 0x3feffe00 */         #   e2: 41d2ff
            memw                                               #   e5: c02000
            l32i         a3, a4, 0x200 /* [0x3ff00000] */      #   e8: 322480
            and          a3, a3, a6                            #   eb: 603310
            or           a3, a3, a5                            #   ee: 503320
            memw                                               #   f1: c02000
            s32i         a3, a4, 0x200 /* a3 -> [0x3ff00000] */ #   f4: 326480
            movi         a0, .Lrel050 /* sdk_pm_attach */      #   f7: 01daff
            callx0       a0 /* sdk_pm_attach */                #   fa: c00000
            movi         a0, .Lrel051 /* sdk_phy_enable_agc */ #   fd: 01d9ff
            callx0       a0 /* sdk_phy_enable_agc */           #  100: c00000
            movi         a2, .Lrel038 /* sdk_g_ic */           #  103: 21cbff
            movi         a0, .Lrel052 /* sdk_cnx_attach */     #  106: 01d8ff
            callx0       a0 /* sdk_cnx_attach */               #  109: c00000
            movi         a0, .Lrel053 /* sdk_wDevEnableRx */   #  10c: 01d8ff
            callx0       a0 /* sdk_wDevEnableRx */             #  10f: c00000
            l32i.n       a0, a1, 4 /* [(local1)] */            #  112: 0811
            addi         a1, a1, 16 /* (top of frame) */       #  114: 12c110
            ret.n                                              #  117: 0df0

            .balign      4
.Lrel054:   .word        sdk_g_ic+0x26e                        #  11c: 00000000
.Lrel055:   .word        sdk_g_ic+0x28d                        #  120: 00000000
.Lrel056:   .word        sdk_g_ic+0x446                        #  124: 00000000
.Llit018:   .word        0x0000ea60                            #  128: 60ea0000
.Lrel057:   .word        sdk_g_ic+0x2ac                        #  12c: 00000000
.Lrel058:   .word        sdk_g_ic+0x1e4                        #  130: 00000000
.Lrel059:   .word        sdk_g_ic+0x20f                        #  134: 00000000
.Lrel060:   .word        sdk_wifi_softap_set_default_ssid      #  138: 00000000
.Lrel061:   .word        bzero                                 #  13c: 00000000
.Lrel062:   .word        bzero                                 #  140: 00000000
.Lrel063:   .word        bzero                                 #  144: 00000000

# Function @ .irom0.text+0x148
# Local variables/stack:
#     (local0):  word      @ -0x20
#     (local1):  word      @ -0x1c
#     (local2):  word      @ -0x18
#     (local3):  word      @ -0x14
#     (local4):  word[4]   @ -0x10
.literal_position
.Lfunc007:  movi         a3, 255 /* 0x000000ff */              #  148: 32a0ff
            addi         a1, a1, -32 /* (local0) */            #  14b: 12c1e0
            s32i.n       a12, a1, 4 /* a12 -> [(local1)] */    #  14e: c911
            s32i.n       a13, a1, 8 /* a13 -> [(local2)] */    #  150: d921
            s32i.n       a0, a1, 0 /* a0 -> [(local0)] */      #  152: 0901
            s32i.n       a14, a1, 12 /* a14 -> [(local3)] */   #  154: e931
            movi         a14, .Lrel054 /* sdk_g_ic+0x26e */    #  156: e1f1ff
            movi         a0, -384 /* 0xfffffe80 */             #  159: 02ae80
            add.n        a0, a14, a0 /* sdk_g_ic+0xee */       #  15c: 0a0e
            l8ui         a2, a0, 242 /* [sdk_g_ic+0x1e0] */    #  15e: 2200f2
            s32i.n       a15, a1, 16 /* a15 -> [(local4)] */   #  161: f941
            bne          a2, a3, .Lbr033                       #  163: 379204
            movi.n       a2, 2 /* 0x00000002 */                #  166: 0c22
            s8i          a2, a0, 242 /* 0x02 -> [sdk_g_ic+0x1e0] */ #  168: 2240f2
.Lbr033:    movi         a0, .Lrel060 /* sdk_wifi_softap_set_default_ssid */ #  16b: 01f3ff
            callx0       a0 /* sdk_wifi_softap_set_default_ssid */ #  16e: c00000
            movi.n       a0, 1 /* 0x00000001 */                #  171: 0c10
            movi         a13, .Lrel056 /* sdk_g_ic+0x446 */    #  173: d1ecff
            movi         a12, .Lrel055 /* sdk_g_ic+0x28d */    #  176: c1eaff
            movi         a5, .Llit018 /* 0x0000ea60 */         #  179: 51ebff
            l8ui         a4, a12, 128 /* [sdk_g_ic+0x30d] */   #  17c: 420c80
            movi.n       a3, 14 /* 0x0000000e */               #  17f: 0ce3
            bltu         a3, a4, .Lbr034                       #  181: 473301
            bnez.n       a4, .Lbr035                           #  184: cc14
.Lbr034:    s8i          a0, a12, 128 /* 0x01 -> [sdk_g_ic+0x30d] */ #  186: 024c80
.Lbr035:    l8ui         a3, a12, 129 /* [sdk_g_ic+0x30e] */   #  189: 320c81
            l16ui        a4, a13, 254 /* [sdk_g_ic+0x544] */   #  18c: 421d7f
            movi.n       a15, 0 /* 0x00000000 */               #  18f: 0c0f
            bltu         a5, a4, .Lbr036                       #  191: 473505
            movi         a6, 99 /* 0x00000063 */               #  194: 62a063
            bltu         a6, a4, .Lbr037                       #  197: 473605
.Lbr036:    movi         a7, 100 /* 0x00000064 */              #  19a: 72a064
            s16i         a7, a13, 254 /* 0x0064 -> [sdk_g_ic+0x544] */ #  19d: 725d7f
.Lbr037:    bgeui        a3, 5, .Lbr038                        #  1a0: f65302
            bnei         a3, 1, .Lbr039                        #  1a3: 66130f
.Lbr038:    s8i          a15, a12, 129 /* 0x00 -> [sdk_g_ic+0x30e] */ #  1a6: f24c81
            movi         a2, .Lrel057 /* sdk_g_ic+0x2ac */     #  1a9: 21e0ff
            movi.n       a3, 64 /* 0x00000040 */               #  1ac: 4c03
            movi         a0, .Lrel061 /* bzero */              #  1ae: 01e3ff
            callx0       a0 /* bzero */                        #  1b1: c00000
            movi.n       a0, 1 /* 0x00000001 */                #  1b4: 0c10
.Lbr039:    l8ui         a8, a12, 130 /* [sdk_g_ic+0x30f] */   #  1b6: 820c82
            l8ui         a9, a12, 131 /* [sdk_g_ic+0x310] */   #  1b9: 920c83
            bltui        a8, 2, .Lbr040                        #  1bc: b62802
            s8i          a15, a12, 130 /* 0x00 -> [sdk_g_ic+0x30f] */ #  1bf: f24c82
.Lbr040:    addmi        a2, a14, -256 /* sdk_g_ic+0x16e */    #  1c2: 22deff
            l16ui        a11, a2, 120 /* [sdk_g_ic+0x1e6] */   #  1c5: b2123c
            l16ui        a2, a2, 118 /* [sdk_g_ic+0x1e4] */    #  1c8: 22123b
            slli         a11, a11, 16                          #  1cb: 00bb11
            or           a11, a11, a2                          #  1ce: 20bb20
            bltui        a9, 5, .Lbr041                        #  1d1: b65904
            movi.n       a10, 4 /* 0x00000004 */               #  1d4: 0c4a
            s8i          a10, a12, 131 /* 0x04 -> [sdk_g_ic+0x310] */ #  1d6: a24c83
.Lbr041:    bnei         a11, -1, .Lbr042                      #  1d9: 660b17
            movi         a2, .Lrel058 /* sdk_g_ic+0x1e4 */     #  1dc: 21d5ff
            movi.n       a3, 36 /* 0x00000024 */               #  1df: 2c43
            movi         a0, .Lrel062 /* bzero */              #  1e1: 01d7ff
            callx0       a0 /* bzero */                        #  1e4: c00000
            movi         a2, .Lrel059 /* sdk_g_ic+0x20f */     #  1e7: 21d3ff
            movi.n       a3, 64 /* 0x00000040 */               #  1ea: 4c03
            movi         a0, .Lrel063 /* bzero */              #  1ec: 01d6ff
            callx0       a0 /* bzero */                        #  1ef: c00000
            movi.n       a0, 1 /* 0x00000001 */                #  1f2: 0c10
.Lbr042:    l8ui         a5, a12, 135 /* [sdk_g_ic+0x314] */   #  1f4: 520c87
            addmi        a3, a12, -256 /* sdk_g_ic+0x18d */    #  1f7: 32dcff
            movi         a6, -384 /* 0xfffffe80 */             #  1fa: 62ae80
            add.n        a6, a14, a6 /* sdk_g_ic+0xee */       #  1fd: 6a6e
            l8ui         a4, a3, 244 /* [sdk_g_ic+0x281] */    #  1ff: 4203f4
            s8i          a15, a6, 243 /* 0x00 -> [sdk_g_ic+0x1e1] */ #  202: f246f3
            bltui        a4, 2, .Lbr043                        #  205: b62402
            s8i          a15, a3, 244 /* 0x00 -> [sdk_g_ic+0x281] */ #  208: f243f4
.Lbr043:    addi         a2, a13, 127 /* sdk_g_ic+0x4c5 */     #  20b: 22cd7f
            addi         a2, a2, 87 /* sdk_g_ic+0x51c */       #  20e: 22c257
            bltui        a5, 6, .Lbr044                        #  211: b66502
            s8i          a0, a12, 135 /* 0x01 -> [sdk_g_ic+0x314] */ #  214: 024c87
.Lbr044:    l32i.n       a12, a1, 4 /* [(local1)] */           #  217: c811
            l32i.n       a14, a1, 12 /* [(local3)] */          #  219: e831
            l32i.n       a15, a1, 16 /* [(local4)] */          #  21b: f841
            l16ui        a0, a2, 2 /* [sdk_g_ic+0x51e] */      #  21d: 021201
            l16ui        a2, a2, 0 /* [sdk_g_ic+0x51c] */      #  220: 221200
            slli         a0, a0, 16                            #  223: 000011
            or           a0, a0, a2                            #  226: 200020
            bgeui        a0, 4, .Lbr045                        #  229: f64001
            bnez.n       a0, .Lbr046                           #  22c: cce0
.Lbr045:    movi.n       a3, 0 /* 0x00000000 */                #  22e: 0c03
            movi.n       a5, 3 /* 0x00000003 */                #  230: 0c35
            addi         a4, a13, 127 /* sdk_g_ic+0x4c5 */     #  232: 42cd7f
            addi         a4, a4, 87 /* sdk_g_ic+0x51c */       #  235: 42c457
            s16i         a5, a4, 0 /* 0x0003 -> [sdk_g_ic+0x51c] */ #  238: 525400
            s16i         a3, a4, 2 /* 0x0000 -> [sdk_g_ic+0x51e] */ #  23b: 325401
.Lbr046:    l32i.n       a13, a1, 8 /* [(local2)] */           #  23e: d821
            l32i.n       a0, a1, 0 /* [(local0)] */            #  240: 0801
            addi         a1, a1, 32 /* (top of frame) */       #  242: 12c120
            ret.n         /* [sdk_g_ic+0x51c] */               #  245: 0df0

            .balign      4
.Lrel064:   .word        .Lstr005                              #  248: 44000000
.Lrel065:   .word        .Lstr006                              #  24c: 5c000000
.Lrel066:   .word        .Lstr007                              #  250: 68000000
.Lrel067:   .word        .Lstr006                              #  254: 5c000000
.Lrel068:   .word        .Lstr008                              #  258: 70000000
.Lrel069:   .word        .Lstr006                              #  25c: 5c000000
.Lrel070:   .word        .Lstr009                              #  260: 78000000
.Lrel071:   .word        .Lstr006                              #  264: 5c000000
.Lrel072:   .word        .Lstr010                              #  268: 80000000
.Lrel073:   .word        .Lstr006                              #  26c: 5c000000
.Lrel074:   .word        .Lstr011                              #  270: 8c000000
.Lrel075:   .word        .Lstr006                              #  274: 5c000000
.Lrel076:   .word        .Lstr012                              #  278: 94000000
.Lrel077:   .word        ets_printf                            #  27c: 00000000
.Lrel078:   .word        printf                                #  280: 00000000
.Lrel079:   .word        printf                                #  284: 00000000
.Lrel080:   .word        printf                                #  288: 00000000
.Lrel081:   .word        printf                                #  28c: 00000000
.Lrel082:   .word        printf                                #  290: 00000000
.Lrel083:   .word        printf                                #  294: 00000000
.Lrel084:   .word        sdk_system_rtc_mem_read               #  298: 00000000
.Lrel085:   .word        sdk_system_rtc_mem_write              #  29c: 00000000

# Function @ .irom0.text+0x2a0
# Local variables/stack:
#     (local0):  word      @ -0x40
#     (local1):  word      @ -0x3c
#     (local2):  word      @ -0x38
#     (local3):  word      @ -0x34
#     (local4):  word      @ -0x30
#     (local5):  word      @ -0x2c
#     (local6):  word      @ -0x28
#     (local7):  word      @ -0x24
#     (local8):  word      @ -0x20
#     (local9):  word      @ -0x1c
#     (local10): word      @ -0x18
#     (local11): word      @ -0x14
#     (local12): word      @ -0x10
#     (local13): word      @ -0xc
#     (local14): word      @ -0x8
#     (local15): word      @ -0x4
.literal_position
.Lfunc008:  movi         a2, .Lrel064 /* .Lstr005 */           #  2a0: 21eaff
            rsr.exccause a3                                    #  2a3: 30e803
            addi         a1, a1, -64 /* (local0) */            #  2a6: 12c1c0
            s32i.n       a12, a1, 44 /* a12 -> [(local11)] */  #  2a9: c9b1
            s32i.n       a13, a1, 48 /* a13 -> [(local12)] */  #  2ab: d9c1
            s32i.n       a14, a1, 52 /* a14 -> [(local13)] */  #  2ad: e9d1
            s32i.n       a15, a1, 56 /* a15 -> [(local14)] */  #  2af: f9e1
            s32i.n       a0, a1, 40 /* a0 -> [(local10)] */    #  2b1: 09a1
            s32i.n       a3, a1, 32 /* a3 -> [(local8)] */     #  2b3: 3981
            movi         a0, .Lrel077 /* ets_printf */         #  2b5: 01f1ff
            callx0       a0 /* ets_printf */                   #  2b8: c00000
            movi         a2, .Lrel065 /* .Lstr006 */           #  2bb: 21e4ff
            movi         a3, .Lrel066 /* .Lstr007 */           #  2be: 31e4ff
            rsr.epc1     a4                                    #  2c1: 40b103
            s32i.n       a4, a1, 36 /* a4 -> [(local9)] */     #  2c4: 4991
            rsr.epc2     a0                                    #  2c6: 00b203
            s32i.n       a0, a1, 60 /* a0 -> [(local15)] */    #  2c9: 09f1
            rsr.epc3     a15                                   #  2cb: f0b303
            rsr.excvaddr a14                                   #  2ce: e0ee03
            rsr.depc     a13                                   #  2d1: d0c003
            rsr.excsave1 a12                                   #  2d4: c0d103
            movi         a0, .Lrel078 /* printf */             #  2d7: 01eaff
            callx0       a0 /* printf */                       #  2da: c00000
            movi         a2, .Lrel067 /* .Lstr006 */           #  2dd: 21ddff
            movi         a3, .Lrel068 /* .Lstr008 */           #  2e0: 31deff
            l32i.n       a4, a1, 60 /* [(local15)] */          #  2e3: 48f1
            movi         a0, .Lrel079 /* printf */             #  2e5: 01e7ff
            callx0       a0 /* printf */                       #  2e8: c00000
            movi         a2, .Lrel069 /* .Lstr006 */           #  2eb: 21dcff
            movi         a3, .Lrel070 /* .Lstr009 */           #  2ee: 31dcff
            mov.n        a4, a15                               #  2f1: 4d0f
            movi         a0, .Lrel080 /* printf */             #  2f3: 01e5ff
            callx0       a0 /* printf */                       #  2f6: c00000
            movi         a2, .Lrel071 /* .Lstr006 */           #  2f9: 21daff
            movi         a3, .Lrel072 /* .Lstr010 */           #  2fc: 31dbff
            mov.n        a4, a14                               #  2ff: 4d0e
            movi         a0, .Lrel081 /* printf */             #  301: 01e2ff
            callx0       a0 /* printf */                       #  304: c00000
            movi         a2, .Lrel073 /* .Lstr006 */           #  307: 21d9ff
            movi         a3, .Lrel074 /* .Lstr011 */           #  30a: 31d9ff
            mov.n        a4, a13                               #  30d: 4d0d
            movi         a0, .Lrel082 /* printf */             #  30f: 01e0ff
            callx0       a0 /* printf */                       #  312: c00000
            movi         a2, .Lrel075 /* .Lstr006 */           #  315: 21d7ff
            movi         a3, .Lrel076 /* .Lstr012 */           #  318: 31d8ff
            mov.n        a4, a12                               #  31b: 4d0c
            movi         a0, .Lrel083 /* printf */             #  31d: 01ddff
            callx0       a0 /* printf */                       #  320: c00000
            movi.n       a2, 0 /* 0x00000000 */                #  323: 0c02
            mov.n        a3, a1 /* (local0) */                 #  325: 3d01
            movi.n       a4, 32 /* 0x00000020 */               #  327: 2c04
            movi         a0, .Lrel084 /* sdk_system_rtc_mem_read */ #  329: 01dbff
            callx0       a0 /* sdk_system_rtc_mem_read */      #  32c: c00000
            s32i.n       a15, a1, 16 /* a15 -> [(local4)] */   #  32f: f941
            s32i.n       a14, a1, 20 /* a14 -> [(local5)] */   #  331: e951
            s32i.n       a13, a1, 24 /* a13 -> [(local6)] */   #  333: d961
            s32i.n       a12, a1, 28 /* a12 -> [(local7)] */   #  335: c971
            l32i.n       a3, a1, 60 /* [(local15)] */          #  337: 38f1
            movi.n       a2, 2 /* 0x00000002 */                #  339: 0c22
            l32i.n       a4, a1, 36 /* [(local9)] */           #  33b: 4891
            l32i.n       a5, a1, 32 /* [(local8)] */           #  33d: 5881
            s32i.n       a5, a1, 4 /* [(local8)] -> [(local1)] */ #  33f: 5911
            s32i.n       a4, a1, 8 /* [(local9)] -> [(local2)] */ #  341: 4921
            s32i.n       a2, a1, 0 /* 0x00000002 -> [(local0)] */ #  343: 2901
            s32i.n       a3, a1, 12 /* [(local15)] -> [(local3)] */ #  345: 3931
            movi.n       a2, 0 /* 0x00000000 */                #  347: 0c02
            mov.n        a3, a1 /* (local0) */                 #  349: 3d01
            movi.n       a4, 32 /* 0x00000020 */               #  34b: 2c04
            movi         a0, .Lrel085 /* sdk_system_rtc_mem_write */ #  34d: 01d3ff
            callx0       a0 /* sdk_system_rtc_mem_write */     #  350: c00000
            l32i.n       a12, a1, 44 /* [(local11)] */         #  353: c8b1
            l32i.n       a13, a1, 48 /* [(local12)] */         #  355: d8c1
            l32i.n       a14, a1, 52 /* [(local13)] */         #  357: e8d1
            l32i.n       a15, a1, 56 /* [(local14)] */         #  359: f8e1
            l32i.n       a0, a1, 40 /* [(local10)] */          #  35b: 08a1
            addi         a1, a1, 64 /* (top of frame) */       #  35d: 12c140
            ret.n                                              #  360: 0df0

            .balign      4
.Llit019:   .word        0x5ffffe00                            #  364: 00feff5f

# Function @ .irom0.text+0x368
.literal_position
sdk_uart_rx_one_char:
            movi         a5, .Llit019 /* 0x5ffffe00 */         #  368: 51ffff
            memw                                               #  36b: c02000
            l32i         a3, a5, 0x21c /* [0x6000001c] */      #  36e: 322587
            movi.n       a4, 1 /* 0x00000001 */                #  371: 0c14
            extui        a3, a3, 0, 8                          #  373: 303074
            bnez.n       a3, .Lbr047                           #  376: cc13
            j            .Lbr048                               #  378: 860200
.Lbr047:    memw                                               #  37b: c02000
            movi.n       a4, 0 /* 0x00000000 */                #  37e: 0c04
            l32i         a6, a5, 0x200 /* [0x60000000] */      #  380: 622580
            s8i          a6, a2, 0 /* [0x60000000] -> [arg0] */ #  383: 624200
.Lbr048:    mov.n        a2, a4                                #  386: 2d04
            ret.n                                              #  388: 0df0

            .balign      4
.Llit020:   .word        0x3feffe00                            #  38c: 00feef3f
.Llit021:   .word        0x60000600                            #  390: 00060060
.Lrel086:   .word        sdk_pp_soft_wdt_init                  #  394: 00000000

# Function @ .irom0.text+0x398
# Local variables/stack:
#     (local0):  word[4]   @ -0x10
.literal_position
sdk_wdt_init:
            movi.n       a4, -2 /* 0xfffffffe */               #  398: 7ce4
            addi         a1, a1, -16 /* (local0) */            #  39a: 12c1f0
            s32i.n       a0, a1, 0 /* a0 -> [(local0)] */      #  39d: 0901
            movi         a11, .Llit020 /* 0x3feffe00 */        #  39f: b1fbff
            movi.n       a3, 1 /* 0x00000001 */                #  3a2: 0c13
            movi         a2, .Llit021 /* 0x60000600 */         #  3a4: 21fbff
            memw                                               #  3a7: c02000
            l32i         a0, a2, 0x300 /* [0x60000900] */      #  3aa: 0222c0
            and          a0, a0, a4                            #  3ad: 400010
            memw                                               #  3b0: c02000
            s32i         a0, a2, 0x300 /* a0 -> [0x60000900] */ #  3b3: 0262c0
            memw                                               #  3b6: c02000
            l32i         a10, a11, 0x204 /* [0x3ff00004] */    #  3b9: a22b81
            or           a10, a10, a3                          #  3bc: 30aa20
            memw                                               #  3bf: c02000
            s32i         a10, a11, 0x204 /* a10 -> [0x3ff00004] */ #  3c2: a26b81
            movi.n       a9, 11 /* 0x0000000b */               #  3c5: 0cb9
            memw                                               #  3c7: c02000
            s32i         a9, a2, 0x304 /* 0x0000000b -> [0x60000904] */ #  3ca: 9262c1
            movi.n       a8, 12 /* 0x0000000c */               #  3cd: 0cc8
            memw                                               #  3cf: c02000
            s32i         a8, a2, 0x308 /* 0x0000000c -> [0x60000908] */ #  3d2: 8262c2
            movi.n       a7, 56 /* 0x00000038 */               #  3d5: 3c87
            memw                                               #  3d7: c02000
            l32i         a6, a2, 0x300 /* [0x60000900] */      #  3da: 6222c0
            or           a6, a6, a7                            #  3dd: 706620
            memw                                               #  3e0: c02000
            s32i         a6, a2, 0x300 /* a6 -> [0x60000900] */ #  3e3: 6262c0
            movi.n       a5, -7 /* 0xfffffff9 */               #  3e6: 7c95
            memw                                               #  3e8: c02000
            l32i         a4, a2, 0x300 /* [0x60000900] */      #  3eb: 4222c0
            and          a4, a4, a5                            #  3ee: 504410
            memw                                               #  3f1: c02000
            s32i         a4, a2, 0x300 /* a4 -> [0x60000900] */ #  3f4: 4262c0
            memw                                               #  3f7: c02000
            l32i         a0, a2, 0x300 /* [0x60000900] */      #  3fa: 0222c0
            or           a0, a0, a3                            #  3fd: 300020
            memw                                               #  400: c02000
            s32i         a0, a2, 0x300 /* a0 -> [0x60000900] */ #  403: 0262c0
            movi         a0, .Lrel086 /* sdk_pp_soft_wdt_init */ #  406: 01e3ff
            callx0       a0 /* sdk_pp_soft_wdt_init */         #  409: c00000
            l32i.n       a0, a1, 0 /* [(local0)] */            #  40c: 0801
            addi         a1, a1, 16 /* (top of frame) */       #  40e: 12c110
            ret.n                                              #  411: 0df0

            .balign      4
.Lrel087:   .word        .Lstr017                              #  414: d4000000
.Lrel088:   .word        .Lstr018                              #  418: f8000000
.Lrel089:   .word        .Lstr013                              #  41c: 9c000000
.Lrel090:   .word        .Lstr014                              #  420: a8000000
.Lrel091:   .word        .Lstr015                              #  424: b4000000
.Llit022:   .word        0x60000e00                            #  428: 000e0060
.Llit023:   .word        0x0000ff00                            #  42c: 00ff0000
.Lrel092:   .word        .Lstr016                              #  430: c4000000
.Lrel093:   .word        .bss                                  #  434: 00000000
.Lrel094:   .word        sdk_g_ic+0x180                        #  438: 00000000
.Lrel095:   .word        sdk_g_ic                              #  43c: 00000000
.Lrel096:   .word        sdk_ets_timer_init                    #  440: 00000000
.Lrel097:   .word        printf                                #  444: 00000000
.Lrel098:   .word        printf                                #  448: 00000000
.Lrel099:   .word        printf                                #  44c: 00000000
.Lrel100:   .word        user_init                             #  450: 00000000
.Lrel101:   .word        sdk_wifi_mode_set                     #  454: 00000000
.Lrel102:   .word        sdk_wifi_station_start                #  458: 00000000
.Lrel103:   .word        sdk_wifi_softap_start                 #  45c: 00000000
.Lrel104:   .word        netif_set_default                     #  460: 00000000
.Lrel105:   .word        netif_set_default                     #  464: 00000000
.Lrel106:   .word        sdk_wifi_station_get_auto_connect     #  468: 00000000
.Lrel107:   .word        sdk_wifi_station_connect              #  46c: 00000000
.Lrel108:   .word        vTaskDelete                           #  470: 00000000

# Function @ .irom0.text+0x474
# Local variables/stack:
#     (local0):  word      @ -0x10
#     (local1):  word[3]   @ -0xc
.literal_position
sdk_user_init_task:
            addi         a1, a1, -16 /* (local0) */            #  474: 12c1f0
            s32i.n       a12, a1, 4 /* a12 -> [(local1)] */    #  477: c911
            s32i.n       a0, a1, 0 /* a0 -> [(local0)] */      #  479: 0901
            movi         a0, .Lrel096 /* sdk_ets_timer_init */ #  47b: 01f1ff
            callx0       a0 /* sdk_ets_timer_init */           #  47e: c00000
            movi         a2, .Lrel087 /* .Lstr017 */           #  481: 21e4ff
            movi         a3, .Lrel088 /* .Lstr018 */           #  484: 31e5ff
            movi         a4, .Lrel089 /* .Lstr013 */           #  487: 41e5ff
            movi         a5, .Lrel090 /* .Lstr014 */           #  48a: 51e5ff
            movi         a0, .Lrel097 /* printf */             #  48d: 01edff
            callx0       a0 /* printf */                       #  490: c00000
            movi         a2, .Lrel091 /* .Lstr015 */           #  493: 21e4ff
            movi         a12, .Llit022 /* 0x60000e00 */        #  496: c1e4ff
            memw                                               #  499: c02000
            l32i         a3, a12, 0x27c /* [0x6000107c] */     #  49c: 322c9f
            extui        a3, a3, 16, 16                        #  49f: 3030f5
            movi         a0, .Lrel098 /* printf */             #  4a2: 01e9ff
            callx0       a0 /* printf */                       #  4a5: c00000
            movi         a4, .Llit023 /* 0x0000ff00 */         #  4a8: 41e1ff
            movi         a2, .Lrel092 /* .Lstr016 */           #  4ab: 21e1ff
            memw                                               #  4ae: c02000
            l32i         a3, a12, 0x3f8 /* [0x600011f8] */     #  4b1: 322cfe
            and          a3, a3, a4                            #  4b4: 403310
            srli         a3, a3, 8                             #  4b7: 303841
            memw                                               #  4ba: c02000
            l32i         a4, a12, 0x3f8 /* [0x600011f8] */     #  4bd: 422cfe
            extui        a4, a4, 0, 8                          #  4c0: 404074
            movi         a0, .Lrel099 /* printf */             #  4c3: 01e2ff
            callx0       a0 /* printf */                       #  4c6: c00000
            movi         a0, .Lrel100 /* user_init */          #  4c9: 01e1ff
            callx0       a0 /* user_init */                    #  4cc: c00000
            movi         a2, .Lrel093 /* sdk_user_init_flag */ #  4cf: 21d9ff
            movi         a12, .Lrel094 /* sdk_g_ic+0x180 */    #  4d2: c1d9ff
            movi.n       a0, 1 /* 0x00000001 */                #  4d5: 0c10
            l8ui         a12, a12, 96 /* [sdk_g_ic+0x1e0] */   #  4d7: c20c60
            s8i          a0, a2, 0 /* 0x01 -> [sdk_user_init_flag] */ #  4da: 024200
            mov.n        a2, a12 /* [sdk_g_ic+0x1e0] */        #  4dd: 2d0c
            movi         a0, .Lrel101 /* sdk_wifi_mode_set */  #  4df: 01ddff
            callx0       a0 /* sdk_wifi_mode_set */            #  4e2: c00000
            beqi         a12, 1, .Lbr049                       #  4e5: 261c02
            bnei         a12, 3, .Lbr050                       #  4e8: 663c05
.Lbr049:    movi         a0, .Lrel102 /* sdk_wifi_station_start */ #  4eb: 01dbff
            callx0       a0 /* sdk_wifi_station_start */       #  4ee: c00000
.Lbr050:    beqi         a12, 2, .Lbr051                       #  4f1: 262c02
            bnei         a12, 3, .Lbr052                       #  4f4: 663c05
.Lbr051:    movi         a0, .Lrel103 /* sdk_wifi_softap_start */ #  4f7: 01d9ff
            callx0       a0 /* sdk_wifi_softap_start */        #  4fa: c00000
.Lbr052:    movi         a0, .Lrel095 /* sdk_g_ic */           #  4fd: 01cfff
            beqi         a12, 1, .Lbr053                       #  500: 261c0c
            l32i.n       a2, a0, 20 /* [sdk_g_ic+0x14] */      #  503: 2850
            l32i.n       a2, a2, 0 /* [[sdk_g_ic+0x14]] */     #  505: 2802
            movi         a0, .Lrel104 /* netif_set_default */  #  507: 01d6ff
            callx0       a0 /* netif_set_default */            #  50a: c00000
            j            .Lbr054                               #  50d: 460200
.Lbr053:    l32i.n       a2, a0, 16 /* [sdk_g_ic+0x10] */      #  510: 2840
            l32i.n       a2, a2, 0 /* [[sdk_g_ic+0x10]] */     #  512: 2802
            movi         a0, .Lrel105 /* netif_set_default */  #  514: 01d4ff
            callx0       a0 /* netif_set_default */            #  517: c00000
.Lbr054:    movi         a0, .Lrel106 /* sdk_wifi_station_get_auto_connect */ #  51a: 01d3ff
            callx0       a0 /* sdk_wifi_station_get_auto_connect */ #  51d: c00000
            bnei         a2, 1, .Lbr055                        #  520: 661205
            movi         a0, .Lrel107 /* sdk_wifi_station_connect */ #  523: 01d2ff
            callx0       a0 /* sdk_wifi_station_connect */     #  526: c00000
.Lbr055:    movi.n       a2, 0 /* 0x00000000 */                #  529: 0c02
            movi         a0, .Lrel108 /* vTaskDelete */        #  52b: 01d1ff
            callx0       a0 /* vTaskDelete */                  #  52e: c00000
            l32i.n       a12, a1, 4 /* [(local1)] */           #  531: c811
            l32i.n       a0, a1, 0 /* [(local0)] */            #  533: 0801
            addi         a1, a1, 16 /* (top of frame) */       #  535: 12c110
            ret.n                                              #  538: 0df0

            .balign      4
.Lrel109:   .word        sdk_rst_if                            #  53c: 00000000
.Lrel110:   .word        .Label002                             #  540: 22000000
.Lrel111:   .word        .Label001                             #  544: 1c000000
.Lrel112:   .word        .bss                                  #  548: 00000000
.Llit024:   .word        0x0104a8c0                            #  54c: c0a80401
.Llit025:   .word        0x00ffffff                            #  550: ffffff00
.Lrel113:   .word        sdk_flashchip                         #  554: 00000000
.Llit026:   .word        0x00ff0000                            #  558: 0000ff00
.Llit027:   .word        0x5ffffe00                            #  55c: 00feff5f
.Llit028:   .word        0x60000e00                            #  560: 000e0060
.Lrel114:   .word        .irom.text                            #  564: 00000000
.Lrel115:   .word        sdk_user_init_task                    #  568: 00000000
.Lrel116:   .word        .Label003                             #  56c: 00010000
.Lrel117:   .word        sdk_xUserTaskHandle                   #  570: 28000000
.Lrel118:   .word        zalloc                                #  574: 00000000
.Lrel119:   .word        sdk_system_rtc_mem_read               #  578: 00000000
.Lrel120:   .word        memset                                #  57c: 00000000
.Lrel121:   .word        sdk_system_rtc_mem_write              #  580: 00000000
.Lrel122:   .word        free                                  #  584: 00000000
.Lrel123:   .word        sdk_sleep_reset_analog_rtcreg_8266    #  588: 00000000
.Lrel124:   .word        .Lfunc001                             #  58c: 14000000
.Lrel125:   .word        sdk_wifi_softap_cacl_mac              #  590: 00000000
.Lrel126:   .word        malloc                                #  594: 00000000
.Lrel127:   .word        __udivsi3                             #  598: 00000000
.Lrel128:   .word        sdk_spi_flash_read                    #  59c: 00000000
.Lrel129:   .word        memcpy                                #  5a0: 00000000
.Lrel130:   .word        free                                  #  5a4: 00000000
.Lrel131:   .word        tcpip_init                            #  5a8: 00000000
.Lrel132:   .word        xTaskGenericCreate                    #  5ac: 00000000
.Lrel133:   .word        vTaskStartScheduler                   #  5b0: 00000000

# Function @ .irom0.text+0x5b4
# Local variables/stack:
#     (local0):  word      @ -0x20
#     (local1):  word[3]   @ -0x1c
#     (local2):  word      @ -0x10
#     (local3):  word      @ -0xc
#     (local4):  word[2]   @ -0x8
.literal_position
.Lfunc009:  movi.n       a2, 32 /* 0x00000020 */               #  5b4: 2c02
            addi         a1, a1, -32 /* (local0) */            #  5b6: 12c1e0
            s32i.n       a12, a1, 20 /* a12 -> [(local3)] */   #  5b9: c951
            s32i.n       a13, a1, 24 /* a13 -> [(local4)] */   #  5bb: d961
            s32i.n       a0, a1, 16 /* a0 -> [(local2)] */     #  5bd: 0941
            movi         a0, .Lrel118 /* zalloc */             #  5bf: 01edff
            callx0       a0 /* zalloc */                       #  5c2: c00000
            movi.n       a4, 32 /* 0x00000020 */               #  5c5: 2c04
            mov.n        a12, a2                               #  5c7: cd02
            movi         a13, .Lrel109 /* sdk_rst_if */        #  5c9: d1dcff
            movi.n       a2, 0 /* 0x00000000 */                #  5cc: 0c02
            mov.n        a3, a13 /* sdk_rst_if */              #  5ce: 3d0d
            movi         a0, .Lrel119 /* sdk_system_rtc_mem_read */ #  5d0: 01eaff
            callx0       a0 /* sdk_system_rtc_mem_read */      #  5d3: c00000
            l32i.n       a0, a13, 0 /* [sdk_rst_if] */         #  5d6: 080d
            bltui        a0, 4, .Lbr056                        #  5d8: b6400b
            mov.n        a2, a13 /* sdk_rst_if */              #  5db: 2d0d
            movi.n       a3, 0 /* 0x00000000 */                #  5dd: 0c03
            movi.n       a4, 32 /* 0x00000020 */               #  5df: 2c04
            movi         a0, .Lrel120 /* memset */             #  5e1: 01e6ff
            callx0       a0 /* memset */                       #  5e4: c00000
.Lbr056:    movi.n       a2, 0 /* 0x00000000 */                #  5e7: 0c02
            mov.n        a3, a12                               #  5e9: 3d0c
            movi.n       a4, 32 /* 0x00000020 */               #  5eb: 2c04
            movi         a0, .Lrel121 /* sdk_system_rtc_mem_write */ #  5ed: 01e4ff
            callx0       a0 /* sdk_system_rtc_mem_write */     #  5f0: c00000
            mov.n        a2, a12                               #  5f3: 2d0c
            movi         a0, .Lrel122 /* free */               #  5f5: 01e3ff
            callx0       a0 /* free */                         #  5f8: c00000
            movi         a0, .Lrel123 /* sdk_sleep_reset_analog_rtcreg_8266 */ #  5fb: 01e3ff
            callx0       a0 /* sdk_sleep_reset_analog_rtcreg_8266 */ #  5fe: c00000
            movi         a13, .Lrel110 /* .Label002 */         #  601: d1cfff
            mov.n        a2, a13 /* .Label002 */               #  604: 2d0d
            movi         a0, .Lrel124 /* .Lfunc001 */          #  606: 01e1ff
            callx0       a0 /* .Lfunc001 */                    #  609: c00000
            movi         a2, .Lrel111 /* .Label001 */          #  60c: 21ceff
            mov.n        a3, a13 /* .Label002 */               #  60f: 3d0d
            movi         a0, .Lrel125 /* sdk_wifi_softap_cacl_mac */ #  611: 01dfff
            callx0       a0 /* sdk_wifi_softap_cacl_mac */     #  614: c00000
            movi         a2, .Llit025 /* 0x00ffffff */         #  617: 21ceff
            movi         a3, .Lrel112 /* sdk_user_init_flag */ #  61a: 31cbff
            movi         a4, .Llit024 /* 0x0104a8c0 */         #  61d: 41cbff
            s32i.n       a4, a3, 4 /* 0x0104a8c0 -> [sdk_info] */ #  620: 4913
            s32i.n       a4, a3, 12 /* 0x0104a8c0 -> [.Ldata002] */ #  622: 4933
            s32i.n       a2, a3, 8 /* 0x00ffffff -> [.Ldata001] */ #  624: 2923
            call0        .Lfunc007                             #  626: 05b2ff
            movi         a2, 128 /* 0x00000080 */              #  629: 22a080
            movi         a0, .Lrel126 /* malloc */             #  62c: 01daff
            callx0       a0 /* malloc */                       #  62f: c00000
            movi         a5, .Lrel113 /* sdk_flashchip */      #  632: 51c8ff
            mov.n        a12, a2                               #  635: cd02
            l32i.n       a3, a5, 12 /* [sdk_flashchip+0xc] */  #  637: 3835
            l32i.n       a2, a5, 4 /* [sdk_flashchip+0x4] */   #  639: 2815
            movi         a0, .Lrel127 /* __udivsi3 */          #  63b: 01d7ff
            callx0       a0 /* __udivsi3 */                    #  63e: c00000
            mov.n        a3, a12                               #  641: 3d0c
            movi         a4, 128 /* 0x00000080 */              #  643: 42a080
            slli         a2, a2, 12                            #  646: 402211
            addmi        a2, a2, -16384                        #  649: 22d2c0
            movi         a0, .Lrel128 /* sdk_spi_flash_read */ #  64c: 01d4ff
            callx0       a0 /* sdk_spi_flash_read */           #  64f: c00000
            movi         a0, .Llit026 /* 0x00ff0000 */         #  652: 01c1ff
            movi         a2, .Llit027 /* 0x5ffffe00 */         #  655: 21c1ff
            memw                                               #  658: c02000
            l32i         a3, a2, 0x21c /* [0x6000001c] */      #  65b: 322287
            bnone        a0, a3, .Lbr058                       #  65e: 370008
.Lbr057:    memw                                               #  661: c02000
            l32i         a4, a2, 0x21c /* [0x6000001c] */      #  664: 422287
            bany         a4, a0, .Lbr057                       #  667: 0784f6
.Lbr058:    movi         a2, .Llit028 /* 0x60000e00 */         #  66a: 21bdff
            memw                                               #  66d: c02000
            l32i         a5, a2, 0x11c /* [0x60000f1c] */      #  670: 522247
            bnone        a0, a5, .Lbr060                       #  673: 570008
.Lbr059:    memw                                               #  676: c02000
            l32i         a6, a2, 0x11c /* [0x60000f1c] */      #  679: 622247
            bany         a6, a0, .Lbr059                       #  67c: 0786f6
.Lbr060:    l8ui         a7, a12, 0                            #  67f: 720c00
            beqi         a7, 5, .Lbr061                        #  682: 265717
            mov.n        a2, a12                               #  685: 2d0c
            movi         a3, .Lrel114 /* .Ldata003 */          #  687: 31b7ff
            movi         a4, 128 /* 0x00000080 */              #  68a: 42a080
            movi         a0, .Lrel129 /* memcpy */             #  68d: 01c4ff
            callx0       a0 /* memcpy */                       #  690: c00000
            mov.n        a3, a13 /* .Label002 */               #  693: 3d0d
            mov.n        a2, a12                               #  695: 2d0c
            call0        .Lfunc006                             #  697: 859dff
            j            .Lbr062                               #  69a: 860100
.Lbr061:    mov.n        a3, a13 /* .Label002 */               #  69d: 3d0d
            mov.n        a2, a12                               #  69f: 2d0c
            call0        .Lfunc006                             #  6a1: c59cff
.Lbr062:    mov.n        a2, a12                               #  6a4: 2d0c
            movi         a0, .Lrel130 /* free */               #  6a6: 01bfff
            callx0       a0 /* free */                         #  6a9: c00000
            movi.n       a2, 0 /* 0x00000000 */                #  6ac: 0c02
            movi.n       a3, 0 /* 0x00000000 */                #  6ae: 0c03
            movi         a0, .Lrel131 /* tcpip_init */         #  6b0: 01beff
            callx0       a0 /* tcpip_init */                   #  6b3: c00000
            call0        sdk_wdt_init                          #  6b6: 050000
            movi         a2, .Lrel115 /* sdk_user_init_task */ #  6b9: 21abff
            movi         a3, .Lrel116 /* .Label003 */          #  6bc: 31acff
            movi         a4, 1024 /* 0x00000400 */             #  6bf: 42a400
            movi.n       a5, 0 /* 0x00000000 */                #  6c2: 0c05
            movi.n       a6, 14 /* 0x0000000e */               #  6c4: 0ce6
            movi         a7, .Lrel117 /* sdk_xUserTaskHandle */ #  6c6: 71aaff
            movi.n       a8, 0 /* 0x00000000 */                #  6c9: 0c08
            s32i.n       a8, a1, 0 /* 0x00000000 -> [(local0)] */ #  6cb: 8901
            s32i.n       a8, a1, 4 /* 0x00000000 -> [(local1)] */ #  6cd: 8911
            movi         a0, .Lrel132 /* xTaskGenericCreate */ #  6cf: 01b7ff
            callx0       a0 /* xTaskGenericCreate */           #  6d2: c00000
            movi         a0, .Lrel133 /* vTaskStartScheduler */ #  6d5: 01b6ff
            callx0       a0 /* vTaskStartScheduler */          #  6d8: c00000
            l32i.n       a12, a1, 20 /* [(local3)] */          #  6db: c851
            l32i.n       a13, a1, 24 /* [(local4)] */          #  6dd: d861
            l32i.n       a0, a1, 16 /* [(local2)] */           #  6df: 0841
            addi         a1, a1, 32 /* (top of frame) */       #  6e1: 12c120
            ret.n                                              #  6e4: 0df0

            .balign      4
.Llit029:   .word        0x0000fffc                            #  6e8: fcff0000
.Lrel134:   .word        .Lstr019                              #  6ec: 04010000
.Lrel135:   .word        .Label004                             #  6f0: 0c010000
.Lrel136:   .word        .Label004                             #  6f4: 0c010000
.Lrel137:   .word        malloc                                #  6f8: 00000000
.Lrel138:   .word        sdk_spi_flash_read                    #  6fc: 00000000
.Lrel139:   .word        printf                                #  700: 00000000
.Lrel140:   .word        printf                                #  704: 00000000
.Lrel141:   .word        printf                                #  708: 00000000
.Lrel142:   .word        free                                  #  70c: 00000000

# Function @ .irom0.text+0x710
# Local variables/stack:
#     (local0):  word      @ -0x20
#     (local1):  word      @ -0x1c
#     (local2):  word      @ -0x18
#     (local3):  word      @ -0x14
#     (local4):  word[4]   @ -0x10
.literal_position
.Lfunc010:  addi         a1, a1, -32 /* (local0) */            #  710: 12c1e0
            s32i.n       a0, a1, 4 /* a0 -> [(local1)] */      #  713: 0911
            s32i.n       a2, a1, 0 /* arg0 -> [(local0)] */    #  715: 2901
            s32i.n       a13, a1, 12 /* a13 -> [(local3)] */   #  717: d931
            s32i.n       a12, a1, 8 /* a12 -> [(local2)] */    #  719: c921
            s32i.n       a14, a1, 16 /* a14 -> [(local4)] */   #  71b: e941
            mov.n        a12, a3 /* arg1 */                    #  71d: cd03
            movi         a14, .Llit029 /* 0x0000fffc */        #  71f: e1f2ff
            addi.n       a13, a3, 3 /* arg1+0x3 */             #  722: 3bd3
            and          a13, a13, a14                         #  724: e0dd10
            mov.n        a2, a13                               #  727: 2d0d
            movi         a0, .Lrel137 /* malloc */             #  729: 01f3ff
            callx0       a0 /* malloc */                       #  72c: c00000
            mov.n        a14, a2                               #  72f: ed02
            mov.n        a4, a13                               #  731: 4d0d
            l32i.n       a2, a1, 0 /* [(local0)] */            #  733: 2801
            mov.n        a3, a14                               #  735: 3d0e
            slli         a2, a2, 12                            #  737: 402211
            movi         a0, .Lrel138 /* sdk_spi_flash_read */ #  73a: 01f0ff
            callx0       a0 /* sdk_spi_flash_read */           #  73d: c00000
            beqz.n       a12, .Lbr065                          #  740: ac6c
            movi.n       a13, 0 /* 0x00000000 */               #  742: 0c0d
.Lbr063:    movi         a2, .Lrel134 /* .Lrel134 */           #  744: 21eaff
            add.n        a3, a14, a13                          #  747: da3e
            l8ui         a3, a3, 0                             #  749: 320300
            movi         a0, .Lrel139 /* .Lrel139 */           #  74c: 01edff
            callx0       a0                                    #  74f: c00000
            addi.n       a4, a13, 1                            #  752: 1b4d
            extui        a4, a4, 0, 5                          #  754: 404044
            bnez.n       a4, .Lbr064                           #  757: cc74
            movi         a2, .Lrel135 /* .Lrel135 */           #  759: 21e5ff
            movi         a0, .Lrel140 /* .Lrel140 */           #  75c: 01eaff
            callx0       a0                                    #  75f: c00000
.Lbr064:    addi.n       a13, a13, 1                           #  762: 1bdd
            extui        a13, a13, 0, 16                       #  764: d0d0f4
            bne          a12, a13, .Lbr063                     #  767: d79cd9
.Lbr065:    movi         a2, .Lrel136 /* .Label004 */          #  76a: 21e2ff
            movi         a0, .Lrel141 /* printf */             #  76d: 01e6ff
            callx0       a0 /* printf */                       #  770: c00000
            mov.n        a2, a14                               #  773: 2d0e
            movi         a0, .Lrel142 /* free */               #  775: 01e5ff
            callx0       a0 /* free */                         #  778: c00000
            l32i.n       a12, a1, 8 /* [(local2)] */           #  77b: c821
            l32i.n       a13, a1, 12 /* [(local3)] */          #  77d: d831
            l32i.n       a14, a1, 16 /* [(local4)] */          #  77f: e841
            l32i.n       a0, a1, 4 /* [(local1)] */            #  781: 0811
            addi         a1, a1, 32 /* (top of frame) */       #  783: 12c120
            ret.n                                              #  786: 0df0

.Lrel143:   .word        .Lstr020                              #  788: 10010000
.Lrel144:   .word        printf                                #  78c: 00000000

# Function @ .irom0.text+0x790
# Local variables/stack:
#     (local0):  word      @ -0x10
#     (local1):  word[3]   @ -0xc
.literal_position
.Lfunc011:  addi         a1, a1, -16 /* (local0) */            #  790: 12c1f0
            s32i.n       a12, a1, 4 /* a12 -> [(local1)] */    #  793: c911
            s32i.n       a0, a1, 0 /* a0 -> [(local0)] */      #  795: 0901
            mov.n        a12, a2 /* arg0 */                    #  797: cd02
            movi         a2, .Lrel143 /* .Lstr020 */           #  799: 21fbff
            movi         a0, .Lrel144 /* printf */             #  79c: 01fcff
            callx0       a0 /* printf */                       #  79f: c00000
            addi.n       a2, a12, 1 /* arg0+0x1 */             #  7a2: 1b2c
            movi         a3, 880 /* 0x00000370 */              #  7a4: 32a370
            call0        .Lfunc010                             #  7a7: 85f6ff
            addi.n       a2, a12, 2 /* arg0+0x2 */             #  7aa: 2b2c
            movi         a3, 880 /* 0x00000370 */              #  7ac: 32a370
            call0        .Lfunc010                             #  7af: 05f6ff
            addi.n       a2, a12, 3 /* arg0+0x3 */             #  7b2: 3b2c
            movi.n       a3, 28 /* 0x0000001c */               #  7b4: 1cc3
            call0        .Lfunc010                             #  7b6: 85f5ff
            l32i.n       a12, a1, 4 /* [(local1)] */           #  7b9: c811
            l32i.n       a0, a1, 0 /* [(local0)] */            #  7bb: 0801
            addi         a1, a1, 16 /* (top of frame) */       #  7bd: 12c110
            ret.n                                              #  7c0: 0df0

            .section     .irom.text, "ax", @progbits

.Ldata003:  .byte        0x05, 0x00, 0x04, 0x02, 0x05, 0x05, 0x05, 0x02
            .byte        0x05, 0x00, 0x04, 0x05, 0x05, 0x04, 0x05, 0x05
            .byte        0x04, 0xfe, 0xfd, 0xff, 0xf0, 0xf0, 0xf0, 0xe0
            .byte        0xe0, 0xe0, 0xe1, 0x0a, 0xff, 0xff, 0xf8, 0x00
            .byte        0xf8, 0xf8, 0x52, 0x4e, 0x4a, 0x44, 0x40, 0x38
            .byte        0x00, 0x00, 0x01, 0x01, 0x02, 0x03, 0x04, 0x05
            .byte        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00
            .byte        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
            .byte        0xe1, 0x0a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
            .byte        0x00, 0x00, 0x01, 0x93, 0x43, 0x00, 0x00, 0x00
            .byte        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
            .byte        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
            .byte        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
            .byte        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
            .byte        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
            .byte        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00

            .section     .rodata.str1.4, "MSa", @progbits, 1

.Lstr001:   .asciz       "Firmware ONLY supports ESP8266!!!\n" #    0: 4669726d
                                                               #    4: 77617265
                                                               #    8: 204f4e4c
                                                               #    c: 59207375
                                                               #   10: 70706f72
                                                               #   14: 74732045
                                                               #   18: 53503832
                                                               #   1c: 36362121
                                                               #   20: 210a00
            .balign      4
.Lstr002:   .asciz       "empty otp\n"                         #   24: 656d7074
                                                               #   28: 79206f74
                                                               #   2c: 700a00
            .balign      4
.Lstr003:   .asciz       "%s %u\n"                             #   30: 25732025
                                                               #   34: 750a00
            .balign      4
.Lstr004:   .asciz       "app_main.c"                          #   38: 6170705f
                                                               #   3c: 6d61696e
                                                               #   40: 2e6300
            .balign      4
.Lstr005:   .asciz       "Fatal exception (%d): \n"            #   44: 46617461
                                                               #   48: 6c206578
                                                               #   4c: 63657074
                                                               #   50: 696f6e20
                                                               #   54: 28256429
                                                               #   58: 3a200a00
.Lstr006:   .asciz       "%s=0x%08x\n"                         #   5c: 25733d30
                                                               #   60: 78253038
                                                               #   64: 780a00
            .balign      4
.Lstr007:   .asciz       "epc1"                                #   68: 65706331
                                                               #   6c: 00
            .balign      4
.Lstr008:   .asciz       "epc2"                                #   70: 65706332
                                                               #   74: 00
            .balign      4
.Lstr009:   .asciz       "epc3"                                #   78: 65706333
                                                               #   7c: 00
            .balign      4
.Lstr010:   .asciz       "epcvaddr"                            #   80: 65706376
                                                               #   84: 61646472
                                                               #   88: 00
            .balign      4
.Lstr011:   .asciz       "depc"                                #   8c: 64657063
                                                               #   90: 00
            .balign      4
.Lstr012:   .asciz       "rtn_add"                             #   94: 72746e5f
                                                               #   98: 61646400
.Lstr013:   .asciz       "Mar 31 2015"                         #   9c: 4d617220
                                                               #   a0: 33312032
                                                               #   a4: 30313500
.Lstr014:   .asciz       "11:43:00"                            #   a8: 31313a34
                                                               #   ac: 333a3030
                                                               #   b0: 00
            .balign      4
.Lstr015:   .asciz       "phy ver: %d, "                       #   b4: 70687920
                                                               #   b8: 7665723a
                                                               #   bc: 2025642c
                                                               #   c0: 2000
            .balign      4
.Lstr016:   .asciz       "pp ver: %d.%d\n\n"                   #   c4: 70702076
                                                               #   c8: 65723a20
                                                               #   cc: 25642e25
                                                               #   d0: 640a0a00
.Lstr017:   .asciz       "\nOS SDK ver: %s compiled @ %s %s\n" #   d4: 0a4f5320
                                                               #   d8: 53444b20
                                                               #   dc: 7665723a
                                                               #   e0: 20257320
                                                               #   e4: 636f6d70
                                                               #   e8: 696c6564
                                                               #   ec: 20402025
                                                               #   f0: 73202573
                                                               #   f4: 0a00
            .balign      4
.Lstr018:   .asciz       "0.9.9"                               #   f8: 302e392e
                                                               #   fc: 3900
            .balign      4
.Label003:  .word        0x00546975                            #  100: 75695400
.Lstr019:   .asciz       "%02x "                               #  104: 25303278
                                                               #  108: 2000
            .balign      4
.Label004:  .word        0x0000000a                            #  10c: 0a000000
.Lstr020:   .asciz       "system param error\n"                #  110: 73797374
                                                               #  114: 656d2070
                                                               #  118: 6172616d
                                                               #  11c: 20657272
                                                               #  120: 6f720a00
.Lstr021:   .asciz       "\"%s\"(stack_size = %d) overflow the heap_size.\n" #  124: 22257322
                                                               #  128: 28737461
                                                               #  12c: 636b5f73
                                                               #  130: 697a6520
                                                               #  134: 3d202564
                                                               #  138: 29206f76
                                                               #  13c: 6572666c
                                                               #  140: 6f772074
                                                               #  144: 68652068
                                                               #  148: 6561705f
                                                               #  14c: 73697a65
                                                               #  150: 2e0a00
            .balign      4
.Lstr022:   .asciz       "idle %d\n"                           #  154: 69646c65
                                                               #  158: 2025640a
                                                               #  15c: 00
            .balign      4
.Lstr023:   .asciz       "tick %d\n"                           #  160: 7469636b
                                                               #  164: 2025640a
                                                               #  168: 00
