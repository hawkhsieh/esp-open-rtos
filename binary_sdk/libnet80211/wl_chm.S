
            .section     .irom0.literal, "ax", @progbits

            .section     .literal, "ax", @progbits

            .section     .text, "ax", @progbits

.Lrel001:   .word        .bss                                  #    0: 00000000

# Function @ .text+0x4
.literal_position
sdk_chm_get_current_channel:
            movi         a2, .Lrel001 /* .Ldata001 */          #    4: 21ffff
            l32i.n       a2, a2, 60 /* [.Ldata009] */          #    7: 28f2
            ret.n         /* [.Ldata009] */                    #    9: 0df0

            .section     .data, "aw", @progbits

            .section     .bss, "aw", @nobits

.Ldata001:  .word        0x00000000                            #    0: 00000000
.Ldata002:  .word        0x00000000                            #    4: 00000000
.Ldata003:  .word        0x00000000                            #    8: 00000000
.Ldata004:  .word        0x00000000                            #    c: 00000000
.Ldata005:  .word        0x00000000                            #   10: 00000000
.Ldata006:  .word        0x00000000                            #   14: 00000000
.Ldata007:  .word        0x00000000                            #   18: 00000000
.Ldata008:  .word        0x00000000                            #   1c: 00000000
.Label001:  .space       28
.Ldata009:  .word        0x00000000                            #   3c: 00000000
.Ldata010:  .byte        0x00
.Ldata011:  .byte        0x00

            .section     .irom0.text, "ax", @progbits

# NOTE: The following is apparently unreferenced code/data
.Llit001:   .word        0x3feffe00                            #    0: 00feef3f

.Lrel002:   .word        sdk_g_ic+0x180                        #    4: 00000000
.Lrel003:   .word        .bss                                  #    8: 00000000
.Lrel004:   .word        sdk_NMIIrqIsOn                        #    c: 00000000
.Lrel005:   .word        sdk_NMIIrqIsOn                        #   10: 00000000
.Lrel006:   .word        .Label001                             #   14: 20000000
.Lrel007:   .word        .Lfunc002                             #   18: 48020000
.Lrel008:   .word        vPortEnterCritical                    #   1c: 00000000
.Lrel009:   .word        vPortExitCritical                     #   20: 00000000
.Lrel010:   .word        sdk_chm_set_current_channel           #   24: 00000000
.Lrel011:   .word        sdk_os_timer_setfn                    #   28: 00000000

# Function @ .irom0.text+0x2c
# Local variables/stack:
#     (local0):  word      @ -0x20
#     (local1):  word      @ -0x1c
#     (local2):  word      @ -0x18
#     (local3):  word      @ -0x14
#     (local4):  word[4]   @ -0x10
.literal_position
sdk_chm_init:
            movi.n       a4, -32 /* 0xffffffe0 */              #   2c: 6c04
            movi         a5, .Lrel004 /* sdk_NMIIrqIsOn */     #   2e: 51f7ff
            movi         a3, .Lrel002 /* sdk_g_ic+0x180 */     #   31: 31f4ff
            movi         a6, .Lrel003 /* .Ldata001 */          #   34: 61f5ff
            addi         a1, a1, -32 /* (local0) */            #   37: 12c1e0
            s32i.n       a12, a1, 4 /* a12 -> [(local1)] */    #   3a: c911
            s32i.n       a13, a1, 8 /* a13 -> [(local2)] */    #   3c: d921
            s32i.n       a0, a1, 0 /* a0 -> [(local0)] */      #   3e: 0901
            movi         a13, .Llit001 /* 0x3feffe00 */        #   40: d1f0ff
            movi.n       a0, 0 /* 0x00000000 */                #   43: 0c00
            s32i.n       a2, a6, 0 /* arg0 -> [.Ldata001] */   #   45: 2906
            mov.n        a12, a2 /* arg0 */                    #   47: cd02
            l8ui         a6, a3, 96 /* [sdk_g_ic+0x1e0] */     #   49: 620360
            l8ui         a2, a5, 0 /* [sdk_NMIIrqIsOn] */      #   4c: 220500
            addmi        a3, a3, 256 /* sdk_g_ic+0x280 */      #   4f: 32d301
            l8ui         a3, a3, 141 /* [sdk_g_ic+0x30d] */    #   52: 32038d
            addi.n       a6, a6, -1 /* [sdk_g_ic+0x1e0]-0x1 */ #   55: 0b66
            addi.n       a3, a3, -1 /* [sdk_g_ic+0x30d]-0x1 */ #   57: 0b33
            extui        a3, a3, 0, 8                          #   59: 303074
            movnez       a0, a3, a6                            #   5c: 600393
            s32i.n       a0, a1, 16 /* a0 -> [(local4)] */     #   5f: 0941
            bnez.n       a2, .Lbr002                           #   61: ec32
            movi         a0, .Lrel008 /* vPortEnterCritical */ #   63: 01eeff
            callx0       a0 /* vPortEnterCritical */           #   66: c00000
            movi.n       a4, -32 /* 0xffffffe0 */              #   69: 6c04
.Lbr001:    memw                                               #   6b: c02000
            l32i         a9, a13, 0x200 /* [0x3ff00000] */     #   6e: 922d80
            and          a9, a9, a4                            #   71: 409910
            memw                                               #   74: c02000
            s32i         a9, a13, 0x200 /* a9 -> [0x3ff00000] */ #   77: 926d80
            memw                                               #   7a: c02000
            l32i         a8, a13, 0x200 /* [0x3ff00000] */     #   7d: 822d80
            bbsi         a8, 0, .Lbr001                        #   80: 07e8e7
            l32i.n       a0, a1, 16 /* [(local4)] */           #   83: 0841
            movi         a5, .Lrel005 /* sdk_NMIIrqIsOn */     #   85: 51e2ff
.Lbr002:    movi         a2, 132 /* 0x00000084 */              #   88: 22a084
            addx2        a0, a0, a0                            #   8b: 000090
            addx4        a0, a0, a12                           #   8e: c000a0
            add.n        a0, a0, a2                            #   91: 2a00
            s32i         a0, a12, 0x14c /* a0 -> [arg0+0x14c] */ #   93: 026c53
            l8ui         a10, a5, 0 /* [sdk_NMIIrqIsOn] */     #   96: a20500
            s32i.n       a0, a1, 12 /* a0 -> [(local3)] */     #   99: 0931
            bnez.n       a10, .Lbr003                          #   9b: dcaa
            memw                                               #   9d: c02000
            l32i         a2, a13, 0x200 /* [0x3ff00000] */     #   a0: 222d80
            movi.n       a3, 1 /* 0x00000001 */                #   a3: 0c13
            and          a2, a2, a4                            #   a5: 402210
            or           a2, a2, a3                            #   a8: 302220
            memw                                               #   ab: c02000
            s32i         a2, a13, 0x200 /* a2 -> [0x3ff00000] */ #   ae: 226d80
            movi         a0, .Lrel009 /* vPortExitCritical */  #   b1: 01dbff
            callx0       a0 /* vPortExitCritical */            #   b4: c00000
            l32i.n       a0, a1, 12 /* [(local3)] */           #   b7: 0831
.Lbr003:    mov.n        a2, a0                                #   b9: 2d00
            movi         a0, .Lrel010 /* sdk_chm_set_current_channel */ #   bb: 01daff
            callx0       a0 /* sdk_chm_set_current_channel */  #   be: c00000
            movi         a2, .Lrel006 /* .Label001 */          #   c1: 21d4ff
            movi         a3, .Lrel007 /* .Lfunc002 */          #   c4: 31d5ff
            movi.n       a4, 0 /* 0x00000000 */                #   c7: 0c04
            movi         a0, .Lrel011 /* sdk_os_timer_setfn */ #   c9: 01d7ff
            callx0       a0 /* sdk_os_timer_setfn */           #   cc: c00000
            l32i.n       a12, a1, 4 /* [(local1)] */           #   cf: c811
            l32i.n       a13, a1, 8 /* [(local2)] */           #   d1: d821
            l32i.n       a0, a1, 0 /* [(local0)] */            #   d3: 0801
            addi         a1, a1, 32 /* (top of frame) */       #   d5: 12c120
            ret.n                                              #   d8: 0df0

            .balign      4
.Lrel012:   .word        .bss                                  #   dc: 00000000
.Lrel013:   .word        .bss                                  #   e0: 00000000

# Function @ .irom0.text+0xe4
# Local variables/stack:
#     (local0):  word      @ -0x10
#     (local1):  word      @ -0xc
#     (local2):  word      @ -0x8
#     (local3):  word      @ -0x4
.literal_position
sdk_chm_acquire_lock:
            addi         a1, a1, -16 /* (local0) */            #   e4: 12c1f0
            s32i.n       a12, a1, 4 /* a12 -> [(local1)] */    #   e7: c911
            s32i.n       a0, a1, 0 /* a0 -> [(local0)] */      #   e9: 0901
            mov.n        a12, a2 /* arg0 */                    #   eb: cd02
            movi         a0, .Lrel012 /* .Ldata001 */          #   ed: 01fbff
            mov.n        a2, a4 /* arg2 */                     #   f0: 2d04
            l8ui         a4, a0, 64 /* [.Ldata010] */          #   f2: 420040
            l8ui         a5, a0, 65 /* [.Ldata011] */          #   f5: 520041
            beqz.n       a4, .Lbr005                           #   f8: 9c44
            s32i.n       a2, a1, 12 /* arg2 -> [(local3)] */   #   fa: 2931
            s32i.n       a3, a1, 8 /* arg1 -> [(local2)] */    #   fc: 3921
            bgeu         a5, a12, .Lbr004                      #   fe: c7b504
            movi.n       a2, 3 /* 0x00000003 */                #  101: 0c32
            j            .Lbr006                               #  103: c60500
.Lbr004:    call0        sdk_chm_cancel_op                     #  106: 050000
            l32i.n       a2, a1, 12 /* [(local3)] */           #  109: 2831
            movi         a0, .Lrel013 /* .Ldata001 */          #  10b: 01f5ff
            l32i.n       a3, a1, 8 /* [(local2)] */            #  10e: 3821
.Lbr005:    s8i          a12, a0, 65 /* arg0 -> [.Ldata011] */ #  110: c24041
            s32i.n       a3, a0, 24 /* a3 -> [.Ldata007] */    #  113: 3960
            s32i.n       a2, a0, 28 /* a2 -> [.Ldata008] */    #  115: 2970
            movi.n       a6, 1 /* 0x00000001 */                #  117: 0c16
            movi.n       a2, 0 /* 0x00000000 */                #  119: 0c02
            s8i          a6, a0, 64 /* 0x01 -> [.Ldata010] */  #  11b: 624040
.Lbr006:    l32i.n       a12, a1, 4 /* [(local1)] */           #  11e: c811
            l32i.n       a0, a1, 0 /* [(local0)] */            #  120: 0801
            addi         a1, a1, 16 /* (top of frame) */       #  122: 12c110
            ret.n                                              #  125: 0df0

            .balign      4
.Lrel014:   .word        .bss                                  #  128: 00000000

# Function @ .irom0.text+0x12c
.literal_position
sdk_chm_release_lock:
            movi         a3, .Lrel014 /* .Ldata001 */          #  12c: 31ffff
            movi.n       a2, 0 /* 0x00000000 */                #  12f: 0c02
            s32i.n       a2, a3, 28 /* 0x00000000 -> [.Ldata008] */ #  131: 2973
            s32i.n       a2, a3, 24 /* 0x00000000 -> [.Ldata007] */ #  133: 2963
            s8i          a2, a3, 64 /* 0x00 -> [.Ldata010] */  #  135: 224340
            s8i          a2, a3, 65 /* 0x00 -> [.Ldata011] */  #  138: 224341
            ret.n         /* 0x00000000 */                     #  13b: 0df0

            .balign      4
.Lrel015:   .word        .bss                                  #  140: 00000000
.Lrel016:   .word        sdk_g_ic                              #  144: 00000000

# Function @ .irom0.text+0x148
# Local variables/stack:
#     (local0):  word[4]   @ -0x10
.literal_position
sdk_chm_start_op:
            addi         a1, a1, -16 /* (local0) */            #  148: 12c1f0
            s32i.n       a0, a1, 0 /* a0 -> [(local0)] */      #  14b: 0901
            movi         a0, .Lrel015 /* .Ldata001 */          #  14d: 01fcff
            l32i.n       a7, a0, 4 /* [.Ldata002] */           #  150: 7810
            beqz.n       a7, .Lbr010                           #  152: 8cf7
            movi.n       a2, 3 /* 0x00000003 */                #  154: 0c32
            j            .Lbr009                               #  156: 060100
.Lbr007:    call0        .Lfunc001                             #  159: 450400
.Lbr008:    movi.n       a2, 0 /* 0x00000000 */                #  15c: 0c02
.Lbr009:    l32i.n       a0, a1, 0 /* [(local0)] */            #  15e: 0801
            addi         a1, a1, 16 /* (top of frame) */       #  160: 12c110
            ret.n                                              #  163: 0df0
.Lbr010:    s32i.n       a2, a0, 4 /* arg0 -> [.Ldata002] */   #  165: 2910
            s32i.n       a4, a0, 16 /* arg2 -> [.Ldata005] */  #  167: 4940
            movi         a8, .Lrel016 /* sdk_g_ic */           #  169: 81f6ff
            s32i.n       a5, a0, 20 /* arg3 -> [.Ldata006] */  #  16c: 5950
            l32i.n       a8, a8, 0 /* [sdk_g_ic] */            #  16e: 8808
            s32i.n       a3, a0, 8 /* arg1 -> [.Ldata003] */   #  170: 3920
            l32i.n       a8, a8, 0 /* [[sdk_g_ic]] */          #  172: 8808
            s32i.n       a6, a0, 12 /* arg4 -> [.Ldata004] */  #  174: 6930
            bbci         a8, 1, .Lbr007                        #  176: 1768df
            call0        .Lfunc001                             #  179: 450200
            j            .Lbr008                               #  17c: 06f7ff

            .balign      4
.Lrel017:   .word        .bss                                  #  180: 00000000
.Lrel018:   .word        .Ldata002                             #  184: 04000000
.Lrel019:   .word        .Label001                             #  188: 20000000
.Lrel020:   .word        sdk_chm_get_current_channel           #  18c: 00000000
.Lrel021:   .word        sdk_chm_set_current_channel           #  190: 00000000
.Lrel022:   .word        bzero                                 #  194: 00000000
.Lrel023:   .word        sdk_os_timer_disarm                   #  198: 00000000
.Lrel024:   .word        sdk_os_timer_arm                      #  19c: 00000000

# Function @ .irom0.text+0x1a0
# Local variables/stack:
#     (local0):  word      @ -0x10
#     (local1):  word      @ -0xc
#     (local2):  word      @ -0x8
#     (local3):  word      @ -0x4
.literal_position
.Lfunc001:  addi         a1, a1, -16 /* (local0) */            #  1a0: 12c1f0
            s32i.n       a13, a1, 12 /* a13 -> [(local3)] */   #  1a3: d931
            s32i.n       a12, a1, 8 /* a12 -> [(local2)] */    #  1a5: c921
            movi         a13, .Lrel017 /* .Ldata001 */         #  1a7: d1f6ff
            s32i.n       a0, a1, 4 /* a0 -> [(local1)] */      #  1aa: 0911
            l32i.n       a12, a13, 16 /* [.Ldata005] */        #  1ac: c84d
            l32i.n       a0, a13, 12 /* [.Ldata004] */         #  1ae: 083d
            s32i.n       a0, a1, 0 /* [.Ldata004] -> [(local0)] */ #  1b0: 0901
            movi         a0, .Lrel020 /* sdk_chm_get_current_channel */ #  1b2: 01f6ff
            callx0       a0 /* sdk_chm_get_current_channel */  #  1b5: c00000
            mov.n        a3, a2                                #  1b8: 3d02
            l32i.n       a2, a13, 4 /* [.Ldata002] */          #  1ba: 281d
            l16ui        a3, a3, 4                             #  1bc: 321302
            l16ui        a4, a2, 4 /* [[.Ldata002]+0x4] */     #  1bf: 421202
            beq          a3, a4, .Lbr011                       #  1c2: 471305
            movi         a0, .Lrel021 /* sdk_chm_set_current_channel */ #  1c5: 01f2ff
            callx0       a0 /* sdk_chm_set_current_channel */  #  1c8: c00000
.Lbr011:    beqz.n       a12, .Lbr012                          #  1cb: 8c5c
            l32i.n       a2, a1, 0 /* [(local0)] */            #  1cd: 2801
            movi.n       a3, 0 /* 0x00000000 */                #  1cf: 0c03
            callx0       a12 /* [.Ldata005] */                 #  1d1: c00c00
.Lbr012:    l32i.n       a4, a13, 8 /* [.Ldata003] */          #  1d4: 482d
            bnez.n       a4, .Lbr013                           #  1d6: ccc4
            movi         a2, .Lrel018 /* .Ldata002 */          #  1d8: 21ebff
            movi.n       a3, 20 /* 0x00000014 */               #  1db: 1c43
            movi         a0, .Lrel022 /* bzero */              #  1dd: 01edff
            callx0       a0 /* bzero */                        #  1e0: c00000
            j            .Lbr014                               #  1e3: 860500
.Lbr013:    movi         a12, .Lrel019 /* .Label001 */         #  1e6: c1e8ff
            mov.n        a2, a12 /* .Label001 */               #  1e9: 2d0c
            movi         a0, .Lrel023 /* sdk_os_timer_disarm */ #  1eb: 01ebff
            callx0       a0 /* sdk_os_timer_disarm */          #  1ee: c00000
            mov.n        a2, a12 /* .Label001 */               #  1f1: 2d0c
            l32i.n       a3, a13, 8 /* [.Ldata003] */          #  1f3: 382d
            movi.n       a4, 0 /* 0x00000000 */                #  1f5: 0c04
            movi         a0, .Lrel024 /* sdk_os_timer_arm */   #  1f7: 01e9ff
            callx0       a0 /* sdk_os_timer_arm */             #  1fa: c00000
.Lbr014:    l32i.n       a12, a1, 8 /* [(local2)] */           #  1fd: c821
            l32i.n       a13, a1, 12 /* [(local3)] */          #  1ff: d831
            l32i.n       a0, a1, 4 /* [(local1)] */            #  201: 0811
            addi         a1, a1, 16 /* (top of frame) */       #  203: 12c110
            ret.n                                              #  206: 0df0

.Lrel025:   .word        .bss                                  #  208: 00000000
.Lrel026:   .word        .bss                                  #  20c: 00000000
.Lrel027:   .word        bzero                                 #  210: 00000000

# Function @ .irom0.text+0x214
# Local variables/stack:
#     (local0):  word      @ -0x10
#     (local1):  word      @ -0xc
#     (local2):  word[2]   @ -0x8
.literal_position
sdk_chm_end_op:
            movi.n       a3, -4 /* 0xfffffffc */               #  214: 7cc3
            addi         a1, a1, -16 /* (local0) */            #  216: 12c1f0
            s32i.n       a0, a1, 4 /* a0 -> [(local1)] */      #  219: 0911
            movi         a0, .Lrel025 /* .Ldata001 */          #  21b: 01fbff
            s32i.n       a2, a1, 0 /* arg0 -> [(local0)] */    #  21e: 2901
            beq          a0, a3, .Lbr015                       #  220: 37101d
            mov.n        a2, a0 /* .Ldata001 */                #  223: 2d00
            l32i.n       a3, a2, 20 /* [.Ldata006] */          #  225: 3852
            s32i.n       a3, a1, 8 /* [.Ldata006] -> [(local2)] */ #  227: 3921
            addi.n       a2, a2, 4 /* .Ldata002 */             #  229: 4b22
            movi.n       a3, 20 /* 0x00000014 */               #  22b: 1c43
            movi         a0, .Lrel027 /* bzero */              #  22d: 01f8ff
            callx0       a0 /* bzero */                        #  230: c00000
            l32i.n       a5, a1, 8 /* [(local2)] */            #  233: 5821
            beqz.n       a5, .Lbr015                           #  235: 8c85
            movi         a2, .Lrel026 /* .Ldata001 */          #  237: 21f5ff
            l32i.n       a3, a1, 0 /* [(local0)] */            #  23a: 3801
            l32i.n       a2, a2, 12 /* [.Ldata004] */          #  23c: 2832
            callx0       a5 /* [(local2)] */                   #  23e: c00500
.Lbr015:    l32i.n       a0, a1, 4 /* [(local1)] */            #  241: 0811
            addi         a1, a1, 16 /* (top of frame) */       #  243: 12c110
            ret.n                                              #  246: 0df0

# Function @ .irom0.text+0x248
# Local variables/stack:
#     (local0):  word[4]   @ -0x10
.literal_position
.Lfunc002:  movi.n       a2, 0 /* 0x00000000 */                #  248: 0c02
            addi         a1, a1, -16 /* (local0) */            #  24a: 12c1f0
            s32i.n       a0, a1, 0 /* a0 -> [(local0)] */      #  24d: 0901
            call0        sdk_chm_end_op                        #  24f: 050000
            l32i.n       a0, a1, 0 /* [(local0)] */            #  252: 0801
            addi         a1, a1, 16 /* (top of frame) */       #  254: 12c110
            ret.n                                              #  257: 0df0

            .balign      4
.Lrel028:   .word        .bss                                  #  25c: 00000000
.Lrel029:   .word        .bss                                  #  260: 00000000
.Lrel030:   .word        sdk_os_timer_disarm                   #  264: 00000000

# Function @ .irom0.text+0x268
# Local variables/stack:
#     (local0):  word[4]   @ -0x10
.literal_position
sdk_chm_cancel_op:
            addi         a1, a1, -16 /* (local0) */            #  268: 12c1f0
            s32i.n       a0, a1, 0 /* a0 -> [(local0)] */      #  26b: 0901
            movi         a0, .Lrel028 /* .Ldata001 */          #  26d: 01fbff
            l32i.n       a2, a0, 4 /* [.Ldata002] */           #  270: 2810
            beqz.n       a2, .Lbr016                           #  272: 9c12
            mov.n        a2, a0 /* .Ldata001 */                #  274: 2d00
            addi         a2, a2, 32 /* .Label001 */            #  276: 22c220
            movi         a0, .Lrel030 /* sdk_os_timer_disarm */ #  279: 01faff
            callx0       a0 /* sdk_os_timer_disarm */          #  27c: c00000
            movi.n       a2, 4 /* 0x00000004 */                #  27f: 0c42
            call0        sdk_chm_end_op                        #  281: 050000
            movi         a0, .Lrel029 /* .Ldata001 */          #  284: 01f7ff
.Lbr016:    l32i.n       a5, a0, 24 /* [.Ldata007] */          #  287: 5860
            beqz.n       a5, .Lbr017                           #  289: 8c55
            movi.n       a3, 4 /* 0x00000004 */                #  28b: 0c43
            l32i.n       a2, a0, 28 /* [.Ldata008] */          #  28d: 2870
            callx0       a5 /* [.Ldata007] */                  #  28f: c00500
.Lbr017:    l32i.n       a0, a1, 0 /* [(local0)] */            #  292: 0801
            addi         a1, a1, 16 /* (top of frame) */       #  294: 12c110
            ret.n                                              #  297: 0df0

            .balign      4
.Lrel031:   .word        sdk_g_ic                              #  29c: 00000000
.Lrel032:   .word        sdk_chm_get_current_channel           #  2a0: 00000000
.Lrel033:   .word        sdk_chm_set_current_channel           #  2a4: 00000000

# Function @ .irom0.text+0x2a8
# Local variables/stack:
#     (local0):  word      @ -0x10
#     (local1):  word[3]   @ -0xc
.literal_position
sdk_chm_return_home_channel:
            addi         a1, a1, -16 /* (local0) */            #  2a8: 12c1f0
            s32i.n       a12, a1, 4 /* a12 -> [(local1)] */    #  2ab: c911
            movi         a12, .Lrel031 /* sdk_g_ic */          #  2ad: c1fbff
            s32i.n       a0, a1, 0 /* a0 -> [(local0)] */      #  2b0: 0901
            l32i         a12, a12, 0x14c /* [sdk_g_ic+0x14c] */ #  2b2: c22c53
            movi         a0, .Lrel032 /* sdk_chm_get_current_channel */ #  2b5: 01faff
            callx0       a0 /* sdk_chm_get_current_channel */  #  2b8: c00000
            l16ui        a0, a2, 4                             #  2bb: 021202
            l16ui        a2, a12, 4 /* [[sdk_g_ic+0x14c]+0x4] */ #  2be: 221c02
            beq          a0, a2, .Lbr018                       #  2c1: 271007
            mov.n        a2, a12 /* [sdk_g_ic+0x14c] */        #  2c4: 2d0c
            movi         a0, .Lrel033 /* sdk_chm_set_current_channel */ #  2c6: 01f7ff
            callx0       a0 /* sdk_chm_set_current_channel */  #  2c9: c00000
.Lbr018:    l32i.n       a12, a1, 4 /* [(local1)] */           #  2cc: c811
            l32i.n       a0, a1, 0 /* [(local0)] */            #  2ce: 0801
            addi         a1, a1, 16 /* (top of frame) */       #  2d0: 12c110
            ret.n                                              #  2d3: 0df0

            .balign      4
.Lrel034:   .word        sdk_NMIIrqIsOn                        #  2d8: 00000000

# NOTE: The following is apparently unreferenced code/data
.Llit002:   .word        0x3feffe00                            #  2dc: 00feef3f

.Lrel035:   .word        sdk_NMIIrqIsOn                        #  2e0: 00000000
.Lrel036:   .word        .bss                                  #  2e4: 00000000
.Lrel037:   .word        sdk_phy_change_channel                #  2e8: 00000000
.Lrel038:   .word        vPortEnterCritical                    #  2ec: 00000000
.Lrel039:   .word        vPortExitCritical                     #  2f0: 00000000

# Function @ .irom0.text+0x2f4
# Local variables/stack:
#     (local0):  word      @ -0x10
#     (local1):  word      @ -0xc
#     (local2):  word[2]   @ -0x8
.literal_position
sdk_chm_set_current_channel:
            movi.n       a3, 1 /* 0x00000001 */                #  2f4: 0c13
            movi.n       a4, 0 /* 0x00000000 */                #  2f6: 0c04
            addi         a1, a1, -16 /* (local0) */            #  2f8: 12c1f0
            s32i.n       a13, a1, 8 /* a13 -> [(local2)] */    #  2fb: d921
            s32i.n       a12, a1, 4 /* a12 -> [(local1)] */    #  2fd: c911
            s32i.n       a0, a1, 0 /* a0 -> [(local0)] */      #  2ff: 0901
            mov.n        a12, a2 /* arg0 */                    #  301: cd02
            l16ui        a2, a2, 4 /* [arg0+0x4] */            #  303: 221202
            movi         a0, .Lrel037 /* sdk_phy_change_channel */ #  306: 01f8ff
            callx0       a0 /* sdk_phy_change_channel */       #  309: c00000
            movi         a2, .Lrel034 /* sdk_NMIIrqIsOn */     #  30c: 21f3ff
            movi.n       a0, -32 /* 0xffffffe0 */              #  30f: 6c00
            l8ui         a2, a2, 0 /* [sdk_NMIIrqIsOn] */      #  311: 220200
            movi         a13, .Llit002 /* 0x3feffe00 */        #  314: d1f2ff
            bnez.n       a2, .Lbr020                           #  317: ec42
            movi         a0, .Lrel038 /* vPortEnterCritical */ #  319: 01f4ff
            callx0       a0 /* vPortEnterCritical */           #  31c: c00000
            movi.n       a0, -32 /* 0xffffffe0 */              #  31f: 6c00
.Lbr019:    memw                                               #  321: c02000
            l32i         a5, a13, 0x200 /* [0x3ff00000] */     #  324: 522d80
            and          a5, a5, a0                            #  327: 005510
            memw                                               #  32a: c02000
            s32i         a5, a13, 0x200 /* a5 -> [0x3ff00000] */ #  32d: 526d80
            memw                                               #  330: c02000
            l32i         a4, a13, 0x200 /* [0x3ff00000] */     #  333: 422d80
            bbsi         a4, 0, .Lbr019                        #  336: 07e4e7
            movi         a2, .Lrel035 /* sdk_NMIIrqIsOn */     #  339: 21e9ff
            l8ui         a2, a2, 0 /* [sdk_NMIIrqIsOn] */      #  33c: 220200
.Lbr020:    movi         a3, .Lrel036 /* .Ldata001 */          #  33f: 31e9ff
            s32i.n       a12, a3, 60 /* arg0 -> [.Ldata009] */ #  342: c9f3
            bnez.n       a2, .Lbr021                           #  344: dc82
            memw                                               #  346: c02000
            l32i         a4, a13, 0x200 /* [0x3ff00000] */     #  349: 422d80
            movi.n       a5, 1 /* 0x00000001 */                #  34c: 0c15
            and          a4, a4, a0                            #  34e: 004410
            or           a4, a4, a5                            #  351: 504420
            memw                                               #  354: c02000
            s32i         a4, a13, 0x200 /* a4 -> [0x3ff00000] */ #  357: 426d80
            movi         a0, .Lrel039 /* vPortExitCritical */  #  35a: 01e5ff
            callx0       a0 /* vPortExitCritical */            #  35d: c00000
.Lbr021:    l32i.n       a12, a1, 4 /* [(local1)] */           #  360: c811
            l32i.n       a13, a1, 8 /* [(local2)] */           #  362: d821
            l32i.n       a0, a1, 0 /* [(local0)] */            #  364: 0801
            addi         a1, a1, 16 /* (top of frame) */       #  366: 12c110
            ret.n                                              #  369: 0df0

            .balign      4
.Lrel040:   .word        .bss                                  #  36c: 00000000

# Function @ .irom0.text+0x370
.literal_position
sdk_chm_freq2index:
            movi.n       a5, 0 /* 0x00000000 */                #  370: 0c05
            movi         a6, .Lrel040 /* .Ldata001 */          #  372: 61feff
            movi.n       a7, 14 /* 0x0000000e */               #  375: 0ce7
            l32i.n       a6, a6, 0 /* [.Ldata001] */           #  377: 6806
.Lbr022:    addx2        a8, a5, a5                            #  379: 508590
            addx4        a8, a8, a6                            #  37c: 6088a0
            l16ui        a8, a8, 136                           #  37f: 821844
            bne          a8, a2, .Lbr023                       #  382: 279803
            mov.n        a2, a5                                #  385: 2d05
            ret.n                                              #  387: 0df0
.Lbr023:    addi.n       a5, a5, 1                             #  389: 1b55
            extui        a5, a5, 0, 8                          #  38b: 505074
            bne          a5, a7, .Lbr022                       #  38e: 7795e7
            movi         a2, 255 /* 0x000000ff */              #  391: 22a0ff
            ret.n         /* 0x000000ff */                     #  394: 0df0

            .balign      4
.Lrel041:   .word        sdk_g_ic                              #  398: 00000000
.Lrel042:   .word        sdk_ieee80211_chan2ieee               #  39c: 00000000
.Lrel043:   .word        sdk_chm_get_current_channel           #  3a0: 00000000
.Lrel044:   .word        sdk_ieee80211_chan2ieee               #  3a4: 00000000

# Function @ .irom0.text+0x3a8
# Local variables/stack:
#     (local0):  word      @ -0x10
#     (local1):  word[3]   @ -0xc
.literal_position
sdk_chm_check_same_channel:
            movi         a2, .Lrel041 /* sdk_g_ic */           #  3a8: 21fcff
            addi         a1, a1, -16 /* (local0) */            #  3ab: 12c1f0
            s32i.n       a0, a1, 4 /* a0 -> [(local1)] */      #  3ae: 0911
            l32i         a2, a2, 0x14c /* [sdk_g_ic+0x14c] */  #  3b0: 222253
            movi         a0, .Lrel042 /* sdk_ieee80211_chan2ieee */ #  3b3: 01faff
            callx0       a0 /* sdk_ieee80211_chan2ieee */      #  3b6: c00000
            s32i.n       a2, a1, 0 /* a2 -> [(local0)] */      #  3b9: 2901
            movi         a0, .Lrel043 /* sdk_chm_get_current_channel */ #  3bb: 01f9ff
            callx0       a0 /* sdk_chm_get_current_channel */  #  3be: c00000
            movi         a0, .Lrel044 /* sdk_ieee80211_chan2ieee */ #  3c1: 01f8ff
            callx0       a0 /* sdk_ieee80211_chan2ieee */      #  3c4: c00000
            movi.n       a3, 0 /* 0x00000000 */                #  3c7: 0c03
            l32i.n       a4, a1, 0 /* [(local0)] */            #  3c9: 4801
            l32i.n       a0, a1, 4 /* [(local1)] */            #  3cb: 0811
            sub          a4, a4, a2                            #  3cd: 2044c0
            addi         a1, a1, 16 /* (top of frame) */       #  3d0: 12c110
            movi.n       a2, 1 /* 0x00000001 */                #  3d3: 0c12
            movnez       a2, a3, a4                            #  3d5: 402393
            ret.n                                              #  3d8: 0df0
