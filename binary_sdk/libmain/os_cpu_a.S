
            .section     .literal, "ax", @progbits

            .section     .text, "ax", @progbits

.Lrel001:   .word        _xt_user_exit                         #    0: 00000000
.Lrel002:   .word        vPortEnterCritical                    #    4: 00000000
.Lrel003:   .word        vTaskSwitchContext                    #    8: 00000000
.Lrel004:   .word        vPortExitCritical                     #    c: 00000000
.Lrel005:   .word        sdk__xt_int_exit                      #   10: 00000000

# Function @ .text+0x14
# Local variables/stack:
#     (local0):  word      @ -0x50
#     (local1):  word      @ -0x4c
#     (local2):  word      @ -0x48
#     (local3):  word      @ -0x44
#     (local4):  word[16]  @ -0x40
.literal_position
vPortYield: wsr.excsave1 a0                                    #   14: 00d113
            addi         a1, a1, -80 /* (local0) */            #   17: 12c1b0
            s32i.n       a0, a1, 4 /* a0 -> [(local1)] */      #   1a: 0911
            addi         a0, a1, 80 /* (top of frame) */       #   1c: 02c150
            s32i.n       a0, a1, 16 /* (top of frame) -> [(local4)] */ #   1f: 0941
            rsr.ps       a0                                    #   21: 00e603
            s32i.n       a0, a1, 8 /* a0 -> [(local2)] */      #   24: 0921
            rsr.excsave1 a0                                    #   26: 00d103
            s32i.n       a0, a1, 12 /* a0 -> [(local3)] */     #   29: 0931
            movi         a0, .Lrel001 /* _xt_user_exit */      #   2b: 01f5ff
            s32i.n       a0, a1, 0 /* _xt_user_exit -> [(local0)] */ #   2e: 0901
            call0        sdk__xt_int_enter                     #   30: 050000
            movi         a0, .Lrel002 /* vPortEnterCritical */ #   33: 01f4ff
            callx0       a0 /* vPortEnterCritical */           #   36: c00000
            movi         a0, .Lrel003 /* vTaskSwitchContext */ #   39: 01f3ff
            callx0       a0 /* vTaskSwitchContext */           #   3c: c00000
            movi         a0, .Lrel004 /* vPortExitCritical */  #   3f: 01f3ff
            callx0       a0 /* vPortExitCritical */            #   42: c00000
            movi         a0, .Lrel005 /* sdk__xt_int_exit */   #   45: 01f2ff
            callx0       a0 /* sdk__xt_int_exit */             #   48: c00000
            ret.n                                              #   4b: 0df0

            .balign      4
.Lrel006:   .word        sdk__xt_context_save                  #   50: 00000000
.Lrel007:   .word        pxCurrentTCB                          #   54: 00000000
.Lrel008:   .word        pxCurrentTCB                          #   58: 00000000
.Lrel009:   .word        pxCurrentTCB                          #   5c: 00000000
.Lrel010:   .word        sdk__xt_context_restore               #   60: 00000000
.Llit001:   .word        0x000c3500                            #   64: 00350c00
.Lrel011:   .word        xPortSysTickHandle                    #   68: 00000000
.Lrel012:   .word        vTaskSwitchContext                    #   6c: 00000000
.Llit002:   .word        0x000c3500                            #   70: 00350c00

# Function @ .text+0x74
.literal_position
sdk__xt_int_enter:
            s32i.n       a12, a1, 60 /* a12 -> [(FP)+0x3c] */  #   74: c9f1
            s32i         a13, a1, 64 /* a13 -> [(FP)+0x40] */  #   76: d26110
            mov.n        a12, a0                               #   79: cd00
            movi         a0, .Lrel006 /* sdk__xt_context_save */ #   7b: 01f5ff
            callx0       a0 /* sdk__xt_context_save */         #   7e: c00000
            movi         a0, .Lrel007 /* pxCurrentTCB */       #   81: 01f4ff
            l32i.n       a0, a0, 0 /* [pxCurrentTCB] */        #   84: 0800
            s32i.n       a1, a0, 0 /* (top of frame) -> [[pxCurrentTCB]] */ #   86: 1900
            mov.n        a0, a12                               #   88: 0d0c
            ret.n                                              #   8a: 0df0

# Function @ .text+0x8c
.literal_position
sdk__xt_int_exit:
            s32i         a14, a1, 68 /* a14 -> [(FP)+0x44] */  #   8c: e26111
            s32i         a15, a1, 72 /* a15 -> [(FP)+0x48] */  #   8f: f26112
            movi         a1, .Lrel008 /* pxCurrentTCB */       #   92: 11f1ff
            l32i.n       a1, a1, 0 /* [pxCurrentTCB] */        #   95: 1801
            l32i.n       a1, a1, 0 /* [[pxCurrentTCB]] */      #   97: 1801
            movi         a14, .Lrel009 /* pxCurrentTCB */      #   99: e1f0ff
            l32i.n       a14, a14, 0 /* [pxCurrentTCB] */      #   9c: e80e
            addi         a15, a1, 80 /* [[pxCurrentTCB]]+0x50 */ #   9e: f2c150
            s32i.n       a15, a14, 0 /* [[pxCurrentTCB]]+0x50 -> [[pxCurrentTCB]] */ #   a1: f90e
            movi         a0, .Lrel010 /* sdk__xt_context_restore */ #   a3: 01efff
            callx0       a0 /* sdk__xt_context_restore */      #   a6: c00000
            l32i         a14, a1, 68 /* [[[pxCurrentTCB]]+0x44] */ #   a9: e22111
            l32i         a15, a1, 72 /* [[[pxCurrentTCB]]+0x48] */ #   ac: f22112
            l32i.n       a0, a1, 0 /* [[[pxCurrentTCB]]] */    #   af: 0801
            ret.n                                              #   b1: 0df0

            .balign      4
# Function @ .text+0xb4
# Local variables/stack:
#     (local0):  word      @ -0x10
#     (local1):  word      @ -0xc
#     (local2):  word[2]   @ -0x8
.literal_position
sdk__xt_timer_int:
            addi         a1, a1, -16 /* (local0) */            #   b4: 12c1f0
            s32i.n       a0, a1, 0 /* a0 -> [(local0)] */      #   b7: 0901
.Lbr001:    movi         a2, .Llit001 /* .Llit001 */           #   b9: 21eaff
            rsr.ccompare0 a3                                    #   bc: 30f003
            add.n        a4, a3, a2                            #   bf: 2a43
            wsr.ccompare0 a4                                    #   c1: 40f013
            esync                                              #   c4: 202000
            s32i.n       a2, a1, 4 /* a2 -> [(local1)] */      #   c7: 2911
            s32i.n       a3, a1, 8 /* a3 -> [(local2)] */      #   c9: 3921
            movi         a0, .Lrel011 /* .Lrel011 */           #   cb: 01e7ff
            callx0       a0                                    #   ce: c00000
            l32i.n       a2, a1, 4 /* [(local1)] */            #   d1: 2811
            l32i.n       a3, a1, 8 /* [(local2)] */            #   d3: 3821
            esync                                              #   d5: 202000
            rsr.ccount   a4                                    #   d8: 40ea03
            sub          a4, a4, a3                            #   db: 3044c0
            blt          a2, a4, .Lbr001                       #   de: 4722d7
            l32i.n       a0, a1, 0 /* [(local0)] */            #   e1: 0801
            addi         a1, a1, 16 /* (top of frame) */       #   e3: 12c110
            ret.n         /* [(local1)] */                     #   e6: 0df0

# Function @ .text+0xe8
# Local variables/stack:
#     (local0):  word      @ -0x10
#     (local1):  word      @ -0xc
#     (local2):  word[2]   @ -0x8
.literal_position
sdk__xt_timer_int1:
            addi         a1, a1, -16 /* (local0) */            #   e8: 12c1f0
            s32i.n       a0, a1, 0 /* a0 -> [(local0)] */      #   eb: 0901
            s32i.n       a2, a1, 4 /* arg0 -> [(local1)] */    #   ed: 2911
            s32i.n       a3, a1, 8 /* arg1 -> [(local2)] */    #   ef: 3921
            movi         a0, .Lrel012 /* vTaskSwitchContext */ #   f1: 01deff
            callx0       a0 /* vTaskSwitchContext */           #   f4: c00000
            l32i.n       a2, a1, 4 /* [(local1)] */            #   f7: 2811
            l32i.n       a3, a1, 8 /* [(local2)] */            #   f9: 3821
            l32i.n       a0, a1, 0 /* [(local0)] */            #   fb: 0801
            addi         a1, a1, 16 /* (top of frame) */       #   fd: 12c110
            ret.n         /* [(local1)] */                     #  100: 0df0

            .balign      4
# Function @ .text+0x104
# Local variables/stack:
#     (local0):  word[4]   @ -0x10
.literal_position
sdk__xt_tick_timer_init:
            addi         a1, a1, -16 /* (local0) */            #  104: 12c1f0
            s32i.n       a0, a1, 0 /* a0 -> [(local0)] */      #  107: 0901
            movi         a3, .Llit002 /* 0x000c3500 */         #  109: 31d9ff
            rsr.ccount   a2                                    #  10c: 20ea03
            add.n        a2, a2, a3                            #  10f: 3a22
            wsr.ccompare0 a2                                    #  111: 20f013
            movi.n       a2, 0 /* 0x00000000 */                #  114: 0c02
            xsr.intenable a2                                    #  116: 20e461
            movi.n       a3, 64 /* 0x00000040 */               #  119: 4c03
            or           a2, a2, a3                            #  11b: 302220
            wsr.intenable a2                                    #  11e: 20e413
            l32i.n       a0, a1, 0 /* [(local0)] */            #  121: 0801
            addi         a1, a1, 16 /* (top of frame) */       #  123: 12c110
            ret.n                                              #  126: 0df0

# Function @ .text+0x128
# Local variables/stack:
#     (local0):  word[4]   @ -0x10
.literal_position
sdk__xt_isr_unmask:
            addi         a1, a1, -16 /* (local0) */            #  128: 12c1f0
            s32i.n       a0, a1, 0 /* a0 -> [(local0)] */      #  12b: 0901
            movi.n       a3, 0 /* 0x00000000 */                #  12d: 0c03
            xsr.intenable a3                                    #  12f: 30e461
            or           a3, a2, a3                            #  132: 303220
            wsr.intenable a3                                    #  135: 30e413
            l32i.n       a0, a1, 0 /* [(local0)] */            #  138: 0801
            addi         a1, a1, 16 /* (top of frame) */       #  13a: 12c110
            ret.n         /* arg0 */                           #  13d: 0df0

            .balign      4
# Function @ .text+0x140
# Local variables/stack:
#     (local0):  word[4]   @ -0x10
.literal_position
sdk__xt_isr_mask:
            addi         a1, a1, -16 /* (local0) */            #  140: 12c1f0
            s32i.n       a0, a1, 0 /* a0 -> [(local0)] */      #  143: 0901
            movi.n       a3, 0 /* 0x00000000 */                #  145: 0c03
            xsr.intenable a3                                    #  147: 30e461
            and          a3, a2, a3                            #  14a: 303210
            wsr.intenable a3                                    #  14d: 30e413
            l32i.n       a0, a1, 0 /* [(local0)] */            #  150: 0801
            addi         a1, a1, 16 /* (top of frame) */       #  152: 12c110
            ret.n         /* arg0 */                           #  155: 0df0

            .balign      4
# Function @ .text+0x158
# Local variables/stack:
#     (local0):  word[4]   @ -0x10
.literal_position
sdk__xt_read_ints:
            addi         a1, a1, -16 /* (local0) */            #  158: 12c1f0
            s32i.n       a0, a1, 0 /* a0 -> [(local0)] */      #  15b: 0901
            rsr.interrupt a2                                    #  15d: 20e203
            l32i.n       a0, a1, 0 /* [(local0)] */            #  160: 0801
            addi         a1, a1, 16 /* (top of frame) */       #  162: 12c110
            ret.n                                              #  165: 0df0

            .balign      4
# Function @ .text+0x168
# Local variables/stack:
#     (local0):  word[4]   @ -0x10
.literal_position
sdk__xt_clear_ints:
            addi         a1, a1, -16 /* (local0) */            #  168: 12c1f0
            s32i.n       a0, a1, 0 /* a0 -> [(local0)] */      #  16b: 0901
            wsr.intclear a2                                    #  16d: 20e313
            l32i.n       a0, a1, 0 /* [(local0)] */            #  170: 0801
            addi         a1, a1, 16 /* (top of frame) */       #  172: 12c110
            ret.n                                              #  175: 0df0

            .section     .data, "aw", @progbits

            .section     .bss, "aw", @nobits
