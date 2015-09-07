
            .section     .text, "ax", @progbits

# Function @ .text+0x0
.literal_position
sdk__xt_context_save:
            s32i.n       a2, a1, 20 /* arg0 -> [(FP)+0x14] */  #    0: 2951
            s32i.n       a3, a1, 24 /* arg1 -> [(FP)+0x18] */  #    2: 3961
            s32i.n       a4, a1, 28 /* arg2 -> [(FP)+0x1c] */  #    4: 4971
            s32i.n       a5, a1, 32 /* arg3 -> [(FP)+0x20] */  #    6: 5981
            s32i.n       a6, a1, 36 /* arg4 -> [(FP)+0x24] */  #    8: 6991
            s32i.n       a7, a1, 40 /* arg5 -> [(FP)+0x28] */  #    a: 79a1
            s32i.n       a8, a1, 44 /* a8 -> [(FP)+0x2c] */    #    c: 89b1
            s32i.n       a9, a1, 48 /* a9 -> [(FP)+0x30] */    #    e: 99c1
            s32i.n       a10, a1, 52 /* a10 -> [(FP)+0x34] */  #   10: a9d1
            s32i.n       a11, a1, 56 /* a11 -> [(FP)+0x38] */  #   12: b9e1
            rsr.sar      a3                                    #   14: 300303
            s32i         a3, a1, 76 /* a3 -> [(FP)+0x4c] */    #   17: 326113
            ret.n         /* arg0 */                           #   1a: 0df0

# Function @ .text+0x1c
.literal_position
sdk__xt_context_restore:
            l32i         a3, a1, 76 /* [(FP)+0x4c] */          #   1c: 322113
            l32i.n       a2, a1, 20 /* [(FP)+0x14] */          #   1f: 2851
            wsr.sar      a3                                    #   21: 300313
            l32i.n       a3, a1, 24 /* [(FP)+0x18] */          #   24: 3861
            l32i.n       a4, a1, 28 /* [(FP)+0x1c] */          #   26: 4871
            l32i.n       a5, a1, 32 /* [(FP)+0x20] */          #   28: 5881
            l32i.n       a6, a1, 36 /* [(FP)+0x24] */          #   2a: 6891
            l32i.n       a7, a1, 40 /* [(FP)+0x28] */          #   2c: 78a1
            l32i.n       a8, a1, 44 /* [(FP)+0x2c] */          #   2e: 88b1
            l32i.n       a9, a1, 48 /* [(FP)+0x30] */          #   30: 98c1
            l32i.n       a10, a1, 52 /* [(FP)+0x34] */         #   32: a8d1
            l32i.n       a11, a1, 56 /* [(FP)+0x38] */         #   34: b8e1
            l32i.n       a12, a1, 60 /* [(FP)+0x3c] */         #   36: c8f1
            l32i         a13, a1, 64 /* [(FP)+0x40] */         #   38: d22110
            ret.n         /* [(FP)+0x14] */                    #   3b: 0df0

            .section     .data, "aw", @progbits

            .section     .bss, "aw", @nobits
