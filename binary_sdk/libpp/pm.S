
            .section     .irom0.literal, "ax", @progbits

            .section     .text, "ax", @progbits

            .section     .data, "aw", @progbits

.Ldata001:  .byte        0x02

            .section     .bss, "aw", @nobits

.Ldata002:  .byte        0x00
.Ldata003:  .byte        0x00
            .byte        0x00, 0x00
.Ldata004:  .word        0x00000000                            #    4: 00000000
.Ldata005:  .word        0x00000000                            #    8: 00000000
.Ldata006:  .word        0x00000000                            #    c: 00000000
.Ldata007:  .word        0x00000000                            #   10: 00000000
.Ldata008:  .word        0x00000000                            #   14: 00000000
.Ldata009:  .word        0x00000000                            #   18: 00000000
.Ldata010:  .word        0x00000000                            #   1c: 00000000

# NOTE: 4 non-alignment zero bytes skipped.

            .skip        4
.Ldata011:  .word        0x00000000                            #   24: 00000000

# NOTE: 4 non-alignment zero bytes skipped.

            .skip        4
.Ldata012:  .hword       0x0000                                #   2c: 0000
.Ldata013:  .byte        0x00
.Ldata014:  .byte        0x00
.Ldata015:  .word        0x00000000                            #   30: 00000000
.Ldata016:  .byte        0x00
.Ldata017:  .byte        0x00
.Ldata018:  .byte        0x00
.Ldata019:  .byte        0x00
.Ldata020:  .byte        0x00
.Ldata021:  .byte        0x00
.Ldata022:  .byte        0x00
.Ldata023:  .byte        0x00
.Ldata024:  .byte        0x00
.Ldata025:  .byte        0x00
.Ldata026:  .byte        0x00
.Ldata027:  .byte        0x00
.Ldata028:  .byte        0x00
.Label001:  .space       7
.Ldata029:  .hword       0x0000                                #   48: 0000
            .balign      4
.Ldata030:  .word        0x00000000                            #   4c: 00000000
.Ldata031:  .word        0x00000000                            #   50: 00000000
.Label002:  .space       28
.Label003:  .space       28
.Label004:  .space       28
.Label005:  .space       28
.Label006:  .space       24
.Label007:  .word        0x00000000                            #   dc: 00000000
.Ldata032:  .byte        0x00
.Ldata033:  .byte        0x00
.Ldata034:  .byte        0x00
.Ldata035:  .byte        0x00
.Ldata036:  .byte        0x00

# NOTE: 1 non-alignment zero bytes skipped.

            .skip        1
.Ldata037:  .hword       0x0000                                #   e6: 0000
.Ldata038:  .hword       0x0000                                #   e8: 0000

# NOTE: 8 non-alignment zero bytes skipped.

            .skip        10
.Ldata039:  .byte        0x00
.Ldata040:  .byte        0x00
            .byte        0x00, 0x00
.Ldata041:  .word        0x00000000                            #   f8: 00000000
            .word        0x00000000                            #   fc: 00000000
            .space       64
.Ldata042:  .byte        0x00, 0x00, 0x00
            .byte        0x00
.Ldata043:  .byte        0x00
.Ldata044:  .byte        0x00
            .byte        0x00
.Ldata045:  .byte        0x00
.Ldata046:  .byte        0x00

            .section     .irom0.text, "ax", @progbits

.Lrel001:   .word        .bss                                  #    0: 00000000
.Lrel002:   .word        vPortEnterCritical                    #    4: 00000000
.Lrel003:   .word        vPortExitCritical                     #    8: 00000000

# Function @ .irom0.text+0xc
# Local variables/stack:
#     (local0):  word      @ -0x10
#     (local1):  word[3]   @ -0xc
.literal_position
.Lfunc001:  addi         a1, a1, -16 /* (local0) */            #    c: 12c1f0
            s32i.n       a0, a1, 0 /* a0 -> [(local0)] */      #    f: 0901
            movi         a0, .Lrel002 /* vPortEnterCritical */ #   11: 01fcff
            callx0       a0 /* vPortEnterCritical */           #   14: c00000
            movi         a4, .Lrel001 /* .Ldata002 */          #   17: 41faff
            l8ui         a2, a4, 0 /* [.Ldata002] */           #   1a: 220400
            addmi        a3, a4, 256 /* .bss+0x100 */          #   1d: 32d401
            addi.n       a0, a2, 1 /* [.Ldata002]+0x1 */       #   20: 1b02
            addx8        a2, a2, a3                            #   22: 3022b0
            extui        a0, a0, 0, 8                          #   25: 000074
            bltui        a0, 8, .Lbr001                        #   28: b68001
            movi.n       a0, 0 /* 0x00000000 */                #   2b: 0c00
.Lbr001:    s32i.n       a2, a1, 4 /* a2 -> [(local1)] */      #   2d: 2911
            l8ui         a5, a4, 1 /* [.Ldata003] */           #   2f: 520401
            s8i          a0, a4, 0 /* a0 -> [.Ldata002] */     #   32: 024400
            addi.n       a5, a5, 1 /* [.Ldata003]+0x1 */       #   35: 1b55
            s8i          a5, a4, 1 /* [.Ldata003]+0x1 -> [.Ldata003] */ #   37: 524401
            movi         a0, .Lrel003 /* vPortExitCritical */  #   3a: 01f3ff
            callx0       a0 /* vPortExitCritical */            #   3d: c00000
            l32i.n       a6, a1, 0 /* [(local0)] */            #   40: 6801
            l32i.n       a2, a1, 4 /* [(local1)] */            #   42: 2811
            mov.n        a0, a6 /* [(local0)] */               #   44: 0d06
            addi         a1, a1, 16 /* (top of frame) */       #   46: 12c110
            ret.n         /* [(local1)] */                     #   49: 0df0

            .balign      4
.Lrel004:   .word        .bss                                  #   4c: 00000000

# Function @ .irom0.text+0x50
.literal_position
.Lfunc002:  movi         a3, .Lrel004 /* .Ldata002 */          #   50: 31ffff
            l8ui         a2, a3, 1 /* [.Ldata003] */           #   53: 220301
            addi.n       a2, a2, -1 /* [.Ldata003]-0x1 */      #   56: 0b22
            s8i          a2, a3, 1 /* [.Ldata003]-0x1 -> [.Ldata003] */ #   58: 224301
            ret.n         /* [.Ldata003]-0x1 */                #   5b: 0df0

            .balign      4
.Lrel005:   .word        .bss                                  #   60: 00000000
.Lrel006:   .word        sdk_g_phyFuns                         #   64: 00000000
.Lrel007:   .word        .Ldata004                             #   68: 04000000
.Lrel008:   .word        .bss                                  #   6c: 00000000
.Lrel009:   .word        sdk_pm_rtc_clock_cali                 #   70: 00000000

# Function @ .irom0.text+0x74
# Local variables/stack:
#     (local0):  word[4]   @ -0x10
.literal_position
sdk_pm_rtc_clock_cali_proc:
            movi         a2, 106 /* 0x0000006a */              #   74: 22a06a
            movi.n       a3, 2 /* 0x00000002 */                #   77: 0c23
            movi.n       a4, 8 /* 0x00000008 */                #   79: 0c84
            movi         a7, .Lrel005 /* .Ldata002 */          #   7b: 71f9ff
            addi         a1, a1, -16 /* (local0) */            #   7e: 12c1f0
            s32i.n       a0, a1, 0 /* a0 -> [(local0)] */      #   81: 0901
            movi         a0, .Lrel006 /* sdk_g_phyFuns */      #   83: 01f8ff
            movi.n       a6, 0 /* 0x00000000 */                #   86: 0c06
            l32i.n       a0, a0, 0 /* [sdk_g_phyFuns] */       #   88: 0800
            mov.n        a5, a6 /* 0x00000000 */               #   8a: 5d06
            l32i         a0, a0, 152 /* [[sdk_g_phyFuns]+0x98] */ #   8c: 022026
            s32i.n       a6, a7, 8 /* 0x00000000 -> [.Ldata005] */ #   8f: 6927
            callx0       a0 /* [[sdk_g_phyFuns]+0x98] */       #   91: c00000
            movi         a2, .Lrel007 /* .Ldata004 */          #   94: 21f5ff
            movi         a0, .Lrel009 /* sdk_pm_rtc_clock_cali */ #   97: 01f6ff
            callx0       a0 /* sdk_pm_rtc_clock_cali */        #   9a: c00000
            movi         a2, .Lrel008 /* .Ldata002 */          #   9d: 21f3ff
            l32i.n       a0, a1, 0 /* [(local0)] */            #   a0: 0801
            addi         a1, a1, 16 /* (top of frame) */       #   a2: 12c110
            l32i.n       a2, a2, 8 /* [.Ldata005] */           #   a5: 2822
            ret.n         /* [.Ldata005] */                    #   a7: 0df0

            .balign      4
.Lrel010:   .word        .bss                                  #   ac: 00000000
.Lrel011:   .word        sdk_pm_usec2rtc                       #   b0: 00000000
.Lrel012:   .word        sdk_pm_set_sleep_cycles               #   b4: 00000000

# Function @ .irom0.text+0xb8
# Local variables/stack:
#     (local0):  word[4]   @ -0x10
.literal_position
sdk_pm_set_sleep_time:
            movi         a3, .Lrel010 /* .Ldata002 */          #   b8: 31fdff
            addi         a1, a1, -16 /* (local0) */            #   bb: 12c1f0
            s32i.n       a0, a1, 0 /* a0 -> [(local0)] */      #   be: 0901
            l32i.n       a3, a3, 8 /* [.Ldata005] */           #   c0: 3823
            movi         a0, .Lrel011 /* sdk_pm_usec2rtc */    #   c2: 01fbff
            callx0       a0 /* sdk_pm_usec2rtc */              #   c5: c00000
            movi         a0, .Lrel012 /* sdk_pm_set_sleep_cycles */ #   c8: 01fbff
            callx0       a0 /* sdk_pm_set_sleep_cycles */      #   cb: c00000
            l32i.n       a0, a1, 0 /* [(local0)] */            #   ce: 0801
            addi         a1, a1, 16 /* (top of frame) */       #   d0: 12c110
            ret.n                                              #   d3: 0df0

            .balign      4
.Lrel013:   .word        .data                                 #   d8: 00000000
.Lrel014:   .word        .bss                                  #   dc: 00000000
.Lrel015:   .word        .bss                                  #   e0: 00000000
.Lrel016:   .word        .rodata.str1.4                        #   e4: 00000000
.Lrel017:   .word        sdk_pend_flag_periodic_cal            #   e8: 00000000
.Lrel018:   .word        sdk_pend_flag_noise_check             #   ec: 00000000
.Lrel019:   .word        sdk_NMIIrqIsOn                        #   f0: 00000000
.Llit001:   .word        0x3feffe00                            #   f4: 00feef3f
.Lrel020:   .word        .bss                                  #   f8: 00000000
.Llit002:   .word        0x3feffe00                            #   fc: 00feef3f
.Lrel021:   .word        sdk_pm_wakeup_init                    #  100: 00000000
.Lrel022:   .word        sdk_clockgate_watchdog                #  104: 00000000
.Lrel023:   .word        sdk_pm_wakeup_init                    #  108: 00000000
.Lrel024:   .word        sdk_clockgate_watchdog                #  10c: 00000000
.Lrel025:   .word        printf                                #  110: 00000000
.Lrel026:   .word        sdk_periodic_cal_top                  #  114: 00000000
.Lrel027:   .word        sdk_pm_wakeup_init                    #  118: 00000000
.Lrel028:   .word        vPortExitCritical                     #  11c: 00000000
.Lrel029:   .word        sdk_clockgate_watchdog                #  120: 00000000
.Lrel030:   .word        sdk_ets_update_cpu_frequency          #  124: 00000000

# Function @ .irom0.text+0x128
# Local variables/stack:
#     (local0):  word[4]   @ -0x10
.literal_position
.Lfunc003:  addi         a1, a1, -16 /* (local0) */            #  128: 12c1f0
            s32i.n       a0, a1, 0 /* a0 -> [(local0)] */      #  12b: 0901
            movi         a0, .Lrel013 /* .Ldata001 */          #  12d: 01eaff
            movi         a2, .Lrel014 /* .Ldata002 */          #  130: 21ebff
            l8ui         a0, a0, 0 /* [.Ldata001] */           #  133: 020000
            l8ui         a2, a2, 224 /* [.Ldata032] */         #  136: 2202e0
            bnei         a0, 1, .Lbr002                        #  139: 661017
            bgeui        a2, 2, .Lbr006                        #  13c: f62265
            movi.n       a2, 2 /* 0x00000002 */                #  13f: 0c22
            movi.n       a3, 0 /* 0x00000000 */                #  141: 0c03
            movi         a0, .Lrel021 /* sdk_pm_wakeup_init */ #  143: 01efff
            callx0       a0 /* sdk_pm_wakeup_init */           #  146: c00000
            movi         a4, .Lrel015 /* .Ldata002 */          #  149: 41e5ff
            movi.n       a3, 2 /* 0x00000002 */                #  14c: 0c23
            s8i          a3, a4, 224 /* 0x02 -> [.Ldata032] */ #  14e: 3244e0
            j            .Lbr007                               #  151: 861600
.Lbr002:    bnei         a0, 2, .Lbr003                        #  154: 662019
            movi.n       a2, 1 /* 0x00000001 */                #  157: 0c12
            movi         a0, .Lrel022 /* sdk_clockgate_watchdog */ #  159: 01eaff
            callx0       a0 /* sdk_clockgate_watchdog */       #  15c: c00000
            movi.n       a2, 8 /* 0x00000008 */                #  15f: 0c82
            movi.n       a3, 0 /* 0x00000000 */                #  161: 0c03
            movi         a0, .Lrel023 /* sdk_pm_wakeup_init */ #  163: 01e9ff
            callx0       a0 /* sdk_pm_wakeup_init */           #  166: c00000
            movi.n       a2, 0 /* 0x00000000 */                #  169: 0c02
            movi         a0, .Lrel024 /* sdk_clockgate_watchdog */ #  16b: 01e8ff
            callx0       a0 /* sdk_clockgate_watchdog */       #  16e: c00000
.Lbr003:    movi         a2, .Lrel016 /* .Lrel016 */           #  171: 21dcff
            movi         a0, .Lrel025 /* .Lrel025 */           #  174: 01e7ff
            callx0       a0                                    #  177: c00000
            movi         a4, .Lrel017 /* sdk_pend_flag_periodic_cal */ #  17a: 41dbff
            l8ui         a5, a4, 0 /* [sdk_pend_flag_periodic_cal] */ #  17d: 520400
            movi.n       a0, 0 /* 0x00000000 */                #  180: 0c00
            bnei         a5, 1, .Lbr004                        #  182: 66150c
            movi.n       a2, 0 /* 0x00000000 */                #  185: 0c02
            s8i          a2, a4, 0 /* 0x00 -> [sdk_pend_flag_periodic_cal] */ #  187: 224400
            movi         a0, .Lrel026 /* sdk_periodic_cal_top */ #  18a: 01e2ff
            callx0       a0 /* sdk_periodic_cal_top */         #  18d: c00000
            movi.n       a0, 0 /* 0x00000000 */                #  190: 0c00
.Lbr004:    movi         a2, .Lrel018 /* sdk_pend_flag_noise_check */ #  192: 21d6ff
            l8ui         a6, a2, 0 /* [sdk_pend_flag_noise_check] */ #  195: 620200
            bnei         a6, 1, .Lbr005                        #  198: 661602
            s8i          a0, a2, 0 /* 0x00 -> [sdk_pend_flag_noise_check] */ #  19b: 024200
.Lbr005:    l32i.n       a0, a1, 0 /* [(local0)] */            #  19e: 0801
            addi         a1, a1, 16 /* (top of frame) */       #  1a0: 12c110
            ret.n         /* sdk_pend_flag_noise_check */      #  1a3: 0df0
.Lbr006:    movi.n       a2, 2 /* 0x00000002 */                #  1a5: 0c22
            movi.n       a3, 1 /* 0x00000001 */                #  1a7: 0c13
            movi         a0, .Lrel027 /* sdk_pm_wakeup_init */ #  1a9: 01dbff
            callx0       a0 /* sdk_pm_wakeup_init */           #  1ac: c00000
.Lbr007:    movi         a7, .Lrel019 /* .Lrel019 */           #  1af: 71d0ff
            l8ui         a7, a7, 0                             #  1b2: 720700
            bnez.n       a7, .Lbr008                           #  1b5: dcd7
            movi.n       a11, -32 /* 0xffffffe0 */             #  1b7: 6c0b
            memw                                               #  1b9: c02000
            movi         a10, .Llit001 /* .Llit001 */          #  1bc: a1ceff
            l32i         a9, a10, 0x200                        #  1bf: 922a80
            and          a9, a9, a11                           #  1c2: b09910
            movi.n       a11, 1 /* 0x00000001 */               #  1c5: 0c1b
            or           a9, a9, a11                           #  1c7: b09920
            memw                                               #  1ca: c02000
            s32i         a9, a10, 0x200                        #  1cd: 926a80
            movi         a0, .Lrel028 /* .Lrel028 */           #  1d0: 01d3ff
            callx0       a0                                    #  1d3: c00000
.Lbr008:    movi.n       a2, 0 /* 0x00000000 */                #  1d6: 0c02
            movi         a0, .Lrel029 /* sdk_clockgate_watchdog */ #  1d8: 01d2ff
            callx0       a0 /* sdk_clockgate_watchdog */       #  1db: c00000
            movi         a0, .Lrel020 /* .Ldata002 */          #  1de: 01c6ff
            l8ui         a0, a0, 225 /* [.Ldata033] */         #  1e1: 0200e1
            bnei         a0, 1, .Lbr003                        #  1e4: 661089
            memw                                               #  1e7: c02000
            movi         a3, .Llit002 /* 0x3feffe00 */         #  1ea: 31c4ff
            l32i         a2, a3, 0x214 /* [0x3ff00014] */      #  1ed: 222385
            movi.n       a4, 1 /* 0x00000001 */                #  1f0: 0c14
            or           a2, a2, a4                            #  1f2: 402220
            memw                                               #  1f5: c02000
            s32i         a2, a3, 0x214 /* a2 -> [0x3ff00014] */ #  1f8: 226385
            movi         a2, 160 /* 0x000000a0 */              #  1fb: 22a0a0
            movi         a0, .Lrel030 /* sdk_ets_update_cpu_frequency */ #  1fe: 01c9ff
            callx0       a0 /* sdk_ets_update_cpu_frequency */ #  201: c00000
            j            .Lbr003                               #  204: 46daff

            .balign      4
.Lrel031:   .word        .bss                                  #  208: 00000000
.Llit003:   .word        0x3ff20a00                            #  20c: 000af23f

# Function @ .irom0.text+0x210
.literal_position
.Lfunc004:  movi         a6, .Lrel031 /* .Ldata002 */          #  210: 61feff
            l8ui         a2, a6, 54 /* [.Ldata018] */          #  213: 220636
            movi         a5, .Llit003 /* 0x3ff20a00 */         #  216: 51fdff
            beqz.n       a2, .Lbr009                           #  219: ac12
            memw                                               #  21b: c02000
            l8ui         a4, a6, 62 /* [.Ldata026] */          #  21e: 42063e
            l32i         a5, a5, 0x200 /* [0x3ff20c00] */      #  221: 522580
            l32i.n       a2, a6, 24 /* [.Ldata009] */          #  224: 2866
            l32i.n       a3, a6, 48 /* [.Ldata015] */          #  226: 38c6
            sub          a2, a2, a5                            #  228: 5022c0
            mull         a3, a3, a4                            #  22b: 403382
            bltu         a3, a2, .Lbr009                       #  22e: 27330c
            l32i         a8, a6, 76 /* [.Ldata030] */          #  231: 822613
            l16ui        a7, a6, 44 /* [.Ldata012] */          #  234: 721616
            add.n        a7, a7, a8                            #  237: 8a77
            bgeu         a7, a2, .Lbr009                       #  239: 27b701
            ret.n                                              #  23c: 0df0
.Lbr009:    movi.n       a2, 0 /* 0x00000000 */                #  23e: 0c02
            ret.n         /* 0x00000000 */                     #  240: 0df0

            .balign      4
.Lrel032:   .word        .bss                                  #  244: 00000000

# Function @ .irom0.text+0x248
.literal_position
sdk_pm_rf_is_closed:
            movi         a4, .Lrel032 /* .Ldata002 */          #  248: 41ffff
            movi.n       a3, 1 /* 0x00000001 */                #  24b: 0c13
            l8ui         a4, a4, 53 /* [.Ldata017] */          #  24d: 420435
            movi.n       a2, 0 /* 0x00000000 */                #  250: 0c02
            extui        a4, a4, 1, 3                          #  252: 404124
            addi         a4, a4, -3                            #  255: 42c4fd
            moveqz       a2, a3, a4                            #  258: 402383
            ret.n                                              #  25b: 0df0

            .balign      4
.Lrel033:   .word        .bss                                  #  260: 00000000
.Lrel034:   .word        .Lstr001                              #  264: 04000000
.Lrel035:   .word        .Lstr002                              #  268: 10000000
.Lrel036:   .word        .Lstr001                              #  26c: 04000000
.Lrel037:   .word        .Lstr003                              #  270: 18000000
.Lrel038:   .word        .Lstr004                              #  274: 20000000
.Lrel039:   .word        .Lstr005                              #  278: 48000000
.Lrel040:   .word        .Label009                             #  27c: 54000000
.Lrel041:   .word        printf                                #  280: 00000000
.Lrel042:   .word        printf                                #  284: 00000000
.Lrel043:   .word        printf                                #  288: 00000000
.Lrel044:   .word        printf                                #  28c: 00000000
.Lrel045:   .word        printf                                #  290: 00000000

# Function @ .irom0.text+0x294
# Local variables/stack:
#     (local0):  word      @ -0x10
#     (local1):  word      @ -0xc
#     (local2):  word[2]   @ -0x8
.literal_position
sdk_pm_set_sleep_type_from_upper:
            addi         a1, a1, -16 /* (local0) */            #  294: 12c1f0
            s32i.n       a0, a1, 0 /* a0 -> [(local0)] */      #  297: 0901
            s32i.n       a13, a1, 8 /* a13 -> [(local2)] */    #  299: d921
            s32i.n       a12, a1, 4 /* a12 -> [(local1)] */    #  29b: c911
            movi         a13, .Lrel033 /* .Ldata002 */         #  29d: d1f0ff
            extui        a12, a2, 0, 8                         #  2a0: 20c074
            bnez.n       a12, .Lbr010                          #  2a3: dc2c
            movi         a2, .Lrel034 /* .Lstr001 */           #  2a5: 21efff
            movi         a3, .Lrel035 /* .Lstr002 */           #  2a8: 31f0ff
            movi.n       a0, 0 /* 0x00000000 */                #  2ab: 0c00
            s8i          a0, a13, 228 /* 0x00 -> [.Ldata036] */ #  2ad: 024de4
            movi         a0, .Lrel041 /* printf */             #  2b0: 01f4ff
            callx0       a0 /* printf */                       #  2b3: c00000
            j            .Lbr014                               #  2b6: 860f00
.Lbr010:    movi.n       a2, 1 /* 0x00000001 */                #  2b9: 0c12
            movi         a3, .Lrel037 /* .Lstr003 */           #  2bb: 31edff
            s8i          a2, a13, 228 /* 0x01 -> [.Ldata036] */ #  2be: 224de4
            movi         a2, .Lrel036 /* .Lstr001 */           #  2c1: 21eaff
            movi         a0, .Lrel042 /* printf */             #  2c4: 01f0ff
            callx0       a0 /* printf */                       #  2c7: c00000
            beqi         a12, 1, .Lbr011                       #  2ca: 261c08
            beqi         a12, 2, .Lbr011                       #  2cd: 262c05
            s8i          a12, a13, 227 /* a12 -> [.Ldata035] */ #  2d0: c24de3
            j            .Lbr014                               #  2d3: 460800
.Lbr011:    l8ui         a3, a13, 226 /* [.Ldata034] */        #  2d6: 320de2
            beq          a3, a12, .Lbr013                      #  2d9: c71312
            bnei         a12, 1, .Lbr012                       #  2dc: 661c0a
            movi         a2, .Lrel038 /* .Lstr004 */           #  2df: 21e5ff
            movi         a0, .Lrel043 /* printf */             #  2e2: 01e9ff
            callx0       a0 /* printf */                       #  2e5: c00000
            movi.n       a12, 2 /* 0x00000002 */               #  2e8: 0c2c
.Lbr012:    mov.n        a3, a12                               #  2ea: 3d0c
            s8i          a12, a13, 226 /* a12 -> [.Ldata034] */ #  2ec: c24de2
.Lbr013:    movi         a2, .Lrel039 /* .Lstr005 */           #  2ef: 21e2ff
            movi         a0, .Lrel044 /* printf */             #  2f2: 01e6ff
            callx0       a0 /* printf */                       #  2f5: c00000
.Lbr014:    movi         a2, .Lrel040 /* .Label009 */          #  2f8: 21e1ff
            movi         a0, .Lrel045 /* printf */             #  2fb: 01e5ff
            callx0       a0 /* printf */                       #  2fe: c00000
            l32i.n       a12, a1, 4 /* [(local1)] */           #  301: c811
            l32i.n       a13, a1, 8 /* [(local2)] */           #  303: d821
            l32i.n       a0, a1, 0 /* [(local0)] */            #  305: 0801
            addi         a1, a1, 16 /* (top of frame) */       #  307: 12c110
            ret.n                                              #  30a: 0df0

.Lrel046:   .word        .bss                                  #  30c: 00000000

# Function @ .irom0.text+0x310
.literal_position
sdk_pm_get_sleep_type:
            movi         a2, .Lrel046 /* .Ldata002 */          #  310: 21ffff
            movi.n       a3, 0 /* 0x00000000 */                #  313: 0c03
            l8ui         a4, a2, 228 /* [.Ldata036] */         #  315: 4202e4
            l8ui         a2, a2, 226 /* [.Ldata034] */         #  318: 2202e2
            addi.n       a4, a4, -1 /* [.Ldata036]-0x1 */      #  31b: 0b44
            movnez       a2, a3, a4                            #  31d: 402393
            ret.n                                              #  320: 0df0

            .balign      4
.Lrel047:   .word        .bss                                  #  324: 00000000
.Lrel048:   .word        .Lstr008                              #  328: 68000000
.Lrel049:   .word        .Lstr006                              #  32c: 58000000
.Lrel050:   .word        .Lstr007                              #  330: 60000000
.Lrel051:   .word        .Label003                             #  334: 70000000
.Lrel052:   .word        .Lstr009                              #  338: 88000000
.Lrel053:   .word        .Label002                             #  33c: 54000000
.Lrel054:   .word        .Lstr010                              #  340: 90000000
.Lrel055:   .word        vTaskSuspendAll                       #  344: 00000000
.Lrel056:   .word        printf                                #  348: 00000000
.Lrel057:   .word        printf                                #  34c: 00000000
.Lrel058:   .word        sdk_os_timer_disarm                   #  350: 00000000
.Lrel059:   .word        sdk_os_timer_arm                      #  354: 00000000
.Lrel060:   .word        xTaskResumeAll                        #  358: 00000000
.Lrel061:   .word        printf                                #  35c: 00000000
.Lrel062:   .word        sdk_os_timer_disarm                   #  360: 00000000
.Lrel063:   .word        printf                                #  364: 00000000
.Lrel064:   .word        __udivsi3                             #  368: 00000000
.Lrel065:   .word        sdk_os_timer_arm                      #  36c: 00000000

# Function @ .irom0.text+0x370
# Local variables/stack:
#     (local0):  word      @ -0x10
#     (local1):  word      @ -0xc
#     (local2):  word[2]   @ -0x8
.literal_position
.Lfunc005:  addi         a1, a1, -16 /* (local0) */            #  370: 12c1f0
            s32i.n       a13, a1, 8 /* a13 -> [(local2)] */    #  373: d921
            s32i.n       a12, a1, 4 /* a12 -> [(local1)] */    #  375: c911
            s32i.n       a0, a1, 0 /* a0 -> [(local0)] */      #  377: 0901
            mov.n        a12, a2 /* arg0 */                    #  379: cd02
            movi         a0, .Lrel055 /* vTaskSuspendAll */    #  37b: 01f2ff
            callx0       a0 /* vTaskSuspendAll */              #  37e: c00000
            movi         a13, .Lrel047 /* .Ldata002 */         #  381: d1e8ff
            l8ui         a0, a13, 53 /* [.Ldata017] */         #  384: 020d35
            extui        a3, a0, 1, 3                          #  387: 003124
            beqi         a3, 3, .Lbr016                        #  38a: 263325
            movi         a2, .Lrel048 /* .Lstr008 */           #  38d: 21e6ff
            mov.n        a4, a12 /* arg0 */                    #  390: 4d0c
            movi         a0, .Lrel056 /* printf */             #  392: 01edff
            callx0       a0 /* printf */                       #  395: c00000
            l8ui         a0, a13, 53 /* [.Ldata017] */         #  398: 020d35
            extui        a2, a0, 1, 3                          #  39b: 002124
            beqi         a2, 3, .Lbr016                        #  39e: 263211
            movi         a2, .Lrel049 /* .Lstr006 */           #  3a1: 21e2ff
            movi         a3, .Lrel050 /* .Lstr007 */           #  3a4: 31e3ff
            movi         a4, 570 /* 0x0000023a */              #  3a7: 42a23a
            movi         a0, .Lrel057 /* printf */             #  3aa: 01e8ff
            callx0       a0 /* printf */                       #  3ad: c00000
.Lbr015:    j            .Lbr015 /* (halt) */                  #  3b0: 06ffff
.Lbr016:    movi         a2, 241 /* 0x000000f1 */              #  3b3: 22a0f1
            and          a2, a0, a2                            #  3b6: 202010
            bbci         a0, 5, .Lbr020                        #  3b9: 576058
            movi.n       a0, 10 /* 0x0000000a */               #  3bc: 0ca0
            or           a0, a2, a0                            #  3be: 000220
.Lbr017:    s8i          a0, a13, 53 /* a0 -> [.Ldata017] */   #  3c1: 024d35
            call0        .Lfunc003                             #  3c4: 05d6ff
            s8i          a12, a13, 55 /* arg0 -> [.Ldata019] */ #  3c7: c24d37
            beqi         a12, 2, .Lbr019                       #  3ca: 262c36
            beqi         a12, 4, .Lbr018                       #  3cd: 264c05
            beqi         a12, 8, .Lbr021                       #  3d0: 268c46
            bnei         a12, 16, .Lbr019                      #  3d3: 66bc2d
.Lbr018:    l8ui         a2, a13, 53 /* [.Ldata017] */         #  3d6: 220d35
            bbci         a2, 5, .Lbr019                        #  3d9: 576227
            movi         a12, .Lrel051 /* .Label003 */         #  3dc: c1d6ff
            mov.n        a2, a12 /* .Label003 */               #  3df: 2d0c
            movi         a0, .Lrel058 /* sdk_os_timer_disarm */ #  3e1: 01dbff
            callx0       a0 /* sdk_os_timer_disarm */          #  3e4: c00000
            movi         a4, 191 /* 0x000000bf */              #  3e7: 42a0bf
            l8ui         a3, a13, 53 /* [.Ldata017] */         #  3ea: 320d35
            mov.n        a2, a12 /* .Label003 */               #  3ed: 2d0c
            and          a3, a3, a4                            #  3ef: 403310
            movi.n       a4, 64 /* 0x00000040 */               #  3f2: 4c04
            or           a3, a3, a4                            #  3f4: 403320
            s8i          a3, a13, 53 /* a3 -> [.Ldata017] */   #  3f7: 324d35
            movi.n       a4, 0 /* 0x00000000 */                #  3fa: 0c04
            movi.n       a3, 10 /* 0x0000000a */               #  3fc: 0ca3
            movi         a0, .Lrel059 /* sdk_os_timer_arm */   #  3fe: 01d5ff
            callx0       a0 /* sdk_os_timer_arm */             #  401: c00000
.Lbr019:    movi         a0, .Lrel060 /* xTaskResumeAll */     #  404: 01d5ff
            callx0       a0 /* xTaskResumeAll */               #  407: c00000
            l32i.n       a12, a1, 4 /* [(local1)] */           #  40a: c811
            l32i.n       a13, a1, 8 /* [(local2)] */           #  40c: d821
            l32i.n       a0, a1, 0 /* [(local0)] */            #  40e: 0801
            addi         a1, a1, 16 /* (top of frame) */       #  410: 12c110
            ret.n                                              #  413: 0df0
.Lbr020:    mov.n        a0, a2                                #  415: 0d02
            j            .Lbr017                               #  417: 86e9ff
.Lbr021:    movi         a2, .Lrel052 /* .Lstr009 */           #  41a: 21c7ff
            movi         a0, .Lrel061 /* printf */             #  41d: 01cfff
            callx0       a0 /* printf */                       #  420: c00000
            movi         a12, .Lrel053 /* .Label002 */         #  423: c1c6ff
            mov.n        a2, a12 /* .Label002 */               #  426: 2d0c
            movi         a0, .Lrel062 /* sdk_os_timer_disarm */ #  428: 01ceff
            callx0       a0 /* sdk_os_timer_disarm */          #  42b: c00000
            movi         a2, .Lrel054 /* .Lstr010 */           #  42e: 21c4ff
            movi         a0, .Lrel063 /* printf */             #  431: 01ccff
            callx0       a0 /* printf */                       #  434: c00000
            l32i         a2, a13, 80 /* [.Ldata031] */         #  437: 222d14
            movi         a3, 1000 /* 0x000003e8 */             #  43a: 32a3e8
            movi         a0, .Lrel064 /* __udivsi3 */          #  43d: 01caff
            callx0       a0 /* __udivsi3 */                    #  440: c00000
            mov.n        a3, a2                                #  443: 3d02
            movi.n       a4, 0 /* 0x00000000 */                #  445: 0c04
            mov.n        a2, a12 /* .Label002 */               #  447: 2d0c
            movi         a0, .Lrel065 /* sdk_os_timer_arm */   #  449: 01c8ff
            callx0       a0 /* sdk_os_timer_arm */             #  44c: c00000
            j            .Lbr019                               #  44f: 46ecff

            .balign      4
.Lrel066:   .word        .data                                 #  454: 00000000

# Function @ .irom0.text+0x458
# Local variables/stack:
#     (local0):  word[4]   @ -0x10
.literal_position
.Lfunc006:  addi         a1, a1, -16 /* (local0) */            #  458: 12c1f0
            s32i.n       a0, a1, 0 /* a0 -> [(local0)] */      #  45b: 0901
            movi         a0, .Lrel066 /* .Ldata001 */          #  45d: 01fdff
            l8ui         a0, a0, 0 /* [.Ldata001] */           #  460: 020000
            bnei         a0, 2, .Lbr022                        #  463: 662004
            movi.n       a2, 8 /* 0x00000008 */                #  466: 0c82
            call0        .Lfunc005                             #  468: 45f0ff
.Lbr022:    l32i.n       a0, a1, 0 /* [(local0)] */            #  46b: 0801
            addi         a1, a1, 16 /* (top of frame) */       #  46d: 12c110
            ret.n                                              #  470: 0df0

            .balign      4
# Function @ .irom0.text+0x474
.literal_position
sdk_uart_tx_flush:
            ret.n         /* arg0 */                           #  474: 0df0

            .balign      4
# Function @ .irom0.text+0x478
.literal_position
sdk_pm_suspend:
            ret.n         /* arg0 */                           #  478: 0df0

            .balign      4
.Lrel067:   .word        .Lstr011                              #  47c: 98000000
.Lrel068:   .word        .bss                                  #  480: 00000000
.Lrel069:   .word        vTaskSuspendAll                       #  484: 00000000
.Lrel070:   .word        printf                                #  488: 00000000
.Lrel071:   .word        xTaskResumeAll                        #  48c: 00000000

# Function @ .irom0.text+0x490
# Local variables/stack:
#     (local0):  word[4]   @ -0x10
.literal_position
.Lfunc007:  addi         a1, a1, -16 /* (local0) */            #  490: 12c1f0
            s32i.n       a0, a1, 0 /* a0 -> [(local0)] */      #  493: 0901
            movi         a0, .Lrel069 /* vTaskSuspendAll */    #  495: 01fbff
            callx0       a0 /* vTaskSuspendAll */              #  498: c00000
            movi         a2, .Lrel067 /* .Lstr011 */           #  49b: 21f8ff
            movi         a0, .Lrel070 /* printf */             #  49e: 01faff
            callx0       a0 /* printf */                       #  4a1: c00000
            movi         a2, .Lrel068 /* .Ldata002 */          #  4a4: 21f7ff
            movi.n       a3, 4 /* 0x00000004 */                #  4a7: 0c43
            l8ui         a0, a2, 53 /* [.Ldata017] */          #  4a9: 020235
            movi         a4, 241 /* 0x000000f1 */              #  4ac: 42a0f1
            and          a0, a0, a4                            #  4af: 400010
            or           a0, a0, a3                            #  4b2: 300020
            s8i          a0, a2, 53 /* a0 -> [.Ldata017] */    #  4b5: 024235
            movi         a0, .Lrel071 /* xTaskResumeAll */     #  4b8: 01f5ff
            callx0       a0 /* xTaskResumeAll */               #  4bb: c00000
            l32i.n       a0, a1, 0 /* [(local0)] */            #  4be: 0801
            addi         a1, a1, 16 /* (top of frame) */       #  4c0: 12c110
            ret.n                                              #  4c3: 0df0

            .balign      4
.Lrel072:   .word        .Label003                             #  4c8: 70000000
.Llit004:   .word        0x3ff20a00                            #  4cc: 000af23f
.Lrel073:   .word        .Lstr012                              #  4d0: a8000000
.Llit005:   .word        0x00019000                            #  4d4: 00900100
.Lrel074:   .word        .Label002                             #  4d8: 54000000
.Lrel075:   .word        .Lstr013                              #  4dc: bc000000
.Lrel076:   .word        .Label010                             #  4e0: c4000000
.Lrel077:   .word        .Lstr014                              #  4e4: dc000000
.Lrel078:   .word        .Lstr015                              #  4e8: e4000000
.Lrel079:   .word        vTaskSuspendAll                       #  4ec: 00000000
.Lrel080:   .word        printf                                #  4f0: 00000000
.Lrel081:   .word        printf                                #  4f4: 00000000
.Lrel082:   .word        sdk_os_timer_disarm                   #  4f8: 00000000
.Lrel083:   .word        sdk_os_timer_disarm                   #  4fc: 00000000
.Lrel084:   .word        printf                                #  500: 00000000
.Lrel085:   .word        __udivsi3                             #  504: 00000000
.Lrel086:   .word        sdk_os_timer_arm                      #  508: 00000000
.Lrel087:   .word        printf                                #  50c: 00000000
.Lrel088:   .word        sdk_os_timer_disarm                   #  510: 00000000
.Lrel089:   .word        sdk_os_timer_disarm                   #  514: 00000000
.Lrel090:   .word        printf                                #  518: 00000000
.Lrel091:   .word        sdk_os_timer_arm                      #  51c: 00000000
.Lrel092:   .word        xTaskResumeAll                        #  520: 00000000

# Function @ .irom0.text+0x524
# Local variables/stack:
#     (local0):  word      @ -0x20
#     (local1):  word      @ -0x1c
#     (local2):  word      @ -0x18
#     (local3):  word      @ -0x14
#     (local4):  word[4]   @ -0x10
.literal_position
.Lfunc008:  addi         a1, a1, -32 /* (local0) */            #  524: 12c1e0
            s32i.n       a12, a1, 4 /* a12 -> [(local1)] */    #  527: c911
            s32i.n       a13, a1, 8 /* a13 -> [(local2)] */    #  529: d921
            s32i.n       a14, a1, 12 /* a14 -> [(local3)] */   #  52b: e931
            s32i.n       a15, a1, 16 /* a15 -> [(local4)] */   #  52d: f941
            s32i.n       a0, a1, 0 /* a0 -> [(local0)] */      #  52f: 0901
            movi         a0, .Lrel079 /* vTaskSuspendAll */    #  531: 01eeff
            callx0       a0 /* vTaskSuspendAll */              #  534: c00000
            movi         a15, .Lrel072 /* .Label003 */         #  537: f1e4ff
            movi         a14, .Llit004 /* 0x3ff20a00 */        #  53a: e1e4ff
            addi         a12, a15, -28 /* .Label002 */         #  53d: c2cfe4
            addi         a13, a15, -112 /* .Ldata002 */        #  540: d2cf90
            memw                                               #  543: c02000
            l8ui         a0, a13, 54 /* [.Ldata018] */         #  546: 020d36
            movi         a3, 241 /* 0x000000f1 */              #  549: 32a0f1
            l8ui         a2, a13, 53 /* [.Ldata017] */         #  54c: 220d35
            l32i         a14, a14, 0x200 /* [0x3ff20c00] */    #  54f: e22e80
            and          a2, a2, a3                            #  552: 302210
            movi.n       a3, 8 /* 0x00000008 */                #  555: 0c83
            or           a2, a2, a3                            #  557: 302220
            s8i          a2, a13, 53 /* a2 -> [.Ldata017] */   #  55a: 224d35
            beqz         a0, .Lbr027                           #  55d: 16300a
            l32i.n       a5, a13, 20 /* [.Ldata008] */         #  560: 585d
            l32i.n       a3, a13, 48 /* [.Ldata015] */         #  562: 38cd
            sub          a0, a5, a14                           #  564: e005c0
            bgeu         a3, a0, .Lbr026                       #  567: 07b349
            movi         a15, 100 /* 0x00000064 */             #  56a: f2a064
            movi.n       a12, 0 /* 0x00000000 */               #  56d: 0c0c
            l8ui         a4, a13, 62 /* [.Ldata026] */         #  56f: 420d3e
.Lbr023:    addi.n       a12, a12, 1                           #  572: 1bcc
            l32i.n       a0, a13, 24 /* [.Ldata009] */         #  574: 086d
            s32i.n       a5, a13, 28 /* a5 -> [.Ldata010] */   #  576: 597d
            mull         a6, a4, a3                            #  578: 306482
            add.n        a5, a3, a5                            #  57b: 5a53
            s32i.n       a5, a13, 20 /* a5 -> [.Ldata008] */   #  57d: 595d
            sub          a2, a0, a5                            #  57f: 5020c0
            bgeu         a6, a2, .Lbr024                       #  582: 27b603
            add.n        a7, a6, a0                            #  585: 0a76
            s32i.n       a7, a13, 24 /* a7 -> [.Ldata009] */   #  587: 796d
.Lbr024:    bne          a12, a15, .Lbr025                     #  589: f79c21
            movi         a2, .Lrel073 /* .Lrel073 */           #  58c: 21d1ff
            mov.n        a6, a14 /* [0x3ff20c00] */            #  58f: 6d0e
            movi         a0, .Lrel080 /* .Lrel080 */           #  591: 01d7ff
            callx0       a0                                    #  594: c00000
            l32i.n       a5, a13, 20 /* [.Ldata008] */         #  597: 585d
            movi         a9, .Llit005 /* .Llit005 */           #  599: 91ceff
            l32i.n       a3, a13, 48 /* [.Ldata015] */         #  59c: 38cd
            l8ui         a4, a13, 62 /* [.Ldata026] */         #  59e: 420d3e
            movi.n       a10, 1 /* 0x00000001 */               #  5a1: 0c1a
            moveqz       a4, a10, a4                           #  5a3: 404a83
            s8i          a4, a13, 62 /* a4 -> [.Ldata026] */   #  5a6: 424d3e
            moveqz       a3, a9, a3                            #  5a9: 303983
            s32i.n       a3, a13, 48 /* a3 -> [.Ldata015] */   #  5ac: 39cd
.Lbr025:    sub          a8, a5, a14                           #  5ae: e085c0
            bltu         a3, a8, .Lbr023                       #  5b1: 8733bd
.Lbr026:    movi         a12, .Lrel074 /* .Label002 */         #  5b4: c1c9ff
            movi         a2, .Lrel075 /* .Lstr013 */           #  5b7: 21c9ff
            addi         a15, a12, 28 /* .Label003 */          #  5ba: f2cc1c
            movi         a0, .Lrel081 /* printf */             #  5bd: 01cdff
            callx0       a0 /* printf */                       #  5c0: c00000
            mov.n        a2, a15 /* .Label003 */               #  5c3: 2d0f
            movi         a0, .Lrel082 /* sdk_os_timer_disarm */ #  5c5: 01ccff
            callx0       a0 /* sdk_os_timer_disarm */          #  5c8: c00000
            mov.n        a2, a12 /* .Label002 */               #  5cb: 2d0c
            movi         a0, .Lrel083 /* sdk_os_timer_disarm */ #  5cd: 01cbff
            callx0       a0 /* sdk_os_timer_disarm */          #  5d0: c00000
            movi         a2, .Lrel076 /* .Label010 */          #  5d3: 21c3ff
            movi         a0, .Lrel084 /* printf */             #  5d6: 01caff
            callx0       a0 /* printf */                       #  5d9: c00000
            movi         a3, 1000 /* 0x000003e8 */             #  5dc: 32a3e8
            l32i         a4, a13, 76 /* [.Ldata030] */         #  5df: 422d13
            l32i.n       a5, a13, 20 /* [.Ldata008] */         #  5e2: 585d
            l32i         a2, a13, 80 /* [.Ldata031] */         #  5e4: 222d14
            sub          a5, a5, a14                           #  5e7: e055c0
            add.n        a2, a2, a5                            #  5ea: 5a22
            sub          a2, a2, a4                            #  5ec: 4022c0
            movi         a0, .Lrel085 /* __udivsi3 */          #  5ef: 01c5ff
            callx0       a0 /* __udivsi3 */                    #  5f2: c00000
            mov.n        a3, a2                                #  5f5: 3d02
            movi.n       a4, 0 /* 0x00000000 */                #  5f7: 0c04
            mov.n        a2, a12 /* .Label002 */               #  5f9: 2d0c
            movi         a0, .Lrel086 /* sdk_os_timer_arm */   #  5fb: 01c3ff
            callx0       a0 /* sdk_os_timer_arm */             #  5fe: c00000
            j            .Lbr028                               #  601: 860b00
.Lbr027:    movi         a2, .Lrel077 /* .Lstr014 */           #  604: 21b8ff
            movi         a0, .Lrel087 /* printf */             #  607: 01c1ff
            callx0       a0 /* printf */                       #  60a: c00000
            mov.n        a2, a15 /* .Label003 */               #  60d: 2d0f
            movi         a0, .Lrel088 /* sdk_os_timer_disarm */ #  60f: 01c0ff
            callx0       a0 /* sdk_os_timer_disarm */          #  612: c00000
            mov.n        a2, a12 /* .Label002 */               #  615: 2d0c
            movi         a0, .Lrel089 /* sdk_os_timer_disarm */ #  617: 01bfff
            callx0       a0 /* sdk_os_timer_disarm */          #  61a: c00000
            movi         a2, .Lrel078 /* .Lstr015 */           #  61d: 21b2ff
            movi         a0, .Lrel090 /* printf */             #  620: 01beff
            callx0       a0 /* printf */                       #  623: c00000
            mov.n        a2, a12 /* .Label002 */               #  626: 2d0c
            movi         a3, 105 /* 0x00000069 */              #  628: 32a069
            movi.n       a4, 0 /* 0x00000000 */                #  62b: 0c04
            movi         a0, .Lrel091 /* sdk_os_timer_arm */   #  62d: 01bbff
            callx0       a0 /* sdk_os_timer_arm */             #  630: c00000
.Lbr028:    movi         a0, .Lrel092 /* xTaskResumeAll */     #  633: 01bbff
            callx0       a0 /* xTaskResumeAll */               #  636: c00000
            l32i.n       a12, a1, 4 /* [(local1)] */           #  639: c811
            l32i.n       a13, a1, 8 /* [(local2)] */           #  63b: d821
            l32i.n       a14, a1, 12 /* [(local3)] */          #  63d: e831
            l32i.n       a15, a1, 16 /* [(local4)] */          #  63f: f841
            l32i.n       a0, a1, 0 /* [(local0)] */            #  641: 0801
            addi         a1, a1, 32 /* (top of frame) */       #  643: 12c120
            ret.n                                              #  646: 0df0

.Lrel093:   .word        .Lstr016                              #  648: ec000000
.Lrel094:   .word        .bss                                  #  64c: 00000000
.Lrel095:   .word        .Lstr017                              #  650: 00010000
.Lrel096:   .word        vTaskSuspendAll                       #  654: 00000000
.Lrel097:   .word        printf                                #  658: 00000000
.Lrel098:   .word        sdk_pm_send_nullfunc                  #  65c: 00000000
.Lrel099:   .word        printf                                #  660: 00000000
.Lrel100:   .word        xTaskResumeAll                        #  664: 00000000
.Lrel101:   .word        PendSV                                #  668: 00000000

# Function @ .irom0.text+0x66c
# Local variables/stack:
#     (local0):  word[4]   @ -0x10
.literal_position
.Lfunc009:  addi         a1, a1, -16 /* (local0) */            #  66c: 12c1f0
            s32i.n       a0, a1, 0 /* a0 -> [(local0)] */      #  66f: 0901
            movi         a0, .Lrel096 /* vTaskSuspendAll */    #  671: 01f8ff
            callx0       a0 /* vTaskSuspendAll */              #  674: c00000
            call0        sdk_pm_rf_is_closed                   #  677: 050000
            bnez.n       a2, .Lbr029                           #  67a: ec62
            movi         a2, .Lrel093 /* .Lstr016 */           #  67c: 21f3ff
            movi         a0, .Lrel097 /* printf */             #  67f: 01f6ff
            callx0       a0 /* printf */                       #  682: c00000
            movi.n       a2, 1 /* 0x00000001 */                #  685: 0c12
            movi         a0, .Lrel098 /* sdk_pm_send_nullfunc */ #  687: 01f5ff
            callx0       a0 /* sdk_pm_send_nullfunc */         #  68a: c00000
            movi         a3, .Lrel094 /* .Ldata002 */          #  68d: 31efff
            movi.n       a4, 2 /* 0x00000002 */                #  690: 0c24
            l8ui         a0, a3, 53 /* [.Ldata017] */          #  692: 020335
            movi         a5, 241 /* 0x000000f1 */              #  695: 52a0f1
            and          a0, a0, a5                            #  698: 500010
            or           a0, a0, a4                            #  69b: 400020
            s8i          a0, a3, 53 /* a0 -> [.Ldata017] */    #  69e: 024335
            j            .Lbr030                               #  6a1: 060200
.Lbr029:    movi         a2, .Lrel095 /* .Lstr017 */           #  6a4: 21ebff
            movi         a0, .Lrel099 /* printf */             #  6a7: 01eeff
            callx0       a0 /* printf */                       #  6aa: c00000
.Lbr030:    movi         a0, .Lrel100 /* .Lrel100 */           #  6ad: 01edff
            callx0       a0                                    #  6b0: c00000
            bnez.n       a2, .Lbr031                           #  6b3: cc62
            movi.n       a2, 1 /* 0x00000001 */                #  6b5: 0c12
            movi         a0, .Lrel101 /* PendSV */             #  6b7: 01ecff
            callx0       a0 /* PendSV */                       #  6ba: c00000
.Lbr031:    l32i.n       a0, a1, 0 /* [(local0)] */            #  6bd: 0801
            addi         a1, a1, 16 /* (top of frame) */       #  6bf: 12c110
            ret.n                                              #  6c2: 0df0

.Lrel102:   .word        .Lstr018                              #  6c4: 1c010000
.Lrel103:   .word        .bss                                  #  6c8: 00000000
.Lrel104:   .word        .Lstr019                              #  6cc: 2c010000
.Lrel105:   .word        vTaskSuspendAll                       #  6d0: 00000000
.Lrel106:   .word        printf                                #  6d4: 00000000
.Lrel107:   .word        sdk_pm_send_nullfunc                  #  6d8: 00000000
.Lrel108:   .word        printf                                #  6dc: 00000000
.Lrel109:   .word        xTaskResumeAll                        #  6e0: 00000000
.Lrel110:   .word        PendSV                                #  6e4: 00000000

# Function @ .irom0.text+0x6e8
# Local variables/stack:
#     (local0):  word[4]   @ -0x10
.literal_position
.Lfunc010:  addi         a1, a1, -16 /* (local0) */            #  6e8: 12c1f0
            s32i.n       a0, a1, 0 /* a0 -> [(local0)] */      #  6eb: 0901
            movi         a0, .Lrel105 /* vTaskSuspendAll */    #  6ed: 01f8ff
            callx0       a0 /* vTaskSuspendAll */              #  6f0: c00000
            call0        sdk_pm_rf_is_closed                   #  6f3: 050000
            bnez.n       a2, .Lbr032                           #  6f6: ec62
            movi         a2, .Lrel102 /* .Lstr018 */           #  6f8: 21f3ff
            movi         a0, .Lrel106 /* printf */             #  6fb: 01f6ff
            callx0       a0 /* printf */                       #  6fe: c00000
            movi.n       a2, 0 /* 0x00000000 */                #  701: 0c02
            movi         a0, .Lrel107 /* sdk_pm_send_nullfunc */ #  703: 01f5ff
            callx0       a0 /* sdk_pm_send_nullfunc */         #  706: c00000
            movi         a3, .Lrel103 /* .Ldata002 */          #  709: 31efff
            movi.n       a4, 12 /* 0x0000000c */               #  70c: 0cc4
            l8ui         a0, a3, 53 /* [.Ldata017] */          #  70e: 020335
            movi         a5, 241 /* 0x000000f1 */              #  711: 52a0f1
            and          a0, a0, a5                            #  714: 500010
            or           a0, a0, a4                            #  717: 400020
            s8i          a0, a3, 53 /* a0 -> [.Ldata017] */    #  71a: 024335
            j            .Lbr033                               #  71d: 060200
.Lbr032:    movi         a2, .Lrel104 /* .Lstr019 */           #  720: 21ebff
            movi         a0, .Lrel108 /* printf */             #  723: 01eeff
            callx0       a0 /* printf */                       #  726: c00000
.Lbr033:    movi         a0, .Lrel109 /* .Lrel109 */           #  729: 01edff
            callx0       a0                                    #  72c: c00000
            bnez.n       a2, .Lbr034                           #  72f: cc62
            movi.n       a2, 1 /* 0x00000001 */                #  731: 0c12
            movi         a0, .Lrel110 /* PendSV */             #  733: 01ecff
            callx0       a0 /* PendSV */                       #  736: c00000
.Lbr034:    l32i.n       a0, a1, 0 /* [(local0)] */            #  739: 0801
            addi         a1, a1, 16 /* (top of frame) */       #  73b: 12c110
            ret.n                                              #  73e: 0df0

.Lrel111:   .word        .Lstr020                              #  740: 44010000
.Lrel112:   .word        .bss                                  #  744: 00000000
.Lrel113:   .word        vTaskSuspendAll                       #  748: 00000000
.Lrel114:   .word        printf                                #  74c: 00000000
.Lrel115:   .word        sdk_ppProcessWaitQ                    #  750: 00000000
.Lrel116:   .word        xTaskResumeAll                        #  754: 00000000

# Function @ .irom0.text+0x758
# Local variables/stack:
#     (local0):  word[4]   @ -0x10
.literal_position
.Lfunc011:  addi         a1, a1, -16 /* (local0) */            #  758: 12c1f0
            s32i.n       a0, a1, 0 /* a0 -> [(local0)] */      #  75b: 0901
            movi         a0, .Lrel113 /* vTaskSuspendAll */    #  75d: 01faff
            callx0       a0 /* vTaskSuspendAll */              #  760: c00000
            movi         a2, .Lrel111 /* .Lstr020 */           #  763: 21f7ff
            movi         a3, .Lrel112 /* .Ldata002 */          #  766: 31f7ff
            movi.n       a4, 14 /* 0x0000000e */               #  769: 0ce4
            l8ui         a0, a3, 53 /* [.Ldata017] */          #  76b: 020335
            movi         a5, 241 /* 0x000000f1 */              #  76e: 52a0f1
            and          a0, a0, a5                            #  771: 500010
            or           a0, a0, a4                            #  774: 400020
            s8i          a0, a3, 53 /* a0 -> [.Ldata017] */    #  777: 024335
            movi         a0, .Lrel114 /* printf */             #  77a: 01f4ff
            callx0       a0 /* printf */                       #  77d: c00000
            movi         a0, .Lrel115 /* sdk_ppProcessWaitQ */ #  780: 01f4ff
            callx0       a0 /* sdk_ppProcessWaitQ */           #  783: c00000
            movi         a0, .Lrel116 /* xTaskResumeAll */     #  786: 01f3ff
            callx0       a0 /* xTaskResumeAll */               #  789: c00000
            l32i.n       a0, a1, 0 /* [(local0)] */            #  78c: 0801
            addi         a1, a1, 16 /* (top of frame) */       #  78e: 12c110
            ret.n                                              #  791: 0df0

            .balign      4
.Lrel117:   .word        .bss                                  #  794: 00000000
.Lrel118:   .word        vTaskSuspendAll                       #  798: 00000000
.Lrel119:   .word        sdk_ppProcessWaitQ                    #  79c: 00000000
.Lrel120:   .word        xTaskResumeAll                        #  7a0: 00000000

# Function @ .irom0.text+0x7a4
# Local variables/stack:
#     (local0):  word[4]   @ -0x10
.literal_position
.Lfunc012:  addi         a1, a1, -16 /* (local0) */            #  7a4: 12c1f0
            s32i.n       a0, a1, 0 /* a0 -> [(local0)] */      #  7a7: 0901
            movi         a0, .Lrel118 /* vTaskSuspendAll */    #  7a9: 01fbff
            callx0       a0 /* vTaskSuspendAll */              #  7ac: c00000
            movi         a2, .Lrel117 /* .Ldata002 */          #  7af: 21f9ff
            l8ui         a0, a2, 53 /* [.Ldata017] */          #  7b2: 020235
            movi         a3, 241 /* 0x000000f1 */              #  7b5: 32a0f1
            and          a0, a0, a3                            #  7b8: 300010
            s8i          a0, a2, 53 /* a0 -> [.Ldata017] */    #  7bb: 024235
            movi         a0, .Lrel119 /* sdk_ppProcessWaitQ */ #  7be: 01f7ff
            callx0       a0 /* sdk_ppProcessWaitQ */           #  7c1: c00000
            movi         a0, .Lrel120 /* xTaskResumeAll */     #  7c4: 01f7ff
            callx0       a0 /* xTaskResumeAll */               #  7c7: c00000
            l32i.n       a0, a1, 0 /* [(local0)] */            #  7ca: 0801
            addi         a1, a1, 16 /* (top of frame) */       #  7cc: 12c110
            ret.n                                              #  7cf: 0df0

            .balign      4
.Lrel121:   .word        .bss                                  #  7d4: 00000000
.Lrel122:   .word        .Lstr021                              #  7d8: 4c010000
.Lrel123:   .word        .Label002                             #  7dc: 54000000
.Lrel124:   .word        .Label003                             #  7e0: 70000000
.Lrel125:   .word        .Lstr022                              #  7e4: 54010000
.Lrel126:   .word        printf                                #  7e8: 00000000
.Lrel127:   .word        sdk_os_timer_disarm                   #  7ec: 00000000
.Lrel128:   .word        sdk_os_timer_disarm                   #  7f0: 00000000
.Lrel129:   .word        printf                                #  7f4: 00000000

# Function @ .irom0.text+0x7f8
# Local variables/stack:
#     (local0):  word      @ -0x10
#     (local1):  word[3]   @ -0xc
.literal_position
.Lfunc013:  addi         a1, a1, -16 /* (local0) */            #  7f8: 12c1f0
            movi         a2, .Lrel122 /* .Lstr021 */           #  7fb: 21f7ff
            s32i.n       a12, a1, 4 /* a12 -> [(local1)] */    #  7fe: c911
            movi         a12, .Lrel121 /* .Ldata002 */         #  800: c1f5ff
            s32i.n       a0, a1, 0 /* a0 -> [(local0)] */      #  803: 0901
            l8ui         a0, a12, 53 /* [.Ldata017] */         #  805: 020c35
            movi         a3, 191 /* 0x000000bf */              #  808: 32a0bf
            and          a0, a0, a3                            #  80b: 300010
            s8i          a0, a12, 53 /* a0 -> [.Ldata017] */   #  80e: 024c35
            movi         a0, .Lrel126 /* printf */             #  811: 01f5ff
            callx0       a0 /* printf */                       #  814: c00000
            movi         a2, .Lrel123 /* .Label002 */          #  817: 21f1ff
            movi         a0, .Lrel127 /* sdk_os_timer_disarm */ #  81a: 01f4ff
            callx0       a0 /* sdk_os_timer_disarm */          #  81d: c00000
            movi         a2, .Lrel124 /* .Label003 */          #  820: 21f0ff
            movi         a0, .Lrel128 /* sdk_os_timer_disarm */ #  823: 01f3ff
            callx0       a0 /* sdk_os_timer_disarm */          #  826: c00000
            l8ui         a0, a12, 53 /* [.Ldata017] */         #  829: 020c35
            l8ui         a4, a12, 59 /* [.Ldata023] */         #  82c: 420c3b
            bbsi         a0, 4, .Lbr037                        #  82f: 47e01b
            bnez.n       a4, .Lbr037                           #  832: dc84
            movi.n       a5, 0 /* 0x00000000 */                #  834: 0c05
            s8i          a5, a12, 61 /* 0x00 -> [.Ldata025] */ #  836: 524c3d
            bbci         a0, 5, .Lbr035                        #  839: 576005
            call0        .Lfunc011                             #  83c: 85f1ff
            j            .Lbr036                               #  83f: 860000
.Lbr035:    call0        .Lfunc012                             #  842: 05f6ff
.Lbr036:    l32i.n       a12, a1, 4 /* [(local1)] */           #  845: c811
            l32i.n       a0, a1, 0 /* [(local0)] */            #  847: 0801
            addi         a1, a1, 16 /* (top of frame) */       #  849: 12c110
            ret.n                                              #  84c: 0df0
.Lbr037:    movi         a2, .Lrel125 /* .Lstr022 */           #  84e: 21e5ff
            movi         a0, .Lrel129 /* printf */             #  851: 01e8ff
            callx0       a0 /* printf */                       #  854: c00000
            call0        .Lfunc010                             #  857: 05e9ff
            j            .Lbr036                               #  85a: c6f9ff

            .balign      4
.Lrel130:   .word        .Lstr023                              #  860: 64010000
.Lrel131:   .word        .Label002                             #  864: 54000000
.Lrel132:   .word        .Label003                             #  868: 70000000
.Lrel133:   .word        .bss                                  #  86c: 00000000
.Lrel134:   .word        .data                                 #  870: 00000000
.Lrel135:   .word        .Label006                             #  874: c4000000
.Llit006:   .word        0x3ff20a00                            #  878: 000af23f
.Lrel136:   .word        .Lstr024                              #  87c: 6c010000
.Llit007:   .word        0x00001770                            #  880: 70170000
.Llit008:   .word        0x00004650                            #  884: 50460000
.Llit009:   .word        0x0000fe3f                            #  888: 3ffe0000
.Lrel137:   .word        printf                                #  88c: 00000000
.Lrel138:   .word        sdk_os_timer_disarm                   #  890: 00000000
.Lrel139:   .word        sdk_os_timer_disarm                   #  894: 00000000
.Lrel140:   .word        sdk_os_timer_disarm                   #  898: 00000000
.Lrel141:   .word        printf                                #  89c: 00000000

# Function @ .irom0.text+0x8a0
# Local variables/stack:
#     (local0):  word      @ -0x10
#     (local1):  word[3]   @ -0xc
.literal_position
sdk_pm_shutdown:
            movi         a2, .Lrel130 /* .Lstr023 */           #  8a0: 21f0ff
            addi         a1, a1, -16 /* (local0) */            #  8a3: 12c1f0
            s32i.n       a12, a1, 4 /* a12 -> [(local1)] */    #  8a6: c911
            s32i.n       a0, a1, 0 /* a0 -> [(local0)] */      #  8a8: 0901
            movi         a0, .Lrel137 /* printf */             #  8aa: 01f8ff
            callx0       a0 /* printf */                       #  8ad: c00000
            movi         a2, .Lrel131 /* .Label002 */          #  8b0: 21edff
            movi         a0, .Lrel138 /* sdk_os_timer_disarm */ #  8b3: 01f7ff
            callx0       a0 /* sdk_os_timer_disarm */          #  8b6: c00000
            movi         a2, .Lrel132 /* .Label003 */          #  8b9: 21ebff
            movi         a0, .Lrel139 /* sdk_os_timer_disarm */ #  8bc: 01f6ff
            callx0       a0 /* sdk_os_timer_disarm */          #  8bf: c00000
            movi         a4, 239 /* 0x000000ef */              #  8c2: 42a0ef
            movi         a3, .Lrel134 /* .Ldata001 */          #  8c5: 31eaff
            movi         a12, .Lrel133 /* .Ldata002 */         #  8c8: c1e9ff
            movi.n       a5, 0 /* 0x00000000 */                #  8cb: 0c05
            s8i          a5, a12, 58 /* 0x00 -> [.Ldata022] */ #  8cd: 524c3a
            s8i          a5, a12, 59 /* 0x00 -> [.Ldata023] */ #  8d0: 524c3b
            l8ui         a0, a12, 53 /* [.Ldata017] */         #  8d3: 020c35
            l8ui         a3, a3, 0 /* [.Ldata001] */           #  8d6: 320300
            and          a0, a0, a4                            #  8d9: 400010
            s8i          a0, a12, 53 /* a0 -> [.Ldata017] */   #  8dc: 024c35
            bnei         a3, 2, .Lbr039                        #  8df: 662315
            call0        sdk_pm_rf_is_closed                   #  8e2: 050000
            beqz.n       a2, .Lbr038                           #  8e5: 8cc2
            movi         a2, .Lrel135 /* .Label006 */          #  8e7: 21e3ff
            movi         a0, .Lrel140 /* sdk_os_timer_disarm */ #  8ea: 01ebff
            callx0       a0 /* sdk_os_timer_disarm */          #  8ed: c00000
            movi.n       a2, 2 /* 0x00000002 */                #  8f0: 0c22
            call0        .Lfunc005                             #  8f2: c5a7ff
.Lbr038:    l8ui         a0, a12, 53 /* [.Ldata017] */         #  8f5: 020c35
.Lbr039:    extui        a3, a0, 1, 3                          #  8f8: 003124
            beqi         a3, 7, .Lbr040                        #  8fb: 26730a
            beqz.n       a3, .Lbr040                           #  8fe: 8c73
            call0        .Lfunc013                             #  900: 45efff
            l8ui         a3, a12, 53 /* [.Ldata017] */         #  903: 320c35
            extui        a3, a3, 1, 3                          #  906: 303124
.Lbr040:    movi         a6, .Llit006 /* 0x3ff20a00 */         #  909: 61dbff
            movi         a2, .Lrel136 /* .Lstr024 */           #  90c: 21dcff
            l32i.n       a7, a12, 12 /* [.Ldata006] */         #  90f: 783c
            l32i.n       a5, a12, 16 /* [.Ldata007] */         #  911: 584c
            l8ui         a4, a12, 58 /* [.Ldata022] */         #  913: 420c3a
            memw                                               #  916: c02000
            l32i         a6, a6, 0x200 /* [0x3ff20c00] */      #  919: 622680
            sub          a6, a6, a7                            #  91c: 7066c0
            movi         a0, .Lrel141 /* printf */             #  91f: 01dfff
            callx0       a0 /* printf */                       #  922: c00000
            movi.n       a7, 7 /* 0x00000007 */                #  925: 0c77
            movi         a9, 223 /* 0x000000df */              #  927: 92a0df
            l8ui         a8, a12, 53 /* [.Ldata017] */         #  92a: 820c35
            movi         a11, .Llit007 /* 0x00001770 */        #  92d: b1d4ff
            movi         a10, .Llit008 /* 0x00004650 */        #  930: a1d5ff
            movi.n       a0, 0 /* 0x00000000 */                #  933: 0c00
            s8i          a0, a12, 54 /* 0x00 -> [.Ldata018] */ #  935: 024c36
            s32i.n       a0, a12, 48 /* 0x00000000 -> [.Ldata015] */ #  938: 09cc
            s8i          a0, a12, 62 /* 0x00 -> [.Ldata026] */ #  93a: 024c3e
            s32i.n       a0, a12, 28 /* 0x00000000 -> [.Ldata010] */ #  93d: 097c
            s32i.n       a0, a12, 20 /* 0x00000000 -> [.Ldata008] */ #  93f: 095c
            s32i.n       a0, a12, 24 /* 0x00000000 -> [.Ldata009] */ #  941: 096c
            s32i.n       a0, a12, 36 /* 0x00000000 -> [.Ldata011] */ #  943: 099c
            s32i         a10, a12, 80 /* 0x00004650 -> [.Ldata031] */ #  945: a26c14
            s32i         a11, a12, 76 /* 0x00001770 -> [.Ldata030] */ #  948: b26c13
            l8ui         a10, a12, 52 /* [.Ldata016] */        #  94b: a20c34
            and          a8, a8, a9                            #  94e: 908810
            extui        a8, a8, 0, 8                          #  951: 808074
            movi         a9, .Llit009 /* 0x0000fe3f */         #  954: 91cdff
            slli         a8, a8, 8                             #  957: 808811
            or           a8, a8, a10                           #  95a: a08820
            movi         a10, 254 /* 0x000000fe */             #  95d: a2a0fe
            and          a8, a8, a9                            #  960: 908810
            extui        a9, a8, 0, 8                          #  963: 809074
            srli         a11, a8, 8                            #  966: 80b841
            s8i          a11, a12, 53 /* a11 -> [.Ldata017] */ #  969: b24c35
            and          a9, a9, a10                           #  96c: a09910
            s8i          a9, a12, 52 /* a9 -> [.Ldata016] */   #  96f: 924c34
            extui        a8, a8, 8, 8                          #  972: 808874
            srli         a8, a8, 1                             #  975: 808141
            bnone        a7, a8, .Lbr041                       #  978: 870702
            call0        .Lfunc012                             #  97b: 85e2ff
.Lbr041:    l32i.n       a12, a1, 4 /* [(local1)] */           #  97e: c811
            l32i.n       a0, a1, 0 /* [(local0)] */            #  980: 0801
            addi         a1, a1, 16 /* (top of frame) */       #  982: 12c110
            ret.n                                              #  985: 0df0

            .balign      4
.Lrel142:   .word        .bss                                  #  988: 00000000
.Lrel143:   .word        .Label005                             #  98c: a8000000
.Lrel144:   .word        .bss                                  #  990: 00000000
.Lrel145:   .word        sdk_os_timer_disarm                   #  994: 00000000
.Lrel146:   .word        sdk_rc_get_mask                       #  998: 00000000
.Lrel147:   .word        sdk_os_timer_arm                      #  99c: 00000000

# Function @ .irom0.text+0x9a0
# Local variables/stack:
#     (local0):  word      @ -0x10
#     (local1):  word[3]   @ -0xc
.literal_position
sdk_pm_reset_idle_sleep:
            addi         a1, a1, -16 /* (local0) */            #  9a0: 12c1f0
            movi         a2, .Lrel142 /* .Ldata002 */          #  9a3: 21f9ff
            s32i.n       a0, a1, 4 /* a0 -> [(local1)] */      #  9a6: 0911
            movi.n       a0, 0 /* 0x00000000 */                #  9a8: 0c00
            s8i          a0, a2, 56 /* 0x00 -> [.Ldata020] */  #  9aa: 024238
            movi         a2, .Lrel143 /* .Label005 */          #  9ad: 21f7ff
            s32i.n       a2, a1, 0 /* .Label005 -> [(local0)] */ #  9b0: 2901
            movi         a0, .Lrel145 /* sdk_os_timer_disarm */ #  9b2: 01f8ff
            callx0       a0 /* sdk_os_timer_disarm */          #  9b5: c00000
            movi         a3, .Lrel144 /* .Ldata002 */          #  9b8: 31f6ff
            l8ui         a3, a3, 53 /* [.Ldata017] */          #  9bb: 320335
            bbsi         a3, 5, .Lbr042                        #  9be: 57e314
            movi         a0, .Lrel146 /* sdk_rc_get_mask */    #  9c1: 01f5ff
            callx0       a0 /* sdk_rc_get_mask */              #  9c4: c00000
            bnez.n       a2, .Lbr042                           #  9c7: ccb2
            l32i.n       a2, a1, 0 /* [(local0)] */            #  9c9: 2801
            movi         a3, 500 /* 0x000001f4 */              #  9cb: 32a1f4
            movi.n       a4, 0 /* 0x00000000 */                #  9ce: 0c04
            movi         a0, .Lrel147 /* sdk_os_timer_arm */   #  9d0: 01f3ff
            callx0       a0 /* sdk_os_timer_arm */             #  9d3: c00000
.Lbr042:    l32i.n       a0, a1, 4 /* [(local1)] */            #  9d6: 0811
            addi         a1, a1, 16 /* (top of frame) */       #  9d8: 12c110
            ret.n                                              #  9db: 0df0

            .balign      4
# Function @ .irom0.text+0x9e0
.literal_position
sdk_pm_idle_sleep:
            ret.n         /* arg0 */                           #  9e0: 0df0

            .balign      4
.Lrel148:   .word        .Label005                             #  9e4: a8000000
.Lrel149:   .word        .bss                                  #  9e8: 00000000
.Lrel150:   .word        .Lstr025                              #  9ec: 84010000
.Lrel151:   .word        .Label001                             #  9f0: 41000000
.Llit010:   .word        0x3ff20a00                            #  9f4: 000af23f
.Lrel152:   .word        .Lstr006                              #  9f8: 58000000
.Lrel153:   .word        .Lstr007                              #  9fc: 60000000
.Lrel154:   .word        vTaskSuspendAll                       #  a00: 00000000
.Lrel155:   .word        sdk_rc_get_sta_trc                    #  a04: 00000000
.Lrel156:   .word        sdk_os_timer_disarm                   #  a08: 00000000
.Lrel157:   .word        printf                                #  a0c: 00000000
.Lrel158:   .word        memcpy                                #  a10: 00000000
.Lrel159:   .word        sdk_pp_disable_idle_timer             #  a14: 00000000
.Lrel160:   .word        sdk_pp_enable_idle_timer              #  a18: 00000000
.Lrel161:   .word        xTaskResumeAll                        #  a1c: 00000000
.Lrel162:   .word        printf                                #  a20: 00000000

# Function @ .irom0.text+0xa24
# Local variables/stack:
#     (local0):  word      @ -0x10
#     (local1):  word      @ -0xc
#     (local2):  word      @ -0x8
#     (local3):  word      @ -0x4
.literal_position
sdk_pm_open:
            addi         a1, a1, -16 /* (local0) */            #  a24: 12c1f0
            s32i.n       a13, a1, 12 /* a13 -> [(local3)] */   #  a27: d931
            s32i.n       a12, a1, 8 /* a12 -> [(local2)] */    #  a29: c921
            s32i.n       a0, a1, 4 /* a0 -> [(local1)] */      #  a2b: 0911
            mov.n        a12, a2 /* arg0 */                    #  a2d: cd02
            movi         a0, .Lrel154 /* vTaskSuspendAll */    #  a2f: 01f4ff
            callx0       a0 /* vTaskSuspendAll */              #  a32: c00000
            mov.n        a2, a12 /* arg0 */                    #  a35: 2d0c
            movi         a0, .Lrel155 /* sdk_rc_get_sta_trc */ #  a37: 01f3ff
            callx0       a0 /* sdk_rc_get_sta_trc */           #  a3a: c00000
            s32i.n       a2, a1, 0 /* a2 -> [(local0)] */      #  a3d: 2901
            beqz         a2, .Lbr044                           #  a3f: 16d208
            movi         a2, .Lrel148 /* .Label005 */          #  a42: 21e8ff
            movi         a13, .Lrel149 /* .Ldata002 */         #  a45: d1e8ff
            movi.n       a3, 32 /* 0x00000020 */               #  a48: 2c03
            l8ui         a0, a13, 53 /* [.Ldata017] */         #  a4a: 020d35
            movi         a4, 223 /* 0x000000df */              #  a4d: 42a0df
            and          a0, a0, a4                            #  a50: 400010
            or           a0, a0, a3                            #  a53: 300020
            s8i          a0, a13, 53 /* a0 -> [.Ldata017] */   #  a56: 024d35
            movi         a0, .Lrel156 /* sdk_os_timer_disarm */ #  a59: 01ebff
            callx0       a0 /* sdk_os_timer_disarm */          #  a5c: c00000
            movi         a2, .Lrel150 /* .Lstr025 */           #  a5f: 21e3ff
            l8ui         a3, a13, 226 /* [.Ldata034] */        #  a62: 320de2
            l8ui         a4, a13, 53 /* [.Ldata017] */         #  a65: 420d35
            l8ui         a5, a13, 58 /* [.Ldata022] */         #  a68: 520d3a
            extui        a4, a4, 1, 3                          #  a6b: 404124
            movi         a0, .Lrel157 /* printf */             #  a6e: 01e7ff
            callx0       a0 /* printf */                       #  a71: c00000
            l8ui         a5, a13, 53 /* [.Ldata017] */         #  a74: 520d35
            extui        a4, a5, 1, 3                          #  a77: 504124
            bnez         a4, .Lbr045                           #  a7a: 563406
            movi.n       a7, 14 /* 0x0000000e */               #  a7d: 0ce7
            movi         a6, 241 /* 0x000000f1 */              #  a7f: 62a0f1
            and          a6, a5, a6                            #  a82: 606510
            or           a6, a6, a7                            #  a85: 706620
            s8i          a6, a13, 53 /* a6 -> [.Ldata017] */   #  a88: 624d35
.Lbr043:    l32i.n       a3, a1, 0 /* [(local0)] */            #  a8b: 3801
            movi         a2, .Lrel151 /* .Lrel151 */           #  a8d: 21d8ff
            l16ui        a4, a3, 32 /* [[(local0)]+0x20] */    #  a90: 421310
            s8i          a12, a13, 64 /* arg0 -> [.Ldata028] */ #  a93: c24d40
            s16i         a4, a13, 72 /* [[(local0)]+0x20] -> [.Ldata029] */ #  a96: 425d24
            addi         a3, a3, 26 /* [(local0)]+0x1a */      #  a99: 32c31a
            movi.n       a4, 6 /* 0x00000006 */                #  a9c: 0c64
            movi         a0, .Lrel158 /* .Lrel158 */           #  a9e: 01dcff
            callx0       a0                                    #  aa1: c00000
            l8ui         a7, a13, 52 /* [.Ldata016] */         #  aa4: 720d34
            movi         a8, 254 /* 0x000000fe */              #  aa7: 82a0fe
            and          a7, a7, a8                            #  aaa: 807710
            movi.n       a8, 1 /* 0x00000001 */                #  aad: 0c18
            or           a7, a7, a8                            #  aaf: 807720
            s8i          a7, a13, 52 /* a7 -> [.Ldata016] */   #  ab2: 724d34
            movi         a6, .Llit010 /* 0x3ff20a00 */         #  ab5: 61cfff
            memw                                               #  ab8: c02000
            movi.n       a5, 0 /* 0x00000000 */                #  abb: 0c05
            l32i         a6, a6, 0x200 /* [0x3ff20c00] */      #  abd: 622680
            s32i.n       a6, a13, 12 /* [0x3ff20c00] -> [.Ldata006] */ #  ac0: 693d
            s32i.n       a5, a13, 16 /* 0x00000000 -> [.Ldata007] */ #  ac2: 594d
            movi         a0, .Lrel159 /* sdk_pp_disable_idle_timer */ #  ac4: 01d4ff
            callx0       a0 /* sdk_pp_disable_idle_timer */    #  ac7: c00000
            movi         a0, .Lrel160 /* sdk_pp_enable_idle_timer */ #  aca: 01d3ff
            callx0       a0 /* sdk_pp_enable_idle_timer */     #  acd: c00000
.Lbr044:    movi         a0, .Lrel161 /* xTaskResumeAll */     #  ad0: 01d3ff
            callx0       a0 /* xTaskResumeAll */               #  ad3: c00000
            l32i.n       a12, a1, 8 /* [(local2)] */           #  ad6: c821
            l32i.n       a13, a1, 12 /* [(local3)] */          #  ad8: d831
            l32i.n       a0, a1, 4 /* [(local1)] */            #  ada: 0811
            addi         a1, a1, 16 /* (top of frame) */       #  adc: 12c110
            ret.n                                              #  adf: 0df0
.Lbr045:    beqi         a4, 6, .Lbr043                        #  ae1: 2664a6
            l8ui         a9, a13, 52 /* [.Ldata016] */         #  ae4: 920d34
            bbci         a9, 0, .Lbr043                        #  ae7: 0769a0
            movi         a2, .Lrel152 /* .Lstr006 */           #  aea: 21c3ff
            movi         a3, .Lrel153 /* .Lstr007 */           #  aed: 31c3ff
            movi         a4, 868 /* 0x00000364 */              #  af0: 42a364
            movi         a0, .Lrel162 /* printf */             #  af3: 01cbff
            callx0       a0 /* printf */                       #  af6: c00000
.Lbr046:    j            .Lbr046 /* (halt) */                  #  af9: 06ffff

.Lrel163:   .word        .bss                                  #  afc: 00000000
.Lrel164:   .word        .Lstr026                              #  b00: a4010000
.Lrel165:   .word        .Lstr027                              #  b04: b0010000
.Lrel166:   .word        .Label002                             #  b08: 54000000
.Lrel167:   .word        .Lstr028                              #  b0c: b8010000
.Lrel168:   .word        .Ldata043                             #  b10: 44010000
.Lrel169:   .word        .Ldata043                             #  b14: 44010000
.Lrel170:   .word        sdk_sleep_start_wait_time             #  b18: 00000000
.Lrel171:   .word        .Ldata044                             #  b1c: 45010000
.Lrel172:   .word        .Label003                             #  b20: 70000000
.Lrel173:   .word        .Lstr030                              #  b24: dc010000
.Lrel174:   .word        .Lstr029                              #  b28: cc010000
.Lrel175:   .word        printf                                #  b2c: 00000000
.Lrel176:   .word        printf                                #  b30: 00000000
.Lrel177:   .word        sdk_os_timer_disarm                   #  b34: 00000000
.Lrel178:   .word        __umoddi3                             #  b38: 00000000
.Lrel179:   .word        printf                                #  b3c: 00000000
.Lrel180:   .word        __divsi3                              #  b40: 00000000
.Lrel181:   .word        sdk_pm_scan_unlocked                  #  b44: 00000000
.Lrel182:   .word        sdk_pp_try_enable_idle_timer          #  b48: 00000000
.Lrel183:   .word        sdk_pm_post                           #  b4c: 00000000
.Lrel184:   .word        sdk_os_timer_disarm                   #  b50: 00000000
.Lrel185:   .word        sdk_pm_get_idle_wait_time             #  b54: 00000000
.Lrel186:   .word        printf                                #  b58: 00000000
.Lrel187:   .word        printf                                #  b5c: 00000000

# Function @ .irom0.text+0xb60
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
#     (local9):  word[3]   @ -0xc
.literal_position
sdk_pm_onBcnRx:
            addi         a1, a1, -48 /* (local0) */            #  b60: 12c1d0
            s32i.n       a13, a1, 24 /* a13 -> [(local6)] */   #  b63: d961
            s32i.n       a15, a1, 32 /* a15 -> [(local8)] */   #  b65: f981
            s32i.n       a12, a1, 20 /* a12 -> [(local5)] */   #  b67: c951
            s32i.n       a14, a1, 28 /* a14 -> [(local7)] */   #  b69: e971
            s32i.n       a0, a1, 16 /* a0 -> [(local4)] */     #  b6b: 0941
            mov.n        a14, a3 /* arg1 */                    #  b6d: ed03
            sub          a0, a4, a3                            #  b6f: 3004c0
            blti         a0, 12, .Lbr051                       #  b72: a6a03e
            addi.n       a0, a14, 12 /* arg1+0xc */            #  b75: cb0e
            l16ui        a3, a3, 8 /* [arg1+0x8] */            #  b77: 321304
            movi         a12, .Lrel163 /* .Ldata002 */         #  b7a: c1e0ff
            slli         a3, a3, 10                            #  b7d: 603311
            s32i.n       a3, a12, 48 /* a3 -> [.Ldata015] */   #  b80: 39cc
            sub          a3, a4, a0                            #  b82: 0034c0
            blti         a3, 2, .Lbr052                        #  b85: a6233a
            movi.n       a13, 0 /* 0x00000000 */               #  b88: 0c0d
.Lbr047:    l8ui         a5, a0, 1                             #  b8a: 520001
            l8ui         a7, a0, 0                             #  b8d: 720000
            addi.n       a6, a5, 2                             #  b90: 2b65
            blt          a3, a6, .Lbr051                       #  b92: 67231e
            bnei         a7, 5, .Lbr048                        #  b95: 665701
            mov.n        a13, a0                               #  b98: dd00
.Lbr048:    add.n        a0, a5, a0                            #  b9a: 0a05
            addi.n       a0, a0, 2                             #  b9c: 2b00
            sub          a3, a4, a0                            #  b9e: 0034c0
            bgei         a3, 2, .Lbr047                        #  ba1: e623e5
            j            .Lbr053                               #  ba4: 460700
.Lbr049:    beqz.n       a15, .Lbr051                          #  ba7: 8c9f
            bbsi         a2, 4, .Lbr050                        #  ba9: 47e204
            l8ui         a2, a12, 59 /* [.Ldata023] */         #  bac: 220c3b
            beqz.n       a2, .Lbr051                           #  baf: 8c12
.Lbr050:    call0        .Lfunc010                             #  bb1: 45b3ff
.Lbr051:    l32i.n       a12, a1, 20 /* [(local5)] */          #  bb4: c851
            l32i.n       a13, a1, 24 /* [(local6)] */          #  bb6: d861
            l32i.n       a14, a1, 28 /* [(local7)] */          #  bb8: e871
            l32i.n       a15, a1, 32 /* [(local8)] */          #  bba: f881
            l32i.n       a0, a1, 16 /* [(local4)] */           #  bbc: 0841
            addi         a1, a1, 48 /* (top of frame) */       #  bbe: 12c130
            ret.n                                              #  bc1: 0df0
.Lbr052:    movi.n       a13, 0 /* 0x00000000 */               #  bc3: 0c0d
.Lbr053:    s32i.n       a2, a1, 12 /* arg0 -> [(local3)] */   #  bc5: 2931
            bnez.n       a13, .Lbr054                          #  bc7: ccad
            movi         a2, .Lrel164 /* .Lrel164 */           #  bc9: 21cdff
            movi         a0, .Lrel175 /* .Lrel175 */           #  bcc: 01d8ff
            callx0       a0                                    #  bcf: c00000
            j            .Lbr051                               #  bd2: 86f7ff
.Lbr054:    movi         a2, .Lrel165 /* .Lstr027 */           #  bd5: 21cbff
            movi         a0, .Lrel176 /* printf */             #  bd8: 01d6ff
            callx0       a0 /* printf */                       #  bdb: c00000
            movi         a2, .Lrel166 /* .Label002 */          #  bde: 21caff
            movi         a0, .Lrel177 /* sdk_os_timer_disarm */ #  be1: 01d4ff
            callx0       a0 /* sdk_os_timer_disarm */          #  be4: c00000
            l32i.n       a4, a12, 48 /* [.Ldata015] */         #  be7: 48cc
            l32i.n       a3, a14, 4 /* [arg1+0x4] */           #  be9: 381e
            l32i.n       a2, a14, 0 /* [arg1] */               #  beb: 280e
            l16ui        a6, a12, 232 /* [.Ldata038] */        #  bed: 621c74
            movi.n       a15, 0 /* 0x00000000 */               #  bf0: 0c0f
            addi.n       a6, a6, 1 /* [.Ldata038]+0x1 */       #  bf2: 1b66
            s16i         a15, a12, 230 /* 0x0000 -> [.Ldata037] */ #  bf4: f25c73
            s16i         a6, a12, 232 /* [.Ldata038]+0x1 -> [.Ldata038] */ #  bf7: 625c74
            l8ui         a14, a13, 3                           #  bfa: e20d03
            l8ui         a5, a13, 2                            #  bfd: 520d02
            s32i.n       a4, a1, 4 /* [.Ldata015] -> [(local1)] */ #  c00: 4911
            moveqz       a5, a14, a5                           #  c02: 505e83
            mull         a5, a5, a4                            #  c05: 405582
            s32i.n       a5, a1, 8 /* a5 -> [(local2)] */      #  c08: 5921
            mov.n        a5, a15 /* 0x00000000 */              #  c0a: 5d0f
            movi         a0, .Lrel178 /* __umoddi3 */          #  c0c: 01cbff
            callx0       a0 /* __umoddi3 */                    #  c0f: c00000
            l32i.n       a9, a1, 12 /* [(local3)] */           #  c12: 9831
            l8ui         a7, a12, 54 /* [.Ldata018] */         #  c14: 720c36
            l32i.n       a9, a9, 32 /* [[(local3)]+0x20] */    #  c17: 9889
            l32i.n       a10, a1, 4 /* [(local1)] */           #  c19: a811
            l32i.n       a9, a9, 4 /* [[[(local3)]+0x20]+0x4] */ #  c1b: 9819
            l32i.n       a8, a1, 8 /* [(local2)] */            #  c1d: 8821
            sub          a9, a9, a2                            #  c1f: 2099c0
            s32i.n       a9, a12, 28 /* a9 -> [.Ldata010] */   #  c22: 997c
            add.n        a8, a8, a9                            #  c24: 9a88
            s32i.n       a8, a12, 24 /* a8 -> [.Ldata009] */   #  c26: 896c
            add.n        a9, a9, a10                           #  c28: aa99
            s32i.n       a9, a12, 20 /* a9 -> [.Ldata008] */   #  c2a: 995c
            beqz.n       a7, .Lbr055                           #  c2c: 9c67
            l8ui         a3, a12, 62 /* [.Ldata026] */         #  c2e: 320c3e
            movi.n       a4, 0 /* 0x00000000 */                #  c31: 0c04
            beq          a14, a3, .Lbr056                      #  c33: 371e14
            mov.n        a4, a14                               #  c36: 4d0e
            movi         a2, .Lrel167 /* .Lstr028 */           #  c38: 21b5ff
            movi         a0, .Lrel179 /* printf */             #  c3b: 01c0ff
            callx0       a0 /* printf */                       #  c3e: c00000
            movi.n       a4, 0 /* 0x00000000 */                #  c41: 0c04
            j            .Lbr056                               #  c43: 060100
.Lbr055:    movi.n       a4, 0 /* 0x00000000 */                #  c46: 0c04
            s8i          a14, a12, 62 /* a14 -> [.Ldata026] */ #  c48: e24c3e
.Lbr056:    movi         a3, 254 /* 0x000000fe */              #  c4b: 32a0fe
            l16ui        a0, a12, 72 /* [.Ldata029] */         #  c4e: 021c24
            movi.n       a10, 1 /* 0x00000001 */               #  c51: 0c1a
            mov.n        a2, a10 /* 0x00000001 */              #  c53: 2d0a
            s8i          a10, a12, 54 /* 0x01 -> [.Ldata018] */ #  c55: a24c36
            extui        a11, a0, 0, 14                        #  c58: 00b0d4
            l8ui         a5, a13, 4                            #  c5b: 520d04
            l8ui         a9, a13, 1                            #  c5e: 920d01
            and          a3, a5, a3                            #  c61: 303510
            add.n        a9, a9, a3                            #  c64: 3a99
            extui        a5, a5, 0, 1                          #  c66: 505004
            s8i          a5, a12, 46 /* a5 -> [.Ldata013] */   #  c69: 524c2e
            addi         a9, a9, -4                            #  c6c: 92c9fc
            extui        a9, a9, 0, 8                          #  c6f: 909074
            beqz.n       a11, .Lbr058                          #  c72: 9cdb
            extui        a8, a0, 3, 11                         #  c74: 0083a4
            bltu         a8, a3, .Lbr057                       #  c77: 373816
            bltu         a9, a8, .Lbr057                       #  c7a: 873913
            extui        a7, a0, 0, 3                          #  c7d: 007024
            sub          a6, a13, a3                           #  c80: 306dc0
            add.n        a6, a8, a6                            #  c83: 6a68
            l8ui         a6, a6, 5                             #  c85: 620605
            ssr          a7                                    #  c88: 000740
            sra          a6, a6                                #  c8b: 6060b1
            bbsi         a6, 0, .Lbr058                        #  c8e: 07e601
.Lbr057:    movi.n       a2, 0 /* 0x00000000 */                #  c91: 0c02
.Lbr058:    movi.n       a0, 1 /* 0x00000001 */                #  c93: 0c10
            extui        a3, a2, 0, 8                          #  c95: 203074
            s8i          a3, a12, 47 /* a3 -> [.Ldata014] */   #  c98: 324c2f
            bnez.n       a5, .Lbr059                           #  c9b: cc35
            movi.n       a7, 0 /* 0x00000000 */                #  c9d: 0c07
            moveqz       a0, a7, a3                            #  c9f: 300783
.Lbr059:    l8ui         a14, a13, 3                           #  ca2: e20d03
            s32i.n       a0, a1, 0 /* a0 -> [(local0)] */      #  ca5: 0901
            movi         a5, .Lrel168 /* .Ldata043 */          #  ca7: 519aff
            extui        a15, a0, 0, 8                         #  caa: 00f074
            l8ui         a3, a5, 0 /* [.Ldata043] */           #  cad: 320500
            extui        a8, a2, 0, 8                          #  cb0: 208074
            addi.n       a3, a3, 1 /* [.Ldata043]+0x1 */       #  cb3: 1b33
            extui        a3, a3, 0, 8                          #  cb5: 303074
            beqz.n       a8, .Lbr060                           #  cb8: 8cd8
            l8ui         a0, a12, 53 /* [.Ldata017] */         #  cba: 020c35
            extui        a0, a0, 1, 3                          #  cbd: 000124
            blti         a0, 2, .Lbr060                        #  cc0: a62005
            bgei         a0, 6, .Lbr060                        #  cc3: e66002
            s8i          a10, a12, 244 /* 0x01 -> [.Ldata039] */ #  cc6: a24cf4
.Lbr060:    bgeui        a14, 4, .Lbr061                       #  cc9: f64e1a
            s32i.n       a3, a1, 36 /* a3 -> [(local9)] */     #  ccc: 3991
            beqz.n       a14, .Lbr061                          #  cce: 9c5e
            mov.n        a3, a14                               #  cd0: 3d0e
            movi.n       a2, 15 /* 0x0000000f */               #  cd2: 0cf2
            movi         a0, .Lrel180 /* __divsi3 */           #  cd4: 019bff
            callx0       a0 /* __divsi3 */                     #  cd7: c00000
            movi.n       a4, 0 /* 0x00000000 */                #  cda: 0c04
            l32i.n       a3, a1, 36 /* [(local9)] */           #  cdc: 3891
            movi         a5, .Lrel169 /* .Ldata043 */          #  cde: 518dff
            extui        a0, a2, 0, 8                          #  ce1: 200074
            j            .Lbr062                               #  ce4: 460000
.Lbr061:    movi.n       a0, 15 /* 0x0000000f */               #  ce7: 0cf0
.Lbr062:    bltu         a3, a0, .Lbr063                       #  ce9: 073325
            s8i          a4, a5, 0 /* 0x00 -> [.Ldata043] */   #  cec: 424500
            movi         a14, .Lrel170 /* .Lrel170 */          #  cef: e18aff
            l8ui         a3, a12, 244 /* [.Ldata039] */        #  cf2: 320cf4
            movi         a0, .Lrel171 /* .Lrel171 */           #  cf5: 0189ff
            beqz         a3, .Lbr074                           #  cf8: 16830c
            l8ui         a2, a0, 0                             #  cfb: 220000
            addi.n       a2, a2, 1                             #  cfe: 1b22
            extui        a2, a2, 0, 8                          #  d00: 202074
            bltui        a2, 2, .Lbr068                        #  d03: b62270
            s8i          a4, a0, 0                             #  d06: 424000
            movi         a3, 1300 /* 0x00000514 */             #  d09: 32a514
            s16i         a3, a14, 0                            #  d0c: 325e00
            j            .Lbr069                               #  d0f: c61900
.Lbr063:    s8i          a3, a5, 0 /* a3 -> [.Ldata043] */     #  d12: 324500
.Lbr064:    l32i.n       a5, a1, 0 /* [(local0)] */            #  d15: 5801
            l8ui         a2, a12, 53 /* [.Ldata017] */         #  d17: 220c35
            extui        a5, a5, 0, 8                          #  d1a: 505074
            bnez         a5, .Lbr067                           #  d1d: 561505
            l8ui         a7, a13, 3                            #  d20: 720d03
            l8ui         a0, a12, 63 /* [.Ldata027] */         #  d23: 020c3f
            movi.n       a6, 8 /* 0x00000008 */                #  d26: 0c86
            mul16u       a7, a0, a7                            #  d28: 7070c1
            bge          a6, a7, .Lbr065                       #  d2b: 77a606
            movi.n       a15, 1 /* 0x00000001 */               #  d2e: 0c1f
            movi.n       a0, 0 /* 0x00000000 */                #  d30: 0c00
            s8i          a0, a12, 63 /* 0x00 -> [.Ldata027] */ #  d32: 024c3f
.Lbr065:    addi.n       a5, a0, 1                             #  d35: 1b50
.Lbr066:    s8i          a5, a12, 63 /* a5 -> [.Ldata027] */   #  d37: 524c3f
            extui        a0, a2, 1, 3                          #  d3a: 200124
            beqz         a0, .Lbr071                           #  d3d: 161005
            addi.n       a8, a0, -1                            #  d40: 0b80
            beqz         a8, .Lbr049                           #  d42: 1618e6
            beqi         a0, 2, .Lbr070                        #  d45: 26203a
            beqi         a0, 3, .Lbr071                        #  d48: 263046
            beqi         a0, 4, .Lbr072                        #  d4b: 264051
            beqi         a0, 5, .Lbr073                        #  d4e: 265057
            addi         a9, a0, -6                            #  d51: 92c0fa
            beqz         a9, .Lbr051                           #  d54: 16c9e5
            addi         a10, a0, -7                           #  d57: a2c0f9
            bnez         a10, .Lbr051                          #  d5a: 566ae5
            bnez         a15, .Lbr051                          #  d5d: 563fe5
            movi         a0, .Lrel181 /* .Lrel181 */           #  d60: 0179ff
            callx0       a0                                    #  d63: c00000
            beqz         a2, .Lbr051                           #  d66: 16a2e4
            movi         a0, .Lrel182 /* .Lrel182 */           #  d69: 0177ff
            callx0       a0                                    #  d6c: c00000
            j            .Lbr051                               #  d6f: 4690ff
.Lbr067:    mov.n        a5, a4 /* 0x00000000 */               #  d72: 5d04
            j            .Lbr066                               #  d74: c6efff
.Lbr068:    s8i          a2, a0, 0                             #  d77: 224000
.Lbr069:    s8i          a4, a12, 244 /* 0x00 -> [.Ldata039] */ #  d7a: 424cf4
            s8i          a4, a12, 245 /* 0x00 -> [.Ldata040] */ #  d7d: 424cf5
            j            .Lbr064                               #  d80: 46e4ff
.Lbr070:    beqz         a15, .Lbr051                          #  d83: 16dfe2
            extui        a11, a2, 4, 1                         #  d86: 20b404
            beqz         a11, .Lbr051                          #  d89: 167be2
            call0        .Lfunc010                             #  d8c: 8595ff
            j            .Lbr051                               #  d8f: 4688ff
.Lbr071:    beqz         a15, .Lbr051                          #  d92: 16efe1
            movi.n       a2, 1 /* 0x00000001 */                #  d95: 0c12
            movi         a0, .Lrel183 /* sdk_pm_post */        #  d97: 016dff
            callx0       a0 /* sdk_pm_post */                  #  d9a: c00000
            j            .Lbr051                               #  d9d: c684ff
.Lbr072:    beqz         a15, .Lbr075                          #  da0: 167f04
            call0        .Lfunc010                             #  da3: 4594ff
            j            .Lbr051                               #  da6: 8682ff
.Lbr073:    beqz         a15, .Lbr076                          #  da9: 167f04
            movi         a2, .Lrel172 /* .Label003 */          #  dac: 215dff
            movi         a0, .Lrel184 /* sdk_os_timer_disarm */ #  daf: 0168ff
            callx0       a0 /* sdk_os_timer_disarm */          #  db2: c00000
            l8ui         a13, a12, 53 /* [.Ldata017] */        #  db5: d20c35
            extui        a13, a13, 4, 1                        #  db8: d0d404
            beqz         a13, .Lbr051                          #  dbb: 165ddf
            call0        .Lfunc010                             #  dbe: 8592ff
            j            .Lbr051                               #  dc1: c67bff
.Lbr074:    l8ui         a3, a12, 245 /* [.Ldata040] */        #  dc4: 320cf5
            s8i          a4, a0, 0                             #  dc7: 424000
            beqz         a3, .Lbr079                           #  dca: 163305
            l8ui         a2, a0, 1                             #  dcd: 220001
            addi.n       a2, a2, 1                             #  dd0: 1b22
            extui        a2, a2, 0, 8                          #  dd2: 202074
            beqz         a2, .Lbr078                           #  dd5: 162204
            movi.n       a3, 0 /* 0x00000000 */                #  dd8: 0c03
            s8i          a3, a0, 1                             #  dda: 324001
            movi         a0, .Lrel185 /* sdk_pm_get_idle_wait_time */ #  ddd: 015dff
            callx0       a0 /* sdk_pm_get_idle_wait_time */    #  de0: c00000
            movi.n       a4, 0 /* 0x00000000 */                #  de3: 0c04
            s16i         a2, a14, 0                            #  de5: 225e00
            j            .Lbr069                               #  de8: 86e3ff
.Lbr075:    bbsi         a2, 4, .Lbr077                        #  deb: 47e21d
            call0        .Lfunc009                             #  dee: c587ff
            j            .Lbr051                               #  df1: c66fff
.Lbr076:    l8ui         a6, a12, 55 /* [.Ldata019] */         #  df4: 620c37
            addi         a6, a6, -8 /* [.Ldata019]-0x8 */      #  df7: 62c6f8
            bnez         a6, .Lbr051                           #  dfa: 5666db
            movi         a2, .Lrel173 /* .Lstr030 */           #  dfd: 2149ff
            movi         a0, .Lrel186 /* printf */             #  e00: 0156ff
            callx0       a0 /* printf */                       #  e03: c00000
            call0        .Lfunc007                             #  e06: 8568ff
            j            .Lbr051                               #  e09: c669ff
.Lbr077:    movi         a2, .Lrel174 /* .Lstr029 */           #  e0c: 2147ff
            movi         a0, .Lrel187 /* printf */             #  e0f: 0153ff
            callx0       a0 /* printf */                       #  e12: c00000
            call0        .Lfunc007                             #  e15: 8567ff
            j            .Lbr051                               #  e18: 0666ff
.Lbr078:    s8i          a2, a0, 1                             #  e1b: 224001
            j            .Lbr069                               #  e1e: 06d6ff
.Lbr079:    s8i          a4, a0, 1                             #  e21: 424001
            j            .Lbr069                               #  e24: 86d4ff

            .balign      4
.Lrel188:   .word        .bss                                  #  e28: 00000000
.Lrel189:   .word        .Lstr031                              #  e2c: ec010000
.Lrel190:   .word        printf                                #  e30: 00000000

# Function @ .irom0.text+0xe34
# Local variables/stack:
#     (local0):  word[4]   @ -0x10
.literal_position
.Lfunc014:  addi         a1, a1, -16 /* (local0) */            #  e34: 12c1f0
            s32i.n       a0, a1, 0 /* a0 -> [(local0)] */      #  e37: 0901
            movi         a0, .Lrel188 /* .Ldata002 */          #  e39: 01fbff
            l8ui         a0, a0, 53 /* [.Ldata017] */          #  e3c: 020035
            extui        a3, a0, 1, 3                          #  e3f: 003124
            bnei         a3, 6, .Lbr080                        #  e42: 666308
            bbci         a0, 5, .Lbr082                        #  e45: 576015
            call0        .Lfunc011                             #  e48: c590ff
            j            .Lbr081                               #  e4b: 060200
.Lbr080:    movi         a2, .Lrel189 /* .Lstr031 */           #  e4e: 21f7ff
            movi         a0, .Lrel190 /* printf */             #  e51: 01f7ff
            callx0       a0 /* printf */                       #  e54: c00000
.Lbr081:    l32i.n       a0, a1, 0 /* [(local0)] */            #  e57: 0801
            addi         a1, a1, 16 /* (top of frame) */       #  e59: 12c110
            ret.n                                              #  e5c: 0df0
.Lbr082:    call0        .Lfunc012                             #  e5e: 4594ff
            j            .Lbr081                               #  e61: 86fcff

.Lrel191:   .word        .bss                                  #  e64: 00000000
.Lrel192:   .word        .Lstr006                              #  e68: 58000000
.Lrel193:   .word        .Lstr007                              #  e6c: 60000000
.Lrel194:   .word        .Lstr033                              #  e70: 04020000
.Lrel195:   .word        .Lstr006                              #  e74: 58000000
.Lrel196:   .word        .Lstr007                              #  e78: 60000000
.Lrel197:   .word        .Lstr032                              #  e7c: f4010000
.Lrel198:   .word        printf                                #  e80: 00000000
.Lrel199:   .word        printf                                #  e84: 00000000
.Lrel200:   .word        printf                                #  e88: 00000000
.Lrel201:   .word        printf                                #  e8c: 00000000

# Function @ .irom0.text+0xe90
# Local variables/stack:
#     (local0):  word[4]   @ -0x10
.literal_position
.Lfunc015:  addi         a1, a1, -16 /* (local0) */            #  e90: 12c1f0
            s32i.n       a0, a1, 0 /* a0 -> [(local0)] */      #  e93: 0901
            movi         a0, .Lrel191 /* .Ldata002 */          #  e95: 01f3ff
            l8ui         a0, a0, 53 /* [.Ldata017] */          #  e98: 020035
            extui        a3, a0, 1, 3                          #  e9b: 003124
            bnei         a3, 1, .Lbr084                        #  e9e: 661314
            bbsi         a0, 5, .Lbr086                        #  ea1: 57e02c
            movi         a2, .Lrel192 /* .Lstr006 */           #  ea4: 21f1ff
            movi         a3, .Lrel193 /* .Lstr007 */           #  ea7: 31f1ff
            movi         a4, 1410 /* 0x00000582 */             #  eaa: 42a582
            movi         a0, .Lrel198 /* printf */             #  ead: 01f4ff
            callx0       a0 /* printf */                       #  eb0: c00000
.Lbr083:    j            .Lbr083 /* (halt) */                  #  eb3: 06ffff
.Lbr084:    movi         a2, .Lrel194 /* .Lstr033 */           #  eb6: 21eeff
            movi         a0, .Lrel199 /* printf */             #  eb9: 01f2ff
            callx0       a0 /* printf */                       #  ebc: c00000
            movi         a2, .Lrel195 /* .Lstr006 */           #  ebf: 21edff
            movi         a3, .Lrel196 /* .Lstr007 */           #  ec2: 31edff
            movi         a4, 1426 /* 0x00000592 */             #  ec5: 42a592
            movi         a0, .Lrel200 /* printf */             #  ec8: 01f0ff
            callx0       a0 /* printf */                       #  ecb: c00000
.Lbr085:    j            .Lbr085 /* (halt) */                  #  ece: 06ffff
.Lbr086:    call0        .Lfunc004                             #  ed1: c533ff
            beqz.n       a2, .Lbr087                           #  ed4: 8cd2
            movi         a2, .Lrel197 /* .Lstr032 */           #  ed6: 21e9ff
            movi         a0, .Lrel201 /* printf */             #  ed9: 01ecff
            callx0       a0 /* printf */                       #  edc: c00000
            call0        .Lfunc007                             #  edf: 055bff
            j            .Lbr088                               #  ee2: 860000
.Lbr087:    call0        .Lfunc008                             #  ee5: c563ff
.Lbr088:    l32i.n       a0, a1, 0 /* [(local0)] */            #  ee8: 0801
            addi         a1, a1, 16 /* (top of frame) */       #  eea: 12c110
            ret.n                                              #  eed: 0df0

            .balign      4
.Lrel202:   .word        .Label004                             #  ef0: 8c000000
.Lrel203:   .word        .bss                                  #  ef4: 00000000
.Lrel204:   .word        .Lstr034                              #  ef8: 0c020000
.Lrel205:   .word        .Ldata045                             #  efc: 47010000
.Lrel206:   .word        .Lstr035                              #  f00: 20020000
.Llit011:   .word        0x3ff20200                            #  f04: 0002f23f
.Lrel207:   .word        .Ldata045                             #  f08: 47010000
.Llit012:   .word        0x000036af                            #  f0c: af360000
.Lrel208:   .word        sdk_os_timer_disarm                   #  f10: 00000000
.Lrel209:   .word        printf                                #  f14: 00000000
.Lrel210:   .word        printf                                #  f18: 00000000
.Lrel211:   .word        sdk_chm_get_current_channel           #  f1c: 00000000
.Lrel212:   .word        sdk_pm_send_nullfunc                  #  f20: 00000000

# Function @ .irom0.text+0xf24
# Local variables/stack:
#     (local0):  word      @ -0x10
#     (local1):  word      @ -0xc
#     (local2):  word      @ -0x8
#     (local3):  word      @ -0x4
.literal_position
.Lfunc016:  mov.n        a3, a2 /* arg0 */                     #  f24: 3d02
            addi         a1, a1, -16 /* (local0) */            #  f26: 12c1f0
            s32i.n       a12, a1, 8 /* a12 -> [(local2)] */    #  f29: c921
            s32i.n       a13, a1, 12 /* a13 -> [(local3)] */   #  f2b: d931
            movi         a2, .Lrel202 /* .Label004 */          #  f2d: 21f0ff
            s32i.n       a0, a1, 4 /* a0 -> [(local1)] */      #  f30: 0911
            s32i.n       a3, a1, 0 /* arg0 -> [(local0)] */    #  f32: 3901
            movi         a0, .Lrel208 /* sdk_os_timer_disarm */ #  f34: 01f7ff
            callx0       a0 /* sdk_os_timer_disarm */          #  f37: c00000
            movi         a13, .Lrel203 /* .Ldata002 */         #  f3a: d1eeff
            l8ui         a0, a13, 53 /* [.Ldata017] */         #  f3d: 020d35
            extui        a0, a0, 1, 3                          #  f40: 000124
            beqz         a0, .Lbr091                           #  f43: 162006
            movi         a2, .Lrel204 /* .Lstr034 */           #  f46: 21ecff
            movi.n       a12, 0 /* 0x00000000 */               #  f49: 0c0c
            s8i          a12, a13, 58 /* 0x00 -> [.Ldata022] */ #  f4b: c24d3a
            s8i          a12, a13, 59 /* 0x00 -> [.Ldata023] */ #  f4e: c24d3b
            movi         a0, .Lrel209 /* printf */             #  f51: 01f0ff
            callx0       a0 /* printf */                       #  f54: c00000
            l32i.n       a3, a1, 0 /* [(local0)] */            #  f57: 3801
            movi         a0, .Lrel205 /* .Ldata045 */          #  f59: 01e8ff
            l32i.n       a3, a3, 32 /* [[(local0)]+0x20] */    #  f5c: 3883
            movi         a9, 239 /* 0x000000ef */              #  f5e: 92a0ef
            l8ui         a3, a3, 15 /* [[[(local0)]+0x20]+0xf] */ #  f61: 32030f
            l8ui         a8, a13, 53 /* [.Ldata017] */         #  f64: 820d35
            beqi         a3, 1, .Lbr092                        #  f67: 261349
            movi         a2, .Lrel206 /* .Lstr035 */           #  f6a: 21e5ff
            movi         a4, .Llit011 /* 0x3ff20200 */         #  f6d: 41e5ff
            memw                                               #  f70: c02000
            l32i         a4, a4, 0x218 /* [0x3ff20418] */      #  f73: 422486
            extui        a4, a4, 12, 16                        #  f76: 404cf4
            slli         a4, a4, 2                             #  f79: e04411
            movi         a0, .Lrel210 /* printf */             #  f7c: 01e7ff
            callx0       a0 /* printf */                       #  f7f: c00000
            movi         a0, .Lrel211 /* sdk_chm_get_current_channel */ #  f82: 01e6ff
            callx0       a0 /* sdk_chm_get_current_channel */  #  f85: c00000
            l8ui         a5, a13, 61 /* [.Ldata025] */         #  f88: 520d3d
            l8ui         a0, a13, 53 /* [.Ldata017] */         #  f8b: 020d35
            bnei         a5, 2, .Lbr089                        #  f8e: 662508
            s8i          a12, a13, 61 /* 0x00 -> [.Ldata025] */ #  f91: c24d3d
            call0        .Lfunc010                             #  f94: 0575ff
            j            .Lbr091                               #  f97: 860300
.Lbr089:    movi.n       a2, 1 /* 0x00000001 */                #  f9a: 0c12
            bbci         a0, 5, .Lbr090                        #  f9c: 576006
            srli         a6, a0, 7                             #  f9f: 006741
            beqz.n       a6, .Lbr094                           #  fa2: bc46
            mov.n        a12, a2 /* 0x00000001 */              #  fa4: cd02
.Lbr090:    s8i          a12, a13, 61 /* a12 -> [.Ldata025] */ #  fa6: c24d3d
.Lbr091:    l32i.n       a12, a1, 8 /* [(local2)] */           #  fa9: c821
            l32i.n       a13, a1, 12 /* [(local3)] */          #  fab: d831
            l32i.n       a0, a1, 4 /* [(local1)] */            #  fad: 0811
            addi         a1, a1, 16 /* (top of frame) */       #  faf: 12c110
            ret.n                                              #  fb2: 0df0
.Lbr092:    s8i          a12, a0, 0 /* 0x00 -> [.Ldata045] */  #  fb4: c24000
            and          a8, a8, a9                            #  fb7: 908810
            l8ui         a7, a13, 61 /* [.Ldata025] */         #  fba: 720d3d
            movi.n       a9, 16 /* 0x00000010 */               #  fbd: 1c09
            or           a8, a8, a9                            #  fbf: 908820
            s8i          a8, a13, 53 /* a8 -> [.Ldata017] */   #  fc2: 824d35
            bnei         a7, 2, .Lbr093                        #  fc5: 662708
            s8i          a12, a13, 61 /* 0x00 -> [.Ldata025] */ #  fc8: c24d3d
            call0        .Lfunc010                             #  fcb: c571ff
            j            .Lbr091                               #  fce: c6f5ff
.Lbr093:    s8i          a12, a13, 61 /* 0x00 -> [.Ldata025] */ #  fd1: c24d3d
            call0        .Lfunc015                             #  fd4: 85ebff
            j            .Lbr091                               #  fd7: 86f3ff
.Lbr094:    call0        .Lfunc004                             #  fda: 4523ff
            movi         a10, .Llit012 /* 0x000036af */        #  fdd: a1cbff
            movi         a0, .Lrel207 /* .Ldata045 */          #  fe0: 01caff
            bltu         a10, a2, .Lbr095                      #  fe3: 273a08
            s8i          a12, a13, 61 /* 0x00 -> [.Ldata025] */ #  fe6: c24d3d
            call0        .Lfunc008                             #  fe9: 8553ff
            j            .Lbr091                               #  fec: 46eeff
.Lbr095:    l8ui         a11, a0, 0 /* [.Ldata045] */          #  fef: b20000
            movi.n       a3, 14 /* 0x0000000e */               #  ff2: 0ce3
            addi.n       a2, a11, 1 /* [.Ldata045]+0x1 */      #  ff4: 1b2b
            bltu         a3, a11, .Lbr096                      #  ff6: b7330d
            s8i          a2, a0, 0 /* [.Ldata045]+0x1 -> [.Ldata045] */ #  ff9: 224000
            movi.n       a2, 1 /* 0x00000001 */                #  ffc: 0c12
            movi         a0, .Lrel212 /* sdk_pm_send_nullfunc */ #  ffe: 01c8ff
            callx0       a0 /* sdk_pm_send_nullfunc */         # 1001: c00000
            j            .Lbr091                               # 1004: 46e8ff
.Lbr096:    movi.n       a2, 1 /* 0x00000001 */                # 1007: 0c12
            s8i          a3, a0, 0 /* 0x0e -> [.Ldata045] */   # 1009: 324000
            call0        sdk_pm_send_nullfunc                  # 100c: 050000
            j            .Lbr091                               # 100f: 86e5ff

            .balign      4
.Lrel213:   .word        .Label004                             # 1014: 8c000000
.Lrel214:   .word        .bss                                  # 1018: 00000000
.Lrel215:   .word        .Lstr036                              # 101c: 30020000
.Lrel216:   .word        .Ldata046                             # 1020: 48010000
.Lrel217:   .word        .Lstr006                              # 1024: 58000000
.Lrel218:   .word        .Lstr007                              # 1028: 60000000
.Lrel219:   .word        .Lstr006                              # 102c: 58000000
.Lrel220:   .word        .Lstr007                              # 1030: 60000000
.Lrel221:   .word        .Label001                             # 1034: 41000000
.Lrel222:   .word        .Ldata046                             # 1038: 48010000
.Lrel223:   .word        sdk_os_timer_disarm                   # 103c: 00000000
.Lrel224:   .word        printf                                # 1040: 00000000
.Lrel225:   .word        sdk_chm_get_current_channel           # 1044: 00000000
.Lrel226:   .word        printf                                # 1048: 00000000
.Lrel227:   .word        printf                                # 104c: 00000000
.Lrel228:   .word        sdk_rc_get_trc                        # 1050: 00000000
.Lrel229:   .word        sdk_pm_send_nullfunc                  # 1054: 00000000
.Lrel230:   .word        sdk_pm_send_nullfunc                  # 1058: 00000000

# Function @ .irom0.text+0x105c
# Local variables/stack:
#     (local0):  word      @ -0x10
#     (local1):  word      @ -0xc
#     (local2):  word[2]   @ -0x8
.literal_position
.Lfunc017:  mov.n        a4, a2 /* arg0 */                     # 105c: 4d02
            addi         a1, a1, -16 /* (local0) */            # 105e: 12c1f0
            s32i.n       a12, a1, 8 /* a12 -> [(local2)] */    # 1061: c921
            movi         a2, .Lrel213 /* .Label004 */          # 1063: 21ecff
            s32i.n       a0, a1, 4 /* a0 -> [(local1)] */      # 1066: 0911
            s32i.n       a4, a1, 0 /* arg0 -> [(local0)] */    # 1068: 4901
            movi         a0, .Lrel223 /* sdk_os_timer_disarm */ # 106a: 01f4ff
            callx0       a0 /* sdk_os_timer_disarm */          # 106d: c00000
            movi         a12, .Lrel214 /* .Ldata002 */         # 1070: c1eaff
            l8ui         a0, a12, 53 /* [.Ldata017] */         # 1073: 020c35
            extui        a0, a0, 1, 3                          # 1076: 000124
            beqz         a0, .Lbr099                           # 1079: 162005
            movi.n       a2, 0 /* 0x00000000 */                # 107c: 0c02
            s8i          a2, a12, 58 /* 0x00 -> [.Ldata022] */ # 107e: 224c3a
            s8i          a2, a12, 60 /* 0x00 -> [.Ldata024] */ # 1081: 224c3c
            movi         a2, .Lrel215 /* .Lstr036 */           # 1084: 21e6ff
            movi         a0, .Lrel224 /* printf */             # 1087: 01eeff
            callx0       a0 /* printf */                       # 108a: c00000
            l32i.n       a3, a1, 0 /* [(local0)] */            # 108d: 3801
            movi.n       a0, 0 /* 0x00000000 */                # 108f: 0c00
            l32i.n       a3, a3, 32 /* [[(local0)]+0x20] */    # 1091: 3883
            movi         a2, .Lrel216 /* .Ldata046 */          # 1093: 21e3ff
            l8ui         a3, a3, 15 /* [[[(local0)]+0x20]+0xf] */ # 1096: 32030f
            l8ui         a8, a12, 61 /* [.Ldata025] */         # 1099: 820c3d
            beqi         a3, 1, .Lbr100                        # 109c: 261338
            movi         a0, .Lrel225 /* sdk_chm_get_current_channel */ # 109f: 01e9ff
            callx0       a0 /* sdk_chm_get_current_channel */  # 10a2: c00000
            l8ui         a4, a12, 61 /* [.Ldata025] */         # 10a5: 420c3d
            l8ui         a6, a12, 53 /* [.Ldata017] */         # 10a8: 620c35
            bnei         a4, 1, .Lbr098                        # 10ab: 661416
            movi         a2, .Lrel217 /* .Lstr006 */           # 10ae: 21ddff
            movi         a3, .Lrel218 /* .Lstr007 */           # 10b1: 31ddff
            movi         a4, 1530 /* 0x000005fa */             # 10b4: 42a5fa
            movi.n       a5, 0 /* 0x00000000 */                # 10b7: 0c05
            s8i          a5, a12, 61 /* 0x00 -> [.Ldata025] */ # 10b9: 524c3d
            movi         a0, .Lrel226 /* printf */             # 10bc: 01e3ff
            callx0       a0 /* printf */                       # 10bf: c00000
.Lbr097:    j            .Lbr097 /* (halt) */                  # 10c2: 06ffff
.Lbr098:    srli         a6, a6, 7                             # 10c5: 606741
            beqz.n       a6, .Lbr103                           # 10c8: bcf6
            movi.n       a7, 2 /* 0x00000002 */                # 10ca: 0c27
            s8i          a7, a12, 61 /* 0x02 -> [.Ldata025] */ # 10cc: 724c3d
.Lbr099:    l32i.n       a12, a1, 8 /* [(local2)] */           # 10cf: c821
            l32i.n       a0, a1, 4 /* [(local1)] */            # 10d1: 0811
            addi         a1, a1, 16 /* (top of frame) */       # 10d3: 12c110
            ret.n                                              # 10d6: 0df0
.Lbr100:    s8i          a0, a2, 0 /* 0x00 -> [.Ldata046] */   # 10d8: 024200
            l8ui         a2, a12, 53 /* [.Ldata017] */         # 10db: 220c35
            movi         a3, 239 /* 0x000000ef */              # 10de: 32a0ef
            and          a2, a2, a3                            # 10e1: 302210
            s8i          a2, a12, 53 /* a2 -> [.Ldata017] */   # 10e4: 224c35
            bnei         a8, 1, .Lbr102                        # 10e7: 661817
            bbci         a2, 5, .Lbr102                        # 10ea: 576214
            movi         a2, .Lrel219 /* .Lstr006 */           # 10ed: 21cfff
            movi         a3, .Lrel220 /* .Lstr007 */           # 10f0: 31d0ff
            movi         a4, 1572 /* 0x00000624 */             # 10f3: 42a624
            s8i          a0, a12, 61 /* 0x00 -> [.Ldata025] */ # 10f6: 024c3d
            movi         a0, .Lrel227 /* printf */             # 10f9: 01d4ff
            callx0       a0 /* printf */                       # 10fc: c00000
.Lbr101:    j            .Lbr101 /* (halt) */                  # 10ff: 06ffff
.Lbr102:    s8i          a0, a12, 61 /* 0x00 -> [.Ldata025] */ # 1102: 024c3d
            call0        .Lfunc014                             # 1105: c5d2ff
            j            .Lbr099                               # 1108: c6f0ff
.Lbr103:    l8ui         a2, a12, 64 /* [.Ldata028] */         # 110b: 220c40
            movi         a3, .Lrel221 /* .Label001 */          # 110e: 31c9ff
            movi         a0, .Lrel228 /* sdk_rc_get_trc */     # 1111: 01cfff
            callx0       a0 /* sdk_rc_get_trc */               # 1114: c00000
            movi         a0, .Lrel222 /* .Ldata046 */          # 1117: 01c8ff
            bnez.n       a2, .Lbr104                           # 111a: cc92
            movi.n       a4, 0 /* 0x00000000 */                # 111c: 0c04
            s8i          a4, a12, 61 /* 0x00 -> [.Ldata025] */ # 111e: 424c3d
            call0        .Lfunc014                             # 1121: 05d1ff
            j            .Lbr099                               # 1124: c6e9ff
.Lbr104:    l8ui         a6, a0, 0 /* [.Ldata046] */           # 1127: 620000
            movi.n       a5, 14 /* 0x0000000e */               # 112a: 0ce5
            addi.n       a2, a6, 1 /* [.Ldata046]+0x1 */       # 112c: 1b26
            bltu         a5, a6, .Lbr105                       # 112e: 67350d
            s8i          a2, a0, 0 /* [.Ldata046]+0x1 -> [.Ldata046] */ # 1131: 224000
            movi.n       a2, 0 /* 0x00000000 */                # 1134: 0c02
            movi         a0, .Lrel229 /* sdk_pm_send_nullfunc */ # 1136: 01c7ff
            callx0       a0 /* sdk_pm_send_nullfunc */         # 1139: c00000
            j            .Lbr099                               # 113c: c6e3ff
.Lbr105:    movi.n       a2, 0 /* 0x00000000 */                # 113f: 0c02
            s8i          a5, a0, 0 /* 0x0e -> [.Ldata046] */   # 1141: 524000
            movi         a0, .Lrel230 /* sdk_pm_send_nullfunc */ # 1144: 01c5ff
            callx0       a0 /* sdk_pm_send_nullfunc */         # 1147: c00000
            j            .Lbr099                               # 114a: 46e0ff

            .balign      4
.Lrel231:   .word        .bss                                  # 1150: 00000000
.Lrel232:   .word        .Lstr037                              # 1154: 44020000
.Llit013:   .word        0x00001e78                            # 1158: 781e0000
.Llit014:   .word        0x00005b68                            # 115c: 685b0000
.Llit015:   .word        0x00001837                            # 1160: 37180000
.Llit016:   .word        0x00002197                            # 1164: 97210000
.Lrel233:   .word        printf                                # 1168: 00000000
.Lrel234:   .word        __udivsi3                             # 116c: 00000000

# Function @ .irom0.text+0x1170
# Local variables/stack:
#     (local0):  word      @ -0x10
#     (local1):  word      @ -0xc
#     (local2):  word      @ -0x8
#     (local3):  word      @ -0x4
.literal_position
.Lfunc018:  mov.n        a3, a2 /* arg0 */                     # 1170: 3d02
            addi         a1, a1, -16 /* (local0) */            # 1172: 12c1f0
            s32i.n       a13, a1, 12 /* a13 -> [(local3)] */   # 1175: d931
            s32i.n       a12, a1, 8 /* a12 -> [(local2)] */    # 1177: c921
            s32i.n       a0, a1, 4 /* a0 -> [(local1)] */      # 1179: 0911
            movi         a12, .Lrel231 /* .Ldata002 */         # 117b: c1f5ff
            movi         a2, .Lrel232 /* .Lstr037 */           # 117e: 21f5ff
            l16ui        a0, a12, 230 /* [.Ldata037] */        # 1181: 021c73
            s32i.n       a3, a1, 0 /* arg0 -> [(local0)] */    # 1184: 3901
            addi.n       a0, a0, 1 /* [.Ldata037]+0x1 */       # 1186: 1b00
            s16i         a0, a12, 230 /* [.Ldata037]+0x1 -> [.Ldata037] */ # 1188: 025c73
            movi         a0, .Lrel233 /* printf */             # 118b: 01f7ff
            callx0       a0 /* printf */                       # 118e: c00000
            l16ui        a13, a12, 230 /* [.Ldata037] */       # 1191: d21c73
            beqz         a13, .Lbr109                          # 1194: 16bd05
            l16ui        a2, a12, 232 /* [.Ldata038] */        # 1197: 221c74
            mov.n        a3, a13 /* [.Ldata037] */             # 119a: 3d0d
            movi         a0, .Lrel234 /* __udivsi3 */          # 119c: 01f4ff
            callx0       a0 /* __udivsi3 */                    # 119f: c00000
            movi.n       a8, 29 /* 0x0000001d */               # 11a2: 1cd8
            extui        a3, a2, 0, 16                         # 11a4: 2030f4
            movi.n       a2, 10 /* 0x0000000a */               # 11a7: 0ca2
            bltu         a2, a3, .Lbr107                       # 11a9: 373221
            l32i         a0, a12, 76 /* [.Ldata030] */         # 11ac: 022c13
            movi         a4, .Llit013 /* 0x00001e78 */         # 11af: 41eaff
            movi         a6, .Llit014 /* 0x00005b68 */         # 11b2: 61eaff
            bltu         a4, a0, .Lbr106                       # 11b5: 073407
            movi         a5, 200 /* 0x000000c8 */              # 11b8: 52a0c8
            add.n        a5, a0, a5 /* [.Ldata030]+0xc8 */     # 11bb: 5a50
            s32i         a5, a12, 76 /* [.Ldata030]+0xc8 -> [.Ldata030] */ # 11bd: 526c13
.Lbr106:    l32i         a0, a12, 80 /* [.Ldata031] */         # 11c0: 022c14
            movi         a7, 600 /* 0x00000258 */              # 11c3: 72a258
            bltu         a6, a0, .Lbr107                       # 11c6: 073604
            add.n        a7, a0, a7 /* [.Ldata031]+0x258 */    # 11c9: 7a70
            s32i         a7, a12, 80 /* [.Ldata031]+0x258 -> [.Ldata031] */ # 11cb: 726c14
.Lbr107:    bgeu         a8, a3, .Lbr109                       # 11ce: 37b821
            l32i         a0, a12, 76 /* [.Ldata030] */         # 11d1: 022c13
            movi         a9, .Llit015 /* 0x00001837 */         # 11d4: 91e3ff
            movi         a11, .Llit016 /* 0x00002197 */        # 11d7: b1e3ff
            bgeu         a9, a0, .Lbr108                       # 11da: 07b907
            movi         a10, -200 /* 0xffffff38 */            # 11dd: a2af38
            add.n        a10, a0, a10 /* [.Ldata030]-0xc8 */   # 11e0: aaa0
            s32i         a10, a12, 76 /* [.Ldata030]-0xc8 -> [.Ldata030] */ # 11e2: a26c13
.Lbr108:    l32i         a0, a12, 80 /* [.Ldata031] */         # 11e5: 022c14
            movi         a2, -600 /* 0xfffffda8 */             # 11e8: 22ada8
            bgeu         a11, a0, .Lbr109                      # 11eb: 07bb04
            add.n        a2, a0, a2 /* [.Ldata031]-0x258 */    # 11ee: 2a20
            s32i         a2, a12, 80 /* [.Ldata031]-0x258 -> [.Ldata031] */ # 11f0: 226c14
.Lbr109:    movi.n       a3, 0 /* 0x00000000 */                # 11f3: 0c03
            s16i         a3, a12, 232 /* 0x0000 -> [.Ldata038] */ # 11f5: 325c74
            bltui        a13, 2, .Lbr110                       # 11f8: b62d09
            l32i.n       a4, a1, 0 /* [(local0)] */            # 11fb: 4801
            beqz.n       a4, .Lbr111                           # 11fd: 8c74
            call0        .Lfunc013                             # 11ff: 855fff
            j            .Lbr111                               # 1202: 860000
.Lbr110:    call0        .Lfunc008                             # 1205: c531ff
.Lbr111:    l32i.n       a12, a1, 8 /* [(local2)] */           # 1208: c821
            l32i.n       a13, a1, 12 /* [(local3)] */          # 120a: d831
            l32i.n       a0, a1, 4 /* [(local1)] */            # 120c: 0811
            addi         a1, a1, 16 /* (top of frame) */       # 120e: 12c110
            ret.n                                              # 1211: 0df0

            .balign      4
.Lrel235:   .word        .Lstr038                              # 1214: 50020000
.Lrel236:   .word        .bss                                  # 1218: 00000000
.Lrel237:   .word        .Lstr006                              # 121c: 58000000
.Lrel238:   .word        .Lstr007                              # 1220: 60000000
.Lrel239:   .word        vTaskSuspendAll                       # 1224: 00000000
.Lrel240:   .word        printf                                # 1228: 00000000
.Lrel241:   .word        printf                                # 122c: 00000000
.Lrel242:   .word        xTaskResumeAll                        # 1230: 00000000

# Function @ .irom0.text+0x1234
# Local variables/stack:
#     (local0):  word[4]   @ -0x10
.literal_position
.Lfunc019:  addi         a1, a1, -16 /* (local0) */            # 1234: 12c1f0
            s32i.n       a0, a1, 0 /* a0 -> [(local0)] */      # 1237: 0901
            movi         a0, .Lrel239 /* vTaskSuspendAll */    # 1239: 01faff
            callx0       a0 /* vTaskSuspendAll */              # 123c: c00000
            movi         a2, .Lrel235 /* .Lstr038 */           # 123f: 21f5ff
            movi         a0, .Lrel240 /* printf */             # 1242: 01f9ff
            callx0       a0 /* printf */                       # 1245: c00000
            movi         a3, .Lrel236 /* .Ldata002 */          # 1248: 31f4ff
            l8ui         a0, a3, 53 /* [.Ldata017] */          # 124b: 020335
            l8ui         a2, a3, 55 /* [.Ldata019] */          # 124e: 220337
            extui        a0, a0, 1, 3                          # 1251: 000124
            bnei         a0, 5, .Lbr112                        # 1254: 665002
            beqi         a2, 8, .Lbr113                        # 1257: 268202
.Lbr112:    bnei         a0, 4, .Lbr117                        # 125a: 664022
.Lbr113:    bnei         a0, 5, .Lbr114                        # 125d: 665005
            l8ui         a4, a3, 55 /* [.Ldata019] */          # 1260: 420337
            beqi         a4, 8, .Lbr116                        # 1263: 268414
.Lbr114:    beqi         a0, 4, .Lbr116                        # 1266: 264011
            movi         a2, .Lrel237 /* .Lstr006 */           # 1269: 21ecff
            movi         a3, .Lrel238 /* .Lstr007 */           # 126c: 31edff
            movi         a4, 1640 /* 0x00000668 */             # 126f: 42a668
            movi         a0, .Lrel241 /* printf */             # 1272: 01eeff
            callx0       a0 /* printf */                       # 1275: c00000
.Lbr115:    j            .Lbr115 /* (halt) */                  # 1278: 06ffff
.Lbr116:    movi.n       a2, 1 /* 0x00000001 */                # 127b: 0c12
            call0        .Lfunc018                             # 127d: 05efff
.Lbr117:    movi         a0, .Lrel242 /* xTaskResumeAll */     # 1280: 01ecff
            callx0       a0 /* xTaskResumeAll */               # 1283: c00000
            l32i.n       a0, a1, 0 /* [(local0)] */            # 1286: 0801
            addi         a1, a1, 16 /* (top of frame) */       # 1288: 12c110
            ret.n                                              # 128b: 0df0

            .balign      4
.Lrel243:   .word        .bss                                  # 1290: 00000000
.Lrel244:   .word        .data                                 # 1294: 00000000
.Lrel245:   .word        .bss                                  # 1298: 00000000
.Lrel246:   .word        .data                                 # 129c: 00000000
.Lrel247:   .word        .Lstr006                              # 12a0: 58000000
.Lrel248:   .word        .Lstr007                              # 12a4: 60000000
.Lrel249:   .word        .Lstr006                              # 12a8: 58000000
.Lrel250:   .word        .Lstr007                              # 12ac: 60000000
.Lrel251:   .word        printf                                # 12b0: 00000000
.Lrel252:   .word        printf                                # 12b4: 00000000

# Function @ .irom0.text+0x12b8
# Local variables/stack:
#     (local0):  word[4]   @ -0x10
.literal_position
.Lfunc020:  movi         a4, 191 /* 0x000000bf */              # 12b8: 42a0bf
            movi         a2, .Lrel243 /* .Ldata002 */          # 12bb: 21f5ff
            addi         a1, a1, -16 /* (local0) */            # 12be: 12c1f0
            s32i.n       a0, a1, 0 /* a0 -> [(local0)] */      # 12c1: 0901
            l8ui         a3, a2, 53 /* [.Ldata017] */          # 12c3: 320235
            movi         a0, .Lrel244 /* .Ldata001 */          # 12c6: 01f3ff
            and          a3, a3, a4                            # 12c9: 403310
            l8ui         a0, a0, 0 /* [.Ldata001] */           # 12cc: 020000
            s8i          a3, a2, 53 /* a3 -> [.Ldata017] */    # 12cf: 324235
            bnei         a0, 2, .Lbr118                        # 12d2: 66200b
            call0        .Lfunc010                             # 12d5: 0541ff
            movi         a0, .Lrel246 /* .Ldata001 */          # 12d8: 01f1ff
            l8ui         a0, a0, 0 /* [.Ldata001] */           # 12db: 020000
            movi         a2, .Lrel245 /* .Ldata002 */          # 12de: 21eeff
.Lbr118:    bnei         a0, 1, .Lbr121                        # 12e1: 66102a
            l8ui         a0, a2, 53 /* [.Ldata017] */          # 12e4: 020235
            extui        a3, a0, 1, 3                          # 12e7: 003124
            beqi         a3, 5, .Lbr120                        # 12ea: 265311
            movi         a2, .Lrel247 /* .Lstr006 */           # 12ed: 21ecff
            movi         a3, .Lrel248 /* .Lstr007 */           # 12f0: 31edff
            movi         a4, 1656 /* 0x00000678 */             # 12f3: 42a678
            movi         a0, .Lrel251 /* printf */             # 12f6: 01eeff
            callx0       a0 /* printf */                       # 12f9: c00000
.Lbr119:    j            .Lbr119 /* (halt) */                  # 12fc: 06ffff
.Lbr120:    bbci         a0, 4, .Lbr121                        # 12ff: 47600c
            l8ui         a4, a2, 58 /* [.Ldata022] */          # 1302: 42023a
            bnez.n       a4, .Lbr122                           # 1305: ccd4
            call0        .Lfunc004                             # 1307: 85f0fe
            beqz.n       a2, .Lbr124                           # 130a: 9ca2
            call0        .Lfunc007                             # 130c: 0518ff
.Lbr121:    l32i.n       a0, a1, 0 /* [(local0)] */            # 130f: 0801
            addi         a1, a1, 16 /* (top of frame) */       # 1311: 12c110
            ret.n                                              # 1314: 0df0
.Lbr122:    movi         a2, .Lrel249 /* .Lstr006 */           # 1316: 21e4ff
            movi         a3, .Lrel250 /* .Lstr007 */           # 1319: 31e4ff
            movi         a4, 1679 /* 0x0000068f */             # 131c: 42a68f
            movi         a0, .Lrel252 /* printf */             # 131f: 01e5ff
            callx0       a0 /* printf */                       # 1322: c00000
.Lbr123:    j            .Lbr123 /* (halt) */                  # 1325: 06ffff
.Lbr124:    call0        .Lfunc008                             # 1328: 851fff
            j            .Lbr121                               # 132b: 06f8ff

            .balign      4
.Lrel253:   .word        .Lstr039                              # 1330: 60020000
.Lrel254:   .word        .Label004                             # 1334: 8c000000
.Lrel255:   .word        printf                                # 1338: 00000000
.Lrel256:   .word        sdk_os_timer_disarm                   # 133c: 00000000
.Lrel257:   .word        sdk_os_timer_arm                      # 1340: 00000000

# Function @ .irom0.text+0x1344
# Local variables/stack:
#     (local0):  word      @ -0x10
#     (local1):  word[3]   @ -0xc
.literal_position
.Lfunc021:  movi         a2, .Lrel253 /* .Lstr039 */           # 1344: 21fbff
            addi         a1, a1, -16 /* (local0) */            # 1347: 12c1f0
            s32i.n       a0, a1, 4 /* a0 -> [(local1)] */      # 134a: 0911
            movi         a0, .Lrel255 /* printf */             # 134c: 01fbff
            callx0       a0 /* printf */                       # 134f: c00000
            movi         a2, .Lrel254 /* .Label004 */          # 1352: 21f8ff
            s32i.n       a2, a1, 0 /* .Label004 -> [(local0)] */ # 1355: 2901
            movi         a0, .Lrel256 /* sdk_os_timer_disarm */ # 1357: 01f9ff
            callx0       a0 /* sdk_os_timer_disarm */          # 135a: c00000
            l32i.n       a2, a1, 0 /* [(local0)] */            # 135d: 2801
            movi.n       a3, 55 /* 0x00000037 */               # 135f: 3c73
            movi.n       a4, 0 /* 0x00000000 */                # 1361: 0c04
            movi         a0, .Lrel257 /* sdk_os_timer_arm */   # 1363: 01f7ff
            callx0       a0 /* sdk_os_timer_arm */             # 1366: c00000
            l32i.n       a0, a1, 4 /* [(local1)] */            # 1369: 0811
            addi         a1, a1, 16 /* (top of frame) */       # 136b: 12c110
            ret.n                                              # 136e: 0df0

.Lrel258:   .word        .bss                                  # 1370: 00000000

# Function @ .irom0.text+0x1374
.literal_position
sdk_pm_enable_gpio_wakeup:
            movi         a3, .Lrel258 /* .Ldata002 */          # 1374: 31ffff
            l8ui         a2, a3, 52 /* [.Ldata016] */          # 1377: 220334
            movi         a4, 223 /* 0x000000df */              # 137a: 42a0df
            and          a2, a2, a4                            # 137d: 402210
            movi.n       a4, 32 /* 0x00000020 */               # 1380: 2c04
            or           a2, a2, a4                            # 1382: 402220
            s8i          a2, a3, 52 /* a2 -> [.Ldata016] */    # 1385: 224334
            ret.n                                              # 1388: 0df0

            .balign      4
.Lrel259:   .word        .bss                                  # 138c: 00000000
.Lrel260:   .word        .Label006                             # 1390: c4000000
.Lrel261:   .word        .Lfunc006                             # 1394: 58040000
.Lrel262:   .word        .bss                                  # 1398: 00000000
.Llit017:   .word        0x000009c4                            # 139c: c4090000
.Llit018:   .word        0x00001770                            # 13a0: 70170000
.Llit019:   .word        0x00004650                            # 13a4: 50460000
.Lrel263:   .word        .Lfunc016                             # 13a8: 240f0000
.Lrel264:   .word        .Lfunc017                             # 13ac: 5c100000
.Lrel265:   .word        .Label002                             # 13b0: 54000000
.Lrel266:   .word        .Lfunc019                             # 13b4: 34120000
.Lrel267:   .word        .Label003                             # 13b8: 70000000
.Lrel268:   .word        .Lfunc020                             # 13bc: b8120000
.Lrel269:   .word        .Label004                             # 13c0: 8c000000
.Lrel270:   .word        .Lfunc021                             # 13c4: 44130000
.Lrel271:   .word        .Label005                             # 13c8: a8000000
.Lrel272:   .word        sdk_pm_idle_sleep                     # 13cc: 00000000
.Lrel273:   .word        .Lfunc023                             # 13d0: 881a0000
.Lrel274:   .word        .Lstr040                              # 13d4: 74020000
.Lrel275:   .word        .Lstr041                              # 13d8: 7c020000
.Lrel276:   .word        .bss                                  # 13dc: 00000000
.Lrel277:   .word        sdk_os_timer_setfn                    # 13e0: 00000000
.Lrel278:   .word        sdk_ppRegisterTxCallback              # 13e4: 00000000
.Lrel279:   .word        sdk_ppRegisterTxCallback              # 13e8: 00000000
.Lrel280:   .word        sdk_os_timer_setfn                    # 13ec: 00000000
.Lrel281:   .word        sdk_os_timer_setfn                    # 13f0: 00000000
.Lrel282:   .word        sdk_os_timer_setfn                    # 13f4: 00000000
.Lrel283:   .word        sdk_os_timer_setfn                    # 13f8: 00000000
.Lrel284:   .word        xTaskGenericCreate                    # 13fc: 00000000
.Lrel285:   .word        printf                                # 1400: 00000000

# Function @ .irom0.text+0x1404
# Local variables/stack:
#     (local0):  word      @ -0x20
#     (local1):  word[3]   @ -0x1c
#     (local2):  word      @ -0x10
#     (local3):  word[3]   @ -0xc
.literal_position
sdk_pm_attach:
            movi         a5, 251 /* 0x000000fb */              # 1404: 52a0fb
            movi         a3, .Lrel259 /* .Ldata002 */          # 1407: 31e1ff
            movi.n       a2, 2 /* 0x00000002 */                # 140a: 0c22
            addi         a1, a1, -32 /* (local0) */            # 140c: 12c1e0
            s32i.n       a0, a1, 20 /* a0 -> [(local3)] */     # 140f: 0951
            s8i          a2, a3, 224 /* 0x02 -> [.Ldata032] */ # 1411: 2243e0
            l8ui         a4, a3, 52 /* [.Ldata016] */          # 1414: 420334
            movi         a2, .Lrel260 /* .Label006 */          # 1417: 21deff
            and          a4, a4, a5                            # 141a: 504410
            movi.n       a5, 4 /* 0x00000004 */                # 141d: 0c45
            or           a4, a4, a5                            # 141f: 504420
            s8i          a4, a3, 52 /* a4 -> [.Ldata016] */    # 1422: 424334
            movi         a5, 254 /* 0x000000fe */              # 1425: 52a0fe
            and          a4, a4, a5                            # 1428: 504410
            s8i          a4, a3, 52 /* a4 -> [.Ldata016] */    # 142b: 424334
            movi         a5, 253 /* 0x000000fd */              # 142e: 52a0fd
            and          a4, a4, a5                            # 1431: 504410
            s8i          a4, a3, 52 /* a4 -> [.Ldata016] */    # 1434: 424334
            movi         a5, 247 /* 0x000000f7 */              # 1437: 52a0f7
            and          a4, a4, a5                            # 143a: 504410
            movi.n       a5, 8 /* 0x00000008 */                # 143d: 0c85
            or           a4, a4, a5                            # 143f: 504420
            s8i          a4, a3, 52 /* a4 -> [.Ldata016] */    # 1442: 424334
            movi         a3, .Lrel261 /* .Lfunc006 */          # 1445: 31d3ff
            movi.n       a4, 0 /* 0x00000000 */                # 1448: 0c04
            movi         a0, .Lrel277 /* sdk_os_timer_setfn */ # 144a: 01e5ff
            callx0       a0 /* sdk_os_timer_setfn */           # 144d: c00000
            movi         a0, 223 /* 0x000000df */              # 1450: 02a0df
            movi.n       a3, 0 /* 0x00000000 */                # 1453: 0c03
            movi.n       a6, 1 /* 0x00000001 */                # 1455: 0c16
            movi         a8, .Llit019 /* 0x00004650 */         # 1457: 81d3ff
            movi         a9, .Llit018 /* 0x00001770 */         # 145a: 91d1ff
            movi         a10, .Llit017 /* 0x000009c4 */        # 145d: a1cfff
            movi         a7, .Lrel262 /* .Ldata002 */          # 1460: 71ceff
            movi.n       a4, 2 /* 0x00000002 */                # 1463: 0c24
            s8i          a4, a7, 226 /* 0x02 -> [.Ldata034] */ # 1465: 4247e2
            s16i         a10, a7, 44 /* 0x09c4 -> [.Ldata012] */ # 1468: a25716
            s32i         a9, a7, 76 /* 0x00001770 -> [.Ldata030] */ # 146b: 926713
            s32i         a8, a7, 80 /* 0x00004650 -> [.Ldata031] */ # 146e: 826714
            s8i          a6, a7, 228 /* 0x01 -> [.Ldata036] */ # 1471: 6247e4
            s8i          a3, a7, 225 /* 0x00 -> [.Ldata033] */ # 1474: 3247e1
            s8i          a3, a7, 227 /* 0x00 -> [.Ldata035] */ # 1477: 3247e3
            s8i          a3, a7, 54 /* 0x00 -> [.Ldata018] */  # 147a: 324736
            l8ui         a2, a7, 52 /* [.Ldata016] */          # 147d: 220734
            l8ui         a11, a7, 53 /* [.Ldata017] */         # 1480: b20735
            and          a2, a2, a0                            # 1483: 002210
            and          a11, a11, a0                          # 1486: 00bb10
            s8i          a11, a7, 53 /* a11 -> [.Ldata017] */  # 1489: b24735
            s8i          a2, a7, 52 /* a2 -> [.Ldata016] */    # 148c: 224734
            movi.n       a3, 5 /* 0x00000005 */                # 148f: 0c53
            movi         a2, .Lrel263 /* .Lfunc016 */          # 1491: 21c5ff
            movi         a0, .Lrel278 /* sdk_ppRegisterTxCallback */ # 1494: 01d4ff
            callx0       a0 /* sdk_ppRegisterTxCallback */     # 1497: c00000
            movi         a2, .Lrel264 /* .Lfunc017 */          # 149a: 21c4ff
            movi.n       a3, 6 /* 0x00000006 */                # 149d: 0c63
            movi         a0, .Lrel279 /* sdk_ppRegisterTxCallback */ # 149f: 01d2ff
            callx0       a0 /* sdk_ppRegisterTxCallback */     # 14a2: c00000
            movi         a2, .Lrel265 /* .Label002 */          # 14a5: 21c2ff
            movi         a3, .Lrel266 /* .Lfunc019 */          # 14a8: 31c3ff
            movi.n       a4, 0 /* 0x00000000 */                # 14ab: 0c04
            movi         a0, .Lrel280 /* sdk_os_timer_setfn */ # 14ad: 01cfff
            callx0       a0 /* sdk_os_timer_setfn */           # 14b0: c00000
            movi         a2, .Lrel267 /* .Label003 */          # 14b3: 21c1ff
            movi         a3, .Lrel268 /* .Lfunc020 */          # 14b6: 31c1ff
            movi.n       a4, 0 /* 0x00000000 */                # 14b9: 0c04
            movi         a0, .Lrel281 /* sdk_os_timer_setfn */ # 14bb: 01cdff
            callx0       a0 /* sdk_os_timer_setfn */           # 14be: c00000
            movi         a2, .Lrel269 /* .Label004 */          # 14c1: 21bfff
            movi         a3, .Lrel270 /* .Lfunc021 */          # 14c4: 31c0ff
            movi.n       a4, 0 /* 0x00000000 */                # 14c7: 0c04
            movi         a0, .Lrel282 /* sdk_os_timer_setfn */ # 14c9: 01caff
            callx0       a0 /* sdk_os_timer_setfn */           # 14cc: c00000
            movi         a2, .Lrel271 /* .Label005 */          # 14cf: 21beff
            movi         a3, .Lrel272 /* sdk_pm_idle_sleep */  # 14d2: 31beff
            movi.n       a4, 0 /* 0x00000000 */                # 14d5: 0c04
            movi         a0, .Lrel283 /* sdk_os_timer_setfn */ # 14d7: 01c8ff
            callx0       a0 /* sdk_os_timer_setfn */           # 14da: c00000
            movi         a2, .Lrel273 /* .Lfunc023 */          # 14dd: 21bcff
            movi         a3, .Lrel274 /* .Lstr040 */           # 14e0: 31bdff
            movi         a4, 176 /* 0x000000b0 */              # 14e3: 42a0b0
            movi.n       a6, 1 /* 0x00000001 */                # 14e6: 0c16
            addi         a7, a1, 16 /* (local2) */             # 14e8: 72c110
            movi.n       a5, 0 /* 0x00000000 */                # 14eb: 0c05
            s32i.n       a5, a1, 0 /* 0x00000000 -> [(local0)] */ # 14ed: 5901
            s32i.n       a5, a1, 4 /* 0x00000000 -> [(local1)] */ # 14ef: 5911
            movi.n       a5, 0 /* 0x00000000 */                # 14f1: 0c05
            movi         a0, .Lrel284 /* xTaskGenericCreate */ # 14f3: 01c2ff
            callx0       a0 /* xTaskGenericCreate */           # 14f6: c00000
            movi         a2, .Lrel275 /* .Lstr041 */           # 14f9: 21b7ff
            l32i.n       a3, a1, 16 /* [(local2)] */           # 14fc: 3841
            movi.n       a4, 1 /* 0x00000001 */                # 14fe: 0c14
            movi         a5, 176 /* 0x000000b0 */              # 1500: 52a0b0
            movi         a0, .Lrel285 /* printf */             # 1503: 01bfff
            callx0       a0 /* printf */                       # 1506: c00000
            movi         a7, .Lrel276 /* .Ldata002 */          # 1509: 71b4ff
            movi.n       a6, 1 /* 0x00000001 */                # 150c: 0c16
            s8i          a6, a7, 57 /* 0x01 -> [.Ldata021] */  # 150e: 624739
            call0        sdk_pm_reset_idle_sleep               # 1511: 050000
            l32i.n       a0, a1, 20 /* [(local3)] */           # 1514: 0851
            addi         a1, a1, 32 /* (top of frame) */       # 1516: 12c120
            ret.n                                              # 1519: 0df0

            .balign      4
.Lrel286:   .word        .bss                                  # 151c: 00000000
.Lrel287:   .word        .Lstr043                              # 1520: bc020000
.Lrel288:   .word        .Label004                             # 1524: 8c000000
.Lrel289:   .word        .Lstr006                              # 1528: 58000000
.Lrel290:   .word        .Lstr007                              # 152c: 60000000
.Llit020:   .word        0xff000fff                            # 1530: ff0f00ff
.Llit021:   .word        0x00018000                            # 1534: 00800100
.Lrel291:   .word        sdk_g_ic                              # 1538: 00000000
.Lrel292:   .word        .Label001                             # 153c: 41000000
.Llit022:   .word        0x3ff20a00                            # 1540: 000af23f
.Llit023:   .word        0x03fffff7                            # 1544: f7ffff03
.Lrel293:   .word        .bss                                  # 1548: 00000000
.Lrel294:   .word        .Lstr042                              # 154c: a4020000
.Lrel295:   .word        printf                                # 1550: 00000000
.Lrel296:   .word        sdk_os_timer_disarm                   # 1554: 00000000
.Lrel297:   .word        sdk_os_timer_arm                      # 1558: 00000000
.Lrel298:   .word        sdk_ppTxPkt                           # 155c: 00000000
.Lrel299:   .word        sdk_ieee80211_getmgtframe             # 1560: 00000000
.Lrel300:   .word        printf                                # 1564: 00000000
.Lrel301:   .word        bzero                                 # 1568: 00000000
.Lrel302:   .word        sdk_ic_get_addr                       # 156c: 00000000
.Lrel303:   .word        sdk_ieee80211_send_setup              # 1570: 00000000
.Lrel304:   .word        printf                                # 1574: 00000000

# Function @ .irom0.text+0x1578
# Local variables/stack:
#     (local0):  word[4]   @ -0x30
#     (local1):  word      @ -0x20
#     (local2):  word      @ -0x1c
#     (local3):  word      @ -0x18
#     (local4):  word      @ -0x14
#     (local5):  word      @ -0x10
#     (local6):  word      @ -0xc
#     (local7):  word[2]   @ -0x8
.literal_position
sdk_pm_send_nullfunc:
            movi.n       a5, 2 /* 0x00000002 */                # 1578: 0c25
            addi         a1, a1, -48 /* (local0) */            # 157a: 12c1d0
            movi         a3, .Lrel286 /* .Ldata002 */          # 157d: 31e7ff
            s32i.n       a0, a1, 40 /* a0 -> [(local7)] */     # 1580: 09a1
            movi.n       a0, 0 /* 0x00000000 */                # 1582: 0c00
            l8ui         a4, a3, 59 /* [.Ldata023] */          # 1584: 42033b
            s32i.n       a0, a1, 16 /* 0x00000000 -> [(local1)] */ # 1587: 0941
            bnez.n       a4, .Lbr126                           # 1589: dc74
            l8ui         a6, a3, 60 /* [.Ldata024] */          # 158b: 62033c
            beqz.n       a6, .Lbr125                           # 158e: 8c56
            mov.n        a5, a2 /* arg0 */                     # 1590: 5d02
            movi.n       a0, 1 /* 0x00000001 */                # 1592: 0c10
            j            .Lbr126                               # 1594: 060300
.Lbr125:    l8ui         a7, a3, 53 /* [.Ldata017] */          # 1597: 720335
            movi.n       a6, 1 /* 0x00000001 */                # 159a: 0c16
            srli         a7, a7, 7                             # 159c: 707741
            beqz         a7, .Lbr130                           # 159f: 162704
            mov.n        a0, a6 /* 0x00000001 */               # 15a2: 0d06
.Lbr126:    movnez       a5, a0, a2                            # 15a4: 205093
            s8i          a5, a3, 61 /* a5 -> [.Ldata025] */    # 15a7: 52433d
            j            .Lbr129                               # 15aa: 060c00
.Lbr127:    l32i.n       a9, a1, 32 /* [(local5)] */           # 15ad: 9881
            movi         a2, .Lrel287 /* .Lstr043 */           # 15af: 21dcff
            l32i.n       a9, a9, 32 /* [[(local5)]+0x20] */    # 15b2: 9889
            movi.n       a8, 64 /* 0x00000040 */               # 15b4: 4c08
            s8i          a8, a9, 14 /* 0x40 -> [[[(local5)]+0x20]+0xe] */ # 15b6: 82490e
            movi         a0, .Lrel295 /* printf */             # 15b9: 01e5ff
            callx0       a0 /* printf */                       # 15bc: c00000
.Lbr128:    movi         a2, .Lrel288 /* .Label004 */          # 15bf: 21d9ff
            s32i.n       a2, a1, 20 /* .Label004 -> [(local2)] */ # 15c2: 2951
            movi         a0, .Lrel296 /* sdk_os_timer_disarm */ # 15c4: 01e4ff
            callx0       a0 /* sdk_os_timer_disarm */          # 15c7: c00000
            l32i.n       a2, a1, 20 /* [(local2)] */           # 15ca: 2851
            movi.n       a3, 55 /* 0x00000037 */               # 15cc: 3c73
            movi.n       a4, 0 /* 0x00000000 */                # 15ce: 0c04
            movi         a0, .Lrel297 /* sdk_os_timer_arm */   # 15d0: 01e2ff
            callx0       a0 /* sdk_os_timer_arm */             # 15d3: c00000
            l32i.n       a2, a1, 32 /* [(local5)] */           # 15d6: 2881
            movi         a0, .Lrel298 /* sdk_ppTxPkt */        # 15d8: 01e1ff
            callx0       a0 /* sdk_ppTxPkt */                  # 15db: c00000
.Lbr129:    l32i.n       a0, a1, 40 /* [(local7)] */           # 15de: 08a1
            addi         a1, a1, 48 /* (top of frame) */       # 15e0: 12c130
            ret.n                                              # 15e3: 0df0
.Lbr130:    s32i.n       a2, a1, 36 /* arg0 -> [(local6)] */   # 15e5: 2991
            s8i          a6, a3, 58 /* 0x01 -> [.Ldata022] */  # 15e7: 62433a
            s32i.n       a0, a1, 28 /* 0x00000000 -> [(local4)] */ # 15ea: 0971
            bnez.n       a2, .Lbr131                           # 15ec: cc42
            s8i          a6, a3, 60 /* 0x01 -> [.Ldata024] */  # 15ee: 62433c
            j            .Lbr132                               # 15f1: 860000
.Lbr131:    s8i          a6, a3, 59 /* 0x01 -> [.Ldata023] */  # 15f4: 62433b
.Lbr132:    addi         a2, a1, 16 /* (local1) */             # 15f7: 22c110
            movi.n       a3, 24 /* 0x00000018 */               # 15fa: 1c83
            movi.n       a4, 0 /* 0x00000000 */                # 15fc: 0c04
            movi         a0, .Lrel299 /* sdk_ieee80211_getmgtframe */ # 15fe: 01d8ff
            callx0       a0 /* sdk_ieee80211_getmgtframe */    # 1601: c00000
            s32i.n       a2, a1, 32 /* a2 -> [(local5)] */     # 1604: 2981
            bnez.n       a2, .Lbr134                           # 1606: dc02
            movi         a2, .Lrel289 /* .Lstr006 */           # 1608: 21c8ff
            movi         a3, .Lrel290 /* .Lstr007 */           # 160b: 31c8ff
            movi         a4, 1818 /* 0x0000071a */             # 160e: 42a71a
            movi         a0, .Lrel300 /* printf */             # 1611: 01d4ff
            callx0       a0 /* printf */                       # 1614: c00000
.Lbr133:    j            .Lbr133 /* (halt) */                  # 1617: 06ffff
.Lbr134:    l32i.n       a2, a2, 4                             # 161a: 2812
            movi.n       a3, 24 /* 0x00000018 */               # 161c: 1c83
            l32i.n       a2, a2, 4                             # 161e: 2812
            s32i.n       a2, a1, 24 /* a2 -> [(local3)] */     # 1620: 2961
            movi         a0, .Lrel301 /* bzero */              # 1622: 01d1ff
            callx0       a0 /* bzero */                        # 1625: c00000
            movi.n       a5, 24 /* 0x00000018 */               # 1628: 1c85
            l32i.n       a4, a1, 32 /* [(local5)] */           # 162a: 4881
            l32i.n       a6, a1, 28 /* [(local4)] */           # 162c: 6871
            s16i         a6, a4, 22 /* [(local4)] -> [[(local5)]+0x16] */ # 162e: 62540b
            s16i         a5, a4, 20 /* 0x0018 -> [[(local5)]+0x14] */ # 1631: 52540a
            movi.n       a9, 64 /* 0x00000040 */               # 1634: 4c09
            movi         a0, 128 /* 0x00000080 */              # 1636: 02a080
            l32i.n       a4, a4, 4 /* [[(local5)]+0x4] */      # 1639: 4814
            memw                                               # 163b: c02000
            l8ui         a11, a4, 3 /* [[[(local5)]+0x4]+0x3] */ # 163e: b20403
            extui        a11, a11, 0, 7                        # 1641: b0b064
            or           a11, a11, a0                          # 1644: 00bb20
            memw                                               # 1647: c02000
            s8i          a11, a4, 3 /* a11 -> [[[(local5)]+0x4]+0x3] */ # 164a: b24403
            movi         a10, 191 /* 0x000000bf */             # 164d: a2a0bf
            memw                                               # 1650: c02000
            l8ui         a8, a4, 3 /* [[[(local5)]+0x4]+0x3] */ # 1653: 820403
            and          a8, a8, a10                           # 1656: a08810
            or           a8, a8, a9                            # 1659: 908820
            memw                                               # 165c: c02000
            s8i          a8, a4, 3 /* a8 -> [[[(local5)]+0x4]+0x3] */ # 165f: 824403
            movi         a7, 223 /* 0x000000df */              # 1662: 72a0df
            memw                                               # 1665: c02000
            l8ui         a5, a4, 3 /* [[[(local5)]+0x4]+0x3] */ # 1668: 520403
            and          a5, a5, a7                            # 166b: 705510
            or           a5, a5, a6                            # 166e: 605520
            memw                                               # 1671: c02000
            s8i          a5, a4, 3 /* a5 -> [[[(local5)]+0x4]+0x3] */ # 1674: 524403
            movi         a6, .Llit020 /* 0xff000fff */         # 1677: 61aeff
            movi         a5, .Llit021 /* 0x00018000 */         # 167a: 51aeff
            memw                                               # 167d: c02000
            l16ui        a3, a4, 2 /* [[[(local5)]+0x4]+0x2] */ # 1680: 321401
            slli         a3, a3, 16                            # 1683: 003311
            memw                                               # 1686: c02000
            l16ui        a7, a4, 0 /* [[[(local5)]+0x4]] */    # 1689: 721400
            or           a3, a3, a7                            # 168c: 703320
            and          a3, a3, a6                            # 168f: 603310
            or           a3, a3, a5                            # 1692: 503320
            memw                                               # 1695: c02000
            s16i         a3, a4, 0 /* a3 -> [[[(local5)]+0x4]] */ # 1698: 325400
            extui        a3, a3, 16, 16                        # 169b: 3030f5
            memw                                               # 169e: c02000
            s16i         a3, a4, 2 /* a3 -> [[[(local5)]+0x4]+0x2] */ # 16a1: 325401
            movi.n       a2, 0 /* 0x00000000 */                # 16a4: 0c02
            movi         a0, .Lrel302 /* sdk_ic_get_addr */    # 16a6: 01b1ff
            callx0       a0 /* sdk_ic_get_addr */              # 16a9: c00000
            l32i.n       a3, a1, 32 /* [(local5)] */           # 16ac: 3881
            movi.n       a4, 72 /* 0x00000048 */               # 16ae: 4c84
            movi.n       a5, 0 /* 0x00000000 */                # 16b0: 0c05
            mov.n        a6, a2                                # 16b2: 6d02
            movi         a8, .Lrel292 /* .Label001 */          # 16b4: 81a2ff
            movi         a2, .Lrel291 /* sdk_g_ic */           # 16b7: 21a0ff
            mov.n        a7, a8 /* .Label001 */                # 16ba: 7d08
            l32i.n       a2, a2, 16 /* [sdk_g_ic+0x10] */      # 16bc: 2842
            s32i.n       a8, a1, 0 /* .Label001 -> [(local0)] */ # 16be: 8901
            movi         a0, .Lrel303 /* sdk_ieee80211_send_setup */ # 16c0: 01acff
            callx0       a0 /* sdk_ieee80211_send_setup */     # 16c3: c00000
            l32i.n       a5, a1, 32 /* [(local5)] */           # 16c6: 5881
            movi         a6, .Llit022 /* 0x3ff20a00 */         # 16c8: 619eff
            l32i.n       a7, a5, 32 /* [[(local5)]+0x20] */    # 16cb: 7885
            memw                                               # 16cd: c02000
            movi.n       a3, 6 /* 0x00000006 */                # 16d0: 0c63
            movi         a4, 240 /* 0x000000f0 */              # 16d2: 42a0f0
            movi         a9, 143 /* 0x0000008f */              # 16d5: 92a08f
            l8ui         a8, a7, 6 /* [[[(local5)]+0x20]+0x6] */ # 16d8: 820706
            l32i         a6, a6, 0x200 /* [0x3ff20c00] */      # 16db: 622680
            and          a8, a8, a9                            # 16de: 908810
            movi         a9, 253 /* 0x000000fd */              # 16e1: 92a0fd
            s8i          a8, a7, 6 /* a8 -> [[[(local5)]+0x20]+0x6] */ # 16e4: 824706
            l32i.n       a2, a5, 32 /* [[(local5)]+0x20] */    # 16e7: 2885
            s32i.n       a6, a7, 16 /* [0x3ff20c00] -> [[[(local5)]+0x20]+0x10] */ # 16e9: 6947
            l8ui         a0, a2, 4 /* [[[(local5)]+0x20]+0x4] */ # 16eb: 020204
            movi         a8, .Lrel293 /* .Ldata002 */          # 16ee: 8196ff
            and          a0, a0, a4                            # 16f1: 400010
            l32i.n       a4, a1, 28 /* [(local4)] */           # 16f4: 4871
            or           a0, a0, a3                            # 16f6: 300020
            s8i          a0, a2, 4 /* a0 -> [[[(local5)]+0x20]+0x4] */ # 16f9: 024204
            l32i.n       a7, a5, 32 /* [[(local5)]+0x20] */    # 16fc: 7885
            l32i.n       a3, a1, 36 /* [(local6)] */           # 16fe: 3891
            l32i.n       a11, a7, 0 /* [[[(local5)]+0x20]] */  # 1700: b807
            movi         a0, .Llit023 /* 0x03fffff7 */         # 1702: 0190ff
            extui        a10, a11, 0, 6                        # 1705: b0a054
            srli         a11, a11, 6                           # 1708: b0b641
            and          a11, a11, a0                          # 170b: 00bb10
            slli         a11, a11, 6                           # 170e: a0bb11
            or           a10, a10, a11                         # 1711: b0aa20
            s32i.n       a10, a7, 0 /* a10 -> [[[(local5)]+0x20]] */ # 1714: a907
            l8ui         a6, a7, 0 /* [[[(local5)]+0x20]] */   # 1716: 620700
            l8ui         a8, a8, 64 /* [.Ldata028] */          # 1719: 820840
            and          a6, a6, a9                            # 171c: 906610
            extui        a8, a8, 0, 1                          # 171f: 808004
            slli         a8, a8, 1                             # 1722: f08811
            or           a6, a6, a8                            # 1725: 806620
            s8i          a6, a7, 0 /* a6 -> [[[(local5)]+0x20]] */ # 1728: 624700
            s32i.n       a4, a5, 24 /* [(local4)] -> [[(local5)]+0x18] */ # 172b: 4965
            beqz         a3, .Lbr127                           # 172d: 16c3e7
            movi         a2, .Lrel294 /* .Lstr042 */           # 1730: 2187ff
            l32i.n       a10, a1, 24 /* [(local3)] */          # 1733: a861
            l32i.n       a8, a1, 32 /* [(local5)] */           # 1735: 8881
            l8ui         a9, a10, 1 /* [[(local3)]+0x1] */     # 1737: 920a01
            movi.n       a11, 16 /* 0x00000010 */              # 173a: 1c0b
            or           a9, a9, a11                           # 173c: b09920
            s8i          a9, a10, 1 /* a9 -> [[(local3)]+0x1] */ # 173f: 924a01
            l32i.n       a8, a8, 32 /* [[(local5)]+0x20] */    # 1742: 8888
            movi.n       a7, 32 /* 0x00000020 */               # 1744: 2c07
            s8i          a7, a8, 14 /* 0x20 -> [[[(local5)]+0x20]+0xe] */ # 1746: 72480e
            movi         a0, .Lrel304 /* printf */             # 1749: 018aff
            callx0       a0 /* printf */                       # 174c: c00000
            j            .Lbr128                               # 174f: 069bff

            .balign      4
.Lrel305:   .word        .bss                                  # 1754: 00000000

# Function @ .irom0.text+0x1758
.literal_position
sdk_pm_is_waked:
            movi         a4, .Lrel305 /* .Ldata002 */          # 1758: 41ffff
            l8ui         a4, a4, 53 /* [.Ldata017] */          # 175b: 420435
            movi.n       a2, 0 /* 0x00000000 */                # 175e: 0c02
            extui        a3, a4, 1, 3                          # 1760: 403124
            bnei         a3, 7, .Lbr135                        # 1763: 667304
            bbci         a4, 5, .Lbr135                        # 1766: 576401
            movi.n       a2, 1 /* 0x00000001 */                # 1769: 0c12
.Lbr135:    extui        a2, a2, 0, 8                          # 176b: 202074
            ret.n                                              # 176e: 0df0

.Lrel306:   .word        .bss                                  # 1770: 00000000

# Function @ .irom0.text+0x1774
.literal_position
sdk_pm_is_open:
            movi         a4, .Lrel306 /* .Ldata002 */          # 1774: 41ffff
            movi.n       a3, 1 /* 0x00000001 */                # 1777: 0c13
            l8ui         a4, a4, 53 /* [.Ldata017] */          # 1779: 420435
            movi.n       a2, 0 /* 0x00000000 */                # 177c: 0c02
            extui        a4, a4, 5, 1                          # 177e: 404504
            addi.n       a4, a4, -1                            # 1781: 0b44
            moveqz       a2, a3, a4                            # 1783: 402383
            ret.n                                              # 1786: 0df0

.Lrel307:   .word        .Label011                             # 1788: d4020000
.Lrel308:   .word        .bss                                  # 178c: 00000000
.Lrel309:   .word        printf                                # 1790: 00000000
.Lrel310:   .word        sdk_pp_disable_idle_timer             # 1794: 00000000

# Function @ .irom0.text+0x1798
# Local variables/stack:
#     (local0):  word[4]   @ -0x10
.literal_position
sdk_pm_scan_lock:
            movi         a2, .Lrel307 /* .Label011 */          # 1798: 21fcff
            addi         a1, a1, -16 /* (local0) */            # 179b: 12c1f0
            s32i.n       a0, a1, 0 /* a0 -> [(local0)] */      # 179e: 0901
            movi         a0, .Lrel309 /* printf */             # 17a0: 01fcff
            callx0       a0 /* printf */                       # 17a3: c00000
            movi         a2, .Lrel308 /* .Ldata002 */          # 17a6: 21f9ff
            l8ui         a0, a2, 53 /* [.Ldata017] */          # 17a9: 020235
            movi         a3, 128 /* 0x00000080 */              # 17ac: 32a080
            extui        a0, a0, 0, 7                          # 17af: 000064
            or           a0, a0, a3                            # 17b2: 300020
            s8i          a0, a2, 53 /* a0 -> [.Ldata017] */    # 17b5: 024235
            movi         a0, .Lrel310 /* sdk_pp_disable_idle_timer */ # 17b8: 01f7ff
            callx0       a0 /* sdk_pp_disable_idle_timer */    # 17bb: c00000
            l32i.n       a0, a1, 0 /* [(local0)] */            # 17be: 0801
            addi         a1, a1, 16 /* (top of frame) */       # 17c0: 12c110
            ret.n                                              # 17c3: 0df0

            .balign      4
# Function @ .irom0.text+0x17c8
# Local variables/stack:
#     (local0):  word[4]   @ -0x10
.literal_position
sdk_pm_try_scan_unlock:
            movi.n       a2, 0 /* 0x00000000 */                # 17c8: 0c02
            addi         a1, a1, -16 /* (local0) */            # 17ca: 12c1f0
            s32i.n       a0, a1, 0 /* a0 -> [(local0)] */      # 17cd: 0901
            call0        .Lfunc022                             # 17cf: 450600
            l32i.n       a0, a1, 0 /* [(local0)] */            # 17d2: 0801
            addi         a1, a1, 16 /* (top of frame) */       # 17d4: 12c110
            ret.n                                              # 17d7: 0df0

            .balign      4
.Lrel311:   .word        .Lstr044                              # 17dc: d8020000
.Lrel312:   .word        printf                                # 17e0: 00000000
.Lrel313:   .word        .Lfunc022                             # 17e4: 34180000

# Function @ .irom0.text+0x17e8
# Local variables/stack:
#     (local0):  word[4]   @ -0x10
.literal_position
sdk_pm_force_scan_unlock:
            movi         a2, .Lrel311 /* .Lstr044 */           # 17e8: 21fdff
            addi         a1, a1, -16 /* (local0) */            # 17eb: 12c1f0
            s32i.n       a0, a1, 0 /* a0 -> [(local0)] */      # 17ee: 0901
            movi         a0, .Lrel312 /* printf */             # 17f0: 01fcff
            callx0       a0 /* printf */                       # 17f3: c00000
            movi.n       a2, 0 /* 0x00000000 */                # 17f6: 0c02
            movi         a0, .Lrel313 /* .Lfunc022 */          # 17f8: 01fbff
            callx0       a0 /* .Lfunc022 */                    # 17fb: c00000
            l32i.n       a0, a1, 0 /* [(local0)] */            # 17fe: 0801
            addi         a1, a1, 16 /* (top of frame) */       # 1800: 12c110
            ret.n                                              # 1803: 0df0

            .balign      4
.Lrel314:   .word        .bss                                  # 1808: 00000000
.Lrel315:   .word        .Lstr045                              # 180c: e0020000
.Lrel316:   .word        .Lstr006                              # 1810: 58000000
.Lrel317:   .word        .Lstr007                              # 1814: 60000000
.Lrel318:   .word        .Lstr006                              # 1818: 58000000
.Lrel319:   .word        .Lstr007                              # 181c: 60000000
.Lrel320:   .word        printf                                # 1820: 00000000
.Lrel321:   .word        printf                                # 1824: 00000000
.Lrel322:   .word        sdk_pp_disable_idle_timer             # 1828: 00000000
.Lrel323:   .word        sdk_pp_enable_idle_timer              # 182c: 00000000
.Lrel324:   .word        printf                                # 1830: 00000000

# Function @ .irom0.text+0x1834
# Local variables/stack:
#     (local0):  word      @ -0x10
#     (local1):  word[3]   @ -0xc
.literal_position
.Lfunc022:  addi         a1, a1, -16 /* (local0) */            # 1834: 12c1f0
            movi         a2, .Lrel315 /* .Lstr045 */           # 1837: 21f5ff
            s32i.n       a12, a1, 4 /* a12 -> [(local1)] */    # 183a: c911
            movi         a12, .Lrel314 /* .Ldata002 */         # 183c: c1f3ff
            s32i.n       a0, a1, 0 /* a0 -> [(local0)] */      # 183f: 0901
            l8ui         a3, a12, 53 /* [.Ldata017] */         # 1841: 320c35
            l8ui         a4, a12, 61 /* [.Ldata025] */         # 1844: 420c3d
            extui        a3, a3, 1, 3                          # 1847: 303124
            movi         a0, .Lrel320 /* printf */             # 184a: 01f5ff
            callx0       a0 /* printf */                       # 184d: c00000
            l8ui         a0, a12, 53 /* [.Ldata017] */         # 1850: 020c35
            l8ui         a5, a12, 58 /* [.Ldata022] */         # 1853: 520c3a
            extui        a4, a0, 0, 7                          # 1856: 004064
            s8i          a4, a12, 53 /* a4 -> [.Ldata017] */   # 1859: 424c35
            bbci         a4, 5, .Lbr138                        # 185c: 576435
            bnez.n       a5, .Lbr138                           # 185f: fc25
            l8ui         a4, a12, 61 /* [.Ldata025] */         # 1861: 420c3d
            movi.n       a2, 0 /* 0x00000000 */                # 1864: 0c02
            bnei         a4, 1, .Lbr139                        # 1866: 661434
            s8i          a2, a12, 61 /* 0x00 -> [.Ldata025] */ # 1869: 224c3d
            extui        a6, a0, 1, 3                          # 186c: 006124
            beqi         a6, 1, .Lbr142                        # 186f: 26164f
            movi         a2, .Lrel316 /* .Lstr006 */           # 1872: 21e7ff
            movi         a3, .Lrel317 /* .Lstr007 */           # 1875: 31e7ff
            movi         a4, 1923 /* 0x00000783 */             # 1878: 42a783
            movi         a0, .Lrel321 /* printf */             # 187b: 01eaff
            callx0       a0 /* printf */                       # 187e: c00000
.Lbr136:    j            .Lbr136 /* (halt) */                  # 1881: 06ffff
.Lbr137:    call0        sdk_pm_is_waked                       # 1884: 050000
            beqz.n       a2, .Lbr138                           # 1887: 8ca2
            movi         a0, .Lrel322 /* sdk_pp_disable_idle_timer */ # 1889: 01e7ff
            callx0       a0 /* sdk_pp_disable_idle_timer */    # 188c: c00000
            movi         a0, .Lrel323 /* sdk_pp_enable_idle_timer */ # 188f: 01e7ff
            callx0       a0 /* sdk_pp_enable_idle_timer */     # 1892: c00000
.Lbr138:    l32i.n       a12, a1, 4 /* [(local1)] */           # 1895: c811
            l32i.n       a0, a1, 0 /* [(local0)] */            # 1897: 0801
            addi         a1, a1, 16 /* (top of frame) */       # 1899: 12c110
            ret.n                                              # 189c: 0df0
.Lbr139:    bnei         a4, 2, .Lbr137                        # 189e: 6624e2
            s8i          a2, a12, 61 /* 0x00 -> [.Ldata025] */ # 18a1: 224c3d
            extui        a7, a0, 1, 3                          # 18a4: 007124
            beqi         a7, 6, .Lbr141                        # 18a7: 266711
            movi         a2, .Lrel318 /* .Lstr006 */           # 18aa: 21dbff
            movi         a3, .Lrel319 /* .Lstr007 */           # 18ad: 31dbff
            movi         a4, 1930 /* 0x0000078a */             # 18b0: 42a78a
            movi         a0, .Lrel324 /* printf */             # 18b3: 01dfff
            callx0       a0 /* printf */                       # 18b6: c00000
.Lbr140:    j            .Lbr140 /* (halt) */                  # 18b9: 06ffff
.Lbr141:    call0        sdk_pm_send_nullfunc                  # 18bc: 050000
            j            .Lbr138                               # 18bf: 86f4ff
.Lbr142:    movi.n       a2, 1 /* 0x00000001 */                # 18c2: 0c12
            call0        sdk_pm_send_nullfunc                  # 18c4: 050000
            j            .Lbr138                               # 18c7: 86f2ff

            .balign      4
.Lrel325:   .word        .bss                                  # 18cc: 00000000

# Function @ .irom0.text+0x18d0
.literal_position
sdk_pm_scan_unlocked:
            movi         a4, .Lrel325 /* .Ldata002 */          # 18d0: 41ffff
            movi.n       a3, 1 /* 0x00000001 */                # 18d3: 0c13
            l8ui         a4, a4, 53 /* [.Ldata017] */          # 18d5: 420435
            movi.n       a2, 0 /* 0x00000000 */                # 18d8: 0c02
            srli         a4, a4, 7                             # 18da: 404741
            moveqz       a2, a3, a4                            # 18dd: 402383
            ret.n                                              # 18e0: 0df0

            .balign      4
.Lrel326:   .word        .bss                                  # 18e4: 00000000

# Function @ .irom0.text+0x18e8
.literal_position
sdk_pm_allow_tx:
            movi         a6, .Lrel326 /* .Ldata002 */          # 18e8: 61ffff
            l8ui         a4, a6, 53 /* [.Ldata017] */          # 18eb: 420635
            movi.n       a5, 1 /* 0x00000001 */                # 18ee: 0c15
            extui        a4, a4, 1, 3                          # 18f0: 404124
            beqi         a4, 7, .Lbr143                        # 18f3: 267409
            beqz.n       a4, .Lbr143                           # 18f6: 8c64
            l8ui         a7, a6, 64 /* [.Ldata028] */          # 18f8: 720640
            bne          a7, a2, .Lbr143                       # 18fb: 279701
            movi.n       a5, 0 /* 0x00000000 */                # 18fe: 0c05
.Lbr143:    extui        a2, a5, 0, 8                          # 1900: 502074
            ret.n                                              # 1903: 0df0

            .balign      4
.Lrel327:   .word        .bss                                  # 1908: 00000000

# Function @ .irom0.text+0x190c
.literal_position
sdk_pm_assoc_parse:
            l16ui        a3, a2, 2 /* [arg0+0x2] */            # 190c: 321201
            beqz.n       a3, .Lbr144                           # 190f: 8c23
            movi.n       a2, -1 /* 0xffffffff */               # 1911: 7cf2
            ret.n         /* 0xffffffff */                     # 1913: 0df0
.Lbr144:    l16ui        a4, a2, 4 /* [arg0+0x4] */            # 1915: 421202
            movi         a5, .Lrel327 /* .Ldata002 */          # 1918: 51fcff
            movi.n       a2, 0 /* 0x00000000 */                # 191b: 0c02
            s16i         a4, a5, 72 /* [arg0+0x4] -> [.Ldata029] */ # 191d: 425524
            ret.n         /* 0x00000000 */                     # 1920: 0df0

            .balign      4
.Lrel328:   .word        .bss                                  # 1924: 00000000
.Lrel329:   .word        memcpy                                # 1928: 00000000

# Function @ .irom0.text+0x192c
# Local variables/stack:
#     (local0):  word[4]   @ -0x10
.literal_position
sdk_pm_set_addr:
            addi         a1, a1, -16 /* (local0) */            # 192c: 12c1f0
            s32i.n       a0, a1, 0 /* a0 -> [(local0)] */      # 192f: 0901
            movi         a0, .Lrel328 /* .Ldata002 */          # 1931: 01fcff
            movi.n       a4, 6 /* 0x00000006 */                # 1934: 0c64
            s8i          a2, a0, 64 /* arg0 -> [.Ldata028] */  # 1936: 224040
            addi         a2, a0, 65 /* .Label001 */            # 1939: 22c041
            movi         a0, .Lrel329 /* memcpy */             # 193c: 01fbff
            callx0       a0 /* memcpy */                       # 193f: c00000
            l32i.n       a0, a1, 0 /* [(local0)] */            # 1942: 0801
            addi         a1, a1, 16 /* (top of frame) */       # 1944: 12c110
            ret.n                                              # 1947: 0df0

            .balign      4
.Lrel330:   .word        .bss                                  # 194c: 00000000
.Lrel331:   .word        memcmp                                # 1950: 00000000

# Function @ .irom0.text+0x1954
# Local variables/stack:
#     (local0):  word[4]   @ -0x10
.literal_position
sdk_pm_sleep_for:
            addi         a1, a1, -16 /* (local0) */            # 1954: 12c1f0
            s32i.n       a0, a1, 0 /* a0 -> [(local0)] */      # 1957: 0901
            movi         a0, .Lrel330 /* .Ldata002 */          # 1959: 01fcff
            l8ui         a3, a0, 53 /* [.Ldata017] */          # 195c: 320035
            bbci         a3, 5, .Lbr145                        # 195f: 576311
            movi.n       a4, 6 /* 0x00000006 */                # 1962: 0c64
            addi         a3, a0, 65 /* .Label001 */            # 1964: 32c041
            movi         a0, .Lrel331 /* memcmp */             # 1967: 01faff
            callx0       a0 /* memcmp */                       # 196a: c00000
            bnez.n       a2, .Lbr145                           # 196d: cc32
            movi.n       a0, 1 /* 0x00000001 */                # 196f: 0c10
            j            .Lbr146                               # 1971: 460000
.Lbr145:    movi.n       a0, 0 /* 0x00000000 */                # 1974: 0c00
.Lbr146:    extui        a2, a0, 0, 8                          # 1976: 002074
            l32i.n       a0, a1, 0 /* [(local0)] */            # 1979: 0801
            addi         a1, a1, 16 /* (top of frame) */       # 197b: 12c110
            ret.n                                              # 197e: 0df0

.Lrel332:   .word        .bss                                  # 1980: 00000000
.Lrel333:   .word        .Ldata042                             # 1984: 40010000
.Lrel334:   .word        .Lstr046                              # 1988: ec020000
.Lrel335:   .word        .Label007                             # 198c: dc000000
.Lrel336:   .word        .Lstr047                              # 1990: fc020000
.Lrel337:   .word        vPortEnterCritical                    # 1994: 00000000
.Lrel338:   .word        vPortExitCritical                     # 1998: 00000000
.Lrel339:   .word        vPortExitCritical                     # 199c: 00000000
.Lrel340:   .word        printf                                # 19a0: 00000000
.Lrel341:   .word        xQueueGenericSend                     # 19a4: 00000000
.Lrel342:   .word        printf                                # 19a8: 00000000

# Function @ .irom0.text+0x19ac
# Local variables/stack:
#     (local0):  word      @ -0x10
#     (local1):  word      @ -0xc
#     (local2):  word[2]   @ -0x8
.literal_position
sdk_pm_post:
            addi         a1, a1, -16 /* (local0) */            # 19ac: 12c1f0
            s32i.n       a0, a1, 4 /* a0 -> [(local1)] */      # 19af: 0911
            movi         a0, .Lrel332 /* .Ldata002 */          # 19b1: 01f3ff
            s32i.n       a12, a1, 8 /* a12 -> [(local2)] */    # 19b4: c921
            l8ui         a0, a0, 57 /* [.Ldata021] */          # 19b6: 020039
            mov.n        a12, a2 /* arg0 */                    # 19b9: cd02
            beqz         a0, .Lbr150                           # 19bb: 168005
            movi         a0, .Lrel337 /* vPortEnterCritical */ # 19be: 01f5ff
            callx0       a0 /* vPortEnterCritical */           # 19c1: c00000
            movi         a2, .Lrel333 /* .Ldata042 */          # 19c4: 21f0ff
            add.n        a2, a12, a2                           # 19c7: 2a2c
            l8ui         a0, a2, 0                             # 19c9: 020200
            beqz.n       a0, .Lbr148                           # 19cc: 8c90
            movi         a0, .Lrel338 /* vPortExitCritical */  # 19ce: 01f2ff
            callx0       a0 /* vPortExitCritical */            # 19d1: c00000
.Lbr147:    movi.n       a2, 0 /* 0x00000000 */                # 19d4: 0c02
            j            .Lbr150                               # 19d6: 460f00
.Lbr148:    addi.n       a3, a0, 1                             # 19d9: 1b30
            s8i          a3, a2, 0                             # 19db: 324200
            movi         a0, .Lrel339 /* vPortExitCritical */  # 19de: 01efff
            callx0       a0 /* vPortExitCritical */            # 19e1: c00000
            call0        .Lfunc001                             # 19e4: 4562fe
            s32i.n       a2, a1, 0 /* a2 -> [(local0)] */      # 19e7: 2901
            bnez.n       a2, .Lbr149                           # 19e9: cc92
            movi         a2, .Lrel334 /* .Lstr046 */           # 19eb: 21e7ff
            movi         a0, .Lrel340 /* printf */             # 19ee: 01ecff
            callx0       a0 /* printf */                       # 19f1: c00000
            l32i.n       a2, a1, 0 /* [(local0)] */            # 19f4: 2801
.Lbr149:    mov.n        a3, a1 /* (local0) */                 # 19f6: 3d01
            movi         a4, .Lrel335 /* .Label007 */          # 19f8: 41e5ff
            s32i.n       a12, a2, 0                            # 19fb: c902
            movi.n       a5, 0 /* 0x00000000 */                # 19fd: 0c05
            l32i.n       a2, a4, 28 /* [.Ldata041] */          # 19ff: 2874
            movi.n       a4, 1 /* 0x00000001 */                # 1a01: 0c14
            movi         a0, .Lrel341 /* xQueueGenericSend */  # 1a03: 01e8ff
            callx0       a0 /* xQueueGenericSend */            # 1a06: c00000
            beqi         a2, 1, .Lbr147                        # 1a09: 2612c7
            movi         a2, .Lrel336 /* .Lstr047 */           # 1a0c: 21e1ff
            movi         a0, .Lrel342 /* printf */             # 1a0f: 01e6ff
            callx0       a0 /* printf */                       # 1a12: c00000
            movi.n       a2, 1 /* 0x00000001 */                # 1a15: 0c12
.Lbr150:    l32i.n       a12, a1, 8 /* [(local2)] */           # 1a17: c821
            l32i.n       a0, a1, 4 /* [(local1)] */            # 1a19: 0811
            addi         a1, a1, 16 /* (top of frame) */       # 1a1b: 12c110
            ret.n                                              # 1a1e: 0df0

.Lrel343:   .word        .bss                                  # 1a20: 00000000
.Llit024:   .word        0x3feffe00                            # 1a24: 00feef3f
.Lrel344:   .word        .Label006                             # 1a28: c4000000
.Lrel345:   .word        .Lstr048                              # 1a2c: 04030000
.Lrel346:   .word        sdk_NMIIrqIsOn                        # 1a30: 00000000
.Lrel347:   .word        sdk_NMIIrqIsOn                        # 1a34: 00000000
.Lrel348:   .word        .Ldata042                             # 1a38: 40010000
.Lrel349:   .word        .Ldata042                             # 1a3c: 40010000
.Lrel350:   .word        .Lstr049                              # 1a40: 10030000
.Lrel351:   .word        .Ldata042                             # 1a44: 40010000
.Lrel352:   .word        .Lstr050                              # 1a48: 1c030000
.Lrel353:   .word        .bss                                  # 1a4c: 00000000
.Lrel354:   .word        .data                                 # 1a50: 00000000
.Lrel355:   .word        xQueueGenericCreate                   # 1a54: 00000000
.Lrel356:   .word        xQueueGenericReceive                  # 1a58: 00000000
.Lrel357:   .word        printf                                # 1a5c: 00000000
.Lrel358:   .word        vPortEnterCritical                    # 1a60: 00000000
.Lrel359:   .word        vPortExitCritical                     # 1a64: 00000000
.Lrel360:   .word        vPortEnterCritical                    # 1a68: 00000000
.Lrel361:   .word        vPortExitCritical                     # 1a6c: 00000000
.Lrel362:   .word        printf                                # 1a70: 00000000
.Lrel363:   .word        sdk_ppCheckTxIdle                     # 1a74: 00000000
.Lrel364:   .word        vPortEnterCritical                    # 1a78: 00000000
.Lrel365:   .word        vPortExitCritical                     # 1a7c: 00000000
.Lrel366:   .word        printf                                # 1a80: 00000000
.Lrel367:   .word        sdk_os_timer_disarm                   # 1a84: 00000000

# Function @ .irom0.text+0x1a88
# Local variables/stack:
#     (local0):  word      @ -0x20
#     (local1):  word      @ -0x1c
#     (local2):  word      @ -0x18
#     (local3):  word      @ -0x14
#     (local4):  word[4]   @ -0x10
.literal_position
.Lfunc023:  movi.n       a2, 8 /* 0x00000008 */                # 1a88: 0c82
            movi.n       a3, 4 /* 0x00000004 */                # 1a8a: 0c43
            movi.n       a4, 0 /* 0x00000000 */                # 1a8c: 0c04
            addi         a1, a1, -32 /* (local0) */            # 1a8e: 12c1e0
            s32i.n       a14, a1, 16 /* a14 -> [(local4)] */   # 1a91: e941
            s32i.n       a13, a1, 12 /* a13 -> [(local3)] */   # 1a93: d931
            s32i.n       a12, a1, 8 /* a12 -> [(local2)] */    # 1a95: c921
            s32i.n       a0, a1, 4 /* a0 -> [(local1)] */      # 1a97: 0911
            movi         a0, .Lrel355 /* xQueueGenericCreate */ # 1a99: 01eeff
            callx0       a0 /* xQueueGenericCreate */          # 1a9c: c00000
            movi         a14, .Llit024 /* 0x3feffe00 */        # 1a9f: e1e1ff
            movi         a7, .Lrel343 /* .Ldata002 */          # 1aa2: 71dfff
            movi         a13, .Lrel344 /* .Label006 */         # 1aa5: d1e0ff
            s32i         a2, a7, 248 /* a2 -> [.Ldata041] */   # 1aa8: 22673e
            addi         a12, a13, 16 /* .bss+0xd4 */          # 1aab: c2cd10
.Lbr151:    mov.n        a3, a1 /* (local0) */                 # 1aae: 3d01
            movi.n       a4, -1 /* 0xffffffff */               # 1ab0: 7cf4
            movi.n       a5, 0 /* 0x00000000 */                # 1ab2: 0c05
            movi         a0, .Lrel356 /* .Lrel356 */           # 1ab4: 01e9ff
            callx0       a0                                    # 1ab7: c00000
            bnei         a2, 1, .Lbr156                        # 1aba: 66127e
            l32i.n       a3, a1, 0 /* [(local0)] */            # 1abd: 3801
            movi         a2, .Lrel345 /* .Lstr048 */           # 1abf: 21dbff
            l32i.n       a3, a3, 0 /* [[(local0)]] */          # 1ac2: 3803
            movi         a0, .Lrel357 /* printf */             # 1ac4: 01e6ff
            callx0       a0 /* printf */                       # 1ac7: c00000
            l32i.n       a0, a1, 0 /* [(local0)] */            # 1aca: 0801
            l32i.n       a0, a0, 0 /* [[(local0)]] */          # 1acc: 0800
            beqz         a0, .Lbr157                           # 1ace: 16f006
            addi.n       a2, a0, -1 /* [[(local0)]]-0x1 */     # 1ad1: 0b20
            beqz         a2, .Lbr158                           # 1ad3: 16220b
            bnei         a0, 2, .Lbr155                        # 1ad6: 66205f
            movi         a2, .Lrel346 /* sdk_NMIIrqIsOn */     # 1ad9: 21d5ff
            l8ui         a2, a2, 0 /* [sdk_NMIIrqIsOn] */      # 1adc: 220200
            bnez.n       a2, .Lbr153                           # 1adf: ec82
            movi         a0, .Lrel358 /* vPortEnterCritical */ # 1ae1: 01dfff
            callx0       a0 /* vPortEnterCritical */           # 1ae4: c00000
.Lbr152:    memw                                               # 1ae7: c02000
            l32i         a4, a14, 0x200 /* [0x3ff00000] */     # 1aea: 422e80
            movi.n       a5, -32 /* 0xffffffe0 */              # 1aed: 6c05
            and          a4, a4, a5                            # 1aef: 504410
            memw                                               # 1af2: c02000
            s32i         a4, a14, 0x200 /* a4 -> [0x3ff00000] */ # 1af5: 426e80
            memw                                               # 1af8: c02000
            l32i         a3, a14, 0x200 /* [0x3ff00000] */     # 1afb: 322e80
            bbsi         a3, 0, .Lbr152                        # 1afe: 07e3e5
            movi         a2, .Lrel347 /* sdk_NMIIrqIsOn */     # 1b01: 21ccff
            l32i.n       a0, a1, 0 /* [(local0)] */            # 1b04: 0801
            l8ui         a2, a2, 0 /* [sdk_NMIIrqIsOn] */      # 1b06: 220200
            l32i.n       a0, a0, 0 /* [[(local0)]] */          # 1b09: 0800
.Lbr153:    movi         a4, .Lrel348 /* .Ldata042 */          # 1b0b: 41cbff
            add.n        a4, a0, a4                            # 1b0e: 4a40
            l8ui         a3, a4, 0                             # 1b10: 320400
            addi.n       a3, a3, -1                            # 1b13: 0b33
            s8i          a3, a4, 0                             # 1b15: 324400
            bnez.n       a2, .Lbr154                           # 1b18: dca2
            memw                                               # 1b1a: c02000
            l32i         a5, a14, 0x200 /* [0x3ff00000] */     # 1b1d: 522e80
            movi.n       a6, -32 /* 0xffffffe0 */              # 1b20: 6c06
            and          a5, a5, a6                            # 1b22: 605510
            movi.n       a6, 1 /* 0x00000001 */                # 1b25: 0c16
            or           a5, a5, a6                            # 1b27: 605520
            memw                                               # 1b2a: c02000
            s32i         a5, a14, 0x200 /* a5 -> [0x3ff00000] */ # 1b2d: 526e80
            movi         a0, .Lrel359 /* vPortExitCritical */  # 1b30: 01cdff
            callx0       a0 /* vPortExitCritical */            # 1b33: c00000
.Lbr154:    call0        sdk_pm_reset_idle_sleep               # 1b36: 050000
.Lbr155:    call0        .Lfunc002                             # 1b39: 4551fe
.Lbr156:    l32i.n       a2, a12, 36 /* [.Ldata041] */         # 1b3c: 289c
            j            .Lbr151                               # 1b3e: 06dbff
.Lbr157:    movi         a0, .Lrel360 /* vPortEnterCritical */ # 1b41: 01c9ff
            callx0       a0 /* vPortEnterCritical */           # 1b44: c00000
            l32i.n       a8, a1, 0 /* [(local0)] */            # 1b47: 8801
            movi         a9, .Lrel349 /* .Ldata042 */          # 1b49: 91bcff
            l32i.n       a8, a8, 0 /* [[(local0)]] */          # 1b4c: 8808
            add.n        a8, a8, a9                            # 1b4e: 9a88
            l8ui         a7, a8, 0                             # 1b50: 720800
            addi.n       a7, a7, -1                            # 1b53: 0b77
            s8i          a7, a8, 0                             # 1b55: 724800
            movi         a0, .Lrel361 /* vPortExitCritical */  # 1b58: 01c5ff
            callx0       a0 /* vPortExitCritical */            # 1b5b: c00000
            movi         a2, .Lrel350 /* .Lstr049 */           # 1b5e: 21b8ff
            movi         a0, .Lrel362 /* printf */             # 1b61: 01c3ff
            callx0       a0 /* printf */                       # 1b64: c00000
            movi.n       a2, 1 /* 0x00000001 */                # 1b67: 0c12
            movi         a0, .Lrel363 /* sdk_ppCheckTxIdle */  # 1b69: 01c2ff
            callx0       a0 /* sdk_ppCheckTxIdle */            # 1b6c: c00000
            bnez         a2, .Lbr155                           # 1b6f: 5662fc
            call0        sdk_pm_is_waked                       # 1b72: 050000
            beqz         a2, .Lbr155                           # 1b75: 1602fc
            l8ui         a10, a12, 16 /* [.Ldata036] */        # 1b78: a20c10
            bnei         a10, 1, .Lbr155                       # 1b7b: 661aba
            movi.n       a11, 1 /* 0x00000001 */               # 1b7e: 0c1b
            s8i          a11, a12, 33 /* 0x01 -> [.Ldata040] */ # 1b80: b24c21
            call0        .Lfunc009                             # 1b83: 85aefe
            j            .Lbr155                               # 1b86: c6ebff
.Lbr158:    movi         a0, .Lrel364 /* vPortEnterCritical */ # 1b89: 01bbff
            callx0       a0 /* vPortEnterCritical */           # 1b8c: c00000
            l32i.n       a2, a1, 0 /* [(local0)] */            # 1b8f: 2801
            movi         a3, .Lrel351 /* .Ldata042 */          # 1b91: 31acff
            l32i.n       a2, a2, 0 /* [[(local0)]] */          # 1b94: 2802
            add.n        a2, a2, a3                            # 1b96: 3a22
            l8ui         a0, a2, 0                             # 1b98: 020200
            addi.n       a0, a0, -1                            # 1b9b: 0b00
            s8i          a0, a2, 0                             # 1b9d: 024200
            movi         a0, .Lrel365 /* vPortExitCritical */  # 1ba0: 01b7ff
            callx0       a0 /* vPortExitCritical */            # 1ba3: c00000
            movi         a2, .Lrel352 /* .Lstr050 */           # 1ba6: 21a8ff
            movi         a0, .Lrel366 /* printf */             # 1ba9: 01b5ff
            callx0       a0 /* printf */                       # 1bac: c00000
            movi         a0, .Lrel353 /* .Ldata002 */          # 1baf: 01a7ff
            l8ui         a0, a0, 53 /* [.Ldata017] */          # 1bb2: 020035
            bbci         a0, 5, .Lbr155                        # 1bb5: 576080
            extui        a0, a0, 1, 3                          # 1bb8: 000124
            bnei         a0, 7, .Lbr159                        # 1bbb: 667002
            j            .Lbr155                               # 1bbe: c6ddff
.Lbr159:    bnei         a0, 6, .Lbr160                        # 1bc1: 666002
            j            .Lbr155                               # 1bc4: 46dcff
.Lbr160:    movi         a2, .Lrel354 /* .Ldata001 */          # 1bc7: 21a2ff
            l8ui         a2, a2, 0 /* [.Ldata001] */           # 1bca: 220200
            bnei         a2, 2, .Lbr162                        # 1bcd: 662217
            mov.n        a2, a13 /* .Label006 */               # 1bd0: 2d0d
            movi         a0, .Lrel367 /* sdk_os_timer_disarm */ # 1bd2: 01acff
            callx0       a0 /* sdk_os_timer_disarm */          # 1bd5: c00000
            call0        sdk_pm_rf_is_closed                   # 1bd8: 050000
            beqz.n       a2, .Lbr161                           # 1bdb: 8c32
            movi.n       a2, 2 /* 0x00000002 */                # 1bdd: 0c22
            call0        .Lfunc005                             # 1bdf: 0579fe
.Lbr161:    call0        .Lfunc013                             # 1be2: 45c1fe
            j            .Lbr155                               # 1be5: 06d4ff
.Lbr162:    call0        .Lfunc013                             # 1be8: c5c0fe
            j            .Lbr155                               # 1beb: 86d2ff

            .balign      4
.Lrel368:   .word        .bss                                  # 1bf0: 00000000
.Lrel369:   .word        sdk_rc_get_sta_trc                    # 1bf4: 00000000

# Function @ .irom0.text+0x1bf8
# Local variables/stack:
#     (local0):  word[4]   @ -0x10
.literal_position
sdk_pm_get_idle_wait_time:
            movi         a2, .Lrel368 /* .Ldata002 */          # 1bf8: 21feff
            addi         a1, a1, -16 /* (local0) */            # 1bfb: 12c1f0
            s32i.n       a0, a1, 0 /* a0 -> [(local0)] */      # 1bfe: 0901
            l8ui         a2, a2, 64 /* [.Ldata028] */          # 1c00: 220240
            movi         a0, .Lrel369 /* sdk_rc_get_sta_trc */ # 1c03: 01fcff
            callx0       a0 /* sdk_rc_get_sta_trc */           # 1c06: c00000
            beqz.n       a2, .Lbr165                           # 1c09: ac62
            l8ui         a2, a2, 1                             # 1c0b: 220201
            movi.n       a3, 26 /* 0x0000001a */               # 1c0e: 1ca3
            slli         a0, a2, 24                            # 1c10: 800201
            srai         a0, a0, 24                            # 1c13: 000831
            bge          a3, a0, .Lbr163                       # 1c16: 07a304
            movi.n       a2, 80 /* 0x00000050 */               # 1c19: 5c02
            j            .Lbr164                               # 1c1b: 460300
.Lbr163:    movi.n       a3, 16 /* 0x00000010 */               # 1c1e: 1c03
            bge          a3, a0, .Lbr165                       # 1c20: 07a30f
            movi         a4, 127 /* 0x0000007f */              # 1c23: 42a07f
            beq          a2, a4, .Lbr165                       # 1c26: 471209
            movi         a2, 160 /* 0x000000a0 */              # 1c29: 22a0a0
.Lbr164:    l32i.n       a0, a1, 0 /* [(local0)] */            # 1c2c: 0801
            addi         a1, a1, 16 /* (top of frame) */       # 1c2e: 12c110
            ret.n                                              # 1c31: 0df0
.Lbr165:    movi         a2, 240 /* 0x000000f0 */              # 1c33: 22a0f0
            j            .Lbr164                               # 1c36: 86fcff

            .section     .rodata.str1.4, "MSa", @progbits, 1

.Label008:  .word        0x00000a77                            #    0: 770a0000
.Lstr001:   .asciz       "sleep %s"                            #    4: 736c6565
                                                               #    8: 70202573
                                                               #    c: 00
            .balign      4
.Lstr002:   .asciz       "disable"                             #   10: 64697361
                                                               #   14: 626c6500
.Lstr003:   .asciz       "enable"                              #   18: 656e6162
                                                               #   1c: 6c6500
            .balign      4
.Lstr004:   .asciz       "\n light sleep is not supported now \n" #   20: 0a206c69
                                                               #   24: 67687420
                                                               #   28: 736c6565
                                                               #   2c: 70206973
                                                               #   30: 206e6f74
                                                               #   34: 20737570
                                                               #   38: 706f7274
                                                               #   3c: 6564206e
                                                               #   40: 6f77200a
                                                               #   44: 00
            .balign      4
.Lstr005:   .asciz       ",type: %d"                           #   48: 2c747970
                                                               #   4c: 653a2025
                                                               #   50: 6400
            .balign      4
.Label009:  .word        0x0000000a                            #   54: 0a000000
.Lstr006:   .asciz       "%s %u\n"                             #   58: 25732025
                                                               #   5c: 750a00
            .balign      4
.Lstr007:   .asciz       "pm.c"                                #   60: 706d2e63
                                                               #   64: 00
            .balign      4
.Lstr008:   .asciz       "pm wakeup st: %d, cause: %d\n"       #   68: 706d2077
                                                               #   6c: 616b6575
                                                               #   70: 70207374
                                                               #   74: 3a202564
                                                               #   78: 2c206361
                                                               #   7c: 7573653a
                                                               #   80: 2025640a
                                                               #   84: 00
            .balign      4
.Lstr009:   .asciz       "c_dt1\n"                             #   88: 635f6474
                                                               #   8c: 310a00
            .balign      4
.Lstr010:   .asciz       "o_dt1\n"                             #   90: 6f5f6474
                                                               #   94: 310a00
            .balign      4
.Lstr011:   .asciz       "SET IDLE CB\n"                       #   98: 53455420
                                                               #   9c: 49444c45
                                                               #   a0: 2043420a
                                                               #   a4: 00
            .balign      4
.Lstr012:   .asciz       "why %u %u %u %u\n"                   #   a8: 77687920
                                                               #   ac: 25752025
                                                               #   b0: 75202575
                                                               #   b4: 2025750a
                                                               #   b8: 00
            .balign      4
.Lstr013:   .asciz       "c_dt2\n"                             #   bc: 635f6474
                                                               #   c0: 320a00
            .balign      4
.Label010:  .byte        0x6f, 0x5f, 0x64, 0x74, 0x32, 0x0a, 0x00, 0x00
            .byte        0x25, 0x75, 0x20, 0x25, 0x75, 0x20, 0x25, 0x75
            .byte        0x20, 0x25, 0x75, 0x0a, 0x00, 0x00, 0x00, 0x00
.Lstr014:   .asciz       "c_dt3\n"                             #   dc: 635f6474
                                                               #   e0: 330a00
            .balign      4
.Lstr015:   .asciz       "o_dt3\n"                             #   e4: 6f5f6474
                                                               #   e8: 330a00
            .balign      4
.Lstr016:   .asciz       "SEND NULL Sleep\n"                   #   ec: 53454e44
                                                               #   f0: 204e554c
                                                               #   f4: 4c20536c
                                                               #   f8: 6565700a
                                                               #   fc: 00
            .balign      4
.Lstr017:   .asciz       "rf close,nulldata_send fail"         #  100: 72662063
                                                               #  104: 6c6f7365
                                                               #  108: 2c6e756c
                                                               #  10c: 6c646174
                                                               #  110: 615f7365
                                                               #  114: 6e642066
                                                               #  118: 61696c00
.Lstr018:   .asciz       "SEND NULL Wake\n"                    #  11c: 53454e44
                                                               #  120: 204e554c
                                                               #  124: 4c205761
                                                               #  128: 6b650a00
.Lstr019:   .asciz       "rf close,nulldata_false"             #  12c: 72662063
                                                               #  130: 6c6f7365
                                                               #  134: 2c6e756c
                                                               #  138: 6c646174
                                                               #  13c: 615f6661
                                                               #  140: 6c736500
.Lstr020:   .asciz       "Waked\n"                             #  144: 57616b65
                                                               #  148: 640a00
            .balign      4
.Lstr021:   .asciz       "c_dt4\n"                             #  14c: 635f6474
                                                               #  150: 340a00
            .balign      4
.Lstr022:   .asciz       "START WAKE UP\n"                     #  154: 53544152
                                                               #  158: 54205741
                                                               #  15c: 4b452055
                                                               #  160: 500a00
            .balign      4
.Lstr023:   .asciz       "c_dt5\n"                             #  164: 635f6474
                                                               #  168: 350a00
            .balign      4
.Lstr024:   .asciz       "pm close %d %d %u/%u\n"              #  16c: 706d2063
                                                               #  170: 6c6f7365
                                                               #  174: 20256420
                                                               #  178: 25642025
                                                               #  17c: 752f2575
                                                               #  180: 0a00
            .balign      4
.Lstr025:   .asciz       "pm open phy_2,type:%d %d %d\n"       #  184: 706d206f
                                                               #  188: 70656e20
                                                               #  18c: 7068795f
                                                               #  190: 322c7479
                                                               #  194: 70653a25
                                                               #  198: 64202564
                                                               #  19c: 2025640a
                                                               #  1a0: 00
            .balign      4
.Lstr026:   .asciz       "noTIM!!\n"                           #  1a4: 6e6f5449
                                                               #  1a8: 4d21210a
                                                               #  1ac: 00
            .balign      4
.Lstr027:   .asciz       "c_dt\n"                              #  1b0: 635f6474
                                                               #  1b4: 0a00
            .balign      4
.Lstr028:   .asciz       "why change %d %d\n"                  #  1b8: 77687920
                                                               #  1bc: 6368616e
                                                               #  1c0: 67652025
                                                               #  1c4: 64202564
                                                               #  1c8: 0a00
            .balign      4
.Lstr029:   .asciz       "bcn_go_slp1\n"                       #  1cc: 62636e5f
                                                               #  1d0: 676f5f73
                                                               #  1d4: 6c70310a
                                                               #  1d8: 00
            .balign      4
.Lstr030:   .asciz       "bcn_go_slp2\n"                       #  1dc: 62636e5f
                                                               #  1e0: 676f5f73
                                                               #  1e4: 6c70320a
                                                               #  1e8: 00
            .balign      4
.Lstr031:   .asciz       "offST%d"                             #  1ec: 6f666653
                                                               #  1f0: 54256400
.Lstr032:   .asciz       "GO_TO_SLEEP\n"                       #  1f4: 474f5f54
                                                               #  1f8: 4f5f534c
                                                               #  1fc: 4545500a
                                                               #  200: 00
            .balign      4
.Lstr033:   .asciz       "onST%d\n"                            #  204: 6f6e5354
                                                               #  208: 25640a00
.Lstr034:   .asciz       "NULL Sleep SENT CB\n"                #  20c: 4e554c4c
                                                               #  210: 20536c65
                                                               #  214: 65702053
                                                               #  218: 454e5420
                                                               #  21c: 43420a00
.Lstr035:   .asciz       "1tx_st:%d,%x\n"                      #  220: 3174785f
                                                               #  224: 73743a25
                                                               #  228: 642c2578
                                                               #  22c: 0a00
            .balign      4
.Lstr036:   .asciz       "NULL Wake SENT CB\n"                 #  230: 4e554c4c
                                                               #  234: 2057616b
                                                               #  238: 65205345
                                                               #  23c: 4e542043
                                                               #  240: 420a00
            .balign      4
.Lstr037:   .asciz       "MISS BCN\n"                          #  244: 4d495353
                                                               #  248: 2042434e
                                                               #  24c: 0a00
            .balign      4
.Lstr038:   .asciz       "dream_timout\n"                      #  250: 64726561
                                                               #  254: 6d5f7469
                                                               #  258: 6d6f7574
                                                               #  25c: 0a00
            .balign      4
.Lstr039:   .asciz       "null data timeout\n"                 #  260: 6e756c6c
                                                               #  264: 20646174
                                                               #  268: 61207469
                                                               #  26c: 6d656f75
                                                               #  270: 740a00
            .balign      4
.Lstr040:   .asciz       "pmTask"                              #  274: 706d5461
                                                               #  278: 736b00
            .balign      4
.Lstr041:   .asciz       "pm_task_hdl : %x, prio:%d, stack:%d\n" #  27c: 706d5f74
                                                               #  280: 61736b5f
                                                               #  284: 68646c20
                                                               #  288: 3a202578
                                                               #  28c: 2c207072
                                                               #  290: 696f3a25
                                                               #  294: 642c2073
                                                               #  298: 7461636b
                                                               #  29c: 3a25640a
                                                               #  2a0: 00
            .balign      4
.Lstr042:   .asciz       "NULL Sleep SEND done\n"              #  2a4: 4e554c4c
                                                               #  2a8: 20536c65
                                                               #  2ac: 65702053
                                                               #  2b0: 454e4420
                                                               #  2b4: 646f6e65
                                                               #  2b8: 0a00
            .balign      4
.Lstr043:   .asciz       "NULL Wake SEND done\n"               #  2bc: 4e554c4c
                                                               #  2c0: 2057616b
                                                               #  2c4: 65205345
                                                               #  2c8: 4e442064
                                                               #  2cc: 6f6e650a
                                                               #  2d0: 00
            .balign      4
.Label011:  .word        0x000a6c73                            #  2d4: 736c0a00
.Lstr044:   .asciz       "usl\n"                               #  2d8: 75736c0a
                                                               #  2dc: 00
            .balign      4
.Lstr045:   .asciz       "sul %d %d\n"                         #  2e0: 73756c20
                                                               #  2e4: 25642025
                                                               #  2e8: 640a00
            .balign      4
.Lstr046:   .asciz       "pm evt1 NULL\n"                      #  2ec: 706d2065
                                                               #  2f0: 76743120
                                                               #  2f4: 4e554c4c
                                                               #  2f8: 0a00
            .balign      4
.Lstr047:   .asciz       "PMQF"                                #  2fc: 504d5146
                                                               #  300: 00
            .balign      4
.Lstr048:   .asciz       "pm_sig: %x\n"                        #  304: 706d5f73
                                                               #  308: 69673a20
                                                               #  30c: 25780a00
.Lstr049:   .asciz       "SLEEP SIG\n"                         #  310: 534c4545
                                                               #  314: 50205349
                                                               #  318: 470a00
            .balign      4
.Lstr050:   .asciz       "WAKE SIG\n"                          #  31c: 57414b45
                                                               #  320: 20534947
                                                               #  324: 0a00
