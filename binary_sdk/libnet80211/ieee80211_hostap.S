
            .section     .literal, "ax", @progbits

            .section     .irom0.literal, "ax", @progbits

            .section     .text, "ax", @progbits

# Function @ .text+0x0
.literal_position
.Lfunc001:  movi         a4, 136 /* 0x00000088 */              #    0: 42a088
            movi.n       a6, 24 /* 0x00000018 */               #    3: 1c86
            movi.n       a5, 30 /* 0x0000001e */               #    5: 1ce5
            l8ui         a7, a2, 1 /* [arg0+0x1] */            #    7: 720201
            l8ui         a3, a2, 0 /* [arg0] */                #    a: 320200
            movi         a8, 140 /* 0x0000008c */              #    d: 82a08c
            and          a3, a3, a8                            #   10: 803310
            extui        a7, a7, 0, 2                          #   13: 707014
            addi         a7, a7, -3                            #   16: 72c7fd
            movnez       a5, a6, a7                            #   19: 705693
            bne          a3, a4, .Lbr001                       #   1c: 479301
            addi.n       a5, a5, 2                             #   1f: 2b55
.Lbr001:    mov.n        a2, a5                                #   21: 2d05
            ret.n                                              #   23: 0df0

            .section     .data, "aw", @progbits

            .section     .bss, "aw", @nobits

.Ldata001:  .byte        0x00
            .byte        0x00, 0x00, 0x00
.Ldata002:  .space       28
sdk_TmpSTAAPCloseAP:
            .byte        0x00
sdk_PendFreeBcnEb:
            .byte        0x00
            .byte        0x00, 0x00
.Ldata003:  .word        0x00000000                            #   24: 00000000

            .section     .irom0.text, "ax", @progbits

.Lrel001:   .word        sdk_g_ic                              #    0: 00000000
.Lrel002:   .word        sdk_g_ic+0x180                        #    4: 00000000
.Lrel003:   .word        sdk_g_ic+0x180                        #    8: 00000000
.Lrel004:   .word        sdk_g_ic+0x180                        #    c: 00000000
.Lrel005:   .word        sdk_g_ic+0x1d2                        #   10: 00000000
.Lrel006:   .word        sdk_g_ic+0x300                        #   14: 00000000
.Llit001:   .word        0x3ff20a00                            #   18: 000af23f
.Lrel007:   .word        .bss                                  #   1c: 00000000
.Lrel008:   .word        .Ldata002                             #   20: 04000000
.Lrel009:   .word        sdk_wifi_get_phy_mode                 #   24: 00000000
.Lrel010:   .word        sdk_gpio_output_set                   #   28: 00000000
.Lrel011:   .word        memcpy                                #   2c: 00000000
.Lrel012:   .word        sdk_ieee80211_chan2ieee               #   30: 00000000
.Lrel013:   .word        sdk_ieee80211_chan2ieee               #   34: 00000000
.Lrel014:   .word        sdk_chm_check_same_channel            #   38: 00000000
.Lrel015:   .word        sdk_ppTxPkt                           #   3c: 00000000
.Lrel016:   .word        sdk_ets_timer_disarm                  #   40: 00000000
.Lrel017:   .word        sdk_wDev_Get_Next_TBTT                #   44: 00000000
.Lrel018:   .word        sdk_ets_timer_arm                     #   48: 00000000

# Function @ .irom0.text+0x4c
# Local variables/stack:
#     (local0):  word      @ -0x20
#     (local1):  word      @ -0x1c
#     (local2):  word      @ -0x18
#     (local3):  word      @ -0x14
#     (local4):  word      @ -0x10
#     (local5):  word      @ -0xc
#     (local6):  word[2]   @ -0x8
.literal_position
.Lfunc002:  addi         a1, a1, -32 /* (local0) */            #   4c: 12c1e0
            s32i.n       a0, a1, 8 /* a0 -> [(local2)] */      #   4f: 0921
            s32i.n       a14, a1, 20 /* a14 -> [(local5)] */   #   51: e951
            s32i.n       a15, a1, 24 /* a15 -> [(local6)] */   #   53: f961
            s32i.n       a13, a1, 16 /* a13 -> [(local4)] */   #   55: d941
            movi         a15, .Lrel001 /* sdk_g_ic */          #   57: f1eaff
            s32i.n       a12, a1, 12 /* a12 -> [(local3)] */   #   5a: c931
            l32i.n       a13, a15, 20 /* [sdk_g_ic+0x14] */    #   5c: d85f
            mov.n        a12, a2 /* arg0 */                    #   5e: cd02
            l32i         a13, a13, 144 /* [[sdk_g_ic+0x14]+0x90] */ #   60: d22d24
            s32i.n       a13, a1, 0 /* [[sdk_g_ic+0x14]+0x90] -> [(local0)] */ #   63: d901
            l16ui        a13, a13, 156 /* [[[sdk_g_ic+0x14]+0x90]+0x9c] */ #   65: d21d4e
            l32i.n       a14, a2, 16 /* [arg0+0x10] */         #   68: e842
            addi.n       a13, a13, -1 /* [[[sdk_g_ic+0x14]+0x90]+0x9c]-0x1 */ #   6a: 0bdd
            movi         a0, .Lrel009 /* sdk_wifi_get_phy_mode */ #   6c: 01eeff
            callx0       a0 /* sdk_wifi_get_phy_mode */        #   6f: c00000
            movi         a0, .Lrel002 /* sdk_g_ic+0x180 */     #   72: 01e4ff
            movi.n       a6, 23 /* 0x00000017 */               #   75: 1c76
            movi.n       a5, 27 /* 0x0000001b */               #   77: 1cb5
            addi.n       a7, a2, -1                            #   79: 0b72
            l32i.n       a3, a1, 0 /* [(local0)] */            #   7b: 3801
            l32i         a4, a15, 0x288 /* [sdk_g_ic+0x288] */ #   7d: 422fa2
            slli         a8, a13, 4                            #   80: c08d11
            s16i         a8, a14, 22 /* a8 -> [[arg0+0x10]+0x16] */ #   83: 825e0b
            l16ui        a2, a3, 156 /* [[(local0)]+0x9c] */   #   86: 22134e
            moveqz       a5, a6, a7                            #   89: 705683
            add.n        a13, a14, a5                          #   8c: 5ade
            s32i.n       a13, a1, 4 /* a13 -> [(local1)] */    #   8e: d911
            addi.n       a2, a2, 1 /* [[(local0)]+0x9c]+0x1 */ #   90: 1b22
            add.n        a13, a4, a13                          #   92: dad4
            s16i         a2, a3, 156 /* [[(local0)]+0x9c]+0x1 -> [[(local0)]+0x9c] */ #   94: 22534e
            l8ui         a0, a0, 97 /* [sdk_g_ic+0x1e1] */     #   97: 020061
            addi         a13, a13, 24                          #   9a: d2cd18
            bnei         a0, 1, .Lbr002                        #   9d: 661039
            movi.n       a4, 1 /* 0x00000001 */                #   a0: 0c14
            movi         a2, .Lrel003 /* sdk_g_ic+0x180 */     #   a2: 21d9ff
            movi.n       a3, 0 /* 0x00000000 */                #   a5: 0c03
            l8ui         a5, a2, 98 /* [sdk_g_ic+0x1e2] */     #   a7: 520262
            l8ui         a2, a2, 99 /* [sdk_g_ic+0x1e3] */     #   aa: 220263
            ssl          a5                                    #   ad: 001540
            extui        a6, a2, 0, 1                          #   b0: 206004
            movi.n       a5, 0 /* 0x00000000 */                #   b3: 0c05
            sll          a2, a2                                #   b5: 0022a1
            moveqz       a3, a4, a6                            #   b8: 603483
            sll          a3, a3                                #   bb: 0033a1
            sll          a4, a4                                #   be: 0044a1
            movi         a0, .Lrel010 /* sdk_gpio_output_set */ #   c1: 01d9ff
            callx0       a0 /* sdk_gpio_output_set */          #   c4: c00000
            movi         a4, .Lrel004 /* sdk_g_ic+0x180 */     #   c7: 41d1ff
            movi.n       a5, 1 /* 0x00000001 */                #   ca: 0c15
            l8ui         a6, a4, 99 /* [sdk_g_ic+0x1e3] */     #   cc: 620463
            movi.n       a3, 0 /* 0x00000000 */                #   cf: 0c03
            extui        a6, a6, 0, 1                          #   d1: 606004
            moveqz       a3, a5, a6                            #   d4: 603583
            s8i          a3, a4, 99 /* a3 -> [sdk_g_ic+0x1e3] */ #   d7: 324463
.Lbr002:    addi.n       a2, a13, 5                            #   da: 5b2d
            movi         a3, .Lrel005 /* sdk_g_ic+0x1d2 */     #   dc: 31cdff
            movi.n       a4, 1 /* 0x00000001 */                #   df: 0c14
            movi         a0, .Lrel011 /* memcpy */             #   e1: 01d2ff
            callx0       a0 /* memcpy */                       #   e4: c00000
            l8ui         a0, a13, 2                            #   e7: 020d02
            bnez.n       a0, .Lbr003                           #   ea: cc10
            l8ui         a0, a13, 3                            #   ec: 020d03
.Lbr003:    addi.n       a7, a0, -1                            #   ef: 0b70
            s8i          a7, a13, 2                            #   f1: 724d02
            l32i         a2, a15, 0x14c /* [sdk_g_ic+0x14c] */ #   f4: 222f53
            movi         a0, .Lrel012 /* sdk_ieee80211_chan2ieee */ #   f7: 01ceff
            callx0       a0 /* sdk_ieee80211_chan2ieee */      #   fa: c00000
            l32i.n       a9, a1, 4 /* [(local1)] */            #   fd: 9811
            l32i         a8, a15, 0x288 /* [sdk_g_ic+0x288] */ #   ff: 822fa2
            add.n        a8, a8, a9                            #  102: 9a88
            s8i          a2, a8, 23                            #  104: 224817
            l32i         a2, a15, 0x14c /* [sdk_g_ic+0x14c] */ #  107: 222f53
            movi         a0, .Lrel013 /* sdk_ieee80211_chan2ieee */ #  10a: 01caff
            callx0       a0 /* sdk_ieee80211_chan2ieee */      #  10d: c00000
            movi         a13, .Lrel006 /* sdk_g_ic+0x300 */    #  110: d1c1ff
            s8i          a2, a13, 13 /* a2 -> [sdk_g_ic+0x30d] */ #  113: 224d0d
            movi         a11, .Llit001 /* 0x3ff20a00 */        #  116: b1c0ff
            memw                                               #  119: c02000
            movi.n       a10, 0 /* 0x00000000 */               #  11c: 0c0a
            l32i.n       a13, a12, 32 /* [arg0+0x20] */        #  11e: d88c
            l32i         a11, a11, 0x200 /* [0x3ff20c00] */    #  120: b22b80
            s32i.n       a11, a13, 16 /* [0x3ff20c00] -> [[arg0+0x20]+0x10] */ #  123: b94d
            s32i.n       a11, a14, 24 /* [0x3ff20c00] -> [[arg0+0x10]+0x18] */ #  125: b96e
            s32i.n       a10, a14, 28 /* 0x00000000 -> [[arg0+0x10]+0x1c] */ #  127: a97e
            movi         a0, .Lrel014 /* sdk_chm_check_same_channel */ #  129: 01c3ff
            callx0       a0 /* sdk_chm_check_same_channel */   #  12c: c00000
            beqz.n       a2, .Lbr004                           #  12f: 9c72
            movi         a15, .Lrel007 /* .Ldata001 */         #  131: f1baff
            mov.n        a2, a12 /* arg0 */                    #  134: 2d0c
            l8ui         a14, a15, 0 /* [.Ldata001] */         #  136: e20f00
            movi.n       a0, 1 /* 0x00000001 */                #  139: 0c10
            or           a14, a14, a0                          #  13b: 00ee20
            s8i          a14, a15, 0 /* a14 -> [.Ldata001] */  #  13e: e24f00
            movi         a0, .Lrel015 /* sdk_ppTxPkt */        #  141: 01beff
            callx0       a0 /* sdk_ppTxPkt */                  #  144: c00000
            j            .Lbr005                               #  147: 060700
.Lbr004:    movi         a12, .Lrel008 /* .Ldata002 */         #  14a: c1b5ff
            mov.n        a2, a12 /* .Ldata002 */               #  14d: 2d0c
            movi         a0, .Lrel016 /* sdk_ets_timer_disarm */ #  14f: 01bcff
            callx0       a0 /* sdk_ets_timer_disarm */         #  152: c00000
            movi         a0, .Lrel017 /* sdk_wDev_Get_Next_TBTT */ #  155: 01bbff
            callx0       a0 /* sdk_wDev_Get_Next_TBTT */       #  158: c00000
            mov.n        a3, a2                                #  15b: 3d02
            movi.n       a4, 0 /* 0x00000000 */                #  15d: 0c04
            mov.n        a2, a12 /* .Ldata002 */               #  15f: 2d0c
            movi         a0, .Lrel018 /* sdk_ets_timer_arm */  #  161: 01b9ff
            callx0       a0 /* sdk_ets_timer_arm */            #  164: c00000
.Lbr005:    l32i.n       a12, a1, 12 /* [(local3)] */          #  167: c831
            l32i.n       a13, a1, 16 /* [(local4)] */          #  169: d841
            l32i.n       a14, a1, 20 /* [(local5)] */          #  16b: e851
            l32i.n       a15, a1, 24 /* [(local6)] */          #  16d: f861
            l32i.n       a0, a1, 8 /* [(local2)] */            #  16f: 0821
            addi         a1, a1, 32 /* (top of frame) */       #  171: 12c120
            ret.n                                              #  174: 0df0

            .balign      4
.Lrel019:   .word        .bss                                  #  178: 00000000
.Lrel020:   .word        .Ldata002                             #  17c: 04000000
.Lrel021:   .word        sdk_ets_timer_disarm                  #  180: 00000000
.Lrel022:   .word        sdk_wDev_Get_Next_TBTT                #  184: 00000000
.Lrel023:   .word        sdk_ets_timer_arm                     #  188: 00000000
.Lrel024:   .word        sdk_wifi_softap_start                 #  18c: 00000000

# Function @ .irom0.text+0x190
# Local variables/stack:
#     (local0):  word[4]   @ -0x10
.literal_position
.Lfunc003:  movi         a4, 254 /* 0x000000fe */              #  190: 42a0fe
            addi         a1, a1, -16 /* (local0) */            #  193: 12c1f0
            movi         a2, .Lrel019 /* .Ldata001 */          #  196: 21f8ff
            s32i.n       a0, a1, 0 /* a0 -> [(local0)] */      #  199: 0901
            l8ui         a0, a2, 0 /* [.Ldata001] */           #  19b: 020200
            l8ui         a3, a2, 32 /* [sdk_TmpSTAAPCloseAP] */ #  19e: 320220
            and          a0, a0, a4                            #  1a1: 400010
            bnez.n       a3, .Lbr006                           #  1a4: dcf3
            s8i          a0, a2, 0 /* a0 -> [.Ldata001] */     #  1a6: 024200
            addi.n       a2, a2, 4 /* .Ldata002 */             #  1a9: 4b22
            movi         a0, .Lrel021 /* sdk_ets_timer_disarm */ #  1ab: 01f5ff
            callx0       a0 /* sdk_ets_timer_disarm */         #  1ae: c00000
            movi         a0, .Lrel022 /* sdk_wDev_Get_Next_TBTT */ #  1b1: 01f4ff
            callx0       a0 /* sdk_wDev_Get_Next_TBTT */       #  1b4: c00000
            mov.n        a3, a2                                #  1b7: 3d02
            movi.n       a4, 0 /* 0x00000000 */                #  1b9: 0c04
            movi         a2, .Lrel020 /* .Ldata002 */          #  1bb: 21f0ff
            movi         a0, .Lrel023 /* sdk_ets_timer_arm */  #  1be: 01f2ff
            callx0       a0 /* sdk_ets_timer_arm */            #  1c1: c00000
            j            .Lbr008                               #  1c4: 060700
.Lbr006:    movi.n       a5, 1 /* 0x00000001 */                #  1c7: 0c15
            s8i          a5, a2, 33 /* 0x01 -> [sdk_PendFreeBcnEb] */ #  1c9: 524221
            bbci         a0, 1, .Lbr007                        #  1cc: 176011
            movi         a6, 253 /* 0x000000fd */              #  1cf: 62a0fd
            and          a6, a0, a6                            #  1d2: 606010
            s8i          a6, a2, 0 /* a6 -> [.Ldata001] */     #  1d5: 624200
            movi         a0, .Lrel024 /* sdk_wifi_softap_start */ #  1d8: 01edff
            callx0       a0 /* sdk_wifi_softap_start */        #  1db: c00000
            j            .Lbr008                               #  1de: 860000
.Lbr007:    s8i          a0, a2, 0 /* a0 -> [.Ldata001] */     #  1e1: 024200
.Lbr008:    l32i.n       a0, a1, 0 /* [(local0)] */            #  1e4: 0801
            addi         a1, a1, 16 /* (top of frame) */       #  1e6: 12c110
            ret.n                                              #  1e9: 0df0

            .balign      4
.Lrel025:   .word        sdk_g_ic                              #  1ec: 00000000
.Lrel026:   .word        sdk_g_ic+0x28e                        #  1f0: 00000000
.Lrel027:   .word        sdk_g_ic+0x28c                        #  1f4: 00000000
.Lrel028:   .word        sdk_g_ic+0x2ac                        #  1f8: 00000000
.Lrel029:   .word        zalloc                                #  1fc: 00000000
.Lrel030:   .word        zalloc                                #  200: 00000000
.Lrel031:   .word        zalloc                                #  204: 00000000
.Lrel032:   .word        memcpy                                #  208: 00000000
.Lrel033:   .word        zalloc                                #  20c: 00000000
.Lrel034:   .word        strlen                                #  210: 00000000
.Lrel035:   .word        memcpy                                #  214: 00000000
.Lrel036:   .word        sdk_hostapd_setup_wpa_psk             #  218: 00000000
.Lrel037:   .word        sdk_wpa_init                          #  21c: 00000000
.Lrel038:   .word        free                                  #  220: 00000000

# Function @ .irom0.text+0x224
# Local variables/stack:
#     (local0):  word      @ -0x20
#     (local1):  word      @ -0x1c
#     (local2):  word      @ -0x18
#     (local3):  word      @ -0x14
#     (local4):  word[4]   @ -0x10
.literal_position
.Lfunc004:  movi.n       a2, 28 /* 0x0000001c */               #  224: 1cc2
            addi         a1, a1, -32 /* (local0) */            #  226: 12c1e0
            s32i.n       a13, a1, 12 /* a13 -> [(local3)] */   #  229: d931
            s32i.n       a14, a1, 16 /* a14 -> [(local4)] */   #  22b: e941
            s32i.n       a12, a1, 8 /* a12 -> [(local2)] */    #  22d: c921
            movi         a12, .Lrel025 /* sdk_g_ic */          #  22f: c1efff
            s32i.n       a0, a1, 4 /* a0 -> [(local1)] */      #  232: 0911
            l32i.n       a12, a12, 20 /* [sdk_g_ic+0x14] */    #  234: c85c
            movi         a0, .Lrel029 /* zalloc */             #  236: 01f1ff
            callx0       a0 /* zalloc */                       #  239: c00000
            s32i         a2, a12, 180 /* a2 -> [[sdk_g_ic+0x14]+0xb4] */ #  23c: 226c2d
            movi         a2, 204 /* 0x000000cc */              #  23f: 22a0cc
            movi         a0, .Lrel030 /* zalloc */             #  242: 01efff
            callx0       a0 /* zalloc */                       #  245: c00000
            l32i         a13, a12, 180 /* [[sdk_g_ic+0x14]+0xb4] */ #  248: d22c2d
            s32i.n       a2, a13, 4 /* a2 -> [[[sdk_g_ic+0x14]+0xb4]+0x4] */ #  24b: 291d
            movi.n       a2, 76 /* 0x0000004c */               #  24d: 4cc2
            movi         a0, .Lrel031 /* zalloc */             #  24f: 01edff
            callx0       a0 /* zalloc */                       #  252: c00000
            movi         a14, .Lrel026 /* sdk_g_ic+0x28e */    #  255: e1e6ff
            l8ui         a0, a14, 128 /* [sdk_g_ic+0x30e] */   #  258: 020e80
            mov.n        a13, a2                               #  25b: dd02
            bnei         a0, 2, .Lbr009                        #  25d: 662006
            movi.n       a3, 1 /* 0x00000001 */                #  260: 0c13
            s32i.n       a3, a2, 0                             #  262: 3902
            l8ui         a0, a14, 128 /* [sdk_g_ic+0x30e] */   #  264: 020e80
.Lbr009:    movi.n       a2, 2 /* 0x00000002 */                #  267: 0c22
            bnei         a0, 3, .Lbr010                        #  269: 663004
            s32i.n       a2, a13, 0                            #  26c: 290d
            l8ui         a0, a14, 128 /* [sdk_g_ic+0x30e] */   #  26e: 020e80
.Lbr010:    bnei         a0, 4, .Lbr011                        #  271: 664003
            movi.n       a5, 3 /* 0x00000003 */                #  274: 0c35
            s32i.n       a5, a13, 0                            #  276: 590d
.Lbr011:    movi         a3, .Lrel027 /* sdk_g_ic+0x28c */     #  278: 31dfff
            addi         a5, a14, -6 /* sdk_g_ic+0x288 */      #  27b: 52cefa
            s32i.n       a2, a13, 40                           #  27e: 29ad
            s32i.n       a2, a13, 4                            #  280: 291d
            s32i.n       a2, a13, 12                           #  282: 293d
            movi.n       a6, 10 /* 0x0000000a */               #  284: 0ca6
            s32i.n       a6, a13, 8                            #  286: 692d
            l32i         a2, a12, 180 /* [[sdk_g_ic+0x14]+0xb4] */ #  288: 222c2d
            s32i.n       a6, a13, 32                           #  28b: 698d
            l32i.n       a2, a2, 4 /* [[[sdk_g_ic+0x14]+0xb4]+0x4] */ #  28d: 2812
            l16ui        a4, a5, 2 /* [sdk_g_ic+0x28a] */      #  28f: 421501
            addi         a2, a2, 16 /* [[[sdk_g_ic+0x14]+0xb4]+0x4]+0x10 */ #  292: 22c210
            l16ui        a5, a5, 0 /* [sdk_g_ic+0x288] */      #  295: 521500
            slli         a4, a4, 16                            #  298: 004411
            or           a4, a4, a5                            #  29b: 504420
            movi         a0, .Lrel032 /* memcpy */             #  29e: 01daff
            callx0       a0 /* memcpy */                       #  2a1: c00000
            movi.n       a2, 64 /* 0x00000040 */               #  2a4: 4c02
            addi         a7, a14, -6 /* sdk_g_ic+0x288 */      #  2a6: 72cefa
            l32i         a8, a12, 180 /* [[sdk_g_ic+0x14]+0xb4] */ #  2a9: 822c2d
            l16ui        a9, a7, 0 /* [sdk_g_ic+0x288] */      #  2ac: 921700
            l16ui        a7, a7, 2 /* [sdk_g_ic+0x28a] */      #  2af: 721701
            l32i.n       a8, a8, 4 /* [[[sdk_g_ic+0x14]+0xb4]+0x4] */ #  2b2: 8818
            slli         a7, a7, 16                            #  2b4: 007711
            or           a7, a7, a9                            #  2b7: 907720
            s32i.n       a7, a8, 48 /* a7 -> [[[[sdk_g_ic+0x14]+0xb4]+0x4]+0x30] */ #  2ba: 79c8
            movi         a0, .Lrel033 /* zalloc */             #  2bc: 01d4ff
            callx0       a0 /* zalloc */                       #  2bf: c00000
            l32i         a8, a12, 180 /* [[sdk_g_ic+0x14]+0xb4] */ #  2c2: 822c2d
            s32i.n       a2, a1, 0 /* a2 -> [(local0)] */      #  2c5: 2901
            l32i.n       a8, a8, 4 /* [[[sdk_g_ic+0x14]+0xb4]+0x4] */ #  2c7: 8818
            movi         a14, .Lrel028 /* sdk_g_ic+0x2ac */    #  2c9: e1cbff
            s32i.n       a2, a8, 60 /* a2 -> [[[[sdk_g_ic+0x14]+0xb4]+0x4]+0x3c] */ #  2cc: 29f8
            mov.n        a2, a14 /* sdk_g_ic+0x2ac */          #  2ce: 2d0e
            movi         a0, .Lrel034 /* strlen */             #  2d0: 01d0ff
            callx0       a0 /* strlen */                       #  2d3: c00000
            mov.n        a4, a2                                #  2d6: 4d02
            mov.n        a3, a14 /* sdk_g_ic+0x2ac */          #  2d8: 3d0e
            l32i.n       a2, a1, 0 /* [(local0)] */            #  2da: 2801
            movi         a0, .Lrel035 /* memcpy */             #  2dc: 01ceff
            callx0       a0 /* memcpy */                       #  2df: c00000
            movi.n       a0, 16 /* 0x00000010 */               #  2e2: 1c00
            movi.n       a3, 3 /* 0x00000003 */                #  2e4: 0c33
            l32i         a2, a12, 180 /* [[sdk_g_ic+0x14]+0xb4] */ #  2e6: 222c2d
            l32i         a10, a12, 144 /* [[sdk_g_ic+0x14]+0x90] */ #  2e9: a22c24
            l32i.n       a2, a2, 4 /* [[[sdk_g_ic+0x14]+0xb4]+0x4] */ #  2ec: 2812
            movi         a4, 300 /* 0x0000012c */              #  2ee: 42a12c
            s32i         a4, a2, 180 /* 0x0000012c -> [[[[sdk_g_ic+0x14]+0xb4]+0x4]+0xb4] */ #  2f1: 42622d
            l32i         a14, a12, 72 /* [[sdk_g_ic+0x14]+0x48] */ #  2f4: e22c12
            s8i          a3, a12, 76 /* 0x03 -> [[sdk_g_ic+0x14]+0x4c] */ #  2f7: 324c4c
            or           a14, a14, a0                          #  2fa: 00ee20
            s32i         a14, a12, 72 /* a14 -> [[sdk_g_ic+0x14]+0x48] */ #  2fd: e26c12
            l32i.n       a9, a10, 8 /* [[[sdk_g_ic+0x14]+0x90]+0x8] */ #  300: 982a
            movi.n       a11, 1 /* 0x00000001 */               #  302: 0c1b
            or           a9, a9, a11                           #  304: b09920
            s32i.n       a9, a10, 8 /* a9 -> [[[sdk_g_ic+0x14]+0x90]+0x8] */ #  307: 992a
            movi         a0, .Lrel036 /* sdk_hostapd_setup_wpa_psk */ #  309: 01c3ff
            callx0       a0 /* sdk_hostapd_setup_wpa_psk */    #  30c: c00000
            mov.n        a3, a13                               #  30f: 3d0d
            l32i.n       a2, a12, 0 /* [[sdk_g_ic+0x14]] */    #  311: 280c
            movi.n       a4, 0 /* 0x00000000 */                #  313: 0c04
            addi         a2, a2, 41 /* [[sdk_g_ic+0x14]]+0x29 */ #  315: 22c229
            movi         a0, .Lrel037 /* sdk_wpa_init */       #  318: 01c1ff
            callx0       a0 /* sdk_wpa_init */                 #  31b: c00000
            l32i         a3, a12, 180 /* [[sdk_g_ic+0x14]+0xb4] */ #  31e: 322c2d
            s32i.n       a2, a3, 24 /* a2 -> [[[sdk_g_ic+0x14]+0xb4]+0x18] */ #  321: 2963
            mov.n        a2, a13                               #  323: 2d0d
            movi         a0, .Lrel038 /* free */               #  325: 01beff
            callx0       a0 /* free */                         #  328: c00000
            l32i.n       a12, a1, 8 /* [(local2)] */           #  32b: c821
            l32i.n       a13, a1, 12 /* [(local3)] */          #  32d: d831
            l32i.n       a14, a1, 16 /* [(local4)] */          #  32f: e841
            l32i.n       a0, a1, 4 /* [(local1)] */            #  331: 0811
            addi         a1, a1, 32 /* (top of frame) */       #  333: 12c120
            ret.n                                              #  336: 0df0

.Lrel039:   .word        sdk_g_ic                              #  338: 00000000
.Lrel040:   .word        free                                  #  33c: 00000000
.Lrel041:   .word        free                                  #  340: 00000000
.Lrel042:   .word        free                                  #  344: 00000000
.Lrel043:   .word        free                                  #  348: 00000000
.Lrel044:   .word        free                                  #  34c: 00000000
.Lrel045:   .word        free                                  #  350: 00000000
.Lrel046:   .word        free                                  #  354: 00000000

# Function @ .irom0.text+0x358
# Local variables/stack:
#     (local0):  word      @ -0x10
#     (local1):  word[3]   @ -0xc
.literal_position
.Lfunc005:  addi         a1, a1, -16 /* (local0) */            #  358: 12c1f0
            movi.n       a5, -17 /* 0xffffffef */              #  35b: 6cf5
            s32i.n       a12, a1, 4 /* a12 -> [(local1)] */    #  35d: c911
            movi         a12, .Lrel039 /* sdk_g_ic */          #  35f: c1f6ff
            s32i.n       a0, a1, 0 /* a0 -> [(local0)] */      #  362: 0901
            l32i.n       a12, a12, 20 /* [sdk_g_ic+0x14] */    #  364: c85c
            movi.n       a0, 0 /* 0x00000000 */                #  366: 0c00
            l32i         a2, a12, 180 /* [[sdk_g_ic+0x14]+0xb4] */ #  368: 222c2d
            s8i          a0, a12, 76 /* 0x00 -> [[sdk_g_ic+0x14]+0x4c] */ #  36b: 024c4c
            l32i         a4, a12, 72 /* [[sdk_g_ic+0x14]+0x48] */ #  36e: 422c12
            l32i         a3, a12, 144 /* [[sdk_g_ic+0x14]+0x90] */ #  371: 322c24
            and          a4, a4, a5                            #  374: 504410
            s32i         a4, a12, 72 /* a4 -> [[sdk_g_ic+0x14]+0x48] */ #  377: 426c12
            s32i.n       a0, a3, 8 /* 0x00000000 -> [[[sdk_g_ic+0x14]+0x90]+0x8] */ #  37a: 0923
            beqz         a2, .Lbr018                           #  37c: 16f206
            l32i.n       a4, a2, 24 /* [[[sdk_g_ic+0x14]+0xb4]+0x18] */ #  37f: 4862
            l32i         a5, a4, 80 /* [[[[sdk_g_ic+0x14]+0xb4]+0x18]+0x50] */ #  381: 522414
            beqz.n       a5, .Lbr012                           #  384: 8cb5
            mov.n        a2, a5 /* [[[[sdk_g_ic+0x14]+0xb4]+0x18]+0x50] */ #  386: 2d05
            movi         a0, .Lrel040 /* free */               #  388: 01edff
            callx0       a0 /* free */                         #  38b: c00000
            l32i         a2, a12, 180 /* [[sdk_g_ic+0x14]+0xb4] */ #  38e: 222c2d
            l32i.n       a4, a2, 24 /* [[[sdk_g_ic+0x14]+0xb4]+0x18] */ #  391: 4862
.Lbr012:    l32i.n       a0, a4, 0 /* [[[[sdk_g_ic+0x14]+0xb4]+0x18]] */ #  393: 0804
            beqz.n       a0, .Lbr013                           #  395: 8cb0
            mov.n        a2, a0 /* [[[[sdk_g_ic+0x14]+0xb4]+0x18]] */ #  397: 2d00
            movi         a0, .Lrel041 /* free */               #  399: 01e9ff
            callx0       a0 /* free */                         #  39c: c00000
            l32i         a2, a12, 180 /* [[sdk_g_ic+0x14]+0xb4] */ #  39f: 222c2d
            l32i.n       a4, a2, 24 /* [[[sdk_g_ic+0x14]+0xb4]+0x18] */ #  3a2: 4862
.Lbr013:    beqz.n       a4, .Lbr014                           #  3a4: 8c94
            mov.n        a2, a4 /* [[[sdk_g_ic+0x14]+0xb4]+0x18] */ #  3a6: 2d04
            movi         a0, .Lrel042 /* free */               #  3a8: 01e7ff
            callx0       a0 /* free */                         #  3ab: c00000
            l32i         a2, a12, 180 /* [[sdk_g_ic+0x14]+0xb4] */ #  3ae: 222c2d
.Lbr014:    l32i.n       a0, a2, 4 /* [[[sdk_g_ic+0x14]+0xb4]+0x4] */ #  3b1: 0812
            l32i.n       a4, a0, 56 /* [[[[sdk_g_ic+0x14]+0xb4]+0x4]+0x38] */ #  3b3: 48e0
            beqz.n       a4, .Lbr015                           #  3b5: 8cb4
            mov.n        a2, a4 /* [[[[sdk_g_ic+0x14]+0xb4]+0x4]+0x38] */ #  3b7: 2d04
            movi         a0, .Lrel043 /* free */               #  3b9: 01e3ff
            callx0       a0 /* free */                         #  3bc: c00000
            l32i         a2, a12, 180 /* [[sdk_g_ic+0x14]+0xb4] */ #  3bf: 222c2d
            l32i.n       a0, a2, 4 /* [[[sdk_g_ic+0x14]+0xb4]+0x4] */ #  3c2: 0812
.Lbr015:    l32i.n       a4, a0, 60 /* [[[[sdk_g_ic+0x14]+0xb4]+0x4]+0x3c] */ #  3c4: 48f0
            beqz.n       a4, .Lbr016                           #  3c6: 8cb4
            mov.n        a2, a4 /* [[[[sdk_g_ic+0x14]+0xb4]+0x4]+0x3c] */ #  3c8: 2d04
            movi         a0, .Lrel044 /* free */               #  3ca: 01e0ff
            callx0       a0 /* free */                         #  3cd: c00000
            l32i         a2, a12, 180 /* [[sdk_g_ic+0x14]+0xb4] */ #  3d0: 222c2d
            l32i.n       a0, a2, 4 /* [[[sdk_g_ic+0x14]+0xb4]+0x4] */ #  3d3: 0812
.Lbr016:    beqz.n       a0, .Lbr017                           #  3d5: 8c90
            mov.n        a2, a0 /* [[[sdk_g_ic+0x14]+0xb4]+0x4] */ #  3d7: 2d00
            movi         a0, .Lrel045 /* free */               #  3d9: 01ddff
            callx0       a0 /* free */                         #  3dc: c00000
            l32i         a2, a12, 180 /* [[sdk_g_ic+0x14]+0xb4] */ #  3df: 222c2d
.Lbr017:    beqz.n       a2, .Lbr018                           #  3e2: 8c92
            movi         a0, .Lrel046 /* free */               #  3e4: 01dcff
            callx0       a0 /* free */                         #  3e7: c00000
            movi.n       a0, 0 /* 0x00000000 */                #  3ea: 0c00
            s32i         a0, a12, 180 /* 0x00000000 -> [[sdk_g_ic+0x14]+0xb4] */ #  3ec: 026c2d
.Lbr018:    l32i.n       a12, a1, 4 /* [(local1)] */           #  3ef: c811
            l32i.n       a0, a1, 0 /* [(local0)] */            #  3f1: 0801
            addi         a1, a1, 16 /* (top of frame) */       #  3f3: 12c110
            ret.n                                              #  3f6: 0df0

.Lrel047:   .word        .Lfunc003                             #  3f8: 90010000
.Lrel048:   .word        .Ldata002                             #  3fc: 04000000
.Lrel049:   .word        .Lfunc002                             #  400: 4c000000
.Lrel050:   .word        sdk_ic_bss_info_update                #  404: 00000000
.Lrel051:   .word        sdk_ppRegisterTxCallback              #  408: 00000000
.Lrel052:   .word        sdk_ieee80211_beacon_alloc            #  40c: 00000000
.Lrel053:   .word        sdk_ets_timer_disarm                  #  410: 00000000
.Lrel054:   .word        sdk_ets_timer_setfn                   #  414: 00000000
.Lrel055:   .word        sdk_wDev_Reset_TBTT                   #  418: 00000000
.Lrel056:   .word        sdk_wDev_Get_Next_TBTT                #  41c: 00000000
.Lrel057:   .word        sdk_ets_timer_arm                     #  420: 00000000

# Function @ .irom0.text+0x424
# Local variables/stack:
#     (local0):  word      @ -0x10
#     (local1):  word      @ -0xc
#     (local2):  word[2]   @ -0x8
.literal_position
sdk_ieee80211_hostap_attach:
            addi         a1, a1, -64 /* (FP)-0x40 */           #  424: 12c1c0
            s32i.n       a13, a1, 56 /* a13 -> [(local2)] */   #  427: d9e1
            s32i.n       a12, a1, 52 /* a12 -> [(local1)] */   #  429: c9d1
            s32i.n       a0, a1, 48 /* a0 -> [(local0)] */     #  42b: 09c1
            mov.n        a12, a2 /* arg0 */                    #  42d: cd02
            addmi        a0, a2, 768 /* arg0+0x300 */          #  42f: 02d203
            l8ui         a0, a0, 14 /* [arg0+0x30e] */         #  432: 02000e
            l32i.n       a13, a2, 20 /* [arg0+0x14] */         #  435: d852
            bgei         a0, 5, .Lbr019                        #  437: e65005
            blti         a0, 2, .Lbr019                        #  43a: a62002
            call0        .Lfunc004                             #  43d: 45deff
.Lbr019:    movi.n       a2, 1 /* 0x00000001 */                #  440: 0c12
            movi.n       a4, 2 /* 0x00000002 */                #  442: 0c24
            l32i.n       a3, a13, 0 /* [[arg0+0x14]] */        #  444: 380d
            movi         a5, 100 /* 0x00000064 */              #  446: 52a064
            addi         a3, a3, 41 /* [[arg0+0x14]]+0x29 */   #  449: 32c329
            movi         a0, .Lrel050 /* sdk_ic_bss_info_update */ #  44c: 01eeff
            callx0       a0 /* sdk_ic_bss_info_update */       #  44f: c00000
            movi         a2, .Lrel047 /* .Lfunc003 */          #  452: 21e9ff
            movi.n       a3, 4 /* 0x00000004 */                #  455: 0c43
            movi.n       a4, 5 /* 0x00000005 */                #  457: 0c54
            movi.n       a5, 0 /* 0x00000000 */                #  459: 0c05
            s16i         a5, a12, 0x1d0 /* 0x0000 -> [arg0+0x1d0] */ #  45b: 525ce8
            s32i.n       a4, a13, 60 /* 0x00000005 -> [[arg0+0x14]+0x3c] */ #  45e: 49fd
            movi         a0, .Lrel051 /* sdk_ppRegisterTxCallback */ #  460: 01eaff
            callx0       a0 /* sdk_ppRegisterTxCallback */     #  463: c00000
            mov.n        a2, a13 /* [arg0+0x14] */             #  466: 2d0d
            mov.n        a3, a1 /* (FP)-0x40 */                #  468: 3d01
            movi         a0, .Lrel052 /* sdk_ieee80211_beacon_alloc */ #  46a: 01e8ff
            callx0       a0 /* sdk_ieee80211_beacon_alloc */   #  46d: c00000
            movi         a12, .Lrel048 /* .Ldata002 */         #  470: c1e3ff
            s32i.n       a2, a12, 32 /* a2 -> [.Ldata003] */   #  473: 298c
            addi         a13, a12, -4 /* .Ldata001 */          #  475: d2ccfc
            mov.n        a2, a12 /* .Ldata002 */               #  478: 2d0c
            movi         a0, .Lrel053 /* sdk_ets_timer_disarm */ #  47a: 01e5ff
            callx0       a0 /* sdk_ets_timer_disarm */         #  47d: c00000
            l32i.n       a4, a13, 36 /* [.Ldata003] */         #  480: 489d
            mov.n        a2, a12 /* .Ldata002 */               #  482: 2d0c
            movi         a3, .Lrel049 /* .Lfunc002 */          #  484: 31dfff
            movi         a0, .Lrel054 /* sdk_ets_timer_setfn */ #  487: 01e3ff
            callx0       a0 /* sdk_ets_timer_setfn */          #  48a: c00000
            movi         a0, .Lrel055 /* sdk_wDev_Reset_TBTT */ #  48d: 01e2ff
            callx0       a0 /* sdk_wDev_Reset_TBTT */          #  490: c00000
            movi         a0, .Lrel056 /* sdk_wDev_Get_Next_TBTT */ #  493: 01e2ff
            callx0       a0 /* sdk_wDev_Get_Next_TBTT */       #  496: c00000
            mov.n        a3, a2                                #  499: 3d02
            movi.n       a4, 0 /* 0x00000000 */                #  49b: 0c04
            mov.n        a2, a12 /* .Ldata002 */               #  49d: 2d0c
            movi         a0, .Lrel057 /* sdk_ets_timer_arm */  #  49f: 01e0ff
            callx0       a0 /* sdk_ets_timer_arm */            #  4a2: c00000
            l32i.n       a12, a1, 52 /* [(local1)] */          #  4a5: c8d1
            l32i.n       a13, a1, 56 /* [(local2)] */          #  4a7: d8e1
            l32i.n       a0, a1, 48 /* [(local0)] */           #  4a9: 08c1
            addi         a1, a1, 64 /* (top of frame) */       #  4ab: 12c140
            ret.n                                              #  4ae: 0df0

.Lrel058:   .word        pbuf_alloc                            #  4b0: 00000000
.Lrel059:   .word        ethernetif_input                      #  4b4: 00000000

# Function @ .irom0.text+0x4b8
# Local variables/stack:
#     (local0):  word      @ -0x10
#     (local1):  word      @ -0xc
#     (local2):  word[2]   @ -0x8
.literal_position
.Lfunc006:  addi         a1, a1, -16 /* (local0) */            #  4b8: 12c1f0
            s32i.n       a12, a1, 8 /* a12 -> [(local2)] */    #  4bb: c921
            s32i.n       a0, a1, 4 /* a0 -> [(local1)] */      #  4bd: 0911
            mov.n        a12, a3 /* arg1 */                    #  4bf: cd03
            l32i.n       a0, a2, 0 /* [arg0] */                #  4c1: 0802
            s32i.n       a0, a1, 0 /* [arg0] -> [(local0)] */  #  4c3: 0901
            beqz.n       a3, .Lbr020                           #  4c5: 9cf3
            movi.n       a2, 3 /* 0x00000003 */                #  4c7: 0c32
            l16ui        a3, a3, 22 /* [arg1+0x16] */          #  4c9: 32130b
            movi.n       a4, 2 /* 0x00000002 */                #  4cc: 0c24
            movi         a0, .Lrel058 /* pbuf_alloc */         #  4ce: 01f8ff
            callx0       a0 /* pbuf_alloc */                   #  4d1: c00000
            l32i.n       a4, a12, 4 /* [arg1+0x4] */           #  4d4: 481c
            mov.n        a3, a2                                #  4d6: 3d02
            l32i.n       a2, a4, 4 /* [[arg1+0x4]+0x4] */      #  4d8: 2814
            s32i.n       a2, a3, 4                             #  4da: 2913
            l32i.n       a2, a1, 0 /* [(local0)] */            #  4dc: 2801
            s32i.n       a3, a12, 0 /* a3 -> [arg1] */         #  4de: 390c
            s32i.n       a12, a3, 16                           #  4e0: c943
            movi         a0, .Lrel059 /* ethernetif_input */   #  4e2: 01f4ff
            callx0       a0 /* ethernetif_input */             #  4e5: c00000
.Lbr020:    l32i.n       a12, a1, 8 /* [(local2)] */           #  4e8: c821
            l32i.n       a0, a1, 4 /* [(local1)] */            #  4ea: 0811
            addi         a1, a1, 16 /* (top of frame) */       #  4ec: 12c110
            ret.n                                              #  4ef: 0df0

            .balign      4
.Llit002:   .word        0x60000600                            #  4f4: 00060060
.Llit003:   .word        0x000493df                            #  4f8: df930400
.Lrel060:   .word        sdk_g_ic                              #  4fc: 00000000
.Lrel061:   .word        sdk_g_ic                              #  500: 00000000
.Lrel062:   .word        sdk_g_ic                              #  504: 00000000
.Lrel063:   .word        __udivsi3                             #  508: 00000000
.Lrel064:   .word        __udivsi3                             #  50c: 00000000
.Lrel065:   .word        sdk_ieee80211_send_mgmt               #  510: 00000000
.Lrel066:   .word        sdk_ieee80211_send_mgmt               #  514: 00000000
.Lrel067:   .word        sdk_cnx_node_leave                    #  518: 00000000

# Function @ .irom0.text+0x51c
# Local variables/stack:
#     (local0):  word      @ -0x10
#     (local1):  word      @ -0xc
#     (local2):  word[2]   @ -0x8
.literal_position
sdk_hostap_handle_timer:
            addi         a1, a1, -16 /* (local0) */            #  51c: 12c1f0
            s32i.n       a0, a1, 4 /* a0 -> [(local1)] */      #  51f: 0911
            s32i.n       a12, a1, 8 /* a12 -> [(local2)] */    #  521: c921
            mov.n        a12, a2 /* arg0 */                    #  523: cd02
            movi         a2, .Llit002 /* 0x60000600 */         #  525: 21f3ff
            memw                                               #  528: c02000
            l32i         a0, a12, 0x108 /* [arg0+0x108] */     #  52b: 022c42
            l32i.n       a2, a2, 36 /* [0x60000624] */         #  52e: 2892
            bltu         a2, a0, .Lbr021                       #  530: 07320e
            movi         a3, 312 /* 0x00000138 */              #  533: 32a138
            sub          a2, a2, a0                            #  536: 0022c0
            movi         a0, .Lrel063 /* __udivsi3 */          #  539: 01f3ff
            callx0       a0 /* __udivsi3 */                    #  53c: c00000
            j            .Lbr022                               #  53f: 460400
.Lbr021:    movi.n       a3, -1 /* 0xffffffff */               #  542: 7cf3
            xor          a3, a0, a3                            #  544: 303030
            add.n        a2, a2, a3                            #  547: 3a22
            addi.n       a2, a2, 1                             #  549: 1b22
            movi         a3, 312 /* 0x00000138 */              #  54b: 32a138
            movi         a0, .Lrel064 /* __udivsi3 */          #  54e: 01efff
            callx0       a0 /* __udivsi3 */                    #  551: c00000
.Lbr022:    movi         a4, .Llit003 /* 0x000493df */         #  554: 41e9ff
            bgeu         a4, a2, .Lbr023                       #  557: 27b43b
            movi         a3, 160 /* 0x000000a0 */              #  55a: 32a0a0
            movi         a2, .Lrel060 /* sdk_g_ic */           #  55d: 21e7ff
            movi.n       a4, 4 /* 0x00000004 */                #  560: 0c44
            l32i.n       a5, a2, 20 /* [sdk_g_ic+0x14] */      #  562: 5852
            l32i.n       a2, a2, 20 /* [sdk_g_ic+0x14] */      #  564: 2852
            l32i         a6, a5, 136 /* [[sdk_g_ic+0x14]+0x88] */ #  566: 622522
            s32i.n       a6, a1, 0 /* [[sdk_g_ic+0x14]+0x88] -> [(local0)] */ #  569: 6901
            s32i         a12, a5, 136 /* arg0 -> [[sdk_g_ic+0x14]+0x88] */ #  56b: c26522
            movi         a0, .Lrel065 /* sdk_ieee80211_send_mgmt */ #  56e: 01e8ff
            callx0       a0 /* sdk_ieee80211_send_mgmt */      #  571: c00000
            movi         a3, 192 /* 0x000000c0 */              #  574: 32a0c0
            movi         a2, .Lrel061 /* sdk_g_ic */           #  577: 21e2ff
            movi.n       a4, 2 /* 0x00000002 */                #  57a: 0c24
            l32i.n       a2, a2, 20 /* [sdk_g_ic+0x14] */      #  57c: 2852
            movi         a0, .Lrel066 /* sdk_ieee80211_send_mgmt */ #  57e: 01e5ff
            callx0       a0 /* sdk_ieee80211_send_mgmt */      #  581: c00000
            movi         a2, .Lrel062 /* sdk_g_ic */           #  584: 21e0ff
            l32i.n       a2, a2, 20 /* [sdk_g_ic+0x14] */      #  587: 2852
            l32i.n       a3, a1, 0 /* [(local0)] */            #  589: 3801
            s32i         a3, a2, 136 /* [(local0)] -> [[sdk_g_ic+0x14]+0x88] */ #  58b: 326222
            mov.n        a3, a12 /* arg0 */                    #  58e: 3d0c
            movi         a0, .Lrel067 /* sdk_cnx_node_leave */ #  590: 01e2ff
            callx0       a0 /* sdk_cnx_node_leave */           #  593: c00000
.Lbr023:    l32i.n       a12, a1, 8 /* [(local2)] */           #  596: c821
            l32i.n       a0, a1, 4 /* [(local1)] */            #  598: 0811
            addi         a1, a1, 16 /* (top of frame) */       #  59a: 12c110
            ret.n                                              #  59d: 0df0

            .balign      4
.Lrel068:   .word        sdk_ieee80211_addr_bcast              #  5a0: 00000000
.Lrel069:   .word        sdk_ieee80211_addr_bcast              #  5a4: 00000000
.Llit004:   .word        0x60000600                            #  5a8: 00060060
.Lrel070:   .word        sdk_ieee80211_addr_bcast              #  5ac: 00000000
.Llit005:   .word        0x00008e88                            #  5b0: 888e0000
.Lrel071:   .word        sdk_ppRecycleRxPkt                    #  5b4: 00000000
.Lrel072:   .word        sdk_cnx_node_search                   #  5b8: 00000000
.Lrel073:   .word        memcmp                                #  5bc: 00000000
.Lrel074:   .word        memcmp                                #  5c0: 00000000
.Lrel075:   .word        sdk_cnx_node_search                   #  5c4: 00000000
.Lrel076:   .word        memcmp                                #  5c8: 00000000
.Lrel077:   .word        memcmp                                #  5cc: 00000000
.Lrel078:   .word        memcpy                                #  5d0: 00000000
.Lrel079:   .word        .text                                 #  5d4: 00000000
.Lrel080:   .word        sdk_ieee80211_send_mgmt               #  5d8: 00000000
.Lrel081:   .word        .Lfunc010                             #  5dc: 880e0000
.Lrel082:   .word        .text                                 #  5e0: 00000000
.Lrel083:   .word        sdk_ieee80211_crypto_decap            #  5e4: 00000000
.Lrel084:   .word        .Lfunc009                             #  5e8: a80a0000
.Lrel085:   .word        sdk_ieee80211_node_pwrsave            #  5ec: 00000000
.Lrel086:   .word        sdk_ieee80211_crypto_decap            #  5f0: 00000000
.Lrel087:   .word        sdk_ieee80211_decap                   #  5f4: 00000000
.Lrel088:   .word        sdk_wpa_receive                       #  5f8: 00000000
.Lrel089:   .word        sdk_wpa_receive                       #  5fc: 00000000

# Function @ .irom0.text+0x600
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
#     (local14): word[2]   @ -0x8
.literal_position
sdk_hostap_input:
            mov.n        a11, a4 /* arg2 */                    #  600: bd04
            addi         a1, a1, -64 /* (local0) */            #  602: 12c1c0
            s32i.n       a15, a1, 44 /* a15 -> [(local11)] */  #  605: f9b1
            s32i.n       a14, a1, 40 /* a14 -> [(local10)] */  #  607: e9a1
            s32i.n       a0, a1, 28 /* a0 -> [(local7)] */     #  609: 0971
            s32i.n       a13, a1, 36 /* a13 -> [(local9)] */   #  60b: d991
            s32i.n       a12, a1, 32 /* a12 -> [(local8)] */   #  60d: c981
            mov.n        a13, a2 /* arg0 */                    #  60f: dd02
            mov.n        a12, a3 /* arg1 */                    #  611: cd03
            l32i.n       a0, a12, 16 /* [arg1+0x10] */         #  613: 084c
            l32i.n       a2, a2, 0 /* [arg0] */                #  615: 2802
            l8ui         a4, a0, 1 /* [[arg1+0x10]+0x1] */     #  617: 420001
            mov.n        a3, a5 /* arg3 */                     #  61a: 3d05
            srli         a4, a4, 6                             #  61c: 404641
            bnez.n       a4, .Lbr024                           #  61f: cc74
            l16ui        a0, a0, 2 /* [[arg1+0x10]+0x2] */     #  621: 021001
            extui        a0, a0, 0, 12                         #  624: 0000b4
            j            .Lbr025                               #  627: 860300
.Lbr024:    l16ui        a5, a0, 6 /* [[arg1+0x10]+0x6] */     #  62a: 521003
            l16ui        a4, a0, 4 /* [[arg1+0x10]+0x4] */     #  62d: 421002
            slli         a0, a5, 16                            #  630: 000511
            or           a0, a0, a4                            #  633: 400020
            srli         a0, a0, 8                             #  636: 000841
.Lbr025:    extui        a0, a0, 0, 16                         #  639: 0000f4
            bltui        a0, 16, .Lbr027                       #  63c: b6b03a
            l32i.n       a14, a12, 4 /* [arg1+0x4] */          #  63f: e81c
            l32i.n       a14, a14, 4 /* [[arg1+0x4]+0x4] */    #  641: e81e
            l8ui         a4, a14, 0 /* [[[arg1+0x4]+0x4]] */   #  643: 420e00
            movi         a15, 255 /* 0x000000ff */             #  646: f2a0ff
            extui        a6, a4, 0, 2                          #  649: 406014
            bnez         a6, .Lbr031                           #  64c: 568604
            movi.n       a9, 23 /* 0x00000017 */               #  64f: 1c79
            s32i.n       a11, a1, 16 /* arg2 -> [(local4)] */  #  651: b941
            s32i.n       a3, a1, 12 /* arg3 -> [(local3)] */   #  653: 3931
            s32i.n       a2, a1, 8 /* [arg0] -> [(local2)] */  #  655: 2921
            l8ui         a5, a14, 1 /* [[[arg1+0x4]+0x4]+0x1] */ #  657: 520e01
            movi         a6, 240 /* 0x000000f0 */              #  65a: 62a0f0
            movi.n       a15, 12 /* 0x0000000c */              #  65d: 0ccf
            and          a15, a4, a15                          #  65f: f0f410
            and          a6, a4, a6                            #  662: 606410
            s32i.n       a6, a1, 52 /* a6 -> [(local13)] */    #  665: 69d1
            extui        a5, a5, 0, 2                          #  667: 505014
            s32i.n       a5, a1, 24 /* a5 -> [(local6)] */     #  66a: 5961
            bnez.n       a5, .Lbr026                           #  66c: cc15
            bnei         a15, 4, .Lbr032                       #  66e: 664f29
.Lbr026:    s32i.n       a0, a1, 4 /* a0 -> [(local1)] */      #  671: 0911
            addi.n       a2, a14, 4 /* [[arg1+0x4]+0x4]+0x4 */ #  673: 4b2e
            s32i.n       a2, a1, 56 /* [[arg1+0x4]+0x4]+0x4 -> [(local14)] */ #  675: 29e1
            j            .Lbr033                               #  677: 860a00
.Lbr027:    movi         a15, 255 /* 0x000000ff */             #  67a: f2a0ff
.Lbr028:    beqz.n       a12, .Lbr029                          #  67d: 8c6c
            mov.n        a2, a12                               #  67f: 2d0c
            movi         a0, .Lrel071 /* .Lrel071 */           #  681: 01ccff
            callx0       a0                                    #  684: c00000
.Lbr029:    mov.n        a2, a15                               #  687: 2d0f
.Lbr030:    l32i.n       a12, a1, 32 /* [(local8)] */          #  689: c881
            l32i.n       a13, a1, 36 /* [(local9)] */          #  68b: d891
            l32i.n       a14, a1, 40 /* [(local10)] */         #  68d: e8a1
            l32i.n       a15, a1, 44 /* [(local11)] */         #  68f: f8b1
            l32i.n       a0, a1, 28 /* [(local7)] */           #  691: 0871
            addi         a1, a1, 64 /* (top of frame) */       #  693: 12c140
            ret.n                                              #  696: 0df0
.Lbr031:    j            .Lbr028                               #  698: 46f8ff
.Lbr032:    bgeu         a9, a0, .Lbr028                       #  69b: 07b9de
            s32i.n       a0, a1, 4 /* a0 -> [(local1)] */      #  69e: 0911
            addi         a3, a14, 16 /* [[arg1+0x4]+0x4]+0x10 */ #  6a0: 32ce10
            s32i.n       a3, a1, 56 /* [[arg1+0x4]+0x4]+0x10 -> [(local14)] */ #  6a3: 39e1
.Lbr033:    addi.n       a2, a14, 10 /* [[arg1+0x4]+0x4]+0xa */ #  6a5: ab2e
            s32i.n       a2, a1, 20 /* [[arg1+0x4]+0x4]+0xa -> [(local5)] */ #  6a7: 2951
            movi         a0, .Lrel072 /* .Lrel072 */           #  6a9: 01c3ff
            callx0       a0                                    #  6ac: c00000
            movi         a8, .Lrel068 /* sdk_ieee80211_addr_bcast */ #  6af: 81bcff
            bnez.n       a2, .Lbr035                           #  6b2: ece2
            l32i.n       a2, a1, 56 /* [(local14)] */          #  6b4: 28e1
            mov.n        a3, a8 /* sdk_ieee80211_addr_bcast */ #  6b6: 3d08
            movi.n       a4, 6 /* 0x00000006 */                #  6b8: 0c64
            movi         a0, .Lrel073 /* memcmp */             #  6ba: 01c0ff
            callx0       a0 /* memcmp */                       #  6bd: c00000
            beqz.n       a2, .Lbr034                           #  6c0: 9c02
            l32i.n       a2, a1, 56 /* [(local14)] */          #  6c2: 28e1
            l32i.n       a3, a1, 8 /* [(local2)] */            #  6c4: 3821
            movi.n       a4, 6 /* 0x00000006 */                #  6c6: 0c64
            addi         a3, a3, 41 /* [(local2)]+0x29 */      #  6c8: 32c329
            movi         a0, .Lrel074 /* memcmp */             #  6cb: 01bdff
            callx0       a0 /* memcmp */                       #  6ce: c00000
            bnez         a2, .Lbr028                           #  6d1: 5682fa
.Lbr034:    movi         a2, .Lrel069 /* sdk_ieee80211_addr_bcast */ #  6d4: 21b4ff
            movi         a0, .Lrel075 /* sdk_cnx_node_search */ #  6d7: 01bbff
            callx0       a0 /* sdk_cnx_node_search */          #  6da: c00000
            s32i.n       a2, a1, 48 /* a2 -> [(local12)] */    #  6dd: 29c1
            bnez.n       a2, .Lbr036                           #  6df: cce2
            j            .Lbr028                               #  6e1: 06e6ff
.Lbr035:    s32i.n       a2, a1, 48 /* a2 -> [(local12)] */    #  6e4: 29c1
            movi         a4, .Llit004 /* 0x60000600 */         #  6e6: 41b0ff
            memw                                               #  6e9: c02000
            l32i.n       a4, a4, 36 /* [0x60000624] */         #  6ec: 4894
            s32i         a4, a2, 0x108                         #  6ee: 426242
.Lbr036:    l32i.n       a5, a1, 48 /* [(local12)] */          #  6f1: 58c1
            s32i         a5, a13, 136 /* [(local12)] -> [arg0+0x88] */ #  6f3: 526d22
            bnez.n       a15, .Lbr037                          #  6f6: cc3f
            l32i.n       a6, a1, 52 /* [(local13)] */          #  6f8: 68d1
            beqi         a6, 64, .Lbr038                       #  6fa: 26d620
.Lbr037:    l32i.n       a2, a1, 56 /* [(local14)] */          #  6fd: 28e1
            l32i.n       a3, a1, 8 /* [(local2)] */            #  6ff: 3821
            movi.n       a4, 6 /* 0x00000006 */                #  701: 0c64
            addi         a3, a3, 41 /* [(local2)]+0x29 */      #  703: 32c329
            movi         a0, .Lrel076 /* memcmp */             #  706: 01b0ff
            callx0       a0 /* memcmp */                       #  709: c00000
            beqz.n       a2, .Lbr038                           #  70c: 8ce2
            l32i.n       a2, a1, 56 /* [(local14)] */          #  70e: 28e1
            movi         a3, .Lrel070 /* sdk_ieee80211_addr_bcast */ #  710: 31a7ff
            movi.n       a4, 6 /* 0x00000006 */                #  713: 0c64
            movi         a0, .Lrel077 /* memcmp */             #  715: 01adff
            callx0       a0 /* memcmp */                       #  718: c00000
            bnez         a2, .Lbr028                           #  71b: 56e2f5
.Lbr038:    l32i.n       a4, a1, 12 /* [(local3)] */           #  71e: 4831
            s8i          a4, a13, 168 /* [(local3)] -> [arg0+0xa8] */ #  720: 424da8
            bbsi         a15, 2, .Lbr042                       #  723: 27ef3e
            l32i.n       a5, a1, 52 /* [(local13)] */          #  726: 58d1
            beqi         a5, 64, .Lbr042                       #  728: 26d539
            l8ui         a0, a14, 1 /* [[[arg1+0x4]+0x4]+0x1] */ #  72b: 020e01
            l8ui         a6, a14, 0 /* [[[arg1+0x4]+0x4]] */   #  72e: 620e00
            movi         a7, 140 /* 0x0000008c */              #  731: 72a08c
            and          a6, a6, a7                            #  734: 706610
            movi         a7, 136 /* 0x00000088 */              #  737: 72a088
            bne          a6, a7, .Lbr039                       #  73a: 77960b
            extui        a8, a0, 0, 2                          #  73d: 008014
            bnei         a8, 3, .Lbr044                        #  740: 663877
            l8ui         a8, a14, 30 /* [[[arg1+0x4]+0x4]+0x1e] */ #  743: 820e1e
            j            .Lbr045                               #  746: 061d00
.Lbr039:    movi.n       a8, 16 /* 0x00000010 */               #  749: 1c08
.Lbr040:    l32i.n       a9, a1, 48 /* [(local12)] */          #  74b: 98c1
            addx2        a8, a8, a9                            #  74d: 908890
            l16ui        a9, a14, 22 /* [[[arg1+0x4]+0x4]+0x16] */ #  750: 921e0b
            bbci         a0, 3, .Lbr041                        #  753: 37600b
            l16ui        a10, a8, 158                          #  756: a2184f
            sub          a10, a9, a10                          #  759: a0a9c0
            bgei         a10, 1, .Lbr041                       #  75c: e61a02
            j            .Lbr028                               #  75f: 86c6ff
.Lbr041:    s16i         a9, a8, 158                           #  762: 92584f
.Lbr042:    l32i.n       a3, a1, 20 /* [(local5)] */           #  765: 3851
            addi         a2, a13, 64 /* arg0+0x40 */           #  767: 22cd40
            movi.n       a4, 6 /* 0x00000006 */                #  76a: 0c64
            movi         a0, .Lrel078 /* memcpy */             #  76c: 0199ff
            callx0       a0 /* memcpy */                       #  76f: c00000
            beqz         a15, .Lbr047                          #  772: 16df05
            beqi         a15, 4, .Lbr046                       #  775: 264f4b
            addi         a11, a15, -8                          #  778: b2cff8
            bnez         a11, .Lbr028                          #  77b: 56ebef
            mov.n        a2, a14 /* [[arg1+0x4]+0x4] */        #  77e: 2d0e
            movi         a0, .Lrel079 /* .Lfunc001 */          #  780: 0195ff
            callx0       a0 /* .Lfunc001 */                    #  783: c00000
            mov.n        a5, a2                                #  786: 5d02
            l32i.n       a0, a1, 4 /* [(local1)] */            #  788: 0811
            s16i         a2, a12, 20 /* a2 -> [arg1+0x14] */   #  78a: 225c0a
            sub          a2, a0, a2                            #  78d: 2020c0
            addi         a2, a2, -4                            #  790: 22c2fc
            s16i         a2, a12, 22 /* a2 -> [arg1+0x16] */   #  793: 225c0b
            bge          a0, a5, .Lbr043                       #  796: 57a002
            j            .Lbr028                               #  799: 06b8ff
.Lbr043:    l32i.n       a3, a1, 24 /* [(local6)] */           #  79c: 3861
            addi.n       a3, a3, -1 /* [(local6)]-0x1 */       #  79e: 0b33
            bnez         a3, .Lbr028                           #  7a0: 5693ed
            l32i.n       a4, a1, 48 /* [(local12)] */          #  7a3: 48c1
            l16ui        a4, a4, 26 /* [[(local12)]+0x1a] */   #  7a5: 42140d
            bnez         a4, .Lbr051                           #  7a8: 56140a
            mov.n        a2, a13 /* arg0 */                    #  7ab: 2d0d
            movi         a3, 160 /* 0x000000a0 */              #  7ad: 32a0a0
            movi.n       a4, 7 /* 0x00000007 */                #  7b0: 0c74
            movi         a0, .Lrel080 /* sdk_ieee80211_send_mgmt */ #  7b2: 0189ff
            callx0       a0 /* sdk_ieee80211_send_mgmt */      #  7b5: c00000
            j            .Lbr028                               #  7b8: 46b0ff
.Lbr044:    l8ui         a8, a14, 24 /* [[[arg1+0x4]+0x4]+0x18] */ #  7bb: 820e18
.Lbr045:    extui        a8, a8, 0, 4                          #  7be: 808034
            j            .Lbr040                               #  7c1: 86e1ff
.Lbr046:    mov.n        a2, a13 /* arg0 */                    #  7c4: 2d0d
            mov.n        a3, a12 /* arg1 */                    #  7c6: 3d0c
            l32i.n       a4, a1, 52 /* [(local13)] */          #  7c8: 48d1
            movi         a0, .Lrel081 /* .Lfunc010 */          #  7ca: 0184ff
            callx0       a0 /* .Lfunc010 */                    #  7cd: c00000
            j            .Lbr028                               #  7d0: 46aaff
.Lbr047:    mov.n        a2, a14 /* [[arg1+0x4]+0x4] */        #  7d3: 2d0e
            movi         a0, .Lrel082 /* .Lfunc001 */          #  7d5: 0182ff
            callx0       a0 /* .Lfunc001 */                    #  7d8: c00000
            mov.n        a4, a2                                #  7db: 4d02
            s16i         a2, a12, 20 /* a2 -> [arg1+0x14] */   #  7dd: 225c0a
            l32i.n       a0, a1, 4 /* [(local1)] */            #  7e0: 0811
            l32i.n       a5, a1, 24 /* [(local6)] */           #  7e2: 5861
            sub          a6, a0, a2                            #  7e4: 2060c0
            addi         a6, a6, -4                            #  7e7: 62c6fc
            s16i         a6, a12, 22 /* a6 -> [arg1+0x16] */   #  7ea: 625c0b
            bnez         a5, .Lbr028                           #  7ed: 56c5e8
            movi.n       a7, 23 /* 0x00000017 */               #  7f0: 1c77
            bltu         a7, a0, .Lbr048                       #  7f2: 073702
            j            .Lbr028                               #  7f5: 06a1ff
.Lbr048:    l8ui         a8, a14, 10 /* [[[arg1+0x4]+0x4]+0xa] */ #  7f8: 820e0a
            extui        a8, a8, 0, 1                          #  7fb: 808004
            bnez         a8, .Lbr028                           #  7fe: 56b8e7
            l8ui         a9, a14, 1 /* [[[arg1+0x4]+0x4]+0x1] */ #  801: 920e01
            bbci         a9, 6, .Lbr050                        #  804: 676932
            l32i.n       a10, a1, 52 /* [(local13)] */         #  807: a8d1
            movi         a11, 176 /* 0x000000b0 */             #  809: b2a0b0
            sub          a10, a10, a11 /* [(local13)]-0xb0 */  #  80c: b0aac0
            bnez         a10, .Lbr028                          #  80f: 56aae6
            l32i         a14, a13, 72 /* [arg0+0x48] */        #  812: e22d12
            movi.n       a0, 16 /* 0x00000010 */               #  815: 1c00
            bany         a14, a0, .Lbr049                      #  817: 078e02
            j            .Lbr028                               #  81a: c697ff
.Lbr049:    mov.n        a2, a13 /* arg0 */                    #  81d: 2d0d
            mov.n        a3, a12 /* arg1 */                    #  81f: 3d0c
            movi         a0, .Lrel083 /* sdk_ieee80211_crypto_decap */ #  821: 0170ff
            callx0       a0 /* sdk_ieee80211_crypto_decap */   #  824: c00000
            beqz         a2, .Lbr028                           #  827: 1622e5
            l32i.n       a3, a12, 4 /* [arg1+0x4] */           #  82a: 381c
            l32i.n       a3, a3, 4 /* [[arg1+0x4]+0x4] */      #  82c: 3813
            l8ui         a2, a3, 1 /* [[[arg1+0x4]+0x4]+0x1] */ #  82e: 220301
            movi         a4, 191 /* 0x000000bf */              #  831: 42a0bf
            and          a2, a2, a4                            #  834: 402210
            s8i          a2, a3, 1 /* a2 -> [[[arg1+0x4]+0x4]+0x1] */ #  837: 224301
.Lbr050:    mov.n        a2, a13 /* arg0 */                    #  83a: 2d0d
            mov.n        a3, a12 /* arg1 */                    #  83c: 3d0c
            l32i.n       a4, a1, 52 /* [(local13)] */          #  83e: 48d1
            l32i.n       a5, a1, 16 /* [(local4)] */           #  840: 5841
            l32i.n       a6, a1, 12 /* [(local3)] */           #  842: 6831
            movi         a0, .Lrel084 /* .Lfunc009 */          #  844: 0169ff
            callx0       a0 /* .Lfunc009 */                    #  847: c00000
            j            .Lbr028                               #  84a: c68bff
.Lbr051:    s32i.n       a5, a1, 0 /* a5 -> [(local0)] */      #  84d: 5901
            l32i.n       a4, a1, 48 /* [(local12)] */          #  84f: 48c1
            movi.n       a3, 16 /* 0x00000010 */               #  851: 1c03
            l32i.n       a4, a4, 8 /* [[(local12)]+0x8] */     #  853: 4824
            l8ui         a0, a14, 1 /* [[[arg1+0x4]+0x4]+0x1] */ #  855: 020e01
            and          a4, a4, a3                            #  858: 304410
            and          a3, a0, a3                            #  85b: 303010
            beq          a3, a4, .Lbr052                       #  85e: 47130a
            l32i.n       a2, a1, 48 /* [(local12)] */          #  861: 28c1
            movi         a0, .Lrel085 /* sdk_ieee80211_node_pwrsave */ #  863: 0162ff
            callx0       a0 /* sdk_ieee80211_node_pwrsave */   #  866: c00000
            l8ui         a0, a14, 1 /* [[[arg1+0x4]+0x4]+0x1] */ #  869: 020e01
.Lbr052:    bbci         a0, 6, .Lbr054                        #  86c: 676028
            l32i         a5, a13, 72 /* [arg0+0x48] */         #  86f: 522d12
            movi.n       a6, 16 /* 0x00000010 */               #  872: 1c06
            bany         a5, a6, .Lbr053                       #  874: 678502
            j            .Lbr028                               #  877: 8680ff
.Lbr053:    mov.n        a2, a13 /* arg0 */                    #  87a: 2d0d
            mov.n        a3, a12 /* arg1 */                    #  87c: 3d0c
            l32i.n       a4, a1, 0 /* [(local0)] */            #  87e: 4801
            movi         a0, .Lrel086 /* sdk_ieee80211_crypto_decap */ #  880: 015cff
            callx0       a0 /* sdk_ieee80211_crypto_decap */   #  883: c00000
            beqz         a2, .Lbr028                           #  886: 1632df
            l8ui         a7, a14, 1 /* [[[arg1+0x4]+0x4]+0x1] */ #  889: 720e01
            movi         a8, 191 /* 0x000000bf */              #  88c: 82a0bf
            and          a7, a7, a8                            #  88f: 807710
            s8i          a7, a14, 1 /* a7 -> [[[arg1+0x4]+0x4]+0x1] */ #  892: 724e01
            j            .Lbr055                               #  895: 860200
.Lbr054:    l32i.n       a10, a12, 4 /* [arg1+0x4] */          #  898: a81c
            l16ui        a9, a12, 20 /* [arg1+0x14] */         #  89a: 921c0a
            l32i.n       a11, a10, 4 /* [[arg1+0x4]+0x4] */    #  89d: b81a
            add.n        a9, a9, a11                           #  89f: ba99
            s32i.n       a9, a10, 4 /* a9 -> [[arg1+0x4]+0x4] */ #  8a1: 991a
.Lbr055:    mov.n        a3, a14 /* [[arg1+0x4]+0x4] */        #  8a3: 3d0e
            mov.n        a2, a12 /* arg1 */                    #  8a5: 2d0c
            l32i.n       a4, a1, 4 /* [(local1)] */            #  8a7: 4811
            l32i.n       a5, a1, 0 /* [(local0)] */            #  8a9: 5801
            movi         a0, .Lrel087 /* .Lrel087 */           #  8ab: 0152ff
            callx0       a0                                    #  8ae: c00000
            mov.n        a3, a2                                #  8b1: 3d02
            mov.n        a12, a2                               #  8b3: cd02
            beqz         a2, .Lbr028                           #  8b5: 1642dc
            movi         a4, .Llit005 /* 0x00008e88 */         #  8b8: 413eff
            l32i.n       a14, a1, 48 /* [(local12)] */         #  8bb: e8c1
            l32i.n       a0, a2, 4                             #  8bd: 0812
            l32i.n       a14, a14, 8 /* [[(local12)]+0x8] */   #  8bf: e82e
            l32i.n       a0, a0, 4                             #  8c1: 0810
            bbsi         a14, 0, .Lbr056                       #  8c3: 07ee35
            l32i.n       a2, a1, 48 /* [(local12)] */          #  8c6: 28c1
            l8ui         a2, a2, 24 /* [[(local12)]+0x18] */   #  8c8: 220218
            bnei         a2, 1, .Lbr057                        #  8cb: 66125a
            l8ui         a5, a0, 13                            #  8ce: 52000d
            l8ui         a6, a0, 12                            #  8d1: 62000c
            slli         a5, a5, 8                             #  8d4: 805511
            or           a5, a5, a6                            #  8d7: 605520
            sub          a5, a5, a4                            #  8da: 4055c0
            bnez         a5, .Lbr028                           #  8dd: 56c5d9
            addi.n       a4, a0, 14                            #  8e0: eb40
            l16ui        a5, a3, 22                            #  8e2: 52130b
            l32i         a2, a13, 180 /* [arg0+0xb4] */        #  8e5: 222d2d
            l32i         a3, a13, 136 /* [arg0+0x88] */        #  8e8: 322d22
            l32i.n       a2, a2, 24 /* [[arg0+0xb4]+0x18] */   #  8eb: 2862
            addi         a5, a5, -14                           #  8ed: 52c5f2
            l32i         a3, a3, 228 /* [[arg0+0x88]+0xe4] */  #  8f0: 322339
            movi         a0, .Lrel088 /* sdk_wpa_receive */    #  8f3: 0141ff
            callx0       a0 /* sdk_wpa_receive */              #  8f6: c00000
            j            .Lbr028                               #  8f9: 0660ff
.Lbr056:    l8ui         a5, a0, 13                            #  8fc: 52000d
            l8ui         a6, a0, 12                            #  8ff: 62000c
            slli         a5, a5, 8                             #  902: 805511
            or           a5, a5, a6                            #  905: 605520
            bne          a5, a4, .Lbr057                       #  908: 47951d
            l32i         a2, a13, 180 /* [arg0+0xb4] */        #  90b: 222d2d
            beqz.n       a2, .Lbr057                           #  90e: 9c72
            l32i.n       a2, a2, 24 /* [[arg0+0xb4]+0x18] */   #  910: 2862
            addi.n       a4, a0, 14                            #  912: eb40
            l16ui        a5, a3, 22                            #  914: 52130b
            l32i         a6, a13, 136 /* [arg0+0x88] */        #  917: 622d22
            addi         a5, a5, -14                           #  91a: 52c5f2
            l32i         a3, a6, 228 /* [[arg0+0x88]+0xe4] */  #  91d: 322639
            movi         a0, .Lrel089 /* sdk_wpa_receive */    #  920: 0137ff
            callx0       a0 /* sdk_wpa_receive */              #  923: c00000
            j            .Lbr028                               #  926: c654ff
.Lbr057:    mov.n        a2, a13 /* arg0 */                    #  929: 2d0d
            call0        .Lfunc006                             #  92b: c5b8ff
            movi.n       a2, 8 /* 0x00000008 */                #  92e: 0c82
            j            .Lbr030                               #  930: 4655ff

            .balign      4
.Lrel090:   .word        sdk_hostap_handle_timer               #  934: 00000000
.Llit006:   .word        0x00002710                            #  938: 10270000
.Llit007:   .word        0x00020000                            #  93c: 00000200
.Lrel091:   .word        free                                  #  940: 00000000
.Lrel092:   .word        sdk_ieee80211_send_mgmt               #  944: 00000000
.Lrel093:   .word        sdk_cnx_node_search                   #  948: 00000000
.Lrel094:   .word        sdk_cnx_node_alloc                    #  94c: 00000000
.Lrel095:   .word        memcpy                                #  950: 00000000
.Lrel096:   .word        sdk_ieee80211_psq_init                #  954: 00000000
.Lrel097:   .word        sdk_os_timer_disarm                   #  958: 00000000
.Lrel098:   .word        sdk_os_timer_setfn                    #  95c: 00000000
.Lrel099:   .word        sdk_os_timer_arm                      #  960: 00000000

# Function @ .irom0.text+0x964
# Local variables/stack:
#     (local0):  word      @ -0x20
#     (local1):  word      @ -0x1c
#     (local2):  word      @ -0x18
#     (local3):  word      @ -0x14
#     (local4):  word      @ -0x10
#     (local5):  word[3]   @ -0xc
.literal_position
.Lfunc007:  addi         a1, a1, -32 /* (local0) */            #  964: 12c1e0
            s32i.n       a12, a1, 20 /* a12 -> [(local5)] */   #  967: c951
            s32i.n       a0, a1, 12 /* a0 -> [(local3)] */     #  969: 0931
            l8ui         a0, a2, 76 /* [arg0+0x4c] */          #  96b: 02024c
            mov.n        a12, a2 /* arg0 */                    #  96e: cd02
            bnei         a0, 2, .Lbr059                        #  970: 662018
            l32i         a2, a2, 84 /* [arg0+0x54] */          #  973: 222215
            beqz.n       a2, .Lbr058                           #  976: 8c92
            movi         a0, .Lrel091 /* free */               #  978: 01f2ff
            callx0       a0 /* free */                         #  97b: c00000
            movi.n       a2, 0 /* 0x00000000 */                #  97e: 0c02
            s32i         a2, a12, 84 /* 0x00000000 -> [arg0+0x54] */ #  980: 226c15
.Lbr058:    l32i.n       a12, a1, 20 /* [(local5)] */          #  983: c851
            l32i.n       a0, a1, 12 /* [(local3)] */           #  985: 0831
            addi         a1, a1, 32 /* (top of frame) */       #  987: 12c120
            ret.n                                              #  98a: 0df0
.Lbr059:    s32i.n       a3, a1, 8 /* arg1 -> [(local2)] */    #  98c: 3921
            bnei         a6, 1, .Lbr058                        #  98e: 6616f1
            addi.n       a4, a6, 1 /* arg4+0x1 */              #  991: 1b46
            movi         a3, 176 /* 0x000000b0 */              #  993: 32a0b0
            movi         a0, .Lrel092 /* sdk_ieee80211_send_mgmt */ #  996: 01ebff
            callx0       a0 /* sdk_ieee80211_send_mgmt */      #  999: c00000
            l32i.n       a2, a1, 8 /* [(local2)] */            #  99c: 2821
            addi.n       a2, a2, 10 /* [(local2)]+0xa */       #  99e: ab22
            s32i.n       a2, a1, 4 /* [(local2)]+0xa -> [(local1)] */ #  9a0: 2911
            movi         a0, .Lrel093 /* sdk_cnx_node_search */ #  9a2: 01e9ff
            callx0       a0 /* sdk_cnx_node_search */          #  9a5: c00000
            s32i.n       a2, a1, 16 /* a2 -> [(local4)] */     #  9a8: 2941
            bnez.n       a2, .Lbr060                           #  9aa: ccb2
            l32i.n       a2, a1, 4 /* [(local1)] */            #  9ac: 2811
            movi         a0, .Lrel094 /* sdk_cnx_node_alloc */ #  9ae: 01e7ff
            callx0       a0 /* sdk_cnx_node_alloc */           #  9b1: c00000
            s32i.n       a2, a1, 16 /* a2 -> [(local4)] */     #  9b4: 2941
            beqz         a2, .Lbr058                           #  9b6: 1692fc
.Lbr060:    l32i.n       a3, a1, 4 /* [(local1)] */            #  9b9: 3811
            l32i.n       a2, a1, 16 /* [(local4)] */           #  9bb: 2841
            movi.n       a4, 6 /* 0x00000006 */                #  9bd: 0c64
            movi         a0, .Lrel095 /* memcpy */             #  9bf: 01e4ff
            callx0       a0 /* memcpy */                       #  9c2: c00000
            l32i.n       a2, a1, 16 /* [(local4)] */           #  9c5: 2841
            movi         a3, 192 /* 0x000000c0 */              #  9c7: 32a0c0
            add.n        a2, a2, a3 /* [(local4)]+0xc0 */      #  9ca: 3a22
            movi.n       a3, 0 /* 0x00000000 */                #  9cc: 0c03
            movi         a0, .Lrel096 /* sdk_ieee80211_psq_init */ #  9ce: 01e1ff
            callx0       a0 /* sdk_ieee80211_psq_init */       #  9d1: c00000
            l32i.n       a2, a1, 16 /* [(local4)] */           #  9d4: 2841
            movi         a3, 236 /* 0x000000ec */              #  9d6: 32a0ec
            add.n        a2, a2, a3 /* [(local4)]+0xec */      #  9d9: 3a22
            s32i.n       a2, a1, 0 /* [(local4)]+0xec -> [(local0)] */ #  9db: 2901
            movi         a0, .Lrel097 /* sdk_os_timer_disarm */ #  9dd: 01deff
            callx0       a0 /* sdk_os_timer_disarm */          #  9e0: c00000
            l32i.n       a2, a1, 0 /* [(local0)] */            #  9e3: 2801
            movi         a3, .Lrel090 /* sdk_hostap_handle_timer */ #  9e5: 31d3ff
            l32i.n       a4, a1, 16 /* [(local4)] */           #  9e8: 4841
            movi         a0, .Lrel098 /* sdk_os_timer_setfn */ #  9ea: 01dcff
            callx0       a0 /* sdk_os_timer_setfn */           #  9ed: c00000
            l32i.n       a2, a1, 0 /* [(local0)] */            #  9f0: 2801
            movi         a3, .Llit006 /* 0x00002710 */         #  9f2: 31d1ff
            movi.n       a4, 1 /* 0x00000001 */                #  9f5: 0c14
            movi         a0, .Lrel099 /* sdk_os_timer_arm */   #  9f7: 01daff
            callx0       a0 /* sdk_os_timer_arm */             #  9fa: c00000
            l32i.n       a9, a1, 16 /* [(local4)] */           #  9fd: 9841
            movi.n       a11, -17 /* 0xffffffef */             #  9ff: 6cfb
            movi.n       a10, -2 /* 0xfffffffe */              #  a01: 7cea
            movi.n       a3, 1 /* 0x00000001 */                #  a03: 0c13
            l32i.n       a2, a1, 16 /* [(local4)] */           #  a05: 2841
            movi         a7, .Llit007 /* 0x00020000 */         #  a07: 71cdff
            l32i.n       a6, a2, 8 /* [[(local4)]+0x8] */      #  a0a: 6822
            movi.n       a8, 32 /* 0x00000020 */               #  a0c: 2c08
            or           a6, a6, a8                            #  a0e: 806620
            or           a6, a6, a7                            #  a11: 706620
            or           a3, a6, a3                            #  a14: 303620
            and          a10, a6, a10                          #  a17: a0a610
            s32i.n       a6, a2, 8 /* a6 -> [[(local4)]+0x8] */ #  a1a: 6922
            l8ui         a0, a12, 76 /* [arg0+0x4c] */         #  a1c: 020c4c
            and          a10, a10, a11                         #  a1f: b0aa10
            addi         a0, a0, -3 /* [arg0+0x4c]-0x3 */      #  a22: 02c0fd
            moveqz       a3, a10, a0                           #  a25: 003a83
            s32i.n       a3, a9, 8 /* a3 -> [[(local4)]+0x8] */ #  a28: 3929
            j            .Lbr058                               #  a2a: 46d5ff

            .balign      4
.Lrel100:   .word        .rodata                               #  a30: 00000000

# Function @ .irom0.text+0xa34
.literal_position
.Lfunc008:  bnez.n       a3, .Lbr063                           #  a34: ec43
            beqz.n       a2, .Lbr063                           #  a36: ac22
            l8ui         a3, a2, 1 /* [arg0+0x1] */            #  a38: 320201
            movi         a6, .Lrel100 /* .Ldata004 */          #  a3b: 61fdff
            blti         a3, 1, .Lbr062                        #  a3e: a61316
            l32i.n       a6, a6, 0 /* [.Ldata004] */           #  a41: 6806
            movi.n       a8, 22 /* 0x00000016 */               #  a43: 1c68
            add.n        a7, a3, a2                            #  a45: 2a73
.Lbr061:    l8ui         a3, a2, 2                             #  a47: 320202
            extui        a3, a3, 0, 7                          #  a4a: 303064
            blt          a8, a3, .Lbr063                       #  a4d: 37280b
            bbc          a6, a3, .Lbr063                       #  a50: 375608
            addi.n       a2, a2, 1                             #  a53: 1b22
            bne          a2, a7, .Lbr061                       #  a55: 7792ee
.Lbr062:    movi.n       a2, 1 /* 0x00000001 */                #  a58: 0c12
            ret.n         /* 0x00000001 */                     #  a5a: 0df0
.Lbr063:    movi.n       a2, 0 /* 0x00000000 */                #  a5c: 0c02
            ret.n         /* 0x00000000 */                     #  a5e: 0df0

.Lrel101:   .word        sdk_g_ic                              #  a60: 00000000
.Lrel102:   .word        sdk_g_ic                              #  a64: 00000000
.Lrel103:   .word        sdk_g_ic+0x280                        #  a68: 00000000
.Llit008:   .word        0x01f25000                            #  a6c: 0050f201
.Lrel104:   .word        sdk_g_ic+0x28c                        #  a70: 00000000
.Lrel105:   .word        sdk_g_ic                              #  a74: 00000000
.Lrel106:   .word        sdk_g_ic                              #  a78: 00000000
.Lrel107:   .word        memcmp                                #  a7c: 00000000
.Lrel108:   .word        memcmp                                #  a80: 00000000
.Lrel109:   .word        sdk_cnx_node_leave                    #  a84: 00000000
.Lrel110:   .word        sdk_ieee80211_parse_beacon            #  a88: 00000000
.Lrel111:   .word        memcmp                                #  a8c: 00000000
.Lrel112:   .word        memcpy                                #  a90: 00000000
.Lrel113:   .word        memcpy                                #  a94: 00000000
.Lrel114:   .word        memcmp                                #  a98: 00000000
.Lrel115:   .word        sdk_ieee80211_send_proberesp          #  a9c: 00000000
.Lrel116:   .word        sdk_ieee80211_setup_rates             #  aa0: 00000000
.Lrel117:   .word        sdk_cnx_node_join                     #  aa4: 00000000

# Function @ .irom0.text+0xaa8
# Local variables/stack:
#     (local0):  word      @ -0x48
#     (local1):  word      @ -0x44
#     (local2):  word      @ -0x40
#     (local3):  word      @ -0x3c
#     (local4):  word      @ -0x38
#     (local5):  word      @ -0x34
#     (local6):  word      @ -0x30
#     (local7):  word      @ -0x2c
#     (local8):  word      @ -0x28
#     (local9):  word      @ -0x24
#     (local10): word      @ -0x20
#     (local11): word      @ -0x1c
#     (local12): word      @ -0x18
#     (local13): word      @ -0x14
#     (local14): word[4]   @ -0x10
.literal_position
.Lfunc009:  movi         a10, .Lrel101 /* sdk_g_ic */          #  aa8: a1eeff
            movi.n       a11, 50 /* 0x00000032 */              #  aab: 3c2b
            movi         a7, 144 /* 0x00000090 */              #  aad: 72a090
            sub          a1, a1, a7 /* (FP)-0x90 */            #  ab0: 7011c0
            s32i         a0, a1, 100 /* a0 -> [(local7)] */    #  ab3: 026119
            l32i.n       a7, a2, 0 /* [arg0] */                #  ab6: 7802
            s32i         a15, a1, 116 /* a15 -> [(local11)] */ #  ab8: f2611d
            s32i         a13, a1, 108 /* a13 -> [(local9)] */  #  abb: d2611b
            s32i         a12, a1, 104 /* a12 -> [(local8)] */  #  abe: c2611a
            s32i         a14, a1, 112 /* a14 -> [(local10)] */ #  ac1: e2611c
            mov.n        a12, a2 /* arg0 */                    #  ac4: cd02
            l32i         a14, a2, 136 /* [arg0+0x88] */        #  ac6: e22222
            mov.n        a13, a4 /* arg2 */                    #  ac9: dd04
            l32i.n       a15, a3, 4 /* [arg1+0x4] */           #  acb: f813
            mov.n        a4, a5 /* arg3 */                     #  acd: 4d05
            movi.n       a5, 48 /* 0x00000030 */               #  acf: 3c05
            l32i.n       a15, a15, 4 /* [[arg1+0x4]+0x4] */    #  ad1: f81f
            l16ui        a2, a3, 22 /* [arg1+0x16] */          #  ad3: 22130b
            addi         a0, a15, 24 /* [[arg1+0x4]+0x4]+0x18 */ #  ad6: 02cf18
            add.n        a2, a2, a15                           #  ad9: fa22
            addi         a2, a2, 24                            #  adb: 22c218
            beqz         a13, .Lbr066                          #  ade: 167d04
            beqi         a13, 16, .Lbr065                      #  ae1: 26bd2e
            beqi         a13, 32, .Lbr066                      #  ae4: 26cd41
            beq          a13, a5, .Lbr065                      #  ae7: 571d28
            bnei         a13, 64, .Lbr064                      #  aea: 66dd02
            j            .Lbr068                               #  aed: 062500
.Lbr064:    movi.n       a5, 80 /* 0x00000050 */               #  af0: 5c05
            addi         a8, a13, -80 /* arg2-0x50 */          #  af2: 82cdb0
            beqz         a8, .Lbr075                           #  af5: 16580d
            addi         a9, a13, -128 /* arg2-0x80 */         #  af8: 92cd80
            beqz         a9, .Lbr076                           #  afb: 16490d
            movi         a11, 160 /* 0x000000a0 */             #  afe: b2a0a0
            beq          a13, a11, .Lbr067                     #  b01: b71d4d
            movi         a3, 176 /* 0x000000b0 */              #  b04: 32a0b0
            sub          a3, a13, a3 /* arg2-0xb0 */           #  b07: 303dc0
            beqz         a3, .Lbr079                           #  b0a: 16f30d
            movi         a4, 192 /* 0x000000c0 */              #  b0d: 42a0c0
            beq          a13, a4, .Lbr067                      #  b10: 471d3e
.Lbr065:    l32i         a12, a1, 104 /* [(local8)] */         #  b13: c2211a
            l32i         a13, a1, 108 /* [(local9)] */         #  b16: d2211b
            l32i         a14, a1, 112 /* [(local10)] */        #  b19: e2211c
            l32i         a15, a1, 116 /* [(local11)] */        #  b1c: f2211d
            movi         a2, 144 /* 0x00000090 */              #  b1f: 22a090
            l32i         a0, a1, 100 /* [(local7)] */          #  b22: 022119
            add.n        a1, a1, a2 /* (top of frame) */       #  b25: 2a11
            ret.n         /* 0x00000090 */                     #  b27: 0df0
.Lbr066:    l32i.n       a5, a12, 60 /* [arg0+0x3c] */         #  b29: 58fc
            s32i         a2, a1, 80 /* a2 -> [(local2)] */     #  b2b: 226114
            bnei         a5, 5, .Lbr065                        #  b2e: 6655e1
            addi         a3, a7, 41 /* [arg0]+0x29 */          #  b31: 32c729
            addi         a2, a15, 16 /* [[arg1+0x4]+0x4]+0x10 */ #  b34: 22cf10
            movi.n       a4, 6 /* 0x00000006 */                #  b37: 0c64
            movi         a0, .Lrel107 /* memcmp */             #  b39: 01d0ff
            callx0       a0 /* memcmp */                       #  b3c: c00000
            bnez         a2, .Lbr065                           #  b3f: 5602fd
            addi         a6, a13, -32 /* arg2-0x20 */          #  b42: 62cde0
            bnez         a6, .Lbr086                           #  b45: 56a614
            movi.n       a0, 1 /* 0x00000001 */                #  b48: 0c10
            movi.n       a7, 48 /* 0x00000030 */               #  b4a: 3c07
            s32i         a7, a1, 88 /* 0x00000030 -> [(local4)] */ #  b4c: 726116
            j            .Lbr087                               #  b4f: c65100
.Lbr067:    s32i         a2, a1, 80 /* a2 -> [(local2)] */     #  b52: 226114
            l32i.n       a8, a12, 60 /* [arg0+0x3c] */         #  b55: 88fc
            s32i         a0, a1, 128 /* [[arg1+0x4]+0x4]+0x18 -> [(local14)] */ #  b57: 026120
            bnei         a8, 5, .Lbr065                        #  b5a: 6658b5
            addi.n       a2, a15, 4 /* [[arg1+0x4]+0x4]+0x4 */ #  b5d: 4b2f
            addi         a3, a7, 41 /* [arg0]+0x29 */          #  b5f: 32c729
            movi.n       a4, 6 /* 0x00000006 */                #  b62: 0c64
            mov.n        a13, a0 /* [[arg1+0x4]+0x4]+0x18 */   #  b64: dd00
            movi         a0, .Lrel108 /* memcmp */             #  b66: 01c6ff
            callx0       a0 /* memcmp */                       #  b69: c00000
            bnez         a2, .Lbr065                           #  b6c: 5632fa
            l32i         a9, a1, 80 /* [(local2)] */           #  b6f: 922114
            sub          a9, a9, a13                           #  b72: d099c0
            blti         a9, 2, .Lbr065                        #  b75: a6299a
            mov.n        a3, a14 /* [arg0+0x88] */             #  b78: 3d0e
            mov.n        a2, a12 /* arg0 */                    #  b7a: 2d0c
            movi         a0, .Lrel109 /* sdk_cnx_node_leave */ #  b7c: 01c2ff
            callx0       a0 /* sdk_cnx_node_leave */           #  b7f: c00000
            j            .Lbr065                               #  b82: 46e3ff
.Lbr068:    l32i.n       a13, a12, 60 /* [arg0+0x3c] */        #  b85: d8fc
            sub          a14, a2, a15                          #  b87: f0e2c0
            bnei         a13, 5, .Lbr065                       #  b8a: 665d85
            addi         a14, a14, -24                         #  b8d: e2cee8
            bgei         a14, 2, .Lbr069                       #  b90: e62e02
            j            .Lbr081                               #  b93: c62e00
.Lbr069:    movi.n       a13, 0 /* 0x00000000 */               #  b96: 0c0d
            movi.n       a3, 0 /* 0x00000000 */                #  b98: 0c03
            sub          a6, a2, a0                            #  b9a: 0062c0
            movi.n       a14, 0 /* 0x00000000 */               #  b9d: 0c0e
.Lbr070:    l8ui         a5, a0, 1                             #  b9f: 520001
            addi.n       a4, a5, 2                             #  ba2: 2b45
            bge          a6, a4, .Lbr071                       #  ba4: 47a602
            j            .Lbr065                               #  ba7: 06daff
.Lbr071:    l8ui         a4, a0, 0                             #  baa: 420000
            beqz.n       a4, .Lbr073                           #  bad: 8ce4
            beqi         a4, 1, .Lbr072                        #  baf: 261407
            bne          a4, a11, .Lbr074                      #  bb2: b7940b
            mov.n        a14, a0                               #  bb5: ed00
            j            .Lbr074                               #  bb7: 860100
.Lbr072:    mov.n        a13, a0                               #  bba: dd00
            j            .Lbr074                               #  bbc: 460000
.Lbr073:    mov.n        a3, a0                                #  bbf: 3d00
.Lbr074:    add.n        a0, a5, a0                            #  bc1: 0a05
            addi.n       a0, a0, 2                             #  bc3: 2b00
            sub          a6, a2, a0                            #  bc5: 0062c0
            bgei         a6, 2, .Lbr070                        #  bc8: e626d3
            j            .Lbr082                               #  bcb: 462200
.Lbr075:    movi.n       a4, 1 /* 0x00000001 */                #  bce: 0c14
            j            .Lbr077                               #  bd0: 460000
.Lbr076:    movi.n       a4, 0 /* 0x00000000 */                #  bd3: 0c04
.Lbr077:    l32i.n       a2, a10, 28 /* [sdk_g_ic+0x1c] */     #  bd5: 287a
            sub          a6, a13, a5 /* arg2-0x50 */           #  bd7: 506dc0
            bbsi         a2, 7, .Lbr078                        #  bda: 77e202
            beqz         a6, .Lbr065                           #  bdd: 1626f3
.Lbr078:    mov.n        a2, a3 /* arg1 */                     #  be0: 2d03
            mov.n        a3, a1 /* (FP)-0x90 */                #  be2: 3d01
            movi         a0, .Lrel110 /* .Lrel110 */           #  be4: 01a9ff
            callx0       a0                                    #  be7: c00000
            j            .Lbr065                               #  bea: 46c9ff
.Lbr079:    s32i         a4, a1, 96 /* arg3 -> [(local6)] */   #  bed: 426118
            s32i         a6, a1, 92 /* arg4 -> [(local5)] */   #  bf0: 626117
            s32i         a2, a1, 80 /* a2 -> [(local2)] */     #  bf3: 226114
            l32i.n       a8, a12, 60 /* [arg0+0x3c] */         #  bf6: 88fc
            s32i         a0, a1, 128 /* [[arg1+0x4]+0x4]+0x18 -> [(local14)] */ #  bf8: 026120
            addi         a8, a8, -5 /* [arg0+0x3c]-0x5 */      #  bfb: 82c8fb
            bnez         a8, .Lbr065                           #  bfe: 5618f1
            addi         a3, a7, 41 /* [arg0]+0x29 */          #  c01: 32c729
            addi         a2, a15, 16 /* [[arg1+0x4]+0x4]+0x10 */ #  c04: 22cf10
            movi.n       a4, 6 /* 0x00000006 */                #  c07: 0c64
            mov.n        a13, a0 /* [[arg1+0x4]+0x4]+0x18 */   #  c09: dd00
            movi         a0, .Lrel111 /* memcmp */             #  c0b: 01a0ff
            callx0       a0 /* memcmp */                       #  c0e: c00000
            bnez         a2, .Lbr065                           #  c11: 56e2ef
            l32i         a9, a1, 80 /* [(local2)] */           #  c14: 922114
            sub          a9, a9, a13                           #  c17: d099c0
            bgei         a9, 6, .Lbr080                        #  c1a: e66902
            j            .Lbr065                               #  c1d: 86bcff
.Lbr080:    l16ui        a0, a13, 0 /* [[[arg1+0x4]+0x4]+0x18] */ #  c20: 021d00
            movi         a10, .Lrel102 /* sdk_g_ic */          #  c23: a190ff
            l16ui        a6, a13, 2 /* [[[arg1+0x4]+0x4]+0x1a] */ #  c26: 621d01
            l32i.n       a10, a10, 28 /* [sdk_g_ic+0x1c] */    #  c29: a87a
            l16ui        a7, a13, 4 /* [[[arg1+0x4]+0x4]+0x1c] */ #  c2b: 721d02
            extui        a10, a10, 26, 1                       #  c2e: a0aa05
            bnez         a10, .Lbr065                          #  c31: 56eaed
            addi.n       a11, a0, -1 /* [[[arg1+0x4]+0x4]+0x18]-0x1 */ #  c34: 0bb0
            l32i         a13, a12, 144 /* [arg0+0x90] */       #  c36: d22c24
            s32i         a13, a12, 136 /* [arg0+0x90] -> [arg0+0x88] */ #  c39: d26c22
            beqz         a11, .Lbr065                          #  c3c: 163bed
            bnez         a0, .Lbr065                           #  c3f: 5600ed
            mov.n        a3, a15 /* [[arg1+0x4]+0x4] */        #  c42: 3d0f
            mov.n        a2, a12 /* arg0 */                    #  c44: 2d0c
            l32i         a4, a1, 96 /* [(local6)] */           #  c46: 422118
            l32i         a5, a1, 92 /* [(local5)] */           #  c49: 522117
            call0        .Lfunc007                             #  c4c: 45d1ff
            j            .Lbr065                               #  c4f: 06b0ff
.Lbr081:    movi.n       a3, 0 /* 0x00000000 */                #  c52: 0c03
            movi.n       a13, 0 /* 0x00000000 */               #  c54: 0c0d
            movi.n       a14, 0 /* 0x00000000 */               #  c56: 0c0e
.Lbr082:    beqz         a13, .Lbr065                          #  c58: 167deb
            l8ui         a2, a13, 1                            #  c5b: 220d01
            bltui        a2, 16, .Lbr083                       #  c5e: b6b202
            j            .Lbr065                               #  c61: 86abff
.Lbr083:    beqz.n       a14, .Lbr084                          #  c64: 8cce
            l8ui         a4, a14, 1                            #  c66: 420e01
            movi.n       a0, 15 /* 0x0000000f */               #  c69: 0cf0
            sub          a0, a0, a2                            #  c6b: 2000c0
            bge          a0, a4, .Lbr084                       #  c6e: 47a002
            j            .Lbr065                               #  c71: 86a7ff
.Lbr084:    beqz         a3, .Lbr065                           #  c74: 16b3e9
            l8ui         a0, a3, 1                             #  c77: 020301
            movi.n       a2, 32 /* 0x00000020 */               #  c7a: 2c02
            bgeu         a2, a0, .Lbr085                       #  c7c: 07b202
            j            .Lbr065                               #  c7f: 06a4ff
.Lbr085:    movi         a4, .Lrel103 /* sdk_g_ic+0x280 */     #  c82: 4179ff
            l8ui         a4, a4, 143 /* [sdk_g_ic+0x30f] */    #  c85: 42048f
            addi.n       a4, a4, -1 /* [sdk_g_ic+0x30f]-0x1 */ #  c88: 0b44
            bnez         a4, .Lbr103                           #  c8a: 569411
            bnez         a0, .Lbr104                           #  c8d: 568011
            j            .Lbr065                               #  c90: c69fff
.Lbr086:    movi.n       a0, 0 /* 0x00000000 */                #  c93: 0c00
            movi.n       a5, 16 /* 0x00000010 */               #  c95: 1c05
            s32i         a5, a1, 88 /* 0x00000010 -> [(local4)] */ #  c97: 526116
.Lbr087:    movi.n       a8, 10 /* 0x0000000a */               #  c9a: 0ca8
            movi.n       a7, 4 /* 0x00000004 */                #  c9c: 0c47
            l32i         a6, a1, 80 /* [(local2)] */           #  c9e: 622114
            movnez       a7, a8, a0                            #  ca1: 007893
            sub          a6, a6, a15                           #  ca4: f066c0
            addi         a6, a6, -24                           #  ca7: 62c6e8
            bge          a6, a7, .Lbr088                       #  caa: 77a602
            j            .Lbr065                               #  cad: 8698ff
.Lbr088:    movi         a11, 221 /* 0x000000dd */             #  cb0: b2a0dd
            l32i         a6, a1, 80 /* [(local2)] */           #  cb3: 622114
            addi         a7, a15, 34 /* [[arg1+0x4]+0x4]+0x22 */ #  cb6: 72cf22
            addi         a13, a15, 28 /* [[arg1+0x4]+0x4]+0x1c */ #  cb9: d2cf1c
            movnez       a13, a7, a0                           #  cbc: 00d793
            sub          a6, a6, a13                           #  cbf: d066c0
            bgei         a6, 2, .Lbr089                        #  cc2: e62602
            j            .Lbr107                               #  cc5: c64b00
.Lbr089:    movi.n       a0, 0 /* 0x00000000 */                #  cc8: 0c00
            movi.n       a7, 0 /* 0x00000000 */                #  cca: 0c07
            addi         a15, a14, 39 /* [arg0+0x88]+0x27 */   #  ccc: f2ce27
            movi.n       a10, 0 /* 0x00000000 */               #  ccf: 0c0a
            s32i         a10, a1, 72 /* 0x00000000 -> [(local0)] */ #  cd1: a26112
            s32i         a15, a1, 84 /* [arg0+0x88]+0x27 -> [(local3)] */ #  cd4: f26115
            movi.n       a15, 0 /* 0x00000000 */               #  cd7: 0c0f
.Lbr090:    l8ui         a5, a13, 1                            #  cd9: 520d01
            l8ui         a3, a13, 0                            #  cdc: 320d00
            addi.n       a10, a5, 2                            #  cdf: 2ba5
            bge          a6, a10, .Lbr091                      #  ce1: a7a602
            j            .Lbr065                               #  ce4: c68aff
.Lbr091:    beqz         a3, .Lbr100                           #  ce7: 16630a
            bnei         a3, 1, .Lbr092                        #  cea: 661302
            j            .Lbr099                               #  ced: c62600
.Lbr092:    movi.n       a2, 45 /* 0x0000002d */               #  cf0: 2cd2
            bne          a3, a2, .Lbr093                       #  cf2: 279302
            j            .Lbr098                               #  cf5: 862300
.Lbr093:    s32i         a7, a1, 120 /* a7 -> [(local12)] */   #  cf8: 72611e
            s32i         a0, a1, 124 /* a0 -> [(local13)] */   #  cfb: 02611f
            movi.n       a4, 48 /* 0x00000030 */               #  cfe: 3c04
            beq          a3, a4, .Lbr097                       #  d00: 471363
            movi.n       a6, 50 /* 0x00000032 */               #  d03: 3c26
            beq          a3, a6, .Lbr096                       #  d05: 671359
            beq          a3, a11, .Lbr094                      #  d08: b71302
            j            .Lbr101                               #  d0b: 462100
.Lbr094:    movi.n       a3, 0 /* 0x00000000 */                #  d0e: 0c03
            bltui        a5, 4, .Lbr095                        #  d10: b64525
            l8ui         a2, a13, 5                            #  d13: 220d05
            l8ui         a9, a13, 3                            #  d16: 920d03
            l8ui         a8, a13, 2                            #  d19: 820d02
            slli         a9, a9, 8                             #  d1c: 809911
            or           a8, a8, a9                            #  d1f: 908820
            l8ui         a9, a13, 4                            #  d22: 920d04
            slli         a2, a2, 24                            #  d25: 802201
            slli         a9, a9, 16                            #  d28: 009911
            or           a9, a9, a2                            #  d2b: 209920
            or           a8, a8, a9                            #  d2e: 908820
            movi         a9, .Llit008 /* .Llit008 */           #  d31: 914eff
            bne          a8, a9, .Lbr095                       #  d34: 979801
            movi.n       a3, 1 /* 0x00000001 */                #  d37: 0c13
.Lbr095:    s32i         a7, a1, 120 /* a7 -> [(local12)] */   #  d39: 72611e
            s32i         a0, a1, 124 /* a0 -> [(local13)] */   #  d3c: 02611f
            beqz         a3, .Lbr101                           #  d3f: 161305
            l32i         a2, a1, 84 /* [(local3)] */           #  d42: 222115
            mov.n        a3, a13                               #  d45: 3d0d
            extui        a4, a10, 0, 8                         #  d47: a04074
            s8i          a4, a14, 38 /* a4 -> [[arg0+0x88]+0x26] */ #  d4a: 424e26
            movi         a0, .Lrel112 /* .Lrel112 */           #  d4d: 0150ff
            callx0       a0                                    #  d50: c00000
            l32i         a0, a1, 124 /* [(local13)] */         #  d53: 02211f
            l32i         a7, a1, 120 /* [(local12)] */         #  d56: 72211e
            movi         a11, 221 /* 0x000000dd */             #  d59: b2a0dd
            l8ui         a5, a13, 1                            #  d5c: 520d01
            j            .Lbr101                               #  d5f: 460c00
.Lbr096:    mov.n        a15, a13                              #  d62: fd0d
            j            .Lbr101                               #  d64: 060b00
.Lbr097:    l32i         a2, a1, 84 /* [(local3)] */           #  d67: 222115
            mov.n        a3, a13                               #  d6a: 3d0d
            extui        a4, a10, 0, 8                         #  d6c: a04074
            s8i          a4, a14, 38 /* a4 -> [[arg0+0x88]+0x26] */ #  d6f: 424e26
            movi         a0, .Lrel113 /* memcpy */             #  d72: 0148ff
            callx0       a0 /* memcpy */                       #  d75: c00000
            l32i         a0, a1, 124 /* [(local13)] */         #  d78: 02211f
            l32i         a7, a1, 120 /* [(local12)] */         #  d7b: 72211e
            movi         a11, 221 /* 0x000000dd */             #  d7e: b2a0dd
            l8ui         a5, a13, 1                            #  d81: 520d01
            j            .Lbr101                               #  d84: 060300
.Lbr098:    mov.n        a7, a13                               #  d87: 7d0d
            j            .Lbr101                               #  d89: c60100
.Lbr099:    mov.n        a0, a13                               #  d8c: 0d0d
            j            .Lbr101                               #  d8e: 860000
.Lbr100:    s32i         a13, a1, 72 /* a13 -> [(local0)] */   #  d91: d26112
.Lbr101:    l32i         a6, a1, 80 /* [(local2)] */           #  d94: 622114
            add.n        a13, a5, a13                          #  d97: dad5
            addi.n       a13, a13, 2                           #  d99: 2bdd
            sub          a6, a6, a13                           #  d9b: d066c0
            blti         a6, 2, .Lbr102                        #  d9e: a62602
            j            .Lbr090                               #  da1: 06cdff
.Lbr102:    j            .Lbr108                               #  da4: c61600
.Lbr103:    beqz.n       a0, .Lbr105                           #  da7: ac40
.Lbr104:    s32i         a0, a1, 76 /* a0 -> [(local1)] */     #  da9: 026113
            l32i         a2, a10, 0x288 /* [sdk_g_ic+0x288] */ #  dac: 222aa2
            s32i         a3, a1, 72 /* a3 -> [(local0)] */     #  daf: 326112
            sub          a2, a2, a0                            #  db2: 0022c0
            bnez         a2, .Lbr065                           #  db5: 56a2d5
            addi.n       a2, a3, 2                             #  db8: 2b23
            l32i         a4, a1, 76 /* [(local1)] */           #  dba: 422113
            movi         a3, .Lrel104 /* sdk_g_ic+0x28c */     #  dbd: 312cff
            movi         a0, .Lrel114 /* memcmp */             #  dc0: 0136ff
            callx0       a0 /* memcmp */                       #  dc3: c00000
            movi         a10, .Lrel105 /* sdk_g_ic */          #  dc6: a12bff
            l32i         a0, a1, 76 /* [(local1)] */           #  dc9: 022113
            bnez         a2, .Lbr065                           #  dcc: 5632d4
.Lbr105:    l32i.n       a3, a10, 28 /* [sdk_g_ic+0x1c] */     #  dcf: 387a
            bbci         a3, 27, .Lbr106                       #  dd1: b77302
            beqz         a0, .Lbr065                           #  dd4: 16b0d3
.Lbr106:    mov.n        a3, a14                               #  dd7: 3d0e
            mov.n        a2, a13                               #  dd9: 2d0d
            l32i         a4, a12, 144 /* [arg0+0x90] */        #  ddb: 422c24
            s32i         a4, a12, 136 /* [arg0+0x90] -> [arg0+0x88] */ #  dde: 426c22
            call0        .Lfunc008                             #  de1: 05c5ff
            addi.n       a3, a15, 10 /* [[arg1+0x4]+0x4]+0xa */ #  de4: ab3f
            mov.n        a4, a2                                #  de6: 4d02
            movi.n       a5, 1 /* 0x00000001 */                #  de8: 0c15
            mov.n        a2, a12 /* arg0 */                    #  dea: 2d0c
            movnez       a4, a5, a4                            #  dec: 404593
            movi         a0, .Lrel115 /* sdk_ieee80211_send_proberesp */ #  def: 012bff
            callx0       a0 /* sdk_ieee80211_send_proberesp */ #  df2: c00000
            j            .Lbr065                               #  df5: 8646ff
.Lbr107:    movi.n       a0, 0 /* 0x00000000 */                #  df8: 0c00
            movi.n       a15, 0 /* 0x00000000 */               #  dfa: 0c0f
            movi.n       a7, 0 /* 0x00000000 */                #  dfc: 0c07
            movi.n       a6, 0 /* 0x00000000 */                #  dfe: 0c06
            s32i         a6, a1, 72 /* 0x00000000 -> [(local0)] */ #  e00: 626112
.Lbr108:    beqz         a0, .Lbr065                           #  e03: 16c0d0
            l8ui         a2, a0, 1                             #  e06: 220001
            bltui        a2, 16, .Lbr109                       #  e09: b6b202
            j            .Lbr065                               #  e0c: c640ff
.Lbr109:    beqz.n       a15, .Lbr110                          #  e0f: 8ccf
            l8ui         a9, a15, 1                            #  e11: 920f01
            movi.n       a8, 15 /* 0x0000000f */               #  e14: 0cf8
            sub          a8, a8, a2                            #  e16: 2088c0
            bge          a8, a9, .Lbr110                       #  e19: 97a802
            j            .Lbr065                               #  e1c: c63cff
.Lbr110:    l32i         a9, a1, 72 /* [(local0)] */           #  e1f: 922112
            beqz         a9, .Lbr065                           #  e22: 16d9ce
            l8ui         a13, a9, 1 /* [[(local0)]+0x1] */     #  e25: d20901
            movi.n       a10, 32 /* 0x00000020 */              #  e28: 2c0a
            bgeu         a10, a13, .Lbr111                     #  e2a: d7ba02
            j            .Lbr065                               #  e2d: 8638ff
.Lbr111:    beqz.n       a7, .Lbr112                           #  e30: 9c47
            l8ui         a2, a7, 1                             #  e32: 220701
            movi.n       a4, 30 /* 0x0000001e */               #  e35: 1ce4
            l8ui         a5, a7, 0                             #  e37: 520700
            movi.n       a3, 26 /* 0x0000001a */               #  e3a: 1ca3
            sub          a5, a5, a11                           #  e3c: b055c0
            moveqz       a3, a4, a5                            #  e3f: 503483
            bgeu         a2, a3, .Lbr112                       #  e42: 37b202
            j            .Lbr065                               #  e45: 8632ff
.Lbr112:    mov.n        a4, a15                               #  e48: 4d0f
            mov.n        a2, a14 /* [arg0+0x88] */             #  e4a: 2d0e
            movi.n       a5, 15 /* 0x0000000f */               #  e4c: 0cf5
            mov.n        a3, a0                                #  e4e: 3d00
            movi         a0, .Lrel116 /* sdk_ieee80211_setup_rates */ #  e50: 0114ff
            callx0       a0 /* sdk_ieee80211_setup_rates */    #  e53: c00000
            extui        a0, a2, 0, 8                          #  e56: 200074
            extui        a6, a2, 7, 1                          #  e59: 206704
            bnez         a6, .Lbr065                           #  e5c: 5636cb
            movi         a7, .Lrel106 /* sdk_g_ic */           #  e5f: 7106ff
            l32i.n       a7, a7, 28 /* [sdk_g_ic+0x1c] */      #  e62: 7877
            bbci         a7, 5, .Lbr113                        #  e64: 576707
            movi.n       a8, 47 /* 0x0000002f */               #  e67: 2cf8
            bltu         a8, a0, .Lbr113                       #  e69: 073802
            j            .Lbr065                               #  e6c: c628ff
.Lbr113:    mov.n        a3, a14 /* [arg0+0x88] */             #  e6f: 3d0e
            mov.n        a2, a12 /* arg0 */                    #  e71: 2d0c
            l32i         a4, a1, 88 /* [(local4)] */           #  e73: 422116
            l32i         a9, a12, 144 /* [arg0+0x90] */        #  e76: 922c24
            s32i         a9, a12, 136 /* [arg0+0x90] -> [arg0+0x88] */ #  e79: 926c22
            movi         a0, .Lrel117 /* sdk_cnx_node_join */  #  e7c: 010aff
            callx0       a0 /* sdk_cnx_node_join */            #  e7f: c00000
            j            .Lbr065                               #  e82: 4623ff

            .balign      4
# Function @ .irom0.text+0xe88
# Local variables/stack:
#     (local0):  word[4]   @ -0x10
.literal_position
.Lfunc010:  addi         a1, a1, -16 /* (local0) */            #  e88: 12c1f0
            s32i.n       a0, a1, 0 /* a0 -> [(local0)] */      #  e8b: 0901
            beqi         a4, 128, .Lbr114                      #  e8d: 26e408
            movi         a0, 160 /* 0x000000a0 */              #  e90: 02a0a0
            bne          a4, a0, .Lbr114                       #  e93: 079402
            call0        .Lfunc011                             #  e96: c50200
.Lbr114:    l32i.n       a0, a1, 0 /* [(local0)] */            #  e99: 0801
            addi         a1, a1, 16 /* (top of frame) */       #  e9b: 12c110
            ret.n                                              #  e9e: 0df0

.Llit009:   .word        0xffff3fff                            #  ea0: ff3fffff
.Llit010:   .word        0x00010000                            #  ea4: 00000100
.Lrel118:   .word        sdk_g_ic                              #  ea8: 00000000
.Lrel119:   .word        sdk_ieee80211_send_nulldata           #  eac: 00000000
.Lrel120:   .word        sdk_ieee80211_set_tim                 #  eb0: 00000000
.Lrel121:   .word        sdk_ieee80211_set_tim                 #  eb4: 00000000
.Lrel122:   .word        sdk_chm_check_same_channel            #  eb8: 00000000
.Lrel123:   .word        sdk_ppTxPkt                           #  ebc: 00000000
.Lrel124:   .word        sdk_ieee80211_send_mgmt               #  ec0: 00000000

# Function @ .irom0.text+0xec4
# Local variables/stack:
#     (local0):  word      @ -0x10
#     (local1):  word      @ -0xc
#     (local2):  word      @ -0x8
#     (local3):  word      @ -0x4
.literal_position
.Lfunc011:  addi         a1, a1, -16 /* (local0) */            #  ec4: 12c1f0
            l32i         a6, a2, 136 /* [arg0+0x88] */         #  ec7: 622222
            s32i.n       a0, a1, 4 /* a0 -> [(local1)] */      #  eca: 0911
            s32i.n       a12, a1, 8 /* a12 -> [(local2)] */    #  ecc: c921
            l32i.n       a0, a3, 4 /* [arg1+0x4] */            #  ece: 0813
            mov.n        a12, a3 /* arg1 */                    #  ed0: cd03
            l32i.n       a0, a0, 4 /* [[arg1+0x4]+0x4] */      #  ed2: 0810
            beqz         a6, .Lbr124                           #  ed4: 16360b
            movi         a5, .Llit009 /* 0xffff3fff */         #  ed7: 51f2ff
            l16ui        a4, a6, 26 /* [[arg0+0x88]+0x1a] */   #  eda: 42160d
            and          a3, a4, a5                            #  edd: 503410
            bany         a4, a5, .Lbr115                       #  ee0: 578402
            j            .Lbr124                               #  ee3: 062900
.Lbr115:    l16ui        a7, a0, 2 /* [[[arg1+0x4]+0x4]+0x2] */ #  ee6: 721001
            extui        a7, a7, 0, 14                         #  ee9: 7070d4
            beq          a3, a7, .Lbr116                       #  eec: 771302
            j            .Lbr123                               #  eef: c62300
.Lbr116:    l32i         a0, a6, 204 /* [[arg0+0x88]+0xcc] */  #  ef2: 022633
            s32i.n       a6, a1, 12 /* [arg0+0x88] -> [(local3)] */ #  ef5: 6931
            bnez.n       a0, .Lbr117                           #  ef7: dc30
            mov.n        a12, a6 /* [arg0+0x88] */             #  ef9: cd06
            movi         a0, .Lrel119 /* sdk_ieee80211_send_nulldata */ #  efb: 01ecff
            callx0       a0 /* sdk_ieee80211_send_nulldata */  #  efe: c00000
            mov.n        a2, a12 /* [arg0+0x88] */             #  f01: 2d0c
            movi.n       a3, 0 /* 0x00000000 */                #  f03: 0c03
            movi         a0, .Lrel120 /* sdk_ieee80211_set_tim */ #  f05: 01eaff
            callx0       a0 /* sdk_ieee80211_set_tim */        #  f08: c00000
            j            .Lbr123                               #  f0b: c61c00
.Lbr117:    movi.n       a3, 0 /* 0x00000000 */                #  f0e: 0c03
            s32i.n       a0, a1, 0 /* [[arg0+0x88]+0xcc] -> [(local0)] */ #  f10: 0901
            s32i.n       a6, a1, 12 /* [arg0+0x88] -> [(local3)] */ #  f12: 6931
            l32i         a8, a6, 212 /* [[arg0+0x88]+0xd4] */  #  f14: 822635
            l32i         a5, a6, 192 /* [[arg0+0x88]+0xc0] */  #  f17: 522630
            addi.n       a8, a8, -1 /* [[arg0+0x88]+0xd4]-0x1 */ #  f1a: 0b88
            addi.n       a5, a5, -1 /* [[arg0+0x88]+0xc0]-0x1 */ #  f1c: 0b55
            s32i         a5, a6, 192 /* [[arg0+0x88]+0xc0]-0x1 -> [[arg0+0x88]+0xc0] */ #  f1e: 526630
            bnez.n       a5, .Lbr118                           #  f21: cc75
            s32i         a3, a6, 208 /* 0x00000000 -> [[arg0+0x88]+0xd0] */ #  f23: 326634
            s32i         a3, a6, 204 /* 0x00000000 -> [[arg0+0x88]+0xcc] */ #  f26: 326633
            j            .Lbr119                               #  f29: 860100
.Lbr118:    s32i.n       a0, a1, 0 /* [[arg0+0x88]+0xcc] -> [(local0)] */ #  f2c: 0901
            l32i.n       a7, a0, 28 /* [[[arg0+0x88]+0xcc]+0x1c] */ #  f2e: 7870
            s32i         a7, a6, 204 /* [[[arg0+0x88]+0xcc]+0x1c] -> [[arg0+0x88]+0xcc] */ #  f30: 726633
.Lbr119:    s32i         a8, a6, 212 /* [[arg0+0x88]+0xd4]-0x1 -> [[arg0+0x88]+0xd4] */ #  f33: 826635
            beqz.n       a5, .Lbr120                           #  f36: 9c95
            l32i.n       a10, a12, 32 /* [arg1+0x20] */        #  f38: a88c
            l32i.n       a11, a10, 0 /* [[arg1+0x20]] */       #  f3a: b80a
            movi         a0, .Llit010 /* 0x00010000 */         #  f3c: 01daff
            extui        a9, a11, 0, 6                         #  f3f: b09054
            srli         a11, a11, 6                           #  f42: b0b641
            or           a11, a11, a0                          #  f45: 00bb20
            slli         a11, a11, 6                           #  f48: a0bb11
            or           a9, a9, a11                           #  f4b: b09920
            s32i.n       a9, a10, 0 /* a9 -> [[arg1+0x20]] */  #  f4e: 990a
            j            .Lbr121                               #  f50: 460200
.Lbr120:    l32i.n       a2, a1, 12 /* [(local3)] */           #  f53: 2831
            movi.n       a3, 0 /* 0x00000000 */                #  f55: 0c03
            movi         a0, .Lrel121 /* sdk_ieee80211_set_tim */ #  f57: 01d7ff
            callx0       a0 /* sdk_ieee80211_set_tim */        #  f5a: c00000
.Lbr121:    movi         a0, .Lrel122 /* .Lrel122 */           #  f5d: 01d6ff
            callx0       a0                                    #  f60: c00000
            beqz.n       a2, .Lbr122                           #  f63: 8c92
            l32i.n       a2, a1, 0 /* [(local0)] */            #  f65: 2801
            movi         a0, .Lrel123 /* sdk_ppTxPkt */        #  f67: 01d5ff
            callx0       a0 /* sdk_ppTxPkt */                  #  f6a: c00000
            j            .Lbr123                               #  f6d: 460400
.Lbr122:    addi         a0, a12, 28 /* arg1+0x1c */           #  f70: 02cc1c
            movi         a2, .Lrel118 /* sdk_g_ic */           #  f73: 21cdff
            movi.n       a4, 0 /* 0x00000000 */                #  f76: 0c04
            l32i         a3, a2, 0x1c4 /* [sdk_g_ic+0x1c4] */  #  f78: 322271
            s32i.n       a4, a12, 28 /* 0x00000000 -> [arg1+0x1c] */ #  f7b: 497c
            s32i.n       a12, a3, 0 /* arg1 -> [[sdk_g_ic+0x1c4]] */ #  f7d: c903
            s32i         a0, a2, 0x1c4 /* arg1+0x1c -> [sdk_g_ic+0x1c4] */ #  f7f: 026271
.Lbr123:    l32i.n       a12, a1, 8 /* [(local2)] */           #  f82: c821
            l32i.n       a0, a1, 4 /* [(local1)] */            #  f84: 0811
            addi         a1, a1, 16 /* (top of frame) */       #  f86: 12c110
            ret.n                                              #  f89: 0df0
.Lbr124:    movi         a3, 192 /* 0x000000c0 */              #  f8b: 32a0c0
            movi.n       a4, 7 /* 0x00000007 */                #  f8e: 0c74
            movi         a0, .Lrel124 /* sdk_ieee80211_send_mgmt */ #  f90: 01ccff
            callx0       a0 /* sdk_ieee80211_send_mgmt */      #  f93: c00000
            j            .Lbr123                               #  f96: 06faff

            .balign      4
.Lrel125:   .word        sdk_g_ic                              #  f9c: 00000000
.Lrel126:   .word        .bss                                  #  fa0: 00000000
.Lrel127:   .word        sdk_info+0x18                         #  fa4: 00000000
.Lrel128:   .word        ethernetif_init                       #  fa8: 00000000
.Lrel129:   .word        sdk_info                              #  fac: 00000000
.Lrel130:   .word        tcpip_input                           #  fb0: 00000000
.Lrel131:   .word        sdk_g_ic                              #  fb4: 00000000
.Lrel132:   .word        sdk_g_ic+0x280                        #  fb8: 00000000
.Lrel133:   .word        sdk_NMIIrqIsOn                        #  fbc: 00000000
.Llit011:   .word        0x3feffe00                            #  fc0: 00feef3f
.Lrel134:   .word        sdk_g_ic                              #  fc4: 00000000
.Lrel135:   .word        sdk_NMIIrqIsOn                        #  fc8: 00000000
.Lrel136:   .word        sdk_g_ic+0x100                        #  fcc: 00000000
.Llit012:   .word        0x3feffe00                            #  fd0: 00feef3f
.Lrel137:   .word        sdk_g_ic                              #  fd4: 00000000
.Lrel138:   .word        .bss                                  #  fd8: 00000000
.Lrel139:   .word        malloc                                #  fdc: 00000000
.Lrel140:   .word        memcpy                                #  fe0: 00000000
.Lrel141:   .word        netif_add                             #  fe4: 00000000
.Lrel142:   .word        sdk_ic_set_vif                        #  fe8: 00000000
.Lrel143:   .word        netif_set_up                          #  fec: 00000000
.Lrel144:   .word        sdk_wifi_get_opmode                   #  ff0: 00000000
.Lrel145:   .word        vPortEnterCritical                    #  ff4: 00000000
.Lrel146:   .word        vPortExitCritical                     #  ff8: 00000000
.Lrel147:   .word        sdk_chm_set_current_channel           #  ffc: 00000000

# Function @ .irom0.text+0x1000
# Local variables/stack:
#     (local0):  word[4]   @ -0x30
#     (local1):  word      @ -0x20
#     (local2):  word      @ -0x1c
#     (local3):  word      @ -0x18
#     (local4):  word      @ -0x14
#     (local5):  word[4]   @ -0x10
.literal_position
sdk_wifi_softap_start:
            addi         a1, a1, -48 /* (local0) */            # 1000: 12c1d0
            s32i.n       a0, a1, 20 /* a0 -> [(local2)] */     # 1003: 0951
            movi         a0, .Lrel125 /* sdk_g_ic */           # 1005: 01e5ff
            s32i.n       a12, a1, 24 /* a12 -> [(local3)] */   # 1008: c961
            l32i.n       a12, a0, 20 /* [sdk_g_ic+0x14] */     # 100a: c850
            movi.n       a2, 0 /* 0x00000000 */                # 100c: 0c02
            bnez.n       a12, .Lbr125                          # 100e: cc1c
            j            .Lbr137                               # 1010: 064c00
.Lbr125:    l8ui         a2, a12, 187 /* [[sdk_g_ic+0x14]+0xbb] */ # 1013: 220cbb
            movi         a6, .Lrel126 /* .Ldata001 */          # 1016: 61e2ff
            addi.n       a2, a2, -1 /* [[sdk_g_ic+0x14]+0xbb]-0x1 */ # 1019: 0b22
            beqz         a2, .Lbr136                           # 101b: 163212
            l8ui         a3, a6, 0 /* [.Ldata001] */           # 101e: 320600
            movi.n       a0, 1 /* 0x00000001 */                # 1021: 0c10
            bbci         a3, 0, .Lbr126                        # 1023: 07630c
            mov.n        a2, a0 /* 0x00000001 */               # 1026: 2d00
            movi.n       a4, 2 /* 0x00000002 */                # 1028: 0c24
            or           a4, a3, a4                            # 102a: 404320
            s8i          a4, a6, 0 /* a4 -> [.Ldata001] */     # 102d: 424600
            j            .Lbr137                               # 1030: 064400
.Lbr126:    movi         a3, .Lrel127 /* sdk_info+0x18 */      # 1033: 31dcff
            l32i.n       a5, a12, 0 /* [[sdk_g_ic+0x14]] */    # 1036: 580c
            s32i.n       a3, a1, 16 /* sdk_info+0x18 -> [(local1)] */ # 1038: 3941
            bnez.n       a5, .Lbr127                           # 103a: fc05
            movi.n       a2, 52 /* 0x00000034 */               # 103c: 3c42
            movi         a0, .Lrel139 /* malloc */             # 103e: 01e7ff
            callx0       a0 /* malloc */                       # 1041: c00000
            l32i.n       a3, a1, 16 /* [(local1)] */           # 1044: 3841
            s32i.n       a2, a12, 0 /* a2 -> [[sdk_g_ic+0x14]] */ # 1046: 290c
            movi.n       a4, 6 /* 0x00000006 */                # 1048: 0c64
            addi         a2, a2, 41                            # 104a: 22c229
            movi         a0, .Lrel140 /* memcpy */             # 104d: 01e4ff
            callx0       a0 /* memcpy */                       # 1050: c00000
            mov.n        a6, a12 /* [sdk_g_ic+0x14] */         # 1053: 6d0c
            movi         a7, .Lrel128 /* ethernetif_init */    # 1055: 71d4ff
            l32i.n       a2, a12, 0 /* [[sdk_g_ic+0x14]] */    # 1058: 280c
            movi         a3, .Lrel129 /* sdk_info */           # 105a: 31d4ff
            movi         a8, .Lrel130 /* tcpip_input */        # 105d: 81d4ff
            addi.n       a4, a3, 4 /* sdk_info+0x4 */          # 1060: 4b43
            addi.n       a5, a3, 8 /* sdk_info+0x8 */          # 1062: 8b53
            s32i.n       a8, a1, 0 /* tcpip_input -> [(local0)] */ # 1064: 8901
            movi         a0, .Lrel141 /* netif_add */          # 1066: 01dfff
            callx0       a0 /* netif_add */                    # 1069: c00000
            l32i.n       a3, a1, 16 /* [(local1)] */           # 106c: 3841
.Lbr127:    movi.n       a2, 1 /* 0x00000001 */                # 106e: 0c12
            movi.n       a5, 1 /* 0x00000001 */                # 1070: 0c15
            movi.n       a6, 0 /* 0x00000000 */                # 1072: 0c06
            mov.n        a4, a3                                # 1074: 4d03
            movi.n       a3, 1 /* 0x00000001 */                # 1076: 0c13
            movi         a0, .Lrel142 /* sdk_ic_set_vif */     # 1078: 01dcff
            callx0       a0 /* sdk_ic_set_vif */               # 107b: c00000
            l32i.n       a2, a12, 0 /* [[sdk_g_ic+0x14]] */    # 107e: 280c
            movi         a0, .Lrel143 /* netif_set_up */       # 1080: 01dbff
            callx0       a0 /* netif_set_up */                 # 1083: c00000
            movi         a0, .Lrel144 /* sdk_wifi_get_opmode */ # 1086: 01daff
            callx0       a0 /* sdk_wifi_get_opmode */          # 1089: c00000
            movi         a0, .Lrel131 /* sdk_g_ic */           # 108c: 01caff
            bnei         a2, 3, .Lbr129                        # 108f: 663211
            l32i.n       a3, a0, 16 /* [sdk_g_ic+0x10] */      # 1092: 3840
            beqz         a3, .Lbr138                           # 1094: 16530b
            l32i.n       a9, a3, 60 /* [[sdk_g_ic+0x10]+0x3c] */ # 1097: 98f3
            movi.n       a3, 0 /* 0x00000000 */                # 1099: 0c03
            bgeui        a9, 2, .Lbr128                        # 109b: f62902
            j            .Lbr138                               # 109e: c62a00
.Lbr128:    j            .Lbr130                               # 10a1: 460000
.Lbr129:    movi.n       a3, 1 /* 0x00000001 */                # 10a4: 0c13
.Lbr130:    beqi         a3, 1, .Lbr131                        # 10a6: 261302
            j            .Lbr135                               # 10a9: c62000
.Lbr131:    movi         a6, .Lrel132 /* sdk_g_ic+0x280 */     # 10ac: 61c3ff
            movi         a4, .Lrel133 /* sdk_NMIIrqIsOn */     # 10af: 41c3ff
            l8ui         a6, a6, 141 /* [sdk_g_ic+0x30d] */    # 10b2: 62068d
            l8ui         a4, a4, 0 /* [sdk_NMIIrqIsOn] */      # 10b5: 420400
            addi.n       a6, a6, -1 /* [sdk_g_ic+0x30d]-0x1 */ # 10b8: 0b66
            extui        a6, a6, 0, 8                          # 10ba: 606074
            s32i.n       a6, a1, 28 /* a6 -> [(local4)] */     # 10bd: 6971
            bnez.n       a4, .Lbr133                           # 10bf: ecc4
            movi         a0, .Lrel145 /* vPortEnterCritical */ # 10c1: 01ccff
            callx0       a0 /* vPortEnterCritical */           # 10c4: c00000
            movi         a3, .Llit011 /* 0x3feffe00 */         # 10c7: 31beff
            movi.n       a8, -32 /* 0xffffffe0 */              # 10ca: 6c08
.Lbr132:    memw                                               # 10cc: c02000
            l32i         a9, a3, 0x200 /* [0x3ff00000] */      # 10cf: 922380
            and          a9, a9, a8                            # 10d2: 809910
            memw                                               # 10d5: c02000
            s32i         a9, a3, 0x200 /* a9 -> [0x3ff00000] */ # 10d8: 926380
            memw                                               # 10db: c02000
            l32i         a7, a3, 0x200 /* [0x3ff00000] */      # 10de: 722380
            bbsi         a7, 0, .Lbr132                        # 10e1: 07e7e7
            movi         a0, .Lrel134 /* sdk_g_ic */           # 10e4: 01b8ff
            movi         a4, .Lrel135 /* sdk_NMIIrqIsOn */     # 10e7: 41b8ff
            l32i.n       a6, a1, 28 /* [(local4)] */           # 10ea: 6871
            l8ui         a4, a4, 0 /* [sdk_NMIIrqIsOn] */      # 10ec: 420400
.Lbr133:    movi         a5, .Lrel136 /* sdk_g_ic+0x100 */     # 10ef: 51b7ff
            movi         a7, 132 /* 0x00000084 */              # 10f2: 72a084
            addx2        a6, a6, a6                            # 10f5: 606690
            addx4        a6, a6, a0                            # 10f8: 0066a0
            add.n        a6, a6, a7                            # 10fb: 7a66
            s32i.n       a6, a1, 32 /* a6 -> [(local5)] */     # 10fd: 6981
            s32i         a6, a5, 76 /* a6 -> [sdk_g_ic+0x14c] */ # 10ff: 626513
            bnez.n       a4, .Lbr134                           # 1102: dcf4
            memw                                               # 1104: c02000
            movi         a8, .Llit012 /* 0x3feffe00 */         # 1107: 81b2ff
            l32i         a7, a8, 0x200 /* [0x3ff00000] */      # 110a: 722880
            movi.n       a9, -32 /* 0xffffffe0 */              # 110d: 6c09
            and          a7, a7, a9                            # 110f: 907710
            movi.n       a9, 1 /* 0x00000001 */                # 1112: 0c19
            or           a7, a7, a9                            # 1114: 907720
            memw                                               # 1117: c02000
            s32i         a7, a8, 0x200 /* a7 -> [0x3ff00000] */ # 111a: 726880
            movi         a0, .Lrel146 /* vPortExitCritical */  # 111d: 01b6ff
            callx0       a0 /* vPortExitCritical */            # 1120: c00000
            l32i.n       a6, a1, 32 /* [(local5)] */           # 1123: 6881
.Lbr134:    mov.n        a2, a6                                # 1125: 2d06
            movi         a0, .Lrel147 /* sdk_chm_set_current_channel */ # 1127: 01b5ff
            callx0       a0 /* sdk_chm_set_current_channel */  # 112a: c00000
            movi         a0, .Lrel137 /* sdk_g_ic */           # 112d: 01a9ff
.Lbr135:    mov.n        a2, a0 /* sdk_g_ic */                 # 1130: 2d00
            call0        sdk_ieee80211_hostap_attach           # 1132: 050000
            movi.n       a10, 1 /* 0x00000001 */               # 1135: 0c1a
            movi         a0, .Lrel138 /* .Ldata001 */          # 1137: 01a8ff
            movi.n       a11, 0 /* 0x00000000 */               # 113a: 0c0b
            s8i          a11, a0, 32 /* 0x00 -> [sdk_TmpSTAAPCloseAP] */ # 113c: b24020
            s8i          a10, a12, 187 /* 0x01 -> [[sdk_g_ic+0x14]+0xbb] */ # 113f: a24cbb
.Lbr136:    movi.n       a2, 1 /* 0x00000001 */                # 1142: 0c12
.Lbr137:    l32i.n       a12, a1, 24 /* [(local3)] */          # 1144: c861
            l32i.n       a0, a1, 20 /* [(local2)] */           # 1146: 0851
            addi         a1, a1, 48 /* (top of frame) */       # 1148: 12c130
            ret.n                                              # 114b: 0df0
.Lbr138:    movi.n       a3, 1 /* 0x00000001 */                # 114d: 0c13
            j            .Lbr130                               # 114f: c6d4ff

            .balign      4
.Lrel148:   .word        sdk_g_ic                              # 1154: 00000000
.Lrel149:   .word        sdk_g_ic+0x280                        # 1158: 00000000
.Lrel150:   .word        .bss                                  # 115c: 00000000
.Lrel151:   .word        sdk_info+0x18                         # 1160: 00000000
.Lrel152:   .word        sdk_ieee80211_send_mgmt               # 1164: 00000000
.Lrel153:   .word        sdk_ieee80211_send_mgmt               # 1168: 00000000
.Lrel154:   .word        sdk_cnx_node_leave                    # 116c: 00000000
.Lrel155:   .word        netif_set_down                        # 1170: 00000000
.Lrel156:   .word        sdk_ets_timer_disarm                  # 1174: 00000000
.Lrel157:   .word        sdk_ic_bss_info_update                # 1178: 00000000
.Lrel158:   .word        sdk_ic_set_vif                        # 117c: 00000000
.Lrel159:   .word        sdk_esf_buf_recycle                   # 1180: 00000000

# Function @ .irom0.text+0x1184
# Local variables/stack:
#     (local0):  word      @ -0x20
#     (local1):  word      @ -0x1c
#     (local2):  word      @ -0x18
#     (local3):  word      @ -0x14
#     (local4):  word      @ -0x10
#     (local5):  word[3]   @ -0xc
.literal_position
sdk_wifi_softap_stop:
            addi         a1, a1, -32 /* (local0) */            # 1184: 12c1e0
            s32i.n       a13, a1, 8 /* a13 -> [(local2)] */    # 1187: d921
            s32i.n       a14, a1, 12 /* a14 -> [(local3)] */   # 1189: e931
            s32i.n       a12, a1, 4 /* a12 -> [(local1)] */    # 118b: c911
            movi         a12, .Lrel148 /* sdk_g_ic */          # 118d: c1f1ff
            s32i.n       a15, a1, 16 /* a15 -> [(local4)] */   # 1190: f941
            l32i.n       a12, a12, 20 /* [sdk_g_ic+0x14] */    # 1192: c85c
            s32i.n       a0, a1, 0 /* a0 -> [(local0)] */      # 1194: 0901
            bnez.n       a12, .Lbr139                          # 1196: cc3c
            movi.n       a2, 0 /* 0x00000000 */                # 1198: 0c02
            j            .Lbr141                               # 119a: 460200
.Lbr139:    l8ui         a13, a12, 187 /* [[sdk_g_ic+0x14]+0xbb] */ # 119d: d20cbb
            movi         a0, .Lrel149 /* sdk_g_ic+0x280 */     # 11a0: 01eeff
            bnez.n       a13, .Lbr142                          # 11a3: ccfd
.Lbr140:    movi.n       a2, 1 /* 0x00000001 */                # 11a5: 0c12
.Lbr141:    l32i.n       a12, a1, 4 /* [(local1)] */           # 11a7: c811
            l32i.n       a13, a1, 8 /* [(local2)] */           # 11a9: d821
            l32i.n       a14, a1, 12 /* [(local3)] */          # 11ab: e831
            l32i.n       a15, a1, 16 /* [(local4)] */          # 11ad: f841
            l32i.n       a0, a1, 0 /* [(local0)] */            # 11af: 0801
            addi         a1, a1, 32 /* (top of frame) */       # 11b1: 12c120
            ret.n                                              # 11b4: 0df0
.Lbr142:    s32i.n       a0, a1, 20 /* sdk_g_ic+0x280 -> [(local5)] */ # 11b6: 0951
            l8ui         a0, a0, 144 /* [sdk_g_ic+0x310] */    # 11b8: 020090
            movi.n       a13, 1 /* 0x00000001 */               # 11bb: 0c1d
            addi.n       a0, a0, 2 /* [sdk_g_ic+0x310]+0x2 */  # 11bd: 2b00
            blti         a0, 2, .Lbr145                        # 11bf: a62044
.Lbr143:    addx4        a14, a13, a12                         # 11c2: c0eda0
            l32i         a2, a14, 144                          # 11c5: 222e24
            beqz.n       a2, .Lbr144                           # 11c8: bc32
            movi         a3, 160 /* 0x000000a0 */              # 11ca: 32a0a0
            l32i         a15, a12, 136 /* [[sdk_g_ic+0x14]+0x88] */ # 11cd: f22c22
            movi.n       a4, 4 /* 0x00000004 */                # 11d0: 0c44
            s32i         a2, a12, 136 /* a2 -> [[sdk_g_ic+0x14]+0x88] */ # 11d2: 226c22
            mov.n        a2, a12 /* [sdk_g_ic+0x14] */         # 11d5: 2d0c
            movi         a0, .Lrel152 /* .Lrel152 */           # 11d7: 01e3ff
            callx0       a0                                    # 11da: c00000
            mov.n        a2, a12 /* [sdk_g_ic+0x14] */         # 11dd: 2d0c
            movi         a3, 192 /* 0x000000c0 */              # 11df: 32a0c0
            movi.n       a4, 2 /* 0x00000002 */                # 11e2: 0c24
            movi         a0, .Lrel153 /* .Lrel153 */           # 11e4: 01e1ff
            callx0       a0                                    # 11e7: c00000
            mov.n        a2, a12 /* [sdk_g_ic+0x14] */         # 11ea: 2d0c
            s32i         a15, a12, 136 /* [[sdk_g_ic+0x14]+0x88] -> [[sdk_g_ic+0x14]+0x88] */ # 11ec: f26c22
            l32i         a3, a14, 144                          # 11ef: 322e24
            movi         a0, .Lrel154 /* .Lrel154 */           # 11f2: 01deff
            callx0       a0                                    # 11f5: c00000
            l32i.n       a0, a1, 20 /* [(local5)] */           # 11f8: 0851
            l8ui         a0, a0, 144 /* [[(local5)]+0x90] */   # 11fa: 020090
            addi.n       a0, a0, 2 /* [[(local5)]+0x90]+0x2 */ # 11fd: 2b00
.Lbr144:    addi.n       a13, a13, 1                           # 11ff: 1bdd
            extui        a13, a13, 0, 8                        # 1201: d0d074
            blt          a13, a0, .Lbr143                      # 1204: 072dba
.Lbr145:    l32i.n       a2, a12, 0 /* [[sdk_g_ic+0x14]] */    # 1207: 280c
            movi         a0, .Lrel155 /* netif_set_down */     # 1209: 01d9ff
            callx0       a0 /* netif_set_down */               # 120c: c00000
            movi         a13, .Lrel150 /* .Ldata001 */         # 120f: d1d3ff
            movi.n       a14, 1 /* 0x00000001 */               # 1212: 0c1e
            s8i          a14, a13, 32 /* 0x01 -> [sdk_TmpSTAAPCloseAP] */ # 1214: e24d20
            addi.n       a2, a13, 4 /* .Ldata002 */            # 1217: 4b2d
            movi         a0, .Lrel156 /* sdk_ets_timer_disarm */ # 1219: 01d6ff
            callx0       a0 /* sdk_ets_timer_disarm */         # 121c: c00000
            movi.n       a2, 1 /* 0x00000001 */                # 121f: 0c12
            movi         a3, .Lrel151 /* sdk_info+0x18 */      # 1221: 31cfff
            movi.n       a4, 2 /* 0x00000002 */                # 1224: 0c24
            movi.n       a5, 0 /* 0x00000000 */                # 1226: 0c05
            movi         a0, .Lrel157 /* sdk_ic_bss_info_update */ # 1228: 01d4ff
            callx0       a0 /* sdk_ic_bss_info_update */       # 122b: c00000
            movi.n       a2, 1 /* 0x00000001 */                # 122e: 0c12
            movi.n       a3, 0 /* 0x00000000 */                # 1230: 0c03
            movi.n       a4, 0 /* 0x00000000 */                # 1232: 0c04
            movi.n       a5, 1 /* 0x00000001 */                # 1234: 0c15
            movi.n       a6, 0 /* 0x00000000 */                # 1236: 0c06
            movi         a0, .Lrel158 /* sdk_ic_set_vif */     # 1238: 01d1ff
            callx0       a0 /* sdk_ic_set_vif */               # 123b: c00000
            call0        .Lfunc005                             # 123e: 8511ff
            l8ui         a15, a13, 0 /* [.Ldata001] */         # 1241: f20d00
            bbsi         a15, 0, .Lbr146                       # 1244: 07ef09
            l32i.n       a2, a13, 36 /* [.Ldata003] */         # 1247: 289d
            movi.n       a3, 4 /* 0x00000004 */                # 1249: 0c43
            movi         a0, .Lrel159 /* sdk_esf_buf_recycle */ # 124b: 01cdff
            callx0       a0 /* sdk_esf_buf_recycle */          # 124e: c00000
.Lbr146:    movi.n       a0, 0 /* 0x00000000 */                # 1251: 0c00
            s8i          a0, a12, 187 /* 0x00 -> [[sdk_g_ic+0x14]+0xbb] */ # 1253: 024cbb
            j            .Lbr140                               # 1256: c6d2ff

            .section     .rodata, "a", @progbits

.Ldata004:  .word        0x00400814                            #    0: 14084000
