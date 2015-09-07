
            .section     .irom0.literal, "ax", @progbits

            .section     .text, "ax", @progbits

            .section     .data, "aw", @progbits

sdk_ieee80211_addr_bcast:
            .byte        0xff, 0xff, 0xff, 0xff, 0xff, 0xff

            .section     .bss, "aw", @nobits

            .section     .irom0.text, "ax", @progbits

.Lrel001:   .word        sdk_ieee80211_tx_mgt_cb               #    0: 00000000
.Llit001:   .word        0x00040000                            #    4: 00000400
.Lrel002:   .word        sdk_ppRegisterTxCallback              #    8: 00000000

# Function @ .irom0.text+0xc
# Local variables/stack:
#     (local0):  word[4]   @ -0x10
.literal_position
sdk_ieee80211_proto_attach:
            movi.n       a3, 2 /* 0x00000002 */                #    c: 0c23
            movi         a4, .Llit001 /* 0x00040000 */         #    e: 41fdff
            movi.n       a6, 1 /* 0x00000001 */                #   11: 0c16
            mov.n        a5, a2 /* arg0 */                     #   13: 5d02
            addi         a1, a1, -16 /* (local0) */            #   15: 12c1f0
            s32i.n       a0, a1, 0 /* a0 -> [(local0)] */      #   18: 0901
            movi         a2, .Lrel001 /* sdk_ieee80211_tx_mgt_cb */ #   1a: 21f9ff
            l32i.n       a0, a5, 28 /* [arg0+0x1c] */          #   1d: 0875
            s32i.n       a6, a5, 12 /* 0x00000001 -> [arg0+0xc] */ #   1f: 6935
            or           a0, a0, a4                            #   21: 400020
            s32i.n       a0, a5, 28 /* a0 -> [arg0+0x1c] */    #   24: 0975
            movi         a0, .Lrel002 /* sdk_ppRegisterTxCallback */ #   26: 01f8ff
            callx0       a0 /* sdk_ppRegisterTxCallback */     #   29: c00000
            l32i.n       a0, a1, 0 /* [(local0)] */            #   2c: 0801
            addi         a1, a1, 16 /* (top of frame) */       #   2e: 12c110
            ret.n                                              #   31: 0df0

            .balign      4
# Function @ .irom0.text+0x34
.literal_position
sdk_ieee80211_set_shortslottime:
            movi         a6, 1024 /* 0x00000400 */             #   34: 62a400
            l32i.n       a5, a2, 28 /* [arg0+0x1c] */          #   37: 5872
            movi         a4, -1025 /* 0xfffffbff */            #   39: 42abff
            and          a4, a5, a4                            #   3c: 404510
            or           a5, a5, a6                            #   3f: 605520
            moveqz       a5, a4, a3                            #   42: 305483
            s32i.n       a5, a2, 28 /* a5 -> [arg0+0x1c] */    #   45: 5972
            ret.n         /* arg0 */                           #   47: 0df0

            .balign      4
.Lrel003:   .word        .rodata                               #   4c: 00000000

# Function @ .irom0.text+0x50
.literal_position
sdk_ieee80211_iserp_rateset:
            l8ui         a8, a2, 0 /* [arg0] */                #   50: 820200
            bltui        a8, 7, .Lbr003                        #   53: b6781e
            movi         a9, .Lrel003 /* .Ldata001 */          #   56: 91fdff
            movi.n       a10, 0 /* 0x00000000 */               #   59: 0c0a
.Lbr001:    blti         a8, 1, .Lbr003                        #   5b: a61816
            movi.n       a5, 0 /* 0x00000000 */                #   5e: 0c05
            l32i.n       a6, a9, 0                             #   60: 6809
.Lbr002:    add.n        a7, a5, a2                            #   62: 2a75
            l8ui         a7, a7, 1                             #   64: 720701
            extui        a7, a7, 0, 7                          #   67: 707064
            beq          a6, a7, .Lbr004                       #   6a: 77160b
            blt          a6, a7, .Lbr003                       #   6d: 772604
            addi.n       a5, a5, 1                             #   70: 1b55
            bne          a5, a8, .Lbr002                       #   72: 8795ec
.Lbr003:    movi.n       a2, 0 /* 0x00000000 */                #   75: 0c02
            ret.n         /* 0x00000000 */                     #   77: 0df0
.Lbr004:    addi.n       a9, a9, 4                             #   79: 4b99
            addi.n       a10, a10, 1                           #   7b: 1baa
            bnei         a10, 7, .Lbr001                       #   7d: 667ada
            movi.n       a2, 1 /* 0x00000001 */                #   80: 0c12
            ret.n         /* 0x00000001 */                     #   82: 0df0

.Lrel004:   .word        .Ldata002                             #   84: 20000000

# Function @ .irom0.text+0x88
# Local variables/stack:
#     (local0):  word[4]   @ -0x10
.literal_position
.Lfunc001:  addi         a1, a1, -16 /* (local0) */            #   88: 12c1f0
            s32i.n       a0, a1, 0 /* a0 -> [(local0)] */      #   8b: 0901
            l8ui         a0, a2, 0 /* [arg0] */                #   8d: 020200
            beqz.n       a0, .Lbr009                           #   90: bcf0
            movi.n       a9, 0 /* 0x00000000 */                #   92: 0c09
            movi         a11, 128 /* 0x00000080 */             #   94: b2a080
            movi         a8, .Lrel004 /* .Ldata002 */          #   97: 81fbff
            slli         a10, a3, 4                            #   9a: c0a311
            add.n        a8, a8, a10                           #   9d: aa88
            l8ui         a7, a8, 0                             #   9f: 720800
.Lbr005:    bnez.n       a4, .Lbr006                           #   a2: cc94
            add.n        a3, a2, a9                            #   a4: 9a32
            l8ui         a0, a3, 1                             #   a6: 020301
            extui        a0, a0, 0, 7                          #   a9: 000064
            s8i          a0, a3, 1                             #   ac: 024301
.Lbr006:    beqz.n       a7, .Lbr008                           #   af: 9c57
            movi.n       a0, 0 /* 0x00000000 */                #   b1: 0c00
            add.n        a10, a2, a9                           #   b3: 9aa2
            l8ui         a3, a10, 1                            #   b5: 320a01
.Lbr007:    add.n        a5, a8, a0                            #   b8: 0a58
            l8ui         a5, a5, 1                             #   ba: 520501
            addi.n       a0, a0, 1                             #   bd: 1b00
            bne          a5, a3, .Lbr010                       #   bf: 379517
            or           a6, a3, a11                           #   c2: b06320
            s8i          a6, a10, 1                            #   c5: 624a01
.Lbr008:    l8ui         a10, a2, 0 /* [arg0] */               #   c8: a20200
            addi.n       a9, a9, 1                             #   cb: 1b99
            extui        a9, a9, 0, 8                          #   cd: 909074
            bltu         a9, a10, .Lbr005                      #   d0: a739ce
.Lbr009:    l32i.n       a0, a1, 0 /* [(local0)] */            #   d3: 0801
            addi         a1, a1, 16 /* (top of frame) */       #   d5: 12c110
            ret.n         /* arg0 */                           #   d8: 0df0
.Lbr010:    extui        a0, a0, 0, 8                          #   da: 000074
            bne          a7, a0, .Lbr007                       #   dd: 0797d7
            j            .Lbr008                               #   e0: 06f9ff

            .balign      4
# Function @ .irom0.text+0xe4
# Local variables/stack:
#     (local0):  word[4]   @ -0x10
.literal_position
sdk_ieee80211_setbasicrates:
            movi.n       a4, 0 /* 0x00000000 */                #   e4: 0c04
            addi         a1, a1, -16 /* (local0) */            #   e6: 12c1f0
            s32i.n       a0, a1, 0 /* a0 -> [(local0)] */      #   e9: 0901
            call0        .Lfunc001                             #   eb: c5f9ff
            l32i.n       a0, a1, 0 /* [(local0)] */            #   ee: 0801
            addi         a1, a1, 16 /* (top of frame) */       #   f0: 12c110
            ret.n                                              #   f3: 0df0

            .balign      4
# Function @ .irom0.text+0xf8
# Local variables/stack:
#     (local0):  word[4]   @ -0x10
.literal_position
sdk_ieee80211_addbasicrates:
            movi.n       a4, 1 /* 0x00000001 */                #   f8: 0c14
            addi         a1, a1, -16 /* (local0) */            #   fa: 12c1f0
            s32i.n       a0, a1, 0 /* a0 -> [(local0)] */      #   fd: 0901
            call0        .Lfunc001                             #   ff: 85f8ff
            l32i.n       a0, a1, 0 /* [(local0)] */            #  102: 0801
            addi         a1, a1, 16 /* (top of frame) */       #  104: 12c110
            ret.n                                              #  107: 0df0

            .balign      4
# Function @ .irom0.text+0x10c
.literal_position
sdk_ieee80211_wme_initparams:
            ret.n         /* arg0 */                           #  10c: 0df0

            .balign      4
# Function @ .irom0.text+0x110
.literal_position
sdk_ieee80211_wme_updateparams:
            ret.n         /* arg0 */                           #  110: 0df0

            .balign      4
.Lrel005:   .word        sdk_g_ic                              #  114: 00000000
.Lrel006:   .word        sdk_g_ic                              #  118: 00000000
.Lrel007:   .word        memcpy                                #  11c: 00000000
.Lrel008:   .word        sdk_ieee80211_sta_new_state           #  120: 00000000
.Lrel009:   .word        sdk_ieee80211_sta_new_state           #  124: 00000000

# Function @ .irom0.text+0x128
# Local variables/stack:
#     (local0):  word      @ -0x10
#     (local1):  word      @ -0xc
#     (local2):  word[2]   @ -0x8
.literal_position
sdk_ieee80211_mlme_connect_bss:
            mov.n        a3, a2 /* arg0 */                     #  128: 3d02
            addi         a1, a1, -16 /* (local0) */            #  12a: 12c1f0
            s32i.n       a5, a1, 4 /* arg3 -> [(local1)] */    #  12d: 5911
            s32i.n       a0, a1, 8 /* a0 -> [(local2)] */      #  12f: 0921
            movi         a2, .Lrel005 /* sdk_g_ic */           #  131: 21f8ff
            s32i.n       a4, a1, 0 /* arg2 -> [(local0)] */    #  134: 4901
            l32i.n       a2, a2, 16 /* [sdk_g_ic+0x10] */      #  136: 2842
            movi.n       a4, 6 /* 0x00000006 */                #  138: 0c64
            s32i         a3, a2, 136 /* arg0 -> [[sdk_g_ic+0x10]+0x88] */ #  13a: 326222
            addi         a2, a2, 64 /* [sdk_g_ic+0x10]+0x40 */ #  13d: 22c240
            movi         a0, .Lrel007 /* memcpy */             #  140: 01f7ff
            callx0       a0 /* memcpy */                       #  143: c00000
            l32i.n       a3, a1, 4 /* [(local1)] */            #  146: 3811
            movi         a0, .Lrel006 /* sdk_g_ic */           #  148: 01f4ff
            beqz.n       a3, .Lbr011                           #  14b: 8ce3
            movi.n       a3, 2 /* 0x00000002 */                #  14d: 0c23
            movi         a4, 176 /* 0x000000b0 */              #  14f: 42a0b0
            mov.n        a2, a0 /* sdk_g_ic */                 #  152: 2d00
            movi         a0, .Lrel008 /* sdk_ieee80211_sta_new_state */ #  154: 01f3ff
            callx0       a0 /* sdk_ieee80211_sta_new_state */  #  157: c00000
            j            .Lbr012                               #  15a: 860400
.Lbr011:    movi.n       a3, 3 /* 0x00000003 */                #  15d: 0c33
            mov.n        a2, a0 /* sdk_g_ic */                 #  15f: 2d00
            l32i.n       a6, a1, 0 /* [(local0)] */            #  161: 6801
            movi.n       a5, 32 /* 0x00000020 */               #  163: 2c05
            movi.n       a4, 0 /* 0x00000000 */                #  165: 0c04
            movnez       a4, a5, a6                            #  167: 604593
            movi         a0, .Lrel009 /* sdk_ieee80211_sta_new_state */ #  16a: 01eeff
            callx0       a0 /* sdk_ieee80211_sta_new_state */  #  16d: c00000
.Lbr012:    l32i.n       a0, a1, 8 /* [(local2)] */            #  170: 0821
            addi         a1, a1, 16 /* (top of frame) */       #  172: 12c110
            ret.n                                              #  175: 0df0

            .section     .rodata, "a", @progbits

.Ldata001:  .byte        0x02, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00
            .byte        0x0b, 0x00, 0x00, 0x00, 0x16, 0x00, 0x00, 0x00
            .byte        0x0c, 0x00, 0x00, 0x00, 0x18, 0x00, 0x00, 0x00
            .byte        0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
.Ldata002:  .byte        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
            .byte        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
            .byte        0x02, 0x02, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00
            .byte        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
            .byte        0x04, 0x02, 0x04, 0x0b, 0x16, 0x00, 0x00, 0x00
            .byte        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
            .byte        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
            .byte        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
            .byte        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
            .byte        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
