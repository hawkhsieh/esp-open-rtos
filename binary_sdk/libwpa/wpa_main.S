
            .section     .irom0.literal, "ax", @progbits

            .section     .text, "ax", @progbits

            .section     .data, "aw", @progbits

            .section     .bss, "aw", @nobits

            .section     .irom0.text, "ax", @progbits

.Lrel001:   .word        sdk_g_ic                              #    0: 00000000
.Lrel002:   .word        sdk_tkip                              #    4: 00000000
.Lrel003:   .word        sdk_ccmp                              #    8: 00000000
.Lrel004:   .word        sdk_wep                               #    c: 00000000
.Lrel005:   .word        sdk_ic_set_key                        #   10: 00000000
.Lrel006:   .word        malloc                                #   14: 00000000
.Lrel007:   .word        free                                  #   18: 00000000
.Lrel008:   .word        malloc                                #   1c: 00000000
.Lrel009:   .word        bzero                                 #   20: 00000000
.Lrel010:   .word        memcpy                                #   24: 00000000

# Function @ .irom0.text+0x28
# Local variables/stack:
#     (local0):  word[4]   @ -0x30
#     (local1):  word      @ -0x20
#     (local2):  word      @ -0x1c
#     (local3):  word      @ -0x18
#     (local4):  word      @ -0x14
#     (local5):  word      @ -0x10
#     (local6):  word[3]   @ -0xc
.literal_position
sdk_ppInstallKey:
            mov.n        a5, a3 /* arg1 */                     #   28: 5d03
            addi         a1, a1, -48 /* (local0) */            #   2a: 12c1d0
            s32i.n       a14, a1, 36 /* a14 -> [(local6)] */   #   2d: e991
            l32i.n       a7, a1, 48 /* [(local7)] */           #   2f: 78c1
            s32i.n       a6, a1, 16 /* arg4 -> [(local1)] */   #   31: 6941
            s32i.n       a0, a1, 24 /* a0 -> [(local3)] */     #   33: 0961
            s32i.n       a13, a1, 32 /* a13 -> [(local5)] */   #   35: d981
            s32i.n       a12, a1, 28 /* a12 -> [(local4)] */   #   37: c971
            l32i.n       a13, a1, 56 /* [(FP)+0x8] */          #   39: d8e1
            mov.n        a12, a2 /* arg0 */                    #   3b: cd02
            l32i.n       a0, a1, 52 /* [(FP)+0x4] */           #   3d: 08d1
            movi.n       a2, 0 /* 0x00000000 */                #   3f: 0c02
            mov.n        a3, a12 /* arg0 */                    #   41: 3d0c
            s32i.n       a0, a1, 0 /* [(FP)+0x4] -> [(local0)] */ #   43: 0901
            addi.n       a6, a13, 1 /* [(FP)+0x8]+0x1 */       #   45: 1b6d
            s32i.n       a6, a1, 20 /* [(FP)+0x8]+0x1 -> [(local2)] */ #   47: 6951
            movi         a0, .Lrel005 /* sdk_ic_set_key */     #   49: 01f1ff
            callx0       a0 /* sdk_ic_set_key */               #   4c: c00000
            movi         a0, .Lrel001 /* sdk_g_ic */           #   4f: 01ecff
            addi.n       a2, a13, -1 /* [(FP)+0x8]-0x1 */      #   52: 0b2d
            addx4        a14, a13, a0                          #   54: 00eda0
            bgei         a13, 4, .Lbr001                       #   57: e64d1d
            l32i.n       a3, a0, 16 /* [sdk_g_ic+0x10] */      #   5a: 3840
            l32i         a3, a3, 136 /* [[sdk_g_ic+0x10]+0x88] */ #   5c: 322322
            s8i          a2, a3, 233 /* [(FP)+0x8]-0x1 -> [[[sdk_g_ic+0x10]+0x88]+0xe9] */ #   5f: 2243e9
            l32i         a13, a14, 0x18c                       #   62: d22e63
            bnez.n       a13, .Lbr003                          #   65: ecad
            movi         a2, 160 /* 0x000000a0 */              #   67: 22a0a0
            movi         a0, .Lrel006 /* malloc */             #   6a: 01eaff
            callx0       a0 /* malloc */                       #   6d: c00000
            mov.n        a13, a2                               #   70: dd02
            s32i         a2, a14, 0x18c                        #   72: 226e63
            j            .Lbr003                               #   75: 860600
.Lbr001:    l32i         a13, a14, 0x18c                       #   78: d22e63
            beqz.n       a13, .Lbr002                          #   7b: 8c6d
            mov.n        a2, a13                               #   7d: 2d0d
            movi         a0, .Lrel007 /* free */               #   7f: 01e6ff
            callx0       a0 /* free */                         #   82: c00000
.Lbr002:    movi         a2, 160 /* 0x000000a0 */              #   85: 22a0a0
            movi         a0, .Lrel008 /* malloc */             #   88: 01e5ff
            callx0       a0 /* malloc */                       #   8b: c00000
            mov.n        a13, a2                               #   8e: dd02
            s32i         a2, a14, 0x18c                        #   90: 226e63
.Lbr003:    mov.n        a2, a13                               #   93: 2d0d
            movi         a3, 160 /* 0x000000a0 */              #   95: 32a0a0
            movi         a0, .Lrel009 /* bzero */              #   98: 01e2ff
            callx0       a0 /* bzero */                        #   9b: c00000
            bnei         a12, 2, .Lbr006                       #   9e: 662c26
            movi         a0, .Lrel002 /* sdk_tkip */           #   a1: 01d8ff
.Lbr004:    s32i         a0, a13, 152                          #   a4: 026d26
.Lbr005:    movi.n       a4, 8 /* 0x00000008 */                #   a7: 0c84
            movi         a2, 144 /* 0x00000090 */              #   a9: 22a090
            l32i.n       a3, a1, 20 /* [(local2)] */           #   ac: 3851
            s16i         a3, a13, 0                            #   ae: 325d00
            add.n        a2, a13, a2                           #   b1: 2a2d
            l32i.n       a3, a1, 16 /* [(local1)] */           #   b3: 3841
            movi         a0, .Lrel010 /* .Lrel010 */           #   b5: 01dbff
            callx0       a0                                    #   b8: c00000
            l32i.n       a12, a1, 28 /* [(local4)] */          #   bb: c871
            l32i.n       a13, a1, 32 /* [(local5)] */          #   bd: d881
            l32i.n       a14, a1, 36 /* [(local6)] */          #   bf: e891
            l32i.n       a0, a1, 24 /* [(local3)] */           #   c1: 0861
            addi         a1, a1, 48 /* (local7) */             #   c3: 12c130
            ret.n                                              #   c6: 0df0
.Lbr006:    bnei         a12, 3, .Lbr007                       #   c8: 663c05
            movi         a0, .Lrel003 /* sdk_ccmp */           #   cb: 01cfff
            j            .Lbr004                               #   ce: 86f4ff
.Lbr007:    beqi         a12, 1, .Lbr008                       #   d1: 261c02
            bnei         a12, 5, .Lbr005                       #   d4: 665ccf
.Lbr008:    movi         a0, .Lrel004 /* sdk_wep */            #   d7: 01cdff
            j            .Lbr004                               #   da: 86f1ff

            .balign      4
.Lrel011:   .word        sdk_g_ic                              #   e0: 00000000
.Lrel012:   .word        sdk_ieee80211_output_pbuf             #   e4: 00000000

# Function @ .irom0.text+0xe8
# Local variables/stack:
#     (local0):  word[4]   @ -0x10
.literal_position
.Lfunc001:  mov.n        a3, a2 /* arg0 */                     #   e8: 3d02
            movi         a2, .Lrel011 /* sdk_g_ic */           #   ea: 21fdff
            addi         a1, a1, -16 /* (local0) */            #   ed: 12c1f0
            l32i.n       a2, a2, 16 /* [sdk_g_ic+0x10] */      #   f0: 2842
            s32i.n       a0, a1, 0 /* a0 -> [(local0)] */      #   f2: 0901
            l32i.n       a2, a2, 0 /* [[sdk_g_ic+0x10]] */     #   f4: 2802
            movi         a0, .Lrel012 /* sdk_ieee80211_output_pbuf */ #   f6: 01fbff
            callx0       a0 /* sdk_ieee80211_output_pbuf */    #   f9: c00000
            l32i.n       a0, a1, 0 /* [(local0)] */            #   fc: 0801
            addi         a1, a1, 16 /* (top of frame) */       #   fe: 12c110
            ret.n                                              #  101: 0df0

            .balign      4
.Lrel013:   .word        sdk_g_ic                              #  104: 00000000
.Lrel014:   .word        sdk_g_ic                              #  108: 00000000
.Lrel015:   .word        sdk_ieee80211_send_mgmt               #  10c: 00000000
.Lrel016:   .word        sdk_ieee80211_sta_new_state           #  110: 00000000

# Function @ .irom0.text+0x114
# Local variables/stack:
#     (local0):  word      @ -0x10
#     (local1):  word[3]   @ -0xc
.literal_position
.Lfunc002:  movi         a3, 192 /* 0x000000c0 */              #  114: 32a0c0
            addi         a1, a1, -16 /* (local0) */            #  117: 12c1f0
            s32i.n       a12, a1, 4 /* a12 -> [(local1)] */    #  11a: c911
            s32i.n       a0, a1, 0 /* a0 -> [(local0)] */      #  11c: 0901
            mov.n        a12, a2 /* arg0 */                    #  11e: cd02
            movi         a2, .Lrel013 /* sdk_g_ic */           #  120: 21f9ff
            mov.n        a4, a12 /* arg0 */                    #  123: 4d0c
            l32i.n       a2, a2, 16 /* [sdk_g_ic+0x10] */      #  125: 2842
            movi         a0, .Lrel015 /* sdk_ieee80211_send_mgmt */ #  127: 01f9ff
            callx0       a0 /* sdk_ieee80211_send_mgmt */      #  12a: c00000
            movi         a2, .Lrel014 /* sdk_g_ic */           #  12d: 21f6ff
            movi.n       a3, 2 /* 0x00000002 */                #  130: 0c23
            movi         a5, 192 /* 0x000000c0 */              #  132: 52a0c0
            slli         a4, a12, 8                            #  135: 804c11
            or           a4, a4, a5                            #  138: 504420
            movi         a0, .Lrel016 /* sdk_ieee80211_sta_new_state */ #  13b: 01f5ff
            callx0       a0 /* sdk_ieee80211_sta_new_state */  #  13e: c00000
            l32i.n       a12, a1, 4 /* [(local1)] */           #  141: c811
            l32i.n       a0, a1, 0 /* [(local0)] */            #  143: 0801
            addi         a1, a1, 16 /* (top of frame) */       #  145: 12c110
            ret.n                                              #  148: 0df0

            .balign      4
.Lrel017:   .word        sdk_wpa_set_profile                   #  14c: 00000000
.Lrel018:   .word        sdk_wpa_set_profile                   #  150: 00000000

# Function @ .irom0.text+0x154
# Local variables/stack:
#     (local0):  word[4]   @ -0x10
.literal_position
sdk_wpa_config_profile:
            addi         a1, a1, -16 /* (local0) */            #  154: 12c1f0
            s32i.n       a0, a1, 0 /* a0 -> [(local0)] */      #  157: 0901
            addmi        a0, a2, 512 /* arg0+0x200 */          #  159: 02d202
            l8ui         a0, a0, 9 /* [arg0+0x209] */          #  15c: 020009
            beqi         a0, 2, .Lbr011                        #  15f: 26201d
            beqi         a0, 3, .Lbr011                        #  162: 26301a
            beqi         a0, 6, .Lbr011                        #  165: 266017
            beqi         a0, 4, .Lbr009                        #  168: 264005
            beqi         a0, 5, .Lbr009                        #  16b: 265002
            bnei         a0, 7, .Lbr010                        #  16e: 667007
.Lbr009:    movi.n       a2, 2 /* 0x00000002 */                #  171: 0c22
            movi         a0, .Lrel017 /* sdk_wpa_set_profile */ #  173: 01f6ff
            callx0       a0 /* sdk_wpa_set_profile */          #  176: c00000
.Lbr010:    l32i.n       a0, a1, 0 /* [(local0)] */            #  179: 0801
            addi         a1, a1, 16 /* (top of frame) */       #  17b: 12c110
            ret.n                                              #  17e: 0df0
.Lbr011:    movi.n       a2, 1 /* 0x00000001 */                #  180: 0c12
            movi         a0, .Lrel018 /* sdk_wpa_set_profile */ #  182: 01f3ff
            callx0       a0 /* sdk_wpa_set_profile */          #  185: c00000
            j            .Lbr010                               #  188: 46fbff

            .balign      4
.Lrel019:   .word        sdk_wpa_set_bss                       #  18c: 00000000

# Function @ .irom0.text+0x190
# Local variables/stack:
#     (local0):  word[4]   @ -0x20
#     (local1):  word[4]   @ -0x10
.literal_position
sdk_wpa_config_bss:
            mov.n        a7, a2 /* arg0 */                     #  190: 7d02
            addi         a1, a1, -32 /* (local0) */            #  192: 12c1e0
            movi         a4, 394 /* 0x0000018a */              #  195: 42a18a
            l16ui        a8, a2, 0x1e4 /* [arg0+0x1e4] */      #  198: 8212f2
            l16ui        a6, a2, 0x1e6 /* [arg0+0x1e6] */      #  19b: 6212f3
            s32i.n       a0, a1, 16 /* a0 -> [(local1)] */     #  19e: 0941
            add.n        a4, a2, a4 /* arg0+0x18a */           #  1a0: 4a42
            l8ui         a5, a4, 130 /* [arg0+0x20c] */        #  1a2: 520482
            movi         a0, 488 /* 0x000001e8 */              #  1a5: 02a1e8
            l8ui         a4, a4, 128 /* [arg0+0x20a] */        #  1a8: 420480
            slli         a6, a6, 16                            #  1ab: 006611
            l32i.n       a2, a2, 16 /* [arg0+0x10] */          #  1ae: 2842
            or           a6, a6, a8                            #  1b0: 806620
            l32i.n       a2, a2, 0 /* [[arg0+0x10]] */         #  1b3: 2802
            s32i.n       a6, a1, 0 /* a6 -> [(local0)] */      #  1b5: 6901
            movi         a6, 527 /* 0x0000020f */              #  1b7: 62a20f
            addi         a2, a2, 41 /* [[arg0+0x10]]+0x29 */   #  1ba: 22c229
            add.n        a6, a7, a6 /* arg0+0x20f */           #  1bd: 6a67
            add.n        a7, a7, a0 /* arg0+0x1e8 */           #  1bf: 0a77
            movi         a0, .Lrel019 /* sdk_wpa_set_bss */    #  1c1: 01f2ff
            callx0       a0 /* sdk_wpa_set_bss */              #  1c4: c00000
            l32i.n       a0, a1, 16 /* [(local1)] */           #  1c7: 0841
            addi         a1, a1, 32 /* (top of frame) */       #  1c9: 12c120
            ret.n                                              #  1cc: 0df0

            .balign      4
.Lrel020:   .word        sdk_g_ic                              #  1d0: 00000000

# Function @ .irom0.text+0x1d4
.literal_position
sdk_wpa_config_assoc_ie:
            movi         a6, .Lrel020 /* sdk_g_ic */           #  1d4: 61ffff
            bnei         a2, 1, .Lbr013                        #  1d7: 661207
            s32i         a3, a6, 0x174 /* arg1 -> [sdk_g_ic+0x174] */ #  1da: 32665d
.Lbr012:    s16i         a4, a3, 0 /* arg2 -> [arg1] */        #  1dd: 425300
            ret.n         /* arg0 */                           #  1e0: 0df0
.Lbr013:    s32i         a3, a6, 0x178 /* arg1 -> [sdk_g_ic+0x178] */ #  1e2: 32665e
            j            .Lbr012                               #  1e5: 06fdff

.Lrel021:   .word        sdk_g_ic                              #  1e8: 00000000
.Lrel022:   .word        sdk_g_ic+0x180                        #  1ec: 00000000

# Function @ .irom0.text+0x1f0
.literal_position
sdk_dhcp_bind_check:
            movi         a4, .Lrel021 /* sdk_g_ic */           #  1f0: 41feff
            l32i.n       a4, a4, 16 /* [sdk_g_ic+0x10] */      #  1f3: 4844
            movi         a3, .Lrel022 /* sdk_g_ic+0x180 */     #  1f5: 31fdff
            l8ui         a2, a4, 186 /* [[sdk_g_ic+0x10]+0xba] */ #  1f8: 2204ba
            l8ui         a3, a3, 138 /* [sdk_g_ic+0x20a] */    #  1fb: 32038a
            beqi         a2, 5, .Lbr015                        #  1fe: 26520a
            beqi         a3, 7, .Lbr014                        #  201: 267302
            bnei         a3, 8, .Lbr015                        #  204: 668304
.Lbr014:    movi.n       a5, 2 /* 0x00000002 */                #  207: 0c25
            s8i          a5, a4, 186 /* 0x02 -> [[sdk_g_ic+0x10]+0xba] */ #  209: 5244ba
.Lbr015:    ret.n         /* [[sdk_g_ic+0x10]+0xba] */         #  20c: 0df0

            .balign      4
.Lrel023:   .word        sdk_g_ic                              #  210: 00000000
.Lrel024:   .word        .rodata.str1.4                        #  214: 00000000
.Lrel025:   .word        sdk_g_ic+0x1e8                        #  218: 00000000
.Llit001:   .word        0x00010000                            #  21c: 00000100
.Llit002:   .word        0x60000e00                            #  220: 000e0060
.Lrel026:   .word        sdk_dhcp_bind_check                   #  224: 00000000
.Llit003:   .word        0x00003a98                            #  228: 983a0000
.Lrel027:   .word        sdk_g_ic                              #  22c: 00000000
.Lrel028:   .word        sdk_dhcpc_flag                        #  230: 00000000
.Lrel029:   .word        .Lstr002                              #  234: 20000000
.Lrel030:   .word        printf                                #  238: 00000000
.Lrel031:   .word        sdk_os_timer_disarm                   #  23c: 00000000
.Lrel032:   .word        sdk_os_timer_setfn                    #  240: 00000000
.Lrel033:   .word        sdk_os_timer_arm                      #  244: 00000000
.Lrel034:   .word        printf                                #  248: 00000000
.Lrel035:   .word        dhcp_start                            #  24c: 00000000
.Lrel036:   .word        sdk_system_station_got_ip_set         #  250: 00000000
.Lrel037:   .word        netif_set_up                          #  254: 00000000

# Function @ .irom0.text+0x258
# Local variables/stack:
#     (local0):  word      @ -0x10
#     (local1):  word      @ -0xc
#     (local2):  word[2]   @ -0x8
.literal_position
sdk_eagle_auth_done:
            addi         a1, a1, -16 /* (local0) */            #  258: 12c1f0
            s32i.n       a12, a1, 8 /* a12 -> [(local2)] */    #  25b: c921
            movi         a12, .Lrel023 /* sdk_g_ic */          #  25d: c1ecff
            l32i.n       a12, a12, 16 /* [sdk_g_ic+0x10] */    #  260: c84c
            s32i.n       a0, a1, 4 /* a0 -> [(local1)] */      #  262: 0911
            l32i         a0, a12, 136 /* [[sdk_g_ic+0x10]+0x88] */ #  264: 022c22
            l32i.n       a2, a0, 8 /* [[[sdk_g_ic+0x10]+0x88]+0x8] */ #  267: 2820
            extui        a2, a2, 0, 1                          #  269: 202004
            bnez         a2, .Lbr017                           #  26c: 56220a
            movi         a2, .Lrel024 /* .Lstr001 */           #  26f: 21e9ff
            l32i         a4, a0, 120 /* [[[sdk_g_ic+0x10]+0x88]+0x78] */ #  272: 42201e
            movi         a3, .Lrel025 /* sdk_g_ic+0x1e8 */     #  275: 31e8ff
            l8ui         a4, a4, 6 /* [[[[sdk_g_ic+0x10]+0x88]+0x78]+0x6] */ #  278: 420406
            movi         a0, .Lrel030 /* printf */             #  27b: 01efff
            callx0       a0 /* printf */                       #  27e: c00000
            l32i         a5, a12, 136 /* [[sdk_g_ic+0x10]+0x88] */ #  281: 522c22
            l32i         a5, a5, 120 /* [[[sdk_g_ic+0x10]+0x88]+0x78] */ #  284: 52251e
            movi         a6, .Llit001 /* 0x00010000 */         #  287: 61e5ff
            l8ui         a5, a5, 6 /* [[[[sdk_g_ic+0x10]+0x88]+0x78]+0x6] */ #  28a: 520506
            or           a5, a5, a6                            #  28d: 605520
            movi         a6, .Llit002 /* 0x60000e00 */         #  290: 61e4ff
            memw                                               #  293: c02000
            s32i         a5, a6, 0x3f4 /* a5 -> [0x600011f4] */ #  296: 5266fd
            addi.n       a2, a12, 4 /* [sdk_g_ic+0x10]+0x4 */  #  299: 4b2c
            s32i.n       a2, a1, 0 /* [sdk_g_ic+0x10]+0x4 -> [(local0)] */ #  29b: 2901
            movi         a0, .Lrel031 /* sdk_os_timer_disarm */ #  29d: 01e7ff
            callx0       a0 /* sdk_os_timer_disarm */          #  2a0: c00000
            l32i.n       a2, a1, 0 /* [(local0)] */            #  2a3: 2801
            movi         a3, .Lrel026 /* sdk_dhcp_bind_check */ #  2a5: 31dfff
            movi.n       a4, 0 /* 0x00000000 */                #  2a8: 0c04
            movi         a0, .Lrel032 /* sdk_os_timer_setfn */ #  2aa: 01e5ff
            callx0       a0 /* sdk_os_timer_setfn */           #  2ad: c00000
            l32i.n       a2, a1, 0 /* [(local0)] */            #  2b0: 2801
            movi         a3, .Llit003 /* 0x00003a98 */         #  2b2: 31ddff
            movi.n       a4, 0 /* 0x00000000 */                #  2b5: 0c04
            movi         a0, .Lrel033 /* sdk_os_timer_arm */   #  2b7: 01e3ff
            callx0       a0 /* sdk_os_timer_arm */             #  2ba: c00000
            movi.n       a9, 1 /* 0x00000001 */                #  2bd: 0c19
            movi         a11, .Lrel027 /* sdk_g_ic */          #  2bf: b1dbff
            l32i         a8, a12, 136 /* [[sdk_g_ic+0x10]+0x88] */ #  2c2: 822c22
            l32i.n       a11, a11, 16 /* [sdk_g_ic+0x10] */    #  2c5: b84b
            movi.n       a10, 0 /* 0x00000000 */               #  2c7: 0c0a
            s8i          a10, a11, 185 /* 0x00 -> [[sdk_g_ic+0x10]+0xb9] */ #  2c9: a24bb9
            s8i          a10, a8, 24 /* 0x00 -> [[[sdk_g_ic+0x10]+0x88]+0x18] */ #  2cc: a24818
            l32i.n       a7, a8, 8 /* [[[sdk_g_ic+0x10]+0x88]+0x8] */ #  2cf: 7828
            l32i.n       a0, a12, 0 /* [[sdk_g_ic+0x10]] */    #  2d1: 080c
            or           a7, a7, a9                            #  2d3: 907720
            s32i.n       a7, a8, 8 /* a7 -> [[[sdk_g_ic+0x10]+0x88]+0x8] */ #  2d6: 7928
            l8ui         a6, a0, 47 /* [[[sdk_g_ic+0x10]]+0x2f] */ #  2d8: 62002f
            bbsi         a6, 3, .Lbr017                        #  2db: 37e633
            l32i.n       a2, a0, 4 /* [[[sdk_g_ic+0x10]]+0x4] */ #  2de: 2810
            movi         a3, .Lrel028 /* sdk_dhcpc_flag */     #  2e0: 31d4ff
            bnez.n       a2, .Lbr016                           #  2e3: dc72
            l8ui         a3, a3, 0 /* [sdk_dhcpc_flag] */      #  2e5: 320300
            beqz.n       a3, .Lbr017                           #  2e8: ac63
            movi         a2, .Lrel029 /* .Lstr002 */           #  2ea: 21d2ff
            movi         a0, .Lrel034 /* printf */             #  2ed: 01d6ff
            callx0       a0 /* printf */                       #  2f0: c00000
            l32i.n       a2, a12, 0 /* [[sdk_g_ic+0x10]] */    #  2f3: 280c
            movi         a0, .Lrel035 /* dhcp_start */         #  2f5: 01d5ff
            callx0       a0 /* dhcp_start */                   #  2f8: c00000
            j            .Lbr017                               #  2fb: c60400
.Lbr016:    addi.n       a2, a0, 4 /* [[sdk_g_ic+0x10]]+0x4 */ #  2fe: 4b20
            addi.n       a3, a0, 8 /* [[sdk_g_ic+0x10]]+0x8 */ #  300: 8b30
            addi.n       a4, a0, 12 /* [[sdk_g_ic+0x10]]+0xc */ #  302: cb40
            movi         a0, .Lrel036 /* sdk_system_station_got_ip_set */ #  304: 01d3ff
            callx0       a0 /* sdk_system_station_got_ip_set */ #  307: c00000
            l32i.n       a2, a12, 0 /* [[sdk_g_ic+0x10]] */    #  30a: 280c
            movi         a0, .Lrel037 /* netif_set_up */       #  30c: 01d2ff
            callx0       a0 /* netif_set_up */                 #  30f: c00000
.Lbr017:    l32i.n       a12, a1, 8 /* [(local2)] */           #  312: c821
            l32i.n       a0, a1, 4 /* [(local1)] */            #  314: 0811
            addi         a1, a1, 16 /* (top of frame) */       #  316: 12c110
            ret.n                                              #  319: 0df0

            .balign      4
# Function @ .irom0.text+0x31c
# Local variables/stack:
#     (local0):  word[4]   @ -0x10
.literal_position
sdk_wpa_neg_complete:
            addi         a1, a1, -16 /* (local0) */            #  31c: 12c1f0
            s32i.n       a0, a1, 0 /* a0 -> [(local0)] */      #  31f: 0901
            call0        sdk_eagle_auth_done                   #  321: 050000
            l32i.n       a0, a1, 0 /* [(local0)] */            #  324: 0801
            addi         a1, a1, 16 /* (top of frame) */       #  326: 12c110
            ret.n                                              #  329: 0df0

            .balign      4
.Lrel038:   .word        .Lfunc001                             #  32c: e8000000
.Lrel039:   .word        sdk_wpa_config_assoc_ie               #  330: 00000000
.Lrel040:   .word        sdk_ppInstallKey                      #  334: 00000000
.Lrel041:   .word        .Lfunc002                             #  338: 14010000
.Lrel042:   .word        sdk_wpa_neg_complete                  #  33c: 00000000
.Lrel043:   .word        sdk_eapol_txcb                        #  340: 00000000
.Lrel044:   .word        sdk_wpa_register                      #  344: 00000000
.Lrel045:   .word        sdk_ppRegisterTxCallback              #  348: 00000000

# Function @ .irom0.text+0x34c
# Local variables/stack:
#     (local0):  word[4]   @ -0x10
.literal_position
sdk_wpa_attach:
            movi         a3, .Lrel038 /* .Lfunc001 */          #  34c: 31f8ff
            movi         a5, .Lrel040 /* sdk_ppInstallKey */   #  34f: 51f9ff
            movi         a6, .Lrel041 /* .Lfunc002 */          #  352: 61f9ff
            movi         a7, .Lrel042 /* sdk_wpa_neg_complete */ #  355: 71f9ff
            mov.n        a4, a2 /* arg0 */                     #  358: 4d02
            addi         a1, a1, -16 /* (local0) */            #  35a: 12c1f0
            s32i.n       a0, a1, 0 /* a0 -> [(local0)] */      #  35d: 0901
            movi.n       a2, 0 /* 0x00000000 */                #  35f: 0c02
            movi         a0, 384 /* 0x00000180 */              #  361: 02a180
            add.n        a0, a4, a0 /* arg0+0x180 */           #  364: 0a04
            s32i         a2, a4, 0x180 /* 0x00000000 -> [arg0+0x180] */ #  366: 226460
            s32i         a0, a4, 0x184 /* arg0+0x180 -> [arg0+0x184] */ #  369: 026461
            movi         a4, .Lrel039 /* sdk_wpa_config_assoc_ie */ #  36c: 41f1ff
            movi         a0, .Lrel044 /* sdk_wpa_register */   #  36f: 01f5ff
            callx0       a0 /* sdk_wpa_register */             #  372: c00000
            movi         a2, .Lrel043 /* sdk_eapol_txcb */     #  375: 21f2ff
            movi.n       a3, 3 /* 0x00000003 */                #  378: 0c33
            movi         a0, .Lrel045 /* sdk_ppRegisterTxCallback */ #  37a: 01f3ff
            callx0       a0 /* sdk_ppRegisterTxCallback */     #  37d: c00000
            l32i.n       a0, a1, 0 /* [(local0)] */            #  380: 0801
            addi         a1, a1, 16 /* (top of frame) */       #  382: 12c110
            ret.n                                              #  385: 0df0

            .section     .rodata.str1.4, "MSa", @progbits, 1

.Lstr001:   .asciz       "\nconnected with %s, channel %d\n"   #    0: 0a636f6e
                                                               #    4: 6e656374
                                                               #    8: 65642077
                                                               #    c: 69746820
                                                               #   10: 25732c20
                                                               #   14: 6368616e
                                                               #   18: 6e656c20
                                                               #   1c: 25640a00
.Lstr002:   .asciz       "dhcp client start...\n"              #   20: 64686370
                                                               #   24: 20636c69
                                                               #   28: 656e7420
                                                               #   2c: 73746172
                                                               #   30: 742e2e2e
                                                               #   34: 0a00
