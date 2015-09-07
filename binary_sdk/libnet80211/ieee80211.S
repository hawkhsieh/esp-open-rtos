
            .section     .irom0.literal, "ax", @progbits

            .section     .text, "ax", @progbits

            .section     .data, "aw", @progbits

            .section     .bss, "aw", @nobits

sdk_g_ic:   .space       16
.Ldata001:  .word        0x00000000                            #   10: 00000000
.Ldata002:  .word        0x00000000                            #   14: 00000000

# NOTE: 1328 non-alignment zero bytes skipped.

            .skip        1328
sdk_xieee80211Queue:
            .word        0x00000000                            #  548: 00000000

            .section     .irom0.text, "ax", @progbits

# NOTE: The following is apparently unreferenced code/data
.Llit001:   .word        0x0000096c                            #    0: 6c090000
.Llit002:   .word        0x000009b4                            #    4: b4090000
.Llit003:   .word        0x000009b4                            #    8: b4090000

.Lrel001:   .word        sdk_ieee80211_get_ratetable           #    c: 00000000

# Function @ .irom0.text+0x10
# Local variables/stack:
#     (local0):  word      @ -0x20
#     (local1):  word      @ -0x1c
#     (local2):  word      @ -0x18
#     (local3):  word      @ -0x14
#     (local4):  word      @ -0x10
#     (local5):  word      @ -0xc
#     (local6):  word[2]   @ -0x8
.literal_position
.Lfunc001:  movi         a5, 131 /* 0x00000083 */              #   10: 52a083
            movi         a6, .Llit002 /* 0x000009b4 */         #   13: 61fcff
            addi         a1, a1, -32 /* (local0) */            #   16: 12c1e0
            s32i.n       a2, a1, 24 /* arg0 -> [(local6)] */   #   19: 2961
            s32i.n       a15, a1, 16 /* a15 -> [(local4)] */   #   1b: f941
            s32i.n       a0, a1, 0 /* a0 -> [(local0)] */      #   1d: 0901
            s32i.n       a12, a1, 4 /* a12 -> [(local1)] */    #   1f: c911
            s32i.n       a13, a1, 8 /* a13 -> [(local2)] */    #   21: d921
            s32i.n       a14, a1, 12 /* a14 -> [(local3)] */   #   23: e931
            movi         a13, .Llit001 /* 0x0000096c */        #   25: d1f6ff
            movi.n       a14, 0 /* 0x00000000 */               #   28: 0c0e
            mov.n        a12, a2 /* arg0 */                    #   2a: cd02
            movi         a0, 156 /* 0x0000009c */              #   2c: 02a09c
            mov.n        a15, a2 /* arg0 */                    #   2f: fd02
            add.n        a0, a15, a0 /* arg0+0x9c */           #   31: 0a0f
            movi.n       a2, 14 /* 0x0000000e */               #   33: 0ce2
            s32i         a2, a15, 128 /* 0x0000000e -> [arg0+0x80] */ #   35: 226f20
.Lbr001:    s32i         a5, a12, 132                          #   38: 526c21
            l8ui         a3, a12, 138                          #   3b: 320c8a
            s32i.n       a0, a1, 20 /* a0 -> [(local5)] */     #   3e: 0951
            bltu         a0, a12, .Lbr002                      #   40: c73008
            s16i         a13, a12, 136                         #   43: d25c44
            bne          a12, a0, .Lbr002                      #   46: 079c02
            s16i         a6, a12, 136                          #   49: 625c44
.Lbr002:    bnez.n       a3, .Lbr003                           #   4c: dc23
            l16ui        a2, a12, 136                          #   4e: 221c44
            movi         a3, 131 /* 0x00000083 */              #   51: 32a083
            call0        sdk_ieee80211_mhz2ieee                #   54: 050000
            l32i.n       a0, a1, 20 /* [(local5)] */           #   57: 0851
            movi         a5, 131 /* 0x00000083 */              #   59: 52a083
            movi         a6, .Llit003 /* .Llit003 */           #   5c: 61ebff
            s8i          a2, a12, 138                          #   5f: 224c8a
.Lbr003:    addi.n       a13, a13, 5                           #   62: 5bdd
            l8ui         a4, a12, 139                          #   64: 420c8b
            addi.n       a14, a14, 1                           #   67: 1bee
            bnez.n       a4, .Lbr004                           #   69: ccd4
            l8ui         a7, a12, 141                          #   6b: 720c8d
            slli         a7, a7, 24                            #   6e: 807701
            srai         a7, a7, 24                            #   71: 707831
            slli         a7, a7, 1                             #   74: f07711
            s8i          a7, a12, 139                          #   77: 724c8b
.Lbr004:    l32i         a8, a15, 128 /* [arg0+0x80] */        #   7a: 822f20
            addi.n       a12, a12, 12                          #   7d: cbcc
            blt          a14, a8, .Lbr001                      #   7f: 872eb5
            movi         a2, 132 /* 0x00000084 */              #   82: 22a084
            add.n        a2, a15, a2 /* arg0+0x84 */           #   85: 2a2f
            movi         a0, .Lrel001 /* .Lrel001 */           #   87: 01e1ff
            callx0       a0                                    #   8a: c00000
            l32i.n       a0, a1, 0 /* [(local0)] */            #   8d: 0801
            l32i.n       a12, a1, 4 /* [(local1)] */           #   8f: c811
            l32i.n       a13, a1, 8 /* [(local2)] */           #   91: d821
            s32i         a2, a15, 0x150 /* a2 -> [arg0+0x150] */ #   93: 226f54
            l32i.n       a14, a1, 12 /* [(local3)] */          #   96: e831
            l32i.n       a15, a1, 16 /* [(local4)] */          #   98: f841
            addi         a1, a1, 32 /* (top of frame) */       #   9a: 12c120
            ret.n                                              #   9d: 0df0

            .balign      4
.Lrel002:   .word        .bss                                  #   a0: 00000000
.Lrel003:   .word        sdk_ieee80211_crypto_attach           #   a4: 00000000
.Lrel004:   .word        sdk_ieee80211_proto_attach            #   a8: 00000000
.Lrel005:   .word        sdk_ieee80211_ht_attach               #   ac: 00000000
.Lrel006:   .word        sdk_chm_init                          #   b0: 00000000
.Lrel007:   .word        sdk_ieee80211_scan_attach             #   b4: 00000000

# Function @ .irom0.text+0xb8
# Local variables/stack:
#     (local0):  word      @ -0x10
#     (local1):  word[3]   @ -0xc
.literal_position
sdk_ieee80211_ifattach:
            addi         a1, a1, -16 /* (local0) */            #   b8: 12c1f0
            s32i.n       a12, a1, 4 /* a12 -> [(local1)] */    #   bb: c911
            s32i.n       a0, a1, 0 /* a0 -> [(local0)] */      #   bd: 0901
            mov.n        a12, a2 /* arg0 */                    #   bf: cd02
            call0        .Lfunc001                             #   c1: c5f4ff
            mov.n        a2, a12 /* arg0 */                    #   c4: 2d0c
            movi         a0, 100 /* 0x00000064 */              #   c6: 02a064
            s16i         a0, a12, 40 /* 0x0064 -> [arg0+0x28] */ #   c9: 025c14
            movi         a0, .Lrel003 /* sdk_ieee80211_crypto_attach */ #   cc: 01f6ff
            callx0       a0 /* sdk_ieee80211_crypto_attach */  #   cf: c00000
            mov.n        a2, a12 /* arg0 */                    #   d2: 2d0c
            movi         a0, .Lrel004 /* sdk_ieee80211_proto_attach */ #   d4: 01f5ff
            callx0       a0 /* sdk_ieee80211_proto_attach */   #   d7: c00000
            movi.n       a3, 0 /* 0x00000000 */                #   da: 0c03
            addmi        a4, a12, 1280 /* arg0+0x500 */        #   dc: 42dc05
            l32i.n       a2, a4, 28 /* [arg0+0x51c] */         #   df: 2874
            s32i.n       a3, a4, 12 /* 0x00000000 -> [arg0+0x50c] */ #   e1: 3934
            bnei         a2, 3, .Lbr005                        #   e3: 663207
            mov.n        a2, a12 /* arg0 */                    #   e6: 2d0c
            movi         a0, .Lrel005 /* sdk_ieee80211_ht_attach */ #   e8: 01f1ff
            callx0       a0 /* sdk_ieee80211_ht_attach */      #   eb: c00000
.Lbr005:    movi         a2, .Lrel002 /* sdk_g_ic */           #   ee: 21ecff
            movi         a0, .Lrel006 /* sdk_chm_init */       #   f1: 01efff
            callx0       a0 /* sdk_chm_init */                 #   f4: c00000
            mov.n        a2, a12 /* arg0 */                    #   f7: 2d0c
            movi         a0, .Lrel007 /* sdk_ieee80211_scan_attach */ #   f9: 01eeff
            callx0       a0 /* sdk_ieee80211_scan_attach */    #   fc: c00000
            l32i.n       a12, a1, 4 /* [(local1)] */           #   ff: c811
            l32i.n       a0, a1, 0 /* [(local0)] */            #  101: 0801
            addi         a1, a1, 16 /* (top of frame) */       #  103: 12c110
            ret.n                                              #  106: 0df0

# NOTE: The following is apparently unreferenced code/data
.Llit004:   .word        0x000009b4                            #  108: b4090000
.Llit005:   .word        0x000009b3                            #  10c: b3090000
.Llit006:   .word        0xfffff699                            #  110: 99f6ffff
.Llit007:   .word        0xfffff630                            #  114: 30f6ffff

.Lrel008:   .word        __divsi3                              #  118: 00000000
.Lrel009:   .word        __divsi3                              #  11c: 00000000
.Lrel010:   .word        __udivsi3                             #  120: 00000000

# Function @ .irom0.text+0x124
# Local variables/stack:
#     (local0):  word[4]   @ -0x10
.literal_position
sdk_ieee80211_mhz2ieee:
            movi         a6, .Llit005 /* 0x000009b3 */         #  124: 61faff
            movi         a7, .Llit006 /* 0xfffff699 */         #  127: 71faff
            addi         a1, a1, -16 /* (local0) */            #  12a: 12c1f0
            s32i.n       a0, a1, 0 /* a0 -> [(local0)] */      #  12d: 0901
            movi         a0, .Llit004 /* 0x000009b4 */         #  12f: 01f6ff
            bbci         a3, 7, .Lbr006                        #  132: 776312
            beq          a2, a0, .Lbr010                       #  135: 07123d
            bltu         a6, a2, .Lbr009                       #  138: 273628
            add.n        a2, a2, a7 /* arg0+0xfffff699 */      #  13b: 7a22
            movi.n       a3, 5 /* 0x00000005 */                #  13d: 0c53
            movi         a0, .Lrel008 /* __divsi3 */           #  13f: 01f6ff
            callx0       a0 /* __divsi3 */                     #  142: c00000
            j            .Lbr008                               #  145: 060500
.Lbr006:    beq          a2, a0, .Lbr010                       #  148: 07122a
            bltu         a6, a2, .Lbr007                       #  14b: 27360c
            add.n        a2, a2, a7 /* arg0+0xfffff699 */      #  14e: 7a22
            movi.n       a3, 5 /* 0x00000005 */                #  150: 0c53
            movi         a0, .Lrel009 /* __divsi3 */           #  152: 01f2ff
            callx0       a0 /* __divsi3 */                     #  155: c00000
            j            .Lbr008                               #  158: 460000
.Lbr007:    movi.n       a2, -1 /* 0xffffffff */               #  15b: 7cf2
.Lbr008:    l32i.n       a0, a1, 0 /* [(local0)] */            #  15d: 0801
            addi         a1, a1, 16 /* (top of frame) */       #  15f: 12c110
            ret.n                                              #  162: 0df0
.Lbr009:    movi         a0, .Llit007 /* 0xfffff630 */         #  164: 01ecff
            movi.n       a3, 20 /* 0x00000014 */               #  167: 1c43
            add.n        a2, a2, a0 /* arg0+0xfffff630 */      #  169: 0a22
            movi         a0, .Lrel010 /* __udivsi3 */          #  16b: 01edff
            callx0       a0 /* __udivsi3 */                    #  16e: c00000
            addi.n       a2, a2, 15                            #  171: fb22
            j            .Lbr008                               #  173: 86f9ff
.Lbr010:    movi.n       a2, 14 /* 0x0000000e */               #  176: 0ce2
            j            .Lbr008                               #  178: 46f8ff

# NOTE: The following is apparently unreferenced code/data
            .balign      4
.Llit008:   .word        0x0000ffff                            #  17c: ffff0000

# Function @ .irom0.text+0x180
.literal_position
sdk_ieee80211_chan2ieee:
            bnez.n       a2, .Lbr011                           #  180: cc22
            movi.n       a2, 0 /* 0x00000000 */                #  182: 0c02
            ret.n         /* 0x00000000 */                     #  184: 0df0
.Lbr011:    movi         a5, .Llit008 /* 0x0000ffff */         #  186: 51fdff
            beq          a2, a5, .Lbr012                       #  189: 571204
            l8ui         a2, a2, 6 /* [arg0+0x6] */            #  18c: 220206
            ret.n         /* [arg0+0x6] */                     #  18f: 0df0
.Lbr012:    mov.n        a2, a5 /* 0x0000ffff */               #  191: 2d05
            ret.n         /* 0x0000ffff */                     #  193: 0df0

# NOTE: The following is apparently unreferenced code/data
            .balign      4
.Llit009:   .word        0x00000967                            #  198: 67090000
.Llit010:   .word        0x000008a4                            #  19c: a4080000
.Llit011:   .word        0x00001388                            #  1a0: 88130000
.Llit012:   .word        0x000009b4                            #  1a4: b4090000

# Function @ .irom0.text+0x1a8
.literal_position
sdk_ieee80211_ieee2mhz:
            movi.n       a7, 14 /* 0x0000000e */               #  1a8: 0ce7
            movi.n       a8, 13 /* 0x0000000d */               #  1aa: 0cd8
            movi         a6, .Llit009 /* 0x00000967 */         #  1ac: 61fbff
            movi         a9, .Llit010 /* 0x000008a4 */         #  1af: 91fbff
            bbci         a3, 7, .Lbr014                        #  1b2: 77630d
            beq          a2, a7, .Lbr016                       #  1b5: 77121f
            bgeu         a8, a2, .Lbr015                       #  1b8: 27b815
.Lbr013:    addx4        a2, a2, a2                            #  1bb: 2022a0
            addx4        a2, a2, a9                            #  1be: 9022a0
            ret.n                                              #  1c1: 0df0
.Lbr014:    beq          a2, a7, .Lbr016                       #  1c3: 771211
            bgeu         a8, a2, .Lbr015                       #  1c6: 27b807
            movi.n       a3, 26 /* 0x0000001a */               #  1c9: 1ca3
            bgeu         a3, a2, .Lbr013                       #  1cb: 27b3ec
            movi         a6, .Llit011 /* 0x00001388 */         #  1ce: 61f4ff
.Lbr015:    addx4        a2, a2, a2                            #  1d1: 2022a0
            add.n        a2, a2, a6                            #  1d4: 6a22
            ret.n                                              #  1d6: 0df0
.Lbr016:    movi         a2, .Llit012 /* 0x000009b4 */         #  1d8: 21f3ff
            ret.n         /* 0x000009b4 */                     #  1db: 0df0

            .balign      4
# Function @ .irom0.text+0x1e0
.literal_position
sdk_ieee80211_find_channel:
            l32i         a6, a2, 128 /* [arg0+0x80] */         #  1e0: 622220
            blti         a6, 1, .Lbr019                        #  1e3: a6161d
            addx2        a7, a6, a6                            #  1e6: 607690
            addx4        a7, a7, a2                            #  1e9: 2077a0
.Lbr017:    l16ui        a8, a2, 136                           #  1ec: 821244
            l32i         a9, a2, 132                           #  1ef: 922221
            bne          a3, a8, .Lbr018                       #  1f2: 879309
            bnone        a9, a4, .Lbr018                       #  1f5: 470906
            movi         a10, 132 /* 0x00000084 */             #  1f8: a2a084
            add.n        a2, a2, a10                           #  1fb: aa22
            ret.n                                              #  1fd: 0df0
.Lbr018:    addi.n       a2, a2, 12                            #  1ff: cb22
            bne          a2, a7, .Lbr017                       #  201: 7792e7
.Lbr019:    movi.n       a2, 0 /* 0x00000000 */                #  204: 0c02
            ret.n         /* 0x00000000 */                     #  206: 0df0

# Function @ .irom0.text+0x208
.literal_position
sdk_ieee80211_find_channel_byieee:
            l32i         a6, a2, 128 /* [arg0+0x80] */         #  208: 622220
            blti         a6, 1, .Lbr022                        #  20b: a6161d
            addx2        a7, a6, a6                            #  20e: 607690
            addx4        a7, a7, a2                            #  211: 2077a0
.Lbr020:    l8ui         a8, a2, 138                           #  214: 82028a
            l32i         a9, a2, 132                           #  217: 922221
            bne          a3, a8, .Lbr021                       #  21a: 879309
            bnone        a9, a4, .Lbr021                       #  21d: 470906
            movi         a10, 132 /* 0x00000084 */             #  220: a2a084
            add.n        a2, a2, a10                           #  223: aa22
            ret.n                                              #  225: 0df0
.Lbr021:    addi.n       a2, a2, 12                            #  227: cb22
            bne          a2, a7, .Lbr020                       #  229: 7792e7
.Lbr022:    movi.n       a2, 0 /* 0x00000000 */                #  22c: 0c02
            ret.n         /* 0x00000000 */                     #  22e: 0df0

.Lrel011:   .word        .rodata.str1.4                        #  230: 00000000
.Lrel012:   .word        .Label001                             #  234: 10000000
.Lrel013:   .word        sdk_info                              #  238: 00000000
.Lrel014:   .word        .Lstr003                              #  23c: 14000000
.Lrel015:   .word        .bss                                  #  240: 00000000
.Lrel016:   .word        .bss                                  #  244: 00000000
.Lrel017:   .word        .bss                                  #  248: 00000000
.Lrel018:   .word        .Label002                             #  24c: 34000000
.Lrel019:   .word        .Label003                             #  250: 3c000000
.Lrel020:   .word        .bss                                  #  254: 00000000
.Lrel021:   .word        .Lstr004                              #  258: 40000000
.Lrel022:   .word        sdk_info                              #  25c: 00000000
.Lrel023:   .word        .Lstr003                              #  260: 14000000
.Lrel024:   .word        .Label002                             #  264: 34000000
.Lrel025:   .word        .Lstr002                              #  268: 08000000
.Lrel026:   .word        .Label004                             #  26c: 48000000
.Lrel027:   .word        printf                                #  270: 00000000
.Lrel028:   .word        printf                                #  274: 00000000
.Lrel029:   .word        printf                                #  278: 00000000
.Lrel030:   .word        zalloc                                #  27c: 00000000
.Lrel031:   .word        zalloc                                #  280: 00000000
.Lrel032:   .word        memcpy                                #  284: 00000000
.Lrel033:   .word        printf                                #  288: 00000000
.Lrel034:   .word        printf                                #  28c: 00000000
.Lrel035:   .word        printf                                #  290: 00000000
.Lrel036:   .word        zalloc                                #  294: 00000000
.Lrel037:   .word        zalloc                                #  298: 00000000
.Lrel038:   .word        memcpy                                #  29c: 00000000
.Lrel039:   .word        printf                                #  2a0: 00000000
.Lrel040:   .word        printf                                #  2a4: 00000000

# Function @ .irom0.text+0x2a8
# Local variables/stack:
#     (local0):  word[4]   @ -0x20
#     (local1):  word      @ -0x10
#     (local2):  word[3]   @ -0xc
.literal_position
sdk_wifi_mode_set:
            addi         a1, a1, -32 /* (local0) */            #  2a8: 12c1e0
            s32i.n       a12, a1, 20 /* a12 -> [(local2)] */   #  2ab: c951
            s32i.n       a0, a1, 16 /* a0 -> [(local1)] */     #  2ad: 0941
            mov.n        a12, a2 /* arg0 */                    #  2af: cd02
            movi         a2, .Lrel011 /* .Lstr001 */           #  2b1: 21dfff
            movi         a0, .Lrel027 /* printf */             #  2b4: 01efff
            callx0       a0 /* printf */                       #  2b7: c00000
            beqz         a12, .Lbr026                          #  2ba: 164c0d
            beqi         a12, 1, .Lbr023                       #  2bd: 261c08
            beqi         a12, 2, .Lbr025                       #  2c0: 262c72
            addi         a0, a12, -3 /* arg0-0x3 */            #  2c3: 02ccfd
            bnez         a0, .Lbr027                           #  2c6: 56100d
.Lbr023:    movi         a2, .Lrel012 /* .Label001 */          #  2c9: 21daff
            movi         a0, .Lrel028 /* printf */             #  2cc: 01eaff
            callx0       a0 /* printf */                       #  2cf: c00000
            movi         a2, .Lrel013 /* sdk_info */           #  2d2: 21d9ff
            l8ui         a7, a2, 34 /* [sdk_info+0x22] */      #  2d5: 720222
            l8ui         a6, a2, 33 /* [sdk_info+0x21] */      #  2d8: 620221
            l8ui         a5, a2, 32 /* [sdk_info+0x20] */      #  2db: 520220
            l8ui         a4, a2, 31 /* [sdk_info+0x1f] */      #  2de: 42021f
            l8ui         a3, a2, 30 /* [sdk_info+0x1e] */      #  2e1: 32021e
            l8ui         a2, a2, 35 /* [sdk_info+0x23] */      #  2e4: 220223
            s32i.n       a2, a1, 0 /* [sdk_info+0x23] -> [(local0)] */ #  2e7: 2901
            movi         a2, .Lrel014 /* .Lstr003 */           #  2e9: 21d4ff
            movi         a0, .Lrel029 /* printf */             #  2ec: 01e3ff
            callx0       a0 /* printf */                       #  2ef: c00000
            movi         a3, .Lrel015 /* sdk_g_ic */           #  2f2: 31d3ff
            l32i.n       a3, a3, 16 /* [.Ldata001] */          #  2f5: 3843
            bnez.n       a3, .Lbr024                           #  2f7: ecf3
            movi         a2, 648 /* 0x00000288 */              #  2f9: 22a288
            movi         a0, .Lrel030 /* zalloc */             #  2fc: 01e0ff
            callx0       a0 /* zalloc */                       #  2ff: c00000
            movi         a5, .Lrel016 /* sdk_g_ic */           #  302: 51d0ff
            movi.n       a4, 0 /* 0x00000000 */                #  305: 0c04
            s32i.n       a2, a5, 16 /* a2 -> [.Ldata001] */    #  307: 2945
            s32i         a4, a2, 176                           #  309: 42622c
            s32i.n       a4, a2, 60                            #  30c: 49f2
            movi         a2, 272 /* 0x00000110 */              #  30e: 22a110
            movi         a0, .Lrel031 /* zalloc */             #  311: 01dbff
            callx0       a0 /* zalloc */                       #  314: c00000
            movi         a6, .Lrel017 /* sdk_g_ic */           #  317: 61ccff
            movi         a3, .Lrel018 /* .Label002 */          #  31a: 31ccff
            l32i.n       a6, a6, 16 /* [.Ldata001] */          #  31d: 6846
            movi.n       a4, 6 /* 0x00000006 */                #  31f: 0c64
            s32i         a2, a6, 140 /* a2 -> [[.Ldata001]+0x8c] */ #  321: 226623
            movi         a0, .Lrel032 /* memcpy */             #  324: 01d8ff
            callx0       a0 /* memcpy */                       #  327: c00000
.Lbr024:    beqi         a12, 1, .Lbr027                       #  32a: 261c6d
            movi         a2, .Lrel019 /* .Label003 */          #  32d: 21c8ff
            movi         a0, .Lrel033 /* printf */             #  330: 01d6ff
            callx0       a0 /* printf */                       #  333: c00000
.Lbr025:    movi         a12, .Lrel020 /* sdk_g_ic */          #  336: c1c7ff
            movi         a2, .Lrel021 /* .Lstr004 */           #  339: 21c7ff
            movi         a0, .Lrel034 /* printf */             #  33c: 01d4ff
            callx0       a0 /* printf */                       #  33f: c00000
            movi         a8, .Lrel022 /* sdk_info */           #  342: 81c6ff
            movi         a2, .Lrel023 /* .Lstr003 */           #  345: 21c6ff
            l8ui         a7, a8, 28 /* [sdk_info+0x1c] */      #  348: 72081c
            l8ui         a6, a8, 27 /* [sdk_info+0x1b] */      #  34b: 62081b
            l8ui         a5, a8, 26 /* [sdk_info+0x1a] */      #  34e: 52081a
            l8ui         a4, a8, 25 /* [sdk_info+0x19] */      #  351: 420819
            l8ui         a3, a8, 24 /* [sdk_info+0x18] */      #  354: 320818
            l8ui         a8, a8, 29 /* [sdk_info+0x1d] */      #  357: 82081d
            s32i.n       a8, a1, 0 /* [sdk_info+0x1d] -> [(local0)] */ #  35a: 8901
            movi         a0, .Lrel035 /* printf */             #  35c: 01cdff
            callx0       a0 /* printf */                       #  35f: c00000
            l32i.n       a9, a12, 20 /* [.Ldata002] */         #  362: 985c
            bnez.n       a9, .Lbr027                           #  364: fc39
            movi         a2, 648 /* 0x00000288 */              #  366: 22a288
            movi         a0, .Lrel036 /* zalloc */             #  369: 01caff
            callx0       a0 /* zalloc */                       #  36c: c00000
            s32i.n       a2, a12, 20 /* a2 -> [.Ldata002] */   #  36f: 295c
            movi.n       a10, 1 /* 0x00000001 */               #  371: 0c1a
            s32i         a10, a2, 176                          #  373: a2622c
            movi         a2, 272 /* 0x00000110 */              #  376: 22a110
            movi         a0, .Lrel037 /* zalloc */             #  379: 01c7ff
            callx0       a0 /* zalloc */                       #  37c: c00000
            movi         a3, .Lrel024 /* .Label002 */          #  37f: 31b9ff
            l32i.n       a11, a12, 20 /* [.Ldata002] */        #  382: b85c
            movi.n       a4, 6 /* 0x00000006 */                #  384: 0c64
            s32i         a2, a11, 144 /* a2 -> [[.Ldata002]+0x90] */ #  386: 226b24
            movi         a0, .Lrel038 /* memcpy */             #  389: 01c4ff
            callx0       a0 /* memcpy */                       #  38c: c00000
            j            .Lbr027                               #  38f: 060200
.Lbr026:    movi         a2, .Lrel025 /* .Lstr002 */           #  392: 21b5ff
            movi         a0, .Lrel039 /* printf */             #  395: 01c2ff
            callx0       a0 /* printf */                       #  398: c00000
.Lbr027:    movi         a2, .Lrel026 /* .Label004 */          #  39b: 21b4ff
            movi         a0, .Lrel040 /* printf */             #  39e: 01c1ff
            callx0       a0 /* printf */                       #  3a1: c00000
            movi.n       a2, 1 /* 0x00000001 */                #  3a4: 0c12
            l32i.n       a12, a1, 20 /* [(local2)] */          #  3a6: c851
            l32i.n       a0, a1, 16 /* [(local1)] */           #  3a8: 0841
            addi         a1, a1, 32 /* (top of frame) */       #  3aa: 12c120
            ret.n         /* 0x00000001 */                     #  3ad: 0df0

            .section     .rodata, "a", @progbits

sdk_ieee80211_opcap:
            .byte        0x01, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00

            .section     .rodata.str1.4, "MSa", @progbits, 1

.Lstr001:   .asciz       "mode : "                             #    0: 6d6f6465
                                                               #    4: 203a2000
.Lstr002:   .asciz       "null"                                #    8: 6e756c6c
                                                               #    c: 00
            .balign      4
.Label001:  .word        0x00617473                            #   10: 73746100
.Lstr003:   .asciz       "(%02x:%02x:%02x:%02x:%02x:%02x)"     #   14: 28253032
                                                               #   18: 783a2530
                                                               #   1c: 32783a25
                                                               #   20: 3032783a
                                                               #   24: 25303278
                                                               #   28: 3a253032
                                                               #   2c: 783a2530
                                                               #   30: 32782900
.Label002:  .byte        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00
.Label003:  .word        0x00202b20                            #   3c: 202b2000
.Lstr004:   .asciz       "softAP"                              #   40: 736f6674
                                                               #   44: 415000
            .balign      4
.Label004:  .byte        0x0a, 0x00
