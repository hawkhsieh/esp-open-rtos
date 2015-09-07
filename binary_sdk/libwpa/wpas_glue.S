
            .section     .irom0.literal, "ax", @progbits

            .section     .text, "ax", @progbits

            .section     .data, "aw", @progbits

            .section     .bss, "aw", @nobits

            .section     .irom0.text, "ax", @progbits

.Lrel001:   .word        memcpy                                #    0: 00000000
.Lrel002:   .word        memset                                #    4: 00000000

# Function @ .irom0.text+0x8
# Local variables/stack:
#     (local0):  word      @ -0x10
#     (local1):  word      @ -0xc
#     (local2):  word      @ -0x8
#     (local3):  word      @ -0x4
.literal_position
.Lfunc001:  addi         a1, a1, -16 /* (local0) */            #    8: 12c1f0
            s32i.n       a12, a1, 8 /* a12 -> [(local2)] */    #    b: c921
            l32i         a8, a2, 0x210 /* [arg0+0x210] */      #    d: 822284
            s32i.n       a13, a1, 12 /* a13 -> [(local3)] */   #   10: d931
            s32i.n       a0, a1, 4 /* a0 -> [(local1)] */      #   12: 0911
            mov.n        a13, a7 /* arg5 */                    #   14: dd07
            addi.n       a0, a5, 4 /* arg3+0x4 */              #   16: 4b05
            movi         a7, 208 /* 0x000000d0 */              #   18: 72a0d0
            add.n        a7, a2, a7 /* arg0+0xd0 */            #   1b: 7a72
            l32i.n       a2, a8, 4 /* [[arg0+0x210]+0x4] */    #   1d: 2818
            s32i.n       a0, a6, 0 /* arg3+0x4 -> [arg4] */    #   1f: 0906
            addi.n       a0, a2, 14 /* [[arg0+0x210]+0x4]+0xe */ #   21: eb02
            bnez.n       a0, .Lbr001                           #   23: cc30
            movi.n       a2, 0 /* 0x00000000 */                #   25: 0c02
            j            .Lbr005                               #   27: 461100
.Lbr001:    addi         a12, a2, 18 /* [[arg0+0x210]+0x4]+0x12 */ #   2a: c2c212
            s32i.n       a0, a1, 0 /* [[arg0+0x210]+0x4]+0xe -> [(local0)] */ #   2d: 0901
            extui        a8, a5, 8, 8                          #   2f: 508874
            extui        a9, a5, 0, 8                          #   32: 509074
            l8ui         a10, a7, 128 /* [arg0+0x150] */       #   35: a20780
            s8i          a10, a2, 14 /* [arg0+0x150] -> [[[arg0+0x210]+0x4]+0xe] */ #   38: a2420e
            slli         a9, a9, 8                             #   3b: 809911
            s8i          a3, a2, 15 /* arg1 -> [[[arg0+0x210]+0x4]+0xf] */ #   3e: 32420f
            or           a8, a8, a9                            #   41: 908820
            s8i          a8, a2, 16 /* a8 -> [[[arg0+0x210]+0x4]+0x10] */ #   44: 824210
            srli         a8, a8, 8                             #   47: 808841
            s8i          a8, a2, 17 /* a8 -> [[[arg0+0x210]+0x4]+0x11] */ #   4a: 824211
            beqz.n       a4, .Lbr002                           #   4d: 8cd4
            mov.n        a3, a4 /* arg2 */                     #   4f: 3d04
            mov.n        a2, a12 /* [[arg0+0x210]+0x4]+0x12 */ #   51: 2d0c
            mov.n        a4, a5 /* arg3 */                     #   53: 4d05
            movi         a0, .Lrel001 /* memcpy */             #   55: 01eaff
            callx0       a0 /* memcpy */                       #   58: c00000
            j            .Lbr003                               #   5b: c60200
.Lbr002:    mov.n        a4, a5 /* arg3 */                     #   5e: 4d05
            mov.n        a2, a12 /* [[arg0+0x210]+0x4]+0x12 */ #   60: 2d0c
            movi.n       a3, 0 /* 0x00000000 */                #   62: 0c03
            movi         a0, .Lrel002 /* memset */             #   64: 01e8ff
            callx0       a0 /* memset */                       #   67: c00000
.Lbr003:    beqz.n       a13, .Lbr004                          #   6a: 8c0d
            s32i.n       a12, a13, 0 /* [[arg0+0x210]+0x4]+0x12 -> [arg5] */ #   6c: c90d
.Lbr004:    l32i.n       a2, a1, 0 /* [(local0)] */            #   6e: 2801
.Lbr005:    l32i.n       a12, a1, 8 /* [(local2)] */           #   70: c821
            l32i.n       a13, a1, 12 /* [(local3)] */          #   72: d831
            l32i.n       a0, a1, 4 /* [(local1)] */            #   74: 0811
            addi         a1, a1, 16 /* (top of frame) */       #   76: 12c110
            ret.n                                              #   79: 0df0

            .balign      4
.Lrel003:   .word        pbuf_alloc                            #   7c: 00000000

# Function @ .irom0.text+0x80
# Local variables/stack:
#     (local0):  word      @ -0x20
#     (local1):  word      @ -0x1c
#     (local2):  word      @ -0x18
#     (local3):  word      @ -0x14
#     (local4):  word      @ -0x10
#     (local5):  word      @ -0xc
#     (local6):  word[2]   @ -0x8
.literal_position
sdk_wpa_sm_alloc_eapol:
            addi         a1, a1, -32 /* (local0) */            #   80: 12c1e0
            s32i.n       a5, a1, 12 /* arg3 -> [(local3)] */   #   83: 5931
            s32i.n       a6, a1, 16 /* arg4 -> [(local4)] */   #   85: 6941
            s32i.n       a7, a1, 20 /* arg5 -> [(local5)] */   #   87: 7951
            s32i.n       a0, a1, 24 /* a0 -> [(local6)] */     #   89: 0961
            s32i.n       a4, a1, 8 /* arg2 -> [(local2)] */    #   8b: 4921
            s32i.n       a2, a1, 0 /* arg0 -> [(local0)] */    #   8d: 2901
            s32i.n       a3, a1, 4 /* arg1 -> [(local1)] */    #   8f: 3911
            movi.n       a2, 3 /* 0x00000003 */                #   91: 0c32
            movi         a3, 256 /* 0x00000100 */              #   93: 32a100
            movi.n       a4, 0 /* 0x00000000 */                #   96: 0c04
            movi         a0, .Lrel003 /* pbuf_alloc */         #   98: 01f9ff
            callx0       a0 /* pbuf_alloc */                   #   9b: c00000
            l32i.n       a3, a1, 4 /* [(local1)] */            #   9e: 3811
            l32i.n       a4, a1, 8 /* [(local2)] */            #   a0: 4821
            l32i.n       a5, a1, 12 /* [(local3)] */           #   a2: 5831
            mov.n        a0, a2                                #   a4: 0d02
            l32i.n       a6, a1, 16 /* [(local4)] */           #   a6: 6841
            l32i.n       a2, a1, 0 /* [(local0)] */            #   a8: 2801
            l32i.n       a7, a1, 20 /* [(local5)] */           #   aa: 7851
            s32i         a0, a2, 0x210 /* a0 -> [[(local0)]+0x210] */ #   ac: 026284
            call0        .Lfunc001                             #   af: 85f5ff
            l32i.n       a0, a1, 24 /* [(local6)] */           #   b2: 0861
            addi         a1, a1, 32 /* (top of frame) */       #   b4: 12c120
            ret.n                                              #   b7: 0df0

            .balign      4
# Function @ .irom0.text+0xbc
# Local variables/stack:
#     (local0):  word[4]   @ -0x10
.literal_position
sdk_wpa_sm_deauthenticate:
            addi         a1, a1, -16 /* (local0) */            #   bc: 12c1f0
            s32i.n       a0, a1, 0 /* a0 -> [(local0)] */      #   bf: 0901
            l32i         a0, a2, 0x168 /* [arg0+0x168] */      #   c1: 02225a
            bltui        a0, 5, .Lbr006                        #   c4: b65007
            l32i         a0, a2, 0x220 /* [arg0+0x220] */      #   c7: 022288
            mov.n        a2, a3 /* arg1 */                     #   ca: 2d03
            callx0       a0 /* [arg0+0x220] */                 #   cc: c00000
.Lbr006:    l32i.n       a0, a1, 0 /* [(local0)] */            #   cf: 0801
            addi         a1, a1, 16 /* (top of frame) */       #   d1: 12c110
            ret.n                                              #   d4: 0df0

            .balign      4
# Function @ .irom0.text+0xd8
.literal_position
sdk_wpa_sm_mlme_setprotection:
            movi.n       a2, 0 /* 0x00000000 */                #   d8: 0c02
            ret.n         /* 0x00000000 */                     #   da: 0df0

# Function @ .irom0.text+0xdc
.literal_position
sdk_wpa_sm_get_beacon_ie:
            movi.n       a2, 0 /* 0x00000000 */                #   dc: 0c02
            ret.n         /* 0x00000000 */                     #   de: 0df0

# Function @ .irom0.text+0xe0
.literal_position
sdk_wpa_sm_disassociate:
            ret.n         /* arg0 */                           #   e0: 0df0
