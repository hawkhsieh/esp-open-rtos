
            .section     .irom0.literal, "ax", @progbits

            .section     .literal, "ax", @progbits

            .section     .text, "ax", @progbits

.Lrel001:   .word        .bss                                  #    0: 00000000
.Lrel002:   .word        sdk_phy_init                          #    4: 00000000

# Function @ .text+0x8
# Local variables/stack:
#     (local0):  word[4]   @ -0x10
.literal_position
sdk_register_phy_ops:
            movi.n       a3, 0 /* 0x00000000 */                #    8: 0c03
            addi         a1, a1, -16 /* (local0) */            #    a: 12c1f0
            mov.n        a5, a2 /* arg0 */                     #    d: 5d02
            s32i.n       a0, a1, 0 /* a0 -> [(local0)] */      #    f: 0901
            movi         a0, .Lrel001 /* .Ldata001 */          #   11: 01fbff
            movi.n       a2, 1 /* 0x00000001 */                #   14: 0c12
            s32i.n       a5, a0, 0 /* arg0 -> [.Ldata001] */   #   16: 5900
            movi         a0, .Lrel002 /* sdk_phy_init */       #   18: 01fbff
            callx0       a0 /* sdk_phy_init */                 #   1b: c00000
            l32i.n       a0, a1, 0 /* [(local0)] */            #   1e: 0801
            addi         a1, a1, 16 /* (top of frame) */       #   20: 12c110
            ret.n                                              #   23: 0df0

            .balign      4
.Lrel003:   .word        .bss                                  #   28: 00000000

# Function @ .text+0x2c
# Local variables/stack:
#     (local0):  word[4]   @ -0x10
.literal_position
sdk_phy_change_channel:
            addi         a1, a1, -16 /* (local0) */            #   2c: 12c1f0
            s32i.n       a0, a1, 0 /* a0 -> [(local0)] */      #   2f: 0901
            movi         a0, .Lrel003 /* .Ldata001 */          #   31: 01fdff
            l32i.n       a0, a0, 0 /* [.Ldata001] */           #   34: 0800
            l32i.n       a0, a0, 4 /* [[.Ldata001]+0x4] */     #   36: 0810
            callx0       a0 /* [[.Ldata001]+0x4] */            #   38: c00000
            movi.n       a2, 0 /* 0x00000000 */                #   3b: 0c02
            l32i.n       a0, a1, 0 /* [(local0)] */            #   3d: 0801
            addi         a1, a1, 16 /* (top of frame) */       #   3f: 12c110
            ret.n         /* 0x00000000 */                     #   42: 0df0

.Llit001:   .word        0x3ff20a00                            #   44: 000af23f

# Function @ .text+0x48
.literal_position
sdk_phy_get_mactime:
            movi         a2, .Llit001 /* 0x3ff20a00 */         #   48: 21ffff
            memw                                               #   4b: c02000
            l32i         a2, a2, 0x200 /* [0x3ff20c00] */      #   4e: 222280
            ret.n         /* [0x3ff20c00] */                   #   51: 0df0

            .section     .data, "aw", @progbits

            .section     .bss, "aw", @nobits

.Ldata001:  .word        0x00000000                            #    0: 00000000

            .section     .irom0.text, "ax", @progbits

.Lrel004:   .word        .bss                                  #    0: 00000000

# Function @ .irom0.text+0x4
# Local variables/stack:
#     (local0):  word[4]   @ -0x10
.literal_position
sdk_rf_init:
            addi         a1, a1, -16 /* (local0) */            #    4: 12c1f0
            s32i.n       a0, a1, 0 /* a0 -> [(local0)] */      #    7: 0901
            movi         a0, .Lrel004 /* .Ldata001 */          #    9: 01fdff
            l32i.n       a0, a0, 0 /* [.Ldata001] */           #    c: 0800
            slli         a4, a2, 24                            #    e: 804201
            l32i.n       a0, a0, 0 /* [[.Ldata001]] */         #   11: 0800
            srai         a2, a4, 24                            #   13: 402831
            callx0       a0 /* [[.Ldata001]] */                #   16: c00000
            l32i.n       a0, a1, 0 /* [(local0)] */            #   19: 0801
            addi         a1, a1, 16 /* (top of frame) */       #   1b: 12c110
            ret.n                                              #   1e: 0df0

.Lrel005:   .word        .bss                                  #   20: 00000000

# Function @ .irom0.text+0x24
# Local variables/stack:
#     (local0):  word[4]   @ -0x10
.literal_position
sdk_bb_init:
            addi         a1, a1, -16 /* (local0) */            #   24: 12c1f0
            s32i.n       a0, a1, 0 /* a0 -> [(local0)] */      #   27: 0901
            movi         a0, .Lrel005 /* .Ldata001 */          #   29: 01fdff
            l32i.n       a0, a0, 0 /* [.Ldata001] */           #   2c: 0800
            l32i.n       a0, a0, 24 /* [[.Ldata001]+0x18] */   #   2e: 0860
            callx0       a0 /* [[.Ldata001]+0x18] */           #   30: c00000
            l32i.n       a0, a1, 0 /* [(local0)] */            #   33: 0801
            addi         a1, a1, 16 /* (top of frame) */       #   35: 12c110
            ret.n                                              #   38: 0df0

            .balign      4
.Lrel006:   .word        .bss                                  #   3c: 00000000
.Lrel007:   .word        .bss                                  #   40: 00000000

# Function @ .irom0.text+0x44
# Local variables/stack:
#     (local0):  word      @ -0x10
#     (local1):  word[3]   @ -0xc
.literal_position
sdk_phy_init:
            addi         a1, a1, -16 /* (local0) */            #   44: 12c1f0
            s32i.n       a12, a1, 4 /* a12 -> [(local1)] */    #   47: c911
            s32i.n       a0, a1, 0 /* a0 -> [(local0)] */      #   49: 0901
            mov.n        a12, a3 /* arg1 */                    #   4b: cd03
            movi         a0, .Lrel006 /* .Ldata001 */          #   4d: 01fbff
            slli         a3, a2, 24                            #   50: 803201
            l32i.n       a0, a0, 0 /* [.Ldata001] */           #   53: 0800
            srai         a2, a3, 24                            #   55: 302831
            l32i.n       a0, a0, 0 /* [[.Ldata001]] */         #   58: 0800
            mov.n        a3, a12 /* arg1 */                    #   5a: 3d0c
            callx0       a0 /* [[.Ldata001]] */                #   5c: c00000
            movi         a0, .Lrel007 /* .Ldata001 */          #   5f: 01f8ff
            l32i.n       a0, a0, 0 /* [.Ldata001] */           #   62: 0800
            l32i.n       a0, a0, 24 /* [[.Ldata001]+0x18] */   #   64: 0860
            mov.n        a2, a12 /* arg1 */                    #   66: 2d0c
            callx0       a0 /* [[.Ldata001]+0x18] */           #   68: c00000
            l32i.n       a12, a1, 4 /* [(local1)] */           #   6b: c811
            l32i.n       a0, a1, 0 /* [(local0)] */            #   6d: 0801
            addi         a1, a1, 16 /* (top of frame) */       #   6f: 12c110
            ret.n                                              #   72: 0df0

.Lrel008:   .word        .bss                                  #   74: 00000000

# Function @ .irom0.text+0x78
# Local variables/stack:
#     (local0):  word[4]   @ -0x10
.literal_position
sdk_RFChannelSel:
            addi         a1, a1, -16 /* (local0) */            #   78: 12c1f0
            s32i.n       a0, a1, 0 /* a0 -> [(local0)] */      #   7b: 0901
            movi         a0, .Lrel008 /* .Ldata001 */          #   7d: 01fdff
            l32i.n       a0, a0, 0 /* [.Ldata001] */           #   80: 0800
            slli         a3, a2, 24                            #   82: 803201
            l32i.n       a0, a0, 8 /* [[.Ldata001]+0x8] */     #   85: 0820
            srai         a2, a3, 24                            #   87: 302831
            callx0       a0 /* [[.Ldata001]+0x8] */            #   8a: c00000
            l32i.n       a0, a1, 0 /* [(local0)] */            #   8d: 0801
            addi         a1, a1, 16 /* (top of frame) */       #   8f: 12c110
            ret.n                                              #   92: 0df0

.Lrel009:   .word        .bss                                  #   94: 00000000

# Function @ .irom0.text+0x98
# Local variables/stack:
#     (local0):  word[4]   @ -0x10
.literal_position
sdk_phy_delete_channel:
            addi         a1, a1, -16 /* (local0) */            #   98: 12c1f0
            s32i.n       a0, a1, 0 /* a0 -> [(local0)] */      #   9b: 0901
            movi         a0, .Lrel009 /* .Ldata001 */          #   9d: 01fdff
            l32i.n       a0, a0, 0 /* [.Ldata001] */           #   a0: 0800
            l32i.n       a0, a0, 12 /* [[.Ldata001]+0xc] */    #   a2: 0830
            callx0       a0 /* [[.Ldata001]+0xc] */            #   a4: c00000
            l32i.n       a0, a1, 0 /* [(local0)] */            #   a7: 0801
            addi         a1, a1, 16 /* (top of frame) */       #   a9: 12c110
            ret.n                                              #   ac: 0df0

            .balign      4
.Lrel010:   .word        .bss                                  #   b0: 00000000

# Function @ .irom0.text+0xb4
# Local variables/stack:
#     (local0):  word[4]   @ -0x10
.literal_position
sdk_phy_enable_agc:
            addi         a1, a1, -16 /* (local0) */            #   b4: 12c1f0
            s32i.n       a0, a1, 0 /* a0 -> [(local0)] */      #   b7: 0901
            movi         a0, .Lrel010 /* .Ldata001 */          #   b9: 01fdff
            l32i.n       a0, a0, 0 /* [.Ldata001] */           #   bc: 0800
            l32i.n       a0, a0, 16 /* [[.Ldata001]+0x10] */   #   be: 0840
            callx0       a0 /* [[.Ldata001]+0x10] */           #   c0: c00000
            l32i.n       a0, a1, 0 /* [(local0)] */            #   c3: 0801
            addi         a1, a1, 16 /* (top of frame) */       #   c5: 12c110
            ret.n                                              #   c8: 0df0

            .balign      4
.Lrel011:   .word        .bss                                  #   cc: 00000000

# Function @ .irom0.text+0xd0
# Local variables/stack:
#     (local0):  word[4]   @ -0x10
.literal_position
sdk_phy_disable_agc:
            addi         a1, a1, -16 /* (local0) */            #   d0: 12c1f0
            s32i.n       a0, a1, 0 /* a0 -> [(local0)] */      #   d3: 0901
            movi         a0, .Lrel011 /* .Ldata001 */          #   d5: 01fdff
            l32i.n       a0, a0, 0 /* [.Ldata001] */           #   d8: 0800
            l32i.n       a0, a0, 20 /* [[.Ldata001]+0x14] */   #   da: 0850
            callx0       a0 /* [[.Ldata001]+0x14] */           #   dc: c00000
            l32i.n       a0, a1, 0 /* [(local0)] */            #   df: 0801
            addi         a1, a1, 16 /* (top of frame) */       #   e1: 12c110
            ret.n                                              #   e4: 0df0

            .balign      4
.Lrel012:   .word        .bss                                  #   e8: 00000000

# Function @ .irom0.text+0xec
# Local variables/stack:
#     (local0):  word[4]   @ -0x10
.literal_position
sdk_phy_initialize_bb:
            addi         a1, a1, -16 /* (local0) */            #   ec: 12c1f0
            s32i.n       a0, a1, 0 /* a0 -> [(local0)] */      #   ef: 0901
            movi         a0, .Lrel012 /* .Ldata001 */          #   f1: 01fdff
            l32i.n       a0, a0, 0 /* [.Ldata001] */           #   f4: 0800
            l32i.n       a0, a0, 24 /* [[.Ldata001]+0x18] */   #   f6: 0860
            callx0       a0 /* [[.Ldata001]+0x18] */           #   f8: c00000
            l32i.n       a0, a1, 0 /* [(local0)] */            #   fb: 0801
            addi         a1, a1, 16 /* (top of frame) */       #   fd: 12c110
            ret.n                                              #  100: 0df0

            .balign      4
.Lrel013:   .word        .bss                                  #  104: 00000000

# Function @ .irom0.text+0x108
# Local variables/stack:
#     (local0):  word[4]   @ -0x10
.literal_position
sdk_phy_set_sense:
            addi         a1, a1, -16 /* (local0) */            #  108: 12c1f0
            s32i.n       a0, a1, 0 /* a0 -> [(local0)] */      #  10b: 0901
            movi         a0, .Lrel013 /* .Ldata001 */          #  10d: 01fdff
            l32i.n       a0, a0, 0 /* [.Ldata001] */           #  110: 0800
            l32i.n       a0, a0, 28 /* [[.Ldata001]+0x1c] */   #  112: 0870
            callx0       a0 /* [[.Ldata001]+0x1c] */           #  114: c00000
            l32i.n       a0, a1, 0 /* [(local0)] */            #  117: 0801
            addi         a1, a1, 16 /* (top of frame) */       #  119: 12c110
            ret.n                                              #  11c: 0df0
