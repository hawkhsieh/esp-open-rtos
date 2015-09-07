
            .section     .irom0.literal, "ax", @progbits

            .section     .text, "ax", @progbits

            .section     .data, "aw", @progbits

            .section     .bss, "aw", @nobits

            .section     .irom0.text, "ax", @progbits

.Lrel001:   .word        sdk_esf_buf_alloc                     #    0: 00000000

# Function @ .irom0.text+0x4
# Local variables/stack:
#     (local0):  word      @ -0x10
#     (local1):  word      @ -0xc
#     (local2):  word[2]   @ -0x8
.literal_position
sdk_ieee80211_getmgtframe:
            movi.n       a5, -4 /* 0xfffffffc */               #    4: 7cc5
            addi         a1, a1, -16 /* (local0) */            #    6: 12c1f0
            s32i.n       a0, a1, 4 /* a0 -> [(local1)] */      #    9: 0911
            s32i.n       a12, a1, 8 /* a12 -> [(local2)] */    #    b: c921
            movi         a0, 256 /* 0x00000100 */              #    d: 02a100
            mov.n        a12, a3 /* arg1 */                    #   10: cd03
            add.n        a3, a3, a4                            #   12: 4a33
            addi.n       a3, a3, 3                             #   14: 3b33
            and          a4, a3, a5                            #   16: 504310
            bgeu         a0, a4, .Lbr001                       #   19: 47b004
            movi.n       a2, 0 /* 0x00000000 */                #   1c: 0c02
            j            .Lbr003                               #   1e: 860700
.Lbr001:    movi.n       a3, 4 /* 0x00000004 */                #   21: 0c43
            s32i.n       a2, a1, 0 /* arg0 -> [(local0)] */    #   23: 2901
            movi.n       a5, 65 /* 0x00000041 */               #   25: 4c15
            bgeu         a4, a5, .Lbr002                       #   27: 57b401
            movi.n       a3, 5 /* 0x00000005 */                #   2a: 0c53
.Lbr002:    movi.n       a2, 0 /* 0x00000000 */                #   2c: 0c02
            movi         a0, .Lrel001 /* sdk_esf_buf_alloc */  #   2e: 01f4ff
            callx0       a0 /* sdk_esf_buf_alloc */            #   31: c00000
            beqz.n       a2, .Lbr003                           #   34: 8c82
            l32i.n       a6, a2, 4                             #   36: 6812
            l32i.n       a6, a6, 4                             #   38: 6816
            l32i.n       a7, a1, 0 /* [(local0)] */            #   3a: 7801
            add.n        a6, a12, a6                           #   3c: 6a6c
            s32i.n       a6, a7, 0 /* a6 -> [[(local0)]] */    #   3e: 6907
.Lbr003:    l32i.n       a12, a1, 8 /* [(local2)] */           #   40: c821
            l32i.n       a0, a1, 4 /* [(local1)] */            #   42: 0811
            addi         a1, a1, 16 /* (top of frame) */       #   44: 12c110
            ret.n                                              #   47: 0df0
