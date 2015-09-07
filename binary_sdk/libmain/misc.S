
            .section     .irom0.literal, "ax", @progbits

            .section     .literal, "ax", @progbits

            .section     .text, "ax", @progbits

.Lrel001:   .word        .data                                 #    0: 00000000

# Function @ .text+0x4
.literal_position
sdk_os_get_cpu_frequency:
            movi         a2, .Lrel001 /* .Ldata001 */          #    4: 21ffff
            l32i.n       a2, a2, 0 /* [.Ldata001] */           #    7: 2802
            ret.n         /* [.Ldata001] */                    #    9: 0df0

            .section     .data, "aw", @progbits

.Ldata001:  .word        0x00000050                            #    0: 50000000

            .section     .bss, "aw", @nobits

sdk__putc1: .word        0x00000000                            #    0: 00000000

            .section     .irom0.text, "ax", @progbits

.Lrel002:   .word        .data                                 #    0: 00000000
.Lrel003:   .word        xthal_get_ccount                      #    4: 00000000
.Lrel004:   .word        xthal_get_ccount                      #    8: 00000000

# Function @ .irom0.text+0xc
# Local variables/stack:
#     (local0):  word      @ -0x10
#     (local1):  word      @ -0xc
#     (local2):  word[2]   @ -0x8
.literal_position
sdk_ets_delay_us:
sdk_os_delay_us:
            addi         a1, a1, -16 /* (local0) */            #    c: 12c1f0
            s32i.n       a13, a1, 8 /* a13 -> [(local2)] */    #    f: d921
            s32i.n       a12, a1, 4 /* a12 -> [(local1)] */    #   11: c911
            s32i.n       a0, a1, 0 /* a0 -> [(local0)] */      #   13: 0901
            mov.n        a12, a2 /* arg0 */                    #   15: cd02
            movi         a0, .Lrel003 /* xthal_get_ccount */   #   17: 01fbff
            callx0       a0 /* xthal_get_ccount */             #   1a: c00000
            movi         a0, .Lrel002 /* .Ldata001 */          #   1d: 01f8ff
            l32i.n       a0, a0, 0 /* [.Ldata001] */           #   20: 0800
            mov.n        a13, a2                               #   22: dd02
            mull         a12, a0, a12                          #   24: c0c082
.Lbr001:    movi         a0, .Lrel004 /* .Lrel004 */           #   27: 01f8ff
            callx0       a0                                    #   2a: c00000
            sub          a3, a2, a13                           #   2d: d032c0
            bltu         a3, a12, .Lbr001                      #   30: c733f3
            l32i.n       a12, a1, 4 /* [(local1)] */           #   33: c811
            l32i.n       a13, a1, 8 /* [(local2)] */           #   35: d821
            l32i.n       a0, a1, 0 /* [(local0)] */            #   37: 0801
            addi         a1, a1, 16 /* (top of frame) */       #   39: 12c110
            ret.n                                              #   3c: 0df0

            .balign      4
.Lrel005:   .word        .data                                 #   40: 00000000

# Function @ .irom0.text+0x44
.literal_position
sdk_ets_update_cpu_frequency:
sdk_os_update_cpu_frequency:
            movi         a3, .Lrel005 /* .Ldata001 */          #   44: 31ffff
            s32i.n       a2, a3, 0 /* arg0 -> [.Ldata001] */   #   47: 2903
            ret.n         /* arg0 */                           #   49: 0df0

            .balign      4
.Lrel006:   .word        .bss                                  #   4c: 00000000

# Function @ .irom0.text+0x50
.literal_position
sdk_os_install_putc1:
            movi         a3, .Lrel006 /* sdk__putc1 */         #   50: 31ffff
            s32i.n       a2, a3, 0 /* arg0 -> [sdk__putc1] */  #   53: 2903
            ret.n         /* arg0 */                           #   55: 0df0

            .balign      4
.Lrel007:   .word        .bss                                  #   58: 00000000

# Function @ .irom0.text+0x5c
# Local variables/stack:
#     (local0):  word[4]   @ -0x10
.literal_position
sdk_os_putc:
            addi         a1, a1, -16 /* (local0) */            #   5c: 12c1f0
            s32i.n       a0, a1, 0 /* a0 -> [(local0)] */      #   5f: 0901
            movi         a0, .Lrel007 /* sdk__putc1 */         #   61: 01fdff
            l32i.n       a0, a0, 0 /* [sdk__putc1] */          #   64: 0800
            callx0       a0 /* [sdk__putc1] */                 #   66: c00000
            l32i.n       a0, a1, 0 /* [(local0)] */            #   69: 0801
            addi         a1, a1, 16 /* (top of frame) */       #   6b: 12c110
            ret.n                                              #   6e: 0df0

.Llit001:   .word        0x60000200                            #   70: 00020060

# Function @ .irom0.text+0x74
.literal_position
sdk_gpio_output_set:
            movi         a6, .Llit001 /* 0x60000200 */         #   74: 61ffff
            memw                                               #   77: c02000
            s32i         a2, a6, 0x104 /* arg0 -> [0x60000304] */ #   7a: 226641
            memw                                               #   7d: c02000
            s32i         a3, a6, 0x108 /* arg1 -> [0x60000308] */ #   80: 326642
            memw                                               #   83: c02000
            s32i         a4, a6, 0x110 /* arg2 -> [0x60000310] */ #   86: 426644
            memw                                               #   89: c02000
            s32i         a5, a6, 0x114 /* arg3 -> [0x60000314] */ #   8c: 526645
            ret.n         /* arg0 */                           #   8f: 0df0

            .balign      4
.Llit002:   .word        0x60000600                            #   94: 00060060
.Llit003:   .word        0xffdfffff                            #   98: ffffdfff

# Function @ .irom0.text+0x9c
.literal_position
sdk_rtc_get_reset_reason:
            movi         a4, .Llit002 /* 0x60000600 */         #   9c: 41feff
            memw                                               #   9f: c02000
            l32i         a2, a4, 0x114 /* [0x60000714] */      #   a2: 222445
            extui        a2, a2, 0, 4                          #   a5: 202034
            bnei         a2, 5, .Lbr003                        #   a8: 665224
            memw                                               #   ab: c02000
            l32i         a3, a4, 0x118 /* [0x60000718] */      #   ae: 322446
            extui        a3, a3, 8, 6                          #   b1: 303854
            bnei         a3, 1, .Lbr002                        #   b4: 661304
            movi.n       a2, 6 /* 0x00000006 */                #   b7: 0c62
            j            .Lbr003                               #   b9: c60400
.Lbr002:    memw                                               #   bc: c02000
            l32i         a6, a4, 0x118 /* [0x60000718] */      #   bf: 622446
            movi.n       a5, 0 /* 0x00000000 */                #   c2: 0c05
            extui        a6, a6, 8, 6                          #   c4: 606854
            addi         a6, a6, -8                            #   c7: 62c6f8
            movnez       a2, a5, a6                            #   ca: 602593
            extui        a2, a2, 0, 8                          #   cd: 202074
.Lbr003:    movi         a8, .Llit003 /* .Llit003 */           #   d0: 81f2ff
            memw                                               #   d3: c02000
            l32i         a7, a4, 0x108 /* [0x60000708] */      #   d6: 722442
            and          a7, a7, a8                            #   d9: 807710
            memw                                               #   dc: c02000
            s32i         a7, a4, 0x108 /* a7 -> [0x60000708] */ #   df: 726442
            ret.n                                              #   e2: 0df0
