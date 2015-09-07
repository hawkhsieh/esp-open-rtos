
            .section     .irom0.literal, "ax", @progbits

            .section     .text, "ax", @progbits

            .section     .data, "aw", @progbits

            .section     .bss, "aw", @nobits

            .section     .irom0.text, "ax", @progbits

.Lrel001:   .word        ap_get_sta                            #    0: 00000000
.Lrel002:   .word        sdk_wpa_receive                       #    4: 00000000

# Function @ .irom0.text+0x8
# Local variables/stack:
#     (local0):  word      @ -0x10
#     (local1):  word      @ -0xc
#     (local2):  word      @ -0x8
#     (local3):  word      @ -0x4
.literal_position
sdk_ieee802_1x_receive:
            addi         a1, a1, -16 /* (local0) */            #    8: 12c1f0
            s32i.n       a0, a1, 0 /* a0 -> [(local0)] */      #    b: 0901
            s32i.n       a13, a1, 8 /* a13 -> [(local2)] */    #    d: d921
            s32i.n       a12, a1, 4 /* a12 -> [(local1)] */    #    f: c911
            s32i.n       a14, a1, 12 /* a14 -> [(local3)] */   #   11: e931
            mov.n        a12, a4 /* arg2 */                    #   13: cd04
            mov.n        a14, a5 /* arg3 */                    #   15: ed05
            mov.n        a13, a2 /* arg0 */                    #   17: dd02
            movi         a0, .Lrel001 /* ap_get_sta */         #   19: 01f9ff
            callx0       a0 /* ap_get_sta */                   #   1c: c00000
            mov.n        a0, a2                                #   1f: 0d02
            beqz         a2, .Lbr002                           #   21: 161205
            l32i.n       a2, a2, 16                            #   24: 2842
            movi         a3, 258 /* 0x00000102 */              #   26: 32a102
            bnone        a2, a3, .Lbr002                       #   29: 370249
            bltui        a14, 4, .Lbr002                       #   2c: b64e46
            addi         a4, a14, -4 /* arg3-0x4 */            #   2f: 42cefc
            l8ui         a6, a12, 3 /* [arg2+0x3] */           #   32: 620c03
            l8ui         a7, a12, 2 /* [arg2+0x2] */           #   35: 720c02
            slli         a6, a6, 8                             #   38: 806611
            or           a6, a6, a7                            #   3b: 706620
            extui        a5, a6, 8, 8                          #   3e: 605874
            extui        a6, a6, 0, 8                          #   41: 606074
            slli         a6, a6, 8                             #   44: 806611
            or           a5, a5, a6                            #   47: 605520
            extui        a5, a5, 0, 16                         #   4a: 5050f4
            bltu         a4, a5, .Lbr002                       #   4d: 573425
            movi.n       a7, 43 /* 0x0000002b */               #   50: 2cb7
            bgeu         a7, a5, .Lbr002                       #   52: 57b720
            l8ui         a8, a12, 1 /* [arg2+0x1] */           #   55: 820c01
            l8ui         a2, a12, 4 /* [arg2+0x4] */           #   58: 220c04
            bnei         a8, 3, .Lbr002                        #   5b: 663817
            movi         a9, 254 /* 0x000000fe */              #   5e: 92a0fe
            beq          a2, a9, .Lbr001                       #   61: 971202
            bnei         a2, 2, .Lbr002                        #   64: 66220e
.Lbr001:    mov.n        a4, a12 /* arg2 */                    #   67: 4d0c
            l32i.n       a2, a13, 24 /* [arg0+0x18] */         #   69: 286d
            addi.n       a5, a5, 4                             #   6b: 4b55
            l32i         a3, a0, 68                            #   6d: 322011
            movi         a0, .Lrel002 /* sdk_wpa_receive */    #   70: 01e5ff
            callx0       a0 /* sdk_wpa_receive */              #   73: c00000
.Lbr002:    l32i.n       a12, a1, 4 /* [(local1)] */           #   76: c811
            l32i.n       a13, a1, 8 /* [(local2)] */           #   78: d821
            l32i.n       a14, a1, 12 /* [(local3)] */          #   7a: e831
            l32i.n       a0, a1, 0 /* [(local0)] */            #   7c: 0801
            addi         a1, a1, 16 /* (top of frame) */       #   7e: 12c110
            ret.n                                              #   81: 0df0
