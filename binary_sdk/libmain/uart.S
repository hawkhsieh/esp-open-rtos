
            .section     .irom0.literal, "ax", @progbits

            .section     .text, "ax", @progbits

            .section     .data, "aw", @progbits

            .section     .bss, "aw", @nobits

            .section     .irom0.text, "ax", @progbits

# Function @ .irom0.text+0x0
.literal_position
sdk_uart_buff_switch:
            ret.n         /* arg0 */                           #    0: 0df0

            .balign      4
.Llit001:   .word        0x00000f00                            #    4: 000f0000
.Llit002:   .word        0x5ffffe00                            #    8: 00feff5f
.Llit003:   .word        0x00060000                            #    c: 00000600
.Llit004:   .word        0xfff9ffff                            #   10: fffff9ff

# Function @ .irom0.text+0x14
.literal_position
sdk_uart_div_modify:
            movi         a5, .Llit001 /* 0x00000f00 */         #   14: 51fcff
            movi         a6, .Llit002 /* 0x5ffffe00 */         #   17: 61fcff
            mul16s       a5, a5, a2                            #   1a: 2055d1
            add.n        a5, a5, a6                            #   1d: 6a55
            memw                                               #   1f: c02000
            s32i         a3, a5, 0x214                         #   22: 326585
            movi         a8, .Llit003 /* 0x00060000 */         #   25: 81f9ff
            memw                                               #   28: c02000
            l32i         a7, a5, 0x220                         #   2b: 722588
            or           a7, a7, a8                            #   2e: 807720
            memw                                               #   31: c02000
            s32i         a7, a5, 0x220                         #   34: 726588
            movi         a6, .Llit004 /* 0xfff9ffff */         #   37: 61f6ff
            memw                                               #   3a: c02000
            l32i         a4, a5, 0x220                         #   3d: 422588
            and          a4, a4, a6                            #   40: 604410
            memw                                               #   43: c02000
            s32i         a4, a5, 0x220                         #   46: 426588
            ret.n         /* arg0 */                           #   49: 0df0

            .balign      4
# Function @ .irom0.text+0x4c
.literal_position
sdk_Uart_Init:
            ret.n         /* arg0 */                           #   4c: 0df0
