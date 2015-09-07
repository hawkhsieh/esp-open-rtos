
            .section     .irom0.literal, "ax", @progbits

            .section     .text, "ax", @progbits

            .section     .data, "aw", @progbits

            .section     .bss, "aw", @nobits

            .section     .irom0.text, "ax", @progbits

# Function @ .irom0.text+0x0
.literal_position
sdk_eloop_cancel_timeout:
            movi.n       a2, 0 /* 0x00000000 */                #    0: 0c02
            ret.n         /* 0x00000000 */                     #    2: 0df0

# Function @ .irom0.text+0x4
.literal_position
sdk_eloop_register_timeout:
            movi.n       a2, 0 /* 0x00000000 */                #    4: 0c02
            ret.n         /* 0x00000000 */                     #    6: 0df0
