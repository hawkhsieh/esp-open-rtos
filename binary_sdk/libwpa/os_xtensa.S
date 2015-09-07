
            .section     .irom0.literal, "ax", @progbits

            .section     .text, "ax", @progbits

            .section     .data, "aw", @progbits

            .section     .bss, "aw", @nobits

            .section     .irom0.text, "ax", @progbits

# Function @ .irom0.text+0x0
.literal_position
sdk_os_get_time:
            movi.n       a2, 0 /* 0x00000000 */                #    0: 0c02
            ret.n         /* 0x00000000 */                     #    2: 0df0

.Lrel001:   .word        rand                                  #    4: 00000000

# Function @ .irom0.text+0x8
# Local variables/stack:
#     (local0):  word[4]   @ -0x10
.literal_position
os_random:  addi         a1, a1, -16 /* (local0) */            #    8: 12c1f0
            s32i.n       a0, a1, 0 /* a0 -> [(local0)] */      #    b: 0901
            movi         a0, .Lrel001 /* rand */               #    d: 01fdff
            callx0       a0 /* rand */                         #   10: c00000
            l32i.n       a0, a1, 0 /* [(local0)] */            #   13: 0801
            addi         a1, a1, 16 /* (top of frame) */       #   15: 12c110
            ret.n                                              #   18: 0df0

            .balign      4
.Lrel002:   .word        rand                                  #   1c: 00000000
.Lrel003:   .word        memcpy                                #   20: 00000000

# Function @ .irom0.text+0x24
# Local variables/stack:
#     (local0):  word      @ -0x20
#     (local1):  word      @ -0x1c
#     (local2):  word      @ -0x18
#     (local3):  word      @ -0x14
#     (local4):  word[4]   @ -0x10
.literal_position
os_get_random:
            addi         a1, a1, -32 /* (local0) */            #   24: 12c1e0
            s32i.n       a0, a1, 4 /* a0 -> [(local1)] */      #   27: 0911
            s32i.n       a13, a1, 12 /* a13 -> [(local3)] */   #   29: d931
            s32i.n       a12, a1, 8 /* a12 -> [(local2)] */    #   2b: c921
            s32i.n       a14, a1, 16 /* a14 -> [(local4)] */   #   2d: e941
            mov.n        a12, a2 /* arg0 */                    #   2f: cd02
            srli         a14, a3, 2                            #   31: 30e241
            blti         a14, 1, .Lbr002                       #   34: a61e1c
            movi.n       a13, 0 /* 0x00000000 */               #   37: 0c0d
.Lbr001:    movi         a0, .Lrel002 /* .Lrel002 */           #   39: 01f8ff
            callx0       a0                                    #   3c: c00000
            mov.n        a3, a1 /* (local0) */                 #   3f: 3d01
            s32i.n       a2, a1, 0 /* a2 -> [(local0)] */      #   41: 2901
            movi.n       a4, 4 /* 0x00000004 */                #   43: 0c44
            mov.n        a2, a12                               #   45: 2d0c
            movi         a0, .Lrel003 /* .Lrel003 */           #   47: 01f6ff
            callx0       a0                                    #   4a: c00000
            addi.n       a12, a12, 4                           #   4d: 4bcc
            addi.n       a13, a13, 1                           #   4f: 1bdd
            bne          a13, a14, .Lbr001                     #   51: e79de4
.Lbr002:    movi.n       a2, 0 /* 0x00000000 */                #   54: 0c02
            l32i.n       a12, a1, 8 /* [(local2)] */           #   56: c821
            l32i.n       a13, a1, 12 /* [(local3)] */          #   58: d831
            l32i.n       a14, a1, 16 /* [(local4)] */          #   5a: e841
            l32i.n       a0, a1, 4 /* [(local1)] */            #   5c: 0811
            addi         a1, a1, 32 /* (top of frame) */       #   5e: 12c120
            ret.n         /* 0x00000000 */                     #   61: 0df0
