
            .section     .literal, "ax", @progbits

            .section     .irom0.literal, "ax", @progbits

            .section     .text, "ax", @progbits

# Function @ .text+0x0
.literal_position
.Lfunc001:  l32i.n       a4, a2, 8 /* [arg0+0x8] */            #    0: 4822
            addi.n       a3, a2, 12 /* arg0+0xc */             #    2: cb32
            moveqz       a4, a3, a4                            #    4: 404383
            mov.n        a2, a4                                #    7: 2d04
            ret.n                                              #    9: 0df0

            .balign      4
.Lrel001:   .word        sdk_wpabuf_put                        #    c: 00000000
.Lrel002:   .word        memcpy                                #   10: 00000000

# Function @ .text+0x14
# Local variables/stack:
#     (local0):  word      @ -0x10
#     (local1):  word      @ -0xc
#     (local2):  word[2]   @ -0x8
.literal_position
.Lfunc002:  addi         a1, a1, -16 /* (local0) */            #   14: 12c1f0
            s32i.n       a0, a1, 0 /* a0 -> [(local0)] */      #   17: 0901
            s32i.n       a12, a1, 4 /* a12 -> [(local1)] */    #   19: c911
            s32i.n       a13, a1, 8 /* a13 -> [(local2)] */    #   1b: d921
            mov.n        a12, a3 /* arg1 */                    #   1d: cd03
            mov.n        a13, a4 /* arg2 */                    #   1f: dd04
            beqz.n       a3, .Lbr001                           #   21: 9c03
            mov.n        a3, a4 /* arg2 */                     #   23: 3d04
            movi         a0, .Lrel001 /* sdk_wpabuf_put */     #   25: 01f9ff
            callx0       a0 /* sdk_wpabuf_put */               #   28: c00000
            mov.n        a4, a13 /* arg2 */                    #   2b: 4d0d
            mov.n        a3, a12 /* arg1 */                    #   2d: 3d0c
            movi         a0, .Lrel002 /* memcpy */             #   2f: 01f8ff
            callx0       a0 /* memcpy */                       #   32: c00000
.Lbr001:    l32i.n       a12, a1, 4 /* [(local1)] */           #   35: c811
            l32i.n       a13, a1, 8 /* [(local2)] */           #   37: d821
            l32i.n       a0, a1, 0 /* [(local0)] */            #   39: 0801
            addi         a1, a1, 16 /* (top of frame) */       #   3b: 12c110
            ret.n                                              #   3e: 0df0

# Function @ .text+0x40
# Local variables/stack:
#     (local0):  word[4]   @ -0x10
.literal_position
.Lfunc003:  mov.n        a6, a3 /* arg1 */                     #   40: 6d03
            addi         a1, a1, -16 /* (local0) */            #   42: 12c1f0
            s32i.n       a0, a1, 0 /* a0 -> [(local0)] */      #   45: 0901
            l32i.n       a4, a6, 4 /* [arg1+0x4] */            #   47: 4816
            l32i.n       a3, a3, 8 /* [arg1+0x8] */            #   49: 3823
            addi.n       a0, a6, 12 /* arg1+0xc */             #   4b: cb06
            moveqz       a3, a0, a3                            #   4d: 303083
            call0        .Lfunc002                             #   50: 05fcff
            l32i.n       a0, a1, 0 /* [(local0)] */            #   53: 0801
            addi         a1, a1, 16 /* (top of frame) */       #   55: 12c110
            ret.n                                              #   58: 0df0

            .section     .data, "aw", @progbits

            .section     .bss, "aw", @nobits

            .section     .irom0.text, "ax", @progbits

.Lrel003:   .word        .rodata.str1.4                        #    0: 00000000
.Lrel004:   .word        ets_printf                            #    4: 00000000

# Function @ .irom0.text+0x8
# Local variables/stack:
#     (local0):  word[4]   @ -0x10
.literal_position
.Lfunc004:  movi         a2, .Lrel003 /* .Lstr001 */           #    8: 21feff
            addi         a1, a1, -16 /* (local0) */            #    b: 12c1f0
            s32i.n       a0, a1, 0 /* a0 -> [(local0)] */      #    e: 0901
            movi         a0, .Lrel004 /* ets_printf */         #   10: 01fdff
            callx0       a0 /* ets_printf */                   #   13: c00000
            l32i.n       a0, a1, 0 /* [(local0)] */            #   16: 0801
            addi         a1, a1, 16 /* (top of frame) */       #   18: 12c110
            ret.n                                              #   1b: 0df0

            .balign      4
.Lrel005:   .word        realloc                               #   20: 00000000
.Lrel006:   .word        memset                                #   24: 00000000
.Lrel007:   .word        memset                                #   28: 00000000
.Lrel008:   .word        realloc                               #   2c: 00000000

# Function @ .irom0.text+0x30
# Local variables/stack:
#     (local0):  word      @ -0x10
#     (local1):  word      @ -0xc
#     (local2):  word      @ -0x8
#     (local3):  word      @ -0x4
.literal_position
sdk_wpabuf_resize:
            addi         a1, a1, -16 /* (local0) */            #   30: 12c1f0
            s32i.n       a0, a1, 0 /* a0 -> [(local0)] */      #   33: 0901
            s32i.n       a13, a1, 8 /* a13 -> [(local2)] */    #   35: d921
            s32i.n       a14, a1, 12 /* a14 -> [(local3)] */   #   37: e931
            s32i.n       a12, a1, 4 /* a12 -> [(local1)] */    #   39: c911
            mov.n        a14, a2 /* arg0 */                    #   3b: ed02
            l32i.n       a12, a2, 0 /* [arg0] */               #   3d: c802
            mov.n        a13, a3 /* arg1 */                    #   3f: dd03
            bnez.n       a12, .Lbr002                          #   41: dc1c
            mov.n        a2, a3 /* arg1 */                     #   43: 2d03
            call0        sdk_wpabuf_alloc                      #   45: 050000
            mov.n        a3, a2                                #   48: 3d02
            s32i.n       a2, a14, 0 /* a2 -> [arg0] */         #   4a: 290e
            movi.n       a0, -1 /* 0xffffffff */               #   4c: 7cf0
            movi.n       a2, 0 /* 0x00000000 */                #   4e: 0c02
            moveqz       a2, a0, a3                            #   50: 302083
            j            .Lbr006                               #   53: 461100
.Lbr002:    l32i.n       a3, a12, 4 /* [[arg0]+0x4] */         #   56: 381c
            l32i.n       a4, a12, 0 /* [[arg0]] */             #   58: 480c
            add.n        a3, a3, a13                           #   5a: da33
            bgeu         a4, a3, .Lbr005                       #   5c: 37b43a
            l32i.n       a2, a12, 8 /* [[arg0]+0x8] */         #   5f: 282c
            beqz         a2, .Lbr007                           #   61: 164204
            movi         a0, .Lrel005 /* realloc */            #   64: 01efff
            callx0       a0 /* realloc */                      #   67: c00000
            mov.n        a14, a2                               #   6a: ed02
            beqz         a2, .Lbr008                           #   6c: 168204
            movi.n       a3, 0 /* 0x00000000 */                #   6f: 0c03
            l32i.n       a2, a12, 4 /* [[arg0]+0x4] */         #   71: 281c
            mov.n        a4, a13 /* arg1 */                    #   73: 4d0d
            add.n        a2, a2, a14                           #   75: ea22
            movi         a0, .Lrel006 /* memset */             #   77: 01ebff
            callx0       a0 /* memset */                       #   7a: c00000
            s32i.n       a14, a12, 8 /* a14 -> [[arg0]+0x8] */ #   7d: e92c
            j            .Lbr004                               #   7f: 460400
.Lbr003:    movi.n       a3, 0 /* 0x00000000 */                #   82: 0c03
            l32i.n       a2, a2, 4                             #   84: 2812
            mov.n        a4, a13 /* arg1 */                    #   86: 4d0d
            add.n        a2, a2, a12                           #   88: ca22
            addi.n       a2, a2, 12                            #   8a: cb22
            movi         a0, .Lrel007 /* memset */             #   8c: 01e7ff
            callx0       a0 /* memset */                       #   8f: c00000
            s32i.n       a12, a14, 0 /* a12 -> [arg0] */       #   92: c90e
.Lbr004:    l32i.n       a3, a12, 4                            #   94: 381c
            add.n        a3, a3, a13                           #   96: da33
            s32i.n       a3, a12, 0                            #   98: 390c
.Lbr005:    movi.n       a2, 0 /* 0x00000000 */                #   9a: 0c02
.Lbr006:    l32i.n       a12, a1, 4 /* [(local1)] */           #   9c: c811
            l32i.n       a13, a1, 8 /* [(local2)] */           #   9e: d821
            l32i.n       a14, a1, 12 /* [(local3)] */          #   a0: e831
            l32i.n       a0, a1, 0 /* [(local0)] */            #   a2: 0801
            addi         a1, a1, 16 /* (top of frame) */       #   a4: 12c110
            ret.n                                              #   a7: 0df0
.Lbr007:    mov.n        a2, a12 /* [arg0] */                  #   a9: 2d0c
            addi.n       a3, a3, 12                            #   ab: cb33
            movi         a0, .Lrel008 /* realloc */            #   ad: 01dfff
            callx0       a0 /* realloc */                      #   b0: c00000
            mov.n        a12, a2                               #   b3: cd02
            bnez         a2, .Lbr003                           #   b5: 5692fc
.Lbr008:    movi.n       a2, -1 /* 0xffffffff */               #   b8: 7cf2
            j            .Lbr006                               #   ba: 86f7ff

            .balign      4
.Lrel009:   .word        zalloc                                #   c0: 00000000

# Function @ .irom0.text+0xc4
# Local variables/stack:
#     (local0):  word      @ -0x10
#     (local1):  word[3]   @ -0xc
.literal_position
sdk_wpabuf_alloc:
            addi         a1, a1, -16 /* (local0) */            #   c4: 12c1f0
            s32i.n       a12, a1, 4 /* a12 -> [(local1)] */    #   c7: c911
            s32i.n       a0, a1, 0 /* a0 -> [(local0)] */      #   c9: 0901
            mov.n        a12, a2 /* arg0 */                    #   cb: cd02
            addi.n       a2, a2, 12 /* arg0+0xc */             #   cd: cb22
            movi         a0, .Lrel009 /* zalloc */             #   cf: 01fcff
            callx0       a0 /* zalloc */                       #   d2: c00000
            l32i.n       a0, a1, 0 /* [(local0)] */            #   d5: 0801
            bnez.n       a2, .Lbr009                           #   d7: cc32
            movi.n       a2, 0 /* 0x00000000 */                #   d9: 0c02
            j            .Lbr010                               #   db: 460000
.Lbr009:    s32i.n       a12, a2, 0                            #   de: c902
.Lbr010:    l32i.n       a12, a1, 4 /* [(local1)] */           #   e0: c811
            addi         a1, a1, 16 /* (top of frame) */       #   e2: 12c110
            ret.n                                              #   e5: 0df0

            .balign      4
.Lrel010:   .word        zalloc                                #   e8: 00000000

# Function @ .irom0.text+0xec
# Local variables/stack:
#     (local0):  word      @ -0x10
#     (local1):  word      @ -0xc
#     (local2):  word[2]   @ -0x8
.literal_position
sdk_wpabuf_alloc_ext_data:
            addi         a1, a1, -16 /* (local0) */            #   ec: 12c1f0
            s32i.n       a3, a1, 4 /* arg1 -> [(local1)] */    #   ef: 3911
            s32i.n       a2, a1, 0 /* arg0 -> [(local0)] */    #   f1: 2901
            s32i.n       a0, a1, 8 /* a0 -> [(local2)] */      #   f3: 0921
            movi.n       a2, 12 /* 0x0000000c */               #   f5: 0cc2
            movi         a0, .Lrel010 /* zalloc */             #   f7: 01fcff
            callx0       a0 /* zalloc */                       #   fa: c00000
            bnez.n       a2, .Lbr011                           #   fd: cc32
            movi.n       a2, 0 /* 0x00000000 */                #   ff: 0c02
            j            .Lbr012                               #  101: 460200
.Lbr011:    l32i.n       a0, a1, 0 /* [(local0)] */            #  104: 0801
            l32i.n       a3, a1, 4 /* [(local1)] */            #  106: 3811
            s32i.n       a3, a2, 0                             #  108: 3902
            s32i.n       a3, a2, 4                             #  10a: 3912
            s32i.n       a0, a2, 8                             #  10c: 0922
.Lbr012:    l32i.n       a0, a1, 8 /* [(local2)] */            #  10e: 0821
            addi         a1, a1, 16 /* (top of frame) */       #  110: 12c110
            ret.n                                              #  113: 0df0

            .balign      4
.Lrel011:   .word        .Lfunc002                             #  118: 14000000

# Function @ .irom0.text+0x11c
# Local variables/stack:
#     (local0):  word      @ -0x10
#     (local1):  word      @ -0xc
#     (local2):  word      @ -0x8
#     (local3):  word      @ -0x4
.literal_position
sdk_wpabuf_alloc_copy:
            mov.n        a9, a2 /* arg0 */                     #  11c: 9d02
            addi         a1, a1, -16 /* (local0) */            #  11e: 12c1f0
            s32i.n       a12, a1, 8 /* a12 -> [(local2)] */    #  121: c921
            mov.n        a2, a3 /* arg1 */                     #  123: 2d03
            s32i.n       a13, a1, 12 /* a13 -> [(local3)] */   #  125: d931
            s32i.n       a0, a1, 4 /* a0 -> [(local1)] */      #  127: 0911
            mov.n        a13, a3 /* arg1 */                    #  129: dd03
            s32i.n       a9, a1, 0 /* arg0 -> [(local0)] */    #  12b: 9901
            call0        sdk_wpabuf_alloc                      #  12d: 050000
            mov.n        a12, a2                               #  130: cd02
            beqz.n       a2, .Lbr013                           #  132: 8c82
            mov.n        a4, a13 /* arg1 */                    #  134: 4d0d
            l32i.n       a3, a1, 0 /* [(local0)] */            #  136: 3801
            movi         a0, .Lrel011 /* .Lfunc002 */          #  138: 01f8ff
            callx0       a0 /* .Lfunc002 */                    #  13b: c00000
.Lbr013:    l32i.n       a0, a1, 4 /* [(local1)] */            #  13e: 0811
            mov.n        a2, a12                               #  140: 2d0c
            l32i.n       a13, a1, 12 /* [(local3)] */          #  142: d831
            l32i.n       a12, a1, 8 /* [(local2)] */           #  144: c821
            addi         a1, a1, 16 /* (top of frame) */       #  146: 12c110
            ret.n                                              #  149: 0df0

            .balign      4
.Lrel012:   .word        .Lfunc002                             #  14c: 14000000

# Function @ .irom0.text+0x150
# Local variables/stack:
#     (local0):  word      @ -0x10
#     (local1):  word      @ -0xc
#     (local2):  word[2]   @ -0x8
.literal_position
sdk_wpabuf_dup:
            addi         a1, a1, -16 /* (local0) */            #  150: 12c1f0
            s32i.n       a12, a1, 4 /* a12 -> [(local1)] */    #  153: c911
            s32i.n       a13, a1, 8 /* a13 -> [(local2)] */    #  155: d921
            s32i.n       a0, a1, 0 /* a0 -> [(local0)] */      #  157: 0901
            mov.n        a13, a2 /* arg0 */                    #  159: dd02
            l32i.n       a2, a2, 4 /* [arg0+0x4] */            #  15b: 2812
            call0        sdk_wpabuf_alloc                      #  15d: 050000
            mov.n        a12, a2                               #  160: cd02
            beqz.n       a2, .Lbr014                           #  162: 8cd2
            l32i.n       a4, a13, 4 /* [arg0+0x4] */           #  164: 481d
            l32i.n       a3, a13, 8 /* [arg0+0x8] */           #  166: 382d
            addi.n       a0, a13, 12 /* arg0+0xc */            #  168: cb0d
            moveqz       a3, a0, a3                            #  16a: 303083
            movi         a0, .Lrel012 /* .Lfunc002 */          #  16d: 01f7ff
            callx0       a0 /* .Lfunc002 */                    #  170: c00000
.Lbr014:    l32i.n       a0, a1, 0 /* [(local0)] */            #  173: 0801
            mov.n        a2, a12                               #  175: 2d0c
            l32i.n       a13, a1, 8 /* [(local2)] */           #  177: d821
            l32i.n       a12, a1, 4 /* [(local1)] */           #  179: c811
            addi         a1, a1, 16 /* (top of frame) */       #  17b: 12c110
            ret.n                                              #  17e: 0df0

.Lrel013:   .word        free                                  #  180: 00000000
.Lrel014:   .word        free                                  #  184: 00000000

# Function @ .irom0.text+0x188
# Local variables/stack:
#     (local0):  word      @ -0x10
#     (local1):  word[3]   @ -0xc
.literal_position
sdk_wpabuf_free:
            addi         a1, a1, -16 /* (local0) */            #  188: 12c1f0
            s32i.n       a12, a1, 4 /* a12 -> [(local1)] */    #  18b: c911
            s32i.n       a0, a1, 0 /* a0 -> [(local0)] */      #  18d: 0901
            mov.n        a12, a2 /* arg0 */                    #  18f: cd02
            beqz.n       a2, .Lbr015                           #  191: 8ce2
            l32i.n       a2, a2, 8 /* [arg0+0x8] */            #  193: 2822
            movi         a0, .Lrel013 /* free */               #  195: 01faff
            callx0       a0 /* free */                         #  198: c00000
            mov.n        a2, a12 /* arg0 */                    #  19b: 2d0c
            movi         a0, .Lrel014 /* free */               #  19d: 01f9ff
            callx0       a0 /* free */                         #  1a0: c00000
.Lbr015:    l32i.n       a12, a1, 4 /* [(local1)] */           #  1a3: c811
            l32i.n       a0, a1, 0 /* [(local0)] */            #  1a5: 0801
            addi         a1, a1, 16 /* (top of frame) */       #  1a7: 12c110
            ret.n                                              #  1aa: 0df0

.Lrel015:   .word        .text                                 #  1ac: 00000000

# Function @ .irom0.text+0x1b0
# Local variables/stack:
#     (local0):  word      @ -0x20
#     (local1):  word      @ -0x1c
#     (local2):  word      @ -0x18
#     (local3):  word      @ -0x14
#     (local4):  word[4]   @ -0x10
.literal_position
sdk_wpabuf_put:
            addi         a1, a1, -32 /* (local0) */            #  1b0: 12c1e0
            s32i.n       a0, a1, 0 /* a0 -> [(local0)] */      #  1b3: 0901
            s32i.n       a13, a1, 8 /* a13 -> [(local2)] */    #  1b5: d921
            s32i.n       a12, a1, 4 /* a12 -> [(local1)] */    #  1b7: c911
            mov.n        a13, a3 /* arg1 */                    #  1b9: dd03
            mov.n        a12, a2 /* arg0 */                    #  1bb: cd02
            movi         a0, .Lrel015 /* .Lfunc001 */          #  1bd: 01fbff
            callx0       a0 /* .Lfunc001 */                    #  1c0: c00000
            s32i.n       a2, a1, 12 /* a2 -> [(local3)] */     #  1c3: 2931
            l32i.n       a3, a12, 0 /* [arg0] */               #  1c5: 380c
            l32i.n       a0, a12, 4 /* [arg0+0x4] */           #  1c7: 081c
            s32i.n       a0, a1, 16 /* [arg0+0x4] -> [(local4)] */ #  1c9: 0941
            add.n        a4, a0, a13                           #  1cb: da40
            s32i.n       a4, a12, 4 /* a4 -> [arg0+0x4] */     #  1cd: 491c
            bgeu         a3, a4, .Lbr016                       #  1cf: 47b30a
            mov.n        a3, a13 /* arg1 */                    #  1d2: 3d0d
            mov.n        a2, a12 /* arg0 */                    #  1d4: 2d0c
            call0        .Lfunc004                             #  1d6: 05e3ff
            l32i.n       a0, a1, 16 /* [(local4)] */           #  1d9: 0841
            l32i.n       a2, a1, 12 /* [(local3)] */           #  1db: 2831
.Lbr016:    l32i.n       a12, a1, 4 /* [(local1)] */           #  1dd: c811
            l32i.n       a13, a1, 8 /* [(local2)] */           #  1df: d821
            add.n        a2, a2, a0                            #  1e1: 0a22
            l32i.n       a0, a1, 0 /* [(local0)] */            #  1e3: 0801
            addi         a1, a1, 32 /* (top of frame) */       #  1e5: 12c120
            ret.n                                              #  1e8: 0df0

            .balign      4
.Lrel016:   .word        .Lfunc003                             #  1ec: 40000000
.Lrel017:   .word        .Lfunc003                             #  1f0: 40000000

# Function @ .irom0.text+0x1f4
# Local variables/stack:
#     (local0):  word      @ -0x10
#     (local1):  word      @ -0xc
#     (local2):  word      @ -0x8
#     (local3):  word      @ -0x4
.literal_position
sdk_wpabuf_concat:
            addi         a1, a1, -16 /* (local0) */            #  1f4: 12c1f0
            s32i.n       a0, a1, 0 /* a0 -> [(local0)] */      #  1f7: 0901
            s32i.n       a14, a1, 12 /* a14 -> [(local3)] */   #  1f9: e931
            s32i.n       a12, a1, 4 /* a12 -> [(local1)] */    #  1fb: c911
            s32i.n       a13, a1, 8 /* a13 -> [(local2)] */    #  1fd: d921
            mov.n        a12, a2 /* arg0 */                    #  1ff: cd02
            mov.n        a13, a3 /* arg1 */                    #  201: dd03
            bnez.n       a3, .Lbr017                           #  203: cc33
            mov.n        a14, a2 /* arg0 */                    #  205: ed02
            j            .Lbr022                               #  207: 460c00
.Lbr017:    bnez.n       a2, .Lbr018                           #  20a: cc32
            movi.n       a0, 0 /* 0x00000000 */                #  20c: 0c00
            j            .Lbr019                               #  20e: 460000
.Lbr018:    l32i.n       a0, a2, 4 /* [arg0+0x4] */            #  211: 0812
.Lbr019:    l32i.n       a2, a13, 4 /* [arg1+0x4] */           #  213: 281d
            add.n        a2, a2, a0                            #  215: 0a22
            call0        sdk_wpabuf_alloc                      #  217: 050000
            mov.n        a14, a2                               #  21a: ed02
            beqz.n       a2, .Lbr021                           #  21c: 9c22
            beqz.n       a12, .Lbr020                          #  21e: 8c6c
            mov.n        a3, a12 /* arg0 */                    #  220: 3d0c
            movi         a0, .Lrel016 /* .Lfunc003 */          #  222: 01f2ff
            callx0       a0 /* .Lfunc003 */                    #  225: c00000
.Lbr020:    mov.n        a2, a14                               #  228: 2d0e
            mov.n        a3, a13 /* arg1 */                    #  22a: 3d0d
            movi         a0, .Lrel017 /* .Lfunc003 */          #  22c: 01f1ff
            callx0       a0 /* .Lfunc003 */                    #  22f: c00000
.Lbr021:    mov.n        a2, a12 /* arg0 */                    #  232: 2d0c
            call0        sdk_wpabuf_free                       #  234: 050000
            mov.n        a2, a13 /* arg1 */                    #  237: 2d0d
            call0        sdk_wpabuf_free                       #  239: 050000
.Lbr022:    l32i.n       a0, a1, 0 /* [(local0)] */            #  23c: 0801
            l32i.n       a12, a1, 4 /* [(local1)] */           #  23e: c811
            mov.n        a2, a14                               #  240: 2d0e
            l32i.n       a13, a1, 8 /* [(local2)] */           #  242: d821
            l32i.n       a14, a1, 12 /* [(local3)] */          #  244: e831
            addi         a1, a1, 16 /* (top of frame) */       #  246: 12c110
            ret.n                                              #  249: 0df0

            .balign      4
.Lrel018:   .word        memset                                #  24c: 00000000
.Lrel019:   .word        .Lfunc003                             #  250: 40000000

# Function @ .irom0.text+0x254
# Local variables/stack:
#     (local0):  word      @ -0x20
#     (local1):  word      @ -0x1c
#     (local2):  word      @ -0x18
#     (local3):  word      @ -0x14
#     (local4):  word[4]   @ -0x10
.literal_position
sdk_wpabuf_zeropad:
            addi         a1, a1, -32 /* (local0) */            #  254: 12c1e0
            s32i.n       a0, a1, 8 /* a0 -> [(local2)] */      #  257: 0921
            s32i.n       a12, a1, 12 /* a12 -> [(local3)] */   #  259: c931
            s32i.n       a13, a1, 16 /* a13 -> [(local4)] */   #  25b: d941
            mov.n        a12, a2 /* arg0 */                    #  25d: cd02
            mov.n        a13, a3 /* arg1 */                    #  25f: dd03
            bnez.n       a2, .Lbr023                           #  261: cc32
            movi.n       a12, 0 /* 0x00000000 */               #  263: 0c0c
            j            .Lbr025                               #  265: 060e00
.Lbr023:    l32i.n       a0, a2, 4 /* [arg0+0x4] */            #  268: 0812
            s32i.n       a0, a1, 0 /* [arg0+0x4] -> [(local0)] */ #  26a: 0901
            bgeu         a0, a3, .Lbr025                       #  26c: 37b031
            mov.n        a2, a3 /* arg1 */                     #  26f: 2d03
            call0        sdk_wpabuf_alloc                      #  271: 050000
            s32i.n       a2, a1, 4 /* a2 -> [(local1)] */      #  274: 2911
            beqz.n       a2, .Lbr024                           #  276: 9ce2
            l32i.n       a2, a1, 0 /* [(local0)] */            #  278: 2801
            sub          a13, a13, a2                          #  27a: 20ddc0
            l32i.n       a2, a1, 4 /* [(local1)] */            #  27d: 2811
            mov.n        a3, a13                               #  27f: 3d0d
            call0        sdk_wpabuf_put                        #  281: 050000
            mov.n        a4, a13                               #  284: 4d0d
            movi.n       a3, 0 /* 0x00000000 */                #  286: 0c03
            movi         a0, .Lrel018 /* memset */             #  288: 01f1ff
            callx0       a0 /* memset */                       #  28b: c00000
            l32i.n       a2, a1, 4 /* [(local1)] */            #  28e: 2811
            mov.n        a3, a12 /* arg0 */                    #  290: 3d0c
            movi         a0, .Lrel019 /* .Lfunc003 */          #  292: 01efff
            callx0       a0 /* .Lfunc003 */                    #  295: c00000
.Lbr024:    mov.n        a2, a12 /* arg0 */                    #  298: 2d0c
            l32i.n       a13, a1, 4 /* [(local1)] */           #  29a: d811
            call0        sdk_wpabuf_free                       #  29c: 050000
            mov.n        a12, a13 /* [(local1)] */             #  29f: cd0d
.Lbr025:    l32i.n       a0, a1, 8 /* [(local2)] */            #  2a1: 0821
            mov.n        a2, a12                               #  2a3: 2d0c
            l32i.n       a13, a1, 16 /* [(local4)] */          #  2a5: d841
            l32i.n       a12, a1, 12 /* [(local3)] */          #  2a7: c831
            addi         a1, a1, 32 /* (top of frame) */       #  2a9: 12c120
            ret.n                                              #  2ac: 0df0

            .balign      4
.Lrel020:   .word        .text                                 #  2b0: 00000000
.Lrel021:   .word        ets_vsnprintf                         #  2b4: 00000000

# Function @ .irom0.text+0x2b8
# Local variables/stack:
#     (local0):  word      @ -0x40
#     (local1):  word      @ -0x3c
#     (local2):  word      @ -0x38
#     (local3):  word      @ -0x34
#     (local4):  word      @ -0x30
#     (local5):  word[5]   @ -0x2c
#     (local6):  word      @ -0x18
#     (local7):  word      @ -0x14
#     (local8):  word      @ -0x10
#     (local9):  word[3]   @ -0xc
.literal_position
wpabuf_printf:
            addi         a1, a1, -64 /* (local0) */            #  2b8: 12c1c0
            s32i.n       a4, a1, 40 /* arg2 -> [(local6)] */   #  2bb: 49a1
            s32i.n       a5, a1, 44 /* arg3 -> [(local7)] */   #  2bd: 59b1
            s32i.n       a6, a1, 48 /* arg4 -> [(local8)] */   #  2bf: 69c1
            s32i.n       a7, a1, 52 /* arg5 -> [(local9)] */   #  2c1: 79d1
            s32i.n       a0, a1, 12 /* a0 -> [(local3)] */     #  2c3: 0931
            s32i.n       a12, a1, 16 /* a12 -> [(local4)] */   #  2c5: c941
            s32i.n       a13, a1, 20 /* a13 -> [(local5)] */   #  2c7: d951
            mov.n        a12, a2 /* arg0 */                    #  2c9: cd02
            mov.n        a13, a3 /* arg1 */                    #  2cb: dd03
            movi         a0, .Lrel020 /* .Lfunc001 */          #  2cd: 01f8ff
            callx0       a0 /* .Lfunc001 */                    #  2d0: c00000
            mov.n        a4, a13 /* arg1 */                    #  2d3: 4d0d
            l32i.n       a3, a12, 0 /* [arg0] */               #  2d5: 380c
            l32i.n       a5, a12, 4 /* [arg0+0x4] */           #  2d7: 581c
            movi.n       a6, 8 /* 0x00000008 */                #  2d9: 0c86
            addi         a9, a1, 32 /* (FP)-0x20 */            #  2db: 92c120
            s32i.n       a9, a1, 4 /* (FP)-0x20 -> [(local1)] */ #  2de: 9911
            s32i.n       a9, a1, 0 /* (FP)-0x20 -> [(local0)] */ #  2e0: 9901
            s32i.n       a6, a1, 8 /* 0x00000008 -> [(local2)] */ #  2e2: 6921
            add.n        a2, a2, a5                            #  2e4: 5a22
            sub          a3, a3, a5                            #  2e6: 5033c0
            mov.n        a6, a9 /* (FP)-0x20 */                #  2e9: 6d09
            mov.n        a5, a9 /* (FP)-0x20 */                #  2eb: 5d09
            l32i.n       a7, a1, 8 /* [(local2)] */            #  2ed: 7821
            movi         a0, .Lrel021 /* ets_vsnprintf */      #  2ef: 01f1ff
            callx0       a0 /* ets_vsnprintf */                #  2f2: c00000
            mov.n        a13, a2                               #  2f5: dd02
            bltz         a2, .Lbr026                           #  2f7: 969200
            l32i.n       a0, a12, 4 /* [arg0+0x4] */           #  2fa: 081c
            l32i.n       a7, a12, 0 /* [arg0] */               #  2fc: 780c
            sub          a7, a7, a0                            #  2fe: 0077c0
            bltu         a2, a7, .Lbr027                       #  301: 773208
.Lbr026:    mov.n        a2, a12 /* arg0 */                    #  304: 2d0c
            mov.n        a3, a13                               #  306: 3d0d
            call0        .Lfunc004                             #  308: c5cfff
            l32i.n       a0, a12, 4 /* [arg0+0x4] */           #  30b: 081c
.Lbr027:    add.n        a8, a13, a0                           #  30d: 0a8d
            s32i.n       a8, a12, 4 /* a8 -> [arg0+0x4] */     #  30f: 891c
            l32i.n       a13, a1, 20 /* [(local5)] */          #  311: d851
            l32i.n       a12, a1, 16 /* [(local4)] */          #  313: c841
            l32i.n       a0, a1, 12 /* [(local3)] */           #  315: 0831
            addi         a1, a1, 64 /* (top of frame) */       #  317: 12c140
            ret.n                                              #  31a: 0df0

            .section     .rodata.str1.4, "MSa", @progbits, 1

.Lstr001:   .asciz       "wpabuf overflow"                     #    0: 77706162
                                                               #    4: 7566206f
                                                               #    8: 76657266
                                                               #    c: 6c6f7700
