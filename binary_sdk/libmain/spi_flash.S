
            .section     .literal, "ax", @progbits

            .section     .text, "ax", @progbits

# NOTE: The following is apparently unreferenced code/data
.Llit001:   .word        0xfe6f9fff                            #    0: ff9f6ffe
.Llit002:   .word        0x60000200                            #    4: 00020060
.Llit003:   .word        0x00002000                            #    8: 00200000

.Lrel001:   .word        .data                                 #    c: 00000000

# NOTE: The following is apparently unreferenced code/data
.Llit004:   .word        0x60000200                            #   10: 00020060
.Llit005:   .word        0x01002000                            #   14: 00200001
.Llit006:   .word        0x00102000                            #   18: 00201000
.Llit007:   .word        0x00802000                            #   1c: 00208000
.Llit008:   .word        0x00006000                            #   20: 00600000

.Lrel002:   .word        Disable_QMode                         #   24: 00000000
.Lrel003:   .word        Enable_QMode                          #   28: 00000000

# Function @ .text+0x2c
# Local variables/stack:
#     (local0):  word      @ -0x10
#     (local1):  word[3]   @ -0xc
.literal_position
sdk_SPIReadModeCnfig:
            addi         a1, a1, -16 /* (local0) */            #   2c: 12c1f0
            s32i.n       a0, a1, 0 /* a0 -> [(local0)] */      #   2f: 0901
            s32i.n       a12, a1, 4 /* a12 -> [(local1)] */    #   31: c911
            movi         a4, .Llit001 /* 0xfe6f9fff */         #   33: 41f3ff
            movi         a3, .Llit002 /* 0x60000200 */         #   36: 31f3ff
            memw                                               #   39: c02000
            l32i.n       a0, a3, 8 /* [0x60000208] */          #   3c: 0823
            and          a0, a0, a4                            #   3e: 400010
            memw                                               #   41: c02000
            s32i.n       a0, a3, 8 /* a0 -> [0x60000208] */    #   44: 0923
            movi         a0, .Lrel001 /* sdk_flashchip */      #   46: 01f1ff
            beqz         a2, .Lbr004                           #   49: 166204
            beqi         a2, 1, .Lbr005                        #   4c: 261249
            beqi         a2, 2, .Lbr006                        #   4f: 26224c
            beqi         a2, 3, .Lbr007                        #   52: 26324f
            addi         a6, a2, -4 /* arg0-0x4 */             #   55: 62c2fc
            movi         a5, .Llit003 /* 0x00002000 */         #   58: 51ecff
            movi.n       a12, 0 /* 0x00000000 */               #   5b: 0c0c
            moveqz       a12, a5, a6                           #   5d: 60c583
.Lbr001:    beqz.n       a2, .Lbr003                           #   60: ac42
            beqi         a2, 1, .Lbr003                        #   62: 261222
            mov.n        a2, a0 /* sdk_flashchip */            #   65: 2d00
            movi         a0, .Lrel002 /* .Lrel002 */           #   67: 01efff
            callx0       a0                                    #   6a: c00000
.Lbr002:    memw                                               #   6d: c02000
            movi         a8, .Llit004 /* 0x60000200 */         #   70: 81e8ff
            l32i.n       a7, a8, 8 /* [0x60000208] */          #   73: 7828
            or           a7, a7, a12                           #   75: c07720
            memw                                               #   78: c02000
            s32i.n       a7, a8, 8 /* a7 -> [0x60000208] */    #   7b: 7928
            movi.n       a2, 0 /* 0x00000000 */                #   7d: 0c02
            l32i.n       a12, a1, 4 /* [(local1)] */           #   7f: c811
            l32i.n       a0, a1, 0 /* [(local0)] */            #   81: 0801
            addi         a1, a1, 16 /* (top of frame) */       #   83: 12c110
            ret.n         /* 0x00000000 */                     #   86: 0df0
.Lbr003:    mov.n        a2, a0 /* sdk_flashchip */            #   88: 2d00
            movi         a0, .Lrel003 /* .Lrel003 */           #   8a: 01e7ff
            callx0       a0                                    #   8d: c00000
            j            .Lbr002                               #   90: 46f6ff
.Lbr004:    movi         a12, .Llit005 /* 0x01002000 */        #   93: c1e0ff
            j            .Lbr001                               #   96: 86f1ff
.Lbr005:    movi         a12, .Llit006 /* 0x00102000 */        #   99: c1dfff
            j            .Lbr001                               #   9c: 06f0ff
.Lbr006:    movi         a12, .Llit007 /* 0x00802000 */        #   9f: c1dfff
            j            .Lbr001                               #   a2: 86eeff
.Lbr007:    movi         a12, .Llit008 /* 0x00006000 */        #   a5: c1deff
            j            .Lbr001                               #   a8: 06edff

            .balign      4
.Lrel004:   .word        .data                                 #   ac: 00000000
.Lrel005:   .word        .data                                 #   b0: 00000000
.Lrel006:   .word        .data                                 #   b4: 00000000
.Lrel007:   .word        .data                                 #   b8: 00000000
.Lrel008:   .word        .data                                 #   bc: 00000000
.Lrel009:   .word        SPI_page_program                      #   c0: 00000000
.Lrel010:   .word        __udivsi3                             #   c4: 00000000
.Lrel011:   .word        SPI_page_program                      #   c8: 00000000
.Lrel012:   .word        SPI_page_program                      #   cc: 00000000
.Lrel013:   .word        __umodsi3                             #   d0: 00000000
.Lrel014:   .word        SPI_page_program                      #   d4: 00000000

# Function @ .text+0xd8
# Local variables/stack:
#     (local0):  word      @ -0x30
#     (local1):  word      @ -0x2c
#     (local2):  word      @ -0x28
#     (local3):  word      @ -0x24
#     (local4):  word      @ -0x20
#     (local5):  word      @ -0x1c
#     (local6):  word      @ -0x18
#     (local7):  word      @ -0x14
#     (local8):  word      @ -0x10
#     (local9):  word[3]   @ -0xc
.literal_position
sdk_SPIWrite:
            mov.n        a5, a4 /* arg2 */                     #   d8: 5d04
            addi         a1, a1, -48 /* (local0) */            #   da: 12c1d0
            s32i.n       a12, a1, 16 /* a12 -> [(local4)] */   #   dd: c941
            s32i.n       a14, a1, 24 /* a14 -> [(local6)] */   #   df: e961
            s32i.n       a3, a1, 36 /* arg1 -> [(local9)] */   #   e1: 3991
            s32i.n       a0, a1, 12 /* a0 -> [(local3)] */     #   e3: 0931
            movi         a4, .Lrel004 /* sdk_flashchip */      #   e5: 41f1ff
            s32i.n       a15, a1, 28 /* a15 -> [(local7)] */   #   e8: f971
            s32i.n       a13, a1, 20 /* a13 -> [(local5)] */   #   ea: d951
            mov.n        a15, a3 /* arg1 */                    #   ec: fd03
            mov.n        a13, a2 /* arg0 */                    #   ee: dd02
            l32i.n       a0, a4, 4 /* [.Ldata001] */           #   f0: 0814
            add.n        a2, a5, a2                            #   f2: 2a25
            bltu         a0, a2, .Lbr008                       #   f4: 273002
            j            .Lbr014                               #   f7: 462000
.Lbr008:    movi.n       a2, 1 /* 0x00000001 */                #   fa: 0c12
            j            .Lbr013                               #   fc: 461b00
.Lbr009:    movi         a2, .Lrel005 /* sdk_flashchip */      #   ff: 21ecff
            mov.n        a3, a13 /* arg0 */                    #  102: 3d0d
            mov.n        a4, a15 /* arg1 */                    #  104: 4d0f
            mov.n        a5, a12                               #  106: 5d0c
            movi         a0, .Lrel009 /* SPI_page_program */   #  108: 01eeff
            callx0       a0 /* SPI_page_program */             #  10b: c00000
            bnez         a2, .Lbr008                           #  10e: 5682fe
            l32i.n       a2, a1, 8 /* [(local2)] */            #  111: 2821
            mov.n        a3, a14 /* [.Ldata003] */             #  113: 3d0e
            sub          a2, a2, a12                           #  115: c022c0
            s32i.n       a2, a1, 0 /* a2 -> [(local0)] */      #  118: 2901
            movi         a0, .Lrel010 /* __udivsi3 */          #  11a: 01eaff
            callx0       a0 /* __udivsi3 */                    #  11d: c00000
            s32i.n       a2, a1, 4 /* a2 -> [(local1)] */      #  120: 2911
            beqz.n       a2, .Lbr011                           #  122: acf2
            movi.n       a3, 0 /* 0x00000000 */                #  124: 0c03
            s32i.n       a3, a1, 32 /* 0x00000000 -> [(local8)] */ #  126: 3981
.Lbr010:    movi         a2, .Lrel006 /* .Lrel006 */           #  128: 21e3ff
            add.n        a3, a13, a12                          #  12b: ca3d
            mov.n        a5, a14 /* [.Ldata003] */             #  12d: 5d0e
            srli         a4, a12, 2                            #  12f: c04241
            addx4        a4, a4, a15                           #  132: f044a0
            movi         a0, .Lrel011 /* .Lrel011 */           #  135: 01e4ff
            callx0       a0                                    #  138: c00000
            bnez         a2, .Lbr008                           #  13b: 56b2fb
            add.n        a12, a14, a12                         #  13e: cace
            l32i.n       a6, a1, 32 /* [(local8)] */           #  140: 6881
            l32i.n       a5, a1, 4 /* [(local1)] */            #  142: 5811
            addi.n       a7, a6, 1 /* [(local8)]+0x1 */        #  144: 1b76
            extui        a6, a7, 0, 8                          #  146: 706074
            s32i.n       a6, a1, 32 /* a6 -> [(local8)] */     #  149: 6981
            bne          a5, a6, .Lbr010                       #  14b: 6795d9
            l32i.n       a8, a1, 8 /* [(local2)] */            #  14e: 8821
            sub          a8, a8, a12                           #  150: c088c0
            s32i.n       a8, a1, 0 /* a8 -> [(local0)] */      #  153: 8901
.Lbr011:    add.n        a3, a13, a12                          #  155: ca3d
            movi         a2, .Lrel007 /* sdk_flashchip */      #  157: 21d8ff
            l32i.n       a5, a1, 0 /* [(local0)] */            #  15a: 5801
            srli         a4, a12, 2                            #  15c: c04241
            addx4        a4, a4, a15                           #  15f: f044a0
            movi         a0, .Lrel012 /* SPI_page_program */   #  162: 01daff
            callx0       a0 /* SPI_page_program */             #  165: c00000
            bnez         a2, .Lbr008                           #  168: 56e2f8
.Lbr012:    movi.n       a2, 0 /* 0x00000000 */                #  16b: 0c02
.Lbr013:    l32i.n       a12, a1, 16 /* [(local4)] */          #  16d: c841
            l32i.n       a13, a1, 20 /* [(local5)] */          #  16f: d851
            l32i.n       a14, a1, 24 /* [(local6)] */          #  171: e861
            l32i.n       a15, a1, 28 /* [(local7)] */          #  173: f871
            l32i.n       a0, a1, 12 /* [(local3)] */           #  175: 0831
            addi         a1, a1, 48 /* (top of frame) */       #  177: 12c130
            ret.n                                              #  17a: 0df0
.Lbr014:    mov.n        a2, a13 /* arg0 */                    #  17c: 2d0d
            l32i.n       a14, a4, 16 /* [.Ldata003] */         #  17e: e844
            s32i.n       a5, a1, 8 /* arg2 -> [(local2)] */    #  180: 5921
            mov.n        a3, a14 /* [.Ldata003] */             #  182: 3d0e
            movi         a0, .Lrel013 /* __umodsi3 */          #  184: 01d3ff
            callx0       a0 /* __umodsi3 */                    #  187: c00000
            l32i.n       a5, a1, 8 /* [(local2)] */            #  18a: 5821
            sub          a12, a14, a2                          #  18c: 20cec0
            bltu         a5, a12, .Lbr015                      #  18f: c73502
            j            .Lbr009                               #  192: 46daff
.Lbr015:    mov.n        a4, a15 /* arg1 */                    #  195: 4d0f
            mov.n        a3, a13 /* arg0 */                    #  197: 3d0d
            movi         a2, .Lrel008 /* sdk_flashchip */      #  199: 21c8ff
            movi         a0, .Lrel014 /* SPI_page_program */   #  19c: 01ceff
            callx0       a0 /* SPI_page_program */             #  19f: c00000
            bnez         a2, .Lbr008                           #  1a2: 5642f5
            j            .Lbr012                               #  1a5: 86f0ff

.Lrel015:   .word        .data                                 #  1a8: 00000000
.Lrel016:   .word        SPI_read_data                         #  1ac: 00000000

# Function @ .text+0x1b0
# Local variables/stack:
#     (local0):  word[4]   @ -0x10
.literal_position
sdk_SPIRead:
            mov.n        a5, a4 /* arg2 */                     #  1b0: 5d04
            mov.n        a7, a3 /* arg1 */                     #  1b2: 7d03
            addi         a1, a1, -16 /* (local0) */            #  1b4: 12c1f0
            s32i.n       a0, a1, 0 /* a0 -> [(local0)] */      #  1b7: 0901
            mov.n        a3, a2 /* arg0 */                     #  1b9: 3d02
            mov.n        a4, a7 /* arg1 */                     #  1bb: 4d07
            movi         a2, .Lrel015 /* sdk_flashchip */      #  1bd: 21faff
            movi         a0, .Lrel016 /* SPI_read_data */      #  1c0: 01fbff
            callx0       a0 /* SPI_read_data */                #  1c3: c00000
            movi.n       a4, 0 /* 0x00000000 */                #  1c6: 0c04
            l32i.n       a3, a1, 0 /* [(local0)] */            #  1c8: 3801
            movi.n       a0, 1 /* 0x00000001 */                #  1ca: 0c10
            addi         a1, a1, 16 /* (top of frame) */       #  1cc: 12c110
            moveqz       a0, a4, a2                            #  1cf: 200483
            mov.n        a2, a0                                #  1d2: 2d00
            mov.n        a0, a3 /* [(local0)] */               #  1d4: 0d03
            ret.n                                              #  1d6: 0df0

.Lrel017:   .word        .data                                 #  1d8: 00000000
.Lrel018:   .word        .data                                 #  1dc: 00000000
.Lrel019:   .word        .data                                 #  1e0: 00000000
.Lrel020:   .word        __udivsi3                             #  1e4: 00000000
.Lrel021:   .word        SPI_write_enable                      #  1e8: 00000000
.Lrel022:   .word        SPI_sector_erase                      #  1ec: 00000000

# Function @ .text+0x1f0
# Local variables/stack:
#     (local0):  word      @ -0x10
#     (local1):  word[3]   @ -0xc
.literal_position
sdk_SPIEraseSector:
            addi         a1, a1, -16 /* (local0) */            #  1f0: 12c1f0
            movi         a3, .Lrel017 /* sdk_flashchip */      #  1f3: 31f9ff
            s32i.n       a12, a1, 4 /* a12 -> [(local1)] */    #  1f6: c911
            mov.n        a12, a2 /* arg0 */                    #  1f8: cd02
            s32i.n       a0, a1, 0 /* a0 -> [(local0)] */      #  1fa: 0901
            l32i.n       a2, a3, 4 /* [.Ldata001] */           #  1fc: 2813
            l32i.n       a3, a3, 12 /* [.Ldata002] */          #  1fe: 3833
            movi         a0, .Lrel020 /* __udivsi3 */          #  200: 01f9ff
            callx0       a0 /* __udivsi3 */                    #  203: c00000
            bgeu         a12, a2, .Lbr016                      #  206: 27bc1f
            movi         a2, .Lrel018 /* sdk_flashchip */      #  209: 21f4ff
            movi         a0, .Lrel021 /* SPI_write_enable */   #  20c: 01f7ff
            callx0       a0 /* SPI_write_enable */             #  20f: c00000
            bnez.n       a2, .Lbr016                           #  212: dc32
            movi         a2, .Lrel019 /* sdk_flashchip */      #  214: 21f3ff
            l32i.n       a3, a2, 12 /* [.Ldata002] */          #  217: 3832
            mull         a3, a3, a12                           #  219: c03382
            movi         a0, .Lrel022 /* SPI_sector_erase */   #  21c: 01f4ff
            callx0       a0 /* SPI_sector_erase */             #  21f: c00000
            bnez.n       a2, .Lbr016                           #  222: cc32
            movi.n       a2, 0 /* 0x00000000 */                #  224: 0c02
            j            .Lbr017                               #  226: 460000
.Lbr016:    movi.n       a2, 1 /* 0x00000001 */                #  229: 0c12
.Lbr017:    l32i.n       a12, a1, 4 /* [(local1)] */           #  22b: c811
            l32i.n       a0, a1, 0 /* [(local0)] */            #  22d: 0801
            addi         a1, a1, 16 /* (top of frame) */       #  22f: 12c110
            ret.n                                              #  232: 0df0

.Lrel023:   .word        .data                                 #  234: 00000000

# NOTE: The following is apparently unreferenced code/data
.Llit009:   .word        0x60000200                            #  238: 00020060
.Llit010:   .word        0x10000000                            #  23c: 00000010
.Llit011:   .word        0x00ffffff                            #  240: ffffff00

.Lrel024:   .word        vPortEnterCritical                    #  244: 00000000
.Lrel025:   .word        Cache_Read_Disable                    #  248: 00000000
.Lrel026:   .word        Wait_SPI_Idle                         #  24c: 00000000
.Lrel027:   .word        Cache_Read_Enable                     #  250: 00000000
.Lrel028:   .word        vPortExitCritical                     #  254: 00000000

# Function @ .text+0x258
# Local variables/stack:
#     (local0):  word      @ -0x10
#     (local1):  word[3]   @ -0xc
.literal_position
sdk_spi_flash_get_id:
            addi         a1, a1, -16 /* (local0) */            #  258: 12c1f0
            s32i.n       a0, a1, 4 /* a0 -> [(local1)] */      #  25b: 0911
            movi         a0, .Lrel024 /* vPortEnterCritical */ #  25d: 01f9ff
            callx0       a0 /* vPortEnterCritical */           #  260: c00000
            movi         a0, .Lrel025 /* Cache_Read_Disable */ #  263: 01f9ff
            callx0       a0 /* Cache_Read_Disable */           #  266: c00000
            movi         a2, .Lrel023 /* sdk_flashchip */      #  269: 21f2ff
            movi         a0, .Lrel026 /* Wait_SPI_Idle */      #  26c: 01f8ff
            callx0       a0 /* Wait_SPI_Idle */                #  26f: c00000
            movi.n       a4, 0 /* 0x00000000 */                #  272: 0c04
            movi         a0, .Llit009 /* 0x60000200 */         #  274: 01f1ff
            memw                                               #  277: c02000
            s32i         a4, a0, 64 /* 0x00000000 -> [0x60000240] */ #  27a: 426010
            movi         a3, .Llit010 /* 0x10000000 */         #  27d: 31efff
            memw                                               #  280: c02000
            s32i.n       a3, a0, 0 /* 0x10000000 -> [0x60000200] */ #  283: 3900
            memw                                               #  285: c02000
            l32i.n       a2, a0, 0 /* [0x60000200] */          #  288: 2800
            beqz.n       a2, .Lbr019                           #  28a: 8c62
.Lbr018:    memw                                               #  28c: c02000
            l32i.n       a5, a0, 0 /* [0x60000200] */          #  28f: 5800
            bnez         a5, .Lbr018                           #  291: 5675ff
.Lbr019:    movi         a7, .Llit011 /* 0x00ffffff */         #  294: 71ebff
            memw                                               #  297: c02000
            movi.n       a2, 0 /* 0x00000000 */                #  29a: 0c02
            movi.n       a3, 0 /* 0x00000000 */                #  29c: 0c03
            l32i         a6, a0, 64 /* [0x60000240] */         #  29e: 622010
            movi.n       a4, 1 /* 0x00000001 */                #  2a1: 0c14
            and          a6, a6, a7                            #  2a3: 706610
            s32i.n       a6, a1, 0 /* a6 -> [(local0)] */      #  2a6: 6901
            movi         a0, .Lrel027 /* Cache_Read_Enable */  #  2a8: 01eaff
            callx0       a0 /* Cache_Read_Enable */            #  2ab: c00000
            movi         a0, .Lrel028 /* vPortExitCritical */  #  2ae: 01e9ff
            callx0       a0 /* vPortExitCritical */            #  2b1: c00000
            l32i.n       a8, a1, 4 /* [(local1)] */            #  2b4: 8811
            l32i.n       a2, a1, 0 /* [(local0)] */            #  2b6: 2801
            mov.n        a0, a8 /* [(local1)] */               #  2b8: 0d08
            addi         a1, a1, 16 /* (top of frame) */       #  2ba: 12c110
            ret.n         /* [(local0)] */                     #  2bd: 0df0

            .balign      4
.Lrel029:   .word        .data                                 #  2c0: 00000000
.Lrel030:   .word        vPortEnterCritical                    #  2c4: 00000000
.Lrel031:   .word        Cache_Read_Disable                    #  2c8: 00000000
.Lrel032:   .word        SPI_read_status                       #  2cc: 00000000
.Lrel033:   .word        Cache_Read_Enable                     #  2d0: 00000000
.Lrel034:   .word        vPortExitCritical                     #  2d4: 00000000

# Function @ .text+0x2d8
# Local variables/stack:
#     (local0):  word      @ -0x10
#     (local1):  word      @ -0xc
#     (local2):  word[2]   @ -0x8
.literal_position
sdk_spi_flash_read_status:
            addi         a1, a1, -16 /* (local0) */            #  2d8: 12c1f0
            s32i.n       a2, a1, 0 /* arg0 -> [(local0)] */    #  2db: 2901
            s32i.n       a0, a1, 8 /* a0 -> [(local2)] */      #  2dd: 0921
            movi         a0, .Lrel030 /* vPortEnterCritical */ #  2df: 01f9ff
            callx0       a0 /* vPortEnterCritical */           #  2e2: c00000
            movi         a0, .Lrel031 /* Cache_Read_Disable */ #  2e5: 01f8ff
            callx0       a0 /* Cache_Read_Disable */           #  2e8: c00000
            movi         a2, .Lrel029 /* sdk_flashchip */      #  2eb: 21f5ff
            l32i.n       a3, a1, 0 /* [(local0)] */            #  2ee: 3801
            movi         a0, .Lrel032 /* SPI_read_status */    #  2f0: 01f7ff
            callx0       a0 /* SPI_read_status */              #  2f3: c00000
            movi.n       a3, 0 /* 0x00000000 */                #  2f6: 0c03
            s32i.n       a2, a1, 4 /* a2 -> [(local1)] */      #  2f8: 2911
            movi.n       a4, 1 /* 0x00000001 */                #  2fa: 0c14
            movi.n       a2, 0 /* 0x00000000 */                #  2fc: 0c02
            movi         a0, .Lrel033 /* Cache_Read_Enable */  #  2fe: 01f4ff
            callx0       a0 /* Cache_Read_Enable */            #  301: c00000
            movi         a0, .Lrel034 /* vPortExitCritical */  #  304: 01f4ff
            callx0       a0 /* vPortExitCritical */            #  307: c00000
            l32i.n       a3, a1, 8 /* [(local2)] */            #  30a: 3821
            l32i.n       a2, a1, 4 /* [(local1)] */            #  30c: 2811
            mov.n        a0, a3 /* [(local2)] */               #  30e: 0d03
            addi         a1, a1, 16 /* (top of frame) */       #  310: 12c110
            ret.n         /* [(local1)] */                     #  313: 0df0

            .balign      4
.Lrel035:   .word        .data                                 #  318: 00000000
.Lrel036:   .word        vPortEnterCritical                    #  31c: 00000000
.Lrel037:   .word        Cache_Read_Disable                    #  320: 00000000
.Lrel038:   .word        SPI_write_status                      #  324: 00000000
.Lrel039:   .word        Cache_Read_Enable                     #  328: 00000000
.Lrel040:   .word        vPortExitCritical                     #  32c: 00000000

# Function @ .text+0x330
# Local variables/stack:
#     (local0):  word      @ -0x10
#     (local1):  word      @ -0xc
#     (local2):  word[2]   @ -0x8
.literal_position
sdk_spi_flash_write_status:
            addi         a1, a1, -16 /* (local0) */            #  330: 12c1f0
            s32i.n       a2, a1, 0 /* arg0 -> [(local0)] */    #  333: 2901
            s32i.n       a0, a1, 8 /* a0 -> [(local2)] */      #  335: 0921
            movi         a0, .Lrel036 /* vPortEnterCritical */ #  337: 01f9ff
            callx0       a0 /* vPortEnterCritical */           #  33a: c00000
            movi         a0, .Lrel037 /* Cache_Read_Disable */ #  33d: 01f8ff
            callx0       a0 /* Cache_Read_Disable */           #  340: c00000
            movi         a2, .Lrel035 /* sdk_flashchip */      #  343: 21f5ff
            l32i.n       a3, a1, 0 /* [(local0)] */            #  346: 3801
            movi         a0, .Lrel038 /* SPI_write_status */   #  348: 01f7ff
            callx0       a0 /* SPI_write_status */             #  34b: c00000
            movi.n       a3, 0 /* 0x00000000 */                #  34e: 0c03
            s32i.n       a2, a1, 4 /* a2 -> [(local1)] */      #  350: 2911
            movi.n       a4, 1 /* 0x00000001 */                #  352: 0c14
            movi.n       a2, 0 /* 0x00000000 */                #  354: 0c02
            movi         a0, .Lrel039 /* Cache_Read_Enable */  #  356: 01f4ff
            callx0       a0 /* Cache_Read_Enable */            #  359: c00000
            movi         a0, .Lrel040 /* vPortExitCritical */  #  35c: 01f4ff
            callx0       a0 /* vPortExitCritical */            #  35f: c00000
            l32i.n       a3, a1, 8 /* [(local2)] */            #  362: 3821
            l32i.n       a2, a1, 4 /* [(local1)] */            #  364: 2811
            mov.n        a0, a3 /* [(local2)] */               #  366: 0d03
            addi         a1, a1, 16 /* (top of frame) */       #  368: 12c110
            ret.n         /* [(local1)] */                     #  36b: 0df0

            .balign      4
.Lrel041:   .word        vPortEnterCritical                    #  370: 00000000
.Lrel042:   .word        Cache_Read_Disable                    #  374: 00000000
.Lrel043:   .word        Cache_Read_Enable                     #  378: 00000000
.Lrel044:   .word        vPortExitCritical                     #  37c: 00000000

# Function @ .text+0x380
# Local variables/stack:
#     (local0):  word      @ -0x10
#     (local1):  word      @ -0xc
#     (local2):  word[2]   @ -0x8
.literal_position
sdk_spi_flash_erase_sector:
            addi         a1, a1, -16 /* (local0) */            #  380: 12c1f0
            s32i.n       a2, a1, 0 /* arg0 -> [(local0)] */    #  383: 2901
            s32i.n       a0, a1, 8 /* a0 -> [(local2)] */      #  385: 0921
            movi         a0, .Lrel041 /* vPortEnterCritical */ #  387: 01faff
            callx0       a0 /* vPortEnterCritical */           #  38a: c00000
            movi         a0, .Lrel042 /* Cache_Read_Disable */ #  38d: 01f9ff
            callx0       a0 /* Cache_Read_Disable */           #  390: c00000
            l32i.n       a2, a1, 0 /* [(local0)] */            #  393: 2801
            call0        sdk_SPIEraseSector                    #  395: 050000
            movi.n       a3, 0 /* 0x00000000 */                #  398: 0c03
            s32i.n       a2, a1, 4 /* a2 -> [(local1)] */      #  39a: 2911
            movi.n       a4, 1 /* 0x00000001 */                #  39c: 0c14
            movi.n       a2, 0 /* 0x00000000 */                #  39e: 0c02
            movi         a0, .Lrel043 /* Cache_Read_Enable */  #  3a0: 01f6ff
            callx0       a0 /* Cache_Read_Enable */            #  3a3: c00000
            movi         a0, .Lrel044 /* vPortExitCritical */  #  3a6: 01f5ff
            callx0       a0 /* vPortExitCritical */            #  3a9: c00000
            l32i.n       a3, a1, 8 /* [(local2)] */            #  3ac: 3821
            l32i.n       a2, a1, 4 /* [(local1)] */            #  3ae: 2811
            mov.n        a0, a3 /* [(local2)] */               #  3b0: 0d03
            addi         a1, a1, 16 /* (top of frame) */       #  3b2: 12c110
            ret.n         /* [(local1)] */                     #  3b5: 0df0

            .balign      4
.Lrel045:   .word        vPortEnterCritical                    #  3b8: 00000000
.Lrel046:   .word        Cache_Read_Disable                    #  3bc: 00000000
.Lrel047:   .word        Cache_Read_Enable                     #  3c0: 00000000
.Lrel048:   .word        vPortExitCritical                     #  3c4: 00000000

# Function @ .text+0x3c8
# Local variables/stack:
#     (local0):  word      @ -0x10
#     (local1):  word      @ -0xc
#     (local2):  word      @ -0x8
#     (local3):  word      @ -0x4
.literal_position
sdk_spi_flash_write:
            addi         a1, a1, -16 /* (local0) */            #  3c8: 12c1f0
            s32i.n       a0, a1, 4 /* a0 -> [(local1)] */      #  3cb: 0911
            s32i.n       a13, a1, 12 /* a13 -> [(local3)] */   #  3cd: d931
            s32i.n       a12, a1, 8 /* a12 -> [(local2)] */    #  3cf: c921
            mov.n        a13, a3 /* arg1 */                    #  3d1: dd03
            mov.n        a12, a4 /* arg2 */                    #  3d3: cd04
            bnez.n       a3, .Lbr020                           #  3d5: cc33
            movi.n       a2, 1 /* 0x00000001 */                #  3d7: 0c12
            j            .Lbr022                               #  3d9: 460e00
.Lbr020:    s32i.n       a2, a1, 0 /* arg0 -> [(local0)] */    #  3dc: 2901
            movi.n       a0, 3 /* 0x00000003 */                #  3de: 0c30
            bnone        a0, a4, .Lbr021                       #  3e0: 470007
            movi.n       a0, 4 /* 0x00000004 */                #  3e3: 0c40
            srli         a12, a4, 2                            #  3e5: 40c241
            addx4        a12, a12, a0                          #  3e8: 00cca0
.Lbr021:    movi         a0, .Lrel045 /* vPortEnterCritical */ #  3eb: 01f3ff
            callx0       a0 /* vPortEnterCritical */           #  3ee: c00000
            movi         a0, .Lrel046 /* Cache_Read_Disable */ #  3f1: 01f2ff
            callx0       a0 /* Cache_Read_Disable */           #  3f4: c00000
            mov.n        a4, a12                               #  3f7: 4d0c
            mov.n        a3, a13 /* arg1 */                    #  3f9: 3d0d
            l32i.n       a2, a1, 0 /* [(local0)] */            #  3fb: 2801
            call0        sdk_SPIWrite                          #  3fd: 050000
            movi.n       a3, 0 /* 0x00000000 */                #  400: 0c03
            mov.n        a12, a2                               #  402: cd02
            movi.n       a4, 1 /* 0x00000001 */                #  404: 0c14
            movi.n       a2, 0 /* 0x00000000 */                #  406: 0c02
            movi         a0, .Lrel047 /* Cache_Read_Enable */  #  408: 01eeff
            callx0       a0 /* Cache_Read_Enable */            #  40b: c00000
            movi         a0, .Lrel048 /* vPortExitCritical */  #  40e: 01edff
            callx0       a0 /* vPortExitCritical */            #  411: c00000
            mov.n        a2, a12                               #  414: 2d0c
.Lbr022:    l32i.n       a12, a1, 8 /* [(local2)] */           #  416: c821
            l32i.n       a13, a1, 12 /* [(local3)] */          #  418: d831
            l32i.n       a0, a1, 4 /* [(local1)] */            #  41a: 0811
            addi         a1, a1, 16 /* (top of frame) */       #  41c: 12c110
            ret.n                                              #  41f: 0df0

            .balign      4
.Lrel049:   .word        vPortEnterCritical                    #  424: 00000000
.Lrel050:   .word        Cache_Read_Disable                    #  428: 00000000
.Lrel051:   .word        Cache_Read_Enable                     #  42c: 00000000
.Lrel052:   .word        vPortExitCritical                     #  430: 00000000

# Function @ .text+0x434
# Local variables/stack:
#     (local0):  word      @ -0x10
#     (local1):  word      @ -0xc
#     (local2):  word      @ -0x8
#     (local3):  word      @ -0x4
.literal_position
sdk_spi_flash_read:
            addi         a1, a1, -16 /* (local0) */            #  434: 12c1f0
            s32i.n       a0, a1, 8 /* a0 -> [(local2)] */      #  437: 0921
            s32i.n       a4, a1, 0 /* arg2 -> [(local0)] */    #  439: 4901
            s32i.n       a12, a1, 12 /* a12 -> [(local3)] */   #  43b: c931
            s32i.n       a2, a1, 4 /* arg0 -> [(local1)] */    #  43d: 2911
            mov.n        a12, a3 /* arg1 */                    #  43f: cd03
            bnez.n       a3, .Lbr023                           #  441: cc33
            movi.n       a2, 1 /* 0x00000001 */                #  443: 0c12
            j            .Lbr024                               #  445: 860a00
.Lbr023:    movi         a0, .Lrel049 /* vPortEnterCritical */ #  448: 01f7ff
            callx0       a0 /* vPortEnterCritical */           #  44b: c00000
            movi         a0, .Lrel050 /* Cache_Read_Disable */ #  44e: 01f6ff
            callx0       a0 /* Cache_Read_Disable */           #  451: c00000
            mov.n        a3, a12 /* arg1 */                    #  454: 3d0c
            l32i.n       a2, a1, 4 /* [(local1)] */            #  456: 2811
            l32i.n       a4, a1, 0 /* [(local0)] */            #  458: 4801
            call0        sdk_SPIRead                           #  45a: 050000
            movi.n       a3, 0 /* 0x00000000 */                #  45d: 0c03
            mov.n        a12, a2                               #  45f: cd02
            movi.n       a4, 1 /* 0x00000001 */                #  461: 0c14
            movi.n       a2, 0 /* 0x00000000 */                #  463: 0c02
            movi         a0, .Lrel051 /* Cache_Read_Enable */  #  465: 01f1ff
            callx0       a0 /* Cache_Read_Enable */            #  468: c00000
            movi         a0, .Lrel052 /* vPortExitCritical */  #  46b: 01f1ff
            callx0       a0 /* vPortExitCritical */            #  46e: c00000
            mov.n        a2, a12                               #  471: 2d0c
.Lbr024:    l32i.n       a12, a1, 12 /* [(local3)] */          #  473: c831
            l32i.n       a0, a1, 8 /* [(local2)] */            #  475: 0821
            addi         a1, a1, 16 /* (top of frame) */       #  477: 12c110
            ret.n                                              #  47a: 0df0

            .section     .data, "aw", @progbits

sdk_flashchip:
            .word        0x001640ef                            #    0: ef401600
.Ldata001:  .word        0x00400000                            #    4: 00004000

# NOTE: The following is apparently unreferenced code/data
            .word        0x00010000                            #    8: 00000100

.Ldata002:  .word        0x00001000                            #    c: 00100000
.Ldata003:  .word        0x00000100                            #   10: 00010000

# NOTE: The following is apparently unreferenced code/data
            .word        0x0000ffff                            #   14: ffff0000

            .section     .bss, "aw", @nobits
