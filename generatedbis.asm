segment_0:004...7f454c460...    Elf64_Ehdr                                          ;= B8h
   |_segment_0:004...e_ident_m...    db          7Fh                                     
   |_segment_0:004...e_ident_m...    ds          "ELF"                                   
   |_segment_0:004...e_ident_c...    db          2h                                      
   |_segment_0:004...e_ident_data    db          1h                                      
   |_segment_0:004...e_ident_v...    db          1h                                      
   |_segment_0:004...e_ident_o...    db          0h                                      
   |_segment_0:004...e_ident_a...    db          0h                                      
   |_segment_0:004...e_ident_pad     db[7]                                               
      |_segment_0:004...[0]             db          0h                                      
      |_segment_0:004...[1]             db          0h                                      
      |_segment_0:004...[2]             db          0h                                      
      |_segment_0:004...[3]             db          0h                                      
      |_segment_0:004...[4]             db          0h                                      
      |_segment_0:004...[5]             db          0h                                      
      |_segment_0:004...[6]             db          0h                                      
   |_segment_0:004...e_type          dw          2h                                      
   |_segment_0:004...e_machine       dw          3Eh                                     
   |_segment_0:004...e_version       ddw         1h                                      
   |_segment_0:004...e_entry         dq          .text:entry                             
   |_segment_0:004...e_phoff         dq          Elf64_Phdr_ARRAY_00400040               
   |_segment_0:004...e_shoff         dq          _elfSectionHeaders:Elf64_Shdr_ARRAY__...
   |_segment_0:004...e_flags         ddw         0h                                      
   |_segment_0:004...e_ehsize        dw          40h                                     
   |_segment_0:004...e_phentsize     dw          38h                                     
   |_segment_0:004...e_phnum         dw          3h                                      
   |_segment_0:004...e_shentsize     dw          40h                                     
   |_segment_0:004...e_shnum         dw          6h                                      
   |_segment_0:004...e_shstrndx      dw          5h                                      
                            Elf64_Phdr_ARRAY_00400040:    ;XREF[1,0]:   00400020
segment_0:004...010000000...    Elf64_Ph...                                        ;PT_LOAD - Loadable segment
   |_segment_0:004...[0]             Elf64_Phdr                                          
      |_segment_0:004...p_type          Elf_Prog...PT_LOAD                                 
      |_segment_0:004...p_flags         ddw         4h                                      
      |_segment_0:004...p_offset        dq          0h                                      
      |_segment_0:004...p_vaddr         dq          400000h                                 
      |_segment_0:004...p_paddr         dq          400000h                                 
      |_segment_0:004...p_filesz        dq          E8h                                     
      |_segment_0:004...p_memsz         dq          E8h                                     
      |_segment_0:004...p_align         dq          1000h                                   
   |_segment_0:004...[1]             Elf64_Phdr                                          
      |_segment_0:004...p_type          Elf_Prog...PT_LOAD                                 
      |_segment_0:004...p_flags         ddw         5h                                      
      |_segment_0:004...p_offset        dq          1000h                                   
      |_segment_0:004...p_vaddr         dq          .text:entry                             
      |_segment_0:004...p_paddr         dq          401000h                                 
      |_segment_0:004...p_filesz        dq          25h                                     
      |_segment_0:004...p_memsz         dq          25h                                     
      |_segment_0:004...p_align         dq          1000h                                   
   |_segment_0:004...[2]             Elf64_Phdr                                          
      |_segment_0:004...p_type          Elf_Prog...PT_LOAD                                 
      |_segment_0:004...p_flags         ddw         6h                                      
      |_segment_0:004...p_offset        dq          2000h                                   
      |_segment_0:004...p_vaddr         dq          .data:message                           
      |_segment_0:004...p_paddr         dq          402000h                                 
      |_segment_0:004...p_filesz        dq          Dh                                      
      |_segment_0:004...p_memsz         dq          Dh                                      
      |_segment_0:004...p_align         dq          1000h                                   
                            ;************************************************************************************************
                            ;*                                           FUNCTION                                           *
                            ;************************************************************************************************
                            ;undefined entry()
                                                          ;XREF[4,0]:   Entry Point,00400018,00400088
                                                          ;             _elfSectionHeaders::00000050
.text:00401000  b8              ??          B8h                                     
.text:00401001  01              ??          01h                                     
.text:00401002  00              ??          00h                                     
.text:00401003  00              ??          00h                                     
.text:00401004  00              ??          00h                                     
.text:00401005  bf              ??          BFh                                     
.text:00401006  01              ??          01h                                     
.text:00401007  00              ??          00h                                     
.text:00401008  00              ??          00h                                     
.text:00401009  00              ??          00h                                     
.text:0040100a  48              ??          48h    H                                
.text:0040100b  be              ??          BEh                                     
.text:0040100c  00              ??          00h                                     ;?  ->  00402000
.text:0040100d  20              ??          20h                                     
.text:0040100e  40              ??          40h    @                                
.text:0040100f  00              ??          00h                                     
.text:00401010  00              ??          00h                                     
.text:00401011  00              ??          00h                                     
.text:00401012  00              ??          00h                                     
.text:00401013  00              ??          00h                                     
.text:00401014  ba              ??          BAh                                     
.text:00401015  0d              ??          0Dh                                     
.text:00401016  00              ??          00h                                     
.text:00401017  00              ??          00h                                     
.text:00401018  00              ??          00h                                     
.text:00401019  0f              ??          0Fh                                     
.text:0040101a  05              ??          05h                                     
.text:0040101b  b8              ??          B8h                                     
.text:0040101c  3c              ??          3Ch    <                                
.text:0040101d  00              ??          00h                                     
.text:0040101e  00              ??          00h                                     
.text:0040101f  00              ??          00h                                     
.text:00401020  48              ??          48h    H                                
.text:00401021  31              ??          31h    1                                
.text:00401022  ff              ??          FFh                                     
.text:00401023  0f              ??          0Fh                                     
.text:00401024  05              ??          05h                                     
                            message:                      ;XREF[2,0]:   004000c0,_elfSectionHeaders::00000090
.data:00402000  48              ??          48h    H                                
.data:00402001  65              ??          65h    e                                
.data:00402002  6c              ??          6Ch    l                                
.data:00402003  6c              ??          6Ch    l                                
.data:00402004  6f              ??          6Fh    o                                
.data:00402005  2c              ??          2Ch    ,                                
.data:00402006  20              ??          20h                                     
.data:00402007  57              ??          57h    W                                
.data:00402008  6f              ??          6Fh    o                                
.data:00402009  72              ??          72h    r                                
.data:0040200a  6c              ??          6Ch    l                                
.data:0040200b  64              ??          64h    d                                
.data:0040200c  0a              ??          0Ah                                     
                            DAT_.shstrtab__00000000:      ;XREF[1,0]:   _elfSectionHeaders::00000150
.shstrtab:.sh...00              ??          00h                                     
.shstrtab:.sh...2e73796d7...    ds          ".symtab"                               
.shstrtab:.sh...2e7374727...    ds          ".strtab"                               
.shstrtab:.sh...2e7368737...    ds          ".shstrtab"                             
.shstrtab:.sh...2e7465787400    ds          ".text"                                 
.shstrtab:.sh...2e6461746100    ds          ".data"                                 
                            DAT_.strtab__00000000:        ;XREF[1,0]:   _elfSectionHeaders::00000110
.strtab:.strt...00              ??          00h                                     
.strtab:.strt...68656c6c6...    ds          "helloWorld.asm"                        
.strtab:.strt...6d6573736...    ds          "message"                               
.strtab:.strt...5f5f62737...    ds          "__bss_start"                           
.strtab:.strt...5f6564617...    ds          "_edata"                                
.strtab:.strt...5f656e6400      ds          "_end"                                  
                            Elf64_Sym_ARRAY_.symtab__00...;XREF[1,0]:   _elfSectionHeaders::000000d0
.symtab:.symt...000000000...    Elf64_Sy...                                        
   |_.symtab:.symt...[0]             Elf64_Sym                                           
      |_.symtab:.symt...st_name         ddw         0h                                      
      |_.symtab:.symt...st_info         db          0h                                      
      |_.symtab:.symt...st_other        db          0h                                      
      |_.symtab:.symt...st_shndx        dw          0h                                      
      |_.symtab:.symt...st_value        dq          0h                                      
      |_.symtab:.symt...st_size         dq          0h                                      
   |_.symtab:.symt...[1]             Elf64_Sym                                           
      |_.symtab:.symt...st_name         ddw         0h                                      
      |_.symtab:.symt...st_info         db          3h                                      
      |_.symtab:.symt...st_other        db          0h                                      
      |_.symtab:.symt...st_shndx        dw          1h                                      
      |_.symtab:.symt...st_value        dq          401000h                                 
      |_.symtab:.symt...st_size         dq          0h                                      
   |_.symtab:.symt...[2]             Elf64_Sym                                           
      |_.symtab:.symt...st_name         ddw         0h                                      
      |_.symtab:.symt...st_info         db          3h                                      
      |_.symtab:.symt...st_other        db          0h                                      
      |_.symtab:.symt...st_shndx        dw          2h                                      
      |_.symtab:.symt...st_value        dq          402000h                                 
      |_.symtab:.symt...st_size         dq          0h                                      
   |_.symtab:.symt...[3]             Elf64_Sym                                           
      |_.symtab:.symt...st_name         ddw         1h                                      
      |_.symtab:.symt...st_info         db          4h                                      
      |_.symtab:.symt...st_other        db          0h                                      
      |_.symtab:.symt...st_shndx        dw          FFF1h                                   
      |_.symtab:.symt...st_value        dq          0h                                      
      |_.symtab:.symt...st_size         dq          0h                                      
   |_.symtab:.symt...[4]             Elf64_Sym                                           
      |_.symtab:.symt...st_name         ddw         10h                                     
      |_.symtab:.symt...st_info         db          0h                                      
      |_.symtab:.symt...st_other        db          0h                                      
      |_.symtab:.symt...st_shndx        dw          2h                                      
      |_.symtab:.symt...st_value        dq          402000h                                 
      |_.symtab:.symt...st_size         dq          0h                                      
   |_.symtab:.symt...[5]             Elf64_Sym                                           
      |_.symtab:.symt...st_name         ddw         1Dh                                     
      |_.symtab:.symt...st_info         db          10h                                     
      |_.symtab:.symt...st_other        db          0h                                      
      |_.symtab:.symt...st_shndx        dw          1h                                      
      |_.symtab:.symt...st_value        dq          401000h                                 
      |_.symtab:.symt...st_size         dq          0h                                      
   |_.symtab:.symt...[6]             Elf64_Sym                                           
      |_.symtab:.symt...st_name         ddw         18h                                     
      |_.symtab:.symt...st_info         db          10h                                     
      |_.symtab:.symt...st_other        db          0h                                      
      |_.symtab:.symt...st_shndx        dw          2h                                      
      |_.symtab:.symt...st_value        dq          40200Dh                                 
      |_.symtab:.symt...st_size         dq          0h                                      
   |_.symtab:.symt...[7]             Elf64_Sym                                           
      |_.symtab:.symt...st_name         ddw         24h                                     
      |_.symtab:.symt...st_info         db          10h                                     
      |_.symtab:.symt...st_other        db          0h                                      
      |_.symtab:.symt...st_shndx        dw          2h                                      
      |_.symtab:.symt...st_value        dq          40200Dh                                 
      |_.symtab:.symt...st_size         dq          0h                                      
   |_.symtab:.symt...[8]             Elf64_Sym                                           
      |_.symtab:.symt...st_name         ddw         2Bh                                     
      |_.symtab:.symt...st_info         db          10h                                     
      |_.symtab:.symt...st_other        db          0h                                      
      |_.symtab:.symt...st_shndx        dw          2h                                      
      |_.symtab:.symt...st_value        dq          402010h                                 
      |_.symtab:.symt...st_size         dq          0h                                      
                            Elf64_Shdr_ARRAY__elfSectio...;XREF[1,0]:   00400028
_elfSectionHe...000000000...    Elf64_Sh...                                        ;SECTION0 - SHT_NULL
   |__elfSectionHe...[0]             Elf64_Shdr                                          
      |__elfSectionHe...sh_name         ddw         0h                                      
      |__elfSectionHe...sh_type         Elf_Sect...SHT_NULL                                
      |__elfSectionHe...sh_flags        dq          0h                                      
      |__elfSectionHe...sh_addr         dq          0h                                      
      |__elfSectionHe...sh_offset       dq          0h                                      
      |__elfSectionHe...sh_size         dq          0h                                      
      |__elfSectionHe...sh_link         ddw         0h                                      
      |__elfSectionHe...sh_info         ddw         0h                                      
      |__elfSectionHe...sh_addralign    dq          0h                                      
      |__elfSectionHe...sh_entsize      dq          0h                                      
   |__elfSectionHe...[1]             Elf64_Shdr                                          
      |__elfSectionHe...sh_name         ddw         1Bh                                     
      |__elfSectionHe...sh_type         Elf_Sect...SHT_PROGBITS                            
      |__elfSectionHe...sh_flags        dq          6h                                      
      |__elfSectionHe...sh_addr         dq          .text:entry                             
      |__elfSectionHe...sh_offset       dq          1000h                                   
      |__elfSectionHe...sh_size         dq          25h                                     
      |__elfSectionHe...sh_link         ddw         0h                                      
      |__elfSectionHe...sh_info         ddw         0h                                      
      |__elfSectionHe...sh_addralign    dq          10h                                     
      |__elfSectionHe...sh_entsize      dq          0h                                      
   |__elfSectionHe...[2]             Elf64_Shdr                                          
      |__elfSectionHe...sh_name         ddw         21h                                     
      |__elfSectionHe...sh_type         Elf_Sect...SHT_PROGBITS                            
      |__elfSectionHe...sh_flags        dq          3h                                      
      |__elfSectionHe...sh_addr         dq          .data:message                           
      |__elfSectionHe...sh_offset       dq          2000h                                   
      |__elfSectionHe...sh_size         dq          Dh                                      
      |__elfSectionHe...sh_link         ddw         0h                                      
      |__elfSectionHe...sh_info         ddw         0h                                      
      |__elfSectionHe...sh_addralign    dq          4h                                      
      |__elfSectionHe...sh_entsize      dq          0h                                      
   |__elfSectionHe...[3]             Elf64_Shdr                                          
      |__elfSectionHe...sh_name         ddw         1h                                      
      |__elfSectionHe...sh_type         Elf_Sect...SHT_SYMTAB                              
      |__elfSectionHe...sh_flags        dq          0h                                      
      |__elfSectionHe...sh_addr         dq          .symtab:Elf64_Sym_ARRAY_.symtab__0000...
      |__elfSectionHe...sh_offset       dq          2010h                                   
      |__elfSectionHe...sh_size         dq          D8h                                     
      |__elfSectionHe...sh_link         ddw         4h                                      
      |__elfSectionHe...sh_info         ddw         5h                                      
      |__elfSectionHe...sh_addralign    dq          8h                                      
      |__elfSectionHe...sh_entsize      dq          18h                                     
   |__elfSectionHe...[4]             Elf64_Shdr                                          
      |__elfSectionHe...sh_name         ddw         9h                                      
      |__elfSectionHe...sh_type         Elf_Sect...SHT_STRTAB                              
      |__elfSectionHe...sh_flags        dq          0h                                      
      |__elfSectionHe...sh_addr         dq          .strtab:DAT_.strtab__00000000           
      |__elfSectionHe...sh_offset       dq          20E8h                                   
      |__elfSectionHe...sh_size         dq          30h                                     
      |__elfSectionHe...sh_link         ddw         0h                                      
      |__elfSectionHe...sh_info         ddw         0h                                      
      |__elfSectionHe...sh_addralign    dq          1h                                      
      |__elfSectionHe...sh_entsize      dq          0h                                      
   |__elfSectionHe...[5]             Elf64_Shdr                                          
      |__elfSectionHe...sh_name         ddw         11h                                     
      |__elfSectionHe...sh_type         Elf_Sect...SHT_STRTAB                              
      |__elfSectionHe...sh_flags        dq          0h                                      
      |__elfSectionHe...sh_addr         dq          .shstrtab:DAT_.shstrtab__00000000       
      |__elfSectionHe...sh_offset       dq          2118h                                   
      |__elfSectionHe...sh_size         dq          27h                                     
      |__elfSectionHe...sh_link         ddw         0h                                      
      |__elfSectionHe...sh_info         ddw         0h                                      
      |__elfSectionHe...sh_addralign    dq          1h                                      
      |__elfSectionHe...sh_entsize      dq          0h                                      
