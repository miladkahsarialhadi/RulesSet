rule SigntureOne
{

    meta:
        Description = "Stuxnet - Exe File"
        Author = "Milad Kahsari Alhadi"
        Hash = "9c891edb5da763398969b6aaa86a5d46971bd28a455b20c2067cb512c9f9a0f8"
    
    strings:
         $OpcodeOne = { 8b 45 08 35 dd 79 19 ae 33 c9 8b 55 08 89 02 89 }
         $OpcodeTwo = { 74 36 8b 7f 08 83 ff 00 74 2e 0f b7 1f 8b 7f 04 }
         $OpcodeThr = { 74 70 81 78 05 8d 54 24 04 75 1b 81 78 08 04 cd }
  
    condition:
        all of them
}

rule SigntureTwo 
{
   
    meta:
        Description = "Stuxnet - file 63e6b8136058d7a06dfff4034b4ab17a261cdf398e63868a601f77ddd1b32802"
        Author = "Milad Kahsari Alhadi"
        Hash = "63e6b8136058d7a06dfff4034b4ab17a261cdf398e63868a601f77ddd1b32802"
   
    strings:
        $StringOne = "\\SystemRoot\\System32\\hal.dll" fullword wide
        $StringTwo = "http://www.jmicron.co.tw0" fullword ascii
   
    condition:
        uint16(0) == 0x5a4d and filesize < 70KB and all of them
}

rule SigntureThr 
{

    meta:
        Description = "Stuxnet - file dll.dll"
        Author = "Milad Kahsari Alhadi"
        Hash = "9e392277f62206098cf794ddebafd2817483cfd57ec03c2e05e7c3c81e72f562"

    strings:
        $StringOne = "SUCKM3 FROM EXPLORER.EXE MOTH4FUCKA #@!" fullword ascii
    
    condition:
        uint16(0) == 0x5a4d and filesize < 100KB and $s1
}

rule SigntureFur 
{

    meta:
        Description = "Stuxnet - Copy of Shortcut to.lnk"
        Author = "Milad Kahsari Alhadi"
        Hash = "801e3b6d84862163a735502f93b9663be53ccbdd7f12b0707336fecba3a829a2"

    strings:
        $StringOne = "\\\\.\\STORAGE#Volume#_??_USBSTOR#Disk&Ven_Kingston&Prod_DataTraveler_2.0&Rev_PMAP#5B6B098B97BE&0#{53f56307-b6bf-11d0-94f2-00a0c" wide

    condition:
        uint16(0) == 0x004c and filesize < 10KB and $x1
}

rule SigntureFiv 
{

    meta:
        Description = "Stuxnet - file ~WTR4141.tmp"
        Author = "Milad Kahsari Alhadi"
        HashOne = "6bcf88251c876ef00b2f32cf97456a3e306c2a263d487b0a50216c6e3cc07c6a"
        HashTwo = "70f8789b03e38d07584f57581363afa848dd5c3a197f2483c6dfa4f3e7f78b9b"

    strings:
        $Sign1 = "SHELL32.DLL.ASLR." fullword wide
        $String2 = "~WTR4141.tmp" fullword wide
        $String3 = "~WTR4132.tmp" fullword wide
        $String4 = "totalcmd.exe" fullword wide
        $String5 = "wincmd.exe" fullword wide
        $String6 = "http://www.realtek.com0" fullword ascii
        $String7 = "{%08x-%08x-%08x-%08x}" fullword wide

    condition:
        ( uint16(0) == 0x5a4d and filesize < 150KB and ( $Sign1 or 3 of ($String*) ) ) or ( 5 of them )
}

rule SigntureSix 
{

    meta:
        Description = "Stuxnet - file 0d8c2bcb575378f6a88d17b5f6ce70e794a264cdc8556c8e812f0b5f9c709198"
        Author = "Milad Kahsari Alhadi"
        HashOne = "0d8c2bcb575378f6a88d17b5f6ce70e794a264cdc8556c8e812f0b5f9c709198"
        HashTwo = "1635ec04f069ccc8331d01fdf31132a4bc8f6fd3830ac94739df95ee093c555c"
   
    strings:
        $Sign1 = "\\objfre_w2k_x86\\i386\\guava.pdb" ascii
        $Sign2 = "MRxCls.sys" fullword wide
        $Sign3 = "MRXNET.Sys" fullword wide
   
    condition:
        ( uint16(0) == 0x5a4d and filesize < 80KB and 1 of them ) or ( all of them )
}

rule SigntureSev 
{

    meta:
        Description = "Stuxnet - file maindll.decrypted.unpacked.dll_"
        Author = "Milad Kahsari Alhadi"
        Hash = "4c3d7b38339d7b8adf73eaf85f0eb9fab4420585c6ab6950ebd360428af11712"

    strings:
        $String1 = "%SystemRoot%\\system32\\Drivers\\mrxsmb.sys;%SystemRoot%\\system32\\Drivers\\*.sys" fullword wide
        $String2 = "<Actions Context=\"%s\"><Exec><Command>%s</Command><Arguments>%s,#%u</Arguments></Exec></Actions>" fullword wide
        $String3 = "%SystemRoot%\\inf\\oem7A.PNF" fullword wide
        $String4 = "%SystemRoot%\\inf\\mdmcpq3.PNF" fullword wide
        $String5 = "%SystemRoot%\\inf\\oem6C.PNF" fullword wide
        $String6 = "@abf varbinary(4096) EXEC @hr = sp_OACreate 'ADODB.Stream', @aods OUT IF @hr <> 0 GOTO endq EXEC @hr = sp_OASetProperty @" wide
        $String7 = "STORAGE#Volume#1&19f7e59c&0&" fullword wide
        $String8 = "view MCPVREADVARPERCON as select VARIABLEID,VARIABLETYPEID,FORMATFITTING,SCALEID,VARIABLENAME,ADDRESSPARAMETER,PROTOKOLL,MAXLIMI" ascii

    condition:
         6 of them
}

rule SigntureEig 
{

    meta:
        Description = "Stuxnet - file s7hkimdb.dll"
        Author = "Milad Kahsari Alhadi"
        Hash = "4071ec265a44d1f0d42ff92b2fa0b30aafa7f6bb2160ed1d0d5372d70ac654bd"

    strings:
        $Sign1 = "S7HKIMDX.DLL" fullword wide
        $Opcode1 = { 8b 45 08 35 dd 79 19 ae 33 c9 8b 55 08 89 02 89 }
        $Opcode2 = { 74 36 8b 7f 08 83 ff 00 74 2e 0f b7 1f 8b 7f 04 }
        $Opcode3 = { 74 70 81 78 05 8d 54 24 04 75 1b 81 78 08 04 cd }

    condition:
        ( uint16(0) == 0x5a4d and filesize < 40KB and $Sign1 and all of ($Opcode*) )
}