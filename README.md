# DumpFile455
File Decrypter for the PS4 version 4.55

change your ip address to use the pc you are listening ie:
 
   socat - tcp-listen:9023
 
 send the payload like:
    
    socat -u FILE:DumpFile455.bin TCP:<ps4 ip>:9020

To compile for 4.55 you need to use an sdk with changes for 4.55 support, i have used https://github.com/xvortex/ps4-payload-sdk

-on your usb stick (fat32) make a directory /455

-insert into the ps4 and run the payload

This will dump all the usermodules self/sprx/sdll/sexe onto your usb in the /455 folder decrypted
some like eboots are renamed because i was too lazy to implement folder generation to mimic the ps4 fs
but you can change to code to suit whatever you choose to :)

=Credits=

-qwertyuiop for his Kernel Exploit / Specter for his code execution method

-IDC for his his patches to allow for self decryption

-Grass Skeu for the original code base this was made from (DumpFile for 1.76 built for hitodamas ps4sdk)
