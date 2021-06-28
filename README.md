# Network-Traffic-Sniffing

The program "mydump" can be used to capture packets in promiscuous mode and also read packets from an existing pcap file. In addition I've also provided the ability to search for a string in the payload and also apply BPF filers.

# Usage:

To get more information about the usage following command can be entered in the terminal: 

go run mydump.go -help

This provides the output regarding usage information as follows:

  -i string
    	Pass the network device interface for live capture
  -r string
    	Pass the file path to read packets from
  -s string
    	Search for string in packet payload


Examples:

1. go run mydump.go -i en0 
2. go run mydump.go -r hw1.pcap
3. go run mydump.go -r hw1.pcap -s png
4. go run mydump.go -r hw1.pcap arp


# Disclaimer:


1. If both the flags -i and -r are provided input while running the command, the preference is given to -r command that is packets will be read from the pcap file.
2. If no flags are provided, packets are captured live from the first available network device interface.
3. BPF filter can also be applied. Example - go run mydump.go -r hw1.pcap tcp and port 80


# Implementation:


I have used the gopacket package in this assignment for capturing packets and reading pcap file along with the ability of BOF filtering. First the data from the flags is taken and if any valid BPF filter is given as input, the filter is applied. Then, if a search string is passed, the packet satisfying the search criteria in the payload is printed. Also, TCP, UDP and ICMP protocols are printed(if any). 


Following are the examples of commands run along with respective outputs:

1. go run mydump.go -i en0

2013-01-12 12:01:44.785526 44:6d:57:f6:7e:00 -> 01:00:5e:00:00:fc type 0x800 len 64 192.168.0.11:55974 
 -> 224.0.0.252:5355 UDP
00000000  45 00 00 32 4e 89 00 00  01 11 c9 82 c0 a8 00 0b  |E..2N...........|
00000010  e0 00 00 fc da a6 14 eb  00 1e d9 59 bc 3a 00 00  |...........Y.:..|
00000020  00 01 00 00 00 00 00 00  04 77 70 61 64 00 00 01  |.........wpad...|
00000030  00 01                                             |..|

2013-01-12 12:01:45.205934 44:6d:57:f6:7e:00 -> 01:00:5e:00:00:fc type 0x800 len 64 192.168.0.11:55974 
 -> 224.0.0.252:5355 UDP
00000000  45 00 00 32 4e 8a 00 00  01 11 c9 81 c0 a8 00 0b  |E..2N...........|
00000010  e0 00 00 fc da a6 14 eb  00 1e d9 59 bc 3a 00 00  |...........Y.:..|
00000020  00 01 00 00 00 00 00 00  04 77 70 61 64 00 00 01  |.........wpad...|
00000030  00 01                                             |..|

2. go run mydump.go -r hw1.pcap

2013-01-14 13:26:42.610532 c4:3d:c7:17:6f:9b -> 01:00:5e:7f:ff:fa type 0x800 len 405 192.168.0.1:1900 
 -> 239.255.255.250:1900 UDP
00000000  45 00 01 87 57 c3 00 00  01 11 af ff c0 a8 00 01  |E...W...........|
00000010  ef ff ff fa 07 6c 07 6c  01 73 1f 78 4e 4f 54 49  |.....l.l.s.xNOTI|
00000020  46 59 20 2a 20 48 54 54  50 2f 31 2e 31 0d 0a 48  |FY * HTTP/1.1..H|
00000030  6f 73 74 3a 20 32 33 39  2e 32 35 35 2e 32 35 35  |ost: 239.255.255|
00000040  2e 32 35 30 3a 31 39 30  30 0d 0a 43 61 63 68 65  |.250:1900..Cache|
00000050  2d 43 6f 6e 74 72 6f 6c  3a 20 6d 61 78 2d 61 67  |-Control: max-ag|
00000060  65 3d 36 30 0d 0a 4c 6f  63 61 74 69 6f 6e 3a 20  |e=60..Location: |
00000070  68 74 74 70 3a 2f 2f 31  39 32 2e 31 36 38 2e 30  |http://192.168.0|
00000080  2e 31 3a 31 39 30 30 2f  57 46 41 44 65 76 69 63  |.1:1900/WFADevic|
00000090  65 2e 78 6d 6c 0d 0a 4e  54 53 3a 20 73 73 64 70  |e.xml..NTS: ssdp|
000000a0  3a 61 6c 69 76 65 0d 0a  53 65 72 76 65 72 3a 20  |:alive..Server: |
000000b0  50 4f 53 49 58 2c 20 55  50 6e 50 2f 31 2e 30 20  |POSIX, UPnP/1.0 |
000000c0  42 72 6f 61 64 63 6f 6d  20 55 50 6e 50 20 53 74  |Broadcom UPnP St|
000000d0  61 63 6b 2f 65 73 74 69  6d 61 74 69 6f 6e 20 31  |ack/estimation 1|
000000e0  2e 30 30 0d 0a 4e 54 3a  20 75 72 6e 3a 73 63 68  |.00..NT: urn:sch|
000000f0  65 6d 61 73 2d 77 69 66  69 61 6c 6c 69 61 6e 63  |emas-wifiallianc|
00000100  65 2d 6f 72 67 3a 73 65  72 76 69 63 65 3a 57 46  |e-org:service:WF|
00000110  41 57 4c 41 4e 43 6f 6e  66 69 67 3a 31 0d 0a 55  |AWLANConfig:1..U|
00000120  53 4e 3a 20 75 75 69 64  3a 46 35 31 39 33 39 30  |SN: uuid:F519390|
00000130  41 2d 34 34 44 44 2d 32  39 35 38 2d 36 32 33 37  |A-44DD-2958-6237|
00000140  2d 45 41 33 37 42 39 38  37 43 33 46 44 3a 3a 75  |-EA37B987C3FD::u|
00000150  72 6e 3a 73 63 68 65 6d  61 73 2d 77 69 66 69 61  |rn:schemas-wifia|
00000160  6c 6c 69 61 6e 63 65 2d  6f 72 67 3a 73 65 72 76  |lliance-org:serv|
00000170  69 63 65 3a 57 46 41 57  4c 41 4e 43 6f 6e 66 69  |ice:WFAWLANConfi|
00000180  67 3a 31 0d 0a 0d 0a                              |g:1....|

2013-01-14 13:27:03.691498 c4:3d:c7:17:6f:9b -> ff:ff:ff:ff:ff:ff type 0x806 len 60 OTHER
00000000  00 01 08 00 06 04 00 01  c4 3d c7 17 6f 9b c0 a8  |.........=..o...|
00000010  00 01 00 00 00 00 00 00  c0 a8 00 0c 00 00 00 00  |................|
00000020  00 00 00 00 00 00 00 00  00 00 00 00 00 00        |..............|

3. go run mydump.go -r hw1.pcap -s png

2013-01-13 05:44:46.446757 00:0c:29:e9:94:8e -> c4:3d:c7:17:6f:9b type 0x800 len 344 192.168.0.200:43029  -> 216.137.63.137:80 TCP PSH ACK 
00000000  45 00 01 4a 24 af 40 00  40 06 3b 7c c0 a8 00 c8  |E..J$.@.@.;|....|
00000010  d8 89 3f 89 a8 15 00 50  0e 4f 1c bd 8d 50 2e 97  |..?....P.O...P..|
00000020  80 18 03 d4 cb 32 00 00  01 01 08 0a 01 02 40 00  |.....2........@.|
00000030  ba b5 44 8c 47 45 54 20  2f 66 61 76 69 63 6f 6e  |..D.GET /favicon|
00000040  2e 69 63 6f 20 48 54 54  50 2f 31 2e 31 0d 0a 48  |.ico HTTP/1.1..H|
00000050  6f 73 74 3a 20 65 63 78  2e 69 6d 61 67 65 73 2d  |ost: ecx.images-|
00000060  61 6d 61 7a 6f 6e 2e 63  6f 6d 0d 0a 55 73 65 72  |amazon.com..User|
00000070  2d 41 67 65 6e 74 3a 20  4d 6f 7a 69 6c 6c 61 2f  |-Agent: Mozilla/|
00000080  35 2e 30 20 28 58 31 31  3b 20 55 62 75 6e 74 75  |5.0 (X11; Ubuntu|
00000090  3b 20 4c 69 6e 75 78 20  69 36 38 36 3b 20 72 76  |; Linux i686; rv|
000000a0  3a 31 37 2e 30 29 20 47  65 63 6b 6f 2f 32 30 31  |:17.0) Gecko/201|
000000b0  30 30 31 30 31 20 46 69  72 65 66 6f 78 2f 31 37  |00101 Firefox/17|
000000c0  2e 30 0d 0a 41 63 63 65  70 74 3a 20 69 6d 61 67  |.0..Accept: imag|
000000d0  65 2f 70 6e 67 2c 69 6d  61 67 65 2f 2a 3b 71 3d  |e/png,image/*;q=|
000000e0  30 2e 38 2c 2a 2f 2a 3b  71 3d 30 2e 35 0d 0a 41  |0.8,*/*;q=0.5..A|
000000f0  63 63 65 70 74 2d 4c 61  6e 67 75 61 67 65 3a 20  |ccept-Language: |
00000100  65 6e 2d 55 53 2c 65 6e  3b 71 3d 30 2e 35 0d 0a  |en-US,en;q=0.5..|
00000110  41 63 63 65 70 74 2d 45  6e 63 6f 64 69 6e 67 3a  |Accept-Encoding:|
00000120  20 67 7a 69 70 2c 20 64  65 66 6c 61 74 65 0d 0a  | gzip, deflate..|
00000130  43 6f 6e 6e 65 63 74 69  6f 6e 3a 20 6b 65 65 70  |Connection: keep|
00000140  2d 61 6c 69 76 65 0d 0a  0d 0a                    |-alive....|

2013-01-13 05:45:26.248386 00:0c:29:e9:94:8e -> c4:3d:c7:17:6f:9b type 0x800 len 342 192.168.0.200:58724  -> 159.148.96.184:80 TCP PSH ACK 
00000000  45 00 01 48 56 95 40 00  40 06 21 5e c0 a8 00 c8  |E..HV.@.@.!^....|
00000010  9f 94 60 b8 e5 64 00 50  58 71 31 50 0b 5e aa 8f  |..`..d.PXq1P.^..|
00000020  80 18 03 d4 a0 fb 00 00  01 01 08 0a 01 02 66 df  |..............f.|
00000030  3c 93 9a 2c 47 45 54 20  2f 66 61 76 69 63 6f 6e  |<..,GET /favicon|
00000040  2e 69 63 6f 20 48 54 54  50 2f 31 2e 31 0d 0a 48  |.ico HTTP/1.1..H|
00000050  6f 73 74 3a 20 69 6d 61  67 65 73 34 2e 62 79 69  |ost: images4.byi|
00000060  6e 74 65 72 2e 6e 65 74  0d 0a 55 73 65 72 2d 41  |nter.net..User-A|
00000070  67 65 6e 74 3a 20 4d 6f  7a 69 6c 6c 61 2f 35 2e  |gent: Mozilla/5.|
00000080  30 20 28 58 31 31 3b 20  55 62 75 6e 74 75 3b 20  |0 (X11; Ubuntu; |
00000090  4c 69 6e 75 78 20 69 36  38 36 3b 20 72 76 3a 31  |Linux i686; rv:1|
000000a0  37 2e 30 29 20 47 65 63  6b 6f 2f 32 30 31 30 30  |7.0) Gecko/20100|
000000b0  31 30 31 20 46 69 72 65  66 6f 78 2f 31 37 2e 30  |101 Firefox/17.0|
000000c0  0d 0a 41 63 63 65 70 74  3a 20 69 6d 61 67 65 2f  |..Accept: image/|
000000d0  70 6e 67 2c 69 6d 61 67  65 2f 2a 3b 71 3d 30 2e  |png,image/*;q=0.|
000000e0  38 2c 2a 2f 2a 3b 71 3d  30 2e 35 0d 0a 41 63 63  |8,*/*;q=0.5..Acc|
000000f0  65 70 74 2d 4c 61 6e 67  75 61 67 65 3a 20 65 6e  |ept-Language: en|
00000100  2d 55 53 2c 65 6e 3b 71  3d 30 2e 35 0d 0a 41 63  |-US,en;q=0.5..Ac|
00000110  63 65 70 74 2d 45 6e 63  6f 64 69 6e 67 3a 20 67  |cept-Encoding: g|
00000120  7a 69 70 2c 20 64 65 66  6c 61 74 65 0d 0a 43 6f  |zip, deflate..Co|
00000130  6e 6e 65 63 74 69 6f 6e  3a 20 6b 65 65 70 2d 61  |nnection: keep-a|
00000140  6c 69 76 65 0d 0a 0d 0a                           |live....|

4. go run mydump.go -r hw1.pcap arp

2013-01-14 13:26:01.740598 c4:3d:c7:17:6f:9b -> ff:ff:ff:ff:ff:ff type 0x806 len 60 OTHER
00000000  00 01 08 00 06 04 00 01  c4 3d c7 17 6f 9b c0 a8  |.........=..o...|
00000010  00 01 00 00 00 00 00 00  c0 a8 00 0c 00 00 00 00  |................|
00000020  00 00 00 00 00 00 00 00  00 00 00 00 00 00        |..............|

2013-01-14 13:26:32.6649 c4:3d:c7:17:6f:9b -> ff:ff:ff:ff:ff:ff type 0x806 len 60 OTHER
00000000  00 01 08 00 06 04 00 01  c4 3d c7 17 6f 9b c0 a8  |.........=..o...|
00000010  00 01 00 00 00 00 00 00  c0 a8 00 0c 00 00 00 00  |................|
00000020  00 00 00 00 00 00 00 00  00 00 00 00 00 00        |..............|

2013-01-14 13:27:03.691498 c4:3d:c7:17:6f:9b -> ff:ff:ff:ff:ff:ff type 0x806 len 60 OTHER
00000000  00 01 08 00 06 04 00 01  c4 3d c7 17 6f 9b c0 a8  |.........=..o...|
00000010  00 01 00 00 00 00 00 00  c0 a8 00 0c 00 00 00 00  |................|
00000020  00 00 00 00 00 00 00 00  00 00 00 00 00 00        |..............|