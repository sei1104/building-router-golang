package main

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"os"
	"syscall"
)

type EtherHeader struct {
	DstMAC    [6]byte
	SrcMAC    [6]byte
	EtherType uint16
}

type arphdr struct {
	ar_hrd uint16
	ar_pro uint16
	ar_hln uint8
	ar_pln uint8
	ar_op  uint16
}

type ether_arp struct {
	ea_hdr  arphdr
	arp_sha [6]byte
	arp_spa [4]byte
	arp_tha [6]byte
	arp_tpa [4]byte
}

func myEtherNtoaR(hwaddr [6]byte) string {
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", hwaddr[0], hwaddr[1], hwaddr[2], hwaddr[3], hwaddr[4], hwaddr[5])
}

func arp_ip2str(buf [4]byte) string {
	return fmt.Sprintf("%02x.%02x.%02x.%02x", buf[0], buf[1], buf[2], buf[3])
}

func ntohs(byte []byte) uint16 {
	return binary.BigEndian.Uint16(byte)
}

func htons(host uint16) int {
	return int((host<<8)&0xff00 | (host>>8)&0x00ff)
}

func InitRawSocket(device string) int {
	proto := htons(syscall.ETH_P_ALL)
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, proto)
	if err != nil {
		log.Fatal("Socket creation error: ", err)
	}
	iface, err := net.InterfaceByName(device)
	if err != nil {
		log.Fatal(err)
	}
	sa := syscall.SockaddrLinklayer{
		Protocol: uint16(proto),
		Ifindex:  iface.Index,
	}

	err = syscall.Bind(fd, &sa)
	if err != nil {
		log.Fatal(err)
	}

	return fd
}

func AnalyzeArp(data []byte, fp *os.File) {
	var arp ether_arp
	// arp.ea_hdr = arphdr{
	// 	1,
	// 	800,
	// 	6,
	// 	4,
	// 	1,
	// }
	copy(arp.arp_sha[:], data[0:6])
	copy(arp.arp_spa[:], data[6:10])
	copy(arp.arp_tha[:], data[10:16])
	copy(arp.arp_tpa[:], data[16:20])

	fmt.Fprintf(fp, "sha=%s\n", myEtherNtoaR(arp.arp_sha))
	fmt.Fprintf(fp, "spa=%s\n", arp_ip2str(arp.arp_spa))
	fmt.Fprintf(fp, "tha=%s\n", myEtherNtoaR(arp.arp_tha))
	fmt.Fprintf(fp, "tpa=%s\n", arp_ip2str(arp.arp_tpa))
	// if size < unsafe.Sizeof(ether_arp) {
	// }
}

func PrintEtherHeader(eh *EtherHeader, fp *os.File) int {
	fmt.Fprintf(fp, "------ether_header------\n")
	fmt.Fprintf(fp, "ether_dhost=%s\n", myEtherNtoaR(eh.DstMAC))
	fmt.Fprintf(fp, "ether_shost=%s\n", myEtherNtoaR(eh.SrcMAC))
	fmt.Fprintf(fp, "ether_type=%d\n", eh.EtherType)

	return 0
}

func main() {
	var arg string
	if len(os.Args) > 1 {
		arg = os.Args[1]
	} else {
		log.Fatal("invalid device name")
	}

	fd := InitRawSocket(arg)
	defer syscall.Close(fd)

	buf := make([]byte, 65536)

	for {
		size, err := syscall.Read(fd, buf)
		if err != nil {
			log.Fatal(err)
		}
		if size < 14 {
			continue
		}

		// var eh EtherHeader
		// copy(eh.DstMAC[:], buf[0:6])
		// copy(eh.SrcMAC[:], buf[6:12])
		// eh.EtherType = binary.BigEndian.Uint16(buf[12:14])

		AnalyzeArp(buf, os.Stdout)
		// PrintEtherHeader(&eh, os.Stdout)
		// fmt.Fprintf(os.Stdout, "%s\n", fmt.Sprintf("%02x---%02x", buf[0:6], buf[6:12]))
	}
}
