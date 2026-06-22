package analyze

import (
	"encoding/binary"
	"fmt"
	"log"
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

func EtherNtoaR(hwaddr [6]byte) string {
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", hwaddr[0], hwaddr[1], hwaddr[2], hwaddr[3], hwaddr[4], hwaddr[5])
}

func ntohs(byte []byte) uint16 {
	return binary.BigEndian.Uint16(byte)
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

	fmt.Fprintf(fp, "ether_dhost=%s\n", EtherNtoaR(arp.arp_sha))
	// if size < unsafe.Sizeof(ether_arp) {
	// }
}

func AnalyzePacket(eh *EtherHeader, size int) {
	if size < 14 {
		log.Fatal("packet size < ether_header \n")
	}

	if eh.EtherType == syscall.ETH_P_ARP {
		log.Printf("Packet[%dbytes]\n", size)
	} else if eh.EtherType == syscall.ETH_P_IP {
		log.Printf("Packet[%dbytes]\n", size)
	} else if eh.EtherType == syscall.ETH_P_IPV6 {
		log.Printf("Packet[%dbytes]\n", size)
	}
}
