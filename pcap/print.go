package main

import (
	"encoding/binary"
	"fmt"
	"os"
)

func EtherNtoaR(hwaddr [6]byte) string {
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", hwaddr[0], hwaddr[1], hwaddr[2], hwaddr[3], hwaddr[4], hwaddr[5])
}

func Ntohs(byte []byte) uint16 {
	return binary.BigEndian.Uint16(byte)
}

func PrintArp(arp EtherArp, fp *os.File) {
	fmt.Fprintf(fp, "sha=%s\n", myEtherNtoaR(arp.sha))
	fmt.Fprintf(fp, "spa=%s\n", arpIP2str(arp.spa))
	fmt.Fprintf(fp, "tha=%s\n", myEtherNtoaR(arp.tha))
	fmt.Fprintf(fp, "tpa=%s\n", arpIP2str(arp.tpa))
}

func PrintEtherHeader(eh *EtherHeader, fp *os.File) int {
	fmt.Fprintf(fp, "------ether_header------\n")
	fmt.Fprintf(fp, "ether_dhost=%s\n", myEtherNtoaR(eh.DstMAC))
	fmt.Fprintf(fp, "ether_shost=%s\n", myEtherNtoaR(eh.SrcMAC))
	fmt.Fprintf(fp, "ether_type=%d\n", eh.EtherType)

	return 0
}
