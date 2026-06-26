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
	fmt.Fprintf(fp, "------ARP------\n")
	fmt.Fprintf(fp, "Sender HWADDR=%s\n", myEtherNtoaR(arp.sha))
	fmt.Fprintf(fp, "Sender IPADDR=%s\n", arpIP2str(arp.spa))
	fmt.Fprintf(fp, "Target HWADDR=%s\n", myEtherNtoaR(arp.tha))
	fmt.Fprintf(fp, "Target IPADDR=%s\n", arpIP2str(arp.tpa))
}

func PrintIPHeader(iph IPHeader, fp *os.File) {
	fmt.Fprintf(fp, "------IPHeader------\n")
	fmt.Fprintf(fp, "version=%d,ihl=%d,tos=%d,totLen=%d\n", iph.version, iph.ihl, iph.tos, iph.totLen)
	fmt.Fprintf(fp, "id=%d,flags=%d,flagOff=%d,ttl=%d\n", iph.id, iph.flags, iph.flagOff, iph.ttl)
	fmt.Fprintf(fp, "proto=%d,checksum=%d\n", iph.protocol, iph.check)
	fmt.Fprintf(fp, "Sender IPADDR=%s\n", uint2IP(iph.saddr))
	fmt.Fprintf(fp, "Destination IPADDR=%s\n", uint2IP(iph.daddr))
}

func PrintEtherHeader(eh *EtherHeader, fp *os.File) int {
	fmt.Fprintf(fp, "------ether_header------\n")
	fmt.Fprintf(fp, "ether_dhost=%s\n", myEtherNtoaR(eh.DstMAC))
	fmt.Fprintf(fp, "ether_shost=%s\n", myEtherNtoaR(eh.SrcMAC))
	fmt.Fprintf(fp, "ether_type=%d\n", eh.EtherType)

	return 0
}
