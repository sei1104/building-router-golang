package main

import (
	"fmt"
	"log"
	"os"
	"syscall"
)

func myEtherNtoaR(hwaddr [6]byte) string {
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", hwaddr[0], hwaddr[1], hwaddr[2], hwaddr[3], hwaddr[4], hwaddr[5])
}

func arpIP2str(buf [4]byte) string {
	// return binary.BigEndian.String(buf)
	return fmt.Sprintf("%d.%d.%d.%d", buf[0], buf[1], buf[2], buf[3])
}

func htons(host uint16) int {
	return int((host<<8)&0xff00 | (host>>8)&0x00ff)
}

func AnalyzeArp(data []byte, fp *os.File) int {
	var arp EtherArp

	copy(arp.sha[:], data[0:6])
	copy(arp.spa[:], data[6:10])
	copy(arp.tha[:], data[10:16])
	copy(arp.tpa[:], data[16:20])

	PrintArp(arp, fp)

	return 0
}

func AnalyzePacket(eh *EtherHeader, fp *os.File, buf []byte, size int) {
	if size < 14 {
		log.Fatal("packet size < ether_header \n")
	}

	if eh.EtherType == syscall.ETH_P_ARP {
		log.Printf("Packet[%dbytes]\n", size)
		AnalyzeArp(buf, fp)
	} else if eh.EtherType == syscall.ETH_P_IP {
		log.Printf("Packet[%dbytes]\n", size)
	} else if eh.EtherType == syscall.ETH_P_IPV6 {
		log.Printf("Packet[%dbytes]\n", size)
	}
}
