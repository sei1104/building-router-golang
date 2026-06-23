package main

import (
	"fmt"
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

	copy(arp.ehArpHdr.hln[:], data[14:16])
	copy(arp.ehArpHdr.pro[:], data[16:18])
	copy(arp.ehArpHdr.hln[:], data[18:19])
	copy(arp.ehArpHdr.pln[:], data[19:20])
	copy(arp.ehArpHdr.op[:], data[20:22])

	copy(arp.sha[:], data[22:28])
	copy(arp.spa[:], data[28:32])
	copy(arp.tha[:], data[32:38])
	copy(arp.tpa[:], data[38:42])

	PrintArp(arp, fp)

	return 0
}

// todo
// checksum
// AnalyzeICMP
// AnalyzeTCP
// AnalyzeUDP

func AnalyzeIp(data []byte, fp *os.File) int {
	// var iphdr *IpHdr

	// copy(iphdr., src []Type)

	return 0
}

func AnalyzePacket(eh *EtherHeader, fp *os.File, buf []byte, size int) {
	// if size < 14 {
	// 	log.Fatal("packet size < ether_header \n")
	// }

	switch eh.EtherType {
	case syscall.ETH_P_ARP:
		// log.Printf("ARP Packet[%dbytes]\n", size)
		AnalyzeArp(buf, fp)
	case syscall.ETH_P_IP:
		// log.Printf("IP Packet[%dbytes]\n", size)
	case syscall.ETH_P_IPV6:
		// log.Printf("IPv6 Packet[%dbytes]\n", size)
	}
}
