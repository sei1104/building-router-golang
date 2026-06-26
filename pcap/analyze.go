package main

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
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

func uint2IP(buf uint32) net.IP {
	ipBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(ipBytes, buf)

	return net.IP(ipBytes)
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

// func AnalyzeIcmp(data []byte, fp *os.File) int {
// }

func AnalyzeIP(data []byte, fp *os.File) int {
	iphdr := new(IPHeader)

	iphdr.version = (data[14] >> 4) & 0x0F
	iphdr.ihl = data[14] & 0x0F
	iphdr.tos = data[15]
	iphdr.totLen = binary.BigEndian.Uint16(data[16:18])
	iphdr.id = binary.BigEndian.Uint16(data[18:20])
	iphdr.flags = data[20] << 3
	iphdr.flagOff = binary.BigEndian.Uint16(data[20:22]) & 0x1FFF
	iphdr.ttl = data[22]
	iphdr.protocol = data[23]
	iphdr.check = binary.BigEndian.Uint16(data[24:26])
	iphdr.saddr = binary.BigEndian.Uint32(data[26:30])
	iphdr.daddr = binary.BigEndian.Uint32(data[30:34])

	PrintIPHeader(*iphdr, fp)

	return 0
}

func AnalyzePacket(eh *EtherHeader, fp *os.File, buf []byte, size int) {
	if size < 14 {
		log.Fatal("packet size < ether_header \n")
	}

	switch eh.EtherType {
	case syscall.ETH_P_ARP:
		log.Printf("ARP Packet[%dbytes]\n", size)
		AnalyzeArp(buf, fp)
	case syscall.ETH_P_IP:
		log.Printf("IP Packet[%dbytes]\n", size)
		AnalyzeIP(buf, fp)
	case syscall.ETH_P_IPV6:
		// log.Printf("IPv6 Packet[%dbytes]\n", size)
	}
}
