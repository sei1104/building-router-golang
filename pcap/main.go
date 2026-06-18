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
		syscall.Close(fd)
		log.Fatal(err)
	}

	return fd
}

func myEtherNtoaR(hwaddr [6]byte) string {
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", hwaddr[0], hwaddr[1], hwaddr[2], hwaddr[3], hwaddr[4], hwaddr[5])
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

		var eh EtherHeader
		copy(eh.DstMAC[:], buf[0:6])
		copy(eh.SrcMAC[:], buf[6:12])
		eh.EtherType = binary.BigEndian.Uint16(buf[12:14])

		// PrintEtherHeader(&eh, os.Stdout)
		fmt.Fprintf(os.Stdout, "%s\n", fmt.Sprintf("%02x---%02x", buf[0:6], buf[6:12]))
	}
}
