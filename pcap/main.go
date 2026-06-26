package main

import (
	"encoding/binary"
	"log"
	"net"
	"os"
	"syscall"
)

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

func main() {
	var arg string
	if len(os.Args) > 1 {
		arg = os.Args[1]
	} else {
		log.Fatal("invalid device name")
	}

	fd := InitRawSocket(arg)
	defer syscall.Close(fd)

	for {
		buf := make([]byte, 100)
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

		AnalyzePacket(&eh, os.Stdout, buf, size)
	}
}
