package main

// EtherHeader no struct
type EtherHeader struct {
	DstMAC    [6]byte
	SrcMAC    [6]byte
	EtherType uint16
}

// ArpHdr no struct
type ArpHdr struct {
	hrd [2]byte
	pro [2]byte
	hln [1]byte
	pln [1]byte
	op  [2]byte
}

type IpHdr struct {
	ihl      []byte
	version  []byte
	tos      []byte
	tot_len  uint16
	id       uint16
	fragOff  uint16
	ttl      uint8
	protocol uint8
	check    uint16
	saddr    uint32
	daddr    uint32
}

// EtherArp no struct
type EtherArp struct {
	ehArpHdr ArpHdr
	sha      [6]byte
	spa      [4]byte
	tha      [6]byte
	tpa      [4]byte
}
