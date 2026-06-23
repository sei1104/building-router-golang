package main

// EtherHeader no struct
type EtherHeader struct {
	DstMAC    [6]byte
	SrcMAC    [6]byte
	EtherType uint16
}

// ArpHdr no struct
type ArpHdr struct {
	hrd uint16
	pro uint16
	hln uint8
	pln uint8
	op  uint16
}

// EtherArp no struct
type EtherArp struct {
	etherArpHdr ArpHdr
	sha         [6]byte
	spa         [4]byte
	tha         [6]byte
	tpa         [4]byte
}
