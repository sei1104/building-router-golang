package main

type InAddr struct {
	inAddr [1]byte
}

type IhAddr struct {
	icd_id  uint16
	icd_seq uint16
}

type IhPmtu struct {
	ipm_void    uint16
	ipm_nextmtu uint16
}

type IhRtradv struct{}

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

type IPHeader struct {
	version  uint8
	ihl      uint8
	tos      uint8
	totLen   uint16
	id       uint16
	flags    uint8
	flagOff  uint16
	ttl      uint8
	protocol uint8
	check    uint16
	saddr    uint32
	daddr    uint32
}

type Icmp struct {
	icmp_type  uint8
	icmp_code  uint8
	icmp_cksum uint16
	ih_pptr    [1]byte
	ih_gwaddr  InAddr
	ih_idseq   IhAddr
	ih_void    uint32
	ih_pmtu    IhPmtu
	ih_rtradv  IhRtradv
}

// EtherArp no struct
type EtherArp struct {
	ehArpHdr ArpHdr
	sha      [6]byte
	spa      [4]byte
	tha      [6]byte
	tpa      [4]byte
}
