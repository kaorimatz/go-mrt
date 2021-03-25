package mrt

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"time"
)

type AS []byte

func (as AS) String() string {
	if len(as) == 2 {
		return strconv.FormatUint(uint64(binary.BigEndian.Uint16(as)), 10)
	} else if len(as) == 4 {
		return strconv.FormatUint(uint64(binary.BigEndian.Uint32(as)), 10)
	} else {
		return string(as)
	}
}

func (as AS) MarshalText() ([]byte, error) {
	if len(as) == 0 {
		return []byte(""), nil
	}
	if len(as) != 2 && len(as) != 4 {
		return nil, errors.New("invalid AS number")
	}
	return []byte(as.String()), nil
}

type decoder struct {
	buf []byte
}

func (d *decoder) uint8() uint8 {
	x := d.buf[0]
	d.buf = d.buf[1:]
	return x
}

func (d *decoder) uint16() uint16 {
	x := binary.BigEndian.Uint16(d.buf)
	d.buf = d.buf[2:]
	return x
}

func (d *decoder) uint32() uint32 {
	x := binary.BigEndian.Uint32(d.buf)
	d.buf = d.buf[4:]
	return x
}

func (d *decoder) uint64() uint64 {
	x := binary.BigEndian.Uint64(d.buf)
	d.buf = d.buf[8:]
	return x
}

func (d *decoder) string(n int) string {
	x := string(d.buf[:n])
	d.buf = d.buf[n:]
	return x
}

func (d *decoder) bytes(n int) []byte {
	x := make([]byte, n)
	d.copy(x)
	return x
}

func (d *decoder) ipv4() net.IP {
	x := make(net.IP, net.IPv4len)
	d.copy(x)
	return x
}

func (d *decoder) ipv4N(n int) net.IP {
	x := make(net.IP, net.IPv4len)
	d.copyN(x, n)
	return x
}

func (d *decoder) ipv6() net.IP {
	x := make(net.IP, net.IPv6len)
	d.copy(x)
	return x
}

func (d *decoder) ipv6N(n int) net.IP {
	x := make(net.IP, net.IPv6len)
	d.copyN(x, n)
	return x
}

func (d *decoder) as2() AS {
	x := make(AS, 2)
	d.copy(x)
	return x
}

func (d *decoder) as4() AS {
	x := make(AS, 4)
	d.copy(x)
	return x
}

func (d *decoder) nlriIPv4() *net.IPNet {
	l := int(d.uint8())
	ip := d.ipv4N((l + 7) >> 3)
	mask := net.CIDRMask(l, net.IPv4len<<3)
	return &net.IPNet{ip, mask}
}

func (d *decoder) nlriIPv6() *net.IPNet {
	l := int(d.uint8())
	ip := d.ipv6N((l + 7) >> 3)
	mask := net.CIDRMask(l, net.IPv6len<<3)
	return &net.IPNet{ip, mask}
}

func (d *decoder) unixTime() time.Time {
	return time.Unix(int64(d.uint32()), 0).UTC()
}

func (d *decoder) skip(n int) []byte {
	x := d.buf[:n]
	d.buf = d.buf[n:]
	return x
}

func (d *decoder) copy(b []byte) {
	copy(b, d.buf)
	d.buf = d.buf[len(b):]
}

func (d *decoder) copyN(b []byte, n int) {
	copy(b, d.buf[:n])
	d.buf = d.buf[n:]
}

func (d *decoder) size() int {
	return len(d.buf)
}

type RecordType uint16

const (
	TYPE_OSPFv2        RecordType = 11
	TYPE_TABLE_DUMP               = 12
	TYPE_TABLE_DUMP_V2            = 13
	TYPE_BGP4MP                   = 16
	TYPE_BGP4MP_ET                = 17
	TYPE_ISIS                     = 32
	TYPE_ISIS_ET                  = 33
	TYPE_OSPFv3                   = 48
	TYPE_OSPFv3_ET                = 49
)

func (t RecordType) HasExtendedTimestamp() bool {
	return t == TYPE_BGP4MP_ET || t == TYPE_ISIS_ET || t == TYPE_OSPFv3_ET
}

type header struct {
	timestamp time.Time
	type_     RecordType
	subtype   uint16
}

func (h *header) Timestamp() time.Time {
	return h.timestamp
}

func (h *header) Type() RecordType {
	return h.type_
}

func (h *header) Subtype() uint16 {
	return h.subtype
}

func (h *header) decodeHeader(d *decoder) error {
	h.timestamp = d.unixTime()
	h.type_ = RecordType(d.uint16())
	h.subtype = d.uint16()
	d.skip(4) // Length (4 octets)
	if h.type_.HasExtendedTimestamp() {
		h.timestamp.Add(time.Duration(d.uint32()) * time.Microsecond)
	}
	return nil
}

type OSPFv2 struct {
	header
	RemoteIPAddress     net.IP
	LocalIPAddress      net.IP
	OSPFMessageContents []byte
}

func (r *OSPFv2) DecodeBytes(data []byte) error {
	d := &decoder{data}
	r.decodeHeader(d)
	r.RemoteIPAddress = d.ipv4()
	r.LocalIPAddress = d.ipv4()
	r.OSPFMessageContents = d.bytes(d.size())
	return nil
}

const (
	TABLE_DUMP_SUBTYPE_AFI_IPv4 = 1
	TABLE_DUMP_SUBTYPE_AFI_IPv6 = 2
)

type TableDump struct {
	header
	ViewNumber     uint16
	SequenceNumber uint16
	Prefix         *net.IPNet
	OriginatedTime time.Time
	PeerIPAddress  net.IP
	PeerAS         AS
	BGPAttributes  []*BGPPathAttribute
}

func (r *TableDump) DecodeBytes(data []byte) error {
	d := &decoder{data}
	r.decodeHeader(d)
	r.ViewNumber = d.uint16()
	r.SequenceNumber = d.uint16()

	if r.subtype == TABLE_DUMP_SUBTYPE_AFI_IPv4 {
		ip := d.ipv4()
		mask := net.CIDRMask(int(d.uint8()), net.IPv4len*8)
		r.Prefix = &net.IPNet{IP: ip, Mask: mask}
	} else {
		ip := d.ipv6()
		mask := net.CIDRMask(int(d.uint8()), net.IPv6len*8)
		r.Prefix = &net.IPNet{IP: ip, Mask: mask}
	}

	d.skip(1) // Status (1 octet)
	r.OriginatedTime = d.unixTime()
	if r.subtype == TABLE_DUMP_SUBTYPE_AFI_IPv4 {
		r.PeerIPAddress = d.ipv4()
	} else {
		r.PeerIPAddress = d.ipv6()
	}
	r.PeerAS = d.as2()

	attrBytes := d.skip(d.size())
	reader := bgpPathAttributeReader{reader: bytes.NewReader(attrBytes), as4: false}
	for {
		attr, err := reader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		r.BGPAttributes = append(r.BGPAttributes, attr)
	}

	return nil
}

const (
	TABLE_DUMP_V2_SUBTYPE_PEER_INDEX_TABLE   = 1
	TABLE_DUMP_V2_SUBTYPE_RIB_IPv4_UNICAST   = 2
	TABLE_DUMP_V2_SUBTYPE_RIB_IPv4_MULTICAST = 3
	TABLE_DUMP_V2_SUBTYPE_RIB_IPv6_UNICAST   = 4
	TABLE_DUMP_V2_SUBTYPE_RIB_IPv6_MULTICAST = 5
	TABLE_DUMP_V2_SUBTYPE_RIB_GENERIC        = 6
)

type TableDumpV2PeerIndexTable struct {
	header
	CollectorBGPID net.IP
	ViewName       string
	PeerEntries    []*TableDumpV2PeerEntry
}

func (r *TableDumpV2PeerIndexTable) DecodeBytes(data []byte) error {
	d := &decoder{data}
	r.decodeHeader(d)
	r.CollectorBGPID = d.ipv4()
	r.ViewName = d.string(int(d.uint16()))

	n := int(d.uint16())
	r.PeerEntries = make([]*TableDumpV2PeerEntry, n)
	for i := 0; i < n; i++ {
		entry := &TableDumpV2PeerEntry{}
		entry.PeerType = d.uint8()
		entry.PeerBGPID = d.ipv4()
		if entry.PeerType&0x1 == 0 {
			entry.PeerIPAddress = d.ipv4()
		} else {
			entry.PeerIPAddress = d.ipv6()
		}
		if entry.PeerType&0x2 == 0 {
			entry.PeerAS = d.as2()
		} else {
			entry.PeerAS = d.as4()
		}
		r.PeerEntries[i] = entry
	}

	return nil
}

type TableDumpV2PeerEntry struct {
	PeerType      uint8
	PeerBGPID     net.IP
	PeerIPAddress net.IP
	PeerAS        AS
}

type TableDumpV2RIB struct {
	header
	SequenceNumber uint32
	Prefix         *net.IPNet
	RIBEntries     []*TableDumpV2RIBEntry
}

func (r *TableDumpV2RIB) DecodeBytes(data []byte) error {
	d := &decoder{data}
	r.decodeHeader(d)
	r.SequenceNumber = d.uint32()

	if r.subtype == TABLE_DUMP_V2_SUBTYPE_RIB_IPv4_UNICAST ||
		r.subtype == TABLE_DUMP_V2_SUBTYPE_RIB_IPv4_MULTICAST {
		r.Prefix = d.nlriIPv4()
	} else {
		r.Prefix = d.nlriIPv6()
	}

	n := int(d.uint16())
	r.RIBEntries = make([]*TableDumpV2RIBEntry, n)
	for i := 0; i < n; i++ {
		entry := &TableDumpV2RIBEntry{}
		entry.PeerIndex = d.uint16()
		entry.OriginatedTime = d.unixTime()

		attrBytes := d.skip(int(d.uint16()))
		reader := bgpPathAttributeReader{reader: bytes.NewReader(attrBytes), as4: true}
		for {
			attr, err := reader.Next()
			if err == io.EOF {
				break
			}
			if err != nil {
				return err
			}
			entry.BGPAttributes = append(entry.BGPAttributes, attr)
		}

		r.RIBEntries[i] = entry
	}

	return nil
}

type AFI uint16

const (
	AFIIPv4 AFI = 1
	AFIIPv6     = 2
)

type SAFI uint8

const (
	SAFIUnicast   SAFI = 1
	SAFIMulticast      = 2
)

type TableDumpV2RIBGeneric struct {
	header
	SequenceNumber uint32
	AFI            AFI
	SAFI           SAFI
	NLRI           []byte
	RIBEntries     []*TableDumpV2RIBEntry
}

func (r *TableDumpV2RIBGeneric) DecodeBytes(data []byte) error {
	d := &decoder{data}
	r.decodeHeader(d)
	r.SequenceNumber = d.uint32()
	r.AFI = AFI(d.uint16())
	r.SAFI = SAFI(d.uint8())
	// r.NLRI
	// r.RIBEntries
	return nil
}

type TableDumpV2RIBEntry struct {
	PeerIndex      uint16
	OriginatedTime time.Time
	BGPAttributes  []*BGPPathAttribute
}

const (
	BGP4MP_SUBTYPE_BGP4MP_STATE_CHANGE      = 0
	BGP4MP_SUBTYPE_BGP4MP_MESSAGE           = 1
	BGP4MP_SUBTYPE_BGP4MP_MESSAGE_AS4       = 4
	BGP4MP_SUBTYPE_BGP4MP_STATE_CHANGE_AS4  = 5
	BGP4MP_SUBTYPE_BGP4MP_MESSAGE_LOCAL     = 6
	BGP4MP_SUBTYPE_BGP4MP_MESSAGE_AS4_LOCAL = 7
)

type BGP4MPStateChange struct {
	header
	PeerAS         AS
	LocalAS        AS
	InterfaceIndex uint16
	AFI            AFI
	PeerIPAddress  net.IP
	LocalIPAddress net.IP
	OldState       uint16
	NewState       uint16
}

func (r *BGP4MPStateChange) DecodeBytes(data []byte) error {
	d := &decoder{data}
	r.decodeHeader(d)

	if r.subtype == BGP4MP_SUBTYPE_BGP4MP_STATE_CHANGE {
		r.PeerAS = d.as2()
		r.LocalAS = d.as2()
	} else {
		r.PeerAS = d.as4()
		r.LocalAS = d.as4()
	}

	r.InterfaceIndex = d.uint16()
	r.AFI = AFI(d.uint16())

	if r.AFI == AFIIPv4 {
		r.PeerIPAddress = d.ipv4()
		r.LocalIPAddress = d.ipv4()
	} else {
		r.PeerIPAddress = d.ipv6()
		r.LocalIPAddress = d.ipv6()
	}

	r.OldState = d.uint16()
	r.NewState = d.uint16()

	return nil
}

type BGP4MPMessage struct {
	header
	PeerAS         AS
	LocalAS        AS
	InterfaceIndex uint16
	AFI            AFI
	PeerIPAddress  net.IP
	LocalIPAddress net.IP
	BGPMessage     *BGPMessage
}

func (r *BGP4MPMessage) DecodeBytes(data []byte) error {
	d := &decoder{data}
	r.decodeHeader(d)

	as4 := r.subtype == BGP4MP_SUBTYPE_BGP4MP_MESSAGE_AS4 ||
		r.subtype == BGP4MP_SUBTYPE_BGP4MP_MESSAGE_AS4_LOCAL
	if as4 {
		r.PeerAS = d.as4()
		r.LocalAS = d.as4()
	} else {
		r.PeerAS = d.as2()
		r.LocalAS = d.as2()
	}

	r.InterfaceIndex = d.uint16()
	r.AFI = AFI(d.uint16())

	if r.AFI == AFIIPv4 {
		r.PeerIPAddress = d.ipv4()
		r.LocalIPAddress = d.ipv4()
	} else {
		r.PeerIPAddress = d.ipv6()
		r.LocalIPAddress = d.ipv6()
	}

	var err error
	r.BGPMessage, err = decodeBGPMessage(d.skip(d.size()), as4, r.AFI)

	return err
}

type ISIS struct {
	header
	ISISPDU []byte
}

func (r *ISIS) DecodeBytes(data []byte) error {
	d := &decoder{data}
	r.decodeHeader(d)
	r.ISISPDU = d.bytes(d.size())
	return nil
}

type OSPFv3 struct {
	header
	AFI                 AFI
	RemoteIPAddress     net.IP
	LocalIPAddress      net.IP
	OSPFMessageContents []byte
}

func (r *OSPFv3) DecodeBytes(data []byte) error {
	d := &decoder{data}
	r.decodeHeader(d)
	r.AFI = AFI(d.uint16())
	r.LocalIPAddress = d.ipv4()
	r.RemoteIPAddress = d.ipv4()
	r.OSPFMessageContents = d.bytes(d.size())
	return nil
}

type Record interface {
	Timestamp() time.Time
	Type() RecordType
	Subtype() uint16
	DecodeBytes([]byte) error
}

type Reader struct {
	reader io.Reader
}

func NewReader(r io.Reader) *Reader {
	return &Reader{
		reader: r,
	}
}

func (r *Reader) Next() (Record, error) {
	hdrBytes := make([]byte, 12)
	if _, err := io.ReadFull(r.reader, hdrBytes); err != nil {
		return nil, err
	}

	hdrType := RecordType(binary.BigEndian.Uint16(hdrBytes[4:]))
	hdrSubtype := binary.BigEndian.Uint16(hdrBytes[6:])
	hdrLength := binary.BigEndian.Uint32(hdrBytes[8:])

	var record Record
	switch hdrType {
	case TYPE_OSPFv2:
		record = new(OSPFv2)
	case TYPE_TABLE_DUMP:
		switch hdrSubtype {
		case TABLE_DUMP_SUBTYPE_AFI_IPv4, TABLE_DUMP_SUBTYPE_AFI_IPv6:
			record = new(TableDump)
		default:
			return nil, fmt.Errorf("unknown MRT record subtype: %d", hdrSubtype)
		}
	case TYPE_TABLE_DUMP_V2:
		switch hdrSubtype {
		case TABLE_DUMP_V2_SUBTYPE_PEER_INDEX_TABLE:
			record = new(TableDumpV2PeerIndexTable)
		case TABLE_DUMP_V2_SUBTYPE_RIB_IPv4_UNICAST,
			TABLE_DUMP_V2_SUBTYPE_RIB_IPv4_MULTICAST,
			TABLE_DUMP_V2_SUBTYPE_RIB_IPv6_UNICAST,
			TABLE_DUMP_V2_SUBTYPE_RIB_IPv6_MULTICAST:
			record = new(TableDumpV2RIB)
		case TABLE_DUMP_V2_SUBTYPE_RIB_GENERIC:
			record = new(TableDumpV2RIBGeneric)
		default:
			return nil, fmt.Errorf("unknown MRT record subtype: %d", hdrSubtype)
		}
	case TYPE_BGP4MP, TYPE_BGP4MP_ET:
		switch hdrSubtype {
		case BGP4MP_SUBTYPE_BGP4MP_STATE_CHANGE, BGP4MP_SUBTYPE_BGP4MP_STATE_CHANGE_AS4:
			record = new(BGP4MPStateChange)
		case BGP4MP_SUBTYPE_BGP4MP_MESSAGE,
			BGP4MP_SUBTYPE_BGP4MP_MESSAGE_AS4,
			BGP4MP_SUBTYPE_BGP4MP_MESSAGE_LOCAL,
			BGP4MP_SUBTYPE_BGP4MP_MESSAGE_AS4_LOCAL:
			record = new(BGP4MPMessage)
		default:
			return nil, fmt.Errorf("unknown MRT record subtype: %d", hdrSubtype)
		}
	case TYPE_ISIS, TYPE_ISIS_ET:
		record = new(ISIS)
	case TYPE_OSPFv3, TYPE_OSPFv3_ET:
		record = new(OSPFv3)
	default:
		return nil, fmt.Errorf("unknown MRT record type: %d", hdrType)
	}

	data := make([]byte, len(hdrBytes)+int(hdrLength))
	copy(data, hdrBytes)
	if _, err := io.ReadFull(r.reader, data[len(hdrBytes):]); err != nil {
		return nil, err
	}

	if err := record.DecodeBytes(data); err != nil {
		return nil, err
	}

	return record, nil
}
