package mrt

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"
)

type BGPPathAttributeOrigin uint8

const (
	BGPPathAttributeOriginIGP BGPPathAttributeOrigin = iota
	BGPPathAttributeOriginEGP
	BGPPathAttributeOriginIncomplete
)

type BGPPathAttributeASPath []*BGPASPathSegment

type BGPASPathSegment struct {
	Type  BGPASPathSegmentType
	Value []AS
}

type BGPASPathSegmentType uint8

const (
	BGPASPathSegmentTypeASSet BGPASPathSegmentType = iota + 1
	BGPASPathSegmentTypeASSequence
)

func decodeASPathAttr(data []byte, as4 bool) (BGPPathAttributeASPath, error) {
	d := &decoder{data}

	var attr BGPPathAttributeASPath

	for d.size() != 0 {
		segment := &BGPASPathSegment{}
		segment.Type = BGPASPathSegmentType(d.uint8())

		n := int(d.uint8())
		segment.Value = make([]AS, n)
		for i := 0; i < n; i++ {
			if as4 {
				segment.Value[i] = AS(d.as4())
			} else {
				segment.Value[i] = AS(d.as2())
			}
		}

		attr = append(attr, segment)
	}

	return attr, nil
}

type BGPPathAttributeAggregator struct {
	AS        AS
	IPAddress net.IP
}

func decodeAggregatorAttr(data []byte, as4 bool) (*BGPPathAttributeAggregator, error) {
	d := &decoder{data}
	attr := &BGPPathAttributeAggregator{}
	if as4 {
		attr.AS = d.as4()
	} else {
		attr.AS = d.as2()
	}
	attr.IPAddress = d.ipv4()
	return attr, nil
}

type BGPPathAttributeCommunities []BGPCommunity

type BGPCommunity uint32

func decodeCommunitiesAttr(data []byte) (BGPPathAttributeCommunities, error) {
	d := &decoder{data}
	n := d.size() / 4
	attr := make(BGPPathAttributeCommunities, n)
	for i := 0; i < n; i++ {
		attr[i] = BGPCommunity(d.uint32())
	}
	return attr, nil
}

type BGPPathAttributeClusterList []BGPClusterID

type BGPClusterID net.IP

func decodeClusterListAttr(data []byte) (BGPPathAttributeClusterList, error) {
	d := &decoder{data}
	n := d.size() / net.IPv4len
	attr := make(BGPPathAttributeClusterList, n)
	for i := 0; i < n; i++ {
		attr[i] = BGPClusterID(d.ipv4())
	}
	return attr, nil
}

type BGPPathAttributeMPReachNLRI struct {
	AFI     AFI
	SAFI    SAFI
	NextHop net.IP
	NLRI    []*net.IPNet
}

func decodeMPReachNLRIAttr(data []byte) (*BGPPathAttributeMPReachNLRI, error) {
	d := &decoder{data}

	attr := &BGPPathAttributeMPReachNLRI{}
	attr.AFI = AFI(d.uint16())
	attr.SAFI = SAFI(d.uint8())

	n := int(d.uint8())
	if attr.AFI == AFIIPv4 {
		attr.NextHop = d.ipv4N(n)
		d.skip(1) // Reserved (1 octet)
		for d.size() != 0 {
			attr.NLRI = append(attr.NLRI, d.nlriIPv4())
		}
	} else if attr.AFI == AFIIPv6 {
		attr.NextHop = d.ipv6N(n)
		d.skip(1) // Reserved (1 octet)
		for d.size() != 0 {
			attr.NLRI = append(attr.NLRI, d.nlriIPv6())
		}
	} else {
		return nil, fmt.Errorf("unknown AFI: %d", attr.AFI)
	}

	return attr, nil
}

type BGPPathAttributeMPUnreachNLRI struct {
	AFI             AFI
	SAFI            SAFI
	WithdrawnRoutes []*net.IPNet
}

func decodeMPUnreachNLRIAttr(data []byte) (*BGPPathAttributeMPUnreachNLRI, error) {
	d := &decoder{data}

	attr := &BGPPathAttributeMPUnreachNLRI{}
	attr.AFI = AFI(d.uint16())
	attr.SAFI = SAFI(d.uint8())

	for d.size() != 0 {
		if attr.AFI == AFIIPv4 {
			attr.WithdrawnRoutes = append(attr.WithdrawnRoutes, d.nlriIPv4())
		} else if attr.AFI == AFIIPv6 {
			attr.WithdrawnRoutes = append(attr.WithdrawnRoutes, d.nlriIPv6())
		} else {
			return nil, fmt.Errorf("unknown AFI: %d", attr.AFI)
		}
	}

	return attr, nil
}

type BGPPathAttributeExtendedCommunities []BGPExtendedCommunity

type BGPExtendedCommunity [8]byte

func decodeExtendedCommunitiesAttr(data []byte) (BGPPathAttributeExtendedCommunities, error) {
	d := &decoder{data}
	n := d.size() / 8
	attr := make(BGPPathAttributeExtendedCommunities, n)
	for i := 0; i < n; i++ {
		d.copy(attr[i][:])
	}
	return attr, nil
}

type BGPPathAttribute struct {
	Flag     uint8
	TypeCode uint8
	Value    interface{}
}

type bgpPathAttributeReader struct {
	reader io.Reader
	as4    bool
}

func (r *bgpPathAttributeReader) Next() (*BGPPathAttribute, error) {
	attrTypeBytes := make([]byte, 2)
	if _, err := io.ReadFull(r.reader, attrTypeBytes); err != nil {
		return nil, err
	}

	attr := &BGPPathAttribute{}
	attr.Flag = attrTypeBytes[0]
	attr.TypeCode = attrTypeBytes[1]

	attrLenSize := 1
	if attr.Flag&0x10 != 0 {
		attrLenSize = 2
	}

	attrLenBytes := make([]byte, attrLenSize)
	if _, err := io.ReadFull(r.reader, attrLenBytes); err != nil {
		return nil, err
	}

	attrLen := int(attrLenBytes[0])
	if attrLenSize == 2 {
		attrLen = int(binary.BigEndian.Uint16(attrLenBytes))
	}

	valueBytes := make([]byte, attrLen)
	if _, err := io.ReadFull(r.reader, valueBytes); err != nil {
		return nil, err
	}

	var err error
	switch attr.TypeCode {
	case 1:
		attr.Value = BGPPathAttributeOrigin(valueBytes[0])
	case 2:
		attr.Value, err = decodeASPathAttr(valueBytes, r.as4)
	case 3:
		attr.Value = net.IP(valueBytes)
	case 4:
		attr.Value = binary.BigEndian.Uint32(valueBytes)
	case 5:
		attr.Value = binary.BigEndian.Uint32(valueBytes)
	case 6:
		// zero-length attribute
	case 7:
		attr.Value, err = decodeAggregatorAttr(valueBytes, r.as4)
	case 8:
		attr.Value, err = decodeCommunitiesAttr(valueBytes)
	case 9:
		attr.Value = net.IP(valueBytes)
	case 10:
		attr.Value, err = decodeClusterListAttr(valueBytes)
	case 14:
		attr.Value, err = decodeMPReachNLRIAttr(valueBytes)
	case 15:
		attr.Value, err = decodeMPUnreachNLRIAttr(valueBytes)
	case 16:
		attr.Value, err = decodeExtendedCommunitiesAttr(valueBytes)
	case 17:
		attr.Value, err = decodeASPathAttr(valueBytes, true)
	case 18:
		attr.Value, err = decodeAggregatorAttr(valueBytes, true)
	default:
		return nil, fmt.Errorf("unknown BGP path attribute type code: %d", attr.TypeCode)
	}

	return attr, err
}

func decodeBGPMessage(data []byte, as4 bool, afi AFI) (*BGPMessage, error) {
	msgType := BGPMessageType(data[18])

	var msg BGPMessage
	var err error
	switch msgType {
	case BGPMessageTypeOpen:
		msg, err = decodeOpenMessage(data)
	case BGPMessageTypeUpdate:
		msg, err = decodeUpdateMessage(data, as4, afi)
	case BGPMessageTypeNotification:
		msg, err = decodeNotificationMessage(data)
	case BGPMessageTypeKeepalive:
		msg, err = decodeKeepaliveMessage(data)
	default:
		return nil, fmt.Errorf("unknown BGP message type: %d", msgType)
	}

	return &msg, err
}

type BGPMessageType uint8

const (
	BGPMessageTypeOpen BGPMessageType = iota + 1
	BGPMessageTypeUpdate
	BGPMessageTypeNotification
	BGPMessageTypeKeepalive
)

type BGPMessage interface {
	Type() BGPMessageType
}

type bgpMessageHeader struct {
	type_ BGPMessageType
}

func (h *bgpMessageHeader) Type() BGPMessageType {
	return h.type_
}

func (h *bgpMessageHeader) decodeHeader(d *decoder) error {
	d.skip(16) // Marker (16 octets)
	d.skip(2)  // Length (2 octets)
	h.type_ = BGPMessageType(d.uint8())
	return nil
}

type BGPOpenMessage struct {
	bgpMessageHeader
	Version            uint8
	MyAS               AS
	HoldTime           time.Duration
	BGPIdentifier      net.IP
	OptionalParameters []*OptionalParameter
}

type OptionalParameter struct {
	Type  uint8
	Value []byte
}

func decodeOpenMessage(data []byte) (*BGPOpenMessage, error) {
	d := &decoder{data}
	msg := &BGPOpenMessage{}
	msg.decodeHeader(d)
	msg.Version = d.uint8()
	msg.MyAS = d.as2()
	msg.HoldTime = time.Duration(d.uint16()) * time.Second
	msg.BGPIdentifier = d.ipv4()
	d.skip(1) // Optional Parameters Length (1 octet)
	for d.size() != 0 {
		p := &OptionalParameter{}
		p.Type = d.uint8()
		p.Value = d.bytes(int(d.uint8()))
		msg.OptionalParameters = append(msg.OptionalParameters, p)
	}
	return msg, nil
}

type BGPUpdateMessage struct {
	bgpMessageHeader
	WithdrawnRoutes []*net.IPNet
	PathAttributes  []*BGPPathAttribute
	NLRI            []*net.IPNet
}

func decodeUpdateMessage(data []byte, as4 bool, afi AFI) (*BGPUpdateMessage, error) {
	d := &decoder{data}

	msg := &BGPUpdateMessage{}
	msg.decodeHeader(d)

	routesLen := int(d.uint16())
	restLen := d.size() - routesLen
	for d.size() != restLen {
		if afi == AFIIPv4 {
			msg.WithdrawnRoutes = append(msg.WithdrawnRoutes, d.nlriIPv4())
		} else if afi == AFIIPv6 {
			msg.WithdrawnRoutes = append(msg.WithdrawnRoutes, d.nlriIPv6())
		} else {
			return nil, fmt.Errorf("unknown AFI: %d", afi)
		}
	}

	attrBytes := d.skip(int(d.uint16()))
	reader := bgpPathAttributeReader{reader: bytes.NewReader(attrBytes), as4: as4}
	for {
		attr, err := reader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		msg.PathAttributes = append(msg.PathAttributes, attr)
	}

	for d.size() != 0 {
		if afi == AFIIPv4 {
			msg.NLRI = append(msg.NLRI, d.nlriIPv4())
		} else if afi == AFIIPv6 {
			msg.NLRI = append(msg.NLRI, d.nlriIPv6())
		} else {
			return nil, fmt.Errorf("unknown AFI: %d", afi)
		}
	}

	return msg, nil
}

type BGPNotificationMessage struct {
	bgpMessageHeader
	ErrorCode    uint8
	ErrorSubcode uint8
	Data         []byte
}

func decodeNotificationMessage(data []byte) (*BGPNotificationMessage, error) {
	d := &decoder{data}
	msg := &BGPNotificationMessage{}
	msg.decodeHeader(d)
	msg.ErrorCode = d.uint8()
	msg.ErrorSubcode = d.uint8()
	msg.Data = d.bytes(d.size())
	return msg, nil
}

type BGPKeepaliveMessage struct {
	bgpMessageHeader
}

func decodeKeepaliveMessage(data []byte) (*BGPKeepaliveMessage, error) {
	d := &decoder{data}
	msg := &BGPKeepaliveMessage{}
	msg.decodeHeader(d)
	return msg, nil
}
