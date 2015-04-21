// +build linux

/*
Package trema_sw implements trema-switch like command line interface.
*/
package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/hkwi/gopenflow"
	"github.com/hkwi/gopenflow/ofp4sw"
	"github.com/hkwi/gopenflow/oxm"
	"io"
	"log"
	"net"
	"strings"
)

type Wrapper struct {
	con    io.ReadWriteCloser
	Closed chan bool
}

func (self Wrapper) Close() error {
	close(self.Closed)
	return self.con.Close()
}

func (self Wrapper) Read(p []byte) (n int, err error) {
	return self.con.Read(p)
}

func (self Wrapper) Write(p []byte) (n int, err error) {
	return self.con.Write(p)
}

func main() {
	var ports string
	flag.StringVar(&ports, "e", "", "comma separated switch ports (netdev names)")
	var ctrl string
	flag.StringVar(&ctrl, "c", "", "control unix domain socket path")
	var datapathId int64
	flag.Int64Var(&datapathId, "i", 0, "datapath id")
	flag.Parse()

	pipe := ofp4sw.NewPipeline()
	pipe.DatapathId = uint64(datapathId)

	if pman, err := gopenflow.NewNamedPortManager(pipe); err != nil {
		log.Print(err)
		return
	} else {
		for _, e := range strings.Split(ports, ",") {
			if sub := strings.IndexRune(e, ':'); sub > 0 {
				switch e[:sub] {
				case "json":
					pipe.AddPort(NewJsonPort(e[sub+1:]))
				}
			} else {
				pman.AddName(e)
			}
		}
	}

	if len(ctrl) == 0 {
		ctrl = fmt.Sprintf("%x.ctrl", datapathId)
	}
	laddr := net.UnixAddr{ctrl, "unix"}
	if s, err := net.ListenUnix("unix", &laddr); err != nil {
		panic(err)
	} else {
		for {
			if con, err := s.AcceptUnix(); err != nil {
				panic(err)
			} else {
				go func() {
					ch := Wrapper{
						con:    con,
						Closed: make(chan bool),
					}
					if err := pipe.AddChannel(ch); err != nil {
						log.Print(err)
					}
					_ = <-ch.Closed
				}()
			}
		}
	}
}

type JsonPort struct {
	name    string
	hwaddr  [6]byte
	monitor chan bool
	ingress chan gopenflow.Frame
	sockets []net.Conn
}

func (self JsonPort) Name() string {
	return self.name
}

func (self JsonPort) HwAddr() [6]byte {
	return [6]byte{0, 0, 0, 0, 0, 0}
}

func (self JsonPort) PhysicalPort() uint32 {
	return 0
}

func (self JsonPort) Monitor() <-chan bool {
	return self.monitor
}

func (self JsonPort) Ingress() <-chan gopenflow.Frame {
	return self.ingress
}

func (self *JsonPort) Egress(pkt gopenflow.Frame) error {
	if !isJson(pkt.Oob) {
		return fmt.Errorf("not a json packet")
	}
	for _, c := range self.sockets {
		c.Write(pkt.Data)
	}
	return nil
}

func (self JsonPort) GetConfig() []gopenflow.PortConfig {
	return nil
}

func (self JsonPort) SetConfig([]gopenflow.PortConfig) {
	return
}

func (self JsonPort) State() []gopenflow.PortState {
	return nil
}

func (self JsonPort) Mtu() uint32 {
	return 1500 - 16
}

func (self JsonPort) Ethernet() (gopenflow.PortEthernetProperty, error) {
	return gopenflow.PortEthernetProperty{}, fmt.Errorf("not an ether")
}

func (self JsonPort) Stats() (gopenflow.PortStats, error) {
	return gopenflow.PortStats{}, nil // XXX: to do implement this
}

func (self JsonPort) Vendor(arg interface{}) interface{} {
	return nil
}

var jsonOxm = make([]byte, 19)

func init() {
	oob1 := jsonOxm[0:8] // length=8
	hdr := oxm.Header(oxm.OXM_OF_PACKET_TYPE)
	hdr.SetLength(4)
	binary.BigEndian.PutUint32(oob1, uint32(hdr))
	binary.BigEndian.PutUint16(oob1[4:], 0)
	binary.BigEndian.PutUint16(oob1[6:], uint16(oxm.OFPHTO_OXM_EXPERIMENTER))

	oob2 := jsonOxm[8:19] // length=11
	binary.BigEndian.PutUint16(oob2, uint16(oxm.OFPXMC_EXPERIMENTER))
	oob2[2] = ACME_OXM_FIELD_BASIC << 1
	oob2[3] = 7
	binary.BigEndian.PutUint32(oob2[4:], uint32(ACME_EXPERIMENTER_ID))
	binary.BigEndian.PutUint16(oob2[8:], uint16(ACMEOXM_BASIC_PACKET_TYPE))
	oob2[10] = 1
}

func isJson(seq []byte) bool {
	oxms := oxm.Oxm(seq).Iter()

	hit := false
	for _, x := range oxms {
		if x.Header().Type() == oxm.OXM_OF_PACKET_TYPE && binary.BigEndian.Uint16(x[4:]) == 0 && binary.BigEndian.Uint16(x[6:]) == oxm.OFPHTO_OXM_EXPERIMENTER {
			hit = true
		}
	}
	if !hit {
		return false
	}

	for _, x := range oxms {
		hdr := x.Header()
		if hdr.Class() == oxm.OFPXMC_EXPERIMENTER &&
			binary.BigEndian.Uint32(x[4:]) == ACME_EXPERIMENTER_ID &&
			hdr.Field() == ACME_OXM_FIELD_BASIC &&
			binary.BigEndian.Uint16(x[8:]) == ACMEOXM_BASIC_PACKET_TYPE &&
			x[10] == ACMEHTB_JSON {
			return true
		}
	}
	return false
}

func unJson(seq []byte) []byte {
	var x oxm.Oxm
	var hdr oxm.Header
	oxms := oxm.Oxm(seq).Iter()

	x = oxms[0]
	hdr = x.Header()
	if hdr.Type() != oxm.OFPXMT_OFB_PACKET_TYPE || binary.BigEndian.Uint16(x[4:]) != 0 || binary.BigEndian.Uint16(x[6:]) != oxm.OFPHTO_OXM_EXPERIMENTER {
		return seq
	}

	x = oxms[1]
	hdr = x.Header()
	if hdr.Class() != oxm.OFPXMC_EXPERIMENTER ||
		binary.BigEndian.Uint32(x[4:]) != ACME_EXPERIMENTER_ID ||
		hdr.Field() != ACME_OXM_FIELD_BASIC ||
		binary.BigEndian.Uint16(x[8:]) != ACMEOXM_BASIC_PACKET_TYPE {
		return seq
	}
	var ret []byte
	for _, r := range oxms[2:] {
		ret = append(ret, r...)
	}
	return ret
}

func NewJsonPort(path string) *JsonPort {
	port := &JsonPort{
		name:    path,
		ingress: make(chan gopenflow.Frame),
	}
	if l, err := net.ListenUnix("unix", &net.UnixAddr{path, "unix"}); err != nil {
		log.Print(err)
		return nil
	} else {
		go func() {
			for {
				if con, err := l.AcceptUnix(); err != nil {
					log.Print(err)
					break
				} else {
					port.sockets = append(port.sockets, con)
					go func() {
						junk := make([]byte, 1500)
						buf := bytes.NewBuffer(junk)
						enc := json.NewEncoder(buf)
						dec := json.NewDecoder(con)

						for {
							var m interface{}
							if err := dec.Decode(&m); err != nil && err != io.EOF {
								log.Print(err)
								break
							}
							if m != nil {
								buf.Reset()
								if err := enc.Encode(m); err != nil {
									log.Print(err)
									break
								}
								port.ingress <- gopenflow.Frame{
									Data: junk[:buf.Len()],
									Oob:  jsonOxm,
								}
							}
						}
						var newSet []net.Conn
						for _, c := range port.sockets {
							if c != con {
								newSet = append(newSet, c)
							}
						}
						port.sockets = newSet
						con.Close()
					}()
				}
			}
			l.Close()
		}()
	}
	return port
}

const ACME_EXPERIMENTER_ID = 0x00ACDE48

const ACME_OXM_FIELD_BASIC = 0

const (
	ACMEOXM_BASIC_UNKNOWN = iota
	ACMEOXM_BASIC_PACKET_TYPE
)

const ( // ACMEHeaderTypeBasic
	ACMEHTB_UNSET = iota
	ACMEHTB_JSON
)

const ETHTYPE_JSON = 0xFFF1

type AcmeOxmHandler struct{}

func init() {
	ofp4sw.AddOxmHandler(ACME_EXPERIMENTER_ID, AcmeOxmHandler{})
}

var pktTypeKey = ofp4sw.OxmKeyExp{
	ACME_EXPERIMENTER_ID,
	ACME_OXM_FIELD_BASIC,
	ACMEOXM_BASIC_PACKET_TYPE,
}

func (self AcmeOxmHandler) Parse(seq []byte) map[ofp4sw.OxmKey]ofp4sw.OxmPayload {
	ret := make(map[ofp4sw.OxmKey]ofp4sw.OxmPayload)
	for _, x := range oxm.Oxm(seq).Iter() {
		hdr := x.Header()
		if hdr.Class() == oxm.OFPXMC_EXPERIMENTER &&
			binary.BigEndian.Uint32(x[4:]) == ACME_EXPERIMENTER_ID {
			k := ofp4sw.OxmKeyExp{
				ACME_EXPERIMENTER_ID,
				hdr.Field(),
				binary.BigEndian.Uint16(x[8:]),
			}
			ret[k] = ofp4sw.OxmValueMask{Value: x[10:]}
		}
	}
	return ret
}

func (self AcmeOxmHandler) OxmId(id uint32) uint32 {
	return id
}

func (self AcmeOxmHandler) Match(frame ofp4sw.Frame, key ofp4sw.OxmKey, payload ofp4sw.OxmPayload) (bool, error) {
	if k, ok := key.(ofp4sw.OxmKeyExp); ok && k == pktTypeKey {
		if p, ok := payload.([]byte); ok {
			switch p[0] {
			case ACMEHTB_UNSET:
				if v, ok := frame.Oob[pktTypeKey]; !ok {
					return true, nil
				} else if b, ok := v.([]byte); !ok {
					return false, fmt.Errorf("unexpected payload")
				} else {
					return b[0] == ACMEHTB_UNSET, nil
				}
			case ACMEHTB_JSON:
				if v, ok := frame.Oob[pktTypeKey]; !ok {
					return false, nil
				} else if b, ok := v.([]byte); ok && b[0] == ACMEHTB_JSON {
					return true, nil
				} else {
					return false, nil
				}
			}
		}
	}
	return false, fmt.Errorf("unhandled")
}

func (self AcmeOxmHandler) SetField(frame *ofp4sw.Frame, key ofp4sw.OxmKey, payload ofp4sw.OxmPayload) error {
	if k, ok := key.(ofp4sw.OxmKeyExp); !ok || k.Experimenter != ACME_EXPERIMENTER_ID {
		return fmt.Errorf("invalid oxm handler call")
	} else if k == pktTypeKey {
		if p, ok := payload.([]byte); !ok {
			return fmt.Errorf("payload error")
		} else if v, ok := frame.Oob[k]; ok {
			if b, ok := v.([]byte); ok {
				if b[0] == p[0] {
					return nil
				}
				if data, err := frame.Serialized(); err != nil {
					return err
				} else if b[0] == ACMEHTB_UNSET && p[0] == ACMEHTB_JSON {
					if binary.BigEndian.Uint16(data[12:]) == ETHTYPE_JSON {
						frame.Oob[key] = payload
						frame.SetSerialized(data[14:])
					} else {
						return fmt.Errorf("not a json ether")
					}
				} else if b[9] == ACMEHTB_JSON && p[0] == ACMEHTB_UNSET {
					frame.Oob[key] = payload
					pkt := append(make([]byte, 14), data...)
					binary.BigEndian.PutUint16(pkt[12:], ETHTYPE_JSON)
					frame.SetSerialized(pkt)
				}
			}
		} else {
			switch p[0] {
			case ACMEHTB_UNSET:
				return nil
			case ACMEHTB_JSON:
				if data, err := frame.Serialized(); err != nil {
					return err
				} else if binary.BigEndian.Uint16(data[12:]) == ETHTYPE_JSON {
					frame.Oob[key] = payload
					frame.SetSerialized(data[14:])
				} else {
					return fmt.Errorf("not a json ether")
				}
			}
		}
	}
	return fmt.Errorf("unhandled")
}

func (self AcmeOxmHandler) Fit(key ofp4sw.OxmKey, narrow, wide ofp4sw.OxmPayload) (bool, error) {
	if k, ok := key.(ofp4sw.OxmKeyExp); ok && k == pktTypeKey {
		if n, ok := narrow.([]byte); !ok {
			return false, fmt.Errorf("payload error")
		} else if w, ok := wide.([]byte); !ok {
			return false, fmt.Errorf("payload error")
		} else {
			return bytes.Equal(n, w), nil
		}
	}
	return false, fmt.Errorf("unhandled")
}

func (self AcmeOxmHandler) Conflict(key ofp4sw.OxmKey, narrow, wide ofp4sw.OxmPayload) (bool, error) {
	if k, ok := key.(ofp4sw.OxmKeyExp); ok && k == pktTypeKey {
		if n, ok := narrow.([]byte); !ok {
			return false, fmt.Errorf("payload error")
		} else if w, ok := wide.([]byte); !ok {
			return false, fmt.Errorf("payload error")
		} else {
			return !bytes.Equal(n, w), nil
		}
	}
	return false, fmt.Errorf("unhandled")
}

func (self AcmeOxmHandler) Expand(map[ofp4sw.OxmKey]ofp4sw.OxmPayload) error {
	return nil
}
