package krb5test

import (
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/jcmturner/gokrb5/v8/client"
	"github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/crypto"
	"github.com/jcmturner/gokrb5/v8/iana"
	"github.com/jcmturner/gokrb5/v8/iana/errorcode"
	"github.com/jcmturner/gokrb5/v8/iana/etypeID"
	"github.com/jcmturner/gokrb5/v8/iana/keyusage"
	"github.com/jcmturner/gokrb5/v8/iana/msgtype"
	"github.com/jcmturner/gokrb5/v8/iana/nametype"
	"github.com/jcmturner/gokrb5/v8/iana/patype"
	"github.com/jcmturner/gokrb5/v8/keytab"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/types"
)

var (
	ServerEncType = "aes256-cts-hmac-sha1-96" // encrypt type supported in KDC
	ServerAddr    = "127.0.0.1:0"             // server address of KDC
	ServerRealm   = "TEST.REALM.COM"          // Realm of KDC
	ServerDomain  = "test.realm.com"          // Domain of KDC
)

type KDC struct {
	Realm      string
	KRB5Conf   *config.Config
	SName      types.PrincipalName
	Principals map[string]PrincipalDetails
	Keytab     *keytab.Keytab
	Logger     *log.Logger

	TCPListener net.Listener
	UDPListener net.PacketConn
	errChan     chan error
	udpWg       sync.WaitGroup
	udpClose    chan interface{}
	tcpWg       sync.WaitGroup
	tcpClose    chan interface{}
}

type PrincipalDetails struct {
	Password string
	Groups   []string
	Client   *client.Client
}

func NewKDC(principals map[string][]string, l *log.Logger) (*KDC, error) {
	kdc := new(KDC)
	kdc.Realm = strings.ToUpper(ServerRealm)
	kdc.Logger = l
	kdc.errChan = make(chan error, 1)
	kdc.udpClose = make(chan interface{})
	kdc.tcpClose = make(chan interface{})

	go func() {
		for err := range kdc.errChan {
			kdc.Logger.Printf("ERROR: %v", err)
		}
	}()

	kdc.SName = types.PrincipalName{
		NameType:   nametype.KRB_NT_SRV_INST,
		NameString: []string{"krbtgt", kdc.Realm},
	}

	var err error
	kdc.TCPListener, err = net.Listen("tcp", ServerAddr)
	if err != nil {
		return nil, fmt.Errorf("could not create TCP listener: %v", err)
	}
	kdc.UDPListener, err = net.ListenPacket("udp", kdc.TCPListener.Addr().String())
	if err != nil {
		return nil, fmt.Errorf("could not create UDP listener: %v", err)
	}

	// Generate the krb5 config object
	kdc.KRB5Conf = config.New()
	encTypeID := etypeID.ETypesByName[ServerEncType]
	kdc.KRB5Conf.LibDefaults.DefaultTGSEnctypes = []string{ServerEncType}
	kdc.KRB5Conf.LibDefaults.DefaultTGSEnctypeIDs = []int32{encTypeID}
	kdc.KRB5Conf.LibDefaults.DefaultTktEnctypes = []string{ServerEncType}
	kdc.KRB5Conf.LibDefaults.DefaultTktEnctypeIDs = []int32{encTypeID}
	kdc.KRB5Conf.LibDefaults.PermittedEnctypes = []string{ServerEncType}
	kdc.KRB5Conf.LibDefaults.PermittedEnctypeIDs = []int32{encTypeID}
	kdc.KRB5Conf.LibDefaults.PreferredPreauthTypes = []int{int(encTypeID)}
	kdc.KRB5Conf.LibDefaults.DefaultRealm = kdc.Realm
	kdc.KRB5Conf.LibDefaults.DNSLookupKDC = false
	kdc.KRB5Conf.LibDefaults.DNSLookupRealm = false

	kdc.KRB5Conf.DomainRealm[strings.ToLower(ServerRealm)] = kdc.Realm

	kdc.KRB5Conf.Realms = append(kdc.KRB5Conf.Realms, config.Realm{
		Realm:         kdc.Realm,
		DefaultDomain: ServerDomain,
		KDC:           []string{kdc.TCPListener.Addr().String()},
	})

	// Generate a KDC secret
	kdc.Keytab = keytab.New()
	pwd := randomString(10)
	err = kdc.Keytab.AddEntry("krbtgt/"+kdc.Realm, kdc.Realm, pwd, time.Now().UTC(), 1, encTypeID)
	if err != nil {
		return nil, fmt.Errorf("error generating server secret keytab: %v", err)
	}
	kdc.Principals = make(map[string]PrincipalDetails)
	kdc.Principals["krbtgt/"+kdc.Realm] = PrincipalDetails{
		Password: pwd,
	}

	// Generate passwords and keytabs for the desired principals
	for p, d := range principals {
		g := make([]string, len(d), len(d))
		copy(g, d)
		pwd := randomString(10)
		err := kdc.Keytab.AddEntry(p, kdc.Realm, pwd, time.Now().UTC(), 1, encTypeID)
		if err != nil {
			return nil, fmt.Errorf("error generating test keytab: %v", err)
		}
		cl := client.NewWithKeytab(p, kdc.Realm, kdc.Keytab, kdc.KRB5Conf, client.Logger(l))
		kdc.Principals[p] = PrincipalDetails{
			Password: pwd,
			Groups:   g,
			Client:   cl,
		}
	}
	return kdc, nil
}

func (k *KDC) Start() {
	k.goServeUDP()
	k.goServeTCP()
}

func (k *KDC) Close() {
	close(k.udpClose)
	err := k.UDPListener.Close()
	if err != nil {
		k.Logger.Printf("error when closing UDP listener: %v", err)
	}
	k.udpWg.Wait()
	close(k.tcpClose)
	err = k.TCPListener.Close()
	if err != nil {
		k.Logger.Printf("error when closing TCP listener: %v", err)
	}
	k.tcpWg.Wait()
	close(k.errChan)
}

func (k *KDC) goServeTCP() {
	go func() {
		for {
			conn, err := k.TCPListener.Accept()
			if err != nil {
				select {
				case <-k.tcpClose:
					// Accept has errored as we are closing down
					return
				default:
					k.errChan <- fmt.Errorf("error reading from TCP listener: %v", err)
				}
			} else {
				k.Logger.Printf("TCP connection established: from=%s", conn.RemoteAddr().String())
				k.tcpWg.Add(1)
				go func() {
					defer conn.Close()
					defer k.tcpWg.Done()
					deadline := time.Now().Add(time.Second * 10)
					err := conn.SetDeadline(deadline)
					if err != nil {
						k.errChan <- fmt.Errorf("serving=%s: %v", conn.RemoteAddr().String(), err)
						return
					}

					// RFC 4120 7.2.2 specifies the first 4 bytes indicate the length of the message in big endian order.
					sh := make([]byte, 4, 4)
					_, err = conn.Read(sh)
					if err != nil {
						k.errChan <- fmt.Errorf("serving=%s: %v", conn.RemoteAddr().String(), err)
						return
					}
					s := binary.BigEndian.Uint32(sh)

					ib := make([]byte, s, s)
					n, err := io.ReadFull(conn, ib)
					if err != nil {
						k.errChan <- fmt.Errorf("serving=%s: %v", conn.RemoteAddr().String(), err)
						return
					}
					if n != int(s) {
						k.errChan <- fmt.Errorf("serving=%s: size of data recieved=%d; expected=%d", conn.RemoteAddr(), n, s)
						return
					}

					ob, err := k.getResponseBytes(ib, conn.RemoteAddr())
					if err != nil {
						k.errChan <- fmt.Errorf("serving=%s: %v", conn.RemoteAddr().String(), err)
						return
					}

					// Add the size header
					rb := make([]byte, 4, 4)
					binary.BigEndian.PutUint32(rb, uint32(len(ob)))
					rb = append(rb, ob...)

					n, err = conn.Write(rb)
					if err != nil {
						k.errChan <- fmt.Errorf("serving=%s: %v", conn.RemoteAddr().String(), err)
						return
					}
					if n != len(rb) {
						k.errChan <- fmt.Errorf("serving=%s: bytes sent did not match length of reply", conn.RemoteAddr())
						return
					}
					k.Logger.Printf("TCP reply sent: bytes=%d to=%s", n, conn.RemoteAddr().String())
				}()
			}
		}
	}()
}

func (k *KDC) goServeUDP() {
	go func() {
		for {
			udpbuf := make([]byte, 4096)
			n, addr, err := k.UDPListener.ReadFrom(udpbuf)
			if err != nil {
				select {
				case <-k.udpClose:
					// ReadFrom has errored as we are closing down
					return
				default:
					k.errChan <- fmt.Errorf("error reading from UDP listener: %v", err)
				}
			} else {
				k.Logger.Printf("UDP packet received: bytes=%d from=%s", n, addr.String())
				k.udpWg.Add(1) // we have a message to handle so iterate wg
				go func() {
					defer k.udpWg.Done()
					deadline := time.Now().Add(time.Second * 10)
					err = k.UDPListener.SetWriteDeadline(deadline)
					if err != nil {
						k.errChan <- fmt.Errorf("serving=%s: %v", addr, err)
						return
					}
					ib := make([]byte, n, n)
					copy(ib, udpbuf)

					ob, err := k.getResponseBytes(ib, addr)
					if err != nil {
						k.errChan <- fmt.Errorf("serving=%s: %v", addr, err)
						return
					}

					n, err = k.UDPListener.WriteTo(ob, addr)
					if err != nil {
						k.errChan <- fmt.Errorf("serving=%s: %v", addr, err)
						return
					}
					k.Logger.Printf("UDP packet sent: bytes=%d to=%s", n, addr.String())
				}()
			}
		}
	}()
}

//msgType returns the kerberos message type ID for the bytes received
func mType(b []byte) (int, error) {
	var m asn1.RawValue
	_, err := asn1.Unmarshal(b, &m)
	if err != nil {
		return 0, err
	}
	if m.Tag == 0 {
		return 0, errors.New("could not determine message type")
	}
	return m.Tag, nil
}

// getResponseBytes returns the appropriate response bytes for the bytes recieved
func (kdc *KDC) getResponseBytes(b []byte, cAddr net.Addr) ([]byte, error) {
	mt, err := mType(b)
	if err != nil {
		return []byte{}, err
	}
	switch mt {
	case msgtype.KRB_AS_REQ:
		m := new(messages.ASReq)
		err := m.Unmarshal(b)
		if err != nil {
			return kdc.krbError(errorcode.KRB_ERR_GENERIC, err)
		}
		return kdc.asRep(m, cAddr)
	case msgtype.KRB_TGS_REQ:
		m := new(messages.TGSReq)
		err := m.Unmarshal(b)
		if err != nil {
			return kdc.krbError(errorcode.KRB_ERR_GENERIC, err)
		}
		return kdc.tgsRep(m, cAddr)
	default:
		kdc.Logger.Printf("received message that was neither AS_REQ or TGS_REQ: from=%v", cAddr)
		return kdc.krbError(errorcode.KRB_ERR_GENERIC, fmt.Errorf("unsupported message type (%d) recieved", mt))
	}
}

func (kdc *KDC) krbError(errorCode int32, err error) ([]byte, error) {
	m := messages.NewKRBError(kdc.SName, kdc.Realm, errorCode, err.Error())
	b, _ := m.Marshal()
	return b, m
}

func (kdc *KDC) asRep(req *messages.ASReq, cAddr net.Addr) ([]byte, error) {
	kdc.Logger.Printf("AS_REQ from=%s: %+v", cAddr, *req)
	etype := kdc.selectTktEtype(req)
	if etype == 0 {
		return kdc.krbError(errorcode.KDC_ERR_ETYPE_NOSUPP, errors.New("cannot agree on enctype to use"))
	}
	kdc.Logger.Printf("AS_REQ from=%s: selected enctype %d", cAddr, etype)

	t := time.Now().UTC()
	endTime := t.Add(kdc.KRB5Conf.LibDefaults.TicketLifetime)
	renewTime := t.Add(kdc.KRB5Conf.LibDefaults.RenewLifetime)
	tkt, skey, err := messages.NewTicket(req.ReqBody.CName, kdc.Realm, kdc.SName, kdc.Realm,
		kdc.KRB5Conf.LibDefaults.KDCDefaultOptions, kdc.Keytab,
		etype, 0, t, t, endTime, renewTime)
	if err != nil {
		return kdc.krbError(errorcode.KRB_ERR_GENERIC, err)
	}

	// The encpart of the asRep is encrypted with the users keytab
	encPart := messages.EncKDCRepPart{
		Key: skey,
		LastReqs: []messages.LastReq{{
			LRType:  0,
			LRValue: time.Time{},
		}},
		Nonce:     req.ReqBody.Nonce,
		Flags:     kdc.KRB5Conf.LibDefaults.KDCDefaultOptions,
		AuthTime:  t,
		EndTime:   endTime,
		RenewTill: renewTime,
		SRealm:    req.ReqBody.Realm,
		SName:     kdc.SName,
	}
	key, kvno, err := kdc.Keytab.GetEncryptionKey(req.ReqBody.CName, kdc.Realm, 0, etype)
	if err != nil {
		return kdc.krbError(errorcode.KRB_ERR_GENERIC, fmt.Errorf("error getting user's encryption key: %v", err))
	}
	b, err := encPart.Marshal()
	if err != nil {
		return kdc.krbError(errorcode.KRB_ERR_GENERIC, fmt.Errorf("error marshaling AS_REP encpart: %v", err))
	}
	encData, err := crypto.GetEncryptedData(b, key, keyusage.AS_REP_ENCPART, kvno)
	if err != nil {
		return kdc.krbError(errorcode.KRB_ERR_GENERIC, fmt.Errorf("error encrypting AS_REP encpart: %v", err))
	}

	m := messages.ASRep{
		KDCRepFields: messages.KDCRepFields{
			PVNO:    iana.PVNO,
			MsgType: msgtype.KRB_AS_REP,
			PAData:  []types.PAData{},
			CRealm:  kdc.Realm,
			CName:   req.ReqBody.CName,
			Ticket:  tkt,
			EncPart: encData,
		},
	}
	kdc.Logger.Printf("AS_REQ from=%s: AS_REP generated %+v", cAddr, m)
	mb, err := m.Marshal()
	if err != nil {
		return kdc.krbError(errorcode.KRB_ERR_GENERIC, fmt.Errorf("error marshaling AS_REP: %v", err))
	}
	return mb, nil
}

func (kdc *KDC) tgsRep(req *messages.TGSReq, cAddr net.Addr) ([]byte, error) {
	kdc.Logger.Printf("AS_REQ from=%s: %+v", cAddr, *req)
	// Get the AP_REQ from the PA data
	var apReq messages.APReq
	for _, pa := range req.PAData {
		if pa.PADataType == patype.PA_TGS_REQ {
			err := apReq.Unmarshal(pa.PADataValue)
			if err != nil {
				return kdc.krbError(errorcode.KDC_ERR_PADATA_TYPE_NOSUPP,
					fmt.Errorf("could not unmarshal PA_TGS_REQ: %v", err))
			}
		}
	}
	if apReq.PVNO == 0 {
		return kdc.krbError(errorcode.KDC_ERR_BAD_PVNO, errors.New("could not find PA_TGS_REQ in padata"))
	}

	// Validate the authenticator checksum. This also decrypts the enc part of the TGT within
	h, err := types.GetHostAddress(cAddr.String())
	if err != nil {
		return kdc.krbError(errorcode.KRB_ERR_GENERIC, fmt.Errorf("could not get client host address: %v", err))
	}
	ok, err := apReq.Verify(kdc.Keytab, time.Minute*5, h, nil)
	if err != nil {
		kerr, ok := err.(messages.KRBError)
		if ok {
			b, _ := kerr.Marshal()
			return b, err
		}
		return kdc.krbError(errorcode.KRB_AP_ERR_BAD_INTEGRITY, fmt.Errorf("could not verify AP_REQ: %v", err))
	}
	if !ok {
		return kdc.krbError(errorcode.KRB_AP_ERR_BAD_INTEGRITY, errors.New("failed to validate AP_REQ"))
	}

	etype := kdc.selectTGSEtype(req)
	if etype == 0 {
		return kdc.krbError(errorcode.KDC_ERR_ETYPE_NOSUPP, errors.New("cannot agree on enctype to use"))
	}
	kdc.Logger.Printf("TGS_REQ from=%s: selected enctype %d", cAddr, etype)

	// Check authenticator checksum
	b, err := req.ReqBody.Marshal()
	if err != nil {
		return kdc.krbError(errorcode.KRB_ERR_GENERIC, fmt.Errorf("could not get request body bytes: %v", err))
	}
	et, err := crypto.GetEtype(etype)
	if err != nil {
		return kdc.krbError(errorcode.KDC_ERR_PADATA_TYPE_NOSUPP, fmt.Errorf("could not get etype: %v", err))
	}
	ok = et.VerifyChecksum(apReq.Ticket.DecryptedEncPart.Key.KeyValue, b, apReq.Authenticator.Cksum.Checksum, keyusage.TGS_REQ_PA_TGS_REQ_AP_REQ_AUTHENTICATOR_CHKSUM)
	if !ok {
		return kdc.krbError(errorcode.KRB_AP_ERR_MODIFIED, fmt.Errorf("checksum of TGS_REQ not valid %v", err))
	}

	tkt, skey, err := messages.NewTicket(req.ReqBody.CName, req.ReqBody.Realm, req.ReqBody.SName, req.ReqBody.Realm,
		kdc.KRB5Conf.LibDefaults.KDCDefaultOptions, kdc.Keytab, etype, 0,
		apReq.Ticket.DecryptedEncPart.AuthTime,
		apReq.Ticket.DecryptedEncPart.StartTime,
		apReq.Ticket.DecryptedEncPart.EndTime,
		apReq.Ticket.DecryptedEncPart.RenewTill)
	if err != nil {
		return kdc.krbError(errorcode.KRB_ERR_GENERIC, err)
	}

	// The encpart of the asRep is encrypted with the users keytab
	encPart := messages.EncKDCRepPart{
		Key: skey,
		LastReqs: []messages.LastReq{messages.LastReq{
			LRType:  0,
			LRValue: time.Time{},
		}},
		Nonce:     req.ReqBody.Nonce,
		Flags:     kdc.KRB5Conf.LibDefaults.KDCDefaultOptions,
		AuthTime:  apReq.Ticket.DecryptedEncPart.AuthTime,
		StartTime: apReq.Ticket.DecryptedEncPart.StartTime,
		EndTime:   apReq.Ticket.DecryptedEncPart.EndTime,
		RenewTill: apReq.Ticket.DecryptedEncPart.RenewTill,
		SRealm:    req.ReqBody.Realm,
		SName:     kdc.SName,
	}
	key := apReq.Authenticator.SubKey
	usage := keyusage.TGS_REP_ENCPART_AUTHENTICATOR_SUB_KEY
	if key.KeyType == 0 && len(key.KeyValue) == 0 {
		key = apReq.Ticket.DecryptedEncPart.Key
		usage = keyusage.TGS_REP_ENCPART_SESSION_KEY
	}
	b, err = encPart.Marshal()
	if err != nil {
		return kdc.krbError(errorcode.KRB_ERR_GENERIC, fmt.Errorf("error marshaling TGS_REP encpart: %v", err))
	}
	encData, err := crypto.GetEncryptedData(b, key, uint32(usage), 0)
	if err != nil {
		return kdc.krbError(errorcode.KRB_ERR_GENERIC, fmt.Errorf("error encrypting TGS_REP encpart: %v", err))
	}

	m := messages.TGSRep{
		KDCRepFields: messages.KDCRepFields{
			PVNO:    iana.PVNO,
			MsgType: msgtype.KRB_TGS_REP,
			PAData:  []types.PAData{},
			CRealm:  kdc.Realm,
			CName:   req.ReqBody.CName,
			Ticket:  tkt,
			EncPart: encData,
		},
	}
	kdc.Logger.Printf("TGS_REQ from=%s: TGS_REP generated %+v", cAddr, m)
	mb, err := m.Marshal()
	if err != nil {
		return kdc.krbError(errorcode.KRB_ERR_GENERIC, fmt.Errorf("error marshaling AS_REP: %v", err))
	}
	return mb, nil
}

func (kdc *KDC) selectTktEtype(req *messages.ASReq) int32 {
	for _, id := range req.ReqBody.EType {
		for _, kdcId := range kdc.KRB5Conf.LibDefaults.DefaultTktEnctypeIDs {
			if id == kdcId {
				return id
			}
		}
	}
	return 0
}

func (kdc *KDC) selectTGSEtype(req *messages.TGSReq) int32 {
	for _, id := range req.ReqBody.EType {
		for _, kdcId := range kdc.KRB5Conf.LibDefaults.DefaultTGSEnctypeIDs {
			if id == kdcId {
				return id
			}
		}
	}
	return 0
}

const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

func randomString(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = letterBytes[rand.Intn(len(letterBytes))]
	}
	return string(b)
}
