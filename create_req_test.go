package create_ca

import (
	"crypto/x509/pkix"
	"log"
	"net"
	"testing"
	"time"
)

func TestCreateReq(t *testing.T) {
	subj := &pkix.Name{
		Country:      []string{"CN"},
		Province:     []string{"Shanghai"},
		Locality:     []string{"Shanghai"},
		Organization: []string{"nsqk.com"},
		CommonName:   "localhost",
	}
	notBefore, _ := time.Parse("Jan 2 15:04:05 2006", "Jan 1 00:00:00 1970")
	ca, err := CreateCA(subj, notBefore, 100)
	//ca, err := ReadCA()
	if err != nil {
		log.Panic(err)
	}

	_ = WriteCA(ca, "./ca")

	crt, err := CreateReq(ca, &ca.CSR.Subject, notBefore, 100, []string{"localhost"}, []net.IP{net.IPv4(127, 0, 0, 1)})

	if err != nil {
		log.Panic(err)
	}

	_ = WriteCA(crt, "./tls")
	crt2, err := CreateReq(ca, &ca.CSR.Subject, notBefore, 100, []string{"localhost"}, []net.IP{net.IPv4(127, 0, 0, 1)})

	if err != nil {
		log.Panic(err)
	}

	_ = WriteCA(crt2, "./tls2")
}
