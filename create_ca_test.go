package create_ca

import (
	"crypto/x509/pkix"
	"log"
	"net"
	"os"
	"testing"
	"time"
)

func TestReadCA(t *testing.T) {
	subj := &pkix.Name{
		Country:      []string{"CN"},
		Province:     []string{"Shanghai"},
		Locality:     []string{"Shanghai"},
		Organization: []string{"nsqk.com"},
		CommonName:   "localhost",
	}
	notBefore, _ := time.Parse("Jan 2 15:04:05 2006", "Jan 1 00:00:00 1970")
	ca, err := ReadCA(ignoreErr(os.ReadFile("./ca.crt")), ignoreErr(os.ReadFile("./ca.key")))
	if err != nil {
		log.Panic(err)
	}

	crt, err := CreateReq(ca, subj, notBefore, 100, []string{"localhost"}, []net.IP{net.ParseIP("127.0.0.1")})

	if err != nil {
		log.Panic(err)
	}

	_ = WriteCA(crt, "./tls3")
}
