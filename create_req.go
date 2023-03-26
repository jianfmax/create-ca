package create_ca

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	cr "crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"math/rand"
	"net"
	"time"
)

// CreateReq 基于根证书创建证书
func CreateReq(ca *CERT, sub *pkix.Name, notBefore time.Time, expire int, dns []string, ip []net.IP) (*CERT, error) {
	var (
		cert = &CERT{}
		err  error
	)
	cert.CERTKEY, err = ecdsa.GenerateKey(elliptic.P256(), cr.Reader)
	if err != nil {
		return nil, err
	}
	if expire < 1 {
		expire = 1
	}
	//notBefore, _ := time.Parse("Jan 2 15:04:05 2006", "Jan 1 00:00:00 1970")
	cert.CSR = &x509.Certificate{
		SerialNumber: big.NewInt(rand.Int63n(2000)),
		Subject:      *sub,
		IPAddresses:  ip,
		DNSNames:     dns,
		NotBefore:    notBefore,
		NotAfter:     notBefore.AddDate(expire, 0, 0), // 过期时间
		SubjectKeyId: []byte{1, 2, 3, 4, 6},
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}

	cert.CERT, err = x509.CreateCertificate(cr.Reader, cert.CSR, ca.CSR, cert.CERTKEY.Public(), ca.CERTKEY)
	if err != nil {
		return nil, err
	}

	cert.CERTPEM = new(bytes.Buffer)
	err = pem.Encode(cert.CERTPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.CERT,
	})
	if err != nil {
		return nil, err
	}
	cert.CERTKEYPEM = new(bytes.Buffer)
	err = pem.Encode(cert.CERTKEYPEM, &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: ignoreErr(x509.MarshalPKCS8PrivateKey(cert.CERTKEY)),
	})
	if err != nil {
		return nil, err
	}
	return cert, nil
}
