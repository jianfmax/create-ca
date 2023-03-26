package create_ca

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	cr "crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"math/rand"
	"time"
)

type CERT struct {
	CERT       []byte
	CERTKEY    *ecdsa.PrivateKey
	CERTPEM    *bytes.Buffer
	CERTKEYPEM *bytes.Buffer
	CSR        *x509.Certificate
}

// CreateCA 创建根证书
func CreateCA(sub *pkix.Name, notBefore time.Time, expire int) (*CERT, error) {
	var (
		ca  = new(CERT)
		err error
	)

	if expire < 1 {
		expire = 1
	}
	ca.CERTKEY, err = ecdsa.GenerateKey(elliptic.P256(), cr.Reader)
	if err != nil {
		return nil, err
	}
	//notBefore, _ := time.Parse("Jan 2 15:04:05 2006", "Jan 1 00:00:00 1970")
	ca.CSR = &x509.Certificate{
		SerialNumber:          big.NewInt(rand.Int63n(2000)),
		Subject:               *sub,
		NotBefore:             notBefore,
		NotAfter:              notBefore.AddDate(expire, 0, 0),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	ca.CERT, err = x509.CreateCertificate(cr.Reader, ca.CSR, ca.CSR, ca.CERTKEY.Public(), ca.CERTKEY)
	if err != nil {
		return nil, err
	}
	ca.CERTPEM = new(bytes.Buffer)
	err = pem.Encode(ca.CERTPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: ca.CERT,
	})
	if err != nil {
		return nil, err
	}
	ca.CERTKEYPEM = new(bytes.Buffer)
	err = pem.Encode(ca.CERTKEYPEM, &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: ignoreErr(x509.MarshalPKCS8PrivateKey(ca.CERTKEY)),
	})
	if err != nil {
		return nil, err
	}
	return ca, nil
}

// ReadCA 读取一个证书
func ReadCA(caCrt, caKey []byte) (*CERT, error) {
	var (
		ca  = new(CERT)
		err error
	)
	ca.CERT = caCrt
	pemBlock, _ := pem.Decode(ca.CERT)
	if pemBlock == nil {
		return ca, errors.New("decode error")
	}
	ca.CSR, err = x509.ParseCertificate(pemBlock.Bytes)
	if err != nil {
		return ca, err
	}
	keyBlock, _ := pem.Decode(caKey)
	if keyBlock == nil {
		return ca, errors.New("decode key error")
	}
	a, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		return ca, err
	}
	ca.CERTKEY = a.(*ecdsa.PrivateKey)
	return ca, nil
}
