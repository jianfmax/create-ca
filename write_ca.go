package create_ca

import "os"

func WriteCA(cert *CERT, file string) error {
	keyFileName := file + ".key"
	certFIleName := file + ".crt"
	kf, err := os.Create(keyFileName)
	if err != nil {
		return err
	}
	defer func(kf *os.File) {
		_ = kf.Close()
	}(kf)

	if _, err := kf.Write(cert.CERTKEYPEM.Bytes()); err != nil {
		return err
	}

	cf, err := os.Create(certFIleName)
	if err != nil {
		return err
	}
	defer func(cf *os.File) {
		_ = cf.Close()
	}(cf)
	if _, err := cf.Write(cert.CERTPEM.Bytes()); err != nil {
		return err
	}
	return nil
}
