package mdktools

import (
	"crypto"
	"crypto/ecdsa"
	cryptorand "crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"github.com/fxamacker/cbor/v2"
	"github.com/youmark/pkcs8"
	"io"
	"time"
)

type CodeSig struct {
	cert    *x509.Certificate
	private *ecdsa.PrivateKey
	hash    crypto.Hash
}

type Seal struct {
	Timestamp         time.Time
	SealedHash        []byte
	SignerCertificate []byte
}

func (sig *Seal) Sum(hash crypto.Hash) []byte {
	hasher := hash.New()
	asn, err := cbor.Marshal(sig)
	if err != nil {
		panic(err)
	}
	hasher.Write(asn)
	return hasher.Sum(nil)
}

type SignatureEnvelope struct {
	Seal
	SealHash []byte
	SealSig  []byte
}

func (s *SignatureEnvelope) String() string {
	return fmt.Sprintf(
		`Signature Envelope: 
Timestamp: %s
DataHash: %X
SealHash: %X`,
		s.Timestamp, s.SealedHash, s.SealHash,
	)
}

func NewSigner(pem []byte, keyPassword []byte, hash crypto.Hash) (*CodeSig, error) {
	cert, key, err := loadCertificateKey(pem, keyPassword)
	if err != nil {
		return nil, err
	}

	if key == nil {
		return nil, NewMdkError(SIGNATURE_ERROR, 10, "no private key found, cannot sign without it")
	}

	signer := &CodeSig{
		hash:    hash,
		cert:    cert,
		private: key,
	}

	return signer, nil
}

func NewVerifier(pem []byte, hash crypto.Hash) (*CodeSig, error) {
	cert, _, err := loadCertificateKey(pem, nil)
	if err != nil {
		return nil, err
	}

	signer := &CodeSig{
		hash:    hash,
		cert:    cert,
		private: nil,
	}

	return signer, nil
}

// Sign signs the data up to dataLen with the key loaded in this signer, returns a raw signature, that needs to be encapsulated
// timestamp should be in UTC form
func (cs *CodeSig) Sign(data io.Reader, expect int64) (*SignatureEnvelope, error) {
	if cs.private == nil {
		return nil, NewMdkError(SIGNATURE_ERROR, 10, "no private key found, cannot sign without it")
	}

	hash := cs.hash.New()
	defer hash.Reset()

	block := make([]byte, hash.BlockSize())
	var read int64 = 0

	for {
		n, err := data.Read(block)
		if err != nil && err != io.EOF {
			return nil, err
		}
		read += int64(n)
		hash.Write(block[:n])
		if n > len(block) || err == io.EOF {
			break
		}
	}

	if read != expect {
		return nil, fmt.Errorf("expected %d bytes, got %d, refusing to sign", expect, read)
	}

	seal := Seal{
		Timestamp:         time.Now().UTC(),
		SealedHash:        hash.Sum(nil),
		SignerCertificate: cs.cert.Raw,
	}

	sigData := &SignatureEnvelope{
		Seal:     seal,
		SealHash: seal.Sum(cs.hash),
		SealSig:  nil,
	}

	sig, err := cs.private.Sign(cryptorand.Reader, seal.Sum(cs.hash), crypto.SHA3_256)
	if err != nil {
		return nil, NewMdkErrorWrap(SIGNATURE_ERROR, 0, err)
	}

	sigData.SealSig = sig

	return sigData, nil
}

func (cs *CodeSig) Verify(sig *SignatureEnvelope, data io.Reader, expect uint64) (bool, error) {
	hash := cs.hash.New()
	defer hash.Reset()

	pub, ok := cs.cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return false, NewMdkError(SIGNATURE_ERROR, 11, "invalid public key present in cert")
	}

	if !ecdsa.VerifyASN1(pub, sig.Seal.Sum(cs.hash), sig.SealSig) {
		return false, NewMdkError(SIGNATURE_ERROR, 1, "invalid signature in seal")
	}

	block := make([]byte, hash.BlockSize())
	var read uint64 = 0

	for {
		n, err := data.Read(block)
		if err != nil && err != io.EOF {
			return false, err
		}
		read += uint64(n)
		hash.Write(block[:n])
		if n > len(block) || err == io.EOF {
			break
		}
	}

	if read != expect {
		return false, fmt.Errorf("expected %d bytes, got %d", expect, read)
	}

	return true, nil
}

func loadCertificateKey(data []byte, password []byte) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	var cert *x509.Certificate = nil
	var pkey *ecdsa.PrivateKey = nil
	for {
		block, rest := pem.Decode(data)
		if block == nil {
			return nil, nil, NewMdkError(CERTIFICATE_ERROR, 32, "failed to decode PEM block, make sure only key in pkcs8 form and certificate are present in the source")
		}
		if rest != nil {
		}
		switch block.Type {
		case "CERTIFICATE":
			c, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, nil, err
			}
			cert = c
		case "ENCRYPTED PRIVATE KEY":
			if password == nil {
				return nil, nil, NewMdkError(CERTIFICATE_ERROR, 1, "encrypted private key requires password")
			}
			k, err := pkcs8.ParsePKCS8PrivateKeyECDSA(block.Bytes, password)
			if err != nil && err.Error() == "pkcs8: incorrect password" {
				NewMdkError(INCORRECT_PASSWORD, 0, err.Error())
			}
			if err != nil {
				return nil, nil, NewMdkError(CERTIFICATE_ERROR, 0, err.Error())
			}
			pkey = k
			if len(rest) > 0 {
				data = rest
			} else {
				break
			}
		case "PRIVATE KEY":
			k, err := pkcs8.ParsePKCS8PrivateKeyECDSA(block.Bytes)
			if err != nil {
				return nil, nil, err
			}
			pkey = k
		}
		if rest == nil || len(rest) == 0 {
			break
		}
	}

	if cert.PublicKeyAlgorithm != x509.ECDSA {
		return nil, nil, fmt.Errorf("unsupported certificate algorithm: %s", cert.PublicKeyAlgorithm)
	}

	return cert, pkey, nil
}
