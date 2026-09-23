//go:build windows

package nettrust

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"strings"
	"syscall"
	"unsafe"
)

// hcceLocalMachine is the machine chain engine (HCCE_LOCAL_MACHINE): trust
// anchored in the LocalMachine stores only, which a non-elevated program
// cannot change. Go's default verifier uses the current user's engine, whose
// Root store any program of the user may add to.
const hcceLocalMachine = syscall.Handle(1)

// CERT_CHAIN_RETURN_LOWER_QUALITY_CONTEXTS (not in package syscall)
const certChainReturnLowerQualityContexts = 0x00000080

func tlsConfig() *tls.Config {
	return &tls.Config{
		// The standard verification is replaced, not skipped: every
		// handshake is checked by verifyConnection below
		InsecureSkipVerify: true,
		VerifyConnection:   verifyConnection,
		MinVersion:         tls.VersionTLS12,
	}
}

func verifyConnection(cs tls.ConnectionState) error {
	if len(cs.PeerCertificates) == 0 {
		return errors.New("tls: the server sent no certificate")
	}
	if cs.ServerName == "" {
		return errors.New("tls: no server name to verify against")
	}
	return verifyMachine(cs.PeerCertificates[0], cs.PeerCertificates[1:], cs.ServerName)
}

// verifyMachine builds and checks the chain like crypto/x509's Windows
// verifier, but with the machine chain engine, then applies the SSL server
// policy (host name included)
func verifyMachine(leaf *x509.Certificate, intermediates []*x509.Certificate, serverName string) error {
	leafCtx, err := syscall.CertCreateCertificateContext(syscall.X509_ASN_ENCODING|syscall.PKCS_7_ASN_ENCODING, &leaf.Raw[0], uint32(len(leaf.Raw)))
	if err != nil {
		return err
	}
	defer syscall.CertFreeCertificateContext(leafCtx)

	store, err := syscall.CertOpenStore(syscall.CERT_STORE_PROV_MEMORY, 0, 0, syscall.CERT_STORE_DEFER_CLOSE_UNTIL_LAST_FREE_FLAG, 0)
	if err != nil {
		return err
	}
	defer syscall.CertCloseStore(store, 0)

	var storeCtx *syscall.CertContext
	if err := syscall.CertAddCertificateContextToStore(store, leafCtx, syscall.CERT_STORE_ADD_ALWAYS, &storeCtx); err != nil {
		return err
	}
	defer syscall.CertFreeCertificateContext(storeCtx)
	for _, ic := range intermediates {
		ctx, err := syscall.CertCreateCertificateContext(syscall.X509_ASN_ENCODING|syscall.PKCS_7_ASN_ENCODING, &ic.Raw[0], uint32(len(ic.Raw)))
		if err != nil {
			return err
		}
		err = syscall.CertAddCertificateContextToStore(store, ctx, syscall.CERT_STORE_ADD_ALWAYS, nil)
		syscall.CertFreeCertificateContext(ctx)
		if err != nil {
			return err
		}
	}

	para := new(syscall.CertChainPara)
	para.Size = uint32(unsafe.Sizeof(*para))
	oids := []*byte{&syscall.OID_PKIX_KP_SERVER_AUTH[0], &syscall.OID_SERVER_GATED_CRYPTO[0], &syscall.OID_SGC_NETSCAPE[0]}
	para.RequestedUsage.Type = syscall.USAGE_MATCH_TYPE_OR
	para.RequestedUsage.Usage.Length = uint32(len(oids))
	para.RequestedUsage.Usage.UsageIdentifiers = &oids[0]

	var chain *syscall.CertChainContext
	if err := syscall.CertGetCertificateChain(hcceLocalMachine, storeCtx, nil, storeCtx.Store, para,
		certChainReturnLowerQualityContexts, 0, &chain); err != nil {
		return err
	}
	defer syscall.CertFreeCertificateChain(chain)

	if status := chain.TrustStatus.ErrorStatus; status != syscall.CERT_TRUST_NO_ERROR {
		switch {
		case status&syscall.CERT_TRUST_IS_NOT_TIME_VALID != 0:
			return fmt.Errorf("tls: certificate of %s has expired or is not yet valid", serverName)
		default:
			return fmt.Errorf("tls: certificate of %s is not trusted by this machine (chain status %#x)", serverName, status)
		}
	}

	name, err := syscall.UTF16PtrFromString(strings.TrimSuffix(serverName, "."))
	if err != nil {
		return err
	}
	ssl := &syscall.SSLExtraCertChainPolicyPara{AuthType: syscall.AUTHTYPE_SERVER, ServerName: name}
	ssl.Size = uint32(unsafe.Sizeof(*ssl))
	policy := &syscall.CertChainPolicyPara{ExtraPolicyPara: (syscall.Pointer)(unsafe.Pointer(ssl))}
	policy.Size = uint32(unsafe.Sizeof(*policy))
	var result syscall.CertChainPolicyStatus
	if err := syscall.CertVerifyCertificateChainPolicy(syscall.CERT_CHAIN_POLICY_SSL, chain, policy, &result); err != nil {
		return err
	}
	if result.Error != 0 {
		return fmt.Errorf("tls: certificate of %s rejected by the SSL policy (%#x)", serverName, result.Error)
	}
	return nil
}
