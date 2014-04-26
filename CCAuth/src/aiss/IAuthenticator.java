package aiss;

import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

public interface IAuthenticator {
	void initPteid();
	void closePteid();
	void showStuff();
	X509Certificate getCertFromByteArray(byte[] request) throws CertificateException;
	boolean verifySignedNonce(PublicKey myPublicKey, String nonce, byte[] signed_nonce);
}
