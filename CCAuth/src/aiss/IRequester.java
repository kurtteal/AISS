package aiss;

import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

public interface IRequester {
	void initPteid();
	void closePteid();
	byte[] sign(byte[] bytes); //cifra
	byte[] getCitizenAuthCertInBytes() throws CertificateException;
	X509Certificate getCertFromByteArray(byte[] certificate_bytes) throws CertificateException;
}
