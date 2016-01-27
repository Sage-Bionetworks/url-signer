package org.sagebionetworks.url;

import static org.junit.Assert.*;

import java.net.MalformedURLException;
import java.net.URL;
import java.security.NoSuchAlgorithmException;
import java.util.Date;

import org.junit.Test;

public class UrlSignerUtilsTest {

	@Test
	public void testMakeS3CanonicalString() throws MalformedURLException {
		HttpMethod method = HttpMethod.POST;
		// All of these urls should generate the same canonical form.
		String[] urls = new String[] {
				"https://host.org/path/child?z=one&a=two&signature=abc",
				"http://host.org/path/child?z=one&a=two",
				"http://host.org/path/child?a=two&z=one",
				"http://host.org/path/child?a=two&z=one#refs",
				"http://host.org:8080/path/child?a=two&z=one",
		};
		// All of the urls should generate this canonical form:
		String expectedResult = "POST host.org /path/child?a=two&z=one";
		for (String url : urls) {
			String canonical = UrlSignerUtils.makeS3CanonicalString(method,
					url, "signature");
			assertEquals(expectedResult, canonical);
		}
	}
	
	@Test
	public void testMakeS3CanonicalStringNoParams() throws MalformedURLException{
		HttpMethod method = HttpMethod.GET;
		String url = "http://localhost:8080/foo/bar#refs";
		String expectedResult = "GET localhost /foo/bar";
		String canonical = UrlSignerUtils.makeS3CanonicalString(method,
				url, "signature");
		assertEquals(expectedResult, canonical);
	}
	
	@Test
	public void testMakeS3CanonicalStringSignatrueNull() throws MalformedURLException{
		HttpMethod method = HttpMethod.GET;
		String url = "http://localhost:8080/foo/bar#refs";
		String expectedResult = "GET localhost /foo/bar";
		String signatureName = null;
		String canonical = UrlSignerUtils.makeS3CanonicalString(method,
				url, signatureName);
		assertEquals(expectedResult, canonical);
	}
	
	@Test
	public void testMakeS3CanonicalStringOneParams() throws MalformedURLException{
		HttpMethod method = HttpMethod.PUT;
		String url = "http://somehost.net/foo/bar?bar=";
		String expectedResult = "PUT somehost.net /foo/bar?bar=";
		String canonical = UrlSignerUtils.makeS3CanonicalString(method,
				url, "signature");
		assertEquals(expectedResult, canonical);
	}
	
	@Test
	public void testGenerateSignature() throws MalformedURLException, NoSuchAlgorithmException{
		String credentials = "a super secret password";
		String signatureParameterName = "signature";
		HttpMethod method = HttpMethod.PUT;
		String url = "http://somehost.net/foo/bar?z=one&a=two&expires=123456";
		String signature = UrlSignerUtils.generateSignature(method, url, signatureParameterName, credentials);
		assertNotNull(signature);
		String expected = "38021c71c349926cff566b41a1fbc1e4bbe7a6e7";
		assertEquals(expected, signature);
	}

	@Test
	public void testGeneratePreSignedURL() throws MalformedURLException{
		HttpMethod method = HttpMethod.GET;
		String credentials = "a super secret password";
		Date expires = new Date(123L);
		String url = "https://synapse.org/root/folder";
		URL presigned = UrlSignerUtils.generatePreSignedURL(method, url, expires, credentials);
		assertNotNull(presigned);
		String expectedUrl = "https://synapse.org/root/folder?expiration=123&hmacSignature=932e432399b7761e9447b881462fb257a9f0b9fe";
		assertEquals(expectedUrl, presigned.toString());
	}
	
	@Test
	public void testGeneratePreSignedURLNullExpires() throws MalformedURLException{
		HttpMethod method = HttpMethod.GET;
		String credentials = "a super secret password";
		Date expires = null;
		String url = "http://synapse.org?foo.bar";
		URL presigned = UrlSignerUtils.generatePreSignedURL(method, url, expires, credentials);
		assertNotNull(presigned);
		String expectedUrl = "http://synapse.org?foo.bar=&hmacSignature=3227e3058d877c158aadf8d7bd08a547d3aa15cc";
		assertEquals(expectedUrl, presigned.toString());
	}
	
	@Test (expected=IllegalArgumentException.class)
	public void testGeneratePreSignedURLMethodNull() throws MalformedURLException{
		HttpMethod method = null;
		String credentials = "a super secret password";
		Date expires = new Date(123L);
		String url = "http://synapse.org?foo.bar";
		// call under test.
		UrlSignerUtils.generatePreSignedURL(method, url, expires, credentials);
	}
	
	@Test (expected=IllegalArgumentException.class)
	public void testGeneratePreSignedURLNullURL() throws MalformedURLException{
		HttpMethod method = HttpMethod.GET;
		String credentials = "a super secret password";
		Date expires = new Date(123L);
		String url = null;
		// call under test.
		UrlSignerUtils.generatePreSignedURL(method, url, expires, credentials);
	}
	
	@Test (expected=IllegalArgumentException.class)
	public void testGeneratePreSignedURLCredsNull() throws MalformedURLException{
		HttpMethod method = HttpMethod.GET;
		String credentials = null;
		Date expires = new Date(123L);
		String url = "http://synapse.org?foo.bar";
		// call under test.
		UrlSignerUtils.generatePreSignedURL(method, url, expires, credentials);
	}
	
	@Test
	public void testValidatePresignedURL() throws MalformedURLException, SignatureMismatchException{
		HttpMethod method = HttpMethod.GET;
		String credentials = "a super secret password";
		Date expires = new Date(System.currentTimeMillis()+(30*1000));
		String url = "http://synapse.org?param1=one&a=two";
		
		URL presignedUrl = UrlSignerUtils.generatePreSignedURL(method, url, expires, credentials);
		// this should be valid
		UrlSignerUtils.validatePresignedURL(method, presignedUrl.toString(), credentials);
	}
	
	@Test
	public void testValidatePresignedURLNoExpires() throws MalformedURLException, SignatureMismatchException{
		HttpMethod method = HttpMethod.GET;
		String credentials = "a super secret password";
		Date expires = null;
		String url = "http://synapse.org?param1=one&a=two";
		URL presignedUrl = UrlSignerUtils.generatePreSignedURL(method, url, expires, credentials);
		// this should be valid
		UrlSignerUtils.validatePresignedURL(method, presignedUrl.toString(), credentials);
	}
	
	@Test (expected=SignatureMismatchException.class)
	public void testValidatePresignedURLExpired() throws MalformedURLException, SignatureMismatchException{
		HttpMethod method = HttpMethod.GET;
		String credentials = "a super secret password";
		//expired long ago
		Date expires = new Date(123);
		String url = "http://synapse.org?param1=one&a=two";
		
		URL presignedUrl = UrlSignerUtils.generatePreSignedURL(method, url, expires, credentials);
		// this should be valid
		UrlSignerUtils.validatePresignedURL(method, presignedUrl.toString(), credentials);
	}
	
	@Test (expected=SignatureMismatchException.class)
	public void testValidatePresignedURLMismatch() throws MalformedURLException, SignatureMismatchException{
		HttpMethod method = HttpMethod.GET;
		String credentials = "a super secret password";
		Date expires = new Date(System.currentTimeMillis()+(30*1000));
		String url = "http://synapse.org?param1=one&a=two";
		
		URL presignedUrl = UrlSignerUtils.generatePreSignedURL(method, url, expires, credentials);
		String preUrl = presignedUrl.toString();
		// change the url
		preUrl = preUrl.replace("one", "onne");
		// this should be valid
		UrlSignerUtils.validatePresignedURL(method, preUrl, credentials);
	}
	
	@Test (expected=IllegalArgumentException.class)
	public void testValidatePresignedURLSignatureMissing() throws MalformedURLException, SignatureMismatchException{
		HttpMethod method = HttpMethod.GET;
		String credentials = "a super secret password";
		String url = "http://synapse.org?param1=one&a=two";
		// this should be valid
		UrlSignerUtils.validatePresignedURL(method, url, credentials);
	}
	
	@Test (expected=IllegalArgumentException.class)
	public void testValidatePresignedURLExpiresFormat() throws MalformedURLException, SignatureMismatchException{
		HttpMethod method = HttpMethod.GET;
		String credentials = "a super secret password";
		Date expires = null;
		String url = "http://synapse.org?"+UrlSignerUtils.EXPIRATION+"=notADate";
		URL presignedUrl = UrlSignerUtils.generatePreSignedURL(method, url, expires, credentials);
		// this should be valid
		UrlSignerUtils.validatePresignedURL(method, presignedUrl.toString(), credentials);
	}
}
