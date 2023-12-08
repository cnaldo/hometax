import java.io.ByteArrayInputStream;
import org.apache.commons.io.FileUtils;
import java.io.File;
import java.io.IOException;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.crypto.PBEParametersGenerator;
import org.bouncycastle.crypto.generators.PKCS5S2ParametersGenerator;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import java.security.PrivateKey;
import java.security.Security;
import java.security.KeyFactory;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.MessageDigest;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.cert.CertificateEncodingException;

import java.util.Base64;
import java.util.HashMap;
import java.io.FileInputStream;
import java.io.FileReader;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.List;
import java.util.Map;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import org.w3c.dom.Document;
import org.w3c.dom.NodeList;

import java.io.DataOutputStream;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;

public class Hometax {
    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public static void main(String[] args) {
        try {
            String keyFilePath = "resource/signPri.key"; // 개인 키 파일 경로
            String derFilePath = "resource/signCert.der";
            String password = ""; // 개인 키 파일의 비밀번호

            // 개인키 객체 추출
            PrivateKey privateKey = readPrivateKey(keyFilePath, password);
            System.out.println("Private Key: " + privateKey + "\n\n");

            // 홈텍스 한번 접속하여 서명할 문자열 추출
            Map<String, String> hometaxInfo = getHometaxInfo();

            // 1. 서명할 원본 값(pkcEncSsn)
            String pkcEncSsn = hometaxInfo.get("pkcEncSsn");
            System.out.println("1. 서명할 원본 값(pkcEncSsn): " + pkcEncSsn + "\n\n");

            // 2. 서명용 공개키에서 얻은 인증서 일련번호
            // DER 형식의 파일을 X.509 인증서로 로드
            String certSerialNumber = extractSerialNumber(derFilePath);
            System.out.println("2. 서명용 공개키에서 얻은 인증서 일련번호: " + certSerialNumber + "\n\n");

            // 3. pkcEncSsn 값을 전자서명한 값
            String signedValue = signData(pkcEncSsn, privateKey);
            System.out.println("3. pkcEncSsn 값을 전자서명한 값: " + signedValue + "\n\n");

            // 4.서명용 공개키에서 얻은 PEM 타입의 인증서 문자열
            // String cert = readPemFile("src/main/java/signCert.pem");
            String cert = derToPem(derFilePath);
            System.out.println("4. 서명용 공개키에서 얻은 PEM 타입의 인증서 문자열: " + cert + "\n\n");

            // 5. 서명용 개인키에서 얻은 Random 값
            String randomEnc = getRValue(keyFilePath, password);
            System.out.println("5. 서명용 개인키에서 얻은 Random 값: " + randomEnc + "\n\n");

            // WMONID와 TXPPsessionID 값을 가져오기
            String wmonId = hometaxInfo.get("WMONID");
            String txppSessionId = hometaxInfo.get("TXPPsessionID");

            // 쿠키 문자열 생성
            String cookieString = String.format(
                    "WMONID=%s; NTS_LOGIN_SYSTEM_CODE_P=TXPP; TXPPsessionID=%s",
                    wmonId, txppSessionId);

            System.out.println("Cookie String: " + cookieString + "\n\n");

            // 서명용 공개키의 PEM 값, Base64 인코딩한 값, 서명용 개인키의 Random 값 설정
            // 조합 및 인코딩
            String logSgnt = combineAndEncode(pkcEncSsn, certSerialNumber, signedValue);
            System.out.println("Encoded String: " + logSgnt + "\n\n");

            System.out.println("Cert: " + cert + "\n\n");
            System.out.println("LogSgnt: " + logSgnt + "\n\n");
            System.out.println("RandomEnc: " + randomEnc + "\n\n");
            System.out.println("CookieString: " + cookieString + "\n\n");

            // POST 요청 보내기
            String jsonpResponse = sendPostRequest(cert, logSgnt, randomEnc, cookieString);
            // System.out.println("Response: " + jsonpResponse+"\n\n");
            // URL 디코딩
            String decodedString = URLDecoder.decode(jsonpResponse, StandardCharsets.UTF_8.toString());
            System.out.println("Decoded String: " + decodedString + "\n\n");

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static PrivateKey readPrivateKey(String filePath, String passwd) throws Exception {
        byte[] encodedKey = FileUtils.readFileToByteArray(new File(filePath));
        byte[] decryptedKey = getDecryptedKey(encodedKey, passwd);

        PKCS8EncodedKeySpec ks = new PKCS8EncodedKeySpec(decryptedKey);
        KeyFactory kf = KeyFactory.getInstance("RSA", "BC");
        return kf.generatePrivate(ks);
    }

    public static String getRValue(String filePath, String passwd) throws Exception {
        byte[] encodedKey = FileUtils.readFileToByteArray(new File(filePath));
        byte[] decryptedKey = getDecryptedKey(encodedKey, passwd);

        try (ByteArrayInputStream bIn2 = new ByteArrayInputStream(decryptedKey);
                ASN1InputStream aIn2 = new ASN1InputStream(bIn2);) {

            ASN1Object asn1Object = aIn2.readObject();
            ASN1Sequence seq = (ASN1Sequence) asn1Object;
            // DLSequence seq = (DLSequence)asn1Object.toASN1Object();

            int i = 0;
            while (i < seq.size()) {

                if (seq.getObjectAt(i) instanceof DLTaggedObject) {
                    DLTaggedObject dlTaggedObject = (DLTaggedObject) seq.getObjectAt(i);

                    if (dlTaggedObject.getTagNo() == 0) {
                        DLSequence seq2 = (DLSequence) dlTaggedObject.getObject();

                        int j = 0;
                        while (j < seq2.size()) {

                            if (seq2.getObjectAt(j) instanceof ASN1ObjectIdentifier) {
                                ASN1ObjectIdentifier idRandomNumOID = (ASN1ObjectIdentifier) seq2.getObjectAt(j);

                                if ("1.2.410.200004.10.1.1.3".equals(idRandomNumOID.toString())) {
                                    DLSet dlSet = (DLSet) seq2.getObjectAt(j + 1);

                                    DERBitString DERBitString = (DERBitString) dlSet.getObjectAt(0);

                                    return Base64.getEncoder().encodeToString(DERBitString.getOctets());
                                }
                            }

                            j++;
                        }

                    }

                }

                i++;
            }

        } catch (Exception e) {
            // logger.error("getRValue 오류", e);
        }
        return null; // RValue를 찾지 못한 경우
    }

    private static byte[] getDecryptedKey(byte[] keyDER, String passwd) throws Exception {
        byte[] decryptedKey = null;

        org.bouncycastle.asn1.pkcs.EncryptedPrivateKeyInfo encryptedPrivateKeyInfo = null;
        try (ByteArrayInputStream bIn = new ByteArrayInputStream(keyDER);
                ASN1InputStream aIn = new ASN1InputStream(bIn);) {

            ASN1Sequence asn1Sequence = (ASN1Sequence) aIn.readObject();

            AlgorithmIdentifier algId = AlgorithmIdentifier.getInstance(asn1Sequence.getObjectAt(0));
            ASN1OctetString data = ASN1OctetString.getInstance(asn1Sequence.getObjectAt(1));

            encryptedPrivateKeyInfo = new org.bouncycastle.asn1.pkcs.EncryptedPrivateKeyInfo(algId, data.getEncoded());

            String privateKeyAlgName = encryptedPrivateKeyInfo.getEncryptionAlgorithm().getAlgorithm().getId();

            if ("1.2.840.113549.1.5.13".equals(privateKeyAlgName)) { // pkcs5PBES2

                // --------------------------------
                // 개인키 암호화 정보에서 Salt, Iteration Count(IC), Initial Vector(IV)를 가져오는 로직
                // --------------------------------
                ASN1Sequence asn1Sequence2 = (ASN1Sequence) algId.getParameters();
                ASN1Sequence asn1Sequence3 = (ASN1Sequence) asn1Sequence2.getObjectAt(0);
                // PBKDF2 Key derivation algorithm
                ASN1Sequence asn1Sequence33 = (ASN1Sequence) asn1Sequence3.getObjectAt(1);
                // Salt 값
                DEROctetString derOctetStringSalt = (DEROctetString) asn1Sequence33.getObjectAt(0);
                // Iteration Count(IC)
                ASN1Integer asn1IntegerIC = (ASN1Integer) asn1Sequence33.getObjectAt(1);

                ASN1Sequence asn1Sequence4 = (ASN1Sequence) asn1Sequence2.getObjectAt(1);
                // Initial Vector(IV)
                DEROctetString derOctetStringIV = (DEROctetString) asn1Sequence4.getObjectAt(1);

                // --------------------------------
                // 복호화 키 생성
                // --------------------------------
                int keySize = 256;
                PBEParametersGenerator generator = new PKCS5S2ParametersGenerator();
                generator.init(
                        PBEParametersGenerator.PKCS5PasswordToBytes(passwd.toCharArray()),
                        derOctetStringSalt.getOctets(),
                        asn1IntegerIC.getValue().intValue());

                byte[] iv = derOctetStringIV.getOctets();

                KeyParameter key = (KeyParameter) generator.generateDerivedParameters(keySize);

                // --------------------------------
                // 복호화 수행
                // --------------------------------
                IvParameterSpec ivSpec = new IvParameterSpec(iv);
                SecretKeySpec secKey = new SecretKeySpec(key.getKey(), "SEED");

                Cipher cipher = Cipher.getInstance("SEED/CBC/PKCS5Padding", "BC");
                cipher.init(Cipher.DECRYPT_MODE, secKey, ivSpec);
                decryptedKey = cipher.doFinal(data.getOctets());

            } else { // 1.2.410.200004.1.15 seedCBCWithSHA1
                ASN1Sequence asn1Sequence2 = (ASN1Sequence) algId.getParameters();

                // Salt 값
                DEROctetString derOctetStringSalt = (DEROctetString) asn1Sequence2.getObjectAt(0);

                // Iteration Count(IC)
                ASN1Integer asn1IntegerIC = (ASN1Integer) asn1Sequence2.getObjectAt(1);

                // --------------------------------
                // 복호화 키 생성
                // --------------------------------
                byte[] dk = new byte[20];
                MessageDigest md = MessageDigest.getInstance("SHA1");
                md.update(passwd.getBytes());
                md.update(derOctetStringSalt.getOctets());
                dk = md.digest();
                for (int i = 1; i < asn1IntegerIC.getValue().intValue(); i++) {
                    dk = md.digest(dk);
                }

                byte[] keyData = new byte[16];
                System.arraycopy(dk, 0, keyData, 0, 16);
                byte[] digestBytes = new byte[4];
                System.arraycopy(dk, 16, digestBytes, 0, 4);

                MessageDigest digest = MessageDigest.getInstance("SHA-1");
                digest.reset();
                digest.update(digestBytes);
                byte[] div = digest.digest();

                // --------------------------------
                // Initial Vector(IV) 생성
                // --------------------------------
                byte[] iv = new byte[16];
                System.arraycopy(div, 0, iv, 0, 16);
                if ("1.2.410.200004.1.4".equals(privateKeyAlgName)) {
                    iv = "012345678912345".getBytes();
                }

                // --------------------------------
                // 복호화 수행
                // --------------------------------
                IvParameterSpec ivSpec = new IvParameterSpec(iv);
                SecretKeySpec secKey = new SecretKeySpec(keyData, "SEED");

                Cipher cipher = Cipher.getInstance("SEED/CBC/PKCS5Padding", "BC");
                cipher.init(Cipher.DECRYPT_MODE, secKey, ivSpec);
                decryptedKey = cipher.doFinal(data.getOctets());
            }

            return decryptedKey;
        }
    }

    public static String signData(String data, PrivateKey privateKey) throws Exception {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(privateKey);
        signature.update(data.getBytes());
        byte[] signedData = signature.sign();

        // 서명을 Base64로 인코딩
        return Base64.getEncoder().encodeToString(signedData);
    }

    public static Map<String, String> getHometaxInfo() {
        Map<String, String> result = new HashMap<>();

        try {
            String urlString = "https://www.hometax.go.kr/wqAction.do?actionId=ATXPPZXA001R01&screenId=UTXPPABA01";
            URL url = new URL(urlString);
            HttpURLConnection connection = (HttpURLConnection) url.openConnection();

            // 요청 방식 설정
            connection.setRequestMethod("GET");

            // 응답 본문 가져오기
            BufferedReader in = new BufferedReader(new InputStreamReader(connection.getInputStream()));
            String inputLine;
            StringBuilder response = new StringBuilder();

            while ((inputLine = in.readLine()) != null) {
                response.append(inputLine);
            }
            in.close();

            // 응답 본문에서 pkcEncSsn 값 추출
            String pkcEncSsn = extractPkcEncSsn(response.toString());
            if (pkcEncSsn != null) {
                result.put("pkcEncSsn", pkcEncSsn);
            }

            // 쿠키 추출
            Map<String, List<String>> headerFields = connection.getHeaderFields();
            List<String> cookiesHeader = headerFields.get("Set-Cookie");

            if (cookiesHeader != null) {
                for (String cookie : cookiesHeader) {
                    if (cookie.startsWith("WMONID")) {
                        result.put("WMONID", cookie.split(";\\s*")[0].split("=")[1]);
                    }
                    if (cookie.startsWith("TXPPsessionID")) {
                        result.put("TXPPsessionID", cookie.split(";\\s*")[0].split("=")[1]);
                    }
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }

        return result;
    }

    private static String extractPkcEncSsn(String xmlResponse) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        DocumentBuilder builder = factory.newDocumentBuilder();
        Document doc = builder.parse(new java.io.ByteArrayInputStream(xmlResponse.getBytes()));
        NodeList nodes = doc.getElementsByTagName("pkcEncSsn");
        if (nodes.getLength() > 0) {
            return nodes.item(0).getTextContent();
        }
        return null;
    }

    public static String sendPostRequest(String cert, String logSgnt, String randomEnc, String cookieString) throws Exception {
        String url = "https://www.hometax.go.kr/pubcLogin.do?domain=hometax.go.kr&mainSys=Y";
        URL obj = new URL(url);
        HttpURLConnection con = (HttpURLConnection) obj.openConnection();

        // POST 요청 설정
        con.setRequestMethod("POST");
        con.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
        con.setRequestProperty("Cookie", cookieString);
        con.setDoOutput(true);

        // 요청 출력
        System.out.println("Request URL: " + url);
        System.out.println("Request Method: " + con.getRequestMethod());
        Map<String, List<String>> requestHeaders = con.getRequestProperties();
        for (Map.Entry<String, List<String>> entry : requestHeaders.entrySet()) {
            String headerName = entry.getKey();
            List<String> headerValues = entry.getValue();
            for (String value : headerValues) {
                System.out.println("Request Header: " + headerName + ": " + value);
            }
        }

        String urlParameters = String.format(
                "cert=%s&logSgnt=%s&pkcLgnClCd=04&pkcLoginYnImpv=Y&randomEnc=%s",
                cert, logSgnt, randomEnc);
        // 요청 본문 출력
        System.out.println("Request Body: " + urlParameters);

        // 요청 전송
        try (DataOutputStream wr = new DataOutputStream(con.getOutputStream())) {
            wr.writeBytes(urlParameters);
            wr.flush();
        }

        // 응답 받기
        StringBuilder response = new StringBuilder();
        try (BufferedReader in = new BufferedReader(new InputStreamReader(con.getInputStream()))) {
            String line;
            while ((line = in.readLine()) != null) {
                response.append(line);
            }
        }

        // 응답 출력
        System.out.println("Response Headers: " + con.getHeaderFields());
        System.out.println("Response Body: " + response.toString());

        return response.toString();
    }

    public static String readPemFile(String filename) throws IOException {
        StringBuilder pemContents = new StringBuilder();
        try (BufferedReader br = new BufferedReader(new FileReader(filename))) {
            String line;
            while ((line = br.readLine()) != null) {
                pemContents.append(line).append("\n");
            }
        }
        return pemContents.toString();
    }

    public static String combineAndEncode(String pkcEncSsn, String certSerialNumber, String signedValue) {
        // 현재 날짜와 시간을 yyyyMMddHHmmss 형식으로 포맷팅
        SimpleDateFormat sdf = new SimpleDateFormat("yyyyMMddHHmmss");
        String currentDate = sdf.format(new Date());

        // 값을 $로 구분하여 결합
        String combined = pkcEncSsn + "$" + certSerialNumber + "$" + currentDate + "$" + signedValue;

        // Base64로 인코딩
        String encoded = Base64.getEncoder().encodeToString(combined.getBytes());

        return encoded;
    }

    public static String extractSerialNumber(String derFilePath) {
        try {
            // DER 형식의 파일을 X.509 인증서로 로드
            FileInputStream fis = new FileInputStream(derFilePath);
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509Certificate certificate = (X509Certificate) cf.generateCertificate(fis);

            // 일련번호 추출
            String certSerialNumber = certificate.getSerialNumber().toString();

            fis.close();
            return certSerialNumber;
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    public static String derToPem(String derFilePath) throws IOException {
        FileInputStream inputStream = new FileInputStream(derFilePath);
        CertificateFactory certificateFactory;
        X509Certificate certificate = null;

        try {
            certificateFactory = CertificateFactory.getInstance("X.509");
            certificate = (X509Certificate) certificateFactory.generateCertificate(inputStream);
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            inputStream.close();
        }

        if (certificate != null) {
            try {
                // Convert to PEM format
                String encodedCert = Base64.getEncoder().encodeToString(certificate.getEncoded());
                StringBuilder pemCertificate = new StringBuilder();
                pemCertificate.append("-----BEGIN CERTIFICATE-----");
                pemCertificate.append(encodedCert);
                pemCertificate.append("-----END CERTIFICATE-----");
                // pemCertificate.append("-----BEGIN CERTIFICATE-----\n");
                // pemCertificate.append(encodedCert).append("\n");
                // pemCertificate.append("-----END CERTIFICATE-----\n");
                return pemCertificate.toString();
            } catch (CertificateEncodingException e) {
                e.printStackTrace();
            }
        }

        return null;
    }
}
