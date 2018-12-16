package CipherPackage;

import javax.crypto.*;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import java.security.*;
import java.security.spec.X509EncodedKeySpec;

import android.util.Base64;

public class User {
    // AES keys
    private String[] sessionPair_ = new String[2];
    private String[] DHPair_ = new String[2];
    
    public User(User mainUser) {
        try {
            // AES key generation
            if(mainUser == null) {    
                // Random strings 
                
            	SecureRandom random = new SecureRandom();
                char[] alphanum = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz".toCharArray();
                char[][] strings = new char[2][16];
                for(int str = 0; str < 2; ++str) {
                    for (int i = 0; i < 16; ++i) {
                        strings[str][i] = alphanum[random.nextInt(alphanum.length)];
                    }
                    sessionPair_[str] = new String(strings[str]);
                } 
            	/*SecureRandom secureRandom = new SecureRandom();
            	KeyGenerator keyGenerator = KeyGenerator.getInstance("AES"); 
            	keyGenerator.init(128, secureRandom);
            	SecretKey secretKey = keyGenerator.generateKey();
            	sessionPair_[0] = Base64.encodeToString(secretKey.getEncoded(), Base64.DEFAULT);
            	System.out.print("\n" + sessionPair_[0] + "\n");
            	
            	byte[] initializationVector = new byte[16]; 
                SecureRandom prng = new SecureRandom(); 
                prng.nextBytes(initializationVector); 
                sessionPair_[1] = Base64.encodeToString(initializationVector, Base64.DEFAULT);
                System.out.print("\n" + sessionPair_[1] + "\n");*/
            }
            else{ 
            	DHGenerateUser(mainUser);
            }
        }
        catch(Exception ex) {
            ex.printStackTrace();
        }
    }
    
    // DH - methods
    private void DHGenerateUser(User mainUser) throws Exception {
    	// ���� ������ ���� 2048 ���
    	SecureRandom secureRandom = new SecureRandom();
        KeyPairGenerator userKpairGen = KeyPairGenerator.getInstance("DH");
        userKpairGen.initialize(1024, secureRandom);
        KeyPair userKpair = userKpairGen.generateKeyPair();
        
        // ���� ������ DH KeyAgreement ������ (��������� ����) � ����������� ��������� ���� � �����
        KeyAgreement userKeyAgree = KeyAgreement.getInstance("DH");
        userKeyAgree.init(userKpair.getPrivate());
        // ���������� ������ ������
        byte[] userPubKeyEnc = userKpair.getPublic().getEncoded();
        String userPubKeyEncStr = Base64.encodeToString(userPubKeyEnc, Base64.DEFAULT);
        
        // ��� �����
        DHPair_[0] = Base64.encodeToString(userKpair.getPublic().getEncoded(), Base64.DEFAULT);
        DHPair_[1] = Base64.encodeToString(userKpair.getPrivate().getEncoded(), Base64.DEFAULT);
        
        // �������� ��� ����, ���������� ���� � ��������� ����������
        String[] result = mainUser.DHGenerateAdmin(userPubKeyEncStr);
             
        byte[] adminPubKeyEnc = Base64.decode(result[0], Base64.DEFAULT); 
        byte[] cipherString1 = Base64.decode(result[1], Base64.DEFAULT);
        byte[] cipherString2 = Base64.decode(result[2], Base64.DEFAULT);
        byte[] encodedParams = Base64.decode(result[3], Base64.DEFAULT);
        
        // �������� �� ������ ���� ������ � ��������� � ������ �������
        KeyFactory userKeyFac = KeyFactory.getInstance("DH");
        X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(adminPubKeyEnc);
        PublicKey adminPubKey = userKeyFac.generatePublic(x509KeySpec); 
        
        userKeyAgree.doPhase(adminPubKey, true);
        byte[] userSharedSecret = userKeyAgree.generateSecret();
        
        // ��������� AES ����	
        SecretKeySpec userAesKey = new SecretKeySpec(userSharedSecret, 0, 16, "AES");
        // ��������� ��������� ���������� � ���� AES ����
        AlgorithmParameters aesParams = AlgorithmParameters.getInstance("AES");
        aesParams.init(encodedParams);      
        // ������ ���� � ����������� ����������� ����������
        Cipher userCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        userCipher.init(Cipher.DECRYPT_MODE, userAesKey, aesParams);
        
        // �������������� ���������� ����
        sessionPair_[0] = new String(userCipher.doFinal(cipherString1));
        sessionPair_[1] = new String(userCipher.doFinal(cipherString2));
    }
    
    private String[] DHGenerateAdmin(String userPubKeyEncStr) throws Exception {
        // ����� �� ������ ����� ��������� � ��������� ���� 
    	byte[] userPubKeyEnc = Base64.decode(userPubKeyEncStr, Base64.DEFAULT);
        KeyFactory adminKeyFac = KeyFactory.getInstance("DH");
        X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(userPubKeyEnc);
        PublicKey userPubKey = adminKeyFac.generatePublic(x509KeySpec); 

        // ����� �������� ��������� ����� ����� � �� �� ������ ������ ���� ����������� ������
        DHParameterSpec dhParamFromuserPubKey = ((DHPublicKey)userPubKey).getParams();
        SecureRandom secureRandom = new SecureRandom();
        KeyPairGenerator adminKpairGen = KeyPairGenerator.getInstance("DH");
        adminKpairGen.initialize(dhParamFromuserPubKey, secureRandom);
        KeyPair adminKpair = adminKpairGen.generateKeyPair();
        
        // ��� �����
        DHPair_[0] = Base64.encodeToString(adminKpair.getPublic().getEncoded(), Base64.DEFAULT);
        DHPair_[1] = Base64.encodeToString(adminKpair.getPrivate().getEncoded(), Base64.DEFAULT);
        
        // ����� ������ DH KeyAgreement ������ (��������� ����) � ����������� ��������� ���� � �����
        KeyAgreement adminKeyAgree = KeyAgreement.getInstance("DH");
        adminKeyAgree.init(adminKpair.getPrivate());
        byte[] adminPubKeyEnc = adminKpair.getPublic().getEncoded();
        // ��������� ���� ����� � ������ �������
        adminKeyAgree.doPhase(userPubKey, true);
        byte[] adminSharedSecret = adminKeyAgree.generateSecret();
        
        // ��������� AES ���� � ������� �� ���� ��������� ����
        SecretKeySpec adminAesKey = new SecretKeySpec(adminSharedSecret, 0, 16, "AES");
        // ������ ����, ��������� ��� � ��������� ����������
        Cipher adminCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        adminCipher.init(Cipher.ENCRYPT_MODE, adminAesKey);
        
        // ����� �������� ������������� ����� � ��������� ����������
        byte[] cipherString1 = adminCipher.doFinal(sessionPair_[0].getBytes());
        byte[] cipherString2 = adminCipher.doFinal(sessionPair_[1].getBytes());
        byte[] encodedParams = adminCipher.getParameters().getEncoded();
        
        // ���������������� ����� � ����� � ��������
        String[] resultString = new String[4];
        resultString[0] = Base64.encodeToString(adminPubKeyEnc, Base64.DEFAULT);
        resultString[1] = Base64.encodeToString(cipherString1, Base64.DEFAULT);
        resultString[2] = Base64.encodeToString(cipherString2, Base64.DEFAULT);
        resultString[3] = Base64.encodeToString(encodedParams, Base64.DEFAULT);
        
        return resultString;
    }
    
    // AES methods - ��� ���������� ���������
    public String encrypt(String value) {
        try {
            IvParameterSpec iv = new IvParameterSpec(sessionPair_[1].getBytes("UTF-8"));
            SecretKeySpec skeySpec = new SecretKeySpec(sessionPair_[0].getBytes("UTF-8"), "AES");

            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
            cipher.init(Cipher.ENCRYPT_MODE, skeySpec, iv);

            byte[] encrypted = cipher.doFinal(value.getBytes());

            return Base64.encodeToString(encrypted, Base64.DEFAULT);
        } catch (Exception ex) {
            ex.printStackTrace();
        }
        return null;
    }

    public String decrypt(String encrypted) {
        try {
            IvParameterSpec iv = new IvParameterSpec(sessionPair_[1].getBytes("UTF-8"));
            SecretKeySpec skeySpec = new SecretKeySpec(sessionPair_[0].getBytes("UTF-8"), "AES");

            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
            cipher.init(Cipher.DECRYPT_MODE, skeySpec, iv);

            byte[] original = cipher.doFinal(Base64.decode(encrypted, Base64.DEFAULT));

            return new String(original);
        } catch (Exception ex) {
            ex.printStackTrace();
        }
        return null;
    }
    
    public String[] getSessionPair() {
    	return sessionPair_;
    }
    
    public String[] getDHPair() {
    	return DHPair_;
    }
}
