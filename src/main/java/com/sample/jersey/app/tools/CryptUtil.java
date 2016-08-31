package com.sample.jersey.app.tools;


import com.synjones.security.KeyReader;
import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;

/*
*	文件:CryptUtil.java
*	日期				作�?			改变情况
*	10/02/2009			steven cheng			创建
*/

/**
 * <p></p>
 * <p>Copyright (c) 2004 Drian. All rights reserved</p>
 * <p>@(#) CryptUtil.java 创建日期 10/02/2009</p>
 * <p>@author <a href="mailto:alf.163.com@163.com">steve cheng </a></p>
 * <p>@version 0.1 </p>
 *
 *
 */

public class CryptUtil {

    public static String[] encrypt(String p12FileName, String cerFileName2, String text){
        try {
//			String p12FileName = "D:/OneCard/key/web-client.p12";
            String pfxPassword = "openssl";
            String keyAlias = "web-client";
//			String cerFileName2 = "D:/OneCard/key/web-client11.cer";
            PrivateKey privatekey = KeyReader.PrivateKey(p12FileName, pfxPassword,
                    keyAlias);
            PublicKey publickey = KeyReader.Publickey(cerFileName2);
            KeyGenerator keygen = KeyGenerator.getInstance("DES");
            SecretKey key = keygen.generateKey();
            byte[] plainText = text.getBytes();
            MessageDigest dig = MessageDigest.getInstance("MD5");
            dig.update(plainText);
            byte[] digMessage = dig.digest();

            Signature sign = Signature.getInstance("MD5withRSA");
            sign.initSign(privatekey);
            sign.update(digMessage);
            byte[] sigText = sign.sign();

            BASE64Encoder b64Encoder = new BASE64Encoder();
            StringBuffer sb = new StringBuffer();

            sb.append("xmlmess=").append(b64Encoder.encode(text.getBytes())).append("&");
            sb.append("mess=").append(b64Encoder.encode(sigText));

            byte[] cryptText = desEncrypt(sb.toString().getBytes(),key);

            byte[] cryptKey = rsaPublicKeyEncrypt(key.getEncoded(),publickey);

            StringBuffer result = new StringBuffer();
            return new String[]{b64Encoder.encode(cryptText),b64Encoder.encode(cryptKey)};

        } catch (Exception e) {
            e.printStackTrace();
        }

        return null;
    }

    public static String decrypt(String fmsg,String gmsg){
        try {
            String p12FileName = "c:/key/web-client.p12";
            String pfxPassword = "openssl";
            String keyAlias = "web-client";
            String cerFileName2 = "c:/key/web-client11.cer";
            PrivateKey privatekey = KeyReader.PrivateKey(p12FileName, pfxPassword,
                    keyAlias);
            PublicKey publickey = KeyReader.Publickey(cerFileName2);
            String keyStr = gmsg;
            String textStr = fmsg;
            BASE64Decoder b64Decoder = new BASE64Decoder();
            byte[] keyBytes = b64Decoder.decodeBuffer(keyStr);

            byte[] decryptKey = rsaPrivateKeyDecrypt(keyBytes,privatekey);
            SecretKey key = generateSecretKeyFromBytes(decryptKey);
            byte[] textBytes = b64Decoder.decodeBuffer(textStr);
            byte[] decryptText = desDecrypt(textBytes,key);

            String text = new String(decryptText);

            String[] texts = text.split("&");


            String textBase64 = texts[0].substring(texts[0].indexOf("=")+1,texts[0].length());

            String signStr = texts[1].substring(texts[1].indexOf("=")+1,texts[1].length());

            byte[] sign = b64Decoder.decodeBuffer(signStr);

            MessageDigest dig = MessageDigest.getInstance("MD5");
            dig.update(b64Decoder.decodeBuffer(textBase64));
            byte[] digMessage = dig.digest();

            Signature signature = Signature.getInstance("MD5withRSA");
            signature.initVerify(publickey);
            signature.update(digMessage);

            if (signature.verify(sign)) {
                return new String(b64Decoder.decodeBuffer(textBase64),"GBK");
            }else {
                System.out.println("no check");
            }


        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * DescribeSecretKey
     * @param key a <code>byte</code> value
     * @return a <code>Secretkey</code> value
     * @exception Exception if an error occurs
     */
    public static SecretKey generateSecretKeyFromBytes(byte[] key) throws Exception{
        DESKeySpec dks = new DESKeySpec(key);
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DES");
        return keyFactory.generateSecret(dks);
    }

    /**
     * Describe <code>desEncrypt</code> method here.
     * Des
     * @param input a <code>byte</code> value
     * @param key a <code>SecretKey</code> value
     * @return a <code>byte[]</code> value
     */
    public static byte[] desEncrypt(byte[] input,SecretKey key) throws Exception{
        Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE,key);
        return cipher.doFinal(input);
    }

    /**
     * Describe <code>desDecrypt</code> method here.
     * DES
     * @param input a <code>byte</code> value
     * @param key a <code>SecretKey</code> value
     * @return a <code>byte[]</code> value
     * @exception Exception if an error occurs
     */
    public static byte[] desDecrypt(byte[] input,SecretKey key) throws Exception{
        Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE,key);
        return cipher.doFinal(input);
    }


    public static byte[] rsaPublicKeyEncrypt(byte[] input,PublicKey key) throws Exception{
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE,key);
        return cipher.doFinal(input);
    }

    public static byte[] rsaPrivateKeyDecrypt(byte[] input,PrivateKey key) throws Exception{
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE,key);
        return cipher.doFinal(input);
    }

//	public static void main(String[] args) throws Exception{
//
//	}

}
