package com.google.number;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.UnsupportedEncodingException;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

/**
 * Created with IntelliJ IDEA.
 * User: Abbot
 * Date: 2017-11-30
 * Time: 13:43
 * Description:
 * 基于JDK的RSA算法，工作模式采用ECB
 */
public class RSACoder
{
    private static final String ENCODING = "UTF-8";
    private static final String KEY_ALGORITHM = "RSA";//非对称加密密钥算法
    private static final String CIPHER_ALGORITHM = "RSA/ECB/PKCS1Padding";//加解密算法 格式：算法/工作模式/填充模式
    private static final int KEY_SIZE = 512;//非对称密钥长度（512~1024之间的64的整数倍）

    /**
     * 还原公钥
     *
     * @param pubKey 二进制公钥
     */
    public static PublicKey toPublicKey(byte[] pubKey) throws NoSuchAlgorithmException, InvalidKeySpecException
    {
        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);//密钥工厂
        return keyFactory.generatePublic(new X509EncodedKeySpec(pubKey));//还原公钥
    }

    /**
     * 还原私钥
     *
     * @param priKey 二进制私钥
     */
    public static PrivateKey toPrivateKey(byte[] priKey) throws NoSuchAlgorithmException, InvalidKeySpecException
    {
        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);//密钥工厂
        return keyFactory.generatePrivate(new PKCS8EncodedKeySpec(priKey));//还原私钥
    }

    /**
     * 生成甲方密钥对
     */
    public static KeyPair initKey() throws NoSuchAlgorithmException
    {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(KEY_ALGORITHM);//密钥对生成器
        keyPairGenerator.initialize(KEY_SIZE);//指定密钥长度
        KeyPair keyPair = keyPairGenerator.generateKeyPair();//生成密钥对
        return keyPair;
    }

    /**
     * 私钥加密
     *
     * @param data    待加密数据
     * @param keyByte 私钥
     */
    public static byte[] encryptPriKey(String data,
                                       byte[] keyByte) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException,
            IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException
    {
        PrivateKey priKey = toPrivateKey(keyByte);//还原私钥

        Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, priKey);//设置加密模式并且初始化key
        return cipher.doFinal(data.getBytes(ENCODING));
    }

    /**
     * 公钥加密
     *
     * @param data    待加密数据
     * @param keyByte 公钥
     */
    public static byte[] encryptPubKey(String data,
                                       byte[] keyByte) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException,
            IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException
    {
        PublicKey pubKey = toPublicKey(keyByte);//还原公钥

        Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, pubKey);//设置加密模式并且初始化key
        return cipher.doFinal(data.getBytes(ENCODING));
    }

    /**
     * 私钥解密
     *
     * @param data    待解密数据
     * @param keyByte 私钥
     */
    public static byte[] decryptPriKey(byte[] data,
                                       byte[] keyByte) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException,
            IllegalBlockSizeException, BadPaddingException
    {
        PrivateKey priKey = toPrivateKey(keyByte);//还原私钥

        Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, priKey);
        return cipher.doFinal(data);
    }

    /**
     * 公钥解密
     *
     * @param data
     * @param keyByte 公钥
     */
    public static byte[] decryptPubKey(byte[] data,
                                       byte[] keyByte) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException,
            IllegalBlockSizeException, BadPaddingException
    {
        PublicKey pubKey = toPublicKey(keyByte);//还原公钥

        Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, pubKey);
        return cipher.doFinal(data);
    }

    /**
     * 获取公钥
     */
    public static byte[] getPublicKey(KeyPair keyPair)
    {
        return keyPair.getPublic().getEncoded();
    }

    /**
     * 获取私钥
     */
    public static byte[] getPrivateKey(KeyPair keyPair)
    {
        return keyPair.getPrivate().getEncoded();
    }


    /**
     * 公钥加密私钥解密
     * 直接给出加密内容和私钥还原加密的内容。
     *
     * @param sercertData
     * @param privateKey
     * @return
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     * @throws InvalidKeyException
     * @throws InvalidKeySpecException
     * @throws UnsupportedEncodingException
     */
    public static String getYourDataPublicKeyToPrivateKey(String sercertData,
                                                          String privateKey) throws NoSuchPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException,
            BadPaddingException, InvalidKeyException, InvalidKeySpecException, UnsupportedEncodingException
    {
        byte[] dataDecode = Base64.getDecoder().decode(sercertData);
        byte[] bytesPrivateKey = Base64.getDecoder().decode(privateKey);

        byte[] bytes = RSACoder.decryptPriKey(dataDecode, bytesPrivateKey);

        return new String(bytes, "UTF-8");


    }


    /**
     * 私钥加密公钥解密
     * 给出加密内容和公钥直接返回加密内容。
     *
     * @param sercetrData
     * @param publicKey
     * @return
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     * @throws InvalidKeyException
     * @throws InvalidKeySpecException
     * @throws UnsupportedEncodingException
     */
    public static String getYourDataPrivateKeyToPublicKey(String sercetrData,
                                                          String publicKey) throws NoSuchPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException,
            BadPaddingException, InvalidKeyException, InvalidKeySpecException, UnsupportedEncodingException
    {
        byte[] dataDecoder = Base64.getDecoder().decode(sercetrData);

        byte[] bytesPublicKey = Base64.getDecoder().decode(publicKey);

        byte[] bytes = RSACoder.decryptPubKey(dataDecoder, bytesPublicKey);

        return new String(bytes, "UTF-8");

    }

    /**
     * 测试
     */
    public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeyException, InvalidKeySpecException, NoSuchPaddingException, IllegalBlockSizeException,
            BadPaddingException, UnsupportedEncodingException
    {
        byte[] pubKey1;//甲方公钥
        byte[] priKey1;//甲方私钥

        /*********************测试是否可以正确生成以上2个key*********************/
        KeyPair keyPair1 = RSACoder.initKey();//生成甲方密钥对
        pubKey1 = RSACoder.getPublicKey(keyPair1);
        priKey1 = RSACoder.getPrivateKey(keyPair1);

        System.out.println("甲方公钥pubKey1-->" + Base64.getEncoder().encodeToString(pubKey1) + "@@pubKey1.length-->" + pubKey1.length);
        System.out.println("甲方私钥priKey1-->" + Base64.getEncoder().encodeToString(priKey1) + "@@priKey1.length-->" + priKey1.length);

        /*********************测试甲方使用私钥加密数据向乙方发送，乙方使用公钥解密数据*********************/
        System.out.println("甲方-->乙方");
        String data = "永远永远的热爱变编程事业";
        byte[] encodeStr = RSACoder.encryptPriKey(data, priKey1);
        System.out.println("甲方加密后的数据-->" + Base64.getEncoder().encodeToString(encodeStr));
        byte[] decodeStr = RSACoder.decryptPubKey(encodeStr, pubKey1);
        System.out.println("乙方解密后的数据-->" + new String(decodeStr, "UTF-8"));

        /*********************测试乙方使用私钥加密数据向甲方发送，甲方使用公钥解密数据*********************/
        System.out.println("乙方-->甲方");
        String data2 = "google is a wonderful company.";
        byte[] encodeStr2 = RSACoder.encryptPubKey(data2, pubKey1);
        System.out.println("乙方加密后的数据-->" + Base64.getEncoder().encodeToString(encodeStr2));
        byte[] decodeStr2 = RSACoder.decryptPriKey(encodeStr2, priKey1);
        System.out.println("甲方解密后的数据-->" + new String(decodeStr2, "UTF-8"));


        byte[] pubkey2;//A public key.
        byte[] prikey2;//A private key.

        KeyPair keyPair = RSACoder.initKey();//create a key pair.

        byte[] publicKey = RSACoder.getPublicKey(keyPair);

        byte[] privateKey = RSACoder.getPrivateKey(keyPair);

        System.out.println("A public key:" + Base64.getEncoder().encodeToString(publicKey));
        System.out.println("A private key:" + Base64.getEncoder().encodeToString(privateKey));

        byte[] bytesPrivateKey = RSACoder.encryptPriKey("9999999999999999999999", privateKey);

        System.out.println("\n*******************************************************************************");
        System.out.println("加密私钥:" + Base64.getEncoder().encodeToString(privateKey));
        System.out.println("私钥加密以后的数字:" + Base64.getEncoder().encodeToString(bytesPrivateKey));
        System.out.println("*******************************************************************************\n");
        byte[] bytesPublicKey = RSACoder.decryptPubKey(bytesPrivateKey, publicKey);
        System.out.println("\n*******************************************************************************");
        System.out.println("解密公钥:" + Base64.getEncoder().encodeToString(publicKey));
        System.out.println("公钥解密以后的数字:" + new String(bytesPublicKey, "UTF-8"));
        System.out.println("*******************************************************************************\n");

        byte[] bytesPublicKeyEncoder = RSACoder.encryptPubKey("1111111111111111", publicKey);

        byte[] bytesPrivateKeyDecoder = RSACoder.decryptPriKey(bytesPublicKeyEncoder, privateKey);

        System.out.println("\n*******************************************************************************");
        System.out.println("加密公钥:" + Base64.getEncoder().encodeToString(publicKey));
        System.out.println("公钥加密后的数字:" + Base64.getEncoder().encodeToString(bytesPublicKeyEncoder));
        System.out.println("*******************************************************************************\n");

        System.out.println("\n*******************************************************************************");
        System.out.println("解密私钥:" + Base64.getEncoder().encodeToString(privateKey));
        System.out.println("私钥解密后的数字:" + new String(bytesPrivateKeyDecoder, "UTF-8"));
        System.out.println("*******************************************************************************\n");

        String yourDataPublicKeyToPrivateKey = getYourDataPublicKeyToPrivateKey("M4TCgbCH1JOm9zwIQ7ygw3KwNdHJC49yWqSTdpXb093j807cbsxX9owQcFSSUt4ssgfqW+mZxzlaDLYbiqGi/Q==",
                                                                                "MIIBVAIBADANBgkqhkiG9w0BAQEFAASCAT4wggE6AgEAAkEAl2t4t9efEz687qqn2/dyisl5tgDPhChsKUGMiM5LnXq" +
                                                                                        "/ZyFb057k3tkIbS6cfRrtIZwHsVHFjzLMoB91muV1RQIDAQABAkEAlPRePsvYawAur8IletgDT9A+8PH" +
                                                                                        "/MgzpyfP3oaT+8ZyJIcaxNc3je1CuwXaIsTOJZxKdk7yIJ8RntpPLddG/CQIhAMq" +
                                                                                        "+vsPGQptuvcgwldmbGGLvY27i591CHYJgZSnLqTP7AiEAvzFxfRaVmMt" +
                                                                                        "ZBWFemIXiswGL5QNkZ35sLpeUnNsad78CIHZhLY2uI5IR9SoAhF6Mmo6Z7FsAjhW41vYbRrZCvkclAiB/QQVsYG" +
                                                                                        "/" + "Jdu8Vaa1wjwxIYKsgDpXxXG/cwv8jN6HyOQIgPo1eE7cM89oKLjStzmTHcdLKxiMw2/CLO+DhtaHDiIs=");


        System.out.println("yourDataPublicKeyToPrivateKey:" + yourDataPublicKeyToPrivateKey);


        String yourDataPrivateKeyToPublicKey = getYourDataPrivateKeyToPublicKey("UPfC2QjEHpFckdIOsLEevqseXHlBsgUKpCcVlm0U5JV78BK7ky/P9K5aMYmPNDjftV" + "/f8NZTMWM/zNq4IhVLpA==",
                                                                                "MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAJv2IJmXhhQBk/LgNA++tGqJFtj" +
                                                                                        "+V99jsXTfWSgQyDs67sBhlfEYNSRDeBzio7ubuvsY1yt6Xg7OaxZgZwzbVPMCAwEAAQ==");

        System.out.println("yourDataPrivateKeyToPublicKey: " + yourDataPrivateKeyToPublicKey);



    }

}
