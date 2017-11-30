package com.google.number;

import java.security.MessageDigest;

/**
 * Created with IntelliJ IDEA.
 * User: Abbot
 * Date: 2017-11-30
 * Time: 10:52
 * Description:
 */
public class MD5Tool
{
    private final static String[] stringDigits = {"0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "a", "b", "c", "d", "e", "f"};

    public MD5Tool()
    {
    }

    /**
     * 返回形式为数字跟字符串。
     *
     * @param bByte
     * @return
     */
    private static String byteToArrayString(byte bByte)
    {
        int iRet = bByte;
        if (iRet < 0)
        {
            iRet += 256;
        }
        int iD1 = iRet / 16;
        int iD2 = iRet % 16;
        return stringDigits[iD1] + stringDigits[iD2];
    }


    /**
     * 返回只为数字形式
     *
     * @param bByte
     * @return
     */
    private static String byteToNum(byte bByte)
    {
        int iRet = bByte;
        System.out.println("iRet1 = " + iRet);
        if (iRet < 0)
        {
            iRet += 256;
        }
        return String.valueOf(iRet);
    }

    /**
     * 转换字节数组为16进制字符串
     *
     * @param bByte
     * @return
     */
    private static String byteToString(byte[] bByte)
    {
        StringBuffer stringBuffer = new StringBuffer();
        for (int i = 0; i < bByte.length; i++)
        {
            stringBuffer.append(byteToArrayString(bByte[i]));
        }
        return stringBuffer.toString();
    }

    /**
     * 返回32位小写
     *
     * @param strObj
     * @return
     */
    public static String getMD5(String strObj)
    {
        String resultString = null;
        try
        {
            resultString = new String(strObj);
            MessageDigest md = MessageDigest.getInstance("MD5");
            /**
             * md.digest() 该函数返回值为存放哈希值结果的byte数组
             */
            resultString = byteToString(md.digest(strObj.getBytes()));
        } catch (Exception e)
        {
            e.printStackTrace();
        }
        return resultString.toUpperCase();
    }

    public static String getMD5Up(String strObj)
    {
        String resultString = null;
        try
        {
            resultString = new String(strObj);
            MessageDigest md = MessageDigest.getInstance("MD5");
            resultString = byteToString(md.digest(strObj.getBytes()));
            StringBuffer stringBuffer = new StringBuffer();

            for (int i = 0; i < resultString.length(); i++)
            {
                if(resultString.charAt(i) >='a' && resultString.charAt(i) <= 'z')
                {
                    stringBuffer.append((char)(resultString.charAt(i)-32));
                }
                else
                {
                    stringBuffer.append(resultString.charAt(i));
                }
            }
            resultString = stringBuffer.toString();
        } catch (Exception e)
        {
            e.printStackTrace();
        }
        return  resultString;
    }

    public static void main(String[] args)
    {
        String zky = MD5Tool.getMD5("zky");

        System.out.println(zky);
    }

}
