package com.tommygina;

import org.gmssl.Random;
import org.gmssl.Sm3;
import org.gmssl.Sm2Key;
import org.gmssl.Sm2Certificate;
import org.gmssl.Sm2Signature;


import org.gmssl.Sm4;
import org.gmssl.Sm4Cbc;


import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;

public class Main {

    // 将base64转化为String
    public static String base64ToString(String base64Str) {
        // 解码为字节数组
        byte[] decodedBytes = Base64.getDecoder().decode(base64Str);
        // 转换为字符串（默认 UTF-8）
        return new String(decodedBytes, StandardCharsets.UTF_8);
    }

    // 去掉bytes中的0字节
    public static byte[] filterNonZeroBytes(byte[] original) {
        if (original == null) {
            return new byte[0]; // 返回空数组或抛出 IllegalArgumentException
        }

        // 统计非零元素数量
        int count = 0;
        for (byte b : original) {
            if (b != 0) {
                count++;
            }
        }

        // 创建新数组并复制非零元素
        byte[] result = new byte[count];
        int index = 0;
        for (byte b : original) {
            if (b != 0) {
                result[index++] = b;
            }
        }
        return result;
    }


    // 获取去掉16
    public static byte[] getLose16Byte(byte[] source) {
        validateArray(source);
        int splitIndex = source.length - 16;
        return Arrays.copyOfRange(source, 0, splitIndex);
    }

    // 获取前半部分数据
    public static byte[] getFirstHalf(byte[] source) {
        validateArray(source);
        int splitIndex = source.length / 2;
        return Arrays.copyOfRange(source, 0, splitIndex);
    }

    // 获取后半部分数据
    public static byte[] getSecondHalf(byte[] source) {
        validateArray(source);
        int splitIndex = source.length / 2;
        return Arrays.copyOfRange(source, splitIndex, source.length);
    }

    // 校验数组有效性
    private static void validateArray(byte[] source) {
        if (source == null) {
            throw new IllegalArgumentException("数组不能为 null");
        }
        if (source.length == 0) {
            throw new IllegalArgumentException("数组长度不能为 0");
        }
    }

    public static void SM4Test() {
        byte[] key = "qazxswed89iujkmn".getBytes();
        byte[] iv = "0011223344556677".getBytes();




        // String s = "abc";
        // String s = "0123456789abcdefg"; // n77N8rUppK7UUYzzzdDwucbAaiwRRKtKSY0UHCB1f1M=
        String s = "0123456789abcdefg0123456789abcdefg"; // n77N8rUppK7UUYzzzdDwufelqj78k5BIRUVA9t2i1FXCEQ1Q3UF/oeRha3aYGU5/
        int sLength = s.getBytes().length;
        int x = (int)Math.ceil((double)sLength / Sm4Cbc.BLOCK_SIZE);
        byte[] ciphertext = new byte[Sm4Cbc.BLOCK_SIZE * (x + 1)];

        int cipherlen;
        int plainlen;
        boolean encrypt = true;
        boolean decrypt = false;

        Sm4Cbc sm4Cbc = new Sm4Cbc();
        sm4Cbc.init(key, iv, encrypt);
        cipherlen = sm4Cbc.update(s.getBytes(), 0, sLength, ciphertext, 0);
        cipherlen += sm4Cbc.doFinal(ciphertext, cipherlen);

        int y = (int)Math.ceil((double) cipherlen / Sm4Cbc.BLOCK_SIZE);
        byte[] plaintext = new byte[Sm4Cbc.BLOCK_SIZE * (y + 1)];

        String base64Str = Base64.getEncoder().encodeToString(getLose16Byte(ciphertext));
        System.out.printf(base64Str);
        System.out.print("\n");

        sm4Cbc.init(key, iv, decrypt);
        plainlen = sm4Cbc.update(ciphertext, 0, cipherlen, plaintext, 0);
        plainlen += sm4Cbc.doFinal(plaintext, plainlen);

//        Base64.getDecoder().decode(getFirstHalf(plaintext));
        base64Str = Base64.getEncoder().encodeToString(plaintext);
        System.out.printf("明文未去0: " + base64Str);
        System.out.print("\n");

        byte[] tmp = getLose16Byte(plaintext);

        base64Str = Base64.getEncoder().encodeToString(filterNonZeroBytes(plaintext));
        System.out.printf("明文已去0: " + base64Str);
        System.out.print("\n");

        base64Str = base64ToString(base64Str);
        System.out.printf("明文： " + base64Str);
        System.out.print("\n");
    }


    public static void SM2Test() {

    }


    // SM3哈希算法测试
    public static void SM3Test() {
        // sm3 一次性哈希
        Sm3 sm3 = new Sm3();
        sm3.update("abc".getBytes());

        byte[] dgst = sm3.digest();

        // 输出HEX格式
        int i;
        System.out.printf("sm3('abc') HEX: \t\t");
        for (i = 0; i < dgst.length; i++) {
            System.out.printf("%02x", dgst[i]);
        }
        System.out.print("\n");

        // 输出Base64格式
        System.out.printf("sm3('abc') Base64: \t\t");
        String base64Str = Base64.getEncoder().encodeToString(dgst);
        System.out.printf(base64Str);
        System.out.print("\n");
    }

    public static void main(String[] args) {
        // SM2Test();
        // SM3Test();
        SM4Test();

    }
}



