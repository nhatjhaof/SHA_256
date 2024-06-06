package com.gCode;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;
import java.util.Vector;

public class SHA_256 {
	public static List<Integer> convertToBinary(String s) {
        List<Integer> binary = new ArrayList<>();
        for (char c : s.toCharArray()) {
            int byteValue = c;
            for (int i = 7; i >= 0; i--) {
                binary.add((byteValue >> i) & 1);
            }
        }
        return binary;
    }

    public static List<Integer> padTo512Bits(List<Integer> binary) {
        int messageLength = binary.size();
        int paddingLength = 448 - (messageLength % 512);
        if (paddingLength < 0) {
            paddingLength += 512;
        }
        List<Integer> paddedBinary = new ArrayList<Integer>(binary);
        paddedBinary.add(1);
        for (int i = 0; i < paddingLength - 1; i++) {
            paddedBinary.add(0);
        }
        long messageLengthBits = messageLength * 8L;
        for (int i = 56; i >= 0; i -= 8) {
            paddedBinary.add((int) ((messageLengthBits >> i) & 0xFF));
        }
        return paddedBinary;
    }

    public static List<Long> resizeBlock(List<Integer> paddedBinary) {
        List<Long> block = new ArrayList<>();
        for (int i = 0; i < paddedBinary.size(); i += 32) {
            long word = 0;
            for (int j = 0; j < 32; j++) {
                word |= (long) paddedBinary.get(i + j) << (31 - j);
            }
            block.add(word);
        }
        return block;
    }

    public static String computeHash(List<Long> block) {
        long[] h = {
            0x6a09e667L, 0xbb67ae85L, 0x3c6ef372L, 0xa54ff53aL,
            0x510e527fL, 0x9b05688cL, 0x1f83d9abL, 0x5be0cd19L
        };

        for (int i = 0; i < block.size(); i += 16) {
            long[] w = new long[64];
            for (int j = 0; j < 16; j++) {
                w[j] = block.get(i + j);
            }
            for (int j = 16; j < 64; j++) {
                long s0 = Long.rotateRight(w[j - 15], 7) ^ Long.rotateRight(w[j - 15], 18) ^ (w[j - 15] >>> 3);
                long s1 = Long.rotateRight(w[j - 2], 17) ^ Long.rotateRight(w[j - 2], 19) ^ (w[j - 2] >>> 10);
                w[j] = (w[j - 16] + s0 + w[j - 7] + s1) & 0xFFFFFFFFL;
            }

            long a = h[0], b = h[1], c = h[2], d = h[3], e = h[4], f = h[5], g = h[6], hh = h[7];

            for (int j = 0; j < 64; j++) {
                long S1 = Long.rotateRight(e, 6) ^ Long.rotateRight(e, 11) ^ Long.rotateRight(e, 25);
                long ch = (e & f) ^ (~e & g);
                long temp1 = (hh + S1 + ch + 0x428a2f98d728ae22L + w[j]) & 0xFFFFFFFFL;
                long S0 = Long.rotateRight(a, 2) ^ Long.rotateRight(a, 13) ^ Long.rotateRight(a, 22);
                long maj = (a & b) ^ (a & c) ^ (b & c);
                long temp2 = (S0 + maj) & 0xFFFFFFFFL;

                hh = g;
                g = f;
                f = e;
                e = (d + temp1) & 0xFFFFFFFFL;
                d = c;
                c = b;
                b = a;
                a = (temp1 + temp2) & 0xFFFFFFFFL;
            }

            h[0] = (h[0] + a) & 0xFFFFFFFFL;
            h[1] = (h[1] + b) & 0xFFFFFFFFL;
            h[2] = (h[2] + c) & 0xFFFFFFFFL;
            h[3] = (h[3] + d) & 0xFFFFFFFFL;
            h[4] = (h[4] + e) & 0xFFFFFFFFL;
            h[5] = (h[5] + f) & 0xFFFFFFFFL;
            h[6] = (h[6] + g) & 0xFFFFFFFFL;
            h[7] = (h[7] + hh) & 0xFFFFFFFFL;
        }

        StringBuilder sb = new StringBuilder();
        for (long value : h) {
            sb.append(String.format("%08x", value));
        }
        return sb.toString();
    }

    public static void main(String[] args) {
        System.out.println("Enter a message:");
        Scanner scanner = new Scanner(System.in);
        String message = scanner.nextLine();

        List<Integer> binary = convertToBinary(message);
        List<Integer> paddedBinary = padTo512Bits(binary);
        List<Long> block = resizeBlock(paddedBinary);
        String hash = computeHash(block);

        System.out.println("SHA-256 hash of \"" + message + "\": " + hash);
    }
}
