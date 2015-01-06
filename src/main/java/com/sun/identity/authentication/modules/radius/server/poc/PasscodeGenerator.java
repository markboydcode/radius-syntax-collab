package com.sun.identity.authentication.modules.radius.server.poc;

import java.util.Random;

/**
 * Generator of variable length integer with each digit of the integer in element of an integer array allowing for
 * preceding zero digits.
 *
 * Created by markboyd on 7/31/14.
 */
public class PasscodeGenerator {

    private static final Random numGen = new Random();

    public static int[] get(int length) {
        int[] code = new int[length];

        for(int i=0; i<length; i++) {
            code[i] = numGen.nextInt(10); // will gen int from 0 to 9 inclusive
        }
        return code;
    }
}
