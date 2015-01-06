package com.sun.identity.authentication.modules.radius.server.poc;


import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.util.Properties;

/**
 * Triggers based upon a user's profile and maintainer of pairings file.
 *
 * Created by markboyd on 6/28/14.
 */
public class UsersProfile {
    private File usrToopherDevicePairsFile = null;

    public static String PAIRING_FILE = "./usrDevicePairs.properties";
    public static final String PAIRING_FILE_COMMENT = "Username to device pairing ID Map";
    private static  File pairsFile = new File(PAIRING_FILE);

    public static Properties getPairings() {

        Properties pairings = new Properties();

        try {
            if (pairsFile.exists()) {
                FileReader fr = new FileReader(pairsFile);
                pairings.load(fr);
                fr.close();
            }
        }
        catch(IOException e) {
            System.out.println("   -- Unable to load pairings file " + pairsFile.getAbsolutePath() + ", Details: " + e.getMessage());
            e.printStackTrace();
        }
        System.out.println("   ------ total pairings: " + pairings.size());
        return pairings;
    }

    public static void addPairing(String username, String pairingId) {
        Properties pairings = getPairings();
        pairings.setProperty(username, pairingId);

        try {
            FileWriter fw = new FileWriter(pairsFile);
            pairings.store(fw, PAIRING_FILE_COMMENT);
            fw.flush();
            fw.close();
        }
        catch(IOException e) {
            System.out.println("   -- Unable to store pairings file " + pairsFile.getAbsolutePath() + ", Details: " + e.getMessage());
            e.printStackTrace();
        }
        System.out.println("   ------ total pairings now: " + pairings.size());
    }

    private static Trigger hasNoDevicePairingTrigger = new Trigger() {
        @Override
        public boolean isTriggered(RequestInfo req, Context ctx) {
            // load user to device pairing ids
            req.devicePairingId = getPairings().getProperty(req.username);
            return req.devicePairingId == null;
        }
    };

    public static Trigger hasNoDevicePairing() {
        return hasNoDevicePairingTrigger;
    }
//
//    /**
//     * Checks to see if user has toopher pairing and if so places the pairing id in Context.toopherPairingId.
//     *
//     * @return
//     */
//    public static Trigger hasDevicePairing() {
//        return new Trigger() {
//            @Override
//            public boolean isTriggered(RequestInfo req, Context ctx) {
//                req.devicePairingId = getPairings().getProperty(req.username);
//                return req.devicePairingId != null;
//            }
//        };
//    }
}
