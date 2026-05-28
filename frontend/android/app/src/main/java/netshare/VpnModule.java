package netshare;

import android.content.Intent;
import android.net.VpnService;
import android.util.Base64;
import android.util.Log;

import com.facebook.react.bridge.Arguments;
import com.facebook.react.bridge.Promise;
import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.bridge.ReactContextBaseJavaModule;
import com.facebook.react.bridge.ReactMethod;
import com.facebook.react.bridge.ReadableArray;
import com.facebook.react.bridge.ReadableMap;
import com.facebook.react.bridge.WritableMap;
import com.facebook.react.modules.core.DeviceEventManagerModule;

import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class VpnModule extends ReactContextBaseJavaModule {

    private static final String TAG              = "VpnModule";
    private static final int    VPN_REQUEST_CODE = 0x0F00;

    static volatile NetShareVpnService activeService = null;

    private final ReactApplicationContext reactContext;
    private Promise vpnPermissionPromise;

    public VpnModule(ReactApplicationContext reactContext) {
        super(reactContext);
        this.reactContext = reactContext;
    }

    @Override
    public String getName() { return "VpnModule"; }

    // ── Key generation ─────────────────────────────────────────────────
    // Uses X25519 via Conscrypt (installed by NetShareVpnService static block)
    // Works on all Android versions — no BouncyCastle needed

    @ReactMethod
    public void generateKeyPair(Promise promise) {
        new Thread(() -> {
            try {
                // Generate clamped X25519 private key
                byte[] privateKey = new byte[32];
                new SecureRandom().nextBytes(privateKey);
                privateKey[0]  &= 248;
                privateKey[31] &= 127;
                privateKey[31] |= 64;

                byte[] publicKey = derivePublicKeyFromPrivate(privateKey);

                WritableMap result = Arguments.createMap();
                result.putString("privateKey", Base64.encodeToString(privateKey, Base64.NO_WRAP));
                result.putString("publicKey",  Base64.encodeToString(publicKey,  Base64.NO_WRAP));
                promise.resolve(result);
            } catch (Exception e) {
                Log.e(TAG, "generateKeyPair failed", e);
                promise.reject("KEYGEN_ERROR", e.getMessage());
            }
        }).start();
    }

    private static byte[] derivePublicKeyFromPrivate(byte[] privateKey) throws Exception {
        // Build PKCS8 wrapper for X25519 private key
        // ASN.1: SEQUENCE { INTEGER 0, SEQUENCE { OID 1.3.101.110 }, OCTET STRING { OCTET STRING <key> } }
        byte[] pkcs8Prefix = new byte[]{
            0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06,
            0x03, 0x2b, 0x65, 0x6e, 0x04, 0x22, 0x04, 0x20
        };
        byte[] pkcs8 = new byte[pkcs8Prefix.length + 32];
        System.arraycopy(pkcs8Prefix, 0, pkcs8, 0, pkcs8Prefix.length);
        System.arraycopy(privateKey, 0, pkcs8, pkcs8Prefix.length, 32);

        KeyFactory kf = KeyFactory.getInstance("X25519");
        java.security.PrivateKey priv = kf.generatePrivate(new PKCS8EncodedKeySpec(pkcs8));

        // Extract public key from private key via KeyPair generation trick
        // Conscrypt supports this — generate a fresh pair, then replace private key bytes
        // Actually: use KeyPairGenerator to get a keypair, extract the public key format,
        // then use X25519 agreement with base point to get our public key
        // Simpler: use base point multiplication via agreement
        byte[] basePoint = new byte[32];
        basePoint[0] = 9;

        // Build SubjectPublicKeyInfo for base point
        byte[] spkiPrefix = new byte[]{
            0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65,
            0x6e, 0x03, 0x21, 0x00
        };
        byte[] spki = new byte[spkiPrefix.length + 32];
        System.arraycopy(spkiPrefix, 0, spki, 0, spkiPrefix.length);
        System.arraycopy(basePoint, 0, spki, spkiPrefix.length, 32);
        java.security.PublicKey pubBasePoint = kf.generatePublic(new X509EncodedKeySpec(spki));

        javax.crypto.KeyAgreement ka = javax.crypto.KeyAgreement.getInstance("X25519");
        ka.init(priv);
        ka.doPhase(pubBasePoint, true);
        return ka.generateSecret();
    }

    // ── VPN permission ─────────────────────────────────────────────────

    @ReactMethod
    public void requestVpnPermission(Promise promise) {
        try {
            android.app.Activity activity = getCurrentActivity();
            if (activity == null) {
                // No activity yet — check if permission already granted
                Intent intent = VpnService.prepare(reactContext);
                if (intent == null) {
                    promise.resolve(true);
                } else {
                    promise.reject("NO_ACTIVITY", "No foreground activity to show VPN permission dialog");
                }
                return;
            }
            Intent intent = VpnService.prepare(activity);
            if (intent == null) {
                promise.resolve(true);
                return;
            }
            vpnPermissionPromise = promise;
            activity.startActivityForResult(intent, VPN_REQUEST_CODE);
        } catch (Exception e) {
            promise.reject("PERMISSION_ERROR", e.getMessage());
        }
    }

    public void onActivityResult(int requestCode, int resultCode, Intent data) {
        if (requestCode != VPN_REQUEST_CODE || vpnPermissionPromise == null) return;
        vpnPermissionPromise.resolve(resultCode == android.app.Activity.RESULT_OK);
        vpnPermissionPromise = null;
    }

    // ── Start / Stop VPN ───────────────────────────────────────────────

    @ReactMethod
    public void startVpn(ReadableMap config, Promise promise) {
        try {
            if (VpnService.prepare(reactContext) != null) {
                promise.reject("NO_PERMISSION", "Call requestVpnPermission() first");
                return;
            }

            Intent intent = new Intent(reactContext, NetShareVpnService.class);
            intent.putExtra("SERVER_ENDPOINT",    config.getString("serverEndpoint"));
            intent.putExtra("SERVER_PUBLIC_KEY",  config.getString("serverPublicKey"));
            intent.putExtra("CLIENT_PRIVATE_KEY", config.getString("clientPrivateKey"));
            intent.putExtra("CLIENT_PUBLIC_KEY",  config.getString("clientPublicKey"));
            intent.putExtra("CLIENT_IP",          config.getString("clientIp"));
            intent.putExtra("SESSION_CODE", config.hasKey("sessionCode") ? config.getString("sessionCode") : "");
            intent.putExtra("ROLE",         config.hasKey("role")        ? config.getString("role")        : "client");

            if (config.hasKey("appPackages")) {
                ReadableArray pkgs = config.getArray("appPackages");
                org.json.JSONArray arr = new org.json.JSONArray();
                if (pkgs != null) {
                    for (int i = 0; i < pkgs.size(); i++) arr.put(pkgs.getString(i));
                }
                intent.putExtra("APP_PACKAGES", arr.toString());
            }

            reactContext.startForegroundService(intent);
            promise.resolve(true);
        } catch (Exception e) {
            Log.e(TAG, "startVpn failed", e);
            promise.reject("START_ERROR", e.getMessage());
        }
    }

    @ReactMethod
    public void stopVpn(Promise promise) {
        try {
            if (activeService != null) {
                activeService.stopVpnClean();
            } else {
                Intent intent = new Intent(reactContext, NetShareVpnService.class);
                intent.setAction("STOP_VPN");
                reactContext.startService(intent);
            }
            promise.resolve(true);
        } catch (Exception e) {
            promise.reject("STOP_ERROR", e.getMessage());
        }
    }

    // ── Stats & Debug ──────────────────────────────────────────────────

    @ReactMethod
    public void getBandwidthStats(Promise promise) {
        try {
            WritableMap stats = Arguments.createMap();
            if (activeService != null) {
                long[] s = activeService.getBandwidthStats();
                stats.putDouble("bytesSent",     (double) s[0]);
                stats.putDouble("bytesReceived", (double) s[1]);
            } else {
                stats.putDouble("bytesSent",     0);
                stats.putDouble("bytesReceived", 0);
            }
            promise.resolve(stats);
        } catch (Exception e) {
            promise.reject("STATS_ERROR", e.getMessage());
        }
    }

    @ReactMethod
    public void getDebugLog(Promise promise) {
        promise.resolve(NetShareVpnService.getDebugLog());
    }

    // ── Event emitter ──────────────────────────────────────────────────

    static void emitEvent(String name, String data) {
        try {
            ReactApplicationContext ctx = _staticContext;
            if (ctx == null || !ctx.hasActiveReactInstance()) return;
            WritableMap params = Arguments.createMap();
            params.putString("data", data);
            ctx.getJSModule(DeviceEventManagerModule.RCTDeviceEventEmitter.class)
               .emit(name, params);
        } catch (Exception e) {
            Log.w(TAG, "emitEvent(" + name + ") failed: " + e.getMessage());
        }
    }

    private static volatile ReactApplicationContext _staticContext;

    @Override
    public void initialize() {
        super.initialize();
        _staticContext = reactContext;
    }

    @Override
    public void invalidate() {
        _staticContext = null;
        super.invalidate();
    }

    @ReactMethod public void addListener(String eventName) {}
    @ReactMethod public void removeListeners(int count)    {}
}
