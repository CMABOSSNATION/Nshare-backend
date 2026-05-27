package com.netshare;

import android.content.Intent;
import android.net.VpnService;
import android.util.Log;
import android.util.Base64;

import com.facebook.react.bridge.Arguments;
import com.facebook.react.bridge.Promise;
import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.bridge.ReactContextBaseJavaModule;
import com.facebook.react.bridge.ReactMethod;
import com.facebook.react.bridge.ReadableArray;
import com.facebook.react.bridge.ReadableMap;
import com.facebook.react.bridge.WritableMap;
import com.facebook.react.modules.core.DeviceEventManagerModule;

import java.security.SecureRandom;
import java.util.Arrays;

import javax.annotation.Nullable;

/**
 * VpnModule — React Native ↔ Android bridge (WireGuard edition)
 * ══════════════════════════════════════════════════════════════
 *
 * ═══════ BUG FIXED ═══════
 *
 * BUG — derivePublicKey() generated a RANDOM new KeyPair and returned
 *   its public key, completely ignoring the privateKey argument.
 *   This means every call to generateKeyPair() returned a mismatched pair:
 *   the returned publicKey did NOT correspond to the returned privateKey.
 *   Any WireGuard handshake using this pair was immediately rejected by the VPS.
 *   This caused the VPN to never connect and the app to appear crashed/stuck.
 *
 *   FIX: Use BouncyCastle (always available on Android via the system provider
 *   or bundled in the APK) to derive the public key by scalar multiplication
 *   of the provided private key with the Curve25519 base point.
 *   On Android 13+ (API 33) the XDH KeyFactory is used instead.
 */
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

    // ── WireGuard key generation ──────────────────────────────────────
    /**
     * Generates an X25519 keypair suitable for WireGuard.
     * Returns { privateKey: "<base64>", publicKey: "<base64>" }
     *
     * The private key is clamped per RFC 7748 §5.
     * The public key is correctly derived from the private scalar.
     */
    @ReactMethod
    public void generateKeyPair(Promise promise) {
        try {
            byte[] privateKey = new byte[32];
            new SecureRandom().nextBytes(privateKey);

            // Clamp per RFC 7748 §5
            privateKey[0]  &= 248;
            privateKey[31] &= 127;
            privateKey[31] |= 64;

            // BUG FIX: derive public key from THIS private key (not a random new one)
            byte[] publicKey = derivePublicKey(privateKey);

            WritableMap result = Arguments.createMap();
            result.putString("privateKey", Base64.encodeToString(privateKey, Base64.NO_WRAP));
            result.putString("publicKey",  Base64.encodeToString(publicKey,  Base64.NO_WRAP));
            promise.resolve(result);

        } catch (Exception e) {
            Log.e(TAG, "generateKeyPair failed", e);
            promise.reject("KEYGEN_ERROR", e.getMessage());
        }
    }

    /**
     * Derives the Curve25519 public key from the given private scalar.
     *
     * Android 13+ (API 33): uses the native XDH KeyFactory.
     * Android 7–12 (API 24–32): uses BouncyCastle via reflection
     *   (BouncyCastle ships inside every Android ROM as part of the
     *    Conscrypt / spongycastle provider — no extra dependency needed).
     *
     * IMPORTANT: the old code called kpg.generateKeyPair() which creates a
     * FRESH random pair and ignores the private key argument entirely.
     * This is the root-cause bug that broke the handshake and made the
     * app appear to crash.
     */
    private byte[] derivePublicKey(byte[] privateKey) throws Exception {
        if (android.os.Build.VERSION.SDK_INT >= 33) {
            // Android 13+: native X25519 via XDH KeyFactory
            java.security.KeyFactory kf = java.security.KeyFactory.getInstance("XDH");
            java.security.spec.NamedParameterSpec spec = new java.security.spec.NamedParameterSpec("X25519");
            java.security.PrivateKey priv = kf.generatePrivate(
                new java.security.spec.XECPrivateKeySpec(spec, privateKey.clone()));

            // Derive the public key: create a KeyPair using a wrapper that
            // accepts the private scalar (Android 13+ supports this via
            // XECPrivateKeySpec → private key → PKCS8 encoding → public key derivation)
            // The correct portable approach on API 33: use KeyAgreement with base point.
            // We do scalar*basePoint by performing DH with the well-known base point (u=9).
            byte[] basePoint = new byte[32];
            basePoint[0] = 9; // Curve25519 base point u-coordinate = 9
            java.security.PublicKey pub = kf.generatePublic(
                new java.security.spec.XECPublicKeySpec(spec,
                    new java.math.BigInteger(1, reverseBytes(basePoint))));
            javax.crypto.KeyAgreement ka = javax.crypto.KeyAgreement.getInstance("XDH");
            ka.init(priv);
            ka.doPhase(pub, true);
            byte[] raw = ka.generateSecret(); // = privateKey * basePoint = publicKey
            return raw;
        }

        // Android 7-12: BouncyCastle via reflection
        try {
            Class<?> privCls  = Class.forName("org.bouncycastle.crypto.params.X25519PrivateKeyParameters");
            Object   privParam = privCls.getDeclaredConstructor(byte[].class, int.class)
                                        .newInstance(privateKey, 0);
            Object   pubParam  = privCls.getMethod("generatePublicKey").invoke(privParam);
            byte[]   out       = new byte[32];
            pubParam.getClass()
                    .getMethod("encode", byte[].class, int.class)
                    .invoke(pubParam, out, 0);
            return out;
        } catch (ClassNotFoundException e) {
            throw new UnsupportedOperationException(
                "X25519 key derivation failed: BouncyCastle not found and API < 33. " +
                "Add 'implementation org.bouncycastle:bcprov-jdk15on:1.70' to app/build.gradle.");
        }
    }

    private static byte[] reverseBytes(byte[] b) {
        byte[] r = b.clone();
        for (int i = 0, j = r.length - 1; i < j; i++, j--) {
            byte t = r[i]; r[i] = r[j]; r[j] = t;
        }
        return r;
    }

    // ── VPN permission ────────────────────────────────────────────────

    @ReactMethod
    public void requestVpnPermission(Promise promise) {
        try {
            Intent intent = VpnService.prepare(getCurrentActivity());
            if (intent == null) {
                // Already granted
                promise.resolve(true);
                return;
            }
            vpnPermissionPromise = promise;
            getCurrentActivity().startActivityForResult(intent, VPN_REQUEST_CODE);
        } catch (Exception e) {
            promise.reject("PERMISSION_ERROR", e.getMessage());
        }
    }

    /** Called from MainActivity.onActivityResult */
    public void onActivityResult(int requestCode, int resultCode, Intent data) {
        if (requestCode != VPN_REQUEST_CODE || vpnPermissionPromise == null) return;
        boolean granted = (resultCode == android.app.Activity.RESULT_OK);
        vpnPermissionPromise.resolve(granted);
        vpnPermissionPromise = null;
    }

    // ── Start / Stop VPN ──────────────────────────────────────────────

    /**
     * config shape:
     * {
     *   serverEndpoint:  "1.2.3.4:51820",
     *   serverPublicKey: "<base64>",
     *   clientPrivateKey:"<base64>",
     *   clientPublicKey: "<base64>",
     *   clientIp:        "10.8.0.5",
     *   sessionCode:     "ABCD-EFGH",
     *   role:            "host" | "client",
     *   appPackages:     ["com.example.app"]   // split-tunnel list
     * }
     */
    @ReactMethod
    public void startVpn(ReadableMap config, Promise promise) {
        try {
            // Validate VPN permission
            Intent permIntent = VpnService.prepare(reactContext);
            if (permIntent != null) {
                promise.reject("NO_PERMISSION", "VPN permission not granted — call requestVpnPermission() first");
                return;
            }

            Intent intent = new Intent(reactContext, NetShareVpnService.class);
            intent.putExtra("SERVER_ENDPOINT",    config.getString("serverEndpoint"));
            intent.putExtra("SERVER_PUBLIC_KEY",  config.getString("serverPublicKey"));
            intent.putExtra("CLIENT_PRIVATE_KEY", config.getString("clientPrivateKey"));
            intent.putExtra("CLIENT_PUBLIC_KEY",  config.getString("clientPublicKey"));
            intent.putExtra("CLIENT_IP",          config.getString("clientIp"));
            intent.putExtra("SESSION_CODE",       config.hasKey("sessionCode")  ? config.getString("sessionCode")  : "");
            intent.putExtra("ROLE",               config.hasKey("role")         ? config.getString("role")         : "client");

            // Serialize app packages array for split-tunnel
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
                // Service may be running without a reference — send stop intent
                Intent intent = new Intent(reactContext, NetShareVpnService.class);
                intent.setAction("STOP_VPN");
                reactContext.startService(intent);
            }
            promise.resolve(true);
        } catch (Exception e) {
            promise.reject("STOP_ERROR", e.getMessage());
        }
    }

    // ── Bandwidth stats ───────────────────────────────────────────────

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

    // ── Debug log ─────────────────────────────────────────────────────

    @ReactMethod
    public void getDebugLog(Promise promise) {
        promise.resolve(NetShareVpnService.getDebugLog());
    }

    // ── Event emitter ─────────────────────────────────────────────────

    static void emitEvent(String name, String data) {
        try {
            ReactApplicationContext ctx = _staticContext;
            if (ctx == null) return;
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

    // Required for RN event listener registration
    @ReactMethod public void addListener(String eventName)  {}
    @ReactMethod public void removeListeners(int count)     {}
}
