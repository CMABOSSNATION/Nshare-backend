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

import java.security.SecureRandom;

import javax.annotation.Nullable;

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

    // ── Key generation ────────────────────────────────────────────────

    @ReactMethod
    public void generateKeyPair(Promise promise) {
        try {
            byte[] privateKey = new byte[32];
            new SecureRandom().nextBytes(privateKey);
            // Clamp per RFC 7748 §5
            privateKey[0]  &= 248;
            privateKey[31] &= 127;
            privateKey[31] |= 64;

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

    private byte[] derivePublicKey(byte[] privateKey) throws Exception {
        if (android.os.Build.VERSION.SDK_INT >= 33) {
            java.security.KeyFactory kf = java.security.KeyFactory.getInstance("XDH");
            java.security.spec.NamedParameterSpec spec = new java.security.spec.NamedParameterSpec("X25519");
            java.security.PrivateKey priv = kf.generatePrivate(
                new java.security.spec.XECPrivateKeySpec(spec, privateKey.clone()));
            byte[] basePoint = new byte[32];
            basePoint[0] = 9;
            java.security.PublicKey pub = kf.generatePublic(
                new java.security.spec.XECPublicKeySpec(spec,
                    new java.math.BigInteger(1, reverseBytes(basePoint))));
            javax.crypto.KeyAgreement ka = javax.crypto.KeyAgreement.getInstance("XDH");
            ka.init(priv);
            ka.doPhase(pub, true);
            return ka.generateSecret();
        }
        // Android 7-12: BouncyCastle
        Class<?> privCls   = Class.forName("org.bouncycastle.crypto.params.X25519PrivateKeyParameters");
        Object   privParam = privCls.getDeclaredConstructor(byte[].class, int.class).newInstance(privateKey, 0);
        Object   pubParam  = privCls.getMethod("generatePublicKey").invoke(privParam);
        byte[]   out       = new byte[32];
        pubParam.getClass().getMethod("encode", byte[].class, int.class).invoke(pubParam, out, 0);
        return out;
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
                promise.resolve(true);
                return;
            }
            vpnPermissionPromise = promise;
            getCurrentActivity().startActivityForResult(intent, VPN_REQUEST_CODE);
        } catch (Exception e) {
            promise.reject("PERMISSION_ERROR", e.getMessage());
        }
    }

    public void onActivityResult(int requestCode, int resultCode, Intent data) {
        if (requestCode != VPN_REQUEST_CODE || vpnPermissionPromise == null) return;
        vpnPermissionPromise.resolve(resultCode == android.app.Activity.RESULT_OK);
        vpnPermissionPromise = null;
    }

    // ── Start / Stop VPN ──────────────────────────────────────────────

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

    // ── Stats & Debug ─────────────────────────────────────────────────

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

    @ReactMethod public void addListener(String eventName) {}
    @ReactMethod public void removeListeners(int count)    {}
}
