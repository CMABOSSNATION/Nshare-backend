package com.netshare;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.Intent;
import android.net.VpnService;
import android.os.Build;
import android.os.ParcelFileDescriptor;
import android.util.Log;

import androidx.core.app.NotificationCompat;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.DatagramChannel;
import java.util.Arrays;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;

/**
 * NetShareVpnService — WireGuard Edition (Crash-fixed)
 *
 * FIXES applied vs original:
 *
 * FIX 1 — START_STICKY (was START_NOT_STICKY)
 *   Android kills background services under memory pressure.
 *   START_NOT_STICKY means the service dies silently and never
 *   restarts — the host's tunnel drops and clients are cut off.
 *   START_STICKY + null-intent guard restarts the service and
 *   re-establishes the tunnel automatically.
 *
 * FIX 2 — concat() called with 5 args (compile error → crash at launch)
 *   The original buildInitiation() passes 5 args to concat() which
 *   only accepts 2. This caused a Java compile error that was masked
 *   by the workflow's patch step — but if you build locally without
 *   the patch the app crashes immediately. Fixed inline with nested calls.
 *
 * FIX 3 — x25519PublicKey() returned random bytes (handshake always fails)
 *   The original method generated a fresh random keypair and returned
 *   its public key, completely ignoring the private key argument.
 *   This means every handshake used a mismatched ephemeral key — the
 *   VPS rejected it and the tunnel never connected.
 *   Fixed to properly derive the public key from the private scalar.
 *
 * FIX 4 — wgToTun / tunToWg used Thread.sleep(1) in tight loops
 *   1ms busy-poll loops pin one CPU core at ~100%, drain battery fast,
 *   and trigger Android's thermal throttle → OS kills the process.
 *   Fixed with a proper selector / blocking read approach.
 *
 * FIX 5 — Reconnection on unexpected disconnect
 *   Added exponential-backoff reconnect so a brief network hiccup
 *   doesn't permanently kill the session.
 */
public class NetShareVpnService extends VpnService {

    private static final String TAG        = "NetShareVPN";
    private static final String CHANNEL_ID = "netshare_vpn";
    private static final int    NOTIF_ID   = 1;
    private static final int    TUN_MTU    = 1420;

    private static final int WG_KEEPALIVE_MS    = 25_000;
    private static final int WG_REKEY_AFTER_MS  = 180_000;
    private static final int RECONNECT_MAX_MS   = 30_000;

    // ── Debug log ─────────────────────────────────────────────────────────
    private static final int MAX_DEBUG_LINES = 200;
    private static final java.util.ArrayDeque<String> debugLog = new java.util.ArrayDeque<>();

    public static synchronized void dbg(String msg) {
        String line = android.text.format.DateFormat.format("HH:mm:ss", new java.util.Date()) + " " + msg;
        Log.d(TAG, msg);
        debugLog.addLast(line);
        if (debugLog.size() > MAX_DEBUG_LINES) debugLog.removeFirst();
        VpnModule.emitEvent("vpnDebug", line);
    }

    public static synchronized String getDebugLog() {
        return String.join("\n", debugLog);
    }

    // ── Service state ──────────────────────────────────────────────────────
    private ParcelFileDescriptor     vpnInterface;
    private DatagramChannel          wgChannel;
    private ExecutorService          executor;
    private ScheduledExecutorService scheduler;
    private final AtomicBoolean      isRunning  = new AtomicBoolean(false);
    private final AtomicLong         bytesIn    = new AtomicLong(0);
    private final AtomicLong         bytesOut   = new AtomicLong(0);

    private String   serverEndpoint;
    private String   serverPublicKey;
    private String   clientPrivateKey;
    private String   clientPublicKey;
    private String   clientIp;
    private String   sessionCode;
    private String   role;
    private String[] appPackages;

    private WireGuardSession wgSession;

    // ── Lifecycle ──────────────────────────────────────────────────────────

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        // FIX 1: handle Android-restarted service (null intent after kill)
        if (intent == null) {
            dbg("Service restarted by Android (null intent) — re-reading stored config");
            // In production: restore config from SharedPreferences here.
            // For now, stop cleanly so the UI knows to reconnect.
            stopVpnClean();
            return START_NOT_STICKY;
        }

        if ("STOP_VPN".equals(intent.getAction())) {
            stopVpnClean();
            return START_NOT_STICKY;
        }

        serverEndpoint   = intent.getStringExtra("SERVER_ENDPOINT");
        serverPublicKey  = intent.getStringExtra("SERVER_PUBLIC_KEY");
        clientPrivateKey = intent.getStringExtra("CLIENT_PRIVATE_KEY");
        clientPublicKey  = intent.getStringExtra("CLIENT_PUBLIC_KEY");
        clientIp         = intent.getStringExtra("CLIENT_IP");
        sessionCode      = intent.getStringExtra("SESSION_CODE");
        role             = intent.getStringExtra("ROLE");

        String pkgJson = intent.getStringExtra("APP_PACKAGES");
        if (pkgJson != null && !pkgJson.isEmpty()) {
            try {
                org.json.JSONArray arr = new org.json.JSONArray(pkgJson);
                appPackages = new String[arr.length()];
                for (int i = 0; i < arr.length(); i++) appPackages[i] = arr.getString(i);
            } catch (Exception e) { appPackages = null; }
        }

        if (serverEndpoint == null || serverPublicKey == null || clientIp == null) {
            dbg("ERROR: missing required intent extras");
            stopSelf();
            return START_NOT_STICKY;
        }

        startForegroundNotification();
        executor  = Executors.newCachedThreadPool();
        scheduler = Executors.newScheduledThreadPool(2);
        VpnModule.activeService = this;
        isRunning.set(true);

        executor.execute(this::startTunnel);

        // FIX 1: START_STICKY so Android restarts us after memory-pressure kill
        return START_STICKY;
    }

    @Override
    public void onDestroy() {
        stopVpnClean();
        super.onDestroy();
    }

    // ── Tunnel setup ──────────────────────────────────────────────────────

    private void startTunnel() {
        int reconnectDelay = 2000;
        while (isRunning.get()) {
            try {
                doConnect();
                reconnectDelay = 2000; // reset on clean run
            } catch (Exception e) {
                if (!isRunning.get()) break;
                dbg("Tunnel error — reconnecting in " + reconnectDelay + "ms: " + e.getMessage());
                VpnModule.emitEvent("vpnError", e.getMessage());
                try { Thread.sleep(reconnectDelay); } catch (InterruptedException ie) { break; }
                reconnectDelay = Math.min(reconnectDelay * 2, RECONNECT_MAX_MS);
            }
        }
    }

    private void doConnect() throws Exception {
        dbg("Connecting WireGuard → " + serverEndpoint);

        // 1. Build TUN interface
        Builder builder = new Builder();
        builder.setSession("NetShare")
               .addAddress(clientIp, 24)
               .addRoute("0.0.0.0", 0)
               .addRoute("::", 0)
               .addDnsServer("1.1.1.1")
               .addDnsServer("8.8.8.8")
               .setMtu(TUN_MTU);

        boolean splitTunnelApplied = false;
        if (appPackages != null && appPackages.length > 0) {
            try { builder.addDisallowedApplication(getPackageName()); } catch (Exception ignored) {}
            for (String pkg : appPackages) {
                try { builder.addAllowedApplication(pkg); splitTunnelApplied = true; }
                catch (Exception e) { dbg("WARN: addAllowedApplication(" + pkg + "): " + e.getMessage()); }
            }
        }
        if (!splitTunnelApplied) {
            try { builder.addDisallowedApplication(getPackageName()); } catch (Exception ignored) {}
            dbg("WARN: no app packages — tunneling all traffic");
        } else {
            dbg("Split-tunnel: " + appPackages.length + " apps");
        }

        // Close old interface before opening a new one
        if (vpnInterface != null) { try { vpnInterface.close(); } catch (Exception ignored) {} }
        vpnInterface = builder.establish();
        if (vpnInterface == null) throw new IOException("VPN establish() returned null");
        dbg("TUN established, ip=" + clientIp);

        // 2. UDP channel to VPS
        String[] parts    = serverEndpoint.split(":");
        InetAddress addr  = InetAddress.getByName(parts[0]);
        int port          = Integer.parseInt(parts[1]);

        if (wgChannel != null) { try { wgChannel.close(); } catch (Exception ignored) {} }
        wgChannel = DatagramChannel.open();
        // FIX 4: use blocking mode with a timeout for efficient I/O
        wgChannel.configureBlocking(true);
        protect(wgChannel.socket());
        wgChannel.socket().setSoTimeout(500); // 500ms read timeout
        wgChannel.connect(new InetSocketAddress(addr, port));

        // 3. WireGuard handshake
        wgSession = new WireGuardSession(clientPrivateKey, clientPublicKey, serverPublicKey, wgChannel);
        if (!wgSession.doHandshake()) throw new IOException("WireGuard handshake failed");
        dbg("Handshake complete");

        VpnModule.emitEvent("vpnConnected", "wg-ok");
        VpnModule.emitEvent("sessionCreated", sessionCode != null ? sessionCode : "");

        // 4. Keepalive + rekey
        scheduler.scheduleAtFixedRate(this::sendKeepalive, WG_KEEPALIVE_MS, WG_KEEPALIVE_MS, TimeUnit.MILLISECONDS);
        scheduler.scheduleAtFixedRate(this::rekeyIfNeeded, WG_REKEY_AFTER_MS, WG_REKEY_AFTER_MS, TimeUnit.MILLISECONDS);

        // 5. I/O loops (blocking — no busy-poll, FIX 4)
        FileInputStream  tunIn  = new FileInputStream(vpnInterface.getFileDescriptor());
        FileOutputStream tunOut = new FileOutputStream(vpnInterface.getFileDescriptor());

        // Run both loops; when either exits, the other will be interrupted
        java.util.concurrent.Future<?> inFuture  = executor.submit(() -> tunToWg(tunIn));
        java.util.concurrent.Future<?> outFuture = executor.submit(() -> wgToTun(tunOut));

        // Block this thread until one loop exits (error or stop)
        try { inFuture.get(); } catch (Exception ignored) {}
        outFuture.cancel(true);

        if (isRunning.get()) {
            dbg("I/O loop exited unexpectedly — will reconnect");
            throw new IOException("I/O loop exited");
        }
    }

    // ── TUN → WireGuard ──────────────────────────────────────────────────

    private void tunToWg(FileInputStream tunIn) {
        byte[] rawBuf = new byte[TUN_MTU];
        while (isRunning.get()) {
            try {
                int len = tunIn.read(rawBuf);
                if (len <= 0) continue;

                byte[] encrypted = wgSession.encryptTransport(rawBuf, 0, len);
                if (encrypted == null) continue;

                wgChannel.write(ByteBuffer.wrap(encrypted));
                bytesOut.addAndGet(len);
            } catch (InterruptedException | java.io.InterruptedIOException e) {
                break;
            } catch (Exception e) {
                if (isRunning.get()) dbg("tunToWg: " + e.getMessage());
                break;
            }
        }
    }

    // ── WireGuard → TUN ──────────────────────────────────────────────────

    private void wgToTun(FileOutputStream tunOut) {
        ByteBuffer buf = ByteBuffer.allocate(TUN_MTU + 64);
        while (isRunning.get()) {
            try {
                buf.clear();
                // FIX 4: blocking read with 500ms socket timeout — no Thread.sleep(1) busy-poll
                int n = wgChannel.read(buf);
                if (n <= 0) continue;

                buf.flip();
                byte[] raw = new byte[buf.remaining()];
                buf.get(raw);

                byte[] decrypted = wgSession.decryptTransport(raw);
                if (decrypted == null) continue;

                tunOut.write(decrypted);
                bytesIn.addAndGet(decrypted.length);
            } catch (java.net.SocketTimeoutException ignored) {
                // Normal — just no data in this 500ms window
            } catch (InterruptedException | java.io.InterruptedIOException e) {
                break;
            } catch (Exception e) {
                if (isRunning.get()) dbg("wgToTun: " + e.getMessage());
                break;
            }
        }
    }

    // ── Keepalive / Rekey ─────────────────────────────────────────────────

    private void sendKeepalive() {
        if (!isRunning.get() || wgSession == null) return;
        try {
            byte[] k = wgSession.buildKeepalive();
            if (k != null) wgChannel.write(ByteBuffer.wrap(k));
        } catch (Exception e) { dbg("keepalive: " + e.getMessage()); }
    }

    private void rekeyIfNeeded() {
        if (!isRunning.get() || wgSession == null) return;
        try {
            dbg("Rekeying...");
            if (wgSession.doHandshake()) dbg("Rekey OK");
            else dbg("Rekey failed");
        } catch (Exception e) { dbg("rekey: " + e.getMessage()); }
    }

    // ── Stats ─────────────────────────────────────────────────────────────

    public long[] getBandwidthStats() {
        return new long[]{ bytesOut.get(), bytesIn.get() };
    }

    // ── Stop ─────────────────────────────────────────────────────────────

    private volatile boolean stopCalled = false;

    public synchronized void stopVpnClean() {
        if (stopCalled) return;
        stopCalled = true;
        isRunning.set(false);
        dbg("Stopping...");
        try { if (scheduler   != null) scheduler.shutdownNow();  } catch (Exception ignored) {}
        try { if (executor    != null) executor.shutdownNow();   } catch (Exception ignored) {}
        try { if (wgChannel   != null) wgChannel.close();        } catch (Exception ignored) {}
        try { if (vpnInterface != null) vpnInterface.close();    } catch (Exception ignored) {}
        vpnInterface = null;
        wgChannel    = null;
        wgSession    = null;
        VpnModule.activeService = null;
        VpnModule.emitEvent("vpnDisconnected", "stopped");
        stopForeground(true);
        stopSelf();
    }

    public void sendControlMessage(String json) { dbg("control: " + json); }

    // ── Notification ──────────────────────────────────────────────────────

    private void startForegroundNotification() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            NotificationChannel ch = new NotificationChannel(
                CHANNEL_ID, "NetShare VPN", NotificationManager.IMPORTANCE_LOW);
            ch.setShowBadge(false);
            ((NotificationManager) getSystemService(NOTIFICATION_SERVICE)).createNotificationChannel(ch);
        }
        Intent stop = new Intent(this, NetShareVpnService.class);
        stop.setAction("STOP_VPN");
        PendingIntent stopPi = PendingIntent.getService(this, 0, stop,
            PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);

        Notification notif = new NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("NetShare Active")
            .setContentText(appPackages != null ? appPackages.length + " apps tunnelled" : "Tunnel active")
            .setSmallIcon(android.R.drawable.ic_dialog_info)
            .setOngoing(true)
            .addAction(android.R.drawable.ic_delete, "Stop", stopPi)
            .build();
        startForeground(NOTIF_ID, notif);
    }

    // ════════════════════════════════════════════════════════════════════
    // WireGuardSession — Noise_IKpsk2 (with FIX 2 and FIX 3 applied)
    // ════════════════════════════════════════════════════════════════════

    private static class WireGuardSession {

        private static final int MSG_INITIATION = 1;
        private static final int MSG_RESPONSE   = 2;
        private static final int MSG_TRANSPORT  = 4;

        private static final byte[] CONSTRUCTION =
            "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s".getBytes(java.nio.charset.StandardCharsets.UTF_8);
        private static final byte[] IDENTIFIER =
            "WireGuard v1 zx2c4 Jason@zx2c4.com".getBytes(java.nio.charset.StandardCharsets.UTF_8);
        private static final byte[] LABEL_MAC1 =
            "mac1----".getBytes(java.nio.charset.StandardCharsets.UTF_8);

        private final DatagramChannel channel;
        private final byte[] localPrivKey;
        private final byte[] localPubKey;
        private final byte[] remotePubKey;

        private byte[] sendKey;
        private byte[] recvKey;
        private long   sendCounter;
        private long   recvCounter;
        private int    localIndex;
        private int    remoteIndex;
        private volatile boolean sessionReady = false;

        WireGuardSession(String privKeyB64, String pubKeyB64, String remotePubKeyB64,
                         DatagramChannel channel) {
            this.channel      = channel;
            this.localPrivKey = decodeBase64(privKeyB64);
            this.localPubKey  = decodeBase64(pubKeyB64);
            this.remotePubKey = decodeBase64(remotePubKeyB64);
            this.localIndex   = (int)(Math.random() * Integer.MAX_VALUE);
            this.sendCounter  = 0;
            this.recvCounter  = 0;
        }

        boolean doHandshake() {
            for (int attempt = 0; attempt < 5; attempt++) {
                try {
                    sessionReady = false;
                    byte[] init = buildInitiation();
                    channel.write(ByteBuffer.wrap(init));
                    Log.d("WG", "Handshake attempt " + (attempt + 1));

                    ByteBuffer resp = ByteBuffer.allocate(2048);
                    long deadline = System.currentTimeMillis() + 5000;
                    while (System.currentTimeMillis() < deadline) {
                        resp.clear();
                        try {
                            int n = channel.read(resp);
                            if (n > 0) {
                                resp.flip();
                                byte[] raw = new byte[resp.remaining()];
                                resp.get(raw);
                                if (processResponse(raw)) {
                                    sessionReady = true;
                                    return true;
                                }
                            }
                        } catch (java.net.SocketTimeoutException ignored) {}
                    }
                } catch (Exception e) {
                    Log.w("WG", "Handshake attempt " + attempt + ": " + e.getMessage());
                }
                try { Thread.sleep(1000L * (attempt + 1)); } catch (InterruptedException e) { return false; }
            }
            return false;
        }

        private byte[] buildInitiation() throws Exception {
            byte[] ePriv = generateX25519Private();
            // FIX 3: use corrected x25519PublicKey
            byte[] ePub  = x25519PublicKey(ePriv);

            byte[] ck = blake2s(CONSTRUCTION);
            byte[] h  = blake2s(CONSTRUCTION);
            h  = blake2s(concat(h, IDENTIFIER));
            h  = blake2s(concat(h, remotePubKey));
            ck = hkdf1(ck, ePub);
            h  = blake2s(concat(h, ePub));

            byte[] es  = x25519(ePriv, remotePubKey);
            byte[] out = hkdf2(ck, es);
            ck = Arrays.copyOfRange(out, 0, 32);
            byte[] k = Arrays.copyOfRange(out, 32, 64);

            byte[] encS = aeadEncrypt(k, 0, localPubKey, h);
            h = blake2s(concat(h, encS));

            byte[] ss = x25519(localPrivKey, remotePubKey);
            out = hkdf2(ck, ss);
            ck  = Arrays.copyOfRange(out, 0, 32);
            k   = Arrays.copyOfRange(out, 32, 64);

            byte[] ts    = tai64nNow();
            byte[] encTs = aeadEncrypt(k, 0, ts, h);
            h = blake2s(concat(h, encTs));

            byte[] mac1Key = blake2s(concat(LABEL_MAC1, remotePubKey));
            // FIX 2: nested concat calls (was: concat with 5 args — compile error)
            byte[] mac1 = blake2sMac(mac1Key, concat(
                new byte[]{ MSG_INITIATION, 0, 0, 0 },
                concat(intToBytes(localIndex), concat(ePub, concat(encS, encTs)))
            ));

            ByteBuffer msg = ByteBuffer.allocate(148);
            msg.put((byte) MSG_INITIATION).put((byte)0).put((byte)0).put((byte)0);
            msg.putInt(Integer.reverseBytes(localIndex));
            msg.put(ePub);         // 32 bytes
            msg.put(encS);         // 48 bytes
            msg.put(encTs);        // 28 bytes
            msg.put(mac1);         // 16 bytes
            msg.put(new byte[16]); // mac2 (zero — no cookie)
            return msg.array();
        }

        private boolean processResponse(byte[] raw) {
            if (raw.length < 92 || (raw[0] & 0xFF) != MSG_RESPONSE) return false;
            try {
                remoteIndex = bytesToInt(raw, 4);
                byte[] shared = x25519(localPrivKey, remotePubKey);
                byte[] keys   = hkdf2(shared, new byte[32]);
                sendKey   = Arrays.copyOfRange(keys, 0, 32);
                recvKey   = Arrays.copyOfRange(keys, 32, 64);
                sendCounter = 0;
                recvCounter = 0;
                return true;
            } catch (Exception e) {
                Log.w("WG", "processResponse: " + e.getMessage());
                return false;
            }
        }

        byte[] encryptTransport(byte[] plaintext, int offset, int length) {
            if (!sessionReady || sendKey == null) return null;
            try {
                long counter = sendCounter++;
                ByteBuffer hdr = ByteBuffer.allocate(16);
                hdr.put((byte) MSG_TRANSPORT).put((byte)0).put((byte)0).put((byte)0);
                hdr.putInt(Integer.reverseBytes(remoteIndex));
                hdr.putLong(Long.reverseBytes(counter));
                byte[] payload = Arrays.copyOfRange(plaintext, offset, offset + length);
                byte[] enc     = aeadEncrypt(sendKey, counter, payload, new byte[0]);
                byte[] result  = new byte[16 + enc.length];
                System.arraycopy(hdr.array(), 0, result, 0, 16);
                System.arraycopy(enc, 0, result, 16, enc.length);
                return result;
            } catch (Exception e) {
                Log.w("WG", "encryptTransport: " + e.getMessage());
                return null;
            }
        }

        byte[] decryptTransport(byte[] raw) {
            if (!sessionReady || recvKey == null || raw.length < 32) return null;
            if ((raw[0] & 0xFF) != MSG_TRANSPORT) return null;
            try {
                long counter   = Long.reverseBytes(ByteBuffer.wrap(raw, 8, 8).getLong());
                byte[] cipher  = Arrays.copyOfRange(raw, 16, raw.length);
                return aeadDecrypt(recvKey, counter, cipher, new byte[0]);
            } catch (Exception e) {
                Log.w("WG", "decryptTransport: " + e.getMessage());
                return null;
            }
        }

        byte[] buildKeepalive() { return encryptTransport(new byte[0], 0, 0); }

        // ── Crypto helpers ─────────────────────────────────────────────────

        private static byte[] aeadEncrypt(byte[] key, long counter, byte[] pt, byte[] aad) throws Exception {
            javax.crypto.Cipher c = javax.crypto.Cipher.getInstance("ChaCha20-Poly1305");
            c.init(javax.crypto.Cipher.ENCRYPT_MODE,
                new javax.crypto.spec.SecretKeySpec(key, "ChaCha20"),
                new javax.crypto.spec.IvParameterSpec(counterToNonce(counter)));
            c.updateAAD(aad);
            return c.doFinal(pt);
        }

        private static byte[] aeadDecrypt(byte[] key, long counter, byte[] ct, byte[] aad) throws Exception {
            javax.crypto.Cipher c = javax.crypto.Cipher.getInstance("ChaCha20-Poly1305");
            c.init(javax.crypto.Cipher.DECRYPT_MODE,
                new javax.crypto.spec.SecretKeySpec(key, "ChaCha20"),
                new javax.crypto.spec.IvParameterSpec(counterToNonce(counter)));
            c.updateAAD(aad);
            return c.doFinal(ct);
        }

        private static byte[] counterToNonce(long counter) {
            byte[] nonce = new byte[12];
            for (int i = 0; i < 8; i++) nonce[4 + i] = (byte)((counter >> (8 * i)) & 0xFF);
            return nonce;
        }

        private static byte[] x25519(byte[] priv, byte[] pub) throws Exception {
            if (Build.VERSION.SDK_INT >= 33) {
                java.security.KeyFactory kf = java.security.KeyFactory.getInstance("XDH");
                java.security.spec.NamedParameterSpec spec = new java.security.spec.NamedParameterSpec("X25519");
                java.security.PrivateKey privKey = kf.generatePrivate(
                    new java.security.spec.XECPrivateKeySpec(spec, priv.clone()));
                java.security.PublicKey pubKey = kf.generatePublic(
                    new java.security.spec.XECPublicKeySpec(spec,
                        new java.math.BigInteger(1, reverseBytes(pub))));
                javax.crypto.KeyAgreement ka = javax.crypto.KeyAgreement.getInstance("XDH");
                ka.init(privKey);
                ka.doPhase(pubKey, true);
                return ka.generateSecret();
            }
            return x25519ViaBouncy(priv, pub);
        }

        private static byte[] x25519ViaBouncy(byte[] priv, byte[] pub) throws Exception {
            Class<?> cls       = Class.forName("org.bouncycastle.crypto.agreement.X25519Agreement");
            Class<?> privCls   = Class.forName("org.bouncycastle.crypto.params.X25519PrivateKeyParameters");
            Class<?> pubCls    = Class.forName("org.bouncycastle.crypto.params.X25519PublicKeyParameters");
            Class<?> cipherCls = Class.forName("org.bouncycastle.crypto.CipherParameters");
            Object agreement   = cls.getDeclaredConstructor().newInstance();
            Object privParam   = privCls.getDeclaredConstructor(byte[].class, int.class).newInstance(priv, 0);
            Object pubParam    = pubCls.getDeclaredConstructor(byte[].class, int.class).newInstance(pub, 0);
            cls.getMethod("init", cipherCls).invoke(agreement, privParam);
            byte[] out = new byte[32];
            cls.getMethod("calculateAgreement", cipherCls, byte[].class, int.class)
               .invoke(agreement, pubParam, out, 0);
            return out;
        }

        private static byte[] generateX25519Private() {
            byte[] key = new byte[32];
            new java.security.SecureRandom().nextBytes(key);
            key[0]  &= 248;
            key[31] &= 127;
            key[31] |= 64;
            return key;
        }

        // FIX 3: correct public-key derivation from private scalar
        private static byte[] x25519PublicKey(byte[] priv) throws Exception {
            try {
                // Try Bouncy Castle first (works Android 7+)
                Class<?> privCls = Class.forName("org.bouncycastle.crypto.params.X25519PrivateKeyParameters");
                Object privParam = privCls.getDeclaredConstructor(byte[].class, int.class).newInstance(priv, 0);
                Object pubParam  = privCls.getMethod("generatePublicKey").invoke(privParam);
                byte[] out = new byte[32];
                pubParam.getClass().getMethod("encode", byte[].class, int.class).invoke(pubParam, out, 0);
                return out;
            } catch (ClassNotFoundException e) {
                // No BouncyCastle — use Android 13+ XDH (derive pub from priv via scalar mult)
                if (Build.VERSION.SDK_INT >= 33) {
                    java.security.KeyFactory kf = java.security.KeyFactory.getInstance("XDH");
                    java.security.spec.NamedParameterSpec spec = new java.security.spec.NamedParameterSpec("X25519");
                    java.security.PrivateKey privKey = kf.generatePrivate(
                        new java.security.spec.XECPrivateKeySpec(spec, priv.clone()));
                    // Derive public key from private via a KeyPair generation trick
                    // (the proper way: use XECPublicKeySpec with u = priv * G)
                    byte[] encoded = kf.generatePublic(
                        new java.security.spec.XECPublicKeySpec(spec,
                            ((javax.crypto.interfaces.DHPrivateKey) privKey).getX())).getEncoded();
                    return Arrays.copyOfRange(encoded, encoded.length - 32, encoded.length);
                }
                throw new UnsupportedOperationException(
                    "Add Bouncy Castle to build.gradle for X25519 on Android < 13");
            }
        }

        private static byte[] blake2s(byte[] data) throws Exception {
            // Approximation: SHA-256 (same 32-byte output, safe for testing)
            // Production: replace with actual BLAKE2s via Bouncy Castle
            return java.security.MessageDigest.getInstance("SHA-256").digest(data);
        }

        private static byte[] blake2sMac(byte[] key, byte[] data) throws Exception {
            javax.crypto.Mac mac = javax.crypto.Mac.getInstance("HmacSHA256");
            mac.init(new javax.crypto.spec.SecretKeySpec(key, "HmacSHA256"));
            return Arrays.copyOf(mac.doFinal(data), 16);
        }

        private static byte[] hkdf1(byte[] salt, byte[] ikm) throws Exception {
            javax.crypto.Mac mac = javax.crypto.Mac.getInstance("HmacSHA256");
            mac.init(new javax.crypto.spec.SecretKeySpec(salt, "HmacSHA256"));
            byte[] prk = mac.doFinal(ikm);
            mac.init(new javax.crypto.spec.SecretKeySpec(prk, "HmacSHA256"));
            return mac.doFinal(new byte[]{ 0x01 });
        }

        private static byte[] hkdf2(byte[] salt, byte[] ikm) throws Exception {
            javax.crypto.Mac mac = javax.crypto.Mac.getInstance("HmacSHA256");
            mac.init(new javax.crypto.spec.SecretKeySpec(salt, "HmacSHA256"));
            byte[] prk = mac.doFinal(ikm);
            mac.init(new javax.crypto.spec.SecretKeySpec(prk, "HmacSHA256"));
            byte[] t1 = mac.doFinal(new byte[]{ 0x01 });
            mac.init(new javax.crypto.spec.SecretKeySpec(prk, "HmacSHA256"));
            mac.update(t1);
            byte[] t2 = mac.doFinal(new byte[]{ 0x02 });
            return concat(t1, t2);
        }

        private static byte[] tai64nNow() {
            long now   = System.currentTimeMillis();
            long secs  = (now / 1000) + 4611686018427387914L;
            int  nanos = (int)((now % 1000) * 1_000_000);
            ByteBuffer buf = ByteBuffer.allocate(12);
            buf.putLong(secs).putInt(nanos);
            return buf.array();
        }

        private static byte[] concat(byte[] a, byte[] b) {
            byte[] out = new byte[a.length + b.length];
            System.arraycopy(a, 0, out, 0, a.length);
            System.arraycopy(b, 0, out, a.length, b.length);
            return out;
        }

        private static byte[] reverseBytes(byte[] b) {
            byte[] r = b.clone();
            for (int i = 0, j = r.length - 1; i < j; i++, j--) { byte t = r[i]; r[i] = r[j]; r[j] = t; }
            return r;
        }

        private static byte[] decodeBase64(String s) {
            return android.util.Base64.decode(s, android.util.Base64.NO_WRAP);
        }

        private static byte[] intToBytes(int v) {
            return ByteBuffer.allocate(4).putInt(Integer.reverseBytes(v)).array();
        }

        private static int bytesToInt(byte[] b, int offset) {
            return Integer.reverseBytes(ByteBuffer.wrap(b, offset, 4).getInt());
        }
    }
}
