package com.netshare;

import android.content.Intent;
import com.facebook.react.ReactActivity;
import com.facebook.react.ReactActivityDelegate;
import com.facebook.react.ReactInstanceManager;
import com.facebook.react.bridge.ReactContext;
import com.facebook.react.defaults.DefaultReactActivityDelegate;

public class MainActivity extends ReactActivity {

    @Override
    protected String getMainComponentName() {
        return "Nshare"; // must match AppRegistry.registerComponent() name in your index.js
    }

    @Override
    protected ReactActivityDelegate createReactActivityDelegate() {
        return new DefaultReactActivityDelegate(this, getMainComponentName(), false);
    }

    /**
     * Called when the user responds to the VPN permission dialog.
     * BUG FIX: original code called getCurrentReactContext() without a null check,
     * which crashes on cold start before React has fully initialised.
     */
    @Override
    public void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);

        ReactInstanceManager rim = getReactInstanceManager();
        if (rim == null) return;

        ReactContext ctx = rim.getCurrentReactContext();
        if (ctx == null) return; // React not ready yet — safe to ignore

        VpnModule module = ctx.getNativeModule(VpnModule.class);
        if (module != null) {
            module.onActivityResult(requestCode, resultCode, data);
        }
    }
}
