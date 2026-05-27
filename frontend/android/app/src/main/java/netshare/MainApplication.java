package com.netshare;

import android.app.Application;
import com.facebook.react.PackageList;
import com.facebook.react.ReactApplication;
import com.facebook.react.ReactNativeHost;
import com.facebook.react.ReactPackage;
import com.facebook.react.defaults.DefaultReactNativeHost;
import com.facebook.soloader.SoLoader;
import java.util.List;

public class MainApplication extends Application implements ReactApplication {

    private final ReactNativeHost mReactNativeHost =
        new DefaultReactNativeHost(this) {

            @Override
            public boolean getUseDeveloperSupport() {
                return false; // set to BuildConfig.DEBUG if you want dev mode
            }

            @Override
            protected List<ReactPackage> getPackages() {
                // PackageList auto-links all standard RN packages.
                // We then add our custom VpnPackage on top.
                List<ReactPackage> packages = new PackageList(this).getPackages();
                packages.add(new VpnPackage());
                return packages;
            }

            @Override
            protected String getJSMainModuleName() {
                return "index";
            }

            @Override
            protected boolean isNewArchEnabled() {
                return false; // keep false unless you've enabled the new arch
            }

            @Override
            protected Boolean isHermesEnabled() {
                return true;
            }
        };

    @Override
    public ReactNativeHost getReactNativeHost() {
        return mReactNativeHost;
    }

    @Override
    public void onCreate() {
        super.onCreate();
        SoLoader.init(this, /* native exopackage */ false);
    }
}
