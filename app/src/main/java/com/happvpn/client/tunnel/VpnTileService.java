package com.happvpn.client.tunnel;

import android.content.Intent;
import android.net.VpnService;

/**
 * Экспортируемый VpnService (нужен для BIND_VPN_SERVICE в манифесте).
 * Реальная работа туннеля — в TunnelEngine, который использует этот сервис.
 */
public class VpnTileService extends VpnService {
    @Override
    public void onCreate() {
        super.onCreate();
        TunnelEngine.attachService(this);
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        return START_STICKY;
    }

    @Override
    public android.os.IBinder onBind(Intent intent) {
        return super.onBind(intent);
    }
}
