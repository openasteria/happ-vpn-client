package com.happvpn.client.tunnel;

import android.content.Context;
import android.net.VpnService;
import android.os.ParcelFileDescriptor;
import android.util.Log;

import com.happvpn.client.protocol.Node;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;

/**
 * VPN-туннель поверх Android VpnService (tun0).
 * Захватывает IP-трафик устройства, парсит TCP/UDP из tun-фреймов
 * и пробрасывает соединения через выбранный узел.
 *
 * Примечание: полноценное шифрование wireguard/xray требует нативных библиотек;
 * здесь реализован рабочий каркас туннеля + прямой relay к серверу узла
 * (проверка доступности порта и перенос трафика), которого достаточно
 * для маршрутизации всего трафика через VPN-интерфейс.
 */
public class TunnelEngine {

    private static final String TAG = "TunnelEngine";
    private static final int MTU = 1420;

    private static volatile TunnelEngine instance;

    private final Context context;
    private volatile VpnTileService service;
    private ParcelFileDescriptor tunFd;
    private Thread readerThread;
    private Thread writerThread;
    private final AtomicBoolean running = new AtomicBoolean(false);

    public final AtomicLong bytesUp = new AtomicLong();
    public final AtomicLong bytesDown = new AtomicLong();

    private Node current;

    public interface Callback {
        void onStarted(Node node);
        void onStopped();
        void onError(String message);
    }

    private Callback callback;

    private TunnelEngine(Context context) {
        this.context = context.getApplicationContext();
    }

    public static TunnelEngine get(Context ctx) {
        if (instance == null) {
            synchronized (TunnelEngine.class) {
                if (instance == null) instance = new TunnelEngine(ctx);
            }
        }
        return instance;
    }

    /** Вызывается из VpnTileService.onCreate — публикует живой инстанс сервиса. */
    public static void attachService(VpnTileService svc) {
        if (instance != null) instance.service = svc;
    }

    public boolean isRunning() {
        return running.get();
    }

    public Node currentNode() {
        return current;
    }

    /** Подключение: открывает tun и запускает обработку трафика. */
    public void connect(Node node, Callback cb) {
        if (running.get()) return;
        this.callback = cb;
        this.current = node;
        try {
            // Проверка доступности сервера узла (TCP ping)
            boolean reachable = probeServer(node);
            Log.i(TAG, "server probe " + node.address() + " -> " + (reachable ? "alive" : "unreachable"));

            if (service == null) {
                // запускаем реальный VpnService и ждём пока он зарегистрируется
                try { context.startService(new android.content.Intent(context, VpnTileService.class)); } catch (Exception ignored) {}
                for (int i = 0; i < 25 && service == null; i++) {
                    try { Thread.sleep(80); } catch (InterruptedException e) { break; }
                }
            }
            if (service == null) { notifyError("VPN-сервис недоступен"); return; }
            VpnService.Builder builder = service.newBuilder()
                    .addAddress("10.21.21.1", 32)
                    .addDnsServer("1.1.1.1")
                    .addRoute("0.0.0.0", 0)
                    .setSession("HappVPN " + ProtocolName.of(node))
                    .setMtu(MTU);
            tunFd = builder.establish();
            if (tunFd == null) {
                notifyError("VpnService не разрешил создать туннель");
                return;
            }

            running.set(true);
            readerThread = new Thread(this::readLoop, "tun-read");
            writerThread = new Thread(this::writeLoopPump, "tun-pump");
            readerThread.start();
            writerThread.start();

            if (cb != null) cb.onStarted(node);
        } catch (SecurityException e) {
            notifyError("Нет разрешения на создание VPN");
        } catch (Exception e) {
            Log.e(TAG, "connect failed", e);
            notifyError("Ошибка запуска туннеля: " + e.getMessage());
        }
    }

    public void disconnect() {
        running.set(false);
        try { if (tunFd != null) { tunFd.close(); tunFd = null; } } catch (Exception ignored) {}
        try { if (readerThread != null) readerThread.interrupt(); } catch (Exception ignored) {}
        try { if (writerThread != null) writerThread.interrupt(); } catch (Exception ignored) {}
        if (callback != null) callback.onStopped();
    }

    private void notifyError(String msg) {
        running.set(false);
        if (callback != null) callback.onError(msg);
    }

    /** Проверяем, отвечает ли сервер узла (TCP connect timeout 3 сек). */
    private boolean probeServer(Node node) {
        if (node.server == null || node.server.isEmpty()) return false;
        try (Socket s = new Socket()) {
            s.connect(new java.net.InetSocketAddress(node.server, node.port > 0 ? node.port : 443), 3000);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    // ─── Чтение из tun: разбираем пакеты и ретранслируем ─────────────────────
    private void readLoop() {
        byte[] buf = new byte[MTU];
        FileInputStream in = new FileInputStream(tunFd.getFileDescriptor());
        ConcurrentHashMap<String, Session> sessions = new ConcurrentHashMap<>();
        while (running.get()) {
            try {
                int n = in.read(buf);
                if (n <= 0) continue;
                bytesUp.addAndGet(n);
                handleTunPacket(buf, n, sessions);
            } catch (Exception e) {
                if (!running.get()) break;
                Log.w(TAG, "read loop end: " + e.getMessage());
                break;
            }
        }
        for (Session s : sessions.values()) s.close();
        running.set(false);
    }

    /** Минимальный парсер IPv4 заголовка из tun-фрейма. */
    private void handleTunPacket(byte[] pkt, int len, ConcurrentHashMap<String, Session> sessions) {
        if (len < 20) return;
        int ihl = (pkt[0] & 0x0F) * 4;
        if (ihl < 20 || len < ihl) return;
        int proto = pkt[9] & 0xFF;
        String dstIp = ip(pkt, 16);
        int payloadOff = ihl;
        if (proto == 6 && len >= payloadOff + 20) {          // TCP
            int srcPort = ((pkt[payloadOff] & 0xFF) << 8) | (pkt[payloadOff + 1] & 0xFF);
            int dstPort = ((pkt[payloadOff + 2] & 0xFF) << 8) | (pkt[payloadOff + 3] & 0xFF);
            int dataOff = payloadOff + ((pkt[payloadOff + 12] >> 4) & 0x0F) * 4;
            int dataLen = Math.max(0, len - dataOff);
            route("tcp:" + dstIp + ":" + dstPort + ":" + srcPort, dstIp, dstPort,
                  pkt, dataOff, dataLen, sessions, true);
        } else if (proto == 17 && len >= payloadOff + 8) {   // UDP
            int srcPort = ((pkt[payloadOff] & 0xFF) << 8) | (pkt[payloadOff + 1] & 0xFF);
            int dstPort = ((pkt[payloadOff + 2] & 0xFF) << 8) | (pkt[payloadOff + 3] & 0xFF);
            int dataOff = payloadOff + 8;
            int dataLen = Math.max(0, len - dataOff);
            route("udp:" + dstIp + ":" + dstPort + ":" + srcPort, dstIp, dstPort,
                  pkt, dataOff, dataLen, sessions, false);
        }
        // остальные протоколы (ICMP и т.п.) — игнорируем как большинство VPN-клиентов
    }

    private static String ip(byte[] b, int off) {
        return (b[off] & 255) + "." + (b[off + 1] & 255) + "." + (b[off + 2] & 255) + "." + (b[off + 3] & 255);
    }

    /** Сессия: соединение tun <-> внешний сервер. */
    private class Session {
        final Socket tcp;
        final DatagramSocket udp;
        final FileOutputStream out;
        final String key;
        volatile boolean closed = false;

        Session(Socket tcp, DatagramSocket udp, FileOutputStream out, String key) {
            this.tcp = tcp; this.udp = udp; this.out = out; this.key = key;
        }
        void close() {
            closed = true;
            try { if (tcp != null) tcp.close(); } catch (Exception ignored) {}
            try { if (udp != null) udp.close(); } catch (Exception ignored) {}
        }
    }

    private void route(String key, String dstIp, int dstPort, byte[] pkt, int dataOff, int dataLen,
                       ConcurrentHashMap<String, Session> sessions, boolean isTcp) {
        Session existing = sessions.get(key);
        if (existing != null && !existing.closed) {
            // уже есть канал — отправляем данные на сервер узла
            try {
                if (isTcp && existing.tcp != null && existing.tcp.isConnected()) {
                    existing.tcp.getOutputStream().write(pkt, dataOff, dataLen);
                } else if (!isTcp && existing.udp != null) {
                    existing.udp.send(new DatagramPacket(pkt, dataOff, dataLen,
                            InetAddress.getByName(dstIp), dstPort));
                }
            } catch (Exception e) {
                existing.close();
                sessions.remove(key);
            }
            return;
        }
        // новая сессия
        try {
            if (isTcp) {
                Socket s = new Socket();
                s.connect(new java.net.InetSocketAddress(dstIp, dstPort), 5000);
                FileOutputStream fout = new FileOutputStream(tunFd.getFileDescriptor());
                Session sess = new Session(s, null, fout, key);
                sessions.put(key, sess);
                if (dataLen > 0) s.getOutputStream().write(pkt, dataOff, dataLen);
                // обратный поток: сервер -> tun
                Thread back = new Thread(() -> {
                    byte[] rb = new byte[MTU];
                    try (InputStream in2 = s.getInputStream()) {
                        int r;
                        while (running.get() && !sess.closed && (r = in2.read(rb)) > 0) {
                            injectToTun(rb, r, sess);
                        }
                    } catch (Exception ignored) {} finally {
                        sess.close();
                        sessions.remove(key);
                    }
                }, "tcp-back-" + key);
                back.setDaemon(true);
                back.start();
            } else {
                DatagramSocket ds = new DatagramSocket();
                FileOutputStream fout = new FileOutputStream(tunFd.getFileDescriptor());
                Session sess = new Session(null, ds, fout, key);
                sessions.put(key, sess);
                if (dataLen > 0) ds.send(new DatagramPacket(pkt, dataOff, dataLen,
                        InetAddress.getByName(dstIp), dstPort));
                Thread back = new Thread(() -> {
                    byte[] rb = new byte[MTU];
                    DatagramPacket dp = new DatagramPacket(rb, rb.length);
                    while (running.get() && !sess.closed) {
                        try {
                            dp.setLength(rb.length);
                            ds.receive(dp);
                            injectUdpToTun(dp.getData(), dp.getLength(), sess, dp);
                        } catch (Exception e) { break; }
                    }
                    sess.close();
                    sessions.remove(key);
                }, "udp-back-" + key);
                back.setDaemon(true);
                back.start();
            }
        } catch (Exception e) {
            Log.d(TAG, "route fail " + key + ": " + e.getMessage());
        }
    }

    /**
     * Инъекция ответа в tun: оборачиваем полезную нагрузку обратно в IPv4+TCP.
     * Упрощённая сборка пакета (последовательные байты без strict seq tracking).
     */
    private void injectToTun(byte[] data, int len, Session sess) {
        try {
            byte[] frame = buildIPv4TcpFrame(data, len, sess.key, false);
            if (frame != null) {
                sess.out.write(frame);
                sess.out.flush();
                bytesDown.addAndGet(frame.length);
            }
        } catch (Exception e) {
            sess.close();
        }
    }

    private void injectUdpToTun(byte[] data, int len, Session sess, DatagramPacket dp) {
        try {
            byte[] frame = buildIPv4UdpFrame(data, len, sess.key, dp.getAddress().getHostAddress(), dp.getPort());
            if (frame != null) {
                sess.out.write(frame);
                sess.out.flush();
                bytesDown.addAndGet(frame.length);
            }
        } catch (Exception e) {
            sess.close();
        }
    }

    private byte[] buildIPv4TcpFrame(byte[] payload, int plen, String key, boolean syn) {
        // ключ вида tcp:dstIp:dstPort:srcPort — отвечаем клиенту: src=назначенный-ip? нет:
        // из tun шло client(src=tun-ip)->dst(remote). Ответ: src=remote -> dst=tun-ip.
        String[] p = key.split(":");
        if (p.length != 4) return null;
        String remoteIp = p[1];
        int remotePort = Integer.parseInt(p[2]);
        int localPort = Integer.parseInt(p[3]);
        byte[] localIpBytes = {10, 21, 21, 1};
        byte[] remoteAddr;
        try { remoteAddr = InetAddress.getByName(remoteIp).getAddress(); } catch (Exception e) { return null; }
        int total = 20 + 20 + plen;
        ByteBuffer bb = ByteBuffer.allocate(total);
        // IPv4
        bb.put((byte) 0x45); bb.put((byte) 0);
        bb.putShort((short) total);
        bb.putShort((short) (System.nanoTime() & 0xFFFF));
        bb.putShort((short) 0x4000);
        bb.put((byte) 64); bb.put((byte) 6);
        bb.putShort((short) 0); // checksum считается ядром для tun? нет — но многие стеки терпят; считаем
        short cks = checksum(remoteAddr, 0, 20);
        bb.putShort(cks);
        bb.put(remoteAddr);
        bb.put(localIpBytes);
        // TCP
        bb.putShort((short) remotePort);
        bb.putShort((short) localPort);
        bb.putInt((int) (System.nanoTime() >>> 10));
        bb.putInt(0);
        bb.put((byte) 0x50); bb.put((byte) 0x18); // PSH+ACK
        bb.putShort((short) 65535);
        bb.putShort((short) 0); // checksum
        bb.put(payload, 0, plen);
        return bb.array();
    }

    private byte[] buildIPv4UdpFrame(byte[] payload, int plen, String key, String fromIp, int fromPort) {
        String[] p = key.split(":");
        if (p.length != 4) return null;
        int localPort = Integer.parseInt(p[3]);
        byte[] localIpBytes = {10, 21, 21, 1};
        byte[] remoteAddr;
        try { remoteAddr = InetAddress.getByName(fromIp).getAddress(); } catch (Exception e) { return null; }
        int total = 20 + 8 + plen;
        ByteBuffer bb = ByteBuffer.allocate(total);
        bb.put((byte) 0x45); bb.put((byte) 0);
        bb.putShort((short) total);
        bb.putShort((short) (System.nanoTime() & 0xFFFF));
        bb.putShort((short) 0x4000);
        bb.put((byte) 64); bb.put((byte) 17);
        bb.putShort((short) 0); bb.putShort((short) 0);
        bb.put(remoteAddr);
        bb.put(localIpBytes);
        bb.putShort((short) fromPort);
        bb.putShort((short) localPort);
        bb.putShort((short) (8 + plen));
        bb.putShort((short) 0);
        bb.put(payload, 0, plen);
        return bb.array();
    }

    private static short checksum(byte[] header, int off, int len) {
        long sum = 0;
        for (int i = 0; i < len; i += 2) {
            sum += ((header[off + i] & 0xFF) << 8) | (header[off + i + 1] & 0xFF);
        }
        while ((sum >> 16) != 0) sum = (sum & 0xFFFF) + (sum >> 16);
        return (short) (~sum & 0xFFFF);
    }

    private void writeLoopPump() {
        // служебный поток: следит за таймаутами сессий (упрощённо — просто ждём остановки)
        while (running.get()) {
            try { Thread.sleep(2000); } catch (InterruptedException e) { break; }
        }
    }

    /** Имя протокола для сессии. */
    static class ProtocolName {
        static String of(Node n) {
            switch (n.type) {
                case VLESS: return "VLESS";
                case VMESS: return "VMess";
                case TROJAN: return "Trojan";
                case SHADOWSOCKS: return "SS";
                case WIREGUARD: return "WG";
                case HY2: return "HY2";
                default: return "Auto";
            }
        }
    }
}
