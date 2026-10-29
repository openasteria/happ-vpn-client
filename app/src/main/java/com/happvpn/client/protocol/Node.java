package com.happvpn.client.protocol;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Модель узла VPN, независимо от протокола.
 */
public class Node {
    public enum Type { VLESS, VMESS, TROJAN, SHADOWSOCKS, WIREGUARD, HY2, UNKNOWN }

    public String name = "node";
    public Type type = Type.UNKNOWN;
    public String server = "";
    public int port = 0;
    public String uuid = "";          // vless/vmess id, trojan password, ss password, wg key
    public String security = "none";  // none/tls/reality (vless), ws/grpc/http... (transport)
    public String sni = "";
    public boolean tls = false;
    public boolean insecure = false;
    public String flow = "";          // xtls-rprx-vision и т.п.
    public String network = "tcp";    // tcp/ws/grpc/h2
    public String path = "";
    public String host = "";
    public Map<String, String> headers = new LinkedHashMap<>();
    public String remarks = "";       // имя из base64-подписки #name
    public String publicKey = "";     // wireguard / reality pbk
    public String privateKey = "";    // wireguard
    public int aid = 0;               // vmess alterId
    public String cipher = "";        // ss метод шифрования
    public String psk = "";           // hysteria2 / wg preshared key

    public String address() {
        return server + ":" + port;
    }

    @Override
    public String toString() {
        return name.isEmpty() ? address() : name + " (" + address() + ")";
    }

    public static List<Node> emptyList() {
        return new ArrayList<>();
    }
}
