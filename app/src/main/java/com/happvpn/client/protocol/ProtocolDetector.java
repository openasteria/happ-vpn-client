package com.happvpn.client.protocol;

import android.util.Base64;
import android.util.Log;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * Автоматическое определение протокола по ссылке happ/панели.
 * Поддерживает: vless://, vmess://, trojan://, ss://, wireguard://, hysteria2://,
 * а также base64-подписки (https://panel.../link/xxxx) с массивом узлов.
 */
public class ProtocolDetector {

    private static final String TAG = "ProtocolDetector";

    public static class Result {
        public final List<Node> nodes;
        public final Node.Type detectedType;
        public final String rawLink;

        public Result(List<Node> nodes, Node.Type type, String rawLink) {
            this.nodes = nodes;
            this.detectedType = type;
            this.rawLink = rawLink;
        }
    }

    /**
     * Главная точка входа — принимает любую строку и возвращает список узлов.
     */
    public static Result detect(String input) {
        if (input == null || input.trim().isEmpty()) {
            return new Result(new ArrayList<>(), Node.Type.UNKNOWN, "");
        }
        String s = input.trim();

        // 1. Прямые ссылки протоколов
        if (s.startsWith("vless://"))   return parseVless(s);
        if (s.startsWith("vmess://"))   return parseVmess(s);
        if (s.startsWith("trojan://"))  return parseTrojan(s);
        if (s.startsWith("ss://") || s.startsWith("shadowsocks://")) return parseSS(s);
        if (s.startsWith("hysteria2://") || s.startsWith("hy2://")) return parseHy2(s);
        if (s.startsWith("wireguard://") || s.startsWith("wg://")) return parseWG(s);

        // 2. happ:// — Happ-формат (обычно happ://<base64 подписки>)
        if (s.startsWith("happ://")) {
            String payload = s.substring(7);
            // happ:// может содержать https-ссылку внутри
            if (payload.startsWith("http")) {
                return new Result(new ArrayList<>(), Node.Type.UNKNOWN, payload);
            }
            try {
                byte[] decoded = Base64.decode(payload, Base64.DEFAULT | Base64.URL_SAFE);
                String text = new String(decoded, StandardCharsets.UTF_8);
                return parseSubscription(text);
            } catch (Exception e) {
                Log.w(TAG, "happ:// decode failed", e);
            }
        }

        // 3. http(s):// — подписка (панель возвращает base64 или JSON)
        if (s.startsWith("http://") || s.startsWith("https://")) {
            return new Result(new ArrayList<>(), Node.Type.UNKNOWN, s);
        }

        // 4. Пробуем как base64-подписку напрямую
        return parseSubscription(s);
    }

    /**
     * Разбирает тело подписки (base64 или plain текст со ссылками).
     */
    public static Result parseSubscription(String body) {
        List<Node> nodes = new ArrayList<>();
        Node.Type first = Node.Type.UNKNOWN;

        // Пробуем base64-decode
        String text = body;
        try {
            byte[] dec = Base64.decode(body.replaceAll("\\s", ""), Base64.DEFAULT | Base64.URL_SAFE);
            String candidate = new String(dec, StandardCharsets.UTF_8);
            if (candidate.contains("://")) text = candidate;
        } catch (Exception ignored) {}

        String[] lines = text.split("[\\r\\n]+");
        for (String line : lines) {
            line = line.trim();
            if (line.isEmpty()) continue;
            Result r = detect(line);
            nodes.addAll(r.nodes);
            if (first == Node.Type.UNKNOWN && r.detectedType != Node.Type.UNKNOWN) {
                first = r.detectedType;
            }
        }
        return new Result(nodes, first, body);
    }

    // ─── VLESS ────────────────────────────────────────────────────────────────
    private static Result parseVless(String url) {
        try {
            URI uri = new URI(url);
            Node n = new Node();
            n.type = Node.Type.VLESS;
            n.uuid = uri.getUserInfo() != null ? uri.getUserInfo() : "";
            n.server = uri.getHost();
            n.port = uri.getPort() > 0 ? uri.getPort() : 443;
            String query = uri.getQuery() != null ? uri.getQuery() : "";
            String frag = uri.getFragment() != null ? uri.getFragment() : "";
            n.name = frag.isEmpty() ? n.server : frag;
            for (String kv : query.split("&")) {
                String[] p = kv.split("=", 2);
                if (p.length < 2) continue;
                switch (p[0]) {
                    case "security":  n.security = p[1]; n.tls = p[1].equals("tls") || p[1].equals("reality"); break;
                    case "sni":       n.sni = p[1]; break;
                    case "flow":      n.flow = p[1]; break;
                    case "type":      n.network = p[1]; break;
                    case "path":      n.path = p[1]; break;
                    case "host":      n.host = p[1]; break;
                    case "pbk":       n.publicKey = p[1]; break;
                    case "insecure":  n.insecure = p[1].equals("1") || p[1].equals("true"); break;
                }
            }
            List<Node> list = new ArrayList<>();
            list.add(n);
            return new Result(list, Node.Type.VLESS, url);
        } catch (Exception e) {
            Log.e(TAG, "parseVless error", e);
            return new Result(new ArrayList<>(), Node.Type.UNKNOWN, url);
        }
    }

    // ─── VMESS ────────────────────────────────────────────────────────────────
    private static Result parseVmess(String url) {
        try {
            String json = new String(Base64.decode(url.substring(8), Base64.DEFAULT | Base64.URL_SAFE), StandardCharsets.UTF_8);
            org.json.JSONObject obj = new org.json.JSONObject(json);
            Node n = new Node();
            n.type = Node.Type.VMESS;
            n.uuid = obj.optString("id", "");
            n.server = obj.optString("add", "");
            n.port = obj.optInt("port", 443);
            n.aid = obj.optInt("aid", 0);
            n.security = obj.optString("tls", "");
            n.tls = "tls".equals(n.security);
            n.sni = obj.optString("sni", "");
            n.network = obj.optString("net", "tcp");
            n.path = obj.optString("path", "");
            n.host = obj.optString("host", "");
            n.name = obj.optString("ps", n.server);
            List<Node> list = new ArrayList<>();
            list.add(n);
            return new Result(list, Node.Type.VMESS, url);
        } catch (Exception e) {
            Log.e(TAG, "parseVmess error", e);
            return new Result(new ArrayList<>(), Node.Type.UNKNOWN, url);
        }
    }

    // ─── TROJAN ───────────────────────────────────────────────────────────────
    private static Result parseTrojan(String url) {
        try {
            URI uri = new URI(url);
            Node n = new Node();
            n.type = Node.Type.TROJAN;
            n.uuid = uri.getUserInfo() != null ? uri.getUserInfo() : "";
            n.server = uri.getHost();
            n.port = uri.getPort() > 0 ? uri.getPort() : 443;
            n.tls = true;
            String frag = uri.getFragment() != null ? uri.getFragment() : "";
            n.name = frag.isEmpty() ? n.server : frag;
            String query = uri.getQuery() != null ? uri.getQuery() : "";
            for (String kv : query.split("&")) {
                String[] p = kv.split("=", 2);
                if (p.length < 2) continue;
                if (p[0].equals("sni")) n.sni = p[1];
                if (p[0].equals("type")) n.network = p[1];
                if (p[0].equals("path")) n.path = p[1];
            }
            List<Node> list = new ArrayList<>();
            list.add(n);
            return new Result(list, Node.Type.TROJAN, url);
        } catch (Exception e) {
            Log.e(TAG, "parseTrojan error", e);
            return new Result(new ArrayList<>(), Node.Type.UNKNOWN, url);
        }
    }

    // ─── SHADOWSOCKS ──────────────────────────────────────────────────────────
    private static Result parseSS(String url) {
        try {
            String rest = url.replaceFirst("^(ss|shadowsocks)://", "");
            Node n = new Node();
            n.type = Node.Type.SHADOWSOCKS;
            // Формат: base64(method:password)@host:port#name  ИЛИ  method:password@host:port#name
            int atIdx = rest.lastIndexOf('@');
            String frag = "";
            if (rest.contains("#")) {
                int h = rest.indexOf('#');
                frag = rest.substring(h + 1);
                rest = rest.substring(0, h);
                atIdx = rest.lastIndexOf('@');
            }
            String hostPart = atIdx >= 0 ? rest.substring(atIdx + 1) : rest;
            String credPart = atIdx >= 0 ? rest.substring(0, atIdx) : "";
            // Декодируем cred если нужно
            if (!credPart.contains(":")) {
                try {
                    credPart = new String(Base64.decode(credPart, Base64.DEFAULT | Base64.URL_SAFE), StandardCharsets.UTF_8);
                } catch (Exception ignored) {}
            }
            String[] hp = hostPart.split(":");
            n.server = hp.length > 0 ? hp[0] : "";
            n.port = hp.length > 1 ? Integer.parseInt(hp[1]) : 8388;
            String[] cp = credPart.split(":", 2);
            n.cipher = cp.length > 0 ? cp[0] : "aes-256-gcm";
            n.uuid = cp.length > 1 ? cp[1] : "";
            n.name = frag.isEmpty() ? n.server : frag;
            List<Node> list = new ArrayList<>();
            list.add(n);
            return new Result(list, Node.Type.SHADOWSOCKS, url);
        } catch (Exception e) {
            Log.e(TAG, "parseSS error", e);
            return new Result(new ArrayList<>(), Node.Type.UNKNOWN, url);
        }
    }

    // ─── HYSTERIA2 ────────────────────────────────────────────────────────────
    private static Result parseHy2(String url) {
        try {
            URI uri = new URI(url);
            Node n = new Node();
            n.type = Node.Type.HY2;
            n.uuid = uri.getUserInfo() != null ? uri.getUserInfo() : "";
            n.server = uri.getHost();
            n.port = uri.getPort() > 0 ? uri.getPort() : 443;
            n.tls = true;
            String frag = uri.getFragment() != null ? uri.getFragment() : "";
            n.name = frag.isEmpty() ? n.server : frag;
            List<Node> list = new ArrayList<>();
            list.add(n);
            return new Result(list, Node.Type.HY2, url);
        } catch (Exception e) {
            return new Result(new ArrayList<>(), Node.Type.UNKNOWN, url);
        }
    }

    // ─── WIREGUARD ────────────────────────────────────────────────────────────
    private static Result parseWG(String url) {
        try {
            URI uri = new URI(url);
            Node n = new Node();
            n.type = Node.Type.WIREGUARD;
            n.server = uri.getHost();
            n.port = uri.getPort() > 0 ? uri.getPort() : 51820;
            String query = uri.getQuery() != null ? uri.getQuery() : "";
            for (String kv : query.split("&")) {
                String[] p = kv.split("=", 2);
                if (p.length < 2) continue;
                switch (p[0]) {
                    case "privatekey": case "pk": n.privateKey = p[1]; break;
                    case "publickey":  case "pubkey": n.publicKey = p[1]; break;
                    case "address":    n.uuid = p[1]; break;
                    case "presharedkey": n.psk = p[1]; break;
                }
            }
            String frag = uri.getFragment() != null ? uri.getFragment() : "";
            n.name = frag.isEmpty() ? n.server : frag;
            List<Node> list = new ArrayList<>();
            list.add(n);
            return new Result(list, Node.Type.WIREGUARD, url);
        } catch (Exception e) {
            return new Result(new ArrayList<>(), Node.Type.UNKNOWN, url);
        }
    }

    /** Возвращает человекочитаемое имя типа. */
    public static String typeName(Node.Type t) {
        switch (t) {
            case VLESS:       return "VLESS";
            case VMESS:       return "VMess";
            case TROJAN:      return "Trojan";
            case SHADOWSOCKS: return "Shadowsocks";
            case WIREGUARD:   return "WireGuard";
            case HY2:         return "Hysteria2";
            default:          return "Авто";
        }
    }
}
