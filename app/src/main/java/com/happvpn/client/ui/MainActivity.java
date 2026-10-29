package com.happvpn.client.ui;

import android.content.ClipboardManager;
import android.content.Context;
import android.content.Intent;
import android.net.VpnService;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.text.Editable;
import android.text.TextWatcher;
import android.view.View;
import android.widget.Toast;

import androidx.activity.result.ActivityResultLauncher;
import androidx.activity.result.contract.ActivityResultContracts;
import androidx.appcompat.app.AppCompatActivity;

import com.happvpn.client.R;
import com.happvpn.client.databinding.ActivityMainBinding;
import com.happvpn.client.protocol.Node;
import com.happvpn.client.protocol.ProtocolDetector;
import com.happvpn.client.tunnel.TunnelEngine;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * Два экрана:
 *  1) Прямоугольник со скруглёнными углами для вставки ссылки happ/панели.
 *     Как только ссылка полная и сервер отвечает — автоматический переход во второе меню.
 *  2) Большая круглая кнопка по центру — подключение/отключение VPN.
 */
public class MainActivity extends AppCompatActivity {

    private ActivityMainBinding b;
    private final ExecutorService io = Executors.newCachedThreadPool();
    private final Handler ui = new Handler(Looper.getMainLooper());

    private ProtocolDetector.Result lastResult;
    private Node selectedNode;
    private long connectStartMs = 0;
    private boolean autoTransitionFired = false;

    private ActivityResultLauncher<Intent> vpnLauncher;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        b = ActivityMainBinding.inflate(getLayoutInflater());
        setContentView(b.root);

        vpnLauncher = registerForActivityResult(new ActivityResultContracts.StartActivityForResult(), r -> {
            if (r.getResultCode() == RESULT_OK) {
                startTunnel();
            } else {
                toast(getString(R.string.vpn_permission_denied));
                setStateDisconnected();
            }
        });

        setupInputScreen();
        setupConnectScreen();

        // Если пришли по ссылке из браузера/панели (happ://... или https://...)
        handleViewIntent(getIntent());
    }

    @Override
    protected void onNewIntent(Intent intent) {
        super.onNewIntent(intent);
        handleViewIntent(intent);
    }

    private void handleViewIntent(Intent intent) {
        if (intent == null || !Intent.ACTION_VIEW.equals(intent.getAction())) return;
        String link = intent.getDataString();
        if (link != null && !link.isEmpty()) {
            b.editLink.setText(link);
            validateAndProceed(link);
        }
    }

    // ─── ЭКРАН 1 ──────────────────────────────────────────────────────────────
    private void setupInputScreen() {
        b.btnPaste.setOnClickListener(v -> {
            ClipboardManager cm = (ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
            if (cm != null && cm.hasText()) {
                b.editLink.setText(cm.getText());
                toast(getString(R.string.toast_copied));
            }
        });

        b.btnCheck.setOnClickListener(v -> validateAndProceed(currentText()));

        // Автопроверка при вводе: как только ссылка «полная» и сервер отвечает —
        // сразу пробрасываем во второе меню.
        b.editLink.addTextChangedListener(new TextWatcher() {
            @Override public void beforeTextChanged(CharSequence s, int a, int c, int d) {}
            @Override public void onTextChanged(CharSequence s, int a, int b, int c) {}
            @Override public void afterTextChanged(Editable s) {
                maybeAutoValidate(s.toString());
            }
        });
    }

    private String currentText() {
        return b.editLink.getText().toString().trim();
    }

    /** Дебаунс-автопроверка: не дёргаем сеть на каждый символ. */
    private Runnable pendingAuto;
    private void maybeAutoValidate(String text) {
        if (autoTransitionFired) return;
        if (pendingAuto != null) ui.removeCallbacks(pendingAuto);
        if (!looksComplete(text)) {
            setStatus(getString(R.string.status_idle), R.color.text_secondary);
            return;
        }
        pendingAuto = () -> validateAndProceed(text);
        ui.postDelayed(pendingAuto, 700);
    }

    /** Ссылка выглядит полной? */
    private boolean looksComplete(String s) {
        if (s == null) return false;
        s = s.trim();
        if (s.length() < 12) return false;
        String low = s.toLowerCase();
        for (String p : new String[]{"vless://", "vmess://", "trojan://", "ss://",
                "happ://", "wireguard://", "wg://", "hy2://", "hysteria2://"}) {
            if (low.startsWith(p)) return true;
        }
        if (!(low.startsWith("http://") || low.startsWith("https://"))) return false;
        // после схемы должен быть хост и путь — ссылка выглядит полной
        int schemeEnd = low.indexOf("://") + 3;
        int firstSlash = low.indexOf('/', schemeEnd);
        return firstSlash > schemeEnd && firstSlash < low.length() - 1;
    }

    /** Полная проверка: локальный разбор + сетевой запрос к панели. */
    private void validateAndProceed(String input) {
        final String text = input == null ? "" : input.trim();
        if (text.isEmpty()) {
            setStatus(getString(R.string.err_empty), R.color.danger);
            return;
        }
        if (!looksComplete(text)) {
            setStatus(getString(R.string.err_not_url), R.color.danger);
            return;
        }
        b.progressCheck.setVisibility(View.VISIBLE);
        b.btnCheck.setEnabled(false);
        setStatus(getString(R.string.status_checking), R.color.accent);

        io.execute(() -> {
            // 1. Локальный разбор протокола
            ProtocolDetector.Result local = ProtocolDetector.detect(text);
            List<Node> nodes = new ArrayList<>(local.nodes);
            Node.Type type = local.detectedType;

            // 2. Если это http(s)-ссылка подписки — запрашиваем панель
            String urlHint = local.rawLink != null && local.rawLink.startsWith("http") ? local.rawLink : text;
            String body = urlHint.startsWith("http") ? fetchSubscription(urlHint) : null;
            if (body != null) {
                ProtocolDetector.Result sub = ProtocolDetector.parseSubscription(body);
                if (!sub.nodes.isEmpty()) {
                    nodes = sub.nodes;
                    type = sub.detectedType;
                }
            }

            final List<Node> fNodes = nodes;
            final Node.Type fType = type;
            final boolean serverResponded = body != null || !nodes.isEmpty();

            ui.post(() -> {
                b.progressCheck.setVisibility(View.GONE);
                b.btnCheck.setEnabled(true);
                if (serverResponded && !fNodes.isEmpty()) {
                    String name = ProtocolDetector.typeName(fType);
                    setStatus(getString(R.string.status_ok, name, fNodes.size()), R.color.success);
                    lastResult = new ProtocolDetector.Result(fNodes, fType, text);
                    autoTransitionFired = true;
                    ui.postDelayed(this::openConnectScreen, 600);
                } else if (body != null) {
                    // сервер ответил, но узлов нет — всё равно идём дальше (подпись может быть пустой)
                    lastResult = new ProtocolDetector.Result(fNodes, fType, text);
                    autoTransitionFired = true;
                    openConnectScreen();
                } else if (!fNodes.isEmpty()) {
                    // сеть недоступна, но ссылку разобрали локально
                    setStatus(getString(R.string.status_err_conn), R.color.text_secondary);
                    lastResult = new ProtocolDetector.Result(fNodes, fType, text);
                    autoTransitionFired = true;
                    ui.postDelayed(this::openConnectScreen, 800);
                } else {
                    setStatus(getString(R.string.status_err_conn), R.color.danger);
                }
            });
        });
    }

    /** HTTP GET подписки. Возвращает тело или null, если сервер не ответил. */
    private String fetchSubscription(String url) {
        try {
            HttpURLConnection c = (HttpURLConnection) new URL(url).openConnection();
            c.setConnectTimeout(5000);
            c.setReadTimeout(6000);
            c.setInstanceFollowRedirects(true);
            c.setRequestProperty("User-Agent", "happ-vpn-client/1.0");
            int code = c.getResponseCode();
            if (code >= 400) return null;
            BufferedReader r = new BufferedReader(
                    new InputStreamReader(c.getInputStream(), StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder();
            String line;
            while ((line = r.readLine()) != null) sb.append(line).append('\n');
            r.close();
            return sb.toString();
        } catch (Exception e) {
            return null;
        }
    }

    // ─── ЭКРАН 2 ──────────────────────────────────────────────────────────────
    private void openConnectScreen() {
        b.screenInput.setVisibility(View.GONE);
        b.screenConnect.setVisibility(View.VISIBLE);

        List<Node> nodes = lastResult != null ? lastResult.nodes : new ArrayList<>();
        Node first = nodes.isEmpty() ? syntheticNodeFromLink() : nodes.get(0);
        pickNode(first);

        String proto = lastResult != null
                ? getString(R.string.protocol_detected) + ": " + ProtocolDetector.typeName(lastResult.detectedType)
                  + " • " + getString(R.string.nodes_count, nodes.size())
                : "";
        b.textProtocol.setText(proto);
        setStateDisconnected();
    }

    /** Если узлов из подписки нет, строим один узел прямо из ссылки. */
    private Node syntheticNodeFromLink() {
        Node n = new Node();
        n.type = Node.Type.UNKNOWN;
        n.name = currentText();
        return n;
    }

    private void pickNode(Node node) {
        selectedNode = node;
        b.textNode.setText(getString(R.string.selected_node) + ": " + node.name + " (" + node.address() + ")");
    }

    private void setupConnectScreen() {
        b.btnBack.setOnClickListener(v -> {
            if (TunnelEngine.get(this).isRunning()) TunnelEngine.get(this).disconnect();
            b.screenConnect.setVisibility(View.GONE);
            b.screenInput.setVisibility(View.VISIBLE);
            autoTransitionFired = false;
        });

        b.buttonConnect.setOnClickListener(v -> {
            TunnelEngine engine = TunnelEngine.get(this);
            if (engine.isRunning()) {
                engine.disconnect();
                setStateDisconnected();
            } else {
                // Запрос разрешения на VPN
                Intent prep = VpnService.prepare(MainActivity.this);
                if (prep != null) {
                    vpnLauncher.launch(prep);
                } else {
                    startTunnel();
                }
            }
        });
    }

    private void startTunnel() {
        if (selectedNode == null) return;
        b.textState.setText(R.string.connecting_state);
        b.textButtonLabel.setText("…");
        b.buttonConnect.setEnabled(false);
        TunnelEngine.get(this).connect(selectedNode, new TunnelEngine.Callback() {
            @Override public void onStarted(Node node) {
                ui.post(() -> {
                    b.buttonConnect.setEnabled(true);
                    setStateConnected(node);
                    toast(getString(R.string.tunnel_started, ProtocolDetector.typeName(node.type)));
                });
            }
            @Override public void onStopped() {
                ui.post(() -> setStateDisconnected());
            }
            @Override public void onError(String message) {
                ui.post(() -> {
                    b.buttonConnect.setEnabled(true);
                    setStateDisconnected();
                    toast(message);
                });
            }
        });
    }

    private void setStateConnected(Node node) {
        b.textState.setText(R.string.connected_state);
        b.textState.setTextColor(getColor(R.color.success));
        b.textButtonLabel.setText(R.string.disconnect_button_label);
        startTrafficTicker();
    }

    private void setStateDisconnected() {
        stopTrafficTicker();
        b.textState.setText(R.string.disconnected_state);
        b.textState.setTextColor(getColor(R.color.text_secondary));
        b.textButtonLabel.setText(R.string.connect_button_label);
        b.textTraffic.setText("");
        connectStartMs = 0;
    }

    // ─── Статистика трафика ───────────────────────────────────────────────────
    private Runnable ticker;
    private void startTrafficTicker() {
        if (connectStartMs == 0) connectStartMs = System.currentTimeMillis();
        ticker = new Runnable() {
            @Override public void run() {
                TunnelEngine e = TunnelEngine.get(MainActivity.this);
                if (!e.isRunning()) return;
                long up = e.bytesUp.get(), down = e.bytesDown.get();
                long secs = (System.currentTimeMillis() - connectStartMs) / 1000;
                b.textTraffic.setText(getString(R.string.traffic_up, fmt(up)) + "   "
                        + getString(R.string.traffic_down, fmt(down)) + "   "
                        + getString(R.string.duration, String.format("%02d:%02d:%02d", secs/3600, (secs/60)%60, secs%60)));
                ui.postDelayed(this, 1000);
            }
        };
        ui.post(ticker);
    }

    private void stopTrafficTicker() {
        if (ticker != null) ui.removeCallbacks(ticker);
    }

    private static String fmt(long bytes) {
        if (bytes < 1024) return bytes + " B";
        if (bytes < 1024 * 1024) return String.format("%.1f KB", bytes / 1024.0);
        if (bytes < 1024L * 1024 * 1024) return String.format("%.1f MB", bytes / 1048576.0);
        return String.format("%.2f GB", bytes / 1073741824.0);
    }

    private void setStatus(String text, int colorRes) {
        b.textStatus.setText(text);
        b.textStatus.setTextColor(getColor(colorRes));
    }

    private void toast(String msg) {
        Toast.makeText(this, msg, Toast.LENGTH_SHORT).show();
    }

    @Override
    protected void onDestroy() {
        super.onDestroy();
        io.shutdownNow();
    }
}
