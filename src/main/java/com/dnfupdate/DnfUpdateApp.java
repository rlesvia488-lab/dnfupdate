package com.dnfupdate;

import com.jcraft.jsch.ChannelExec;
import com.jcraft.jsch.JSch;
import com.jcraft.jsch.JSchException;
import com.jcraft.jsch.Session;
import com.sun.net.httpserver.Headers;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedDeque;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Semaphore;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

public final class DnfUpdateApp {
    private static final int DEFAULT_PORT = 8080;
    private static final int MAX_EVENT_HISTORY = 2000;
    private static final DateTimeFormatter CLOCK =
            DateTimeFormatter.ofPattern("HH:mm:ss").withZone(ZoneId.systemDefault());

    private final Map<String, Job> jobs = new ConcurrentHashMap<>();
    private final ExecutorService jobPool = Executors.newCachedThreadPool();
    private final Path appDir;

    private DnfUpdateApp(Path appDir) {
        this.appDir = appDir;
    }

    public static void main(String[] args) throws Exception {
        int port = Optional.ofNullable(System.getenv("DNF_UPDATE_PORT"))
                .flatMap(DnfUpdateApp::parseInt)
                .orElse(DEFAULT_PORT);

        Path appDir = findAppDir();
        DnfUpdateApp app = new DnfUpdateApp(appDir);
        HttpServer server = HttpServer.create(new InetSocketAddress(port), 0);
        server.createContext("/", app::handleIndex);
        server.createContext("/api/start", app::handleStart);
        server.createContext("/api/job", app::handleJob);
        server.setExecutor(Executors.newVirtualThreadPerTaskExecutor());
        server.start();
        System.out.println("DNF Update UI running at http://localhost:" + port);
        System.out.println("Looking for key files next to the JAR in: " + appDir.toAbsolutePath());
    }

    private static Path findAppDir() {
        try {
            Path location = Path.of(DnfUpdateApp.class.getProtectionDomain()
                    .getCodeSource()
                    .getLocation()
                    .toURI());
            return Files.isRegularFile(location) ? location.getParent() : location;
        } catch (Exception ignored) {
            return Path.of(".").toAbsolutePath().normalize();
        }
    }

    private void handleIndex(HttpExchange exchange) throws IOException {
        if (!"GET".equalsIgnoreCase(exchange.getRequestMethod())) {
            send(exchange, 405, "text/plain", "Method not allowed");
            return;
        }
        send(exchange, 200, "text/html; charset=utf-8", Html.INDEX);
    }

    private void handleStart(HttpExchange exchange) throws IOException {
        if (!"POST".equalsIgnoreCase(exchange.getRequestMethod())) {
            send(exchange, 405, "application/json", "{\"error\":\"Method not allowed\"}");
            return;
        }

        Map<String, String> form = readForm(exchange);
        List<String> hosts = form.getOrDefault("hosts", "").lines()
                .map(String::trim)
                .filter(line -> !line.isBlank())
                .filter(line -> !line.startsWith("#"))
                .distinct()
                .toList();
        if (hosts.isEmpty()) {
            send(exchange, 400, "application/json", "{\"error\":\"Add at least one server IP or hostname.\"}");
            return;
        }

        Path key1 = appDir.resolve(blankDefault(form.get("key1"), "key1.ppk")).normalize();
        Path key2 = appDir.resolve(blankDefault(form.get("key2"), "key2.ppk")).normalize();
        if (!Files.isRegularFile(key1) && !Files.isRegularFile(key2)) {
            send(exchange, 400, "application/json",
                    "{\"error\":\"Neither key file was found next to the JAR. Expected key1.ppk or key2.ppk by default.\"}");
            return;
        }

        Settings settings = new Settings(
                blankDefault(form.get("username"), "cloud-user"),
                key1,
                key2,
                clamp(parseInt(form.get("port")).orElse(22), 1, 65535),
                clamp(parseInt(form.get("timeout")).orElse(30), 5, 300),
                clamp(parseInt(form.get("concurrency")).orElse(3), 1, 20),
                "on".equals(form.get("reboot")),
                "on".equals(form.get("makecache")),
                "on".equals(form.get("skipBroken"))
        );

        Job job = new Job(UUID.randomUUID().toString(), hosts, settings);
        jobs.put(job.id, job);
        jobPool.submit(() -> runJob(job));
        send(exchange, 200, "application/json", "{\"jobId\":\"" + escapeJson(job.id) + "\"}");
    }

    private void handleJob(HttpExchange exchange) throws IOException {
        URI uri = exchange.getRequestURI();
        String[] parts = uri.getPath().split("/");
        if (parts.length < 4) {
            send(exchange, 404, "text/plain", "Not found");
            return;
        }
        Job job = jobs.get(parts[3]);
        if (job == null) {
            send(exchange, 404, "text/plain", "Job not found");
            return;
        }
        if (parts.length >= 5 && "events".equals(parts[4])) {
            streamEvents(exchange, job);
            return;
        }
        send(exchange, 200, "application/json", job.toJson());
    }

    private void streamEvents(HttpExchange exchange, Job job) throws IOException {
        Headers headers = exchange.getResponseHeaders();
        headers.set("Content-Type", "text/event-stream; charset=utf-8");
        headers.set("Cache-Control", "no-cache");
        headers.set("Connection", "keep-alive");
        exchange.sendResponseHeaders(200, 0);

        try (OutputStream body = exchange.getResponseBody();
             PrintWriter writer = new PrintWriter(body, true, StandardCharsets.UTF_8)) {
            AtomicInteger cursor = new AtomicInteger(0);
            while (!job.finished.get() || cursor.get() < job.events.size()) {
                List<Event> snapshot = job.snapshotEvents();
                while (cursor.get() < snapshot.size()) {
                    Event event = snapshot.get(cursor.getAndIncrement());
                    writer.print("event: log\n");
                    writer.print("data: " + event.toJson() + "\n\n");
                    writer.flush();
                }
                if (!job.finished.get()) {
                    writer.print(": ping\n\n");
                    writer.flush();
                }
                sleep(750);
            }
            writer.print("event: done\n");
            writer.print("data: " + job.toJson() + "\n\n");
            writer.flush();
        } catch (IOException ignored) {
            // Browser tab closed; the job keeps running.
        } finally {
            exchange.close();
        }
    }

    private void runJob(Job job) {
        job.add("system", "info", "Started job for " + job.hosts.size() + " server(s).");
        Semaphore semaphore = new Semaphore(job.settings.concurrency);
        List<CompletableFuture<Void>> futures = new ArrayList<>();

        for (String host : job.hosts) {
            futures.add(CompletableFuture.runAsync(() -> {
                boolean acquired = false;
                try {
                    semaphore.acquire();
                    acquired = true;
                    updateOneHost(job, host);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    job.fail(host, "Interrupted before starting.");
                } finally {
                    if (acquired) {
                        semaphore.release();
                    }
                }
            }, jobPool));
        }

        CompletableFuture.allOf(futures.toArray(CompletableFuture[]::new)).join();
        job.finished.set(true);
        job.add("system", job.failed.get() == 0 ? "success" : "error",
                "Finished. Success: " + job.succeeded.get() + ", failed: " + job.failed.get() + ".");
    }

    private void updateOneHost(Job job, String host) {
        job.startHost(host);
        Session session = null;
        try {
            session = connect(job, host);
            runRemote(job, host, session, "hostnamectl || hostname");
            if (job.settings.makecache) {
                runRemote(job, host, session, "sudo -n dnf -y makecache --refresh");
            }
            String updateCommand = "sudo -n dnf -y update --security";
            if (job.settings.skipBroken) {
                updateCommand += " --skip-broken";
            }
            runRemote(job, host, session, updateCommand);
            runRemote(job, host, session, "if command -v needs-restarting >/dev/null 2>&1; then sudo -n needs-restarting -r; else echo 'needs-restarting not installed; continuing'; fi", true);
            runRemote(job, host, session, "sync");
            if (job.settings.reboot) {
                job.add(host, "info", "Reboot requested. SSH may disconnect now.");
                runRemote(job, host, session, "sudo -n systemctl reboot -i || sudo -n reboot", true);
            }
            job.succeed(host, job.settings.reboot ? "Update command finished and reboot was requested." : "Update command finished.");
        } catch (Exception e) {
            job.fail(host, e.getMessage());
        } finally {
            if (session != null) {
                session.disconnect();
            }
        }
    }

    private Session connect(Job job, String host) throws JSchException, IOException {
        List<Path> keys = new ArrayList<>();
        if (Files.isRegularFile(job.settings.key1)) {
            keys.add(job.settings.key1);
        }
        if (Files.isRegularFile(job.settings.key2) && !Objects.equals(job.settings.key1, job.settings.key2)) {
            keys.add(job.settings.key2);
        }
        if (keys.isEmpty()) {
            throw new IOException("No readable PPK key files were found.");
        }

        JSchException last = null;
        for (Path key : keys) {
            JSch jsch = new JSch();
            try {
                job.add(host, "info", "Trying SSH key: " + key.getFileName());
                jsch.addIdentity(key.toString());
                Session session = jsch.getSession(job.settings.username, host, job.settings.port);
                session.setConfig("StrictHostKeyChecking", "no");
                session.setConfig("PreferredAuthentications", "publickey");
                session.setTimeout(job.settings.timeoutSeconds * 1000);
                session.connect(job.settings.timeoutSeconds * 1000);
                job.add(host, "success", "Connected with " + key.getFileName());
                return session;
            } catch (JSchException e) {
                last = e;
                job.add(host, "warn", "Key failed: " + key.getFileName() + " (" + cleanMessage(e) + ")");
            }
        }
        throw last == null ? new JSchException("SSH authentication failed.") : last;
    }

    private void runRemote(Job job, String host, Session session, String command) throws Exception {
        runRemote(job, host, session, command, false);
    }

    private void runRemote(Job job, String host, Session session, String command, boolean allowNonZero) throws Exception {
        job.add(host, "cmd", "$ " + command);
        ChannelExec channel = (ChannelExec) session.openChannel("exec");
        channel.setCommand(command);
        channel.setPty(true);
        ByteArrayOutputStream err = new ByteArrayOutputStream();
        channel.setErrStream(err);

        try (InputStream output = channel.getInputStream()) {
            channel.connect();
            readChannel(job, host, output, channel);
            String errorText = err.toString(StandardCharsets.UTF_8);
            if (!errorText.isBlank()) {
                errorText.lines().forEach(line -> job.add(host, "warn", line));
            }
            int status = channel.getExitStatus();
            if (status != 0 && !allowNonZero) {
                throw new IOException("Command failed with exit code " + status + ": " + command);
            }
            if (status != 0) {
                job.add(host, "warn", "Command exited with " + status + " but was allowed to continue.");
            }
        } finally {
            channel.disconnect();
        }
    }

    private void readChannel(Job job, String host, InputStream input, ChannelExec channel) throws IOException {
        BufferedReader reader = new BufferedReader(new InputStreamReader(input, StandardCharsets.UTF_8));
        StringBuilder pending = new StringBuilder();
        while (!channel.isClosed() || reader.ready()) {
            while (reader.ready()) {
                int ch = reader.read();
                if (ch < 0) {
                    break;
                }
                if (ch == '\n') {
                    emitLine(job, host, pending);
                } else if (ch != '\r') {
                    pending.append((char) ch);
                }
            }
            sleep(100);
        }
        emitLine(job, host, pending);
    }

    private void emitLine(Job job, String host, StringBuilder pending) {
        if (!pending.isEmpty()) {
            job.add(host, "out", pending.toString());
            pending.setLength(0);
        }
    }

    private static Map<String, String> readForm(HttpExchange exchange) throws IOException {
        String body = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
        Map<String, String> values = new LinkedHashMap<>();
        for (String pair : body.split("&")) {
            if (pair.isBlank()) {
                continue;
            }
            String[] pieces = pair.split("=", 2);
            String key = decode(pieces[0]);
            String value = pieces.length == 2 ? decode(pieces[1]) : "";
            values.put(key, value);
        }
        return values;
    }

    private static String decode(String value) {
        return URLDecoder.decode(value, StandardCharsets.UTF_8);
    }

    private static void send(HttpExchange exchange, int status, String contentType, String body) throws IOException {
        byte[] data = body.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", contentType);
        exchange.sendResponseHeaders(status, data.length);
        try (OutputStream output = exchange.getResponseBody()) {
            output.write(data);
        }
    }

    private static String blankDefault(String value, String fallback) {
        return value == null || value.isBlank() ? fallback : value.trim();
    }

    private static Optional<Integer> parseInt(String value) {
        try {
            return value == null || value.isBlank() ? Optional.empty() : Optional.of(Integer.parseInt(value.trim()));
        } catch (NumberFormatException e) {
            return Optional.empty();
        }
    }

    private static int clamp(int value, int min, int max) {
        return Math.max(min, Math.min(max, value));
    }

    private static void sleep(long millis) {
        try {
            Thread.sleep(millis);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    private static String cleanMessage(Exception e) {
        return Optional.ofNullable(e.getMessage()).orElse(e.getClass().getSimpleName()).replace("\"", "'");
    }

    private static String escapeJson(String value) {
        StringBuilder builder = new StringBuilder(value.length() + 16);
        for (int i = 0; i < value.length(); i++) {
            char ch = value.charAt(i);
            switch (ch) {
                case '"' -> builder.append("\\\"");
                case '\\' -> builder.append("\\\\");
                case '\b' -> builder.append("\\b");
                case '\f' -> builder.append("\\f");
                case '\n' -> builder.append("\\n");
                case '\r' -> builder.append("\\r");
                case '\t' -> builder.append("\\t");
                default -> {
                    if (ch < 0x20) {
                        builder.append(String.format("\\u%04x", (int) ch));
                    } else {
                        builder.append(ch);
                    }
                }
            }
        }
        return builder.toString();
    }

    private record Settings(
            String username,
            Path key1,
            Path key2,
            int port,
            int timeoutSeconds,
            int concurrency,
            boolean reboot,
            boolean makecache,
            boolean skipBroken
    ) {
    }

    private static final class Job {
        private final String id;
        private final List<String> hosts;
        private final Settings settings;
        private final ConcurrentLinkedDeque<Event> events = new ConcurrentLinkedDeque<>();
        private final Map<String, String> hostStatus = new ConcurrentHashMap<>();
        private final AtomicBoolean finished = new AtomicBoolean(false);
        private final AtomicInteger succeeded = new AtomicInteger(0);
        private final AtomicInteger failed = new AtomicInteger(0);

        private Job(String id, List<String> hosts, Settings settings) {
            this.id = id;
            this.hosts = List.copyOf(hosts);
            this.settings = settings;
            hosts.forEach(host -> hostStatus.put(host, "queued"));
        }

        private void startHost(String host) {
            hostStatus.put(host, "running");
            add(host, "info", "Starting.");
        }

        private void succeed(String host, String message) {
            hostStatus.put(host, "success");
            succeeded.incrementAndGet();
            add(host, "success", message);
        }

        private void fail(String host, String message) {
            hostStatus.put(host, "failed");
            failed.incrementAndGet();
            add(host, "error", message == null ? "Failed." : message);
        }

        private void add(String host, String level, String message) {
            events.add(new Event(Instant.now(), host, level, message));
            while (events.size() > MAX_EVENT_HISTORY) {
                events.pollFirst();
            }
        }

        private List<Event> snapshotEvents() {
            return new ArrayList<>(events);
        }

        private String toJson() {
            StringBuilder statusJson = new StringBuilder("{");
            List<String> sortedHosts = new ArrayList<>(hostStatus.keySet());
            Collections.sort(sortedHosts);
            for (int i = 0; i < sortedHosts.size(); i++) {
                String host = sortedHosts.get(i);
                if (i > 0) {
                    statusJson.append(',');
                }
                statusJson.append('"').append(escapeJson(host)).append("\":\"")
                        .append(escapeJson(hostStatus.get(host))).append('"');
            }
            statusJson.append('}');
            return "{"
                    + "\"id\":\"" + escapeJson(id) + "\","
                    + "\"finished\":" + finished.get() + ","
                    + "\"total\":" + hosts.size() + ","
                    + "\"succeeded\":" + succeeded.get() + ","
                    + "\"failed\":" + failed.get() + ","
                    + "\"statuses\":" + statusJson
                    + "}";
        }
    }

    private record Event(Instant at, String host, String level, String message) {
        private String toJson() {
            return "{"
                    + "\"time\":\"" + CLOCK.format(at) + "\","
                    + "\"host\":\"" + escapeJson(host) + "\","
                    + "\"level\":\"" + escapeJson(level.toLowerCase(Locale.ROOT)) + "\","
                    + "\"message\":\"" + escapeJson(message) + "\""
                    + "}";
        }
    }

    private static final class Html {
        private static final String INDEX = """
                <!doctype html>
                <html lang="en">
                <head>
                  <meta charset="utf-8">
                  <meta name="viewport" content="width=device-width, initial-scale=1">
                  <title>DNF Security Update Console</title>
                  <style>
                    :root {
                      color-scheme: light;
                      --ink: #17202a;
                      --muted: #64748b;
                      --line: #d8dee9;
                      --panel: #ffffff;
                      --wash: #f4f7fb;
                      --blue: #1d4ed8;
                      --green: #15803d;
                      --red: #b91c1c;
                      --amber: #a16207;
                      --mono: "SFMono-Regular", Consolas, "Liberation Mono", monospace;
                      font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
                    }
                    * { box-sizing: border-box; }
                    body {
                      margin: 0;
                      min-height: 100vh;
                      background: var(--wash);
                      color: var(--ink);
                    }
                    header {
                      border-bottom: 1px solid var(--line);
                      background: #fff;
                    }
                    .wrap {
                      width: min(1180px, calc(100vw - 32px));
                      margin: 0 auto;
                    }
                    header .wrap {
                      display: flex;
                      justify-content: space-between;
                      align-items: center;
                      min-height: 72px;
                      gap: 16px;
                    }
                    h1 {
                      font-size: 22px;
                      margin: 0;
                      letter-spacing: 0;
                    }
                    .subtitle {
                      color: var(--muted);
                      font-size: 13px;
                      margin-top: 4px;
                    }
                    main.wrap {
                      display: grid;
                      grid-template-columns: 380px minmax(0, 1fr);
                      gap: 18px;
                      padding: 18px 0;
                    }
                    section {
                      background: var(--panel);
                      border: 1px solid var(--line);
                      border-radius: 8px;
                    }
                    .controls {
                      padding: 16px;
                      align-self: start;
                    }
                    label {
                      display: block;
                      font-size: 13px;
                      font-weight: 700;
                      margin-bottom: 6px;
                    }
                    input, textarea {
                      width: 100%;
                      border: 1px solid #cbd5e1;
                      border-radius: 6px;
                      padding: 10px 11px;
                      font: inherit;
                      color: var(--ink);
                      background: #fff;
                    }
                    textarea {
                      min-height: 210px;
                      resize: vertical;
                      font-family: var(--mono);
                      font-size: 13px;
                    }
                    .field { margin-bottom: 14px; }
                    .grid2 {
                      display: grid;
                      grid-template-columns: 1fr 1fr;
                      gap: 12px;
                    }
                    .check {
                      display: flex;
                      align-items: center;
                      gap: 10px;
                      padding: 9px 0;
                      color: var(--ink);
                      font-size: 14px;
                    }
                    .check input {
                      width: 18px;
                      height: 18px;
                    }
                    button {
                      width: 100%;
                      border: 0;
                      border-radius: 6px;
                      background: var(--blue);
                      color: #fff;
                      padding: 12px 14px;
                      font-weight: 800;
                      cursor: pointer;
                    }
                    button:disabled {
                      opacity: .6;
                      cursor: wait;
                    }
                    .statusbar {
                      display: grid;
                      grid-template-columns: repeat(4, 1fr);
                      gap: 10px;
                      padding: 14px;
                      border-bottom: 1px solid var(--line);
                    }
                    .stat {
                      border: 1px solid var(--line);
                      border-radius: 8px;
                      padding: 10px;
                      min-width: 0;
                    }
                    .stat b {
                      display: block;
                      font-size: 22px;
                    }
                    .stat span {
                      color: var(--muted);
                      font-size: 12px;
                    }
                    .hosts {
                      display: flex;
                      gap: 8px;
                      flex-wrap: wrap;
                      padding: 12px 14px;
                      border-bottom: 1px solid var(--line);
                      min-height: 54px;
                    }
                    .pill {
                      border: 1px solid var(--line);
                      border-radius: 999px;
                      padding: 5px 10px;
                      font-size: 12px;
                      background: #fff;
                    }
                    .pill.running { border-color: var(--blue); color: var(--blue); }
                    .pill.success { border-color: var(--green); color: var(--green); }
                    .pill.failed { border-color: var(--red); color: var(--red); }
                    .logs {
                      height: 590px;
                      overflow: auto;
                      background: #101820;
                      color: #e5edf5;
                      border-radius: 0 0 8px 8px;
                      padding: 12px;
                      font-family: var(--mono);
                      font-size: 13px;
                      line-height: 1.45;
                    }
                    .line {
                      white-space: pre-wrap;
                      overflow-wrap: anywhere;
                      padding: 1px 0;
                    }
                    .time { color: #94a3b8; }
                    .host { color: #93c5fd; }
                    .cmd { color: #fbbf24; }
                    .success { color: #86efac; }
                    .error { color: #fca5a5; }
                    .warn { color: #fde68a; }
                    .muted { color: var(--muted); font-size: 12px; margin-top: 6px; }
                    @media (max-width: 880px) {
                      main.wrap { grid-template-columns: 1fr; }
                      .statusbar { grid-template-columns: repeat(2, 1fr); }
                      header .wrap { align-items: flex-start; flex-direction: column; justify-content: center; padding: 12px 0; }
                    }
                  </style>
                </head>
                <body>
                  <header>
                    <div class="wrap">
                      <div>
                        <h1>DNF Security Update Console</h1>
                        <div class="subtitle">Runs <code>dnf update --security</code> over SSH, streams progress, then reboots selected servers.</div>
                      </div>
                      <div class="subtitle">Keys are loaded from the JAR folder</div>
                    </div>
                  </header>
                  <main class="wrap">
                    <section class="controls">
                      <form id="jobForm">
                        <div class="field">
                          <label for="hosts">Servers</label>
                          <textarea id="hosts" name="hosts" placeholder="10.0.1.10&#10;10.0.1.11"></textarea>
                          <div class="muted">One IP or hostname per line. Lines starting with # are ignored.</div>
                        </div>
                        <div class="grid2">
                          <div class="field">
                            <label for="username">SSH user</label>
                            <input id="username" name="username" value="cloud-user">
                          </div>
                          <div class="field">
                            <label for="port">SSH port</label>
                            <input id="port" name="port" value="22" inputmode="numeric">
                          </div>
                        </div>
                        <div class="grid2">
                          <div class="field">
                            <label for="key1">Primary PPK</label>
                            <input id="key1" name="key1" value="key1.ppk">
                          </div>
                          <div class="field">
                            <label for="key2">Fallback PPK</label>
                            <input id="key2" name="key2" value="key2.ppk">
                          </div>
                        </div>
                        <div class="grid2">
                          <div class="field">
                            <label for="concurrency">Parallel servers</label>
                            <input id="concurrency" name="concurrency" value="3" inputmode="numeric">
                          </div>
                          <div class="field">
                            <label for="timeout">SSH timeout sec</label>
                            <input id="timeout" name="timeout" value="30" inputmode="numeric">
                          </div>
                        </div>
                        <label class="check"><input type="checkbox" name="makecache" checked> Refresh DNF cache first</label>
                        <label class="check"><input type="checkbox" name="skipBroken"> Add --skip-broken</label>
                        <label class="check"><input type="checkbox" name="reboot" checked> Reboot after update</label>
                        <button id="runButton" type="submit">Start Update</button>
                      </form>
                    </section>
                    <section>
                      <div class="statusbar">
                        <div class="stat"><b id="total">0</b><span>Total</span></div>
                        <div class="stat"><b id="running">0</b><span>Running</span></div>
                        <div class="stat"><b id="succeeded">0</b><span>Succeeded</span></div>
                        <div class="stat"><b id="failed">0</b><span>Failed</span></div>
                      </div>
                      <div id="hostsView" class="hosts"></div>
                      <div id="logs" class="logs" aria-live="polite"></div>
                    </section>
                  </main>
                  <script>
                    const form = document.getElementById('jobForm');
                    const logs = document.getElementById('logs');
                    const runButton = document.getElementById('runButton');
                    const hostsView = document.getElementById('hostsView');
                    const counts = {
                      total: document.getElementById('total'),
                      running: document.getElementById('running'),
                      succeeded: document.getElementById('succeeded'),
                      failed: document.getElementById('failed')
                    };
                    let source = null;

                    function appendLine(event) {
                      const row = document.createElement('div');
                      row.className = 'line';
                      row.innerHTML = `<span class="time">[${escapeHtml(event.time)}]</span> <span class="host">${escapeHtml(event.host)}</span> <span class="${escapeHtml(event.level)}">${escapeHtml(event.level.toUpperCase())}</span> ${escapeHtml(event.message)}`;
                      logs.appendChild(row);
                      logs.scrollTop = logs.scrollHeight;
                    }

                    function updateSummary(job) {
                      counts.total.textContent = job.total || 0;
                      counts.succeeded.textContent = job.succeeded || 0;
                      counts.failed.textContent = job.failed || 0;
                      const statuses = job.statuses || {};
                      counts.running.textContent = Object.values(statuses).filter(v => v === 'running').length;
                      hostsView.innerHTML = '';
                      Object.keys(statuses).sort().forEach(host => {
                        const pill = document.createElement('span');
                        pill.className = `pill ${statuses[host]}`;
                        pill.textContent = `${host} · ${statuses[host]}`;
                        hostsView.appendChild(pill);
                      });
                    }

                    function escapeHtml(text) {
                      return String(text ?? '').replace(/[&<>"']/g, ch => ({
                        '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
                      }[ch]));
                    }

                    form.addEventListener('submit', async (event) => {
                      event.preventDefault();
                      if (source) source.close();
                      logs.innerHTML = '';
                      hostsView.innerHTML = '';
                      runButton.disabled = true;
                      runButton.textContent = 'Running...';
                      try {
                        const response = await fetch('/api/start', {
                          method: 'POST',
                          body: new URLSearchParams(new FormData(form))
                        });
                        const data = await response.json();
                        if (!response.ok) throw new Error(data.error || 'Unable to start job.');
                        source = new EventSource(`/api/job/${encodeURIComponent(data.jobId)}/events`);
                        source.addEventListener('log', (message) => appendLine(JSON.parse(message.data)));
                        source.addEventListener('done', (message) => {
                          updateSummary(JSON.parse(message.data));
                          source.close();
                          runButton.disabled = false;
                          runButton.textContent = 'Start Update';
                        });
                        source.onerror = () => {
                          appendLine({time: new Date().toLocaleTimeString(), host: 'ui', level: 'warn', message: 'Live connection dropped. The backend job may still be running.'});
                        };
                        const timer = setInterval(async () => {
                          if (!source || source.readyState === EventSource.CLOSED) {
                            clearInterval(timer);
                            return;
                          }
                          const status = await fetch(`/api/job/${encodeURIComponent(data.jobId)}`).then(r => r.json());
                          updateSummary(status);
                        }, 1200);
                      } catch (error) {
                        appendLine({time: new Date().toLocaleTimeString(), host: 'ui', level: 'error', message: error.message});
                        runButton.disabled = false;
                        runButton.textContent = 'Start Update';
                      }
                    });
                  </script>
                </body>
                </html>
                """;
    }
}
