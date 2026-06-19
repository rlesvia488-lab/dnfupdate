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
import java.net.URLEncoder;
import java.net.URLDecoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.Comparator;
import java.util.Collection;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.TreeSet;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedDeque;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Semaphore;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public final class DnfUpdateApp {
    private static final int DEFAULT_PORT = 8080;
    private static final int MAX_EVENT_HISTORY = 2000;
    private static final String AUDIT_LOG_FILE = "patch-audit.log";
    private static final String STATUS_LOG_FILE = "status-checks.tsv";
    private static final String REPORT_DIR = "reports";
    private static final long REBOOT_VERIFY_TIMEOUT_MILLIS = 5 * 60 * 1000L;
    private static final long REBOOT_VERIFY_INTERVAL_MILLIS = 10 * 1000L;
    private static final Pattern RHSA_PATTERN = Pattern.compile("\\bRHSA-\\d{4}:\\d+\\b");
    private static final List<String> HEALTHCHECK_URLS = List.of(
            "http://127.0.0.1:8080/actuator/health",
            "https://127.0.0.1:8443/actuator/health",
            "https://127.0.0.1:8443/health",
            "https://127.0.0.1:8443/mgw/health",
            "https://127.0.0.1:8443/services/Version",
            "https://127.0.0.1:8443/api/health-check/v1.0/health"
    );
    private static final List<AuthPassphrase> AUTHORIZED_PASSPHRASES = List.of(
            new AuthPassphrase("member-01", "955d62e5e35a83af2a33e6d0b81bcd6a8fee326a9c353044a4763eb79b6c6828"),
            new AuthPassphrase("member-02", "4baea3706961d4f19c23486e254b097801247318759716d357f4c4291b9b08db"),
            new AuthPassphrase("member-03", "2bbc56ba0c56a5b3f467efb9fc5d39c3f4b9e69927def3f77131ded825240425"),
            new AuthPassphrase("member-04", "0bf620d498213ed4d36edcf4268a012d89717d0069badb493f44025245bc07fa"),
            new AuthPassphrase("member-05", "729f821b4cd92998f74607d710ef9fc65cd9438b17191d2b61a72ad3b4f4f917"),
            new AuthPassphrase("member-06", "9715a70fa988651ec048d063b97f0bdd7268f9127b93773dc44ed66015f19fbb"),
            new AuthPassphrase("member-07", "a11d4e261748573bfc29ac00e69fc22e66c32c12ddd69fd7c2116b5283ac969d"),
            new AuthPassphrase("member-08", "b18f68e4553f71894dfd81ccdcadac3ff893e8c6387bfdc364b6ca48c60ff489"),
            new AuthPassphrase("member-09", "639646ccc08a8bce3e09f00e0d9a489e2bd72a4b430724dd705d878970c3e579"),
            new AuthPassphrase("member-10", "f3d0938da118f9be94bcf46ce4abd42d4f4af968455b68364b99e7161331d643"),
            new AuthPassphrase("member-11", "204dacab88e78a161f6519e98089a3006281100b6dfe51ddce885ce59e3b1f0a"),
            new AuthPassphrase("member-12", "590e633ffec79c6d4b04c881c690d39ccb8eafb011ef473a847a9176ca214cdb"),
            new AuthPassphrase("member-13", "a02593564740608962aadad6b31da0351b3e74efb3af12e580150734262ba687"),
            new AuthPassphrase("member-14", "bbcf55582e9df7f189aa9c9ea5b46a6b005c6e54d81fed8c9045e030a80862c3")
    );
    private static final DateTimeFormatter CLOCK =
            DateTimeFormatter.ofPattern("HH:mm:ss").withZone(ZoneId.systemDefault());
    private static final DateTimeFormatter REPORT_FILE_CLOCK =
            DateTimeFormatter.ofPattern("yyyyMMdd-HHmmss").withZone(ZoneId.systemDefault());
    private static final DateTimeFormatter REPORT_DISPLAY_CLOCK =
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss z").withZone(ZoneId.systemDefault());

    private final Map<String, Job> jobs = new ConcurrentHashMap<>();
    private final ExecutorService jobPool = Executors.newCachedThreadPool();
    private final Path appDir;
    private volatile VaultStatus vaultStatus = VaultStatus.disabled("Vault is disabled.");
    private volatile String vaultClientToken = "";

    private DnfUpdateApp(Path appDir) {
        this.appDir = appDir;
    }

    public static void main(String[] args) throws Exception {
        int port = Optional.ofNullable(System.getenv("DNF_UPDATE_PORT"))
                .flatMap(DnfUpdateApp::parseInt)
                .orElse(DEFAULT_PORT);

        Path appDir = findAppDir();
        DnfUpdateApp app = new DnfUpdateApp(appDir);
        app.initializeVault();
        HttpServer server = HttpServer.create(new InetSocketAddress(port), 0);
        server.createContext("/patching", app::handlePatching);
        server.createContext("/dryrun", app::handleDryRunReports);
        server.createContext("/status", app::handleStatus);
        server.createContext("/vault", app::handleVault);
        server.createContext("/reports", app::handleReportFile);
        server.createContext("/", app::handleIndex);
        server.createContext("/api/start", app::handleStart);
        server.createContext("/api/technical-accounts", app::handleTechnicalAccounts);
        server.createContext("/api/job", app::handleJob);
        server.setExecutor(Executors.newCachedThreadPool());
        server.start();
        System.out.println("DNF Update UI running at http://localhost:" + port);
        System.out.println("Looking for key files next to the JAR in: " + appDir.toAbsolutePath());
        System.out.println("Patch audit log: " + appDir.resolve(AUDIT_LOG_FILE).toAbsolutePath());
        System.out.println("Post-reboot status log: " + appDir.resolve(STATUS_LOG_FILE).toAbsolutePath());
        System.out.println("HTML reports directory: " + appDir.resolve(REPORT_DIR).toAbsolutePath());
        System.out.println("Vault status: " + app.vaultStatus.state() + " - " + app.vaultStatus.message());
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

    private void initializeVault() {
        VaultConfig config = VaultConfig.fromRuntime();
        if (!config.enabled()) {
            vaultStatus = VaultStatus.disabled("Vault is disabled. Set VAULT_ENABLED=true in start.sh to enable it.");
            return;
        }
        if (config.uri().isBlank() || config.roleId().isBlank() || config.secretId().isBlank()) {
            vaultStatus = VaultStatus.down(config, "Vault is enabled, but VAULT_URI, VAULT_ROLE_ID, or VAULT_SECRET_ID is missing.");
            return;
        }

        try {
            URI loginUri = URI.create(stripTrailingSlash(config.uri()) + "/v1/auth/approle/login");
            String body = "{\"role_id\":\"" + escapeJson(config.roleId()) + "\",\"secret_id\":\"" + escapeJson(config.secretId()) + "\"}";
            HttpRequest.Builder requestBuilder = HttpRequest.newBuilder(loginUri)
                    .timeout(Duration.ofMillis(5000))
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(body, StandardCharsets.UTF_8));
            if (!config.namespace().isBlank()) {
                requestBuilder.header("X-Vault-Namespace", config.namespace());
            }

            HttpClient client = HttpClient.newBuilder()
                    .connectTimeout(Duration.ofMillis(5000))
                    .build();
            HttpResponse<String> response = client.send(requestBuilder.build(), HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
            Optional<String> token = extractJsonString(response.body(), "client_token");
            if (response.statusCode() >= 200 && response.statusCode() < 300 && token.isPresent()) {
                vaultClientToken = token.get();
                vaultStatus = VaultStatus.up(config, "Connected to Vault with AppRole. Token was received and kept only in memory for the login check.");
            } else {
                vaultClientToken = "";
                vaultStatus = VaultStatus.down(config, "Vault AppRole login failed with HTTP " + response.statusCode() + ".");
            }
        } catch (Exception e) {
            vaultClientToken = "";
            vaultStatus = VaultStatus.down(config, "Vault connection failed: " + cleanMessage(e));
        }
    }

    private static String stripTrailingSlash(String value) {
        String result = value.trim();
        while (result.endsWith("/")) {
            result = result.substring(0, result.length() - 1);
        }
        return result;
    }

    private static Optional<String> extractJsonString(String json, String key) {
        if (json == null || json.isBlank()) {
            return Optional.empty();
        }
        Pattern pattern = Pattern.compile("\"" + Pattern.quote(key) + "\"\\s*:\\s*\"((?:\\\\.|[^\"])*)\"");
        Matcher matcher = pattern.matcher(json);
        if (!matcher.find()) {
            return Optional.empty();
        }
        return Optional.of(unescapeJsonString(matcher.group(1)));
    }

    private static String unescapeJsonString(String value) {
        StringBuilder builder = new StringBuilder(value.length());
        for (int i = 0; i < value.length(); i++) {
            char ch = value.charAt(i);
            if (ch == '\\' && i + 1 < value.length()) {
                char next = value.charAt(++i);
                switch (next) {
                    case '"', '\\', '/' -> builder.append(next);
                    case 'b' -> builder.append('\b');
                    case 'f' -> builder.append('\f');
                    case 'n' -> builder.append('\n');
                    case 'r' -> builder.append('\r');
                    case 't' -> builder.append('\t');
                    default -> builder.append(next);
                }
            } else {
                builder.append(ch);
            }
        }
        return builder.toString();
    }

    private void handleIndex(HttpExchange exchange) throws IOException {
        if (!"GET".equalsIgnoreCase(exchange.getRequestMethod())) {
            send(exchange, 405, "text/plain", "Method not allowed");
            return;
        }
        String path = exchange.getRequestURI().getPath();
        if ("/status".equals(path) || "/status/".equals(path)) {
            send(exchange, 200, "text/html; charset=utf-8", buildStatusPage());
            return;
        }
        if ("/patching".equals(path) || "/patching/".equals(path)) {
            send(exchange, 200, "text/html; charset=utf-8", buildReportsIndex(ReportKind.PATCH));
            return;
        }
        if ("/dryrun".equals(path) || "/dryrun/".equals(path)) {
            send(exchange, 200, "text/html; charset=utf-8", buildReportsIndex(ReportKind.DRY_RUN));
            return;
        }
        if ("/vault".equals(path) || "/vault/".equals(path)) {
            send(exchange, 200, "text/html; charset=utf-8", buildVaultPage());
            return;
        }
        send(exchange, 200, "text/html; charset=utf-8", Html.INDEX);
    }

    private void handlePatching(HttpExchange exchange) throws IOException {
        if (!"GET".equalsIgnoreCase(exchange.getRequestMethod())) {
            send(exchange, 405, "text/plain", "Method not allowed");
            return;
        }
        send(exchange, 200, "text/html; charset=utf-8", buildReportsIndex(ReportKind.PATCH));
    }

    private void handleDryRunReports(HttpExchange exchange) throws IOException {
        if (!"GET".equalsIgnoreCase(exchange.getRequestMethod())) {
            send(exchange, 405, "text/plain", "Method not allowed");
            return;
        }
        send(exchange, 200, "text/html; charset=utf-8", buildReportsIndex(ReportKind.DRY_RUN));
    }

    private void handleStatus(HttpExchange exchange) throws IOException {
        if (!"GET".equalsIgnoreCase(exchange.getRequestMethod())) {
            send(exchange, 405, "text/plain", "Method not allowed");
            return;
        }
        send(exchange, 200, "text/html; charset=utf-8", buildStatusPage());
    }

    private void handleVault(HttpExchange exchange) throws IOException {
        if (!"GET".equalsIgnoreCase(exchange.getRequestMethod())) {
            send(exchange, 405, "text/plain", "Method not allowed");
            return;
        }
        send(exchange, 200, "text/html; charset=utf-8", buildVaultPage());
    }

    private void handleReportFile(HttpExchange exchange) throws IOException {
        if (!"GET".equalsIgnoreCase(exchange.getRequestMethod())) {
            send(exchange, 405, "text/plain", "Method not allowed");
            return;
        }

        String prefix = "/reports/";
        String path = exchange.getRequestURI().getPath();
        if (!path.startsWith(prefix) || path.length() <= prefix.length()) {
            send(exchange, 404, "text/plain", "Report not found");
            return;
        }

        String requestedName = URLDecoder.decode(path.substring(prefix.length()), StandardCharsets.UTF_8);
        if (requestedName.contains("/") || requestedName.contains("\\") || !requestedName.endsWith(".html")) {
            send(exchange, 400, "text/plain", "Invalid report name");
            return;
        }

        Path reportsDir = appDir.resolve(REPORT_DIR).normalize();
        Path report = reportsDir.resolve(requestedName).normalize();
        if (!report.startsWith(reportsDir) || !Files.isRegularFile(report)) {
            send(exchange, 404, "text/plain", "Report not found");
            return;
        }

        byte[] data = Files.readAllBytes(report);
        exchange.getResponseHeaders().set("Content-Type", "text/html; charset=utf-8");
        exchange.sendResponseHeaders(200, data.length);
        try (OutputStream output = exchange.getResponseBody()) {
            output.write(data);
        }
    }

    private void handleStart(HttpExchange exchange) throws IOException {
        if (!"POST".equalsIgnoreCase(exchange.getRequestMethod())) {
            send(exchange, 405, "application/json", "{\"error\":\"Method not allowed\"}");
            return;
        }

        Map<String, String> form = readForm(exchange);
        Optional<String> authorizedMember = authorizedMember(form.get("passphrase"));
        if (authorizedMember.isEmpty()) {
            send(exchange, 403, "application/json", "{\"error\":\"Invalid patch passphrase.\"}");
            return;
        }

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

        String technicalAccountName = form.getOrDefault("technicalAccount", "").trim();
        if (technicalAccountName.isBlank()) {
            send(exchange, 400, "application/json", "{\"error\":\"Select a Vault technical account.\"}");
            return;
        }
        try {
            CloudRecoveryConfig recoveryConfig = loadCloudRecoveryConfig(vaultStatus.config());
            if (findTechnicalAccount(recoveryConfig, technicalAccountName).isEmpty()) {
                send(exchange, 400, "application/json", "{\"error\":\"The selected Vault technical account is not available. Refresh the page and try again.\"}");
                return;
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            send(exchange, 503, "application/json", "{\"error\":\"Loading Vault technical accounts was interrupted.\"}");
            return;
        } catch (Exception e) {
            send(exchange, 503, "application/json", "{\"error\":\"Unable to validate the Vault technical account: "
                    + escapeJson(cleanMessage(e)) + "\"}");
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
                "on".equals(form.get("skipBroken")),
                "on".equals(form.get("dryRun")),
                technicalAccountName
        );

        Job job = new Job(UUID.randomUUID().toString(), hosts, settings, authorizedMember.get());
        appendAuditLog(authorizedMember.get(), hosts, technicalAccountName);
        jobs.put(job.id, job);
        jobPool.submit(() -> runJob(job));
        send(exchange, 200, "application/json", "{\"jobId\":\"" + escapeJson(job.id) + "\"}");
    }

    private Optional<String> authorizedMember(String submitted) {
        String normalized = submitted == null ? "" : submitted.trim();
        if (normalized.isBlank()) {
            return Optional.empty();
        }

        String submittedHash = sha256Hex(normalized);
        for (AuthPassphrase passphrase : AUTHORIZED_PASSPHRASES) {
            if (constantTimeEquals(submittedHash, passphrase.sha256Hex())) {
                return Optional.of(passphrase.memberId());
            }
        }
        return Optional.empty();
    }

    private void appendAuditLog(String memberId, List<String> hosts, String technicalAccountName) throws IOException {
        String line = Instant.now() + " member=" + memberId + " technicalAccount=" + technicalAccountName
                + " servers=" + String.join(",", hosts) + System.lineSeparator();
        Files.writeString(appDir.resolve(AUDIT_LOG_FILE).normalize(), line, StandardCharsets.UTF_8,
                java.nio.file.StandardOpenOption.CREATE, java.nio.file.StandardOpenOption.APPEND);
    }

    private void handleTechnicalAccounts(HttpExchange exchange) throws IOException {
        if (!"GET".equalsIgnoreCase(exchange.getRequestMethod())) {
            send(exchange, 405, "application/json", "{\"error\":\"Method not allowed\"}");
            return;
        }
        if (!"UP".equals(vaultStatus.state()) || vaultClientToken.isBlank()) {
            send(exchange, 503, "application/json", "{\"error\":\"Vault is not connected.\"}");
            return;
        }
        try {
            CloudRecoveryConfig config = loadCloudRecoveryConfig(vaultStatus.config());
            List<String> names = config.accounts().stream().map(TechnicalAccount::name).distinct().sorted(String.CASE_INSENSITIVE_ORDER).toList();
            StringBuilder json = new StringBuilder("{\"accounts\":[");
            for (int i = 0; i < names.size(); i++) {
                if (i > 0) {
                    json.append(',');
                }
                json.append('\"').append(escapeJson(names.get(i))).append('\"');
            }
            json.append("]}");
            send(exchange, 200, "application/json", json.toString());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            send(exchange, 503, "application/json", "{\"error\":\"Loading Vault technical accounts was interrupted.\"}");
        } catch (Exception e) {
            send(exchange, 503, "application/json", "{\"error\":\"Unable to load Vault technical accounts: "
                    + escapeJson(cleanMessage(e)) + "\"}");
        }
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
        job.add("system", "info", "Started " + (job.settings.dryRun ? "dry run" : "patch job") + " for " + job.hosts.size() + " server(s).");
        job.add("system", "info", (job.settings.dryRun ? "Dry run" : "Patch") + " authorized by " + job.authorizedMember + " for servers: " + String.join(", ", job.hosts));
        job.add("system", "info", "Selected Vault technical account: " + job.settings.technicalAccountName + ".");
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
        try {
            Path report = writeHtmlReport(job);
            job.add("system", "success", "HTML report generated: " + report.toAbsolutePath());
        } catch (IOException e) {
            job.add("system", "error", "Unable to generate HTML report: " + e.getMessage());
        }
        job.finished.set(true);
        job.add("system", job.failed.get() == 0 ? "success" : "error",
                "Finished. Success: " + job.succeeded.get() + ", failed: " + job.failed.get() + ".");
    }

    private void updateOneHost(Job job, String host) {
        job.startHost(host);
        Session session = null;
        HostReport report = job.reportFor(host);
        try {
            session = connect(job, host);
            runRemote(job, host, session, "hostnamectl || hostname");
            if (job.settings.makecache && !job.settings.dryRun) {
                runRemote(job, host, session, "sudo -n dnf -y makecache --refresh");
            }
            RemoteResult beforeSecurity = runRemote(job, host, session, "sudo -n dnf updateinfo list --security --updates", true);
            report.rhsaPresentBefore.addAll(extractRhsa(beforeSecurity.lines()));
            if (report.rhsaPresentBefore.isEmpty()) {
                job.add(host, "info", "No RHSA security advisories are currently available to install.");
            } else {
                job.add(host, "info", "RHSA available to install: " + String.join(", ", report.rhsaPresentBefore));
            }
            if (job.settings.dryRun) {
                RemoteResult installedOnly = runRemote(job, host, session, "sudo -n dnf updateinfo list --security --installed", true);
                report.rhsaInstalledAfter.addAll(extractRhsa(installedOnly.lines()));
                job.succeed(host, "Dry run finished. No update or reboot commands were executed.");
                return;
            }
            String updateCommand = "sudo -n dnf -y update --security";
            if (job.settings.skipBroken) {
                updateCommand += " --skip-broken";
            }
            runRemote(job, host, session, updateCommand);
            RemoteResult afterInstalled = runRemote(job, host, session, "sudo -n dnf updateinfo list --security --installed", true);
            report.rhsaInstalledAfter.addAll(extractRhsa(afterInstalled.lines()));
            report.rhsaCorrected.addAll(report.rhsaPresentBefore);
            report.rhsaCorrected.retainAll(report.rhsaInstalledAfter);
            if (report.rhsaCorrected.isEmpty() && !report.rhsaPresentBefore.isEmpty()) {
                job.add(host, "warn", "No matching corrected RHSA IDs were confirmed in installed updateinfo after patching.");
            } else if (!report.rhsaCorrected.isEmpty()) {
                job.add(host, "success", "RHSA corrected/installed: " + String.join(", ", report.rhsaCorrected));
            }
            runRemote(job, host, session, "if command -v needs-restarting >/dev/null 2>&1; then sudo -n needs-restarting -r; else echo 'needs-restarting not installed; continuing'; fi", true);
            runRemote(job, host, session, "sync");
            if (job.settings.reboot) {
                runRemote(job, host, session, "sudo -n dnf -y remove --oldinstallonly");
                String bootIdBefore = readBootId(job, host, session);
                job.add(host, "info", "Reboot requested. SSH may disconnect now.");
                job.add(host, "info", "After the reboot command is sent, the app will check SSH every 10 seconds for up to 5 minutes.");
                runRemote(job, host, session, "sudo -n sh -c 'nohup sh -c \"sleep 2; systemctl reboot -i || reboot\" >/dev/null 2>&1 &'", true);
                session.disconnect();
                session = null;
                PostRebootStatus status = verifyAfterReboot(job, host, report, bootIdBefore);
                try {
                    appendStatusLog(job, host, status);
                } catch (IOException e) {
                    job.add(host, "warn", "Unable to write post-reboot status log: " + e.getMessage());
                }
                if (!status.machineUp()) {
                    job.fail(host, "Update finished, but server was not reachable over SSH after reboot wait.");
                    return;
                }
                if (!status.serviceUp()) {
                    job.fail(host, "Update finished and server is reachable, but no configured health check returned HTTP 200.");
                    return;
                }
                job.succeed(host, "Update finished, reboot verified, and service is up via " + status.workingHealthcheck().orElse("unknown health check") + ".");
                return;
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

    private String readBootId(Job job, String host, Session session) {
        try {
            RemoteResult result = runRemote(job, host, session, "cat /proc/sys/kernel/random/boot_id", true);
            if (!result.lines().isEmpty()) {
                return result.lines().get(result.lines().size() - 1).trim();
            }
        } catch (Exception e) {
            job.add(host, "warn", "Unable to read Linux boot ID: " + cleanMessage(e));
        }
        return "";
    }

    private PostRebootStatus verifyAfterReboot(Job job, String host, HostReport report, String bootIdBefore) {
        job.add(host, "info", "Starting post-reboot SSH checks every 10 seconds for up to 5 minutes.");
        SshWaitResult sshWait = waitForSsh(job, host, "Post-reboot SSH check attempt ");
        Session verificationSession = sshWait.session();

        if (verificationSession == null) {
            job.add(host, "error", "Server was not reachable over SSH within 5 minutes after reboot. Last error: "
                    + (sshWait.lastFailure() == null ? "timeout" : cleanMessage(sshWait.lastFailure())));
            if (forceHardRebootWithCloudApi(job, host)) {
                job.add(host, "info", "Hard reboot API request was accepted. Checking SSH every 10 seconds for up to 5 minutes.");
                sshWait = waitForSsh(job, host, "Post-hard-reboot SSH check attempt ");
                verificationSession = sshWait.session();
            }
            if (verificationSession == null) {
                report.machineUpAfterReboot = false;
                report.serviceUpAfterReboot = false;
                job.add(host, "error", "Server was still not reachable over SSH after hard reboot API recovery. Last error: "
                        + (sshWait.lastFailure() == null ? "timeout" : cleanMessage(sshWait.lastFailure())));
                return new PostRebootStatus(false, false, Optional.empty());
            }
        }

        try {
            report.machineUpAfterReboot = true;
            job.add(host, "success", "Server is reachable over SSH after reboot.");

            String bootIdAfter = readBootId(job, host, verificationSession);
            if (!bootIdBefore.isBlank() && !bootIdAfter.isBlank()) {
                if (bootIdBefore.equals(bootIdAfter)) {
                    report.serviceUpAfterReboot = false;
                    job.add(host, "error", "SSH is reachable, but Linux boot ID did not change. Reboot was not confirmed, so service checks were skipped.");
                    return new PostRebootStatus(true, false, Optional.empty());
                }
                job.add(host, "success", "Reboot confirmed because Linux boot ID changed.");
            } else {
                job.add(host, "warn", "Linux boot ID could not be confirmed. Continuing with SSH reachability as the machine-up check.");
            }

            for (String url : HEALTHCHECK_URLS) {
                String command = "curl -k -s -o /dev/null -w \"%{http_code}\" --max-time 10 " + shellQuote(url);
                RemoteResult result = runRemote(job, host, verificationSession, command, true);
                String statusCode = result.lines().isEmpty() ? "" : result.lines().get(result.lines().size() - 1).trim();
                if ("200".equals(statusCode)) {
                    report.serviceUpAfterReboot = true;
                    report.workingHealthcheck = url;
                    job.add(host, "success", "Service health check returned HTTP 200: " + url);
                    return new PostRebootStatus(true, true, Optional.of(url));
                }
            }

            report.serviceUpAfterReboot = false;
            job.add(host, "error", "Server is reachable, but none of the configured health checks returned HTTP 200.");
            return new PostRebootStatus(true, false, Optional.empty());
        } catch (Exception e) {
            report.machineUpAfterReboot = true;
            report.serviceUpAfterReboot = false;
            job.add(host, "error", "Server is reachable, but health check execution failed: " + cleanMessage(e));
            return new PostRebootStatus(true, false, Optional.empty());
        } finally {
            if (verificationSession != null) {
                verificationSession.disconnect();
            }
        }
    }

    private SshWaitResult waitForSsh(Job job, String host, String attemptPrefix) {
        long deadline = System.currentTimeMillis() + REBOOT_VERIFY_TIMEOUT_MILLIS;
        int attempt = 1;
        Exception lastFailure = null;
        while (System.currentTimeMillis() <= deadline) {
            try {
                job.add(host, "info", attemptPrefix + attempt + ".");
                return new SshWaitResult(connect(job, host), null);
            } catch (Exception e) {
                lastFailure = e;
                long remaining = deadline - System.currentTimeMillis();
                if (remaining <= 0) {
                    break;
                }
                sleep(Math.min(REBOOT_VERIFY_INTERVAL_MILLIS, remaining));
                attempt++;
            }
        }
        return new SshWaitResult(null, lastFailure);
    }

    private boolean forceHardRebootWithCloudApi(Job job, String host) {
        VaultConfig config = vaultStatus.config();
        if (!"UP".equals(vaultStatus.state()) || vaultClientToken.isBlank()) {
            job.add(host, "error", "Cannot call hard reboot API because Vault is not connected.");
            return false;
        }
        try {
            CloudRecoveryConfig recoveryConfig = loadCloudRecoveryConfig(config);
            if (recoveryConfig.accounts().isEmpty()) {
                job.add(host, "error", "No technical accounts found in Vault secret " + config.technicalAccountsPath() + ".");
                return false;
            }
            if (!recoveryConfig.isComplete()) {
                job.add(host, "error", "Cloud API URLs are missing from Vault secret " + config.technicalAccountsPath() + ".");
                return false;
            }
            Optional<TechnicalAccount> selected = findTechnicalAccount(recoveryConfig, job.settings.technicalAccountName);
            if (selected.isEmpty()) {
                job.add(host, "error", "Selected technical account " + job.settings.technicalAccountName + " was not found in Vault.");
                return false;
            }
            TechnicalAccount account = selected.get();
            job.add(host, "info", "Using selected Vault technical account " + account.name() + " for hard reboot recovery.");
            String accessToken = requestCmaasToken(account, recoveryConfig);
            for (OcsEndpoint endpoint : recoveryConfig.ocsEndpoints()) {
                try {
                    Optional<CloudServer> server = findCloudServer(host, accessToken, endpoint);
                    if (server.isEmpty()) {
                        job.add(host, "warn", "Server " + host + " was not found in OCS endpoint " + endpoint.name() + ".");
                        continue;
                    }
                    sendHardReboot(server.get(), accessToken, endpoint);
                    job.add(host, "success", "Hard reboot API request sent for OCS server " + server.get().id()
                            + " (" + server.get().name() + ") using " + account.name() + " via " + endpoint.name() + ".");
                    return true;
                } catch (Exception e) {
                    job.add(host, "warn", "OCS endpoint " + endpoint.name() + " failed using "
                            + account.name() + ": " + cleanMessage(e));
                }
            }
        } catch (Exception e) {
            job.add(host, "error", "Unable to run hard reboot API recovery: " + cleanMessage(e));
        }
        return false;
    }

    private static Optional<TechnicalAccount> findTechnicalAccount(CloudRecoveryConfig config, String name) {
        return config.accounts().stream().filter(account -> account.name().equals(name)).findFirst();
    }

    private CloudRecoveryConfig loadCloudRecoveryConfig(VaultConfig config) throws IOException, InterruptedException {
        List<String> candidatePaths = vaultSecretPaths(config.technicalAccountsPath());
        Exception lastFailure = null;
        for (String path : candidatePaths) {
            try {
                URI uri = URI.create(stripTrailingSlash(config.uri()) + path);
                HttpRequest.Builder requestBuilder = HttpRequest.newBuilder(uri)
                        .timeout(Duration.ofMillis(15000))
                        .header("X-Vault-Token", vaultClientToken)
                        .GET();
                if (!config.namespace().isBlank()) {
                    requestBuilder.header("X-Vault-Namespace", config.namespace());
                }
                HttpResponse<String> response = httpClient().send(requestBuilder.build(), HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
                if (response.statusCode() == 404) {
                    continue;
                }
                if (response.statusCode() < 200 || response.statusCode() >= 300) {
                    throw new IOException("Vault secret read failed with HTTP " + response.statusCode());
                }
                Object parsed = new JsonParser(response.body()).parse();
                Object data = vaultDataPayload(parsed);
                List<TechnicalAccount> accounts = new ArrayList<>();
                collectTechnicalAccounts(data, "", accounts, new HashSet<>());
                List<OcsEndpoint> ocsEndpoints = new ArrayList<>();
                collectOcsEndpoints(data, ocsEndpoints, new HashSet<>());
                return new CloudRecoveryConfig(
                        accounts,
                        findFirstString(data, "cmaas_oauth_token_url", "cmaasOauthTokenUrl", "oauth_token_url", "oauthTokenUrl"),
                        ocsEndpoints
                );
            } catch (Exception e) {
                lastFailure = e;
            }
        }
        if (lastFailure instanceof IOException ioe) {
            throw ioe;
        }
        if (lastFailure instanceof InterruptedException ie) {
            throw ie;
        }
        if (lastFailure != null) {
            throw new IOException(lastFailure);
        }
        return new CloudRecoveryConfig(List.of(), "", List.of());
    }

    private static List<String> vaultSecretPaths(String configuredPath) {
        String clean = configuredPath == null ? "" : configuredPath.trim();
        if (clean.isBlank()) {
            return List.of();
        }
        if (clean.startsWith("/v1/")) {
            return List.of(clean);
        }
        clean = clean.replaceFirst("^/+", "");
        return List.of("/v1/secret/data/" + clean, "/v1/secret/" + clean);
    }

    @SuppressWarnings("unchecked")
    private static Object vaultDataPayload(Object parsed) {
        if (!(parsed instanceof Map<?, ?> root)) {
            return parsed;
        }
        Object data = root.get("data");
        if (data instanceof Map<?, ?> firstData) {
            Object nestedData = firstData.get("data");
            if (nestedData instanceof Map<?, ?> || nestedData instanceof List<?>) {
                return nestedData;
            }
            return firstData;
        }
        return root;
    }

    @SuppressWarnings("unchecked")
    private static void collectTechnicalAccounts(Object value, String suggestedName, List<TechnicalAccount> accounts, Set<String> seen) {
        if (value instanceof Map<?, ?> map) {
            String accountId = firstNonBlank(map, "account_id", "accountId", "account-id");
            String clientId = firstNonBlank(map, "client_id", "clientId", "client-id");
            String clientSecret = firstNonBlank(map, "client_secret", "clientSecret", "client-secret");
            if (!accountId.isBlank() && !clientId.isBlank() && !clientSecret.isBlank()) {
                String key = accountId + "\n" + clientId;
                if (seen.add(key)) {
                    String explicitName = firstNonBlank(map, "name", "label", "trigram", "technical_account_name");
                    String name = !explicitName.isBlank() ? explicitName
                            : isAccountContainerName(suggestedName) || suggestedName.isBlank() ? accountId : suggestedName;
                    accounts.add(new TechnicalAccount(name, accountId, clientId, clientSecret));
                }
            }
            for (Map.Entry<?, ?> entry : map.entrySet()) {
                collectTechnicalAccounts(entry.getValue(), stringValue(entry.getKey()), accounts, seen);
            }
        } else if (value instanceof Collection<?> collection) {
            for (Object nested : collection) {
                collectTechnicalAccounts(nested, suggestedName, accounts, seen);
            }
        }
    }

    private static boolean isAccountContainerName(String name) {
        return "accounts".equalsIgnoreCase(name) || "technical_accounts".equalsIgnoreCase(name)
                || "technicalAccounts".equalsIgnoreCase(name);
    }

    private static void collectOcsEndpoints(Object value, List<OcsEndpoint> endpoints, Set<String> seen) {
        if (value instanceof Map<?, ?> map) {
            String serversUrl = firstNonBlank(map, "ocs_servers_url", "ocsServersUrl", "servers_url", "serversUrl");
            String actionUrl = firstNonBlank(map, "ocs_server_action_url", "ocsServerActionUrl", "server_action_url", "serverActionUrl");
            if (!serversUrl.isBlank() && !actionUrl.isBlank()) {
                String key = serversUrl + "\n" + actionUrl;
                if (seen.add(key)) {
                    String name = firstNonBlank(map, "region", "name", "location");
                    endpoints.add(new OcsEndpoint(name.isBlank() ? "default" : name, serversUrl, actionUrl));
                }
            }
            for (Object nested : map.values()) {
                collectOcsEndpoints(nested, endpoints, seen);
            }
        } else if (value instanceof Collection<?> collection) {
            for (Object nested : collection) {
                collectOcsEndpoints(nested, endpoints, seen);
            }
        }
    }

    private static String firstNonBlank(Map<?, ?> map, String... keys) {
        for (String key : keys) {
            String value = stringValue(map.get(key));
            if (!value.isBlank()) {
                return value;
            }
        }
        return "";
    }

    private static String findFirstString(Object value, String... keys) {
        if (value instanceof Map<?, ?> map) {
            String direct = firstNonBlank(map, keys);
            if (!direct.isBlank()) {
                return direct;
            }
            for (Object nested : map.values()) {
                String found = findFirstString(nested, keys);
                if (!found.isBlank()) {
                    return found;
                }
            }
        } else if (value instanceof Collection<?> collection) {
            for (Object nested : collection) {
                String found = findFirstString(nested, keys);
                if (!found.isBlank()) {
                    return found;
                }
            }
        }
        return "";
    }

    private String requestCmaasToken(TechnicalAccount account, CloudRecoveryConfig config) throws IOException, InterruptedException {
        if (config.oauthTokenUrl().isBlank()) {
            throw new IOException("CMAAS OAuth token URL is missing from Vault");
        }
        String scope = account.accountId() + ":sgcp:cmaas:write_node "
                + account.accountId() + ":sgcp:cmaas:read "
                + account.accountId() + ":sgcp:lbaas:read "
                + account.accountId() + ":sgcp:ocs:read "
                + account.accountId() + ":sgcp:files:read "
                + account.accountId() + ":sgcp:files:write";
        String body = "grant_type=client_credentials&scope=" + URLEncoder.encode(scope, StandardCharsets.UTF_8);
        String basic = Base64.getEncoder().encodeToString((account.clientId() + ":" + account.clientSecret()).getBytes(StandardCharsets.UTF_8));
        HttpRequest request = HttpRequest.newBuilder(URI.create(config.oauthTokenUrl()))
                .timeout(Duration.ofMillis(15000))
                .header("Authorization", "Basic " + basic)
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString(body, StandardCharsets.UTF_8))
                .build();
        HttpResponse<String> response = httpClient().send(request, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
        if (response.statusCode() < 200 || response.statusCode() >= 300) {
            throw new IOException("OAuth token request failed with HTTP " + response.statusCode());
        }
        Object parsed = new JsonParser(response.body()).parse();
        String token = findString(parsed, "access_token");
        if (token.isBlank()) {
            throw new IOException("OAuth response did not contain access_token");
        }
        return token;
    }

    private Optional<CloudServer> findCloudServer(String host, String accessToken, OcsEndpoint endpoint) throws IOException, InterruptedException {
        Exception lastFailure = null;
        for (int attempt = 1; attempt <= 3; attempt++) {
            try {
                HttpRequest request = HttpRequest.newBuilder(URI.create(endpoint.serversUrl()))
                        .timeout(Duration.ofMillis(15000))
                        .header("Content-Type", "application/json")
                        .header("Authorization", "Bearer " + accessToken)
                        .GET()
                        .build();
                HttpResponse<String> response = httpClient().send(request, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
                if (response.statusCode() == 200) {
                    Object parsed = new JsonParser(response.body()).parse();
                    return findMatchingServer(parsed, host);
                }
                throw new IOException("OCS server list failed with HTTP " + response.statusCode());
            } catch (Exception e) {
                lastFailure = e;
                if (attempt < 3) {
                    sleep(5000);
                }
            }
        }
        if (lastFailure instanceof IOException ioe) {
            throw ioe;
        }
        if (lastFailure instanceof InterruptedException ie) {
            throw ie;
        }
        throw new IOException(lastFailure);
    }

    private static Optional<CloudServer> findMatchingServer(Object parsed, String host) {
        if (!(parsed instanceof Map<?, ?> root)) {
            return Optional.empty();
        }
        Object servers = root.get("servers");
        if (!(servers instanceof Collection<?> collection)) {
            return Optional.empty();
        }
        String target = host.trim();
        for (Object item : collection) {
            if (!(item instanceof Map<?, ?> server)) {
                continue;
            }
            String accessIp = stringValue(server.get("accessIPv4"));
            String name = stringValue(server.get("name"));
            String id = stringValue(server.get("id"));
            if (!id.isBlank() && (target.equalsIgnoreCase(accessIp) || target.equalsIgnoreCase(name))) {
                return Optional.of(new CloudServer(id, name.isBlank() ? accessIp : name, accessIp));
            }
        }
        return Optional.empty();
    }

    private void sendHardReboot(CloudServer server, String accessToken, OcsEndpoint endpoint) throws IOException, InterruptedException {
        String body = "{\"reboot\":{\"type\":\"HARD\"}}";
        HttpRequest request = HttpRequest.newBuilder(URI.create(serverActionUrl(endpoint.actionUrl(), server.id())))
                .timeout(Duration.ofMillis(15000))
                .header("Content-Type", "application/json")
                .header("Authorization", "Bearer " + accessToken)
                .POST(HttpRequest.BodyPublishers.ofString(body, StandardCharsets.UTF_8))
                .build();
        HttpResponse<String> response = httpClient().send(request, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
        if (response.statusCode() < 200 || response.statusCode() >= 300) {
            throw new IOException("OCS hard reboot action failed with HTTP " + response.statusCode());
        }
    }

    private static HttpClient httpClient() {
        return HttpClient.newBuilder()
                .connectTimeout(Duration.ofMillis(5000))
                .build();
    }

    private void appendStatusLog(Job job, String host, PostRebootStatus status) throws IOException {
        String line = Instant.now()
                + "\t" + job.id
                + "\t" + host
                + "\t" + (status.machineUp() ? "UP" : "DOWN")
                + "\t" + (status.serviceUp() ? "UP" : "DOWN")
                + "\t" + status.workingHealthcheck().orElse("")
                + System.lineSeparator();
        Files.writeString(appDir.resolve(STATUS_LOG_FILE).normalize(), line, StandardCharsets.UTF_8,
                java.nio.file.StandardOpenOption.CREATE, java.nio.file.StandardOpenOption.APPEND);
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

    private RemoteResult runRemote(Job job, String host, Session session, String command) throws Exception {
        return runRemote(job, host, session, command, false);
    }

    private RemoteResult runRemote(Job job, String host, Session session, String command, boolean allowNonZero) throws Exception {
        job.add(host, "cmd", "$ " + command);
        ChannelExec channel = (ChannelExec) session.openChannel("exec");
        channel.setCommand(command);
        channel.setPty(true);
        ByteArrayOutputStream err = new ByteArrayOutputStream();
        channel.setErrStream(err);

        try (InputStream output = channel.getInputStream()) {
            channel.connect();
            List<String> lines = readChannel(job, host, output, channel);
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
            return new RemoteResult(status, lines);
        } finally {
            channel.disconnect();
        }
    }

    private List<String> readChannel(Job job, String host, InputStream input, ChannelExec channel) throws IOException {
        BufferedReader reader = new BufferedReader(new InputStreamReader(input, StandardCharsets.UTF_8));
        StringBuilder pending = new StringBuilder();
        List<String> lines = new ArrayList<>();
        while (!channel.isClosed() || reader.ready()) {
            while (reader.ready()) {
                int ch = reader.read();
                if (ch < 0) {
                    break;
                }
                if (ch == '\n') {
                    emitLine(job, host, pending, lines);
                } else if (ch != '\r') {
                    pending.append((char) ch);
                }
            }
            sleep(100);
        }
        emitLine(job, host, pending, lines);
        return lines;
    }

    private void emitLine(Job job, String host, StringBuilder pending, List<String> lines) {
        if (!pending.isEmpty()) {
            String line = pending.toString();
            lines.add(line);
            job.add(host, "out", line);
            pending.setLength(0);
        }
    }

    private static Set<String> extractRhsa(List<String> lines) {
        Set<String> advisories = new TreeSet<>();
        for (String line : lines) {
            Matcher matcher = RHSA_PATTERN.matcher(line);
            while (matcher.find()) {
                advisories.add(matcher.group());
            }
        }
        return advisories;
    }

    private Path writeHtmlReport(Job job) throws IOException {
        Path reportsDir = appDir.resolve(REPORT_DIR).normalize();
        Files.createDirectories(reportsDir);
        String prefix = job.settings.dryRun ? "dryrun-report-" : "patch-report-";
        Path reportPath = reportsDir.resolve(prefix + REPORT_FILE_CLOCK.format(job.startedAt)
                + "-" + job.id.substring(0, 8) + ".html");
        Files.writeString(reportPath, buildHtmlReport(job), StandardCharsets.UTF_8);
        return reportPath;
    }

    private String buildHtmlReport(Job job) {
        StringBuilder html = new StringBuilder();
        html.append("""
                <!doctype html>
                <html lang="en">
                <head>
                  <meta charset="utf-8">
                  <meta name="viewport" content="width=device-width, initial-scale=1">
                  <title>DNF Patch Report</title>
                  <style>
                    body { margin: 0; font-family: Arial, sans-serif; color: #17202a; background: #f4f7fb; }
                    main { width: min(1180px, calc(100vw - 32px)); margin: 0 auto; padding: 24px 0; }
                    h1 { margin: 0 0 4px; font-size: 26px; }
                    h2 { margin: 28px 0 10px; font-size: 18px; }
                    .meta, .summary { background: #fff; border: 1px solid #d8dee9; border-radius: 8px; padding: 14px; margin-top: 14px; }
                    .grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 10px; }
                    .stat { border: 1px solid #d8dee9; border-radius: 8px; padding: 10px; background: #fff; }
                    .stat b { display: block; font-size: 22px; }
                    table { width: 100%; border-collapse: collapse; background: #fff; border: 1px solid #d8dee9; }
                    th, td { border-bottom: 1px solid #d8dee9; padding: 10px; text-align: left; vertical-align: top; }
                    th { background: #eef2f7; font-size: 13px; }
                    ul { margin: 0; padding-left: 18px; }
                    .success { color: #15803d; font-weight: 700; }
                    .failed { color: #b91c1c; font-weight: 700; }
                    .running, .queued { color: #1d4ed8; font-weight: 700; }
                    .empty { color: #64748b; }
                    @media (max-width: 760px) { .grid { grid-template-columns: repeat(2, 1fr); } table { font-size: 13px; } }
                  </style>
                </head>
                <body>
                <main>
                """);
        html.append("<h1>").append(job.settings.dryRun ? "DNF Dry Run Report" : "DNF Patch Report").append("</h1>");
        html.append("<div class=\"meta\">")
                .append("<div><b>Run ID:</b> ").append(escapeHtml(job.id)).append("</div>")
                .append("<div><b>Run type:</b> ").append(job.settings.dryRun ? "Dry run" : "Patch").append("</div>")
                .append("<div><b>Started:</b> ").append(escapeHtml(REPORT_DISPLAY_CLOCK.format(job.startedAt))).append("</div>")
                .append("<div><b>Authorized member:</b> ").append(escapeHtml(job.authorizedMember)).append("</div>")
                .append("<div><b>Vault technical account:</b> ").append(escapeHtml(job.settings.technicalAccountName)).append("</div>")
                .append("<div><b>Command:</b> ")
                .append(job.settings.dryRun ? "dry run only; no update command executed" : "sudo -n dnf -y update --security")
                .append(!job.settings.dryRun && job.settings.skipBroken ? " --skip-broken" : "")
                .append("</div>")
                .append("</div>");

        html.append("<div class=\"summary grid\">")
                .append(stat("Total", job.hosts.size()))
                .append(stat("Succeeded", job.succeeded.get()))
                .append(stat("Failed", job.failed.get()))
                .append(stat("Reboot Requested", !job.settings.dryRun && job.settings.reboot ? "Yes" : "No"))
                .append("</div>");

        html.append("<h2>Server Status And RHSA</h2>");
        html.append("<table><thead><tr>");
        if (job.settings.dryRun) {
            html.append("<th>Server</th><th>Status</th><th>RHSA Available To Install</th><th>All Installed RHSA In The OS</th>");
        } else if (job.settings.reboot) {
            html.append("<th>Server</th><th>Status</th><th>RHSA Available To Install</th><th>RHSA Corrected By This Run</th><th>All Installed RHSA In The OS</th><th>Machine After Reboot</th><th>Service After Reboot</th><th>Working Healthcheck</th>");
        } else {
            html.append("<th>Server</th><th>Status</th><th>RHSA Available To Install</th><th>RHSA Corrected By This Run</th><th>All Installed RHSA In The OS</th>");
        }
        html.append("</tr></thead><tbody>");
        List<String> sortedHosts = new ArrayList<>(job.hosts);
        Collections.sort(sortedHosts);
        for (String host : sortedHosts) {
            HostReport report = job.reportFor(host);
            String status = job.hostStatus.getOrDefault(host, "unknown");
            html.append("<tr>")
                    .append("<td>").append(escapeHtml(host)).append("</td>")
                    .append("<td class=\"").append(escapeHtml(status)).append("\">").append(escapeHtml(status)).append("</td>")
                    .append("<td>").append(advisoryList(report.rhsaPresentBefore)).append("</td>");
            if (!job.settings.dryRun) {
                html.append("<td>").append(advisoryList(report.rhsaCorrected)).append("</td>");
            }
            html.append("<td>").append(advisoryList(report.rhsaInstalledAfter)).append("</td>");
            if (!job.settings.dryRun && job.settings.reboot) {
                html.append(statusCell(report.machineUpAfterReboot == null ? "UNKNOWN" : report.machineUpAfterReboot ? "UP" : "DOWN"))
                        .append(statusCell(report.serviceUpAfterReboot == null ? "UNKNOWN" : report.serviceUpAfterReboot ? "UP" : "DOWN"))
                        .append("<td>").append(report.workingHealthcheck == null ? "<span class=\"empty\">None</span>" : escapeHtml(report.workingHealthcheck)).append("</td>");
            }
            html.append("</tr>");
        }
        html.append("</tbody></table>");
        html.append("""
                </main>
                </body>
                </html>
                """);
        return html.toString();
    }

    private String buildReportsIndex(ReportKind kind) throws IOException {
        Path reportsDir = appDir.resolve(REPORT_DIR).normalize();
        Files.createDirectories(reportsDir);
        List<ReportEntry> reports = new ArrayList<>();
        String reportPrefix = kind == ReportKind.DRY_RUN ? "dryrun-report-" : "patch-report-";
        try (var stream = Files.list(reportsDir)) {
            stream.filter(Files::isRegularFile)
                    .filter(path -> path.getFileName().toString().endsWith(".html"))
                    .filter(path -> path.getFileName().toString().startsWith(reportPrefix))
                    .forEach(path -> {
                        try {
                            reports.add(new ReportEntry(
                                    path.getFileName().toString(),
                                    Files.getLastModifiedTime(path).toInstant(),
                                    Files.size(path)
                            ));
                        } catch (IOException ignored) {
                            // Skip unreadable report files.
                        }
                    });
        }
        reports.sort(Comparator.comparing(ReportEntry::modifiedAt).reversed()
                .thenComparing(ReportEntry::name));

        StringBuilder html = new StringBuilder();
        html.append("""
                <!doctype html>
                <html lang="en">
                <head>
                  <meta charset="utf-8">
                  <meta name="viewport" content="width=device-width, initial-scale=1">
                  <title>Reports</title>
                  <style>
                    body { margin: 0; font-family: Arial, sans-serif; color: #17202a; background: #f4f7fb; }
                    main { width: min(980px, calc(100vw - 32px)); margin: 0 auto; padding: 24px 0; }
                    header { display: flex; justify-content: space-between; gap: 16px; align-items: center; margin-bottom: 18px; }
                    h1 { margin: 0; font-size: 26px; }
                    a { color: #1d4ed8; text-decoration: none; }
                    a:hover { text-decoration: underline; }
                    .button { border: 1px solid #cbd5e1; border-radius: 6px; padding: 8px 10px; background: #fff; }
                    table { width: 100%; border-collapse: collapse; background: #fff; border: 1px solid #d8dee9; }
                    th, td { border-bottom: 1px solid #d8dee9; padding: 11px; text-align: left; }
                    th { background: #eef2f7; font-size: 13px; }
                    .empty { background: #fff; border: 1px solid #d8dee9; border-radius: 8px; padding: 18px; color: #64748b; }
                    .muted { color: #64748b; font-size: 13px; }
                  </style>
                </head>
                <body>
                <main>
                  <header>
                    <div>
                      <h1>__REPORT_TITLE__</h1>
                      <div class="muted">Newest reports first</div>
                    </div>
                    <div>
                      <a class="button" href="/">Update Console</a>
                      <a class="button" href="__OTHER_ROUTE__">__OTHER_LABEL__</a>
                    </div>
                  </header>
                """.replace("__REPORT_TITLE__", kind == ReportKind.DRY_RUN ? "Dry Run Reports" : "Patch Reports")
                .replace("__OTHER_ROUTE__", kind == ReportKind.DRY_RUN ? "/patching" : "/dryrun")
                .replace("__OTHER_LABEL__", kind == ReportKind.DRY_RUN ? "Patch Reports" : "Dry Run Reports"));
        if (reports.isEmpty()) {
            html.append("<div class=\"empty\">No ")
                    .append(kind == ReportKind.DRY_RUN ? "dry run" : "patch")
                    .append(" reports have been generated yet.</div>");
        } else {
            html.append("<table><thead><tr><th>Report</th><th>Date</th><th>Size</th></tr></thead><tbody>");
            for (ReportEntry report : reports) {
                String href = "/reports/" + URLEncoder.encode(report.name(), StandardCharsets.UTF_8).replace("+", "%20");
                html.append("<tr>")
                        .append("<td><a href=\"").append(escapeHtml(href)).append("\">")
                        .append(escapeHtml(report.name())).append("</a></td>")
                        .append("<td>").append(escapeHtml(REPORT_DISPLAY_CLOCK.format(report.modifiedAt()))).append("</td>")
                        .append("<td>").append(escapeHtml(formatBytes(report.size()))).append("</td>")
                        .append("</tr>");
            }
            html.append("</tbody></table>");
        }
        html.append("""
                </main>
                </body>
                </html>
                """);
        return html.toString();
    }

    private String buildStatusPage() throws IOException {
        List<StatusEntry> statuses = readStatusEntries();
        statuses.sort(Comparator.comparing(StatusEntry::checkedAt).reversed());

        StringBuilder html = new StringBuilder();
        html.append("""
                <!doctype html>
                <html lang="en">
                <head>
                  <meta charset="utf-8">
                  <meta name="viewport" content="width=device-width, initial-scale=1">
                  <title>Post-Reboot Status</title>
                  <style>
                    body { margin: 0; font-family: Arial, sans-serif; color: #17202a; background: #f4f7fb; }
                    main { width: min(1180px, calc(100vw - 32px)); margin: 0 auto; padding: 24px 0; }
                    header { display: flex; justify-content: space-between; gap: 16px; align-items: center; margin-bottom: 18px; }
                    h1 { margin: 0; font-size: 26px; }
                    a { color: #1d4ed8; text-decoration: none; }
                    a:hover { text-decoration: underline; }
                    .button { border: 1px solid #cbd5e1; border-radius: 6px; padding: 8px 10px; background: #fff; }
                    table { width: 100%; border-collapse: collapse; background: #fff; border: 1px solid #d8dee9; }
                    th, td { border-bottom: 1px solid #d8dee9; padding: 11px; text-align: left; vertical-align: top; }
                    th { background: #eef2f7; font-size: 13px; }
                    .up { color: #15803d; font-weight: 700; }
                    .down { color: #b91c1c; font-weight: 700; }
                    .empty { background: #fff; border: 1px solid #d8dee9; border-radius: 8px; padding: 18px; color: #64748b; }
                    .muted { color: #64748b; font-size: 13px; }
                  </style>
                </head>
                <body>
                <main>
                  <header>
                    <div>
                      <h1>Post-Reboot Status</h1>
                      <div class="muted">Newest checks first</div>
                    </div>
                    <a class="button" href="/">Update Console</a>
                  </header>
                """);
        if (statuses.isEmpty()) {
            html.append("<div class=\"empty\">No post-reboot status checks have been recorded yet.</div>");
        } else {
            html.append("<table><thead><tr>")
                    .append("<th>Date</th><th>Server</th><th>Machine</th><th>Service</th><th>Working Healthcheck</th><th>Run ID</th>")
                    .append("</tr></thead><tbody>");
            for (StatusEntry status : statuses) {
                html.append("<tr>")
                        .append("<td>").append(escapeHtml(REPORT_DISPLAY_CLOCK.format(status.checkedAt()))).append("</td>")
                        .append("<td>").append(escapeHtml(status.host())).append("</td>")
                        .append(statusCell(status.machineStatus()))
                        .append(statusCell(status.serviceStatus()))
                        .append("<td>").append(status.workingHealthcheck().isBlank() ? "<span class=\"muted\">None</span>" : escapeHtml(status.workingHealthcheck())).append("</td>")
                        .append("<td>").append(escapeHtml(status.jobId())).append("</td>")
                        .append("</tr>");
            }
            html.append("</tbody></table>");
        }
        html.append("""
                </main>
                </body>
                </html>
                """);
        return html.toString();
    }

    private String buildVaultPage() {
        VaultStatus status = vaultStatus;
        String stateClass = switch (status.state()) {
            case "UP" -> "up";
            case "DOWN" -> "down";
            default -> "disabled";
        };
        StringBuilder html = new StringBuilder();
        html.append("""
                <!doctype html>
                <html lang="en">
                <head>
                  <meta charset="utf-8">
                  <meta name="viewport" content="width=device-width, initial-scale=1">
                  <title>Vault Status</title>
                  <style>
                    body { margin: 0; font-family: Arial, sans-serif; color: #17202a; background: #f4f7fb; }
                    main { width: min(860px, calc(100vw - 32px)); margin: 0 auto; padding: 24px 0; }
                    header { display: flex; justify-content: space-between; gap: 16px; align-items: center; margin-bottom: 18px; }
                    h1 { margin: 0; font-size: 26px; }
                    a { color: #1d4ed8; text-decoration: none; }
                    a:hover { text-decoration: underline; }
                    .button { border: 1px solid #cbd5e1; border-radius: 6px; padding: 8px 10px; background: #fff; }
                    .panel { background: #fff; border: 1px solid #d8dee9; border-radius: 8px; padding: 18px; }
                    .state { display: inline-block; border-radius: 999px; padding: 5px 10px; font-weight: 800; font-size: 13px; }
                    .up { color: #15803d; background: #dcfce7; }
                    .down { color: #b91c1c; background: #fee2e2; }
                    .disabled { color: #64748b; background: #e2e8f0; }
                    table { width: 100%; border-collapse: collapse; margin-top: 16px; }
                    th, td { border-top: 1px solid #d8dee9; padding: 10px; text-align: left; vertical-align: top; }
                    th { width: 210px; color: #64748b; font-size: 13px; }
                    .muted { color: #64748b; font-size: 13px; }
                  </style>
                </head>
                <body>
                <main>
                  <header>
                    <div>
                      <h1>Vault Status</h1>
                      <div class="muted">AppRole connection status from startup configuration</div>
                    </div>
                    <a class="button" href="/">Update Console</a>
                  </header>
                  <section class="panel">
                """);
        html.append("<div class=\"state ").append(stateClass).append("\">").append(escapeHtml(status.state())).append("</div>");
        html.append("<p>").append(escapeHtml(status.message())).append("</p>");
        html.append("<table><tbody>")
                .append(row("Enabled", Boolean.toString(status.config().enabled())))
                .append(row("URI", status.config().uri()))
                .append(row("Context", status.config().context()))
                .append(row("Namespace", status.config().namespace()))
                .append(row("Technical Accounts Path", status.config().technicalAccountsPath()))
                .append(row("Cloud API URLs", "read from Vault technical accounts secret"))
                .append(row("Authentication", "approle"))
                .append(row("Role ID", status.config().roleId().isBlank() ? "missing" : "configured"))
                .append(row("Secret ID", status.config().secretId().isBlank() ? "missing" : "configured"))
                .append(row("Checked At", REPORT_DISPLAY_CLOCK.format(status.checkedAt())))
                .append("</tbody></table>");
        html.append("""
                  </section>
                </main>
                </body>
                </html>
                """);
        return html.toString();
    }

    private static String row(String name, String value) {
        return "<tr><th>" + escapeHtml(name) + "</th><td>" + escapeHtml(value == null || value.isBlank() ? "not set" : value) + "</td></tr>";
    }

    private List<StatusEntry> readStatusEntries() throws IOException {
        Path statusLog = appDir.resolve(STATUS_LOG_FILE).normalize();
        if (!Files.isRegularFile(statusLog)) {
            return new ArrayList<>();
        }
        List<StatusEntry> entries = new ArrayList<>();
        for (String line : Files.readAllLines(statusLog, StandardCharsets.UTF_8)) {
            String[] parts = line.split("\t", -1);
            if (parts.length < 6) {
                continue;
            }
            try {
                entries.add(new StatusEntry(
                        Instant.parse(stripBom(parts[0])),
                        parts[1],
                        parts[2],
                        parts[3],
                        parts[4],
                        parts[5]
                ));
            } catch (Exception ignored) {
                // Skip malformed status lines.
            }
        }
        return entries;
    }

    private static String stripBom(String value) {
        if (value != null && !value.isEmpty() && value.charAt(0) == '\uFEFF') {
            return value.substring(1);
        }
        return value;
    }

    private static String statusCell(String status) {
        String normalized = status == null ? "DOWN" : status.toUpperCase(Locale.ROOT);
        String css = "UP".equals(normalized) ? "up" : "down";
        return "<td class=\"" + css + "\">" + escapeHtml(normalized) + "</td>";
    }

    private static String formatBytes(long bytes) {
        if (bytes < 1024) {
            return bytes + " B";
        }
        if (bytes < 1024 * 1024) {
            return String.format(Locale.ROOT, "%.1f KB", bytes / 1024.0);
        }
        return String.format(Locale.ROOT, "%.1f MB", bytes / (1024.0 * 1024.0));
    }

    private static String stat(String label, int value) {
        return stat(label, Integer.toString(value));
    }

    private static String stat(String label, String value) {
        return "<div class=\"stat\"><b>" + escapeHtml(value) + "</b><span>" + escapeHtml(label) + "</span></div>";
    }

    private static String advisoryList(Set<String> advisories) {
        if (advisories.isEmpty()) {
            return "<span class=\"empty\">None recorded</span>";
        }
        StringBuilder html = new StringBuilder("<ul>");
        synchronized (advisories) {
            for (String advisory : advisories) {
                html.append("<li>").append(escapeHtml(advisory)).append("</li>");
            }
        }
        html.append("</ul>");
        return html.toString();
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

    private static String shellQuote(String value) {
        return "'" + value.replace("'", "'\\''") + "'";
    }

    private static String sha256Hex(String value) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] bytes = digest.digest(value.getBytes(StandardCharsets.UTF_8));
            StringBuilder hex = new StringBuilder(bytes.length * 2);
            for (byte b : bytes) {
                hex.append(String.format("%02x", b));
            }
            return hex.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is not available.", e);
        }
    }

    private static boolean constantTimeEquals(String left, String right) {
        byte[] leftBytes = left.getBytes(StandardCharsets.UTF_8);
        byte[] rightBytes = right.getBytes(StandardCharsets.UTF_8);
        int diff = leftBytes.length ^ rightBytes.length;
        int max = Math.max(leftBytes.length, rightBytes.length);
        for (int i = 0; i < max; i++) {
            byte a = i < leftBytes.length ? leftBytes[i] : 0;
            byte b = i < rightBytes.length ? rightBytes[i] : 0;
            diff |= a ^ b;
        }
        return diff == 0;
    }

    private static String stringValue(Object value) {
        return value == null ? "" : String.valueOf(value).trim();
    }

    private static String findString(Object value, String key) {
        if (value instanceof Map<?, ?> map) {
            Object direct = map.get(key);
            if (direct != null) {
                return stringValue(direct);
            }
            for (Object nested : map.values()) {
                String found = findString(nested, key);
                if (!found.isBlank()) {
                    return found;
                }
            }
        } else if (value instanceof Collection<?> collection) {
            for (Object nested : collection) {
                String found = findString(nested, key);
                if (!found.isBlank()) {
                    return found;
                }
            }
        }
        return "";
    }

    private static String urlPathEncode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8).replace("+", "%20");
    }

    private static String serverActionUrl(String template, String serverId) {
        String clean = template.trim();
        if (clean.contains("%s")) {
            return String.format(clean, urlPathEncode(serverId));
        }
        while (clean.endsWith("/")) {
            clean = clean.substring(0, clean.length() - 1);
        }
        return clean + "/servers/" + urlPathEncode(serverId) + "/action";
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

    private static String escapeHtml(String value) {
        StringBuilder builder = new StringBuilder(value.length() + 16);
        for (int i = 0; i < value.length(); i++) {
            char ch = value.charAt(i);
            switch (ch) {
                case '&' -> builder.append("&amp;");
                case '<' -> builder.append("&lt;");
                case '>' -> builder.append("&gt;");
                case '"' -> builder.append("&quot;");
                case '\'' -> builder.append("&#39;");
                default -> builder.append(ch);
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
            boolean skipBroken,
            boolean dryRun,
            String technicalAccountName
    ) {
    }

    private record AuthPassphrase(String memberId, String sha256Hex) {
    }

    private record RemoteResult(int exitStatus, List<String> lines) {
    }

    private record ReportEntry(String name, Instant modifiedAt, long size) {
    }

    private record StatusEntry(
            Instant checkedAt,
            String jobId,
            String host,
            String machineStatus,
            String serviceStatus,
            String workingHealthcheck
    ) {
    }

    private record PostRebootStatus(boolean machineUp, boolean serviceUp, Optional<String> workingHealthcheck) {
    }

    private record SshWaitResult(Session session, Exception lastFailure) {
    }

    private record TechnicalAccount(String name, String accountId, String clientId, String clientSecret) {
    }

    private record CloudServer(String id, String name, String accessIPv4) {
    }

    private record OcsEndpoint(String name, String serversUrl, String actionUrl) {
    }

    private record CloudRecoveryConfig(
            List<TechnicalAccount> accounts,
            String oauthTokenUrl,
            List<OcsEndpoint> ocsEndpoints
    ) {
        private boolean isComplete() {
            return !oauthTokenUrl.isBlank() && !ocsEndpoints.isEmpty();
        }
    }

    private record VaultConfig(
            boolean enabled,
            String uri,
            String context,
            String namespace,
            String technicalAccountsPath,
            String roleId,
            String secretId
    ) {
        private static VaultConfig fromRuntime() {
            return new VaultConfig(
                    Boolean.parseBoolean(runtimeValue("VAULT_ENABLED", "spring.cloud.vault.enabled", "false")),
                    runtimeValue("VAULT_URI", "spring.cloud.vault.uri", ""),
                    runtimeValue("VAULT_CONTEXT", "spring.cloud.vault.kv.default-context", ""),
                    runtimeValue("VAULT_NAMESPACE", "spring.cloud.vault.namespace", ""),
                    runtimeValue("VAULT_TECH_ACCOUNTS_PATH", "dnfupdate.vault.technical-accounts-path",
                            runtimeValue("VAULT_CONTEXT", "spring.cloud.vault.kv.default-context", "")),
                    runtimeValue("VAULT_ROLE_ID", "spring.cloud.vault.app-role.role-id", ""),
                    runtimeValue("VAULT_SECRET_ID", "spring.cloud.vault.app-role.secret-id", "")
            );
        }

        private static String runtimeValue(String envName, String propertyName, String fallback) {
            String envValue = System.getenv(envName);
            if (envValue != null && !envValue.isBlank()) {
                return envValue.trim();
            }
            String propertyValue = System.getProperty(propertyName);
            if (propertyValue != null && !propertyValue.isBlank()) {
                return propertyValue.trim();
            }
            return fallback;
        }
    }

    private record VaultStatus(String state, String message, VaultConfig config, Instant checkedAt) {
        private static VaultStatus disabled(String message) {
            return new VaultStatus("DISABLED", message, VaultConfig.fromRuntime(), Instant.now());
        }

        private static VaultStatus up(VaultConfig config, String message) {
            return new VaultStatus("UP", message, config, Instant.now());
        }

        private static VaultStatus down(VaultConfig config, String message) {
            return new VaultStatus("DOWN", message, config, Instant.now());
        }
    }

    private enum ReportKind {
        PATCH,
        DRY_RUN
    }

    private static final class HostReport {
        private final Set<String> rhsaPresentBefore = Collections.synchronizedSet(new TreeSet<>());
        private final Set<String> rhsaInstalledAfter = Collections.synchronizedSet(new TreeSet<>());
        private final Set<String> rhsaCorrected = Collections.synchronizedSet(new TreeSet<>());
        private volatile Boolean machineUpAfterReboot;
        private volatile Boolean serviceUpAfterReboot;
        private volatile String workingHealthcheck;
    }

    private static final class Job {
        private final String id;
        private final Instant startedAt = Instant.now();
        private final List<String> hosts;
        private final Settings settings;
        private final String authorizedMember;
        private final ConcurrentLinkedDeque<Event> events = new ConcurrentLinkedDeque<>();
        private final Map<String, String> hostStatus = new ConcurrentHashMap<>();
        private final Map<String, HostReport> reports = new ConcurrentHashMap<>();
        private final AtomicBoolean finished = new AtomicBoolean(false);
        private final AtomicInteger succeeded = new AtomicInteger(0);
        private final AtomicInteger failed = new AtomicInteger(0);

        private Job(String id, List<String> hosts, Settings settings, String authorizedMember) {
            this.id = id;
            this.hosts = List.copyOf(hosts);
            this.settings = settings;
            this.authorizedMember = authorizedMember;
            hosts.forEach(host -> hostStatus.put(host, "queued"));
            hosts.forEach(host -> reports.put(host, new HostReport()));
        }

        private HostReport reportFor(String host) {
            return reports.computeIfAbsent(host, ignored -> new HostReport());
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

    private static final class JsonParser {
        private final String text;
        private int index;

        private JsonParser(String text) {
            this.text = text == null ? "" : text;
        }

        private Object parse() throws IOException {
            Object value = parseValue();
            skipWhitespace();
            if (index != text.length()) {
                throw new IOException("Unexpected JSON content at position " + index);
            }
            return value;
        }

        private Object parseValue() throws IOException {
            skipWhitespace();
            if (index >= text.length()) {
                throw new IOException("Unexpected end of JSON");
            }
            char ch = text.charAt(index);
            return switch (ch) {
                case '{' -> parseObject();
                case '[' -> parseArray();
                case '"' -> parseString();
                case 't' -> parseLiteral("true", Boolean.TRUE);
                case 'f' -> parseLiteral("false", Boolean.FALSE);
                case 'n' -> parseLiteral("null", null);
                default -> {
                    if (ch == '-' || Character.isDigit(ch)) {
                        yield parseNumber();
                    }
                    throw new IOException("Unexpected JSON character at position " + index);
                }
            };
        }

        private Map<String, Object> parseObject() throws IOException {
            expect('{');
            Map<String, Object> map = new LinkedHashMap<>();
            skipWhitespace();
            if (peek('}')) {
                index++;
                return map;
            }
            while (true) {
                String key = parseString();
                skipWhitespace();
                expect(':');
                map.put(key, parseValue());
                skipWhitespace();
                if (peek('}')) {
                    index++;
                    return map;
                }
                expect(',');
            }
        }

        private List<Object> parseArray() throws IOException {
            expect('[');
            List<Object> list = new ArrayList<>();
            skipWhitespace();
            if (peek(']')) {
                index++;
                return list;
            }
            while (true) {
                list.add(parseValue());
                skipWhitespace();
                if (peek(']')) {
                    index++;
                    return list;
                }
                expect(',');
            }
        }

        private String parseString() throws IOException {
            expect('"');
            StringBuilder builder = new StringBuilder();
            while (index < text.length()) {
                char ch = text.charAt(index++);
                if (ch == '"') {
                    return builder.toString();
                }
                if (ch == '\\') {
                    if (index >= text.length()) {
                        throw new IOException("Invalid JSON escape");
                    }
                    char escaped = text.charAt(index++);
                    switch (escaped) {
                        case '"', '\\', '/' -> builder.append(escaped);
                        case 'b' -> builder.append('\b');
                        case 'f' -> builder.append('\f');
                        case 'n' -> builder.append('\n');
                        case 'r' -> builder.append('\r');
                        case 't' -> builder.append('\t');
                        case 'u' -> {
                            if (index + 4 > text.length()) {
                                throw new IOException("Invalid JSON unicode escape");
                            }
                            String hex = text.substring(index, index + 4);
                            builder.append((char) Integer.parseInt(hex, 16));
                            index += 4;
                        }
                        default -> throw new IOException("Invalid JSON escape");
                    }
                } else {
                    builder.append(ch);
                }
            }
            throw new IOException("Unterminated JSON string");
        }

        private Object parseNumber() throws IOException {
            int start = index;
            if (peek('-')) {
                index++;
            }
            while (index < text.length() && Character.isDigit(text.charAt(index))) {
                index++;
            }
            if (peek('.')) {
                index++;
                while (index < text.length() && Character.isDigit(text.charAt(index))) {
                    index++;
                }
            }
            if (index < text.length() && (text.charAt(index) == 'e' || text.charAt(index) == 'E')) {
                index++;
                if (index < text.length() && (text.charAt(index) == '+' || text.charAt(index) == '-')) {
                    index++;
                }
                while (index < text.length() && Character.isDigit(text.charAt(index))) {
                    index++;
                }
            }
            String number = text.substring(start, index);
            try {
                return number.contains(".") || number.contains("e") || number.contains("E")
                        ? Double.parseDouble(number)
                        : Long.parseLong(number);
            } catch (NumberFormatException e) {
                throw new IOException("Invalid JSON number");
            }
        }

        private Object parseLiteral(String literal, Object value) throws IOException {
            if (!text.startsWith(literal, index)) {
                throw new IOException("Invalid JSON literal at position " + index);
            }
            index += literal.length();
            return value;
        }

        private void expect(char expected) throws IOException {
            skipWhitespace();
            if (index >= text.length() || text.charAt(index) != expected) {
                throw new IOException("Expected '" + expected + "' at position " + index);
            }
            index++;
        }

        private boolean peek(char expected) {
            return index < text.length() && text.charAt(index) == expected;
        }

        private void skipWhitespace() {
            while (index < text.length() && Character.isWhitespace(text.charAt(index))) {
                index++;
            }
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
                    input, textarea, select {
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
                      <div class="subtitle"><a href="/patching">Patch reports</a> · <a href="/dryrun">Dry run reports</a> · <a href="/status">Status</a> · <a href="/vault">Vault</a> · Keys are loaded from the JAR folder</div>
                    </div>
                  </header>
                  <main class="wrap">
                    <section class="controls">
                      <form id="jobForm">
                        <div class="field">
                          <label for="passphrase">Patch passphrase</label>
                          <input id="passphrase" name="passphrase" type="password" autocomplete="off" required>
                          <div class="muted">Required before any server patching starts.</div>
                        </div>
                        <div class="field">
                          <label for="technicalAccount">Vault technical account</label>
                          <select id="technicalAccount" name="technicalAccount" required disabled>
                            <option value="">Loading accounts from Vault...</option>
                          </select>
                          <div id="technicalAccountHelp" class="muted">Select the account group that owns these servers.</div>
                        </div>
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
                        <label class="check"><input id="dryRun" type="checkbox" name="dryRun"> Dry run report only</label>
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
                    const dryRun = document.getElementById('dryRun');
                    const technicalAccount = document.getElementById('technicalAccount');
                    const technicalAccountHelp = document.getElementById('technicalAccountHelp');
                    const hostsView = document.getElementById('hostsView');
                    const counts = {
                      total: document.getElementById('total'),
                      running: document.getElementById('running'),
                      succeeded: document.getElementById('succeeded'),
                      failed: document.getElementById('failed')
                    };
                    let source = null;

                    async function loadTechnicalAccounts() {
                      try {
                        const response = await fetch('/api/technical-accounts');
                        const data = await response.json();
                        if (!response.ok) throw new Error(data.error || 'Unable to load accounts.');
                        technicalAccount.innerHTML = '<option value="">Select an account</option>';
                        (data.accounts || []).forEach(name => {
                          const option = document.createElement('option');
                          option.value = name;
                          option.textContent = name;
                          technicalAccount.appendChild(option);
                        });
                        technicalAccount.disabled = false;
                        if (!data.accounts || data.accounts.length === 0) {
                          technicalAccountHelp.textContent = 'No named technical accounts were found in Vault.';
                        }
                      } catch (error) {
                        technicalAccount.innerHTML = '<option value="">Vault accounts unavailable</option>';
                        technicalAccountHelp.textContent = error.message;
                      }
                    }

                    loadTechnicalAccounts();

                    dryRun.addEventListener('change', () => {
                      runButton.textContent = dryRun.checked ? 'Start Dry Run' : 'Start Update';
                    });

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
                      runButton.textContent = dryRun.checked ? 'Dry Run Running...' : 'Running...';
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
                          runButton.textContent = dryRun.checked ? 'Start Dry Run' : 'Start Update';
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
                        runButton.textContent = dryRun.checked ? 'Start Dry Run' : 'Start Update';
                      }
                    });
                  </script>
                </body>
                </html>
                """;
    }
}
