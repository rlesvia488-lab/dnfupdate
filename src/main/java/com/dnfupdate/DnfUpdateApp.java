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
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.LinkedHashMap;
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
    private static final long REBOOT_WAIT_MILLIS = 5 * 60 * 1000L;
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
        server.createContext("/patching", app::handlePatching);
        server.createContext("/dryrun", app::handleDryRunReports);
        server.createContext("/status", app::handleStatus);
        server.createContext("/reports", app::handleReportFile);
        server.createContext("/", app::handleIndex);
        server.createContext("/api/start", app::handleStart);
        server.createContext("/api/job", app::handleJob);
        server.setExecutor(Executors.newCachedThreadPool());
        server.start();
        System.out.println("DNF Update UI running at http://localhost:" + port);
        System.out.println("Looking for key files next to the JAR in: " + appDir.toAbsolutePath());
        System.out.println("Patch audit log: " + appDir.resolve(AUDIT_LOG_FILE).toAbsolutePath());
        System.out.println("Post-reboot status log: " + appDir.resolve(STATUS_LOG_FILE).toAbsolutePath());
        System.out.println("HTML reports directory: " + appDir.resolve(REPORT_DIR).toAbsolutePath());
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
                "on".equals(form.get("dryRun"))
        );

        Job job = new Job(UUID.randomUUID().toString(), hosts, settings, authorizedMember.get());
        appendAuditLog(authorizedMember.get(), hosts);
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

    private void appendAuditLog(String memberId, List<String> hosts) throws IOException {
        String line = Instant.now() + " member=" + memberId + " servers=" + String.join(",", hosts) + System.lineSeparator();
        Files.writeString(appDir.resolve(AUDIT_LOG_FILE).normalize(), line, StandardCharsets.UTF_8,
                java.nio.file.StandardOpenOption.CREATE, java.nio.file.StandardOpenOption.APPEND);
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
                job.add(host, "info", "Reboot requested. SSH may disconnect now.");
                runRemote(job, host, session, "sudo -n systemctl reboot -i || sudo -n reboot", true);
                session.disconnect();
                session = null;
                PostRebootStatus status = verifyAfterReboot(job, host, report);
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

    private PostRebootStatus verifyAfterReboot(Job job, String host, HostReport report) {
        job.add(host, "info", "Waiting 5 minutes before post-reboot SSH verification.");
        sleep(REBOOT_WAIT_MILLIS);

        Session verificationSession = null;
        try {
            verificationSession = connect(job, host);
            report.machineUpAfterReboot = true;
            job.add(host, "success", "Server is reachable over SSH after reboot.");

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
            report.machineUpAfterReboot = false;
            report.serviceUpAfterReboot = false;
            job.add(host, "error", "Server is not reachable over SSH after reboot wait: " + cleanMessage(e));
            return new PostRebootStatus(false, false, Optional.empty());
        } finally {
            if (verificationSession != null) {
                verificationSession.disconnect();
            }
        }
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
            boolean dryRun
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
                      <div class="subtitle"><a href="/patching">Patch reports</a> · <a href="/dryrun">Dry run reports</a> · <a href="/status">Status</a> · Keys are loaded from the JAR folder</div>
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
                    const hostsView = document.getElementById('hostsView');
                    const counts = {
                      total: document.getElementById('total'),
                      running: document.getElementById('running'),
                      succeeded: document.getElementById('succeeded'),
                      failed: document.getElementById('failed')
                    };
                    let source = null;

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
