import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.HttpExchange;

import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.SecureRandom;
import java.sql.*;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

public class Main {

    private static final Map<String, Session> SESSIONS =
        new ConcurrentHashMap<>();

    private static final SecureRandom RANDOM = new SecureRandom();

    private static final Path PUBLIC =
        Paths.get("public").toAbsolutePath().normalize();

    record Session(int id, String userId, String name, String role) {}

    public static void main(String[] args) throws Exception {

        Class.forName("com.mysql.cj.jdbc.Driver");

        createOwnerIfNeeded();

        HttpServer server = HttpServer.create(
            new InetSocketAddress(8080), 0
        );

        server.createContext("/api/", Main::handleAPI);
        server.createContext("/", Main::serveFiles);

        server.setExecutor(
            java.util.concurrent.Executors.newCachedThreadPool()
        );

        server.start();

        System.out.println("WiFiTrust started!");
        System.out.println("Open http://localhost:8080");
    }

    // Create the first owner account from environment variables
    private static void createOwnerIfNeeded() throws Exception {

        String id = System.getenv("OWNER_ID");
        String password = System.getenv("OWNER_PASSWORD");
        String name = System.getenv().getOrDefault(
            "OWNER_NAME", "Office Administrator"
        );

        if (id == null || id.isBlank()
                || password == null || password.length() < 10) {

            throw new IllegalStateException(
                "Set OWNER_ID and OWNER_PASSWORD. Password must be at least 10 characters."
            );
        }

        try (Connection con = Database.getConnection()) {

            PreparedStatement check = con.prepareStatement(
                "SELECT id FROM users WHERE user_id=? AND role='OWNER'"
            );

            check.setString(1, id);

            try (ResultSet rs = check.executeQuery()) {
                if (rs.next()) return;
            }

            String salt = PasswordUtil.generateSalt();
            String hash = PasswordUtil.hashPassword(password, salt);

            PreparedStatement ps = con.prepareStatement(
                "INSERT INTO users(user_id,full_name,password_hash,password_salt,role) VALUES(?,?,?,?,'OWNER')"
            );

            ps.setString(1, id);
            ps.setString(2, name);
            ps.setString(3, hash);
            ps.setString(4, salt);
            ps.executeUpdate();

            System.out.println("Initial owner account created.");
        }
    }

    // Main API controller
    private static void handleAPI(HttpExchange ex)
            throws IOException {

        try {

            ex.getResponseHeaders().set("Cache-Control", "no-store");

            String path = ex.getRequestURI().getPath();
            String method = ex.getRequestMethod();

            Map<String, String> data = readForm(ex);

            if (path.equals("/api/login") && method.equals("POST")) {
                login(ex, data);
                return;
            }

            if (path.equals("/api/logout") && method.equals("POST")) {
                logout(ex);
                return;
            }

            Session session = getSession(ex);

            if (session == null) {
                send(ex, 401,
                    "{\"error\":\"ACCESS DENIED. Please log in.\"}");
                return;
            }

            if (path.equals("/api/me") && method.equals("GET")) {

                send(ex, 200,
                    "{\"userId\":\"" + json(session.userId()) +
                    "\",\"name\":\"" + json(session.name()) +
                    "\",\"role\":\"" + session.role() + "\"}");

                return;
            }

            if (path.equals("/api/employees")
                    && session.role().equals("OWNER")) {

                if (method.equals("GET")) {
                    listEmployees(ex);
                    return;
                }

                if (method.equals("POST")) {
                    addEmployee(ex, data);
                    return;
                }
            }

            if (path.equals("/api/deactivate")
                    && method.equals("POST")
                    && session.role().equals("OWNER")) {

                deactivateEmployee(ex, data);
                return;
            }

            if (path.equals("/api/requests")) {

                if (method.equals("GET")) {
                    listRequests(ex, session);
                    return;
                }

                if (method.equals("POST")
                        && session.role().equals("EMPLOYEE")) {

                    createRequest(ex, data, session);
                    return;
                }
            }

            if (path.equals("/api/decision")
                    && method.equals("POST")
                    && session.role().equals("OWNER")) {

                decideRequest(ex, data, session);
                return;
            }

            if (path.equals("/api/history")
                    && method.equals("GET")) {

                listHistory(ex, session);
                return;
            }

            send(ex, 403,
                "{\"error\":\"You do not have permission.\"}");

        } catch (IllegalArgumentException e) {

            send(ex, 400,
                "{\"error\":\"" + json(e.getMessage()) + "\"}");

        } catch (Exception e) {

            e.printStackTrace();

            send(ex, 500,
                "{\"error\":\"Server error. Check the Java terminal.\"}");
        }
    }

    // LOGIN
    private static void login(
        HttpExchange ex, Map<String, String> data
    ) throws Exception {

        String id = required(data, "userId", 40);
        String password = required(data, "password", 100);

        try (Connection con = Database.getConnection()) {

            PreparedStatement ps = con.prepareStatement(
                "SELECT * FROM users WHERE user_id=? AND active=TRUE"
            );

            ps.setString(1, id);

            try (ResultSet rs = ps.executeQuery()) {

                if (!rs.next()) {
                    send(ex, 401,
                        "{\"error\":\"ACCESS DENIED. Invalid or inactive office User ID.\"}");
                    return;
                }

                boolean valid = PasswordUtil.verifyPassword(
                    password,
                    rs.getString("password_salt"),
                    rs.getString("password_hash")
                );

                if (!valid) {
                    send(ex, 401,
                        "{\"error\":\"ACCESS DENIED. Incorrect password.\"}");
                    return;
                }

                String token = createToken();

                Session session = new Session(
                    rs.getInt("id"),
                    rs.getString("user_id"),
                    rs.getString("full_name"),
                    rs.getString("role")
                );

                SESSIONS.put(token, session);

                ex.getResponseHeaders().add(
                    "Set-Cookie",
                    "WIFISESSION=" + token +
                    "; Path=/; HttpOnly; SameSite=Strict"
                );

                send(ex, 200,
                    "{\"ok\":true,\"role\":\"" +
                    session.role() + "\"}");
            }
        }
    }

    // LOGOUT
    private static void logout(HttpExchange ex)
            throws IOException {

        String token = getCookie(ex, "WIFISESSION");

        if (token != null) {
            SESSIONS.remove(token);
        }

        ex.getResponseHeaders().add(
            "Set-Cookie",
            "WIFISESSION=; Path=/; Max-Age=0; HttpOnly; SameSite=Strict"
        );

        send(ex, 200, "{\"ok\":true}");
    }

    // OWNER CREATES EMPLOYEE ACCOUNT
    private static void addEmployee(
        HttpExchange ex, Map<String, String> data
    ) throws Exception {

        String id = required(data, "userId", 40);
        String name = required(data, "name", 100);
        String password = required(data, "password", 100);

        if (password.length() < 10) {
            throw new IllegalArgumentException(
                "Temporary password must have at least 10 characters."
            );
        }

        String salt = PasswordUtil.generateSalt();
        String hash = PasswordUtil.hashPassword(password, salt);

        try (Connection con = Database.getConnection()) {

            PreparedStatement ps = con.prepareStatement(
                "INSERT INTO users(user_id,full_name,password_hash,password_salt,role) VALUES(?,?,?,?,'EMPLOYEE')"
            );

            ps.setString(1, id);
            ps.setString(2, name);
            ps.setString(3, hash);
            ps.setString(4, salt);

            ps.executeUpdate();

            send(ex, 201,
                "{\"message\":\"Employee account created successfully.\"}");

        } catch (SQLIntegrityConstraintViolationException e) {

            throw new IllegalArgumentException(
                "This office User ID already exists."
            );
        }
    }

    // VIEW EMPLOYEES
    private static void listEmployees(HttpExchange ex)
            throws Exception {

        StringBuilder out = new StringBuilder(
            "{\"employees\":["
        );

        boolean first = true;

        try (Connection con = Database.getConnection();
             PreparedStatement ps = con.prepareStatement(
                "SELECT id,user_id,full_name,active,created_at FROM users WHERE role='EMPLOYEE' ORDER BY created_at DESC"
             );
             ResultSet rs = ps.executeQuery()) {

            while (rs.next()) {

                if (!first) out.append(",");
                first = false;

                out.append("{")
                    .append("\"id\":").append(rs.getInt("id"))
                    .append(",\"userId\":\"").append(json(rs.getString("user_id"))).append("\"")
                    .append(",\"name\":\"").append(json(rs.getString("full_name"))).append("\"")
                    .append(",\"active\":").append(rs.getBoolean("active"))
                    .append(",\"createdAt\":\"").append(json(rs.getString("created_at"))).append("\"")
                    .append("}");
            }
        }

        out.append("]}");

        send(ex, 200, out.toString());
    }

    // DEACTIVATE EMPLOYEE
    private static void deactivateEmployee(
        HttpExchange ex, Map<String, String> data
    ) throws Exception {

        int id = integer(data, "id");

        try (Connection con = Database.getConnection();
             PreparedStatement ps = con.prepareStatement(
                "UPDATE users SET active=FALSE WHERE id=? AND role='EMPLOYEE'"
             )) {

            ps.setInt(1, id);

            if (ps.executeUpdate() == 0) {
                throw new IllegalArgumentException(
                    "Employee not found."
                );
            }
        }

        // Remove any active sessions belonging to the employee
        SESSIONS.entrySet().removeIf(
            entry -> entry.getValue().id() == id
        );

        send(ex, 200, "{\"ok\":true}");
    }

    // EMPLOYEE SUBMITS DEVICE REQUEST
    private static void createRequest(
        HttpExchange ex,
        Map<String, String> data,
        Session session
    ) throws Exception {

        String device = required(data, "deviceName", 100);
        String type = required(data, "deviceType", 30);

        String mac = required(data, "macAddress", 17)
            .toUpperCase(Locale.ROOT);

        if (!mac.matches("([0-9A-F]{2}:){5}[0-9A-F]{2}")) {
            throw new IllegalArgumentException(
                "Enter MAC address like AA:BB:CC:DD:EE:FF."
            );
        }

        if (!Set.of("Laptop", "Mobile phone", "Tablet", "Other")
                .contains(type)) {

            throw new IllegalArgumentException(
                "Choose a valid device type."
            );
        }

        int requestId;

        try (Connection con = Database.getConnection();
             PreparedStatement ps = con.prepareStatement(
                "INSERT INTO access_requests(employee_db_id,device_name,device_type,mac_address) VALUES(?,?,?,?)",
                Statement.RETURN_GENERATED_KEYS
             )) {

            ps.setInt(1, session.id());
            ps.setString(2, device);
            ps.setString(3, type);
            ps.setString(4, mac);

            ps.executeUpdate();

            try (ResultSet keys = ps.getGeneratedKeys()) {
                keys.next();
                requestId = keys.getInt(1);
            }
        }

        addHistory(
            requestId,
            "SUBMITTED",
            session.id(),
            "Employee submitted device request"
        );

        send(ex, 201,
            "{\"message\":\"Request submitted. Current status: PENDING.\"}");
    }

    // VIEW REQUESTS
    private static void listRequests(
        HttpExchange ex, Session session
    ) throws Exception {

        String sql;

        if (session.role().equals("OWNER")) {

            sql = "SELECT a.id,u.user_id,u.full_name," +
                "a.device_name,a.device_type,a.mac_address," +
                "a.status,a.created_at,a.decided_at " +
                "FROM access_requests a " +
                "JOIN users u ON a.employee_db_id=u.id " +
                "ORDER BY a.created_at DESC";

        } else {

            sql = "SELECT a.id,u.user_id,u.full_name," +
                "a.device_name,a.device_type,a.mac_address," +
                "a.status,a.created_at,a.decided_at " +
                "FROM access_requests a " +
                "JOIN users u ON a.employee_db_id=u.id " +
                "WHERE a.employee_db_id=? " +
                "ORDER BY a.created_at DESC";
        }

        StringBuilder out = new StringBuilder(
            "{\"requests\":["
        );

        boolean first = true;

        try (Connection con = Database.getConnection();
             PreparedStatement ps = con.prepareStatement(sql)) {

            if (session.role().equals("EMPLOYEE")) {
                ps.setInt(1, session.id());
            }

            try (ResultSet rs = ps.executeQuery()) {

                while (rs.next()) {

                    if (!first) out.append(",");
                    first = false;

                    out.append("{")
                        .append("\"id\":").append(rs.getInt("id"))
                        .append(",\"userId\":\"").append(json(rs.getString("user_id"))).append("\"")
                        .append(",\"employee\":\"").append(json(rs.getString("full_name"))).append("\"")
                        .append(",\"device\":\"").append(json(rs.getString("device_name"))).append("\"")
                        .append(",\"type\":\"").append(json(rs.getString("device_type"))).append("\"")
                        .append(",\"mac\":\"").append(json(rs.getString("mac_address"))).append("\"")
                        .append(",\"status\":\"").append(rs.getString("status")).append("\"")
                        .append(",\"created\":\"").append(json(rs.getString("created_at"))).append("\"")
                        .append(",\"decided\":\"").append(json(rs.getString("decided_at"))).append("\"")
                        .append("}");
                }
            }
        }

        out.append("]}");

        send(ex, 200, out.toString());
    }

    // OWNER ALLOWS, DENIES OR REVOKES
    private static void decideRequest(
        HttpExchange ex,
        Map<String, String> data,
        Session owner
    ) throws Exception {

        int id = integer(data, "id");
        String status = required(data, "status", 10);

        if (!Set.of("ALLOWED", "DENIED", "REVOKED").contains(status)) {
            throw new IllegalArgumentException("Invalid decision.");
        }

        try (Connection con = Database.getConnection()) {

            con.setAutoCommit(false);

            try {

                String currentStatus;

                try (PreparedStatement check = con.prepareStatement(
                    "SELECT status FROM access_requests WHERE id=? FOR UPDATE"
                )) {
                    check.setInt(1, id);

                    try (ResultSet rs = check.executeQuery()) {
                        if (!rs.next()) {
                            throw new IllegalArgumentException(
                                "Request not found."
                            );
                        }
                        currentStatus = rs.getString("status");
                    }
                }

                if (status.equals("REVOKED")
                        && !currentStatus.equals("ALLOWED")) {
                    throw new IllegalArgumentException(
                        "Only an allowed request can be revoked."
                    );
                }

                if (!status.equals("REVOKED")
                        && !currentStatus.equals("PENDING")) {
                    throw new IllegalArgumentException(
                        "Only pending requests can be allowed or denied."
                    );
                }

                try (PreparedStatement ps = con.prepareStatement(
                    "UPDATE access_requests SET status=?,decided_at=CURRENT_TIMESTAMP,decided_by=? WHERE id=?"
                )) {
                    ps.setString(1, status);
                    ps.setInt(2, owner.id());
                    ps.setInt(3, id);
                    ps.executeUpdate();
                }

                try (PreparedStatement ps = con.prepareStatement(
                    "INSERT INTO request_history(request_id,action,changed_by,notes) VALUES(?,?,?,?)"
                )) {
                    ps.setInt(1, id);
                    ps.setString(2, status);
                    ps.setInt(3, owner.id());
                    ps.setString(4, "Owner decision");
                    ps.executeUpdate();
                }

                con.commit();

            } catch (Exception e) {
                con.rollback();
                throw e;
            }
        }

        send(ex, 200,
            "{\"ok\":true,\"message\":\"Status updated to " + status + "\"}");
    }

    // SAVE HISTORY
    private static void addHistory(
        int requestId,
        String action,
        int userId,
        String notes
    ) throws Exception {

        try (Connection con = Database.getConnection();
             PreparedStatement ps = con.prepareStatement(
                "INSERT INTO request_history(request_id,action,changed_by,notes) VALUES(?,?,?,?)"
             )) {

            ps.setInt(1, requestId);
            ps.setString(2, action);
            ps.setInt(3, userId);
            ps.setString(4, notes);

            ps.executeUpdate();
        }
    }

    // VIEW HISTORY
    private static void listHistory(
        HttpExchange ex, Session session
    ) throws Exception {

        String sql;

        if (session.role().equals("OWNER")) {

            sql = "SELECT h.id,h.request_id,h.action,h.notes,h.changed_at," +
                "u.user_id,u.full_name " +
                "FROM request_history h " +
                "JOIN users u ON h.changed_by=u.id " +
                "ORDER BY h.changed_at DESC";

        } else {

            sql = "SELECT h.id,h.request_id,h.action,h.notes,h.changed_at," +
                "u.user_id,u.full_name " +
                "FROM request_history h " +
                "JOIN users u ON h.changed_by=u.id " +
                "JOIN access_requests a ON h.request_id=a.id " +
                "WHERE a.employee_db_id=? " +
                "ORDER BY h.changed_at DESC";
        }

        StringBuilder out = new StringBuilder(
            "{\"history\":["
        );

        boolean first = true;

        try (Connection con = Database.getConnection();
             PreparedStatement ps = con.prepareStatement(sql)) {

            if (session.role().equals("EMPLOYEE")) {
                ps.setInt(1, session.id());
            }

            try (ResultSet rs = ps.executeQuery()) {

                while (rs.next()) {

                    if (!first) out.append(",");
                    first = false;

                    out.append("{")
                        .append("\"id\":").append(rs.getInt("id"))
                        .append(",\"requestId\":").append(rs.getInt("request_id"))
                        .append(",\"action\":\"").append(json(rs.getString("action"))).append("\"")
                        .append(",\"notes\":\"").append(json(rs.getString("notes"))).append("\"")
                        .append(",\"changedAt\":\"").append(json(rs.getString("changed_at"))).append("\"")
                        .append(",\"userId\":\"").append(json(rs.getString("user_id"))).append("\"")
                        .append(",\"name\":\"").append(json(rs.getString("full_name"))).append("\"")
                        .append("}");
                }
            }
        }

        out.append("]}");

        send(ex, 200, out.toString());
    }

    // SERVE HTML, CSS AND JAVASCRIPT
    private static void serveFiles(HttpExchange ex)
            throws IOException {

        String path = ex.getRequestURI().getPath();

        if (path.equals("/")) {
            path = "/index.html";
        }

        Path file = PUBLIC.resolve(path.substring(1)).normalize();

        if (!file.startsWith(PUBLIC)
                || !Files.exists(file)
                || Files.isDirectory(file)) {

            send(ex, 404, "File not found.");
            return;
        }

        String type;

        if (path.endsWith(".css")) {
            type = "text/css; charset=utf-8";
        } else if (path.endsWith(".js")) {
            type = "application/javascript; charset=utf-8";
        } else {
            type = "text/html; charset=utf-8";
        }

        byte[] content = Files.readAllBytes(file);

        ex.getResponseHeaders().set("Content-Type", type);
        ex.sendResponseHeaders(200, content.length);

        try (OutputStream out = ex.getResponseBody()) {
            out.write(content);
        }
    }

    // FORM DATA
    private static Map<String, String> readForm(
        HttpExchange ex
    ) throws IOException {

        if (!ex.getRequestMethod().equals("POST")) {
            return Map.of();
        }

        String body = new String(
            ex.getRequestBody().readAllBytes(),
            StandardCharsets.UTF_8
        );

        Map<String, String> data = new HashMap<>();

        for (String pair : body.split("&")) {

            String[] parts = pair.split("=", 2);

            String key = URLDecoder.decode(
                parts[0], StandardCharsets.UTF_8
            );

            String value = parts.length > 1
                ? URLDecoder.decode(parts[1], StandardCharsets.UTF_8)
                : "";

            data.put(key, value);
        }

        return data;
    }

    private static String required(
        Map<String, String> data, String key, int max
    ) {

        String value = data.getOrDefault(key, "").trim();

        if (value.isEmpty() || value.length() > max) {
            throw new IllegalArgumentException(
                "Check the " + key + " field."
            );
        }

        return value;
    }

    private static int integer(
        Map<String, String> data, String key
    ) {

        try {
            return Integer.parseInt(required(data, key, 10));
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException("Invalid ID.");
        }
    }

    private static Session getSession(HttpExchange ex) {

        String token = getCookie(ex, "WIFISESSION");

        return token == null ? null : SESSIONS.get(token);
    }

    private static String getCookie(
        HttpExchange ex, String name
    ) {

        String cookie = ex.getRequestHeaders().getFirst("Cookie");

        if (cookie == null) return null;

        for (String part : cookie.split(";")) {

            String[] pair = part.trim().split("=", 2);

            if (pair.length == 2 && pair[0].equals(name)) {
                return pair[1];
            }
        }

        return null;
    }

    private static String createToken() {

        byte[] bytes = new byte[32];
        RANDOM.nextBytes(bytes);

        return Base64.getUrlEncoder()
            .withoutPadding().encodeToString(bytes);
    }

    private static String json(String value) {

        if (value == null) return "";

        return value.replace("\\", "\\\\")
            .replace("\"", "\\\"")
            .replace("\n", " ")
            .replace("\r", " ");
    }

    private static void send(
        HttpExchange ex, int status, String body
    ) throws IOException {

        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);

        ex.getResponseHeaders().set(
            "Content-Type", "application/json; charset=utf-8"
        );

        ex.sendResponseHeaders(status, bytes.length);

        try (OutputStream out = ex.getResponseBody()) {
            out.write(bytes);
        }
    }
}