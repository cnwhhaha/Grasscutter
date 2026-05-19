package emu.grasscutter.server.packet.recv;

import static emu.grasscutter.config.Configuration.ACCOUNT;

import emu.grasscutter.*;
import emu.grasscutter.database.DatabaseHelper;
import emu.grasscutter.game.player.Player;
import emu.grasscutter.net.packet.*;
import emu.grasscutter.server.event.game.PlayerCreationEvent;
import emu.grasscutter.server.game.GameSession;
import emu.grasscutter.server.game.GameSession.SessionState;
import emu.grasscutter.server.packet.send.PacketGetPlayerTokenRsp;
import emu.grasscutter.utils.*;
import java.nio.charset.StandardCharsets;
import java.util.*;

/**
 * v2.0.10: Universal proto parser-based handler for Genshin 4.8.0 client.
 *
 * Strategy: The 4.8.0 client uses its own unique proto field numbers that don't
 * match any single LunaGC version. For REQUESTS we use the general parser to
 * extract fields from their known positions (verified by captured payloads).
 * For RESPONSES we write critical fields at ALL known LunaGC positions
 * (4.6.0 + 4.7.0 + 5.0.0) simultaneously — the client's proto parser will
 * match whichever position its schema defines and ignore unknown positions.
 *
 * We do NOT attempt RSA key exchange. The server stays on DISPATCH_KEY
 * encryption throughout. This avoids the complexity of reverse-engineering
 * the exact server_rand_key/sign field positions.
 *
 * Known request fields (verified from capture):
 *   field 1: varint=3       (platform_type or unknown)
 *   field 4: varint=1       (unknown)
 *   field 5: varint=1       (unknown)
 *   field 9: string         (account_uid)     — matches LunaGC 4.6.0
 *   field 10: string        (account_token)
 *   field 13: varint=1      (unknown)
 *   field 43: varint=5      (unknown)
 *   field 450: string       (client_rand_key)
 *   field 470: varint=1     (unknown)
 *   field 1226: varint=2    (key_id)
 *   field 1419: string      ("csc")
 *   field 1465: varint=2    (unknown)
 */
@Opcodes(PacketOpcodes.GetPlayerTokenReq)
public class HandlerGetPlayerTokenReq extends PacketHandler {

    /**
     * Parse all top-level proto fields from raw bytes into a map.
     * Returns field_number → value (Long for varint, byte[] for string/bytes).
     */
    private static Map<Integer, Object> parseProtoFields(byte[] data) {
        Map<Integer, Object> fields = new LinkedHashMap<>();
        int pos = 0;
        while (pos < data.length) {
            long[] tagResult = readVarint(data, pos);
            if (tagResult[0] < 0) break;
            long tag = tagResult[1];
            pos = (int) tagResult[0];
            int fieldNum = (int) (tag >> 3);
            int wireType = (int) (tag & 7);

            if (wireType == 0) { // varint
                long[] valResult = readVarint(data, pos);
                if (valResult[0] < 0) break;
                fields.put(fieldNum, valResult[1]);
                pos = (int) valResult[0];
            } else if (wireType == 2) { // length-delimited
                long[] lenResult = readVarint(data, pos);
                if (lenResult[0] < 0) break;
                int len = (int) lenResult[1];
                pos = (int) lenResult[0];
                if (pos + len > data.length) break;
                byte[] bytes = Arrays.copyOfRange(data, pos, pos + len);
                fields.put(fieldNum, bytes);
                pos += len;
            } else if (wireType == 5) { // fixed32
                if (pos + 4 > data.length) break;
                long val = (data[pos] & 0xFFL)
                        | ((data[pos+1] & 0xFFL) << 8)
                        | ((data[pos+2] & 0xFFL) << 16)
                        | ((data[pos+3] & 0xFFL) << 24);
                fields.put(fieldNum, val);
                pos += 4;
            } else {
                break; // unknown wire type
            }
        }
        return fields;
    }

    /** Read a protobuf varint. Returns [newPosition, value] or [-1, 0] on error. */
    private static long[] readVarint(byte[] data, int offset) {
        long result = 0;
        int shift = 0;
        int pos = offset;
        while (pos < data.length) {
            int b = data[pos++] & 0xFF;
            result |= (long)(b & 0x7F) << shift;
            if ((b & 0x80) == 0) {
                return new long[]{pos, result};
            }
            shift += 7;
        }
        return new long[]{-1, 0};
    }

    /** Get a string value from parsed fields. */
    private static String getFieldString(Map<Integer, Object> fields, int fieldNum) {
        Object v = fields.get(fieldNum);
        if (v instanceof byte[]) return new String((byte[]) v, StandardCharsets.UTF_8);
        return "";
    }

    /** Get a varint value from parsed fields. */
    private static long getFieldVarint(Map<Integer, Object> fields, int fieldNum, long defaultVal) {
        Object v = fields.get(fieldNum);
        if (v instanceof Long) return (Long) v;
        return defaultVal;
    }

    @Override
    public void handle(GameSession session, byte[] header, byte[] payload) throws Exception {
        // Parse all fields from the raw protobuf payload
        Map<Integer, Object> fields = parseProtoFields(payload);

        // Extract account info — verified from 4.8.0 capture: field 9=account_uid, field 10=account_token
        String accountId = getFieldString(fields, 9);
        if (accountId.isEmpty()) {
            accountId = getFieldString(fields, 3); // LunaGC 5.0.0 fallback
        }
        String accountToken = getFieldString(fields, 10);
        if (accountToken.isEmpty()) {
            accountToken = getFieldString(fields, 4); // LunaGC 5.0.0 fallback
        }

        Grasscutter.getLogger().info(
            "[TokenReq] accountId='{}' tokenLen={} payloadLen={}",
            accountId, accountToken.length(), payload.length);

        // Log all fields for debugging
        StringBuilder fieldLog = new StringBuilder("[TokenReq] Fields: ");
        for (var entry : fields.entrySet()) {
            Object v = entry.getValue();
            String display;
            if (v instanceof byte[]) {
                byte[] b = (byte[]) v;
                if (b.length <= 32) {
                    display = "str'" + new String(b, StandardCharsets.UTF_8) + "'";
                } else {
                    display = "str(len=" + b.length + ",start=" + bytesToHex(b, 8) + ")";
                }
            } else {
                display = "varint=" + v;
            }
            fieldLog.append(entry.getKey()).append("=").append(display).append(" ");
        }
        Grasscutter.getLogger().info(fieldLog.toString());

        if (accountId.isEmpty()) {
            Grasscutter.getLogger().error("[TokenReq] Could not extract account_uid from payload!");
            session.close();
            return;
        }

        // Look up account by ID
        var account = DispatchUtils.getAccountById(accountId);
        if (account == null) {
            Grasscutter.getLogger().warn("[TokenReq] No account found for id='{}', closing", accountId);
            session.close();
            return;
        }

        session.setAccount(account);

        // Kick existing player with same account
        boolean kicked = false;
        var exists = Grasscutter.getGameServer().getPlayerByAccountId(accountId);
        if (exists != null) {
            var existsSession = exists.getSession();
            if (existsSession != session) {
                exists.onLogout();
                existsSession.close();
                Grasscutter.getLogger().warn("Player {} was kicked due to duplicated login", account.getUsername());
                kicked = true;
            }
        }

        if (!kicked) {
            if (ACCOUNT.maxPlayer > -1
                    && Grasscutter.getGameServer().getPlayers().size() >= ACCOUNT.maxPlayer) {
                session.close();
                return;
            }
        }

        // Player creation and loading
        var event = new PlayerCreationEvent(session, Player.class);
        event.call();
        var player = DatabaseHelper.getPlayerByAccount(account, event.getPlayerClass());
        if (player == null) {
            var nextPlayerUid = DatabaseHelper.getNextPlayerId(session.getAccount().getReservedPlayerUid());
            player = event.getPlayerClass().getDeclaredConstructor(GameSession.class).newInstance(session);
            DatabaseHelper.generatePlayerUid(player, nextPlayerUid);
        }
        session.setPlayer(player);

        if (session.getAccount().isBanned()) {
            session.setState(SessionState.ACCOUNT_BANNED);
            session.send(new PacketGetPlayerTokenRsp(
                    session, 21, "FORBID_CHEATING_PLUGINS", session.getAccount().getBanEndTime()));
            return;
        }

        player.loadFromDatabase();
        session.setState(SessionState.WAITING_FOR_LOGIN);

        // v2.0.10: NO key exchange. Stay on DISPATCH_KEY. Never call setUseSecretKey.
        // Build a multi-position response covering all known LunaGC proto versions.
        session.send(buildMultiPositionTokenRsp(session));
    }

    /**
     * Build GetPlayerTokenRsp writing critical fields at ALL known LunaGC positions
     * (4.6.0, 4.7.0, 5.0.0). The 4.8.0 client will match the position(s) its proto
     * defines and safely ignore the rest.
     *
     * Key fields and their positions across versions:
     *
     *   uid (uint32):         v4.6=13,  v4.7=4,   v5.0=8
     *   token (string):        v4.6=14,  v4.7=2,   v5.0=15
     *   account_uid (string):  v4.6=3,   v4.7=9,   v5.0=6
     *   platform_type (uint32): v4.6=15, v4.7=14,  v5.0=13
     *   country_code (string):  v4.6=1096, v4.7=254, v5.0=1269
     *   key_id (uint32):       v4.6=1411, v4.7=720,  v5.0=398
     *   client_ip_str (string): v4.6=703,  —,       v5.0=1871
     *   client_version_random_key (string): v4.6=207, —, v5.0=496
     *   security_cmd_buffer (bytes): —,     v4.7=3,  v5.0=4
     *   server_rand_key (string): v4.6=1118, v4.7=910, v5.0=68
     *   sign (string):         v4.6=477,  v4.7=414, v5.0=1885
     */
    private BasePacket buildMultiPositionTokenRsp(GameSession session) {
        var player = session.getPlayer();
        var account = session.getAccount();
        var token = account.getToken();
        int uid = player.getUid();
        String accountId = account.getId();  // e.g. "10001"

        // Dummy server_rand_key/sign from original LunaGC codebase
        String dummyRandKey = "CfO2d7eEYha5bJRXdCfoiemPNAtXDpyNTQ3ObeTt5a7SSHz6GAEO1WPiTQ7fR6OG8LqhVN3ZTxH9Bnkc09BnCxud+kn0+PiGv1PTOuWK0LkQQ1xmg89zA9IHS+OJd1yKT2BBmJf4sN61gi+WtT7aFwRlzku3kGCk6p2wiPo2enE7UwCFi/GiD4vq/m3hNZiKBjitAvheaqbSLjMpBax+c8HXoY5G09ap1PjEnUQPIK0xZRRQKpnrWcCyP4j8N3WwYYQGDW+OYOJjBvJdv+D6XSdEi+4IsZASYVpu9V8UZ570Cakbc+IjUm0UZJXghcR7izIjKtoNHf2Fmc26DEp1Jw==";
        String dummySign = "mMx/Klovbzq1QxQvVgm30nYhj0jDOykyo9aparyWRNz3ACxV/2gIdLpyM/SMerWMTcx26NapQ9HsKK7BRK7Yx+nMR0O83BkBlxfl+NEarYr6kj9lBKAxZYXTXFRYA4sRynvwa/MOPmGwYMNl6aVvMohhvrsTopsRvIuGFtnCVL2wBfbxcNnbVfP5k+DxPuQnxa/vi+ju8TogW2R+r0p9zQ5NJe1oaYe4xYbyhefFVv11FA/JQHwMHLEyrEdPqTzdN75CUmE09yLuAoeJzoJ1vwwjwfcH9dMDPxsewNJBGiylVHYf56kF4HypNkYNjtxbghgLBaHg0ZoeYHTOJ7YUTQ==";

        try {
            java.io.ByteArrayOutputStream bos = new java.io.ByteArrayOutputStream();

            // === uid (uint32) — all known positions ===
            writeVarintField(bos, 13, 0, uid);  // LunaGC 4.6.0
            writeVarintField(bos, 4, 0, uid);   // LunaGC 4.7.0
            writeVarintField(bos, 8, 0, uid);   // LunaGC 5.0.0

            // === token (string) — all known positions ===
            if (token != null && !token.isEmpty()) {
                writeStringField(bos, 14, token);  // LunaGC 4.6.0
                writeStringField(bos, 2, token);   // LunaGC 4.7.0
                writeStringField(bos, 15, token);  // LunaGC 5.0.0
            }

            // === account_uid (string) — all known positions ===
            if (accountId != null && !accountId.isEmpty()) {
                writeStringField(bos, 3, accountId);   // LunaGC 4.6.0
                writeStringField(bos, 9, accountId);   // LunaGC 4.7.0
                writeStringField(bos, 6, accountId);   // LunaGC 5.0.0
            }

            // === platform_type (uint32) — all known positions ===
            writeVarintField(bos, 15, 0, 3);  // LunaGC 4.6.0
            writeVarintField(bos, 14, 0, 3);  // LunaGC 4.7.0
            writeVarintField(bos, 13, 0, 3);  // LunaGC 5.0.0

            // === country_code (string) — all known positions ===
            writeStringField(bos, 1096, "US");  // LunaGC 4.6.0
            writeStringField(bos, 254, "US");    // LunaGC 4.7.0
            writeStringField(bos, 1269, "US");   // LunaGC 5.0.0

            // === key_id (uint32) — all known positions ===
            writeVarintField(bos, 1411, 0, 0);  // LunaGC 4.6.0 (key_id=0 → no key exchange)
            writeVarintField(bos, 720, 0, 0);   // LunaGC 4.7.0
            writeVarintField(bos, 398, 0, 0);   // LunaGC 5.0.0

            // === client_ip_str (string) ===
            String ipStr = session.getAddress().getAddress().getHostAddress();
            writeStringField(bos, 703, ipStr);   // LunaGC 4.6.0
            writeStringField(bos, 1871, ipStr);  // LunaGC 5.0.0

            // === client_version_random_key (string) ===
            String versionKey = "c25-314dd05b0b5f";
            writeStringField(bos, 207, versionKey);  // LunaGC 4.6.0
            writeStringField(bos, 496, versionKey);  // LunaGC 5.0.0

            // === security_cmd_buffer (bytes) ===
            // Write the actual encrypt seed buffer so client can derive correct keys
            writeBytesField(bos, 3, Crypto.ENCRYPT_SEED_BUFFER);  // LunaGC 4.7.0 position
            writeBytesField(bos, 4, Crypto.ENCRYPT_SEED_BUFFER);  // LunaGC 5.0.0 position

            // === server_rand_key (string) — dummy ===
            writeStringField(bos, 1118, dummyRandKey);  // LunaGC 4.6.0
            writeStringField(bos, 910, dummyRandKey);   // LunaGC 4.7.0
            writeStringField(bos, 68, dummyRandKey);    // LunaGC 5.0.0

            // === sign (string) — dummy ===
            writeStringField(bos, 477, dummySign);   // LunaGC 4.6.0
            writeStringField(bos, 414, dummySign);   // LunaGC 4.7.0
            writeStringField(bos, 1885, dummySign);  // LunaGC 5.0.0

            byte[] data = bos.toByteArray();
            Grasscutter.getLogger().info("[TokenReq] Multi rsp size={} uid={} accountId={}",
                data.length, uid, accountId);

            BasePacket pkt = new BasePacket(PacketOpcodes.GetPlayerTokenRsp, true);
            pkt.setUseDispatchKey(true);
            pkt.setData(data);
            return pkt;
        } catch (Exception e) {
            Grasscutter.getLogger().error("[TokenReq] Failed to build multi rsp: {}", e.getMessage(), e);
            return null;
        }
    }

    // === Protobuf encoding helpers ===

    private static void writeVarintField(java.io.ByteArrayOutputStream bos,
                                          int fieldNum, int wireType, long value)
            throws java.io.IOException {
        int tag = (fieldNum << 3) | (wireType & 7);
        writeVarint(bos, tag);
        writeVarint(bos, value);
    }

    private static void writeStringField(java.io.ByteArrayOutputStream bos,
                                          int fieldNum, String value)
            throws java.io.IOException {
        if (value == null || value.isEmpty()) return;
        int tag = (fieldNum << 3) | 2;
        byte[] strBytes = value.getBytes(StandardCharsets.UTF_8);
        writeVarint(bos, tag);
        writeVarint(bos, strBytes.length);
        bos.write(strBytes);
    }

    private static void writeBytesField(java.io.ByteArrayOutputStream bos,
                                         int fieldNum, byte[] value)
            throws java.io.IOException {
        if (value == null || value.length == 0) return;
        int tag = (fieldNum << 3) | 2;
        writeVarint(bos, tag);
        writeVarint(bos, value.length);
        bos.write(value);
    }

    private static void writeVarint(java.io.ByteArrayOutputStream bos, long value)
            throws java.io.IOException {
        while (true) {
            int bits = (int) (value & 0x7F);
            value >>>= 7;
            if (value != 0) {
                bos.write(bits | 0x80);
            } else {
                bos.write(bits);
                break;
            }
        }
    }

    private static String bytesToHex(byte[] bytes, int maxLen) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < Math.min(bytes.length, maxLen); i++) {
            sb.append(String.format("%02X ", bytes[i]));
        }
        return sb.toString().trim();
    }
}
