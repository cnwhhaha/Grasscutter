package emu.grasscutter.server.packet.recv;

import static emu.grasscutter.config.Configuration.ACCOUNT;

import emu.grasscutter.*;
import emu.grasscutter.database.DatabaseHelper;
import emu.grasscutter.game.player.Player;
import emu.grasscutter.net.packet.*;
import emu.grasscutter.server.event.game.PlayerCreationEvent;
import emu.grasscutter.server.game.GameSession;
import emu.grasscutter.server.game.GameSession.SessionState;
import emu.grasscutter.utils.*;
import java.nio.charset.StandardCharsets;
import java.util.*;

/**
 * v2.0.12: Smart multi-position raw proto handler for 5.3.5 client (masquerading as 4.8.0).
 *
 * The client binary identifies as 5.3.5, not 4.8.0. Its proto field numbers match
 * NEITHER 4.x nor 5.0.0 exactly. We don't have the exact 5.3.5 proto definitions, so
 * we use a smart multi-position approach: write critical fields at ALL known LunaGC
 * positions (4.6.0 + 4.7.0 + 5.0.0) that are wire-type-compatible.
 *
 * Wire type conflict handling:
 *   - Fields 2, 14, 15 have string vs varint conflicts for token/platform_type.
 *     Resolution: write token as string at field 2 (4.7.0) + field 15 (5.0.0),
 *     write platform_type as varint at field 13 (5.0.0) + field 14 (4.7.0).
 *   - Field 3: account_uid (4.6.0, string) + security_cmd_buffer (4.7.0, bytes).
 *     Both wire type 2, write both safely.
 *   - Field 4: uid (4.7.0, varint) vs security_cmd_buffer (5.0.0, bytes). CONFLICT.
 *     Write uid at field 4; security_cmd_buffer only at field 3 (4.7.0 pos).
 *   - Field 13: uid (4.6.0, varint) + platform_type (5.0.0, varint). Both varint.
 *     Write platform_type here; uid is covered at fields 4 and 8.
 *
 * Known 5.3.5 request fields:
 *   field 1: varint=3       (platform_type)
 *   field 4: varint=1       (account_type)
 *   field 5: varint=1       (is_guest)
 *   field 9: string         (account_uid)
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

    // === Proto field parsing (for REQUEST) ===

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
                break;
            }
        }
        return fields;
    }

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

    private static String getFieldString(Map<Integer, Object> fields, int fieldNum) {
        Object v = fields.get(fieldNum);
        if (v instanceof byte[]) return new String((byte[]) v, StandardCharsets.UTF_8);
        return "";
    }

    private static long getFieldVarint(Map<Integer, Object> fields, int fieldNum, long defaultVal) {
        Object v = fields.get(fieldNum);
        if (v instanceof Long) return (Long) v;
        return defaultVal;
    }

    // === Proto field writing (for RESPONSE) ===

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

    // === Main handler ===

    @Override
    public void handle(GameSession session, byte[] header, byte[] payload) throws Exception {
        // Parse all fields from the raw protobuf payload
        Map<Integer, Object> fields = parseProtoFields(payload);

        // Extract account info from 5.3.5 positions: field 9=account_uid, field 10=account_token
        String accountId = getFieldString(fields, 9);
        if (accountId.isEmpty()) {
            accountId = getFieldString(fields, 10); // fallback
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
            session.send(buildBannedRsp(session));
            return;
        }

        player.loadFromDatabase();
        session.setState(SessionState.WAITING_FOR_LOGIN);

        // v2.0.12: Smart multi-position response covering 4.6.0, 4.7.0, 5.0.0 proto positions.
        // NO key exchange — stay on DISPATCH_KEY. Set key_id=0 everywhere.
        session.send(buildMultiPositionTokenRsp(session));
    }

    /**
     * Build GetPlayerTokenRsp writing critical fields at ALL known LunaGC positions
     * where wire types are compatible, with smart conflict resolution.
     *
     * Field position reference:
     *
     *   uid (uint32/varint):
     *     v4.6=13*, v4.7=4, v5.0=8    (*conflict at 13 with v5.0 platform_type)
     *
     *   token (string):
     *     v4.6=14*, v4.7=2, v5.0=15*  (*conflict at 14 with v4.7 platform_type;
     *                                   *conflict at 15 with v4.6 platform_type)
     *
     *   account_uid (string):
     *     v4.6=3, v4.7=9, v5.0=6      (all string → safe to triple-write)
     *
     *   platform_type (uint32/varint):
     *     v4.6=15*, v4.7=14*, v5.0=13* (*conflicts: 15 vs token, 14 vs token, 13 vs uid)
     *
     *   security_cmd_buffer (bytes):
     *     v4.7=3, v5.0=4*             (*v5.0 pos 4 conflicts with v4.7 uid)
     *
     * CONFLICT RESOLUTION:
     *   - Field 2:  write token (v4.7, string) ✓
     *   - Field 3:  write account_uid (v4.6, string) + security_cmd_buffer (v4.7, bytes)
     *               both wire type 2 → safe ✓
     *   - Field 4:  write uid (v4.7, varint). Skip security_cmd_buffer at 4 (v5.0 conflict) ✓
     *   - Field 6:  write account_uid (v5.0, string) ✓
     *   - Field 8:  write uid (v5.0, varint) ✓
     *   - Field 9:  write account_uid (v4.7, string) ✓
     *   - Field 13: write platform_type (v5.0, varint). Skip uid at 13 (covered at 4,8) ✓
     *   - Field 14: write platform_type (v4.7, varint). Skip token at 14 (covered at 2,15) ✓
     *   - Field 15: write token (v5.0, string). Skip platform_type at 15 (covered at 13,14) ✓
     */
    private BasePacket buildMultiPositionTokenRsp(GameSession session) {
        var player = session.getPlayer();
        var account = session.getAccount();
        var token = account.getToken();
        int uid = player.getUid();
        String accountId = account.getId();

        String dummyRandKey = "CfO2d7eEYha5bJRXdCfoiemPNAtXDpyNTQ3ObeTt5a7SSHz6GAEO1WPiTQ7fR6OG8LqhVN3ZTxH9Bnkc09BnCxud+kn0+PiGv1PTOuWK0LkQQ1xmg89zA9IHS+OJd1yKT2BBmJf4sN61gi+WtT7aFwRlzku3kGCk6p2wiPo2enE7UwCFi/GiD4vq/m3hNZiKBjitAvheaqbSLjMpBax+c8HXoY5G09ap1PjEnUQPIK0xZRRQKpnrWcCyP4j8N3WwYYQGDW+OYOJjBvJdv+D6XSdEi+4IsZASYVpu9V8UZ570Cakbc+IjUm0UZJXghcR7izIjKtoNHf2Fmc26DEp1Jw==";
        String dummySign = "mMx/Klovbzq1QxQvVgm30nYhj0jDOykyo9aparyWRNz3ACxV/2gIdLpyM/SMerWMTcx26NapQ9HsKK7BRK7Yx+nMR0O83BkBlxfl+NEarYr6kj9lBKAxZYXTXFRYA4sRynvwa/MOPmGwYMNl6aVvMohhvrsTopsRvIuGFtnCVL2wBfbxcNnbVfP5k+DxPuQnxa/vi+ju8TogW2R+r0p9zQ5NJe1oaYe4xYbyhefFVv11FA/JQHwMHLEyrEdPqTzdN75CUmE09yLuAoeJzoJ1vwwjwfcH9dMDPxsewNJBGiylVHYf56kF4HypNkYNjtxbghgLBaHg0ZoeYHTOJ7YUTQ==";
        String ipStr = session.getAddress().getAddress().getHostAddress();

        try {
            java.io.ByteArrayOutputStream bos = new java.io.ByteArrayOutputStream();

            // === uid (uint32) — fields 4 (v4.7) + 8 (v5.0) ===
            writeVarintField(bos, 4, 0, uid);   // v4.7
            writeVarintField(bos, 8, 0, uid);   // v5.0

            // === token (string) — fields 2 (v4.7) + 15 (v5.0) ===
            // (skip field 14 — conflict with v4.7 platform_type varint)
            if (token != null && !token.isEmpty()) {
                writeStringField(bos, 2, token);   // v4.7
                writeStringField(bos, 15, token);  // v5.0
            }

            // === account_uid (string) — fields 3 (v4.6) + 6 (v5.0) + 9 (v4.7) ===
            // all wire type 2, safe to write at all three positions
            if (accountId != null && !accountId.isEmpty()) {
                writeStringField(bos, 3, accountId);   // v4.6
                writeStringField(bos, 6, accountId);   // v5.0
                writeStringField(bos, 9, accountId);   // v4.7
            }

            // === platform_type (uint32) — fields 13 (v5.0) + 14 (v4.7) ===
            // (skip field 15 — conflict with v5.0 token string)
            writeVarintField(bos, 13, 0, 3);  // v5.0
            writeVarintField(bos, 14, 0, 3);  // v4.7

            // === security_cmd_buffer (bytes) — field 3 (v4.7) ===
            // (also at field 3: v4.6 account_uid — both wire type 2, safe)
            // (skip field 4 — conflict with v4.7 uid varint)
            writeBytesField(bos, 3, Crypto.ENCRYPT_SEED_BUFFER);

            // === key_id (uint32) — fields 398 (v5.0) + 720 (v4.7) + 1411 (v4.6) ===
            // all varint, set to 0 = no key exchange
            writeVarintField(bos, 398, 0, 0);   // v5.0
            writeVarintField(bos, 720, 0, 0);   // v4.7
            writeVarintField(bos, 1411, 0, 0);  // v4.6

            // === country_code (string) — fields 254 (v4.7) + 1096 (v4.6) + 1269 (v5.0) ===
            writeStringField(bos, 254, "US");   // v4.7
            writeStringField(bos, 1096, "US");  // v4.6
            writeStringField(bos, 1269, "US");  // v5.0

            // === server_rand_key (string) — fields 68 (v5.0) + 910 (v4.7) + 1118 (v4.6) ===
            writeStringField(bos, 68, dummyRandKey);   // v5.0
            writeStringField(bos, 910, dummyRandKey);  // v4.7
            writeStringField(bos, 1118, dummyRandKey); // v4.6

            // === sign (string) — fields 414 (v4.7) + 477 (v4.6) + 1885 (v5.0) ===
            writeStringField(bos, 414, dummySign);   // v4.7
            writeStringField(bos, 477, dummySign);   // v4.6
            writeStringField(bos, 1885, dummySign);  // v5.0

            // === client_version_random_key (string) — fields 207 (v4.6) + 496 (v5.0) ===
            String versionKey = "c25-314dd05b0b5f";
            writeStringField(bos, 207, versionKey);  // v4.6
            writeStringField(bos, 496, versionKey);  // v5.0
            // v4.7 position 1402 is available, write it too
            writeStringField(bos, 1402, versionKey); // v4.7

            // === client_ip_str (string) — fields 703 (v4.6) + 1871 (v5.0) + 1950 (v4.7) ===
            if (ipStr != null && !ipStr.isEmpty()) {
                writeStringField(bos, 703, ipStr);   // v4.6
                writeStringField(bos, 1871, ipStr);  // v5.0
                writeStringField(bos, 1950, ipStr);  // v4.7
            }

            byte[] data = bos.toByteArray();
            Grasscutter.getLogger().info("[TokenReq] Multi-rsp size={} uid={} accountId={}",
                data.length, uid, accountId);

            BasePacket pkt = new BasePacket(PacketOpcodes.GetPlayerTokenRsp, true);
            pkt.setUseDispatchKey(true);
            pkt.setData(data);
            return pkt;
        } catch (Exception e) {
            Grasscutter.getLogger().error("[TokenReq] Failed to build multi-rsp: {}", e.getMessage(), e);
            return null;
        }
    }

    private BasePacket buildBannedRsp(GameSession session) {
        try {
            java.io.ByteArrayOutputStream bos = new java.io.ByteArrayOutputStream();
            // uid at fields 4 (v4.7) and 8 (v5.0)
            writeVarintField(bos, 4, 0, session.getPlayer().getUid());
            writeVarintField(bos, 8, 0, session.getPlayer().getUid());
            // country_code at all positions
            writeStringField(bos, 254, "US");
            writeStringField(bos, 1096, "US");
            writeStringField(bos, 1269, "US");

            byte[] data = bos.toByteArray();
            BasePacket pkt = new BasePacket(PacketOpcodes.GetPlayerTokenRsp, true);
            pkt.setUseDispatchKey(true);
            pkt.setData(data);
            return pkt;
        } catch (Exception e) {
            return null;
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