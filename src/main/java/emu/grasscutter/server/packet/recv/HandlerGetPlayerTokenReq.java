package emu.grasscutter.server.packet.recv;

import static emu.grasscutter.config.Configuration.ACCOUNT;

import com.google.protobuf.ByteString;
import emu.grasscutter.*;
import emu.grasscutter.database.DatabaseHelper;
import emu.grasscutter.game.player.Player;
import emu.grasscutter.net.packet.*;
import emu.grasscutter.net.proto.GetPlayerTokenRspOuterClass.GetPlayerTokenRsp;
import emu.grasscutter.server.event.game.PlayerCreationEvent;
import emu.grasscutter.server.game.GameSession;
import emu.grasscutter.server.game.GameSession.SessionState;
import emu.grasscutter.utils.*;
import java.nio.charset.StandardCharsets;
import java.util.*;

/**
 * v2.0.11: Clean proto handler for Genshin 4.8.0 client.
 *
 * The 4.8.0 client uses its own unique proto field numbers that are different
 * from 4.6.0, 4.7.0, and 5.0.0. The previous v2.0.10 multi-position approach
 * created INVALID protobuf due to type conflicts at overlapping field numbers
 * (fields 2, 3, 4, 13, 14, 15 have string vs varint vs bytes conflicts).
 *
 * v2.0.11 strategy:
 *   For REQUESTS: raw proto parser extracts from 4.8.0 positions (same as v2.0.10).
 *   For RESPONSES: build using the generated GetPlayerTokenRsp proto class
 *   (4.7.0 field numbers), which is CLEAN protobuf. Evidence that this matches
 *   4.8.0: field 9 (account_uid) is the same position in both 4.8.0 client's
 *   GetPlayerTokenReq and 4.7.0 server's GetPlayerTokenRsp.
 *
 *   Additionally, the security_cmd_buffer (Crypto.ENCRYPT_SEED_BUFFER) is included
 *   so the client can derive encryption keys correctly.
 *
 * Known 4.8.0 request fields (verified from capture):
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
 *   field 1419: string      ("csc" = country/channel code)
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

        // Extract account info from 4.8.0 positions: field 9=account_uid, field 10=account_token
        String accountId = getFieldString(fields, 9);
        if (accountId.isEmpty()) {
            accountId = getFieldString(fields, 10); // fallback: some captures show uid at 10
        }
        String accountToken = getFieldString(fields, 10);
        if (accountToken.isEmpty()) {
            accountToken = getFieldString(fields, 14); // 4.6.0 fallback
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

        // v2.0.11: NO key exchange. Stay on DISPATCH_KEY.
        // Use CLEAN protobuf via generated proto class (4.7.0 field numbers).
        // Includes security_cmd_buffer with ENCRYPT_SEED_BUFFER.
        session.send(buildCleanTokenRsp(session));
    }

    /**
     * Build a CLEAN GetPlayerTokenRsp using the generated proto class.
     * Uses 4.7.0 field numbers which produce valid, non-conflicting protobuf.
     *
     * Field mapping (from GetPlayerTokenRsp.proto, 4.7.0):
     *   uid=4, token=2, security_cmd_buffer=3, account_uid=9,
     *   platform_type=14, country_code=254, sign=414, key_id=720,
     *   server_rand_key=910, client_version_random_key=1402, client_ip_str=1950
     */
    private BasePacket buildCleanTokenRsp(GameSession session) {
        var player = session.getPlayer();
        var account = session.getAccount();

        GetPlayerTokenRsp p = GetPlayerTokenRsp.newBuilder()
                .setUid(player.getUid())
                .setToken(account.getToken())
                .setAccountUid(account.getId())
                .setPlatformType(3)  // 3 = PC
                .setCountryCode("US")
                .setKeyId(0)  // key_id=0 → no key exchange, stay on DISPATCH_KEY
                .setSecurityCmdBuffer(ByteString.copyFrom(Crypto.ENCRYPT_SEED_BUFFER))
                .setClientVersionRandomKey("c25-314dd05b0b5f")
                .setClientIpStr(session.getAddress().getAddress().getHostAddress())
                .setServerRandKey(
                    "CfO2d7eEYha5bJRXdCfoiemPNAtXDpyNTQ3ObeTt5a7SSHz6GAEO1WPiTQ7fR6OG8LqhVN3ZTxH9Bnkc09BnCxud+kn0+PiGv1PTOuWK0LkQQ1xmg89zA9IHS+OJd1yKT2BBmJf4sN61gi+WtT7aFwRlzku3kGCk6p2wiPo2enE7UwCFi/GiD4vq/m3hNZiKBjitAvheaqbSLjMpBax+c8HXoY5G09ap1PjEnUQPIK0xZRRQKpnrWcCyP4j8N3WwYYQGDW+OYOJjBvJdv+D6XSdEi+4IsZASYVpu9V8UZ570Cakbc+IjUm0UZJXghcR7izIjKtoNHf2Fmc26DEp1Jw==")
                .setSign(
                    "mMx/Klovbzq1QxQvVgm30nYhj0jDOykyo9aparyWRNz3ACxV/2gIdLpyM/SMerWMTcx26NapQ9HsKK7BRK7Yx+nMR0O83BkBlxfl+NEarYr6kj9lBKAxZYXTXFRYA4sRynvwa/MOPmGwYMNl6aVvMohhvrsTopsRvIuGFtnCVL2wBfbxcNnbVfP5k+DxPuQnxa/vi+ju8TogW2R+r0p9zQ5NJe1oaYe4xYbyhefFVv11FA/JQHwMHLEyrEdPqTzdN75CUmE09yLuAoeJzoJ1vwwjwfcH9dMDPxsewNJBGiylVHYf56kF4HypNkYNjtxbghgLBaHg0ZoeYHTOJ7YUTQ==")
                .build();

        byte[] data = p.toByteArray();
        Grasscutter.getLogger().info("[TokenReq] Clean rsp size={} uid={} accountId={}",
            data.length, player.getUid(), account.getId());

        BasePacket pkt = new BasePacket(PacketOpcodes.GetPlayerTokenRsp, true);
        pkt.setUseDispatchKey(true);
        pkt.setData(data);
        return pkt;
    }

    /** Build response for banned accounts. */
    private BasePacket buildBannedRsp(GameSession session) {
        var player = session.getPlayer();
        var account = session.getAccount();

        GetPlayerTokenRsp p = GetPlayerTokenRsp.newBuilder()
                .setUid(player.getUid())
                .setCountryCode("US")
                .build();

        BasePacket pkt = new BasePacket(PacketOpcodes.GetPlayerTokenRsp, true);
        pkt.setUseDispatchKey(true);
        pkt.setData(p.toByteArray());
        return pkt;
    }

    private static String bytesToHex(byte[] bytes, int maxLen) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < Math.min(bytes.length, maxLen); i++) {
            sb.append(String.format("%02X ", bytes[i]));
        }
        return sb.toString().trim();
    }
}
