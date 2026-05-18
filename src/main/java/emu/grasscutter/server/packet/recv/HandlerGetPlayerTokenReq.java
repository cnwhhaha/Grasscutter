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
import emu.grasscutter.utils.helpers.ByteHelper;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.Signature;
import java.util.*;
import javax.crypto.Cipher;

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

        // Extract account info: 4.8.0 client sends account_uid at field 9, token at field 10
        String accountId = getFieldString(fields, 9);
        if (accountId.isEmpty()) {
            accountId = getFieldString(fields, 3); // fallback: LunaGC 5.0.0 field
        }
        String accountToken = getFieldString(fields, 10);
        if (accountToken.isEmpty()) {
            accountToken = getFieldString(fields, 4); // fallback
        }

        // Extract key exchange fields: 4.8.0 client sends key_id at 1226, client_rand_key at 450
        int keyId = (int) getFieldVarint(fields, 1226, 0);
        if (keyId == 0) keyId = (int) getFieldVarint(fields, 1485, 0); // LunaGC 5.0.0 fallback
        String clientRandKey = getFieldString(fields, 450);
        if (clientRandKey.isEmpty()) clientRandKey = getFieldString(fields, 94); // LunaGC fallback

        Grasscutter.getLogger().info(
            "[TokenReq] accountId='{}' tokenLen={} keyId={} clientRandKeyLen={} payloadLen={}",
            accountId, accountToken.length(), keyId, clientRandKey.length(), payload.length);

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

        // Send the token response
        if (keyId > 0 && !clientRandKey.isEmpty()) {
            // Key exchange requested by client
            sendTokenRspWithKeyExchange(session, keyId, clientRandKey);
        } else {
            // Simple response with dummy server_rand_key/sign
            session.send(buildRawTokenRsp(session, keyId, null, null, null));
        }
    }

    /**
     * Perform key exchange (RSA decrypt → XOR → RSA encrypt → sign)
     * with XOR fallback if RSA keys aren't available.
     */
    private void sendTokenRspWithKeyExchange(GameSession session, int keyId, String clientRandKeyB64) {
        var encryptSeed = session.getEncryptSeed();
        try {
            // Try full RSA key exchange
            var cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.DECRYPT_MODE, Crypto.CUR_SIGNING_KEY);
            var clientSeedEncrypted = Utils.base64Decode(clientRandKeyB64);
            var clientSeed = ByteBuffer.wrap(cipher.doFinal(clientSeedEncrypted)).getLong();
            var seedBytes = ByteBuffer.wrap(new byte[8]).putLong(encryptSeed ^ clientSeed).array();

            cipher.init(Cipher.ENCRYPT_MODE, Crypto.EncryptionKeys.get(keyId));
            var seedEncrypted = cipher.doFinal(seedBytes);

            var privateSignature = Signature.getInstance("SHA256withRSA");
            privateSignature.initSign(Crypto.CUR_SIGNING_KEY);
            privateSignature.update(seedBytes);

            String serverRandKey = Utils.base64Encode(seedEncrypted);
            String sign = Utils.base64Encode(privateSignature.sign());
            Grasscutter.getLogger().info("[TokenReq] Key exchange OK, sending encrypted seed");
            session.setUseSecretKey(true);
            session.send(buildRawTokenRsp(session, keyId, serverRandKey, sign, seedBytes));
        } catch (Exception e) {
            // RSA failed → XOR fallback
            Grasscutter.getLogger().warn("[TokenReq] RSA key exchange failed ({}), using XOR fallback", e.getMessage());
            try {
                var clientBytes = Utils.base64Decode(clientRandKeyB64);
                var seed = ByteHelper.longToBytes(encryptSeed);
                Crypto.xor(clientBytes, seed);
                String serverRandKey = Utils.base64Encode(clientBytes);
                var seedBytes = ByteHelper.longToBytes(encryptSeed);
                session.setUseSecretKey(true);
                session.send(buildRawTokenRsp(session, keyId, serverRandKey, "bm90aGluZyBoZXJl", seedBytes));
            } catch (Exception ex) {
                Grasscutter.getLogger().error("[TokenReq] XOR fallback also failed: {}", ex.getMessage());
                session.setUseSecretKey(true);
                session.send(buildRawTokenRsp(session, keyId, null, null, null));
            }
        }
    }

    /**
     * Build a raw protobuf-encoded GetPlayerTokenRsp using LunaGC 5.0.0 field numbers
     * (compatible with Genshin 4.8.0 client).
     *
     * Field mapping (LunaGC 5.0.0 GetPlayerTokenRsp proto):
     *   uid = 8 (uint32)
     *   token = 15 (string)
     *   account_uid = 6 (string)
     *   security_cmd_buffer = 4 (bytes)
     *   platform_type = 13 (uint32)
     *   country_code = 1269 (string)
     *   key_id = 398 (uint32)
     *   server_rand_key = 68 (string)
     *   sign = 1885 (string)
     *   client_version_random_key = 496 (string)
     *   client_ip_str = 1871 (string)
     */
    private BasePacket buildRawTokenRsp(GameSession session, int keyId,
                                         String serverRandKey, String sign, byte[] securitySeed) {
        var player = session.getPlayer();
        var token = session.getAccount().getToken();
        int uid = player.getUid();

        // Use dummy server_rand_key/sign if not provided (from LunaGC codebase)
        if (serverRandKey == null || serverRandKey.isEmpty()) {
            serverRandKey = "CfO2d7eEYha5bJRXdCfoiemPNAtXDpyNTQ3ObeTt5a7SSHz6GAEO1WPiTQ7fR6OG8LqhVN3ZTxH9Bnkc09BnCxud+kn0+PiGv1PTOuWK0LkQQ1xmg89zA9IHS+OJd1yKT2BBmJf4sN61gi+WtT7aFwRlzku3kGCk6p2wiPo2enE7UwCFi/GiD4vq/m3hNZiKBjitAvheaqbSLjMpBax+c8HXoY5G09ap1PjEnUQPIK0xZRRQKpnrWcCyP4j8N3WwYYQGDW+OYOJjBvJdv+D6XSdEi+4IsZASYVpu9V8UZ570Cakbc+IjUm0UZJXghcR7izIjKtoNHf2Fmc26DEp1Jw==";
        }
        if (sign == null || sign.isEmpty()) {
            sign = "mMx/Klovbzq1QxQvVgm30nYhj0jDOykyo9aparyWRNz3ACxV/2gIdLpyM/SMerWMTcx26NapQ9HsKK7BRK7Yx+nMR0O83BkBlxfl+NEarYr6kj9lBKAxZYXTXFRYA4sRynvwa/MOPmGwYMNl6aVvMohhvrsTopsRvIuGFtnCVL2wBfbxcNnbVfP5k+DxPuQnxa/vi+ju8TogW2R+r0p9zQ5NJe1oaYe4xYbyhefFVv11FA/JQHwMHLEyrEdPqTzdN75CUmE09yLuAoeJzoJ1vwwjwfcH9dMDPxsewNJBGiylVHYf56kF4HypNkYNjtxbghgLBaHg0ZoeYHTOJ7YUTQ==";
        }

        try {
            java.io.ByteArrayOutputStream bos = new java.io.ByteArrayOutputStream();

            // uid = 8 (uint32)
            writeVarintField(bos, 8, 0, uid);
            // account_uid = 6 (string)
            writeStringField(bos, 6, String.valueOf(uid));
            // token = 15 (string)
            writeStringField(bos, 15, token != null ? token : "");
            // security_cmd_buffer = 4 (bytes) — send actual XOR seed for 4.8.0 client
            byte[] cmdBuf = (securitySeed != null && securitySeed.length > 0)
                ? securitySeed : Crypto.ENCRYPT_SEED_BUFFER;
            writeBytesField(bos, 4, cmdBuf);
            // platform_type = 13 (uint32)
            writeVarintField(bos, 13, 0, 3);
            // country_code = 1269 (string)
            writeStringField(bos, 1269, "US");
            // key_id = 398 (uint32)
            writeVarintField(bos, 398, 0, keyId);
            // server_rand_key = 68 (string)
            writeStringField(bos, 68, serverRandKey);
            // sign = 1885 (string)
            writeStringField(bos, 1885, sign);
            // client_version_random_key = 496 (string)
            writeStringField(bos, 496, "c25-314dd05b0b5f");
            // client_ip_str = 1871 (string)
            writeStringField(bos, 1871, session.getAddress().getAddress().getHostAddress());

            byte[] data = bos.toByteArray();
            Grasscutter.getLogger().info("[TokenReq] Raw rsp size={} uid={} keyId={} firstBytes={}",
                data.length, uid, keyId, bytesToHex(data, Math.min(data.length, 40)));

            BasePacket pkt = new BasePacket(PacketOpcodes.GetPlayerTokenRsp, true);
            pkt.setUseDispatchKey(true);
            pkt.setData(data);
            return pkt;
        } catch (Exception e) {
            Grasscutter.getLogger().error("[TokenReq] Failed to build raw rsp: {}", e.getMessage(), e);
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
