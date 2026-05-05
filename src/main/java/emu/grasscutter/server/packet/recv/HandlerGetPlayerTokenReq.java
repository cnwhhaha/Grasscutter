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

@Opcodes(PacketOpcodes.GetPlayerTokenReq)
public class HandlerGetPlayerTokenReq extends PacketHandler {

    /**
     * Manually extract a string field from raw protobuf bytes.
     * Protobuf wire format: tag = (field_number << 3) | wire_type (2 for length-delimited)
     */
    private static String extractFieldString(byte[] data, int fieldNumber) {
        int tag = (fieldNumber << 3) | 2; // wire_type 2 = length-delimited
        for (int i = 0; i < data.length - 1; i++) {
            if ((data[i] & 0xFF) == tag) {
                int len = data[i + 1] & 0xFF;
                if (i + 1 + len < data.length) {
                    return new String(data, i + 2, len);
                }
            }
        }
        return "";
    }

    @Override
    public void handle(GameSession session, byte[] header, byte[] payload) throws Exception {
        // Proto mismatch: client sends UID in field 9, server proto expects field 10.
        // Manually extract UID from raw payload bytes.
        var accountId = extractFieldString(payload, 9);
        if (accountId.isEmpty()) {
            // Fallback: try field 10 (standard proto)
            accountId = extractFieldString(payload, 10);
        }

        Grasscutter.getLogger().info("[TokenReq] Extracted accountId='{}' from payload (len={})", accountId, payload.length);

        if (accountId.isEmpty()) {
            Grasscutter.getLogger().error("[TokenReq] Could not extract UID from payload!");
            session.close();
            return;
        }

        // Look up account by ID directly (skip token auth due to proto mismatch)
        var account = DispatchUtils.getAccountById(accountId);
        if (account == null) {
            Grasscutter.getLogger().warn("[TokenReq] No account found for id='{}', closing session", accountId);
            session.close();
            return;
        }

        // Set account
        session.setAccount(account);

        // Check if player object exists in server
        boolean kicked = false;
        var exists = Grasscutter.getGameServer().getPlayerByAccountId(accountId);
        if (exists != null) {
            var existsSession = exists.getSession();
            if (existsSession != session) {
                exists.onLogout();
                existsSession.close();
                Grasscutter.getLogger()
                        .warn("Player {} was kicked due to duplicated login", account.getUsername());
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

        // Call creation event.
        var event = new PlayerCreationEvent(session, Player.class);
        event.call();

        // Get player.
        var player = DatabaseHelper.getPlayerByAccount(account, event.getPlayerClass());

        if (player == null) {
            var nextPlayerUid =
                    DatabaseHelper.getNextPlayerId(session.getAccount().getReservedPlayerUid());
            player =
                    event.getPlayerClass().getDeclaredConstructor(GameSession.class).newInstance(session);
            DatabaseHelper.generatePlayerUid(player, nextPlayerUid);
        }

        session.setPlayer(player);

        // Checks if the player is banned
        if (session.getAccount().isBanned()) {
            session.setState(SessionState.ACCOUNT_BANNED);
            session.send(
                    new PacketGetPlayerTokenRsp(
                            session, 21, "FORBID_CHEATING_PLUGINS", session.getAccount().getBanEndTime()));
            return;
        }

        player.loadFromDatabase();

        // Set session state - DON'T switch to secret key, stay on DISPATCH_KEY
        // This avoids the broken RSA key exchange due to proto field mismatch
        // session.setUseSecretKey(true);  // DISABLED: keep using DISPATCH_KEY
        session.setState(SessionState.WAITING_FOR_LOGIN);

        // Send manually constructed GetPlayerTokenRsp with client-compatible field numbers
        // Client uses field 9 for account_uid → try field 8 for uid in response
        Grasscutter.getLogger().info("[TokenReq] Login accepted for '{}', sending raw token rsp", accountId);
        session.send(buildRawTokenRsp(session));
    }

    /**
     * Build a raw protobuf-encoded GetPlayerTokenRsp using client-compatible field numbers.
     * This bypasses the server's proto-generated classes which have wrong field numbers.
     */
    private BasePacket buildRawTokenRsp(GameSession session) {
        var player = session.getPlayer();
        var token = session.getAccount().getToken();
        int uid = player.getUid();

        // Raw protobuf encoder - we write field tags and values manually
        try {
            java.io.ByteArrayOutputStream bos = new java.io.ByteArrayOutputStream();
            
            // Field 8: uid (uint32) - try LunaGC 5.0.0 field mapping
            writeVarintField(bos, 8, 0, uid);
            // Field 6: account_uid (string) 
            writeStringField(bos, 6, String.valueOf(uid));
            // Field 2: token (string) - server proto has it at field 2
            writeStringField(bos, 2, token != null ? token : "");
            // Field 4: uid also at field 4 (server proto)
            writeVarintField(bos, 4, 0, uid);
            // Field 9: uid at field 9 (matching client request pattern)
            writeVarintField(bos, 9, 0, uid);
            // Field 15: token at field 15 (LunaGC 5.0.0)
            writeStringField(bos, 15, token != null ? token : "");
            // Field 398: key_id = 0 (no key exchange)
            writeVarintField(bos, 398, 0, 0);
            // Field 720: key_id = 0 (server proto)
            writeVarintField(bos, 720, 0, 0);
            
            byte[] data = bos.toByteArray();
            Grasscutter.getLogger().info("[TokenReq] Raw rsp size={} uid={} hex={}", 
                data.length, uid, bytesToHex(data, Math.min(data.length, 64)));
            
            BasePacket pkt = new BasePacket(PacketOpcodes.GetPlayerTokenRsp, true);
            pkt.setUseDispatchKey(true);
            pkt.setData(data);
            return pkt;
        } catch (Exception e) {
            Grasscutter.getLogger().error("[TokenReq] Failed to build raw rsp: {}", e.getMessage());
            return null;
        }
    }

    private static void writeVarintField(java.io.ByteArrayOutputStream bos, int fieldNum, int wireType, long value) throws java.io.IOException {
        int tag = (fieldNum << 3) | (wireType & 7);
        writeVarint(bos, tag);
        writeVarint(bos, value);
    }

    private static void writeStringField(java.io.ByteArrayOutputStream bos, int fieldNum, String value) throws java.io.IOException {
        int tag = (fieldNum << 3) | 2; // wire_type 2 = length-delimited
        byte[] strBytes = value.getBytes(java.nio.charset.StandardCharsets.UTF_8);
        writeVarint(bos, tag);
        writeVarint(bos, strBytes.length);
        bos.write(strBytes);
    }

    private static void writeVarint(java.io.ByteArrayOutputStream bos, long value) throws java.io.IOException {
        while (true) {
            int bits = (int)(value & 0x7F);
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
