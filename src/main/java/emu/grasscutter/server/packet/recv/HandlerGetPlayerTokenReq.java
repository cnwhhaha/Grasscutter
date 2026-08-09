package emu.grasscutter.server.packet.recv;

import static emu.grasscutter.config.Configuration.ACCOUNT;

import java.nio.ByteBuffer;
import java.security.Signature;
import javax.crypto.Cipher;

import emu.grasscutter.DebugConstants;
import emu.grasscutter.Grasscutter;
import emu.grasscutter.database.DatabaseHelper;
import emu.grasscutter.game.player.Player;
import emu.grasscutter.net.packet.Opcodes;
import emu.grasscutter.net.packet.PacketHandler;
import emu.grasscutter.net.packet.PacketOpcodes;
import emu.grasscutter.net.proto.GetPlayerTokenReqOuterClass.GetPlayerTokenReq;
import emu.grasscutter.server.event.game.PlayerCreationEvent;
import emu.grasscutter.server.game.GameSession;
import emu.grasscutter.server.game.GameSession.SessionState;
import emu.grasscutter.server.packet.send.PacketGetPlayerTokenRsp;
import emu.grasscutter.utils.DispatchUtils;
import emu.grasscutter.utils.Utils;
import emu.grasscutter.utils.Crypto;

@Opcodes(PacketOpcodes.GetPlayerTokenReq)
public class HandlerGetPlayerTokenReq extends PacketHandler {

    /**
     * Extract field 450 (client_rand_key) and field 1226 (key_id) directly from
     * the parsed GetPlayerTokenReq proto message (fields confirmed against the
     * 4.8.0 client dump in `4.8proto-work/4.8.proto`, message CLJNMLBEIHN).
     */
    private static KeyExchangeData extractKeyExchangeData(GetPlayerTokenReq req) {
        String clientRandKey = req.getField450ClientRandKey();
        int keyId = req.getField1226KeyId();
        return new KeyExchangeData(clientRandKey.isBlank() ? null : clientRandKey, keyId);
    }

    private static class KeyExchangeData {
        String clientRandKey;
        int keyId;

        KeyExchangeData(String clientRandKey, int keyId) {
            this.clientRandKey = clientRandKey;
            this.keyId = keyId;
        }
    }

    @Override
    public void handle(GameSession session, byte[] header, byte[] payload) throws Exception {
        var req = GetPlayerTokenReq.parseFrom(payload);

        var accountUid = req.getAccountUid().toStringUtf8();
        if (accountUid.isBlank()) {
            accountUid = req.getAccountUid().toString().replace("\"", "");
        }
        var field9Uid = req.getField9Uid();
        var field10Material = req.getField10Material();
        var field10MaterialUtf8 = field10Material.toStringUtf8();

        Grasscutter.getLogger()
                .info(
                        "GetPlayerTokenReq accountUid={} field9Uid={} accountType={} platformType={} channelId={} isGuest={} field10Utf8={} field10Len={}",
                        accountUid,
                        field9Uid,
                        req.getAccountType(),
                        req.getPlatformType(),
                        req.getChannelId(),
                        req.getIsGuest(),
                        field10MaterialUtf8,
                        field10Material.size());

        var accountId = !field9Uid.isBlank() ? field9Uid : accountUid;
        var accountToken = field10MaterialUtf8;
        var account = DispatchUtils.authenticate(accountId, accountToken);

        if (account == null && !DebugConstants.ACCEPT_CLIENT_TOKEN) {
            session.close();
            return;
        } else if (account == null) {
            account = DispatchUtils.getAccountById(accountId);
            if (account == null) {
                session.close();
                return;
            }
        }

        session.setAccount(account);

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

        if (!kicked
                && ACCOUNT.maxPlayer > -1
                && Grasscutter.getGameServer().getPlayers().size() >= ACCOUNT.maxPlayer) {
            session.close();
            return;
        }

        var event = new PlayerCreationEvent(session, Player.class);
        event.call();

        var player = DatabaseHelper.getPlayerByAccount(account, event.getPlayerClass());
        if (player == null) {
            var nextPlayerUid =
                    DatabaseHelper.getNextPlayerId(session.getAccount().getReservedPlayerUid());
            player = event.getPlayerClass().getDeclaredConstructor(GameSession.class).newInstance(session);
            DatabaseHelper.generatePlayerUid(player, nextPlayerUid);
        }

        session.setPlayer(player);

        if (session.getAccount().isBanned()) {
            session.setState(SessionState.ACCOUNT_BANNED);
            session.send(
                    new PacketGetPlayerTokenRsp(
                            session, 21, "FORBID_CHEATING_PLUGINS", session.getAccount().getBanEndTime()));
            return;
        }

        player.loadFromDatabase();

        session.setState(SessionState.WAITING_FOR_LOGIN);

        // RSA Key Exchange for 4.8.0
        String serverRandKey = null;
        String sign = null;

        try {
            // Extract client_rand_key and key_id from the parsed proto message
            var keyExchangeData = extractKeyExchangeData(req);
            Grasscutter.getLogger().info(
                    "Key exchange: keyId={}, clientRandKeyLen={}",
                    keyExchangeData.keyId,
                    keyExchangeData.clientRandKey != null ? keyExchangeData.clientRandKey.length() : 0);

            if (keyExchangeData.keyId > 0 && keyExchangeData.clientRandKey != null) {
                var encryptSeed = session.getEncryptSeed();

                // Decrypt client_rand_key using CUR_SIGNING_KEY
                var cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
                cipher.init(Cipher.DECRYPT_MODE, Crypto.CUR_SIGNING_KEY);

                var clientSeedEncrypted = Utils.base64Decode(keyExchangeData.clientRandKey);
                var clientSeed = ByteBuffer.wrap(cipher.doFinal(clientSeedEncrypted)).getLong();

                Grasscutter.getLogger().info(
                        "Key exchange: encryptSeed={}, clientSeed={}",
                        encryptSeed,
                        clientSeed);

                // Calculate seedBytes = encryptSeed ^ clientSeed
                var seedBytes = ByteBuffer.wrap(new byte[8]).putLong(encryptSeed ^ clientSeed).array();

                // Encrypt seedBytes using EncryptionKeys[keyId] → server_rand_key
                cipher.init(Cipher.ENCRYPT_MODE, Crypto.EncryptionKeys.get(keyExchangeData.keyId));
                var seedEncrypted = cipher.doFinal(seedBytes);
                serverRandKey = Utils.base64Encode(seedEncrypted);

                // Sign seedBytes using CUR_SIGNING_KEY → sign
                var privateSignature = Signature.getInstance("SHA256withRSA");
                privateSignature.initSign(Crypto.CUR_SIGNING_KEY);
                privateSignature.update(seedBytes);
                sign = Utils.base64Encode(privateSignature.sign());

                Grasscutter.getLogger().info(
                        "Key exchange success: serverRandKeyLen={}, signLen={}",
                        serverRandKey.length(),
                        sign.length());
            }
        } catch (Exception e) {
            Grasscutter.getLogger().warn("Key exchange failed, using fallback", e);
            // Fallback for UA Patch users (from 4.0)
            var keyExchangeData = extractKeyExchangeData(req);
            if (keyExchangeData.clientRandKey != null) {
                var encryptSeed = session.getEncryptSeed();
                var clientBytes = Utils.base64Decode(keyExchangeData.clientRandKey);
                var seed = ByteBuffer.wrap(new byte[8]).putLong(encryptSeed).array();
                Crypto.xor(clientBytes, seed);
                serverRandKey = Utils.base64Encode(clientBytes);
                sign = "bm90aGluZyBoZXJl";
            }
        }

        // Send response
        session.send(new PacketGetPlayerTokenRsp(session, req, serverRandKey, sign));
        session.setUseSecretKey(true);

        Grasscutter.getLogger()
                .info(
                        "GetPlayerTokenRsp sent uid={} seed={} platformType={} channelId={} serverRandKey={} sign={}",
                        session.getPlayer().getUid(),
                        session.getEncryptSeed(),
                        req.getPlatformType(),
                        req.getChannelId(),
                        serverRandKey != null ? serverRandKey.substring(0, Math.min(20, serverRandKey.length())) : "null",
                        sign != null ? sign.substring(0, Math.min(20, sign.length())) : "null");
    }
}