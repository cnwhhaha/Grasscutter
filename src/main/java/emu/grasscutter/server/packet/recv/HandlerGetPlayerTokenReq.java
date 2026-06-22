package emu.grasscutter.server.packet.recv;

import static emu.grasscutter.config.Configuration.ACCOUNT;

import com.google.protobuf.ByteString;
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

@Opcodes(PacketOpcodes.GetPlayerTokenReq)
public class HandlerGetPlayerTokenReq extends PacketHandler {
    private static String toHex(ByteString data) {
        var bytes = data.toByteArray();
        var builder = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            builder.append(String.format("%02x", b));
        }
        return builder.toString();
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
                        "GetPlayerTokenReq accountUid={} field9Uid={} accountType={} platformType={} channelId={} isGuest={} field10Utf8={} field10RawHex={} field10Len={}",
                        accountUid,
                        field9Uid,
                        req.getAccountType(),
                        req.getPlatformType(),
                        req.getChannelId(),
                        req.getIsGuest(),
                        field10MaterialUtf8,
                        toHex(field10Material),
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
        session.send(new PacketGetPlayerTokenRsp(session, req));
        session.setUseSecretKey(true);

        Grasscutter.getLogger()
                .info(
                        "GetPlayerTokenRsp sent uid={} seed={} platformType={} channelId={} state={}",
                        session.getPlayer().getUid(),
                        session.getEncryptSeed(),
                        req.getPlatformType(),
                        req.getChannelId(),
                        session.getState());
    }
}
