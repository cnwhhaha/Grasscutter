package emu.grasscutter.server.packet.recv;

import static emu.grasscutter.config.Configuration.GAME_OPTIONS;

import emu.grasscutter.Grasscutter;
import emu.grasscutter.data.GameData;
import emu.grasscutter.game.avatar.Avatar;
import emu.grasscutter.game.player.Player;
import emu.grasscutter.net.packet.*;
import emu.grasscutter.net.proto.PlayerLoginReqOuterClass.PlayerLoginReq;
import emu.grasscutter.server.game.GameSession;
import emu.grasscutter.server.packet.send.PacketPlayerLoginRsp;

@Opcodes(PacketOpcodes.PlayerLoginReq) // Sends initial data packets
public class HandlerPlayerLoginReq extends PacketHandler {

    @Override
    public void handle(GameSession session, byte[] header, byte[] payload) throws Exception {
        // Check
        if (session.getAccount() == null) {
            session.close();
            return;
        }

        // Parse request
        PlayerLoginReq req = PlayerLoginReq.parseFrom(payload);

        Grasscutter.getLogger()
                .info(
                        "PlayerLoginReq tokenMatch={} loginRand={} expectedSeed={} targetUid={} accountType={} platformType={} channelId={} countryCode={} checksumClientVersion={} extraBinDataLen={} securityCmdReplyLen={}",
                        req.getToken().equals(session.getAccount().getToken()),
                        req.getLoginRand(),
                        session.getEncryptSeed(),
                        req.getTargetUid(),
                        req.getAccountType(),
                        req.getPlatformType(),
                        req.getChannelId(),
                        req.getCountryCode(),
                        req.getChecksumClientVersion(),
                        req.getExtraBinData().size(),
                        req.getSecurityCmdReply().size());

        // Authenticate session
        if (!req.getToken().equals(session.getAccount().getToken())) {
            session.close();
            return;
        }

        // Load character from db
        Player player = session.getPlayer();

        // Show opening cutscene if player has no avatars
        if (player.getAvatars().getAvatarCount() == 0) {
            // Pick character (Disabled due to opcode issue)
            // session.setState(SessionState.PICKING_CHARACTER);
            // session.send(new BasePacket(PacketOpcodes.DoSetPlayerBornDataNotify));

            // Hardcode default mc and nickname
            int avatarId = 10000007;
            Avatar mainCharacter = new Avatar(avatarId);

            // Check if the default Anemo skill should be given.
            if (!GAME_OPTIONS.questing.enabled) {
                mainCharacter.setSkillDepotData(GameData.getAvatarSkillDepotDataMap().get(704));
            }

            // Manually handle adding to team
            player.addAvatar(mainCharacter, false);
            player.setMainCharacterId(avatarId);
            player.setHeadImage(avatarId);
            player
                    .getTeamManager()
                    .getCurrentSinglePlayerTeamInfo()
                    .getAvatars()
                    .add(mainCharacter.getAvatarId());
            player.save(); // TODO save player team in different object

            // Login done
            session.getPlayer().onLogin();
        } else {
            // Login done
            session.getPlayer().onLogin();
        }

        // Final packet to tell client logging in is done
        session.send(new PacketPlayerLoginRsp(session));

        Grasscutter.getLogger()
                .info(
                        "PlayerLoginRsp sent uid={} loginRand={} stateBeforeActive={}",
                        session.getPlayer().getUid(),
                        session.getEncryptSeed(),
                        session.getState());
    }
}
