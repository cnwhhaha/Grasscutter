package emu.grasscutter.server.packet.send;

import com.google.protobuf.ByteString;
import emu.grasscutter.net.packet.*;
import emu.grasscutter.net.proto.GetPlayerTokenReqOuterClass.GetPlayerTokenReq;
import emu.grasscutter.net.proto.GetPlayerTokenRspOuterClass.GetPlayerTokenRsp;
import emu.grasscutter.server.game.GameSession;
import emu.grasscutter.utils.Crypto;

public class PacketGetPlayerTokenRsp extends BasePacket {

    public PacketGetPlayerTokenRsp(GameSession session, GetPlayerTokenReq req) {
        super(PacketOpcodes.GetPlayerTokenRsp, true);

        this.setUseDispatchKey(true);

        GetPlayerTokenRsp p =
                GetPlayerTokenRsp.newBuilder()
                        .setPlayerUid(session.getPlayer().getUid())
                        .setAccountToken(session.getAccount().getToken())
                        .setAccountType((int) req.getAccountType())
                        .setIsProficientPlayer(session.getPlayer().getAvatars().getAvatarCount() > 0)
                        .setSecretKey(session.getEncryptSeed())
                        .setSecretKeyBuffer(ByteString.copyFrom(Crypto.ENCRYPT_SEED_BUFFER))
                        .setPlatformType(req.getPlatformType() > 0 ? req.getPlatformType() : 3)
                        .setChannelId((int) req.getSchannelId())
                        .setCountryCode("US")
                        .setUnk1("csc")
                        .setUnk3(1)
                        .setClientIp(session.getAddress().getAddress().getHostAddress())
                        .build();

        this.setData(p.toByteArray());
    }

    public PacketGetPlayerTokenRsp(GameSession session, int retcode, String msg, int blackEndTime) {
        super(PacketOpcodes.GetPlayerTokenRsp, true);

        this.setUseDispatchKey(true);

        GetPlayerTokenRsp p =
                GetPlayerTokenRsp.newBuilder()
                        .setPlayerUid(session.getPlayer().getUid())
                        .setCountryCode("US")
                        .setClientIp(session.getAddress().getAddress().getHostAddress())
                        .build();

        this.setData(p.toByteArray());
    }
}
