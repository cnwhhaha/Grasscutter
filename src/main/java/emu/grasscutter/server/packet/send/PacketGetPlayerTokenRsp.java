package emu.grasscutter.server.packet.send;

import com.google.protobuf.ByteString;
import emu.grasscutter.net.packet.*;
import emu.grasscutter.net.proto.GetPlayerTokenReqOuterClass.GetPlayerTokenReq;
import emu.grasscutter.net.proto.GetPlayerTokenRspOuterClass.GetPlayerTokenRsp;
import emu.grasscutter.server.game.GameSession;
import emu.grasscutter.utils.Crypto;

public class PacketGetPlayerTokenRsp extends BasePacket {
    private static final String DEFAULT_COUNTRY_CODE = "US";
    private static final String DEFAULT_CPS = "mihoyo";

    private static long resolvePlatformType(GetPlayerTokenReq req) {
        return req.getPlatformType() > 0 ? req.getPlatformType() : 3;
    }

    private static int resolveChannelId(GetPlayerTokenReq req) {
        return req.getChannelId() > 0 ? req.getChannelId() : 1;
    }

    public PacketGetPlayerTokenRsp(GameSession session, GetPlayerTokenReq req) {
        super(PacketOpcodes.GetPlayerTokenRsp, true);

        this.setUseDispatchKey(true);

        GetPlayerTokenRsp p =
                GetPlayerTokenRsp.newBuilder()
                        .setPlayerUid(session.getPlayer().getUid())
                        .setAccountToken(session.getAccount().getToken())
                        .setAccountType((int) req.getAccountType())
                        .setIsProficientPlayer(session.getPlayer().getAvatars().getAvatarCount() > 0)
                        .setGmUid(0)
                        .setSecretKey(session.getEncryptSeed())
                        .setSecretKeyBuffer(ByteString.copyFrom(Crypto.ENCRYPT_SEED_BUFFER))
                        .setPlatformType(resolvePlatformType(req))
                        .setChannelId(resolveChannelId(req))
                        .setCountryCode(DEFAULT_COUNTRY_CODE)
                        .setUnk1(DEFAULT_CPS)
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
                        .setCountryCode(DEFAULT_COUNTRY_CODE)
                        .setUnk1(DEFAULT_CPS)
                        .setUnk3(1)
                        .setClientIp(session.getAddress().getAddress().getHostAddress())
                        .build();

        this.setData(p.toByteArray());
    }
}
