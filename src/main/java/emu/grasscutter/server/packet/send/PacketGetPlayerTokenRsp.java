package emu.grasscutter.server.packet.send;

import java.io.ByteArrayOutputStream;
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

    private static void writeVarint(ByteArrayOutputStream out, long value) {
        long current = value;
        while ((current & ~0x7FL) != 0) {
            out.write((int) ((current & 0x7F) | 0x80));
            current >>>= 7;
        }
        out.write((int) current);
    }

    private static void writeTag(ByteArrayOutputStream out, int field, int wireType) {
        writeVarint(out, ((long) field << 3) | wireType);
    }

    private static void writeString(ByteArrayOutputStream out, int field, String value) {
        if (value == null || value.isBlank()) {
            return;
        }

        var bytes = value.getBytes(java.nio.charset.StandardCharsets.UTF_8);
        writeTag(out, field, 2);
        writeVarint(out, bytes.length);
        out.writeBytes(bytes);
    }

    private static void writeBytes(ByteArrayOutputStream out, int field, byte[] value) {
        if (value == null || value.length == 0) {
            return;
        }

        writeTag(out, field, 2);
        writeVarint(out, value.length);
        out.writeBytes(value);
    }

    private static void writeUInt32(ByteArrayOutputStream out, int field, long value) {
        if (value == 0) {
            return;
        }

        writeTag(out, field, 0);
        writeVarint(out, value & 0xFFFFFFFFL);
    }

    private static void writeUInt64(ByteArrayOutputStream out, int field, long value) {
        if (value == 0) {
            return;
        }

        writeTag(out, field, 0);
        writeVarint(out, value);
    }

    private static void writeBool(ByteArrayOutputStream out, int field, boolean value) {
        if (!value) {
            return;
        }

        writeTag(out, field, 0);
        writeVarint(out, 1);
    }

    private static byte[] buildRawTokenRsp(GameSession session, GetPlayerTokenReq req) {
        var out = new ByteArrayOutputStream(256);

        writeUInt32(out, 3, session.getPlayer().getUid());
        writeString(out, 4, session.getAccount().getToken());
        writeUInt32(out, 6, req.getAccountType());
        writeBool(out, 8, session.getPlayer().getAvatars().getAvatarCount() > 0);
        writeUInt32(out, 10, 0);
        writeBytes(out, 12, Crypto.ENCRYPT_SEED_BUFFER);
        writeUInt64(out, 13, resolvePlatformType(req));
        writeUInt32(out, 16, resolveChannelId(req));
        writeString(out, 22, DEFAULT_CPS);
        writeUInt32(out, 23, 1);

        var address = session.getAddress();
        if (address != null && address.getAddress() != null) {
            writeString(out, 24, address.getAddress().getHostAddress());
        }

        return out.toByteArray();
    }

    public PacketGetPlayerTokenRsp(GameSession session, GetPlayerTokenReq req) {
        super(PacketOpcodes.GetPlayerTokenRsp, true);

        this.setUseDispatchKey(true);

        this.setData(buildRawTokenRsp(session, req));
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
