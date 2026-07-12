package emu.grasscutter.server.packet.send;

import emu.grasscutter.net.proto.GetPlayerTokenRspOuterClass.GetPlayerTokenRsp;
import emu.grasscutter.utils.Utils;

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import emu.grasscutter.net.packet.*;
import emu.grasscutter.net.proto.GetPlayerTokenReqOuterClass.GetPlayerTokenReq;
import emu.grasscutter.server.game.GameSession;
import emu.grasscutter.utils.Crypto;

public class PacketGetPlayerTokenRsp_4_8_attempt extends BasePacket {
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

    /**
     * Build GetPlayerTokenRsp for 4.8.0 client with correct field mapping from IDA analysis.
     * Field mapping based on sub_14BEBF530 (Table 2) analysis.
     */
    private static byte[] buildRawTokenRsp_4_8(
            GameSession session,
            GetPlayerTokenReq req,
            String serverRandKey,
            String sign) {
        var out = new ByteArrayOutputStream(1024);

        // Field 1: retcode (varint) - 0 = success
        writeUInt32(out, 1, 0);

        // Field 2: secret_key_seed (varint) - encrypt seed
        writeUInt64(out, 2, session.getEncryptSeed());

        // Field 3: sub-message (len-delim) - complex structure
        // Placeholder - needs proper sub-message implementation
        writeTag(out, 3, 2);
        writeVarint(out, 0);

        // Field 4: account_type (varint) - 4.8 uses varint, not string
        writeUInt32(out, 4, req.getAccountType());

        // Field 5: ??? (varint) - unknown, placeholder
        writeUInt32(out, 5, 0);

        // Field 6: ??? (varint) - unknown, placeholder
        writeUInt32(out, 6, 0);

        // Field 7: ??? (varint) - unknown, placeholder
        writeUInt32(out, 7, 0);

        // Field 8: ??? (varint) - unknown, placeholder
        writeUInt32(out, 8, 0);

        // Field 9: server_rand_key (bytes) - RSA encrypted seedBytes
        if (serverRandKey != null && !serverRandKey.isBlank()) {
            byte[] serverRandKeyBytes = Utils.base64Decode(serverRandKey);
            writeBytes(out, 9, serverRandKeyBytes);
        }

        // Field 10: ??? (varint) - unknown, placeholder
        writeUInt32(out, 10, 0);

        // Field 11: ??? (varint) - unknown, placeholder
        writeUInt32(out, 11, 0);

        // Field 12: ??? (varint) - unknown, placeholder
        writeUInt32(out, 12, 0);

        // Field 13: platform_type (varint) - confirmed match
        writeUInt64(out, 13, resolvePlatformType(req));

        // Field 14: ??? (varint) - unknown, placeholder
        writeUInt32(out, 14, 0);

        // Field 15: ??? (varint) - unknown, placeholder
        writeUInt32(out, 15, 0);

        // Field 16: sub-message (len-delim) - complex structure
        // Placeholder - needs proper sub-message implementation
        writeTag(out, 16, 2);
        writeVarint(out, 0);

        // Field 17: ??? (varint) - unknown, placeholder
        writeUInt32(out, 17, 0);

        // Field 19: ??? (varint) - NOT string! - wire type conflict fixed
        writeUInt32(out, 19, 0);

        // Field 22: sub-message (len-delim) - complex structure
        // Placeholder - needs proper sub-message implementation
        writeTag(out, 22, 2);
        writeVarint(out, 0);

        // Field 24: ??? (varint) - unknown, placeholder
        writeUInt32(out, 24, 0);

        // Field 25: ??? (varint) - unknown, placeholder
        writeUInt32(out, 25, 0);

        // Field 26: sign (bytes) - RSA signature of seedBytes
        if (sign != null && !sign.isBlank()) {
            byte[] signBytes = Utils.base64Decode(sign);
            writeBytes(out, 26, signBytes);
        }

        // Field 27: ??? (varint) - unknown, placeholder
        writeUInt32(out, 27, 0);

        // Field 28: ??? (varint) - unknown, placeholder
        writeUInt32(out, 28, 0);

        // Field 29: ??? (varint) - unknown, placeholder
        writeUInt32(out, 29, 0);

        return out.toByteArray();
    }

    public PacketGetPlayerTokenRsp_4_8_attempt(GameSession session, GetPlayerTokenReq req, String serverRandKey, String sign) {
        super(PacketOpcodes.GetPlayerTokenRsp, true);

        this.setUseDispatchKey(true);

        this.setData(buildRawTokenRsp_4_8(session, req, serverRandKey, sign));
    }

    // Fallback constructor for error cases (uses old proto)
    public PacketGetPlayerTokenRsp_4_8_attempt(GameSession session, int retcode, String msg, int blackEndTime) {
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