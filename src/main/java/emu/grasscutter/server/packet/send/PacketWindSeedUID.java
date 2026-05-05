package emu.grasscutter.server.packet.send;

import com.google.protobuf.ByteString;
import emu.grasscutter.net.packet.BasePacket;
import emu.grasscutter.net.packet.PacketOpcodes;
import emu.grasscutter.net.proto.WindSeedType1NotifyOuterClass.WindSeedType1Notify;
import emu.grasscutter.utils.FileUtils;

public class PacketWindSeedUID extends BasePacket {
    public PacketWindSeedUID() {
        super(PacketOpcodes.WindSeedType1Notify);
        byte[] data = FileUtils.readResource("/lua/UID.luac");
        WindSeedType1Notify proto =
                WindSeedType1Notify.newBuilder().setPayload(ByteString.copyFrom(data)).build();

        this.setData(proto);
    }
}
