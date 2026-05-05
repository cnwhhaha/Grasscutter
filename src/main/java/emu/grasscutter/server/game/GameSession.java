package emu.grasscutter.server.game;

import static emu.grasscutter.config.Configuration.*;
import static emu.grasscutter.utils.lang.Language.translate;

import emu.grasscutter.Grasscutter;
import emu.grasscutter.Grasscutter.ServerDebugMode;
import emu.grasscutter.game.Account;
import emu.grasscutter.game.player.Player;
import emu.grasscutter.net.packet.*;
import emu.grasscutter.server.event.game.SendPacketEvent;
import emu.grasscutter.utils.*;
import io.netty.buffer.*;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.net.InetSocketAddress;
import java.nio.file.Path;
import java.text.SimpleDateFormat;
import java.util.Date;
import lombok.*;

public class GameSession implements GameSessionManager.KcpChannel {
    private final GameServer server;
    private GameSessionManager.KcpTunnel tunnel;

    @Getter @Setter private Account account;
    @Getter private Player player;

    @Getter private long encryptSeed = Crypto.ENCRYPT_SEED;
    private byte[] encryptKey = Crypto.ENCRYPT_KEY;

    private boolean useSecretKey;
    @Getter @Setter private SessionState state;

    @Getter private int clientTime;
    @Getter private long lastPingTime;
    private int lastClientSeq = 10;

    private static PrintWriter sessionLogWriter;
    private static final boolean ENABLE_SESSION_LOG = true;
    static {
        if (ENABLE_SESSION_LOG) {
            try {
                sessionLogWriter = new PrintWriter(new FileWriter("logs/session-debug.log", true), true);
            } catch (IOException e) {
                sessionLogWriter = null;
            }
        }
    }

    private void sessionLog(String msg) {
        if (!ENABLE_SESSION_LOG) return;
        var ts = new SimpleDateFormat("HH:mm:ss.SSS").format(new Date());
        var addr = getAddress();
        var addrStr = addr != null ? addr.toString() : "no-addr";
        var line = ts + " [SESSION:" + addrStr + "|" + state + "] " + msg;
        Grasscutter.getLogger().debug(line);
        if (sessionLogWriter != null) {
            sessionLogWriter.println(line);
            sessionLogWriter.flush();
        }
    }

    private static String bytesToHex(byte[] bytes, int maxLen) {
        StringBuilder sb = new StringBuilder();
        int len = Math.min(bytes.length, maxLen);
        for (int i = 0; i < len; i++) {
            sb.append(String.format("%02X ", bytes[i]));
            if ((i + 1) % 16 == 0) sb.append("\n               ");
        }
        if (bytes.length > maxLen) sb.append("...(" + bytes.length + " total)");
        return sb.toString().trim();
    }

    public GameSession(GameServer server) {
        this.server = server;
        this.state = SessionState.WAITING_FOR_TOKEN;
        this.lastPingTime = System.currentTimeMillis();

        if (GAME_INFO.useUniquePacketKey) {
            this.encryptKey = new byte[4096];
            this.encryptSeed = Crypto.generateEncryptKeyAndSeed(this.encryptKey);
        }
    }

    public GameServer getServer() {
        return server;
    }

    public InetSocketAddress getAddress() {
        try {
            return tunnel.getAddress();
        } catch (Throwable ignore) {
            return null;
        }
    }

    public boolean useSecretKey() {
        return useSecretKey;
    }

    public String getAccountId() {
        return this.getAccount().getId();
    }

    public synchronized void setPlayer(Player player) {
        this.player = player;
        this.player.setSession(this);
        this.player.setAccount(this.getAccount());
    }

    public boolean isLoggedIn() {
        return this.getPlayer() != null;
    }

    public void updateLastPingTime(int clientTime) {
        this.clientTime = clientTime;
        this.lastPingTime = System.currentTimeMillis();
    }

    public int getNextClientSequence() {
        return ++lastClientSeq;
    }

    public void replayPacket(int opcode, String name) {
        Path filePath = FileUtils.getPluginPath(name);
        File p = filePath.toFile();

        if (!p.exists()) return;

        byte[] packet = FileUtils.read(p);

        BasePacket basePacket = new BasePacket(opcode);
        basePacket.setData(packet);

        send(basePacket);
    }

    public void logPacket(String sendOrRecv, int opcode, byte[] payload) {
        Grasscutter.getLogger()
                .info(sendOrRecv + ": " + PacketOpcodesUtils.getOpcodeName(opcode) + " (" + opcode + ")");
        if (GAME_INFO.isShowPacketPayload) System.out.println(Utils.bytesToHex(payload));
    }

    public void send(BasePacket packet) {
        // Test
        if (packet.getOpcode() <= 0) {
            Grasscutter.getLogger().warn("Tried to send packet with missing cmd id!");
            return;
        }

        var opcodeName = PacketOpcodesUtils.getOpcodeName(packet.getOpcode());

        // Header
        if (packet.shouldBuildHeader()) {
            packet.buildHeader(this.getNextClientSequence());
        }

        // Log
        switch (GAME_INFO.logPackets) {
            case ALL -> {
                if (!PacketOpcodesUtils.LOOP_PACKETS.contains(packet.getOpcode())
                        || GAME_INFO.isShowLoopPackets) {
                    logPacket("SEND", packet.getOpcode(), packet.getData());
                }
            }
            case WHITELIST -> {
                if (SERVER.debugWhitelist.contains(packet.getOpcode())) {
                    logPacket("SEND", packet.getOpcode(), packet.getData());
                }
            }
            case BLACKLIST -> {
                if (!SERVER.debugBlacklist.contains(packet.getOpcode())) {
                    logPacket("SEND", packet.getOpcode(), packet.getData());
                }
            }
            default -> {}
        }

        // Invoke event.
        SendPacketEvent event = new SendPacketEvent(this, packet);
        event.call();
        if (!event.isCanceled()) { // If event is not cancelled, continue.
            try {
                packet = event.getPacket();
                var bytes = packet.build();
                sessionLog("SEND: opcode=" + packet.getOpcode() + " (" + opcodeName + ")"
                    + " len=" + bytes.length + " encrypt=" + packet.shouldEncrypt);
                if (packet.shouldEncrypt) {
                    if (Grasscutter.getConfig().server.game.useXorEncryption) {
                        Crypto.xor(bytes, packet.useDispatchKey() ? Crypto.DISPATCH_KEY : this.encryptKey);
                    }
                }
                tunnel.writeData(bytes);
            } catch (Exception e) {
                Grasscutter.getLogger().debug("Unable to send packet to client: " + e.getMessage());
                sessionLog("SEND FAIL: " + e.getClass().getSimpleName() + ": " + e.getMessage());
            }
        }
    }

    @Override
    public void onConnected(GameSessionManager.KcpTunnel tunnel) {
        this.tunnel = tunnel;
        sessionLog("KCP tunnel connected, state=" + state + " useSecretKey=" + useSecretKey
            + " encryptSeed=" + encryptSeed);
        Grasscutter.getLogger().info(translate("messages.game.connect", this.getAddress().toString()));
    }

    @Override
    public void handleReceive(byte[] bytes) {
        sessionLog("RECV raw: len=" + bytes.length
            + " firstBytes=" + bytesToHex(bytes, 32)
            + " useSecretKey=" + useSecretKey());

        // Decrypt and turn back into a packet
        if (Grasscutter.getConfig().server.game.useXorEncryption) {
            byte[] keyUsed = useSecretKey() ? this.encryptKey : Crypto.DISPATCH_KEY;
            sessionLog("DECRYPT: using " + (useSecretKey() ? "encryptKey(len=" + encryptKey.length + ")" : "DISPATCH_KEY(len=" + Crypto.DISPATCH_KEY.length + ")"));
            Crypto.xor(bytes, keyUsed);
            sessionLog("DECRYPT done: firstBytes=" + bytesToHex(bytes, 32));
        }
        ByteBuf packet = Unpooled.wrappedBuffer(bytes);

        try {
            boolean allDebug = GAME_INFO.logPackets == ServerDebugMode.ALL;
            int pktCount = 0;
            while (packet.readableBytes() > 0) {
                pktCount++;
                // Length
                if (packet.readableBytes() < 12) {
                    sessionLog("PARSE: remaining=" + packet.readableBytes() + " < 12, breaking");
                    return;
                }
                // Packet sanity check
                int const1 = packet.readShort();
                if (const1 != 17767) {
                    // Dump full buffer for debugging
                    byte[] remaining = new byte[Math.min(packet.readableBytes() + 2, 64)];
                    packet.getBytes(packet.readerIndex() - 2, remaining);
                    sessionLog("PARSE FAIL: Bad magic const1=" + const1 + " (expected 17767) "
                        + " at pkt#" + pktCount + " remaining=" + packet.readableBytes()
                        + " dump=" + bytesToHex(remaining, 64));
                    if (allDebug) {
                        Grasscutter.getLogger()
                                .error("Bad Data Package Received: got {} ,expect 17767", const1);
                    }
                    return; // Bad packet
                }
                // Data
                int opcode = packet.readShort();
                int headerLength = packet.readShort();
                int payloadLength = packet.readInt();

                sessionLog("PACKET #" + pktCount + ": opcode=" + opcode
                    + " (" + PacketOpcodesUtils.getOpcodeName(opcode) + ")"
                    + " headerLen=" + headerLength + " payloadLen=" + payloadLength);

                if (headerLength < 0 || headerLength > 65535 || payloadLength < 0 || payloadLength > 10*1024*1024) {
                    sessionLog("PARSE FAIL: Invalid lengths headerLen=" + headerLength + " payloadLen=" + payloadLength);
                    return;
                }

                if (packet.readableBytes() < headerLength + payloadLength + 2) {
                    sessionLog("PARSE FAIL: Not enough bytes for body. need="
                        + (headerLength + payloadLength + 2) + " have=" + packet.readableBytes());
                    return;
                }

                byte[] header = new byte[headerLength];
                byte[] payload = new byte[payloadLength];

                packet.readBytes(header);
                packet.readBytes(payload);
                // Sanity check #2
                int const2 = packet.readShort();
                if (const2 != -30293) {
                    sessionLog("PARSE FAIL: Bad tail magic const2=" + const2 + " (expected -30293) at pkt#" + pktCount);
                    if (allDebug) {
                        Grasscutter.getLogger()
                                .error("Bad Data Package Received: got {} ,expect -30293", const2);
                    }
                    return; // Bad packet
                }

                // Log packet
                switch (GAME_INFO.logPackets) {
                    case ALL -> {
                        if (!PacketOpcodesUtils.LOOP_PACKETS.contains(opcode) || GAME_INFO.isShowLoopPackets) {
                            logPacket("RECV", opcode, payload);
                        }
                    }
                    case WHITELIST -> {
                        if (SERVER.debugWhitelist.contains(opcode)) {
                            logPacket("RECV", opcode, payload);
                        }
                    }
                    case BLACKLIST -> {
                        if (!(SERVER.debugBlacklist.contains(opcode))) {
                            logPacket("RECV", opcode, payload);
                        }
                    }
                    default -> {}
                }

                sessionLog("DISPATCH packet opcode=" + opcode + " state=" + state);

                // Dump raw payload for proto debugging
                try {
                    java.nio.file.Path dumpDir = java.nio.file.Paths.get("./payload_dump");
                    java.nio.file.Files.createDirectories(dumpDir);
                    String fname = String.format("recv_%d_%s_%d.bin",
                        opcode, PacketOpcodesUtils.getOpcodeName(opcode), System.currentTimeMillis());
                    java.nio.file.Path dumpFile = dumpDir.resolve(fname);
                    java.io.FileOutputStream fos = new java.io.FileOutputStream(dumpFile.toFile());
                    // Write: [4 bytes opcode][4 bytes headerLen][header bytes][payload bytes]
                    fos.write(java.nio.ByteBuffer.allocate(4).putInt(opcode).array());
                    fos.write(java.nio.ByteBuffer.allocate(4).putInt(header.length).array());
                    fos.write(header);
                    fos.write(payload);
                    fos.close();
                } catch (Exception ignored) {}

                // Handle
                getServer().getPacketHandler().handle(this, opcode, header, payload);
            }
            if (pktCount == 0) {
                sessionLog("RECV: buffer was empty after reading");
            }
        } catch (Exception e) {
            sessionLog("RECV EXCEPTION: " + e.getClass().getSimpleName() + ": " + e.getMessage());
            e.printStackTrace();
        } finally {
            packet.release();
        }
    }

    @Override
    public void handleClose() {
        sessionLog("handleClose: state=" + state + " isLoggedIn=" + isLoggedIn());
        setState(SessionState.INACTIVE);
        // send disconnection pack in case of reconnection
        Grasscutter.getLogger()
                .info(translate("messages.game.disconnect", this.getAddress().toString()));
        // Save after disconnecting
        if (this.isLoggedIn()) {
            Player player = getPlayer();
            // Call logout event.
            player.onLogout();
        }
        try {
            send(new BasePacket(PacketOpcodes.ServerDisconnectClientNotify));
        } catch (Throwable ignore) {
            Grasscutter.getLogger().warn("closing {} error", getAddress().getAddress().getHostAddress());
        }
        tunnel = null;
    }

    public void setUseSecretKey(boolean useSecretKey) {
        this.useSecretKey = useSecretKey;
        sessionLog("setUseSecretKey: " + useSecretKey + " state=" + state);
    }

    public void close() {
        tunnel.close();
    }

    public boolean isActive() {
        return getState() == SessionState.ACTIVE;
    }

    public enum SessionState {
        INACTIVE,
        WAITING_FOR_TOKEN,
        WAITING_FOR_LOGIN,
        PICKING_CHARACTER,
        ACTIVE,
        ACCOUNT_BANNED
    }
}
