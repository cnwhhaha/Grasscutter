package emu.grasscutter.server.game;

import emu.grasscutter.Grasscutter;
import emu.grasscutter.utils.Utils;
import io.netty.buffer.*;
import io.netty.channel.DefaultEventLoop;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.net.InetSocketAddress;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;
import kcp.highway.*;
import lombok.Getter;

public class GameSessionManager {
    @Getter private static final DefaultEventLoop logicThread = new DefaultEventLoop();
    private static final ConcurrentHashMap<Ukcp, GameSession> sessions = new ConcurrentHashMap<>();
    private static final AtomicLong kcpPacketsReceived = new AtomicLong(0);
    private static final AtomicLong kcpPacketsSent = new AtomicLong(0);

    private static PrintWriter kcpLogWriter;
    static {
        try {
            kcpLogWriter = new PrintWriter(new FileWriter("logs/kcp-debug.log", true), true);
        } catch (IOException e) {
            kcpLogWriter = null;
        }
    }

    public static void kcpLog(String msg) {
        var ts = new SimpleDateFormat("HH:mm:ss.SSS").format(new Date());
        var line = ts + " [KCP] " + msg;
        Grasscutter.getLogger().debug(line);
        if (kcpLogWriter != null) {
            kcpLogWriter.println(line);
            kcpLogWriter.flush();
        }
    }

    public static long getKcpPacketsReceived() { return kcpPacketsReceived.get(); }
    public static long getKcpPacketsSent() { return kcpPacketsSent.get(); }

    private static final KcpListener listener =
            new KcpListener() {
                @Override
                public void onConnected(Ukcp ukcp) {
                    var addr = ukcp.user().getRemoteAddress();
                    var conv = ukcp.getConv();
                    kcpLog("KCP onConnected: addr=" + addr + " conv=" + conv
                        + " sessions=" + sessions.size());

                    int times = 0;
                    GameServer server = Grasscutter.getGameServer();
                    while (server == null) { // Waiting server to establish
                        try {
                            Thread.sleep(1000);
                        } catch (InterruptedException e) {
                            e.printStackTrace();
                            ukcp.close();
                            kcpLog("KCP onConnected ABORTED: server still null after " + (times*1000) + "ms");
                            return;
                        }
                        if (times++ > 5) {
                            Grasscutter.getLogger().error("Service is not available!");
                            kcpLog("KCP onConnected ABORTED: server not available after 5s");
                            ukcp.close();
                            return;
                        }
                        server = Grasscutter.getGameServer();
                    }
                    GameSession conversation = new GameSession(server);
                    conversation.onConnected(
                            new KcpTunnel() {
                                @Override
                                public InetSocketAddress getAddress() {
                                    return ukcp.user().getRemoteAddress();
                                }

                                @Override
                                public void writeData(byte[] bytes) {
                                    kcpPacketsSent.incrementAndGet();
                                    ByteBuf buf = Unpooled.wrappedBuffer(bytes);
                                    ukcp.write(buf);
                                    buf.release();
                                }

                                @Override
                                public void close() {
                                    ukcp.close();
                                }

                                @Override
                                public int getSrtt() {
                                    return ukcp.srtt();
                                }
                            });
                    sessions.put(ukcp, conversation);
                    kcpLog("KCP session created: addr=" + addr + " totalSessions=" + sessions.size());
                }

                @Override
                public void handleReceive(ByteBuf buf, Ukcp kcp) {
                    int len = buf.readableBytes();
                    kcpPacketsReceived.incrementAndGet();
                    var addr = kcp.user().getRemoteAddress();

                    if (len > 0 && len <= 16) {
                        // Small packets may be KCP control packets (ACK etc)
                        byte[] peek = new byte[Math.min(len, 16)];
                        buf.getBytes(buf.readerIndex(), peek);
                        kcpLog("KCP handleReceive SMALL: addr=" + addr + " len=" + len
                            + " hex=" + bytesToHex(peek));
                    }

                    var byteData = Utils.byteBufToArray(buf);
                    logicThread.execute(
                            () -> {
                                try {
                                    var conversation = sessions.get(kcp);
                                    if (conversation != null) {
                                        conversation.handleReceive(byteData);
                                    } else {
                                        kcpLog("KCP handleReceive: NO SESSION for kcp=" + kcp.getConv());
                                    }
                                } catch (Exception e) {
                                    kcpLog("KCP handleReceive EXCEPTION: " + e.getMessage());
                                    e.printStackTrace();
                                }
                            });
                }

                @Override
                public void handleException(Throwable ex, Ukcp ukcp) {
                    var addr = ukcp != null ? ukcp.user().getRemoteAddress().toString() : "unknown";
                    kcpLog("KCP handleException: addr=" + addr
                        + " ex=" + ex.getClass().getSimpleName() + ": " + ex.getMessage());
                    Grasscutter.getLogger().error("[KCP] Exception from " + addr + ": " + ex.getMessage());
                    if (ex instanceof IOException) {
                        kcpLog("KCP IOException (likely disconnect): " + ex.getMessage());
                    } else {
                        ex.printStackTrace();
                    }
                }

                @Override
                public void handleClose(Ukcp ukcp) {
                    var addr = ukcp.user().getRemoteAddress();
                    GameSession conversation = sessions.get(ukcp);
                    kcpLog("KCP handleClose: addr=" + addr + " hasSession=" + (conversation != null)
                        + " remainingSessions=" + (sessions.size() - 1));
                    if (conversation != null) {
                        conversation.handleClose();
                        sessions.remove(ukcp);
                    }
                }
            };

    public static KcpListener getListener() {
        return listener;
    }

    public interface KcpTunnel {
        InetSocketAddress getAddress();

        void writeData(byte[] bytes);

        void close();

        int getSrtt();
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02X ", b));
        }
        return sb.toString().trim();
    }

    interface KcpChannel {
        void onConnected(KcpTunnel tunnel);

        void handleClose();

        void handleReceive(byte[] bytes);
    }
}
