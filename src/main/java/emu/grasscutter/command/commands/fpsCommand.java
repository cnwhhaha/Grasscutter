package emu.grasscutter.command.commands;

import emu.grasscutter.command.Command;
import emu.grasscutter.command.CommandHandler;
import emu.grasscutter.game.player.Player;
import emu.grasscutter.server.packet.send.PacketWindy;
import java.util.List;

@Command(
        label = "fps",
        usage = "fps",
        permission = "player.windy",
        permissionTargeted = "player.windy.others")
public class fpsCommand implements CommandHandler {
    @Override
    public void execute(final Player sender, final Player targetPlayer, final List<String> args) {

        String path = "fps";
        targetPlayer.sendPacket(new PacketWindy(path));
    }
}
