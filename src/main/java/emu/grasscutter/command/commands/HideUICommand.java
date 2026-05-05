package emu.grasscutter.command.commands;

import emu.grasscutter.command.Command;
import emu.grasscutter.command.CommandHandler;
import emu.grasscutter.game.player.Player;
import emu.grasscutter.server.packet.send.PacketWindy;
import java.util.List;

@Command(
        label = "HideUI",
        usage = "HideUI",
        aliases = {"hui"},
        permission = "player.windy",
        permissionTargeted = "player.windy.others")
public class HideUICommand implements CommandHandler {
    @Override
    public void execute(final Player sender, final Player targetPlayer, final List<String> args) {

        String path = "HideUI";
        targetPlayer.sendPacket(new PacketWindy(path));
        CommandHandler.sendMessage(sender, "UI hidden successfully.");
    }
}
