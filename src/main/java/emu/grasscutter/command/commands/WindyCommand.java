package emu.grasscutter.command.commands;

import emu.grasscutter.command.Command;
import emu.grasscutter.command.CommandHandler;
import emu.grasscutter.game.player.Player;
import emu.grasscutter.server.packet.send.PacketWindSeedClientNotify;
import java.util.List;

@Command(
        label = "windy",
        usage = "windy",
        aliases = {"w"},
        permission = "player.windy",
        permissionTargeted = "player.windy.others")
public class WindyCommand implements CommandHandler {
    @Override
    public void execute(final Player sender, final Player targetPlayer, final List<String> args) {

        String path = "C:/Windy/" + args.get(0) + ".luac";
        targetPlayer.sendPacket(new PacketWindSeedClientNotify(path));
        CommandHandler.sendMessage(sender, "Successfully executed the " + args.get(0) + " Lua script!");
    }
}
