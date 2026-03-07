package emu.grasscutter.command.commands;

import emu.grasscutter.command.*;
import emu.grasscutter.game.player.Player;
import emu.grasscutter.game.quest.GameQuest;
import emu.grasscutter.game.quest.enums.QuestState;
import java.util.*;

@Command(
        label = "nexttask",
        aliases = {"ntask"},
        usage = {"[subQuestId]"},
        permission = "player.quest",
        permissionTargeted = "player.quest.others")
public final class NextTaskCommand implements CommandHandler {
    @Override
    public void execute(Player sender, Player targetPlayer, List<String> args) {
        GameQuest targetQuest = null;

        if (!args.isEmpty()) {
            try {
                int subQuestId = Integer.parseInt(args.get(0));
                var quest = targetPlayer.getQuestManager().getQuestById(subQuestId);
                if (quest == null) {
                    CommandHandler.sendMessage(sender, "Quest not found: " + subQuestId);
                    return;
                }
                if (quest.getState() != QuestState.QUEST_STATE_UNFINISHED) {
                    CommandHandler.sendMessage(
                            sender,
                            "Quest "
                                    + subQuestId
                                    + " is not in unfinished state ("
                                    + quest.getState().name()
                                    + ").");
                    return;
                }
                targetQuest = quest;
            } catch (NumberFormatException ignored) {
                CommandHandler.sendMessage(sender, "Invalid quest id: " + args.get(0));
                return;
            }
        } else {
            targetQuest =
                    targetPlayer.getQuestManager().getActiveMainQuests().stream()
                            .map(mainQuest -> mainQuest.getChildQuests().values())
                            .flatMap(Collection::stream)
                            .filter(quest -> quest.getState() == QuestState.QUEST_STATE_UNFINISHED)
                            .min(
                                    Comparator.comparingInt(GameQuest::getAcceptTime)
                                            .thenComparingInt(
                                                    q ->
                                                            q.getQuestData() != null
                                                                    ? q.getQuestData().getOrder()
                                                                    : Integer.MAX_VALUE)
                                            .thenComparingInt(GameQuest::getSubQuestId))
                            .orElse(null);

            if (targetQuest == null) {
                CommandHandler.sendMessage(sender, "No unfinished quest found.");
                return;
            }
        }

        int questId = targetQuest.getSubQuestId();
        targetQuest.finish();

        CommandHandler.sendMessage(sender, "Forced quest stage completion: " + questId + ".");
    }
}
