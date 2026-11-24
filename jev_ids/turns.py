"""The turn rule of the adversarial loop: which side adapts after a round, decided without a model.

In reading order:

- `Shift` and `shift_between`: how the attack Flows answered in two consecutive rounds changed sides.
- `Evidence`: what the rule reads of one round.
- `Turn`, `decide_who_adapts` and `other_side`: the side given the turn, and why.

A real detector lets some attacks pass and catches others on almost any split with more than one attack Flow, where an all-or-nothing
rule would never give the attacker the turn. The rule is therefore relative to the previous round. Over the attack Flows answered in both
rounds, `newly_alerted` counts those that passed before and raise an alert now, and `newly_passing` those that raised an alert before and
pass now. Their difference, `net`, says for whom the regime got worse, and a `noise_margin` keeps a detector that flips a few Verdicts
between two identical calls from being read as a move by either side.
"""

from collections.abc import Mapping
from dataclasses import dataclass, field

ATTACKER = "attacker"
DEFENDER = "defender"

# Naming the four reasons a side is given the turn; a loop that ends has its own reasons in `adversarial.py`.
ATTACK_PASSED = "attack_passed"
ATTACK_ALERTED = "attack_alerted"
REGIME_LOOSENED = "regime_loosened"
DEFENSE_UNDER_REVIEW = "defense_under_review"


@dataclass(frozen=True)
class Shift:
    """How the attack Flows answered in two consecutive rounds changed sides; both counts are 0 in the first round.

    Attributes:
        newly_alerted: attack Flows that passed in the previous round and raise an alert now.
        newly_passing: attack Flows that raised an alert in the previous round and pass now.
    """

    newly_alerted: int = 0
    newly_passing: int = 0

    @property
    def net(self) -> int:
        """Alerts gained minus alerts lost: positive when the regime got worse for the attacker."""
        return self.newly_alerted - self.newly_passing


def shift_between(previous: Mapping[int, bool] | None, current: Mapping[int, bool]) -> Shift:
    """Count the attack Flows that changed sides between two rounds.

    Only the Flows answered in both rounds are compared, so a failed call in either round moves nothing.

    Args:
        previous: whether each answered attack Flow raised an alert in the previous round, or None in the first round.
        current: the same for the round just judged, under the same keys.

    Returns:
        The two counts, both 0 without a previous round.
    """
    if previous is None:
        return Shift()
    shared = previous.keys() & current.keys()
    return Shift(
        newly_alerted=sum(1 for key in shared if current[key] and not previous[key]),
        newly_passing=sum(1 for key in shared if previous[key] and not current[key]),
    )


@dataclass(frozen=True)
class Evidence:
    """What the rule reads of one round, all of it counted over answered attack Flows.

    Attributes:
        first_round: whether no previous round exists to compare with.
        attacks_detected: attack Flows that raised an alert.
        attacks_passed: attack Flows that raised none.
        shift: the Flows that changed sides since the previous round.
        note_unchanged: whether the note in force is the one of the previous round.
    """

    first_round: bool
    attacks_detected: int
    attacks_passed: int
    shift: Shift = field(default_factory=Shift)
    note_unchanged: bool = False


@dataclass(frozen=True)
class Turn:
    """The side given the turn after a round, and the reason."""

    side: str
    reason: str


def decide_who_adapts(evidence: Evidence, noise_margin: int = 0) -> Turn:
    """The side that adapts after a round, by a fixed rule and no model.

    In the first round the defender moves when any attack passed, else the attacker moves because its attacks were caught. From then on,
    in this order: more attacks caught than before, beyond the margin, gives the attacker the turn (`attack_alerted`); more attacks passing
    than before, beyond the margin, while the attacker changed nothing, also gives it the turn (`regime_loosened`), because only the
    defender can have opened that door; any attack still passing gives the defender the turn (`attack_passed`); and with nothing passing
    the defender reviews a defense that nothing is testing (`defense_under_review`).

    Args:
        evidence: what the round measured over the answered attack Flows.
        noise_margin: how far `net` must move, in Flows, before it counts as a shift.

    Returns:
        The side and the reason.
    """
    if evidence.first_round:
        return _first_turn(evidence)
    net = evidence.shift.net
    if net > noise_margin:
        return Turn(ATTACKER, ATTACK_ALERTED)
    if -net > noise_margin and evidence.note_unchanged:
        return Turn(ATTACKER, REGIME_LOOSENED)
    return _standing_turn(evidence)


def _first_turn(evidence: Evidence) -> Turn:
    """The first round has no shift to read: the attacker moves only when attacks were answered and every one was caught."""
    if evidence.attacks_passed == 0 and evidence.attacks_detected > 0:
        return Turn(ATTACKER, ATTACK_ALERTED)
    return _standing_turn(evidence)


def _standing_turn(evidence: Evidence) -> Turn:
    """Without a shift, the defender moves: against the attacks that pass, or to review a defense nothing is testing."""
    if evidence.attacks_passed > 0:
        return Turn(DEFENDER, ATTACK_PASSED)
    return Turn(DEFENDER, DEFENSE_UNDER_REVIEW)


def other_side(side: str) -> str:
    """The side that is asked when the one given the turn holds."""
    return DEFENDER if side == ATTACKER else ATTACKER
