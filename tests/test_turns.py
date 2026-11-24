"""The turn rule: who adapts after a round, relative to the previous one."""

import pytest

from jev_ids.turns import (
    ATTACK_ALERTED,
    ATTACK_PASSED,
    ATTACKER,
    DEFENDER,
    DEFENSE_UNDER_REVIEW,
    REGIME_LOOSENED,
    Evidence,
    Shift,
    Turn,
    decide_who_adapts,
    other_side,
    shift_between,
)


def test_shift_counts_only_the_attacks_answered_in_both_rounds() -> None:
    previous = {0: False, 1: True, 2: True, 3: False}
    # Leaving Flow 3 out of the current round, as a failed call does, and adding Flow 4, which the previous round did not answer.
    current = {0: True, 1: False, 2: True, 4: True}
    shift = shift_between(previous, current)
    assert shift == Shift(newly_alerted=1, newly_passing=1)
    assert shift.net == 0
    assert shift_between(None, current) == Shift()
    assert shift_between({}, current) == Shift()


@pytest.mark.parametrize(
    ("detected", "passed", "expected"),
    [
        # A real detector lets some attacks pass and catches others: any pass gives the defender the turn.
        (20, 11, Turn(DEFENDER, ATTACK_PASSED)),
        (0, 31, Turn(DEFENDER, ATTACK_PASSED)),
        (31, 0, Turn(ATTACKER, ATTACK_ALERTED)),
        # Naming no alert when no attack Flow was answered at all.
        (0, 0, Turn(DEFENDER, DEFENSE_UNDER_REVIEW)),
    ],
)
def test_first_round_reads_the_counts_alone(detected: int, passed: int, expected: Turn) -> None:
    evidence = Evidence(first_round=True, attacks_detected=detected, attacks_passed=passed)
    assert decide_who_adapts(evidence) == expected


@pytest.mark.parametrize(
    ("shift", "note_unchanged", "passed", "expected"),
    [
        # More attacks caught than before: the attacker adapts although most of its attacks still pass.
        (Shift(newly_alerted=3, newly_passing=1), True, 20, Turn(ATTACKER, ATTACK_ALERTED)),
        # More attacks passing than before while the note stayed: the defender opened the door, so the attacker moves.
        (Shift(newly_alerted=0, newly_passing=2), True, 20, Turn(ATTACKER, REGIME_LOOSENED)),
        # The same shift after the attacker rewrote its note is the attacker's own doing, and the defender answers it.
        (Shift(newly_alerted=0, newly_passing=2), False, 20, Turn(DEFENDER, ATTACK_PASSED)),
        (Shift(), True, 20, Turn(DEFENDER, ATTACK_PASSED)),
        (Shift(), True, 0, Turn(DEFENDER, DEFENSE_UNDER_REVIEW)),
        (Shift(newly_alerted=0, newly_passing=2), False, 0, Turn(DEFENDER, DEFENSE_UNDER_REVIEW)),
    ],
)
def test_later_rounds_follow_the_rule_in_order(shift: Shift, note_unchanged: bool, passed: int, expected: Turn) -> None:
    evidence = Evidence(first_round=False, attacks_detected=31 - passed, attacks_passed=passed, shift=shift, note_unchanged=note_unchanged)
    assert decide_who_adapts(evidence) == expected


def test_noise_margin_keeps_a_small_shift_from_counting() -> None:
    tightened = Evidence(first_round=False, attacks_detected=11, attacks_passed=20, shift=Shift(newly_alerted=2), note_unchanged=True)
    loosened = Evidence(first_round=False, attacks_detected=11, attacks_passed=20, shift=Shift(newly_passing=2), note_unchanged=True)
    assert decide_who_adapts(tightened, noise_margin=1) == Turn(ATTACKER, ATTACK_ALERTED)
    assert decide_who_adapts(tightened, noise_margin=2) == Turn(DEFENDER, ATTACK_PASSED)
    assert decide_who_adapts(loosened, noise_margin=1) == Turn(ATTACKER, REGIME_LOOSENED)
    assert decide_who_adapts(loosened, noise_margin=2) == Turn(DEFENDER, ATTACK_PASSED)


def test_other_side_swaps_the_two_sides() -> None:
    assert other_side(ATTACKER) == DEFENDER
    assert other_side(DEFENDER) == ATTACKER
