"""Typosquat detection: exact distance, and popularity as the deciding signal."""

import pytest

from blastradius.typosquat import (
    UNKNOWN_DOWNLOADS,
    candidate_pairs,
    damerau_distance_within,
    deletion_keys,
    find_typosquats,
)


class TestDistance:
    @pytest.mark.parametrize(
        "left,right",
        [
            ("axios", "axioss"),  # insertion
            ("commander", "comander"),  # deletion
            ("lodash", "fodash"),  # substitution
            ("chalk", "chakl"),  # transposition
        ],
    )
    def test_one_keystroke_apart(self, left, right):
        assert damerau_distance_within(left, right) == 1

    @pytest.mark.parametrize(
        "left,right",
        [
            ("axios", "axios"),  # identical is distance 0, not a typosquat
            ("axios", "axiosss"),  # two insertions
            ("lodash", "fodask"),  # two substitutions
            ("express", "fastify"),
        ],
    )
    def test_not_one_keystroke_apart(self, left, right):
        assert damerau_distance_within(left, right) != 1

    def test_identical_names_are_distance_zero(self):
        assert damerau_distance_within("axios", "axios") == 0

    def test_deletion_keys_cover_every_position(self):
        assert deletion_keys("abc") == {"abc", "bc", "ac", "ab"}


class TestCandidates:
    def test_finds_the_pair_without_comparing_everything(self):
        names = ["axios", "axioss", "express", "lodash", "react", "webpack"]
        assert candidate_pairs(names) == [("axios", "axioss")]

    def test_short_names_are_ignored(self):
        assert candidate_pairs(["ms", "mz", "qs"]) == []

    def test_pairs_are_unordered_and_unique(self):
        pairs = candidate_pairs(["chalk", "chalkk", "chalkk"])
        assert pairs == [("chalk", "chalkk")]


class TestFindTyposquats:
    NAMES = ["axios", "axioss", "es-errors", "es-error"]
    DOWNLOADS = {
        "axios": 119_805_667,
        "axioss": 33,
        "es-errors": 900_000_000,
        "es-error": 400_000_000,
    }

    def test_obscure_lookalike_of_a_popular_package_is_flagged(self):
        found = find_typosquats(self.NAMES, self.DOWNLOADS)
        assert [(pair.suspect, pair.target) for pair in found] == [("axioss", "axios")]

    def test_two_popular_packages_are_not_a_typosquat(self):
        """`es-errors` and `es-error` differ by one character and both ship widely."""
        found = find_typosquats(["es-errors", "es-error"], self.DOWNLOADS)
        assert found == []

    def test_ratio_is_recorded_for_triage(self):
        pair = find_typosquats(self.NAMES, self.DOWNLOADS)[0]
        assert pair.downloads_ratio == pytest.approx(33 / 119_805_667, rel=1e-5)
        assert pair.suspect_downloads == 33
        assert pair.target_downloads == 119_805_667

    def test_unknown_downloads_alone_is_not_enough(self):
        """npm deletes malicious releases, so silence is common - and not proof."""
        downloads = {"axios": 119_805_667}
        assert find_typosquats(self.NAMES, downloads) == []

    def test_known_malware_is_kept_even_without_download_data(self):
        downloads = {"axios": 119_805_667}
        found = find_typosquats(self.NAMES, downloads, always_suspect={"axioss"})
        assert [(pair.suspect, pair.target) for pair in found] == [("axioss", "axios")]
        assert found[0].suspect_downloads == UNKNOWN_DOWNLOADS

    def test_unpopular_target_is_skipped(self):
        found = find_typosquats(["tinylib", "tinylibb"], {"tinylib": 40, "tinylibb": 1})
        assert found == []

    def test_direction_follows_popularity(self):
        found = find_typosquats(self.NAMES, self.DOWNLOADS)
        assert found[0].suspect == "axioss" and found[0].target == "axios"

    def test_a_compromised_popular_package_is_not_called_a_typosquat(self):
        """Regression, with the numbers that produced it.

        A CI run emitted `color -> colord` and `synckit -> asynckit`: OSV names
        both `color` and `synckit` in malicious-release advisories, and the
        `always_suspect` waiver used to skip the popularity check entirely - so
        two of the most installed packages on npm were reported as impersonating
        smaller neighbours. Being compromised is not impersonating.
        """
        downloads = {
            "color": 49_623_174,
            "colord": 18_867_184,
            "synckit": 54_547_152,
            "asynckit": 115_641_564,
        }
        found = find_typosquats(
            list(downloads), downloads, always_suspect={"color", "synckit"}
        )
        assert found == [], f"a popular package was accused of typosquatting: {found}"

    def test_known_malware_still_needs_the_popularity_gap(self):
        downloads = {"axios": 119_805_667, "axioss": 119_000_000}
        assert find_typosquats(self.NAMES, downloads, always_suspect={"axioss"}) == []
