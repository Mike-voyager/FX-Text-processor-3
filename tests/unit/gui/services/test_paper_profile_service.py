"""Тесты для PaperProfile и PaperProfileService.

Tests:
    - TestPaperProfile: тесты для PaperProfile dataclass
    - TestPaperProfileService: тесты для сервиса управления профилями

Author: Mike Voyager
Date: 2026-04-07
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from unittest.mock import patch

import pytest

from src.model.enums import FontFamily, PaperType
from src.services.paper_profile_service import (
    DEFAULT_BOTTOM_MARGIN_MM,
    DEFAULT_LEFT_MARGIN_MM,
    DEFAULT_RIGHT_MARGIN_MM,
    DEFAULT_TOP_MARGIN_MM,
    MAX_FAVORITES,
    PaperProfile,
    PaperProfileService,
    TEAR_OFF_EXTRA_MM,
)


class TestPaperProfile:
    """Тесты для PaperProfile."""

    @pytest.fixture
    def sample_profile(self) -> PaperProfile:
        """Создаёт тестовый профиль."""
        return PaperProfile(
            id="a4_test",
            name="A4 Test",
            name_ru="A4 Тест",
            category="continuous",
            paper_type=PaperType.CONTINUOUS_TRACTOR,
            width_mm=210.0,
            height_mm=297.0,
            default_cpi=10,
            default_lpi=6,
        )

    def test_calculate_cols_cpi_10(self, sample_profile: PaperProfile) -> None:
        """Тест расчёта колонок при CPI=10."""
        cols = sample_profile.calculate_cols(cpi=10)
        # Printable width: 210 - 13 - 13 = 184mm
        # Inches: 184 / 25.4 = 7.24 inches
        # Cols: 7.24 * 10 = 72
        assert cols == 72

    def test_calculate_cols_cpi_20(self, sample_profile: PaperProfile) -> None:
        """Тест расчёта колонок при CPI=20."""
        cols = sample_profile.calculate_cols(cpi=20)
        # Cols: 7.24 * 20 = 144
        assert cols == 144

    def test_tear_off_adds_10mm(self, sample_profile: PaperProfile) -> None:
        """Тест добавления tear-off перфорации (+10mm)."""
        profile_with_tear = sample_profile.with_tear_off(enabled=True)

        assert profile_with_tear.tear_off_perforation is True
        assert profile_with_tear.effective_left_margin == DEFAULT_LEFT_MARGIN_MM + TEAR_OFF_EXTRA_MM
        assert profile_with_tear.effective_right_margin == DEFAULT_RIGHT_MARGIN_MM + TEAR_OFF_EXTRA_MM

    def test_tear_off_sheet_feed_no_effect(self) -> None:
        """Тест что tear-off не влияет на sheet feed."""
        profile = PaperProfile(
            id="a4_sheet",
            name="A4 Sheet",
            name_ru="A4 Листовая",
            category="sheet",
            paper_type=PaperType.SHEET_FEED,
            width_mm=210.0,
            height_mm=297.0,
            tear_off_perforation=True,
        )

        # Tear-off не применяется к sheet feed
        assert profile.effective_left_margin == DEFAULT_LEFT_MARGIN_MM
        assert profile.effective_right_margin == DEFAULT_RIGHT_MARGIN_MM

    def test_effective_margins(self, sample_profile: PaperProfile) -> None:
        """Тест расчёта эффективных margins."""
        profile_with_margins = sample_profile.with_updated_margins(
            left=20.0,
            right=20.0,
            top=10.0,
            bottom=10.0,
        )

        assert profile_with_margins.left_margin_mm == 20.0
        assert profile_with_margins.right_margin_mm == 20.0
        assert profile_with_margins.top_margin_mm == 10.0
        assert profile_with_margins.bottom_margin_mm == 10.0

        # Effective margins without tear-off
        assert profile_with_margins.effective_left_margin == 20.0
        assert profile_with_margins.effective_right_margin == 20.0

    def test_printable_area_calculation(self, sample_profile: PaperProfile) -> None:
        """Тест расчёта печатной области."""
        # Printable width = 210 - 13 - 13 = 184mm
        assert sample_profile.printable_width_mm == 184.0

        # Printable height = 297 - 4.2 - 4.2 = 288.6mm
        assert sample_profile.printable_height_mm == pytest.approx(288.6, abs=0.1)

    def test_printable_area_display(self, sample_profile: PaperProfile) -> None:
        """Тест отображения печатной области."""
        display = sample_profile.get_printable_area_display()

        assert "184.0" in display or "184" in display
        assert "288.6" in display or "288" in display
        assert "cols" in display
        assert "rows" in display
        assert "@ 10 CPI" in display

    def test_profile_serialization(self, sample_profile: PaperProfile) -> None:
        """Тест сериализации/десериализации профиля."""
        data = sample_profile.to_dict()

        assert data["id"] == "a4_test"
        assert data["name"] == "A4 Test"
        assert data["width_mm"] == 210.0
        assert "CONTINUOUS_TRACTOR" in data["paper_type"].upper()

        # Deserialize
        restored = PaperProfile.from_dict(data)
        assert restored.id == sample_profile.id
        assert restored.width_mm == sample_profile.width_mm

    def test_profile_frozen_immutable(self, sample_profile: PaperProfile) -> None:
        """Тест что PaperProfile immutable (frozen dataclass)."""
        with pytest.raises(AttributeError):
            sample_profile.width_mm = 220.0  # type: ignore[misc]

    def test_calculate_rows(self, sample_profile: PaperProfile) -> None:
        """Тест расчёта строк при разных LPI."""
        rows_6lpi = sample_profile.calculate_rows(lpi=6)
        rows_8lpi = sample_profile.calculate_rows(lpi=8)

        # LPI 8 should give more rows than LPI 6
        assert rows_8lpi > rows_6lpi


class TestPaperProfileService:
    """Тесты для PaperProfileService."""

    @pytest.fixture
    def temp_config_dir(self, tmp_path: Path) -> Path:
        """Создаёт временную директорию для конфигурации."""
        return tmp_path / ".fxtextprocessor"

    @pytest.fixture
    def service(self, temp_config_dir: Path) -> PaperProfileService:
        """Создаёт сервис с временной директорией."""
        return PaperProfileService(config_dir=temp_config_dir)

    def test_get_favorites_max_6(self, service: PaperProfileService) -> None:
        """Тест максимум 6 избранных профилей."""
        # Add all builtin profiles to favorites
        builtin = service.get_builtin_profiles()
        profile_ids = [p.id for p in builtin[:10]]  # Try to add more than 6

        service.set_favorites(profile_ids)

        favorites = service.get_favorites()
        assert len(favorites) <= MAX_FAVORITES

    def test_set_favorites(self, service: PaperProfileService) -> None:
        """Тест установки избранных профилей."""
        service.set_favorites(["a4_tractor", "letter_tractor"])

        favorites = service.get_favorites()
        favorite_ids = [p.id for p in favorites]

        assert "a4_tractor" in favorite_ids
        assert "letter_tractor" in favorite_ids

    def test_builtin_profiles(self, service: PaperProfileService) -> None:
        """Тест наличия встроенных профилей."""
        builtin = service.get_builtin_profiles()

        assert len(builtin) > 0

        # Check specific profiles exist
        profile_ids = {p.id for p in builtin}
        assert "a4_tractor" in profile_ids
        assert "a4_sheet" in profile_ids
        assert "e65_envelope" in profile_ids

    def test_get_profile(self, service: PaperProfileService) -> None:
        """Тест получения профиля по ID."""
        profile = service.get_profile("a4_tractor")

        assert profile is not None
        assert profile.id == "a4_tractor"
        assert profile.paper_type == PaperType.CONTINUOUS_TRACTOR

    def test_get_profile_not_found(self, service: PaperProfileService) -> None:
        """Тест получения несуществующего профиля."""
        profile = service.get_profile("nonexistent")
        assert profile is None

    def test_add_to_favorites(self, service: PaperProfileService) -> None:
        """Тест добавления в избранное."""
        result = service.add_to_favorites("a4_tractor")
        assert result is True

        assert service.is_favorite("a4_tractor") is True

    def test_add_to_favorites_already_exists(self, service: PaperProfileService) -> None:
        """Тест добавления уже избранного профиля."""
        service.add_to_favorites("a4_tractor")
        result = service.add_to_favorites("a4_tractor")

        assert result is False

    def test_add_to_favorites_invalid_profile(self, service: PaperProfileService) -> None:
        """Тест добавления несуществующего профиля."""
        result = service.add_to_favorites("nonexistent")
        assert result is False

    def test_remove_from_favorites(self, service: PaperProfileService) -> None:
        """Тест удаления из избранного."""
        service.add_to_favorites("a4_tractor")
        result = service.remove_from_favorites("a4_tractor")

        assert result is True
        assert service.is_favorite("a4_tractor") is False

    def test_favorites_persistence(self, temp_config_dir: Path) -> None:
        """Тест сохранения/загрузки избранных."""
        # Create service and add favorites
        service1 = PaperProfileService(config_dir=temp_config_dir)
        service1.set_favorites(["a4_tractor", "letter_tractor"])

        # Create new service instance with same directory
        service2 = PaperProfileService(config_dir=temp_config_dir)
        favorites = service2.get_favorites()
        favorite_ids = [p.id for p in favorites]

        assert "a4_tractor" in favorite_ids
        assert "letter_tractor" in favorite_ids

    def test_custom_profile_creation(self, service: PaperProfileService) -> None:
        """Тест создания пользовательского профиля."""
        profile = service.create_custom_profile(
            name="Custom Profile",
            name_ru="Пользовательский профиль",
            category="continuous",
            paper_type=PaperType.CONTINUOUS_TRACTOR,
            width_mm=200.0,
            height_mm=150.0,
        )

        assert profile.id.startswith("custom_")
        assert profile.is_custom is True
        assert profile.width_mm == 200.0
        assert profile.height_mm == 150.0

        # Should be retrievable
        retrieved = service.get_profile(profile.id)
        assert retrieved is not None
        assert retrieved.id == profile.id

    def test_delete_custom_profile(self, service: PaperProfileService) -> None:
        """Тест удаления пользовательского профиля."""
        profile = service.create_custom_profile(
            name="To Delete",
            name_ru="Для удаления",
            category="sheet",
            paper_type=PaperType.SHEET_FEED,
            width_mm=100.0,
            height_mm=100.0,
        )

        result = service.delete_custom_profile(profile.id)
        assert result is True
        assert service.get_profile(profile.id) is None

    def test_delete_builtin_profile_fails(self, service: PaperProfileService) -> None:
        """Тест что удаление встроенного профиля не работает."""
        result = service.delete_custom_profile("a4_tractor")
        assert result is False

    def test_get_profiles_by_category(self, service: PaperProfileService) -> None:
        """Тест получения профилей по категории."""
        continuous = service.get_profiles_by_category("continuous")
        sheet = service.get_profiles_by_category("sheet")
        envelope = service.get_profiles_by_category("envelope")

        assert all(p.category == "continuous" for p in continuous)
        assert all(p.category == "sheet" for p in sheet)
        assert all(p.category == "envelope" for p in envelope)

    def test_get_all_profiles(self, service: PaperProfileService) -> None:
        """Тест получения всех профилей."""
        # Add some favorites
        service.set_favorites(["a4_tractor"])

        all_profiles = service.get_all_profiles()
        favorites = service.get_favorites()

        # First profile should be a favorite
        if favorites:
            assert all_profiles[0].id == favorites[0].id

    def test_profile_export_import(self, service: PaperProfileService) -> None:
        """Тест экспорта/импорта профилей."""
        # Create custom profile
        profile = service.create_custom_profile(
            name="Export Test",
            name_ru="Тест экспорта",
            category="continuous",
            paper_type=PaperType.CONTINUOUS_TRACTOR,
            width_mm=250.0,
            height_mm=200.0,
        )

        # Export
        exported = service.export_profiles()

        assert "version" in exported
        assert "profiles" in exported
        assert "favorites" in exported
        assert len(exported["profiles"]) >= 1

        # Import to new service
        new_service = PaperProfileService(config_dir=Path("/tmp/test_import"))
        imported_count = new_service.import_profiles(exported)

        assert imported_count >= 1

    def test_update_profile(self, service: PaperProfileService) -> None:
        """Тест обновления профиля."""
        profile = service.create_custom_profile(
            name="Original",
            name_ru="Оригинал",
            category="sheet",
            paper_type=PaperType.SHEET_FEED,
            width_mm=100.0,
            height_mm=100.0,
        )

        updated = service.update_profile(
            profile.id,
            name="Updated",
            name_ru="Обновлённый",
            width_mm=150.0,
        )

        assert updated is not None
        assert updated.name == "Updated"
        assert updated.width_mm == 150.0

    def test_favorites_file_permissions(self, service: PaperProfileService, temp_config_dir: Path) -> None:
        """Тест прав доступа к файлу избранного."""
        service.set_favorites(["a4_tractor"])

        favorites_file = temp_config_dir / "favorites.json"
        if favorites_file.exists():
            mode = os.stat(favorites_file).st_mode
            # Check that file is readable/writable only by owner (0o600)
            assert (mode & 0o777) == 0o600
