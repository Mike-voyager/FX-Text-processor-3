"""Tests for TemplateManager.

Tests template save/load, .fxstpl format, special blank signature,
and validation report functionality.

Coverage target: ≥90%
"""

from __future__ import annotations

import json
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from src.services.template_manager import (
    FormTemplate,
    TemplatePage,
    TemplateManager,
    TemplateValidator,
    ValidationReport,
    FXSTPL_MAGIC,
    FXSTPL_VERSION,
)
from src.documents.types.type_schema import FieldDefinition, FieldType


# =============================================================================
# FIXTURES
# =============================================================================


@pytest.fixture
def temp_dir():
    """Create a temporary directory."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


@pytest.fixture
def sample_field_def():
    """Create a sample FieldDefinition."""
    return FieldDefinition(
        field_id="test_field",
        field_type=FieldType.TEXT_INPUT,
        label="Test Label",
        label_i18n={"ru": "Тестовая метка"},
        required=True,
    )


@pytest.fixture
def sample_template(sample_field_def):
    """Create a sample FormTemplate."""
    page = TemplatePage(
        index=0,
        paper_profile_id="A4-10cpi",
        fields=[sample_field_def],
    )
    return FormTemplate(
        template_id="test-template-123",
        name="Test Template",
        name_ru="Тестовый шаблон",
        doc_type="DVN-44-K53",
        pages=[page],
        author="Test Author",
    )


@pytest.fixture
def template_manager(temp_dir):
    """Create a TemplateManager instance."""
    return TemplateManager(templates_dir=temp_dir)


# =============================================================================
# TEST: Save Template
# =============================================================================


class TestSaveTemplate:
    """Test suite for saving templates."""

    def test_save_template_creates_file(self, template_manager, sample_template):
        """Test save_template creates a .fxstpl file."""
        path = template_manager.save_template(sample_template)
        
        assert path.exists()
        assert path.suffix == ".fxstpl"

    def test_save_template_updates_modified_time(self, template_manager, sample_template):
        """Test save_template updates modified_at timestamp."""
        old_modified = sample_template.modified_at
        
        # Small delay to ensure different timestamp
        import time
        time.sleep(0.01)
        
        template_manager.save_template(sample_template)
        
        assert sample_template.modified_at != old_modified

    def test_save_template_validates(self, template_manager):
        """Test save_template validates before saving."""
        # Create invalid template (no pages)
        invalid_template = FormTemplate(
            template_id="invalid",
            name="Invalid",
            name_ru="Невалидный",
            doc_type="",
            pages=[],  # Invalid: no pages
        )
        
        with pytest.raises(ValueError, match="Template validation failed"):
            template_manager.save_template(invalid_template)

    def test_save_without_validation(self, template_manager):
        """Test save with validate=False skips validation."""
        # Create template that would fail validation
        invalid_template = FormTemplate(
            template_id="invalid",
            name="Invalid",
            name_ru="Невалидный",
            doc_type="",
            pages=[],
        )
        
        # Should not raise when validation is skipped
        path = template_manager.save_template(invalid_template, validate=False)
        assert path.exists()


# =============================================================================
# TEST: Load Template
# =============================================================================


class TestLoadTemplate:
    """Test suite for loading templates."""

    def test_load_template(self, template_manager, sample_template):
        """Test load_template loads saved template."""
        template_manager.save_template(sample_template)
        
        loaded = template_manager.load_template("test-template-123")
        
        assert loaded.template_id == "test-template-123"
        assert loaded.name == "Test Template"
        assert len(loaded.pages) == 1

    def test_load_template_not_found(self, template_manager):
        """Test load_template raises FileNotFoundError for missing template."""
        with pytest.raises(FileNotFoundError, match="Template missing not found"):
            template_manager.load_template("missing")

    def test_load_preserves_field_data(self, template_manager, sample_template, sample_field_def):
        """Test load preserves field definition data."""
        template_manager.save_template(sample_template)
        
        loaded = template_manager.load_template("test-template-123")
        field = loaded.pages[0].fields[0]
        
        assert field.field_id == sample_field_def.field_id
        assert field.field_type == sample_field_def.field_type
        assert field.label == sample_field_def.label


# =============================================================================
# TEST: FXSTPL Format
# =============================================================================


class TestFXSTPLFormat:
    """Test suite for .fxstpl file format."""

    def test_fxstpl_magic_constant(self):
        """Test FXSTPL magic constant."""
        assert FXSTPL_MAGIC == "FXSTPL"

    def test_fxstpl_version_constant(self):
        """Test FXSTPL version constant."""
        assert FXSTPL_VERSION == "1.0"

    def test_save_includes_magic(self, template_manager, sample_template):
        """Test saved file includes magic header."""
        path = template_manager.save_template(sample_template)
        
        with open(path, "r", encoding="utf-8") as f:
            lines = f.readlines()
        
        assert lines[0].strip() == FXSTPL_MAGIC

    def test_save_includes_version(self, template_manager, sample_template):
        """Test saved file includes version."""
        path = template_manager.save_template(sample_template)
        
        with open(path, "r", encoding="utf-8") as f:
            lines = f.readlines()
        
        assert lines[1].strip() == FXSTPL_VERSION

    def test_save_includes_json_data(self, template_manager, sample_template):
        """Test saved file includes JSON data."""
        path = template_manager.save_template(sample_template)
        
        with open(path, "r", encoding="utf-8") as f:
            lines = f.readlines()
        
        # Lines after header should be valid JSON
        json_data = "".join(lines[2:])
        data = json.loads(json_data)
        
        assert data["template_id"] == "test-template-123"
        assert data["name"] == "Test Template"


# =============================================================================
# TEST: Special Blank Signature
# =============================================================================


class TestSpecialBlankSignature:
    """Test suite for special blank signature."""

    def test_special_blank_flag(self, template_manager, sample_template):
        """Test special blank flag is set on save."""
        path = template_manager.save_template(sample_template, is_special_blank=True)
        
        loaded = FormTemplate.load(path)
        assert loaded.is_special_blank is True

    def test_regular_blank_no_signature(self, template_manager, sample_template):
        """Test regular blank has no signature."""
        path = template_manager.save_template(sample_template, is_special_blank=False)
        
        loaded = FormTemplate.load(path)
        assert loaded.is_special_blank is False
        assert loaded.signature is None

    def test_load_requires_signature_for_special(self, temp_dir, sample_template):
        """Test load requires signature for special blanks."""
        # Create special blank without signature
        sample_template.is_special_blank = True
        sample_template.signature = None
        
        path = temp_dir / "test.fxstpl"
        sample_template.save(path)
        
        with pytest.raises(ValueError, match="Special blank missing signature"):
            FormTemplate.load(path)


# =============================================================================
# TEST: Validation Report
# =============================================================================


class TestValidationReport:
    """Test suite for ValidationReport."""

    def test_empty_report_is_valid(self):
        """Test empty report is valid."""
        report = ValidationReport()
        assert report.is_valid is True

    def test_report_with_error_is_invalid(self):
        """Test report with error is invalid."""
        report = ValidationReport(errors=["Field overlap detected"])
        assert report.is_valid is False

    def test_add_error(self):
        """Test add_error adds to errors list."""
        report = ValidationReport()
        report.add_error("Test error")
        
        assert "Test error" in report.errors

    def test_add_warning(self):
        """Test add_warning adds to warnings list."""
        report = ValidationReport()
        report.add_warning("Test warning")
        
        assert "Test warning" in report.warnings


# =============================================================================
# TEST: Template Validator
# =============================================================================


class TestTemplateValidator:
    """Test suite for TemplateValidator."""

    def test_validator_creation(self):
        """Test TemplateValidator creation."""
        validator = TemplateValidator()
        assert validator is not None

    def test_validate_empty_template(self):
        """Test validation catches empty template."""
        validator = TemplateValidator()
        
        empty_template = FormTemplate(
            template_id="test",
            name="Test",
            name_ru="Тест",
            doc_type="",
            pages=[],  # Empty pages
        )
        
        report = validator.validate(empty_template)
        
        assert report.is_valid is False
        assert any("page" in e.lower() for e in report.errors)

    def test_validate_missing_name(self):
        """Test validation catches missing name."""
        validator = TemplateValidator()
        
        template = FormTemplate(
            template_id="test",
            name="",  # Missing name
            name_ru="Тест",
            doc_type="TEST",
            pages=[TemplatePage(0, "A4", [])],
        )
        
        report = validator.validate(template)
        
        assert report.is_valid is False

    def test_validate_valid_template(self, sample_template):
        """Test validation passes for valid template."""
        validator = TemplateValidator()
        
        report = validator.validate(sample_template)
        
        assert report.is_valid is True


# =============================================================================
# TEST: List Templates
# =============================================================================


class TestListTemplates:
    """Test suite for listing templates."""

    def test_list_templates_empty(self, template_manager):
        """Test list_templates returns empty list for empty directory."""
        templates = template_manager.list_templates()
        assert templates == []

    def test_list_templates_returns_templates(self, template_manager, sample_template):
        """Test list_templates returns saved templates."""
        template_manager.save_template(sample_template)
        
        templates = template_manager.list_templates()
        
        assert len(templates) == 1
        assert templates[0].template_id == "test-template-123"


# =============================================================================
# TEST: Delete Template
# =============================================================================


class TestDeleteTemplate:
    """Test suite for deleting templates."""

    def test_delete_template_removes_file(self, template_manager, sample_template):
        """Test delete_template removes the file."""
        template_manager.save_template(sample_template)
        
        result = template_manager.delete_template("test-template-123")
        
        assert result is True
        assert len(template_manager.list_templates()) == 0

    def test_delete_missing_template_returns_false(self, template_manager):
        """Test delete_template returns False for missing template."""
        result = template_manager.delete_template("non-existent")
        
        assert result is False


# =============================================================================
# TEST: Create Template
# =============================================================================


class TestCreateTemplate:
    """Test suite for creating templates."""

    def test_create_template(self, template_manager):
        """Test create_template creates new template."""
        template = template_manager.create_template(
            name="New Template",
            name_ru="Новый шаблон",
            doc_type="DVN-44-K53",
            author="Test Author",
        )
        
        assert template.name == "New Template"
        assert template.name_ru == "Новый шаблон"
        assert template.doc_type == "DVN-44-K53"
        assert template.author == "Test Author"
        assert template.pages == []

    def test_create_template_generates_id(self, template_manager):
        """Test create_template generates unique ID."""
        template1 = template_manager.create_template("Test1", "Тест1", "DOC")
        template2 = template_manager.create_template("Test2", "Тест2", "DOC")
        
        assert template1.template_id != template2.template_id


# =============================================================================
# TEST: Duplicate Template
# =============================================================================


class TestDuplicateTemplate:
    """Test suite for duplicating templates."""

    def test_duplicate_template_creates_copy(self, template_manager, sample_template):
        """Test duplicate_template creates a copy."""
        template_manager.save_template(sample_template)
        
        duplicate = template_manager.duplicate_template("test-template-123")
        
        assert duplicate.template_id != sample_template.template_id
        assert duplicate.name == "Test Template (Copy)"
        assert duplicate.name_ru == "Тестовый шаблон (Копия)"

    def test_duplicate_clears_special_blank(self, template_manager, sample_template):
        """Test duplicate clears special blank flag."""
        sample_template.is_special_blank = True
        sample_template.signature = "test_signature"
        template_manager.save_template(sample_template, is_special_blank=True)
        
        duplicate = template_manager.duplicate_template("test-template-123")
        
        assert duplicate.is_special_blank is False
        assert duplicate.signature is None


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--cov=src.services.template_manager"])
