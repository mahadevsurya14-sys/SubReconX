"""Tests for scope validation and authorization controls."""

import pytest

from subreconx.core.scope import ScopeManager
from subreconx.exceptions import ScopeViolationError, InvalidDomainError


class TestScopeManagerBasics:
    """Test basic scope management operations."""

    def test_initially_empty(self) -> None:
        scope = ScopeManager()
        assert scope.is_empty is True
        assert scope.domain_count == 0
        assert scope.scopes == []

    def test_add_domain(self) -> None:
        scope = ScopeManager()
        result = scope.add_domain("example.com")
        assert result == "example.com"
        assert scope.is_empty is False
        assert scope.domain_count == 1

    def test_add_domain_sanitizes(self) -> None:
        """add_domain should validate and sanitize the input."""
        scope = ScopeManager()
        result = scope.add_domain("  HTTPS://Example.COM/  ")
        assert result == "example.com"

    def test_add_domain_invalid_raises(self) -> None:
        scope = ScopeManager()
        with pytest.raises(InvalidDomainError):
            scope.add_domain("")

    def test_add_multiple_domains(self) -> None:
        scope = ScopeManager()
        scope.add_domain("example.com")
        scope.add_domain("another.org")
        assert scope.domain_count == 2

    def test_add_duplicate_domain(self) -> None:
        """Adding the same domain twice should not create duplicates."""
        scope = ScopeManager()
        scope.add_domain("example.com")
        scope.add_domain("example.com")
        assert scope.domain_count == 1

    def test_remove_domain(self) -> None:
        scope = ScopeManager()
        scope.add_domain("example.com")
        removed = scope.remove_domain("example.com")
        assert removed is True
        assert scope.is_empty is True

    def test_remove_nonexistent_domain(self) -> None:
        scope = ScopeManager()
        removed = scope.remove_domain("nothere.com")
        assert removed is False

    def test_clear(self) -> None:
        scope = ScopeManager()
        scope.add_domain("example.com")
        scope.add_domain("another.org")
        scope.clear()
        assert scope.is_empty is True
        assert scope.domain_count == 0


class TestScopeChecking:
    """Test is_in_scope with various inputs."""

    @pytest.fixture
    def scope(self) -> ScopeManager:
        """Scope with example.com (including subdomains)."""
        s = ScopeManager()
        s.add_domain("example.com", include_subdomains=True)
        return s

    def test_exact_match(self, scope: ScopeManager) -> None:
        assert scope.is_in_scope("example.com") is True

    def test_subdomain_in_scope(self, scope: ScopeManager) -> None:
        assert scope.is_in_scope("api.example.com") is True

    def test_deep_subdomain_in_scope(self, scope: ScopeManager) -> None:
        assert scope.is_in_scope("a.b.c.example.com") is True

    def test_other_domain_out_of_scope(self, scope: ScopeManager) -> None:
        assert scope.is_in_scope("evil.com") is False

    def test_partial_match_not_in_scope(self, scope: ScopeManager) -> None:
        """notexample.com should NOT match example.com."""
        assert scope.is_in_scope("notexample.com") is False

    def test_suffix_overlap_not_in_scope(self, scope: ScopeManager) -> None:
        """badexample.com should NOT match example.com."""
        assert scope.is_in_scope("badexample.com") is False

    def test_empty_hostname(self, scope: ScopeManager) -> None:
        assert scope.is_in_scope("") is False

    def test_case_insensitive(self, scope: ScopeManager) -> None:
        assert scope.is_in_scope("API.EXAMPLE.COM") is True

    def test_trailing_dot_handled(self, scope: ScopeManager) -> None:
        assert scope.is_in_scope("example.com.") is True

    def test_whitespace_handled(self, scope: ScopeManager) -> None:
        assert scope.is_in_scope("  example.com  ") is True


class TestScopeExactOnly:
    """Test scope with include_subdomains=False."""

    def test_exact_only_match(self) -> None:
        scope = ScopeManager()
        scope.add_domain("example.com", include_subdomains=False)
        assert scope.is_in_scope("example.com") is True
        assert scope.is_in_scope("sub.example.com") is False

    def test_scopes_display_no_wildcard(self) -> None:
        scope = ScopeManager()
        scope.add_domain("example.com", include_subdomains=False)
        assert "*.example.com" not in scope.scopes
        assert "example.com" in scope.scopes


class TestValidateTarget:
    """Test the validate_target method (strict scope + syntax check)."""

    @pytest.fixture
    def scope(self) -> ScopeManager:
        s = ScopeManager()
        s.add_domain("example.com")
        return s

    def test_valid_in_scope_target(self, scope: ScopeManager) -> None:
        result = scope.validate_target("api.example.com")
        assert result == "api.example.com"

    def test_out_of_scope_raises(self, scope: ScopeManager) -> None:
        with pytest.raises(ScopeViolationError, match="outside the authorized scope"):
            scope.validate_target("evil.com")

    def test_invalid_hostname_raises(self, scope: ScopeManager) -> None:
        with pytest.raises(InvalidDomainError, match="Invalid hostname"):
            scope.validate_target("not a hostname")

    def test_single_label_raises(self, scope: ScopeManager) -> None:
        with pytest.raises(InvalidDomainError, match="Invalid hostname"):
            scope.validate_target("example")


class TestFilterInScope:
    """Test bulk scope filtering."""

    def test_filter_mixed_hostnames(self) -> None:
        scope = ScopeManager()
        scope.add_domain("example.com")

        hostnames = [
            "api.example.com",
            "evil.com",
            "cdn.example.com",
            "other.org",
        ]
        in_scope, out_of_scope = scope.filter_in_scope(hostnames)

        assert set(in_scope) == {"api.example.com", "cdn.example.com"}
        assert set(out_of_scope) == {"evil.com", "other.org"}

    def test_filter_all_in_scope(self) -> None:
        scope = ScopeManager()
        scope.add_domain("example.com")

        hostnames = ["a.example.com", "b.example.com"]
        in_scope, out_of_scope = scope.filter_in_scope(hostnames)
        assert len(in_scope) == 2
        assert len(out_of_scope) == 0

    def test_filter_all_out_of_scope(self) -> None:
        scope = ScopeManager()
        scope.add_domain("example.com")

        hostnames = ["evil.com", "bad.org"]
        in_scope, out_of_scope = scope.filter_in_scope(hostnames)
        assert len(in_scope) == 0
        assert len(out_of_scope) == 2

    def test_filter_empty_list(self) -> None:
        scope = ScopeManager()
        scope.add_domain("example.com")
        in_scope, out_of_scope = scope.filter_in_scope([])
        assert in_scope == []
        assert out_of_scope == []


class TestScopeDisplay:
    """Test human-readable scope display."""

    def test_empty_scope_message(self) -> None:
        scope = ScopeManager()
        display = scope.get_scope_display()
        assert "No domains in scope" in display

    def test_populated_scope_display(self) -> None:
        scope = ScopeManager()
        scope.add_domain("example.com")
        display = scope.get_scope_display()
        assert "example.com" in display
        assert "Authorized" in display

    def test_repr(self) -> None:
        scope = ScopeManager()
        scope.add_domain("example.com")
        r = repr(scope)
        assert "ScopeManager" in r
        assert "example.com" in r
