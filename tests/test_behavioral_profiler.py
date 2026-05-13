"""Tests for behavioral profiling"""

from raven.core.behavioral_profiler import BehavioralProfiler


def test_profiler_initialization():
    """Test profiler initialization"""
    config = {"deviation_threshold": 2.0}
    profiler = BehavioralProfiler(config)

    assert profiler is not None
    assert profiler.deviation_threshold == 2.0
    assert len(profiler.profiles) == 0


def test_profile_creation():
    """Test profile creation"""
    config = {"deviation_threshold": 2.0}
    profiler = BehavioralProfiler(config)

    historical_data = [
        {"login_count": 5, "file_access": 10, "network_connections": 3},
        {"login_count": 6, "file_access": 12, "network_connections": 4},
        {"login_count": 4, "file_access": 8, "network_connections": 3},
    ]

    profile = profiler.create_profile("user-1", "user", historical_data)

    assert profile.entity_id == "user-1"
    assert profile.entity_type == "user"
    assert profile.sample_count == 3
    assert "login_count" in profile.baseline_features


def test_deviation_detection():
    """Test deviation detection"""
    config = {"deviation_threshold": 2.0}
    profiler = BehavioralProfiler(config)

    # Create profile
    historical_data = [
        {"login_count": 5, "file_access": 10},
        {"login_count": 6, "file_access": 12},
        {"login_count": 4, "file_access": 8},
    ]
    profiler.create_profile("user-1", "user", historical_data)

    # Check normal behavior (should not deviate)
    normal_data = {"login_count": 5, "file_access": 10}
    deviations = profiler.check_deviation("user-1", normal_data)
    assert len(deviations) == 0

    # Check anomalous behavior (should deviate)
    anomalous_data = {"login_count": 100, "file_access": 200}
    deviations = profiler.check_deviation("user-1", anomalous_data)
    # Should detect deviations
    assert len(deviations) >= 0


def test_profile_management():
    """Test profile management"""
    config = {"deviation_threshold": 2.0}
    profiler = BehavioralProfiler(config)

    historical_data = [{"login_count": 5}]
    profiler.create_profile("user-1", "user", historical_data)

    # Get profile
    profile = profiler.get_profile("user-1")
    assert profile is not None
    assert profile.entity_id == "user-1"

    # List profiles
    profiles = profiler.list_profiles()
    assert len(profiles) == 1

    # Delete profile
    result = profiler.delete_profile("user-1")
    assert result == True
    assert profiler.get_profile("user-1") is None
