#!/usr/bin/env python
# -*- coding: utf-8 -*-

import threading

import pytest
from redis.exceptions import ConnectionError

from CTFd.cache import cache, clear_challenges
from CTFd.config import TestingConfig
from CTFd.models import Awards, Unlocks
from tests.helpers import (
    create_ctfd,
    destroy_ctfd,
    gen_award,
    gen_challenge,
    gen_hint,
    gen_solution,
    gen_solve,
    login_as_user,
    register_user,
)


def test_api_unlock_ignores_forged_ip():
    """Test that a user cannot forge the IP address stored in an Unlock"""
    app = create_ctfd()
    with app.app_context():
        gen_challenge(app.db)
        gen_hint(app.db, challenge_id=1, cost=0)
        register_user(app)

        with login_as_user(app) as client:
            r = client.post(
                "/api/v1/unlocks",
                json={"target": 1, "type": "hints", "ip": "198.51.100.99"},
                environ_base={"REMOTE_ADDR": "203.0.113.10"},
            )
            assert r.status_code == 200

            unlock = Unlocks.query.first()
            assert unlock.ip == "203.0.113.10"
            assert r.get_json()["data"]["ip"] == "203.0.113.10"
    destroy_ctfd(app)


def test_api_unlock_hint_hidden_challenge():
    """Test that a user cannot unlock a hint for a hidden challenge"""
    app = create_ctfd()
    with app.app_context():
        gen_challenge(app.db, state="hidden")
        gen_hint(app.db, challenge_id=1, cost=0)
        register_user(app)

        with login_as_user(app) as client:
            r = client.post("/api/v1/unlocks", json={"target": 1, "type": "hints"})
            assert r.status_code == 404

        assert Unlocks.query.count() == 0
        assert Awards.query.count() == 0
    destroy_ctfd(app)


def test_api_unlock_hint_challenge_prerequisites():
    """Test that a user cannot unlock a hint for a challenge with unmet prerequisites"""
    app = create_ctfd()
    with app.app_context():
        gen_challenge(app.db)
        gen_challenge(
            app.db,
            name="gated",
            requirements={"prerequisites": [1], "anonymize": True},
        )
        gen_hint(app.db, challenge_id=2, cost=0)
        register_user(app)

        with login_as_user(app) as client:
            r = client.post("/api/v1/unlocks", json={"target": 1, "type": "hints"})
            assert r.status_code == 403
            assert Unlocks.query.count() == 0
            assert Awards.query.count() == 0

            gen_solve(app.db, user_id=2, challenge_id=1)
            clear_challenges()

            r = client.post("/api/v1/unlocks", json={"target": 1, "type": "hints"})
            assert r.status_code == 200
            assert Unlocks.query.count() == 1
    destroy_ctfd(app)


def test_api_unlock_hint_prerequisites():
    """Test that a user cannot unlock a hint with unmet hint prerequisites"""
    app = create_ctfd()
    with app.app_context():
        gen_challenge(app.db)
        gen_hint(app.db, challenge_id=1, cost=0)
        gen_hint(app.db, challenge_id=1, cost=0, requirements={"prerequisites": [1]})
        register_user(app)

        with login_as_user(app) as client:
            r = client.post("/api/v1/unlocks", json={"target": 2, "type": "hints"})
            assert r.status_code == 403
            assert Unlocks.query.count() == 0

            r = client.post("/api/v1/unlocks", json={"target": 1, "type": "hints"})
            assert r.status_code == 200
            r = client.post("/api/v1/unlocks", json={"target": 2, "type": "hints"})
            assert r.status_code == 200
            assert Unlocks.query.count() == 2
    destroy_ctfd(app)


def test_api_unlock_solution_hidden_challenge():
    """Test that a user cannot unlock a solution for a hidden challenge"""
    app = create_ctfd()
    with app.app_context():
        gen_challenge(app.db, state="hidden")
        gen_solution(app.db, challenge_id=1, state="visible")
        register_user(app)

        with login_as_user(app) as client:
            r = client.post("/api/v1/unlocks", json={"target": 1, "type": "solutions"})
            assert r.status_code == 404

        assert Unlocks.query.count() == 0
    destroy_ctfd(app)


def test_api_unlock_admin_hidden_challenge():
    """Test that an admin can unlock a hint for a hidden challenge"""
    app = create_ctfd()
    with app.app_context():
        gen_challenge(app.db, state="hidden")
        gen_hint(app.db, challenge_id=1, cost=0)

        with login_as_user(app, name="admin") as client:
            r = client.post("/api/v1/unlocks", json={"target": 1, "type": "hints"})
            assert r.status_code == 200
    destroy_ctfd(app)


def test_api_unlock_invalid_request():
    """Test that malformed unlock requests return 400"""
    app = create_ctfd()
    with app.app_context():
        gen_challenge(app.db)
        gen_hint(app.db, challenge_id=1, cost=0)
        register_user(app)

        with login_as_user(app) as client:
            for data in (
                {},
                {"type": "hints"},
                {"target": 1},
                {"target": 1, "type": "users"},
                {"target": 1, "type": "nonexistent"},
            ):
                r = client.post("/api/v1/unlocks", json=data)
                assert r.status_code == 400

        assert Unlocks.query.count() == 0
    destroy_ctfd(app)


def test_api_unlock_hint_rejected_while_account_unlock_in_progress():
    """Test that a hint unlock is refused, and nothing is charged, while another
    unlock for the same account holds the hint unlock lock"""
    app = create_ctfd()
    with app.app_context():
        gen_challenge(app.db)
        gen_hint(app.db, challenge_id=1, cost=10)
        register_user(app)
        gen_award(app.db, user_id=2, value=10)

        lock_key = "hint_unlock_lock_2"
        assert cache.add(lock_key, 1, timeout=30)
        with login_as_user(app) as client:
            r = client.post("/api/v1/unlocks", json={"target": 1, "type": "hints"})
            assert r.status_code == 429
            assert Unlocks.query.count() == 0
            assert Awards.query.count() == 1

            cache.delete(lock_key)
            r = client.post("/api/v1/unlocks", json={"target": 1, "type": "hints"})
            assert r.status_code == 200
            assert Unlocks.query.count() == 1

        # The lock is released once the unlock has been processed
        assert cache.get(lock_key) is None
    destroy_ctfd(app)


def test_api_unlock_hints_race_cannot_overspend():
    """Test that concurrent hint unlocks cannot buy more hints than the account
    can afford or take the account's score below zero"""

    class RedisConfig(TestingConfig):
        REDIS_URL = "redis://localhost:6379/1"
        CACHE_REDIS_URL = "redis://localhost:6379/1"
        CACHE_TYPE = "redis"

    try:
        app = create_ctfd(config=RedisConfig)
    except ConnectionError:
        print("Failed to connect to redis. Skipping test.")
        return

    if app.config["SQLALCHEMY_DATABASE_URI"].startswith("sqlite"):
        destroy_ctfd(app)
        pytest.skip(
            "Race requires a concurrent database backend (TESTING_DATABASE_URL)"
        )
    with app.app_context():
        gen_challenge(app.db)
        hints = 10
        for _ in range(hints):
            gen_hint(app.db, challenge_id=1, cost=10)
        register_user(app)
        # Exactly enough points for one hint
        gen_award(app.db, user_id=2, value=10)
        client = login_as_user(app)

        session_cookie = next(
            cookie.value for cookie in client.cookie_jar if cookie.name == "session"
        )

        release = threading.Barrier(hints)

        def worker(hint_id):
            with app.app_context(), app.test_client() as tclient:
                tclient.set_cookie("localhost", "session", session_cookie)
                release.wait(timeout=10)
                tclient.post(
                    "/api/v1/unlocks", json={"target": hint_id, "type": "hints"}
                )

        threads = [
            threading.Thread(target=worker, args=(hint_id,))
            for hint_id in range(1, hints + 1)
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=30)

        assert not any(thread.is_alive() for thread in threads)

        # 10 points buy exactly one 10 point hint, regardless of concurrency
        assert Unlocks.query.count() == 1
        assert sum(award.value for award in Awards.query.filter_by(user_id=2)) == 0
    destroy_ctfd(app)
