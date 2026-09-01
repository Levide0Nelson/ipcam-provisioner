"""Fixtures partagées : config du site de démo + réseau simulé + talker HTTP."""

from __future__ import annotations

import asyncio

import pytest

from ipcam_provisioner.net import HttpTalker
from ipcam_provisioner.simulation.demo import build_demo_site, demo_config


@pytest.fixture
def config():
    cfg = demo_config()
    cfg.discovery.timeout_seconds = 0.3
    return cfg


@pytest.fixture
async def network(config):
    net = await build_demo_site(config)
    yield net
    await net.stop()


@pytest.fixture
async def talker(network):
    t = HttpTalker(network, timeout=1.0)
    yield t
    await t.aclose()


@pytest.fixture
def semaphore():
    return asyncio.Semaphore(50)
