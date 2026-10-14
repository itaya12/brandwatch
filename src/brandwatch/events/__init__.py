"""Scan events: the durable, replayable feed behind the Live Scan Console (spec §14)."""

from brandwatch.events.emitter import ScanEvent, ScanEventEmitter

__all__ = ["ScanEvent", "ScanEventEmitter"]
