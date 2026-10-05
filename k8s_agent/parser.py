"""
Log parsing engine for standard and Kubernetes-specific log formats.
"""

from __future__ import annotations

import json
import re
from typing import Iterable, List, Optional

from .models import LogEntry

# CRI-O / containerd log regex: 2026-10-04T12:00:00.123456789Z stdout F log message
CRI_LOG_PATTERN = re.compile(
    r"^(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2}))\s+"
    r"(?P<stream>stdout|stderr)\s+"
    r"(?P<flag>[FP])\s+"
    r"(?P<message>.*)$"
)

# Kubelet / klog format: E1004 12:00:00.123456 1234 file.go:123] message
KLOG_PATTERN = re.compile(
    r"^(?P<severity>[IWEF])(?P<month_day>\d{4})\s+(?P<time>\d{2}:\d{2}:\d{2}\.\d+)\s+"
    r"(?P<pid>\d+)\s+(?P<source>[^:\]]+:\d+)\]\s+(?P<message>.*)$"
)

# ISO Timestamp prefix: 2026-10-04T12:00:00.123Z or 2026-10-04 12:00:00 [ERROR] ...
ISO_PREFIX_PATTERN = re.compile(
    r"^(?P<timestamp>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?)\s+"
    r"(?:\[?(?P<level>FATAL|CRITICAL|ERROR|ERR|WARN|WARNING|INFO|DEBUG|TRACE)\]?\s+)?(?P<message>.*)$",
    re.IGNORECASE,
)

# Pod / Namespace extraction patterns
POD_PATTERN = re.compile(r"(?:pod[/:= ]+|podName[=:]\s*|in pod\s+)[\"']?([a-z0-9](?:[-a-z0-9]*[a-z0-9])?(?:-[a-z0-9]{5,10}-[a-z0-9]{5})?)[\"']?", re.IGNORECASE)
NAMESPACE_PATTERN = re.compile(r"(?:namespace[/:= ]+|ns[=:]\s*|in namespace\s+)[\"']?([a-z0-9](?:[-a-z0-9]*[a-z0-9])?)[\"']?", re.IGNORECASE)
CONTAINER_PATTERN = re.compile(r"(?:container[/:= ]+|containerName[=:]\s*|failed container[= ])[\"']?([a-z0-9](?:[-a-z0-9]*[a-z0-9])?)[\"']?", re.IGNORECASE)

KLOG_SEVERITY_MAP = {
    "I": "INFO",
    "W": "WARN",
    "E": "ERROR",
    "F": "FATAL",
}


class LogParser:
    """Parses raw Kubernetes log lines into structured LogEntry models."""

    @classmethod
    def parse_lines(cls, lines: Iterable[str]) -> List[LogEntry]:
        entries: List[LogEntry] = []
        for line_num, raw_line in enumerate(lines, start=1):
            stripped = raw_line.rstrip("\r\n")
            if not stripped.strip():
                continue
            entry = cls.parse_line(stripped, line_num)
            entries.append(entry)
        return entries

    @classmethod
    def parse_text(cls, text: str) -> List[LogEntry]:
        return cls.parse_lines(text.splitlines())

    @classmethod
    def parse_line(cls, line: str, line_number: int = 1) -> LogEntry:
        # Check if line is JSON
        trimmed = line.strip()
        if (trimmed.startswith("{") and trimmed.endswith("}")) or (
            trimmed.startswith("[") and trimmed.endswith("]")
        ):
            try:
                data = json.loads(trimmed)
                if isinstance(data, dict):
                    return cls._parse_json_entry(data, line, line_number)
            except Exception:
                pass

        # Check CRI format
        cri_match = CRI_LOG_PATTERN.match(line)
        if cri_match:
            timestamp = cri_match.group("timestamp")
            stream = cri_match.group("stream")
            message = cri_match.group("message")
            level = "ERROR" if stream == "stderr" else cls._detect_level(message)
            pod = cls._extract_pod(message)
            ns = cls._extract_namespace(message)
            container = cls._extract_container(message)
            return LogEntry(
                line_number=line_number,
                raw_text=line,
                message=message,
                timestamp=timestamp,
                level=level,
                stream=stream,
                pod_name=pod,
                namespace=ns,
                container=container,
            )

        # Check klog format
        klog_match = KLOG_PATTERN.match(line)
        if klog_match:
            sev_char = klog_match.group("severity")
            level = KLOG_SEVERITY_MAP.get(sev_char, "INFO")
            timestamp = f"{klog_match.group('month_day')} {klog_match.group('time')}"
            message = klog_match.group("message")
            pod = cls._extract_pod(message)
            ns = cls._extract_namespace(message)
            return LogEntry(
                line_number=line_number,
                raw_text=line,
                message=message,
                timestamp=timestamp,
                level=level,
                pod_name=pod,
                namespace=ns,
            )

        # Check ISO timestamp format
        iso_match = ISO_PREFIX_PATTERN.match(line)
        if iso_match:
            timestamp = iso_match.group("timestamp")
            raw_level = iso_match.group("level")
            message = iso_match.group("message")
            level = cls._normalize_level(raw_level) if raw_level else cls._detect_level(message)
            pod = cls._extract_pod(line)
            ns = cls._extract_namespace(line)
            return LogEntry(
                line_number=line_number,
                raw_text=line,
                message=message,
                timestamp=timestamp,
                level=level,
                pod_name=pod,
                namespace=ns,
            )

        # Fallback to plain text line
        level = cls._detect_level(line)
        pod = cls._extract_pod(line)
        ns = cls._extract_namespace(line)
        return LogEntry(
            line_number=line_number,
            raw_text=line,
            message=line,
            level=level,
            pod_name=pod,
            namespace=ns,
        )

    @classmethod
    def _parse_json_entry(cls, data: dict, raw_text: str, line_number: int) -> LogEntry:
        # Check standard json keys
        timestamp = (
            data.get("timestamp")
            or data.get("time")
            or data.get("@timestamp")
            or data.get("ts")
            or data.get("date")
        )
        if timestamp is not None:
            timestamp = str(timestamp)

        raw_level = (
            data.get("level")
            or data.get("severity")
            or data.get("log_level")
            or data.get("loglevel")
            or "INFO"
        )
        level = cls._normalize_level(str(raw_level))

        message = (
            data.get("message")
            or data.get("msg")
            or data.get("log")
            or data.get("error")
            or json.dumps(data)
        )
        if not isinstance(message, str):
            message = str(message)

        pod = (
            data.get("pod")
            or data.get("pod_name")
            or data.get("podName")
            or cls._extract_pod(raw_text)
        )
        ns = (
            data.get("namespace")
            or data.get("ns")
            or cls._extract_namespace(raw_text)
        )
        container = (
            data.get("container")
            or data.get("container_name")
            or data.get("containerName")
        )

        return LogEntry(
            line_number=line_number,
            raw_text=raw_text,
            message=message,
            timestamp=timestamp,
            level=level,
            pod_name=str(pod) if pod else None,
            namespace=str(ns) if ns else None,
            container=str(container) if container else None,
            is_json=True,
            structured_data=data,
        )

    @staticmethod
    def _normalize_level(raw_level: str) -> str:
        lvl = raw_level.strip().upper()
        if lvl in ("FATAL", "CRITICAL", "PANIC"):
            return "FATAL"
        if lvl in ("ERROR", "ERR"):
            return "ERROR"
        if lvl in ("WARN", "WARNING"):
            return "WARN"
        if lvl in ("INFO", "NOTICE"):
            return "INFO"
        if lvl in ("DEBUG", "TRACE"):
            return "DEBUG"
        return "INFO"

    @classmethod
    def _detect_level(cls, text: str) -> str:
        upper = text.upper()
        if any(w in upper for w in ["PANIC:", "FATAL:", "CRITICAL:", "FATAL "]):
            return "FATAL"
        if any(w in upper for w in ["ERROR", "ERR:", "EXCEPTION", "FAILED", "FAILURE"]):
            return "ERROR"
        if any(w in upper for w in ["WARN", "WARNING"]):
            return "WARN"
        return "INFO"

    @classmethod
    def _extract_pod(cls, text: str) -> Optional[str]:
        m = POD_PATTERN.search(text)
        if m:
            val = m.group(1).strip()
            # Ignore trivial false matches
            if val.lower() not in ("failed", "restart", "ready", "started", "killing", "crashloopbackoff"):
                return val
        # Check bracketed pod pattern e.g. [app-name-hash-random]
        bm = re.search(r"\[([a-z0-9](?:[-a-z0-9]*[a-z0-9])?-[a-z0-9]{5,10}-[a-z0-9]{5})\]", text, re.IGNORECASE)
        if bm:
            return bm.group(1).strip()
        return None

    @classmethod
    def _extract_namespace(cls, text: str) -> Optional[str]:
        m = NAMESPACE_PATTERN.search(text)
        if m:
            val = m.group(1).strip()
            return val
        return None

    @classmethod
    def _extract_container(cls, text: str) -> Optional[str]:
        m = CONTAINER_PATTERN.search(text)
        return m.group(1).strip() if m else None
