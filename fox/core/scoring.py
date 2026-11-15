#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Scoring — one place where a score comes from.

Only findings that survived validation count: verified and observed
ones at full weight, false positives excluded entirely. The score
explains itself: every finding carries its severity, its evidence
and its validation status, so the report can say WHY a finding is
HIGH instead of just printing a number.
"""
WEIGHTS = {"critical": 25, "high": 15, "medium": 8, "low": 3, "info": 0}


def grade_for(score):
    if score is None:
        return "INCOMPLETE"
    if score >= 95:
        return "A+"
    if score >= 90:
        return "A"
    if score >= 80:
        return "B"
    if score >= 70:
        return "C"
    if score >= 60:
        return "D"
    return "F"


def score_findings(findings):
    """Score validated findings. Returns (score, grade, distribution)."""
    total = sum(WEIGHTS.get(f.get("severity"), 0) for f in findings)
    score = max(0, 100 - total)
    dist = {}
    for f in findings:
        dist[f["severity"]] = dist.get(f["severity"], 0) + 1
    return score, grade_for(score), dist
