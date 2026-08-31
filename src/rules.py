"""
Shared rule-evaluation helpers.

Both the data generator and the control-testing engine use these so that the
definition of "in scope" and "in violation" lives in exactly one place.
"""

from __future__ import annotations

import pandas as pd


def scope_mask(df: pd.DataFrame, scope: dict) -> pd.Series:
    """Boolean Series - rows that are in scope for a control ({} => all rows)."""
    mask = pd.Series(True, index=df.index)
    for col, val in scope.items():
        if isinstance(val, list):
            mask &= df[col].isin(val)
        else:
            mask &= df[col] == val
    return mask


def detect_mask(df: pd.DataFrame, detect: dict) -> pd.Series:
    """Boolean Series - rows that fail the control's detection rule."""
    kind = detect["type"]
    if kind == "eq":
        mask = pd.Series(True, index=df.index)
        for col, val in detect["cols"].items():
            mask &= df[col] == val
        return mask
    if kind == "gt":
        return df[detect["col"]] > detect["value"]
    if kind == "lt":
        return df[detect["col"]] < detect["value"]
    if kind == "isin":
        return df[detect["col"]].isin(detect["values"])
    raise ValueError(f"unknown detect type: {kind}")


def violation_mask(df: pd.DataFrame, control: dict) -> pd.Series:
    """Rows that are both in scope and in violation."""
    return scope_mask(df, control["scope"]) & detect_mask(df, control["detect"])


def scope_coercion_values(scope: dict) -> dict:
    """Concrete column values that place a row *in scope* (first option for lists)."""
    out = {}
    for col, val in scope.items():
        out[col] = val[0] if isinstance(val, list) else val
    return out
