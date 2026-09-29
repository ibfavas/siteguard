"""Pure presentation helpers for the SiteGuard UI.

Kept free of Flask/SQLite imports so the logic is unit-testable without
booting the app (importing app.py starts the scheduler).
"""

GRADE_SCORE = {"A": 5, "B": 4, "C": 3, "D": 2, "F": 1}
SCORE_GRADE = {v: k for k, v in GRADE_SCORE.items()}


def average_grade(grades):
    """Mean grade letter for a list of grade letters. None when empty."""
    scores = [GRADE_SCORE.get(g) for g in (grades or [])]
    scores = [s for s in scores if s]
    if not scores:
        return None
    return SCORE_GRADE[round(sum(scores) / len(scores))]


def sites_added_this_month(sites, now=None):
    """Count of sites whose created_at falls in the current UTC month."""
    from datetime import datetime, timezone
    now = now or datetime.now(timezone.utc)
    count = 0
    for s in sites:
        created = s.get("created_at") if isinstance(s, dict) else None
        try:
            dt = datetime.fromisoformat(str(created))
        except Exception:
            continue
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        if dt.year == now.year and dt.month == now.month:
            count += 1
    return count


def sparkline_svg(grades):
    """Inline SVG trend sparkline for grades, oldest first.

    Returns "" when there is nothing meaningful to draw (fewer than two
    real grades). The line is green when the trend improved, red when it
    got worse, grey when flat.
    """
    scores = [GRADE_SCORE.get(g) for g in (grades or [])]
    scores = [s for s in scores if s]
    if len(scores) < 2:
        return ""
    w, h, pad = 64, 22, 3
    n = len(scores)
    xs = [pad + i * (w - 2 * pad) / (n - 1) for i in range(n)]
    ys = [pad + (5 - s) * (h - 2 * pad) / 4 for s in scores]
    points = " ".join(f"{x:.1f},{y:.1f}" for x, y in zip(xs, ys))
    first, last = scores[0], scores[-1]
    if last > first:
        color = "#15803d"
    elif last < first:
        color = "#c0392b"
    else:
        color = "#6b7a8d"
    label = " \u2192 ".join(str(g) for g in grades)
    return (
        f'<svg class="spark" width="{w}" height="{h}" viewBox="0 0 {w} {h}"'
        f' role="img" aria-label="grade trend: {label}">'
        f'<polyline points="{points}" fill="none" stroke="{color}"'
        f' stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>'
        f'<circle cx="{xs[-1]:.1f}" cy="{ys[-1]:.1f}" r="2.6" fill="{color}"/>'
        "</svg>"
    )
