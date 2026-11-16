"""Render the repository architecture to SVG and PNG using Pillow."""
from pathlib import Path
from html import escape
import math

from PIL import Image, ImageDraw, ImageFont

ROOT = Path(__file__).resolve().parent
W, H, SCALE = 1800, 1330, 2
canvas = Image.new("RGB", (W * SCALE, H * SCALE), "#f6f8fc")
draw = ImageDraw.Draw(canvas)
svg = [f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" viewBox="0 0 {W} {H}" role="img" aria-labelledby="title desc">',
       '<title id="title">CloudShield solution architecture</title>',
       '<desc id="desc">HTTPS clients reach Nginx, Waitress and a Flask application. Completed requests pass through collection, detection, scoring and response logic in one transaction. SQLite is shared by the web application, a separate maintenance worker and administrator queries. EC2 is the deployment target.</desc>',
       f'<rect width="{W}" height="{H}" fill="#f6f8fc"/>']
INK, MUTED, BLUE, GREEN, ORANGE = "#182b49", "#526580", "#356ee6", "#128479", "#b65e16"


def font(size, bold=False):
    name = "segoeuib.ttf" if bold else "segoeui.ttf"
    return ImageFont.truetype(str(Path("C:/Windows/Fonts") / name), size * SCALE)


def text(x, y, value, size=22, color=INK, bold=False):
    draw.text((x * SCALE, y * SCALE), value, font=font(size, bold), fill=color, anchor="lt")
    svg.append(f'<text x="{x}" y="{y}" font-family="Segoe UI, Arial, sans-serif" font-size="{size}" font-weight="{700 if bold else 400}" fill="{color}" dominant-baseline="text-before-edge">{escape(value)}</text>')
    bbox = draw.textbbox((0, 0), value, font=font(size, bold))
    assert x + (bbox[2] - bbox[0]) / SCALE <= W - 30, value


def rect(x, y, w, h, fill="#fff", border="#d9e2ef", radius=16, dashed=False):
    draw.rounded_rectangle((x*SCALE, y*SCALE, (x+w)*SCALE, (y+h)*SCALE), radius=radius*SCALE, fill=fill, outline=border, width=2*SCALE)
    dash = ' stroke-dasharray="9 7"' if dashed else ""
    svg.append(f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="{radius}" fill="{fill}" stroke="{border}" stroke-width="2"{dash}/>')


def line(points, color=BLUE, dashed=False, arrow=True):
    scaled = [(x*SCALE, y*SCALE) for x, y in points]
    if dashed:
        for start, end in zip(scaled, scaled[1:]):
            length = math.dist(start, end)
            for distance in range(0, int(length), 16*SCALE):
                a, b = distance/length, min(distance+9*SCALE, length)/length
                draw.line([(start[0]+(end[0]-start[0])*a, start[1]+(end[1]-start[1])*a), (start[0]+(end[0]-start[0])*b, start[1]+(end[1]-start[1])*b)], fill=color, width=3*SCALE)
    else:
        draw.line(scaled, fill=color, width=3*SCALE, joint="curve")
    dash = ' stroke-dasharray="9 7"' if dashed else ""
    svg.append(f'<polyline points="{" ".join(f"{x},{y}" for x,y in points)}" fill="none" stroke="{color}" stroke-width="3"{dash}/>')
    if arrow:
        (ax, ay), (bx, by) = points[-2:]
        angle = math.atan2(by-ay, bx-ax)
        triangle = [(bx, by), (bx-12*math.cos(angle)+6*math.sin(angle), by-12*math.sin(angle)-6*math.cos(angle)), (bx-12*math.cos(angle)-6*math.sin(angle), by-12*math.sin(angle)+6*math.cos(angle))]
        draw.polygon([(x*SCALE, y*SCALE) for x,y in triangle], fill=color)
        svg.append(f'<polygon points="{" ".join(f"{x},{y}" for x,y in triangle)}" fill="{color}"/>')


def card(x, y, w, h, label, title, rows, accent=BLUE, fill="#fff"):
    rect(x, y, w, h, fill)
    text(x+22, y+17, label.upper(), 15, accent, True)
    title_size = 25
    while draw.textlength(title, font=font(title_size, True)) / SCALE > w-44:
        title_size -= 1
    text(x+22, y+45, title, title_size, INK, True)
    for index, row in enumerate(rows):
        size = 19
        assert draw.textlength(row, font=font(size)) / SCALE <= w-44, (title, row)
        text(x+22, y+85+index*28, row, size, MUTED)


text(65, 35, "CloudShield", 44, INK, True)
text(330, 48, "Solution architecture", 30, MUTED)
text(65, 96, "Application telemetry → explainable risk → adaptive response", 23, MUTED)

card(75, 160, 330, 110, "client", "Users / demo browser", ["Login, requests, access attempts"])
card(1270, 160, 450, 110, "administrator", "Admin browser", ["HTML + JavaScript + Chart.js"])

rect(45, 320, 1710, 865, "#eef3fb", "#b7c7dd", 22, True)
text(285, 337, "SINGLE EC2 HOST · DEPLOYMENT TARGET", 17, MUTED, True)
text(1270, 337, "systemd supervises web + worker", 18, MUTED)
line([(240, 270), (240, 390)])
line([(1495, 270), (1495, 297), (240, 297)], arrow=False)
text(710, 270, "HTTPS requests / responses", 18, BLUE)

card(75, 390, 320, 145, "edge", "Nginx", ["TLS termination", "Trusted proxy headers"])
card(450, 390, 305, 145, "wsgi server", "Waitress", ["Loopback 127.0.0.1:8000", "Runs the Flask application"])
card(810, 390, 445, 145, "flask · before request", "Authentication + enforcement", ["Session user + current IP / user blocks", "Catch-up maintenance; blocked → 429"])
card(1310, 390, 410, 145, "flask · routes", "Application + admin APIs", ["Role checks + CSRF protection", "Workspace, login, dashboard, JSON"])
line([(395, 462), (450, 462)])
line([(755, 462), (810, 462)])
line([(1255, 462), (1310, 462)])

text(550, 548, "after_request · capture the completed response", 20, BLUE)

rect(65, 617, 1665, 310, "#fff", "#c7d7ed", 18)
line([(1515, 535), (1515, 580), (247, 580), (247, 670)])
text(475, 628, "FLASK TELEMETRY PIPELINE · ONE ATOMIC SQLITE TRANSACTION", 16, BLUE, True)
card(85, 670, 335, 185, "01 · collection", "Normalize + log", ["Request ID, UTC time, IP / user", "Route, status, outcome", "Allowlisted metadata only"])
card(470, 670, 335, 185, "02 · detection", "Evaluate four rules", ["Failed logins; rapid requests", "Restricted access; new context", "Windows, cooldowns, evidence"])
card(855, 670, 350, 185, "03 · risk scoring", "Explainable risk 0–100", ["Separate IP + verified-user scores", "Finding weights + quiet reductions", "Effective risk = higher score"])
card(1255, 670, 455, 185, "04 · incidents + response", "Decide + record actions", ["Group evidence into IP incident timelines", "Monitor / alert / temporary block", "Five-minute block on subsequent requests"], ORANGE)
for start, end in [(420, 470), (805, 855), (1205, 1255)]:
    line([(start, 762), (end, 762)])
text(87, 881, "Events, findings, source history, scores and response records commit together. Blocked requests are logged without increasing risk.", 20, MUTED)

line([(637, 927), (637, 1007)], GREEN)
line([(1030, 927), (1030, 1007)], GREEN)
line([(1482, 927), (1482, 959), (1150, 959), (1150, 1007)], GREEN)
text(690, 960, "Read + persist evidence and state", 18, GREEN)

card(85, 1007, 335, 145, "separate process · every 10s", "Risk maintenance worker", ["Quiet decay; incident closure", "Block expiry / renewal"], GREEN, "#effaf7")
card(475, 1007, 730, 145, "shared persistent store", "SQLite database", ["Users · events · findings · source history · versioned configuration", "Risk ledger · incidents · alerts · blocks · action audits"], GREEN, "#effaf7")
card(1255, 1007, 455, 145, "admin-only dashboard + json apis", "Investigate + acknowledge", ["Risk charts, evidence and incident timelines", "Browser polls /api/dashboard every 5s"])
line([(420, 1080), (475, 1080)], GREEN)
line([(1205, 1080), (1255, 1080)], GREEN)

text(75, 1200, "POLICY", 15, BLUE, True)
text(75, 1226, "Versioned rules.json + policy.json", 19, MUTED)
text(610, 1200, "OPERATIONS", 15, GREEN, True)
text(610, 1226, "Daily database backups · audited recovery CLI", 19, MUTED)
text(1245, 1200, "DEFAULT RESPONSE LEVELS", 15, ORANGE, True)
text(1245, 1226, "0–24 allow · 25–49 monitor", 19, MUTED)
text(1245, 1254, "50–74 alert · 75–100 alert + block", 19, MUTED)
text(75, 1289, "Scope: application-level protection. CAPTCHA is recommended; email, WAF/IAM, ML and multi-cloud integrations are future work.", 19, MUTED)

svg.append("</svg>")
(ROOT / "architecture.svg").write_text("\n".join(svg), encoding="utf-8")
canvas.resize((W, H), Image.Resampling.LANCZOS).save(ROOT / "architecture.png")
print("Rendered docs/architecture.svg and docs/architecture.png")
