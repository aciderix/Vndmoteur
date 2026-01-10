#!/usr/bin/env python3
"""
VND Scene Renderer - HTML/SVG Visualization
============================================

Generates interactive HTML visualization of VND scenes.
Shows hotspots, polygons, and scene structure.

Usage:
    python vnd_renderer.py couleurs1.vnd
    # Opens output.html in browser or creates vnd_scene.html
"""

import sys
import os
import struct
import re
import webbrowser
from pathlib import Path
from dataclasses import dataclass
from typing import List, Tuple, Optional, Dict


@dataclass
class Polygon:
    points: List[Tuple[int, int]]

    @property
    def svg_points(self) -> str:
        return " ".join(f"{x},{y}" for x, y in self.points)

    @property
    def bounding_box(self) -> Tuple[int, int, int, int]:
        if not self.points:
            return (0, 0, 0, 0)
        xs = [p[0] for p in self.points]
        ys = [p[1] for p in self.points]
        return (min(xs), min(ys), max(xs), max(ys))


@dataclass
class Hotspot:
    name: str
    text_bbox: Tuple[int, int, int, int]
    polygon: Optional[Polygon]
    commands: List[str]


@dataclass
class Scene:
    name: str
    background: Optional[str]
    audio: Optional[str]
    hotspots: List[Hotspot]


class VNDRenderer:
    """Render VND scenes to HTML/SVG"""

    def __init__(self, filepath: str):
        self.filepath = filepath
        self.data = b''
        self.scenes: List[Scene] = []
        self.variables: List[str] = []
        self.width = 640
        self.height = 480

    def read_uint32(self, offset: int) -> int:
        if offset + 4 > len(self.data):
            return 0
        return struct.unpack_from('<I', self.data, offset)[0]

    def read_int32(self, offset: int) -> int:
        if offset + 4 > len(self.data):
            return 0
        return struct.unpack_from('<i', self.data, offset)[0]

    def parse_polygon_at(self, offset: int) -> Optional[Polygon]:
        """Parse polygon at offset"""
        if offset + 4 > len(self.data):
            return None

        count = self.read_uint32(offset)
        if count < 3 or count > 30:
            return None

        if offset + 4 + count * 8 > len(self.data):
            return None

        points = []
        pos = offset + 4
        for _ in range(count):
            x = self.read_int32(pos)
            y = self.read_int32(pos + 4)
            pos += 8

            if not (-100 <= x <= 2000 and -100 <= y <= 1000):
                return None
            points.append((x, y))

        return Polygon(points=points)

    def find_hotspots(self) -> List[Hotspot]:
        """Find all hotspots with polygons"""
        hotspots = []

        # Pattern: "X Y W H 0 Name"
        pattern = rb'(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+0\s+([A-Za-z][^\x00\n\r]{1,50})'

        for match in re.finditer(pattern, self.data):
            x1, y1, x2, y2 = map(int, match.groups()[:4])
            name = match.group(5).decode('latin-1', errors='replace').strip()

            if len(name) > 50 or not name[0].isalpha():
                continue

            # Find polygon after text
            text_end = match.end()
            polygon = None
            for scan in range(text_end, min(text_end + 50, len(self.data) - 4)):
                polygon = self.parse_polygon_at(scan)
                if polygon:
                    break

            # Find associated commands (conditionals before this hotspot)
            commands = []
            search_start = max(0, match.start() - 500)
            search_data = self.data[search_start:match.start()].decode('latin-1', errors='replace')
            for line in search_data.split('\x00'):
                if 'then' in line.lower() and any(kw in line.lower() for kw in ['scene', 'set_var', 'addbmp', 'playwav']):
                    commands.append(line.strip())

            hotspots.append(Hotspot(
                name=name,
                text_bbox=(x1, y1, x2, y2),
                polygon=polygon,
                commands=commands[-3:] if commands else []
            ))

        return hotspots

    def find_backgrounds(self) -> List[str]:
        """Find background image references"""
        backgrounds = []
        pattern = rb'euroland\\[a-zA-Z0-9_]+\.bmp'
        for match in re.finditer(pattern, self.data):
            bg = match.group().decode('latin-1')
            if bg not in backgrounds:
                backgrounds.append(bg)
        return backgrounds

    def parse(self):
        """Parse the VND file"""
        with open(self.filepath, 'rb') as f:
            self.data = f.read()

        # Get screen dimensions from header
        if len(self.data) > 0x60:
            self.width = self.read_uint32(0x4f)
            self.height = self.read_uint32(0x53)
            if self.width == 0 or self.width > 2000:
                self.width = 640
            if self.height == 0 or self.height > 1500:
                self.height = 480

        # Find hotspots
        hotspots = self.find_hotspots()

        # Find backgrounds
        backgrounds = self.find_backgrounds()

        # Create main scene
        self.scenes.append(Scene(
            name="Main Scene",
            background=backgrounds[0] if backgrounds else None,
            audio=None,
            hotspots=hotspots
        ))

    def generate_html(self) -> str:
        """Generate interactive HTML visualization"""

        # Color palette for polygons
        colors = [
            '#FF6B6B', '#4ECDC4', '#45B7D1', '#96CEB4', '#FFEAA7',
            '#DDA0DD', '#98D8C8', '#F7DC6F', '#BB8FCE', '#85C1E9',
            '#F8B500', '#00CED1', '#FF69B4', '#32CD32', '#FFD700'
        ]

        html = f'''<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>VND Scene Renderer - {os.path.basename(self.filepath)}</title>
    <style>
        body {{
            font-family: 'Segoe UI', Arial, sans-serif;
            background: #1a1a2e;
            color: #eee;
            margin: 0;
            padding: 20px;
        }}
        h1 {{
            color: #4ECDC4;
            margin-bottom: 10px;
        }}
        .container {{
            display: flex;
            gap: 20px;
        }}
        .scene-view {{
            background: #16213e;
            border-radius: 8px;
            padding: 10px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.3);
        }}
        .info-panel {{
            background: #16213e;
            border-radius: 8px;
            padding: 15px;
            width: 350px;
            max-height: 600px;
            overflow-y: auto;
        }}
        .hotspot-list {{
            list-style: none;
            padding: 0;
            margin: 0;
        }}
        .hotspot-item {{
            padding: 8px 12px;
            margin: 4px 0;
            background: #0f3460;
            border-radius: 4px;
            cursor: pointer;
            transition: background 0.2s;
        }}
        .hotspot-item:hover {{
            background: #1a4a7a;
        }}
        .hotspot-item.active {{
            background: #4ECDC4;
            color: #1a1a2e;
        }}
        .polygon {{
            fill-opacity: 0.3;
            stroke-width: 2;
            cursor: pointer;
            transition: fill-opacity 0.2s;
        }}
        .polygon:hover {{
            fill-opacity: 0.6;
        }}
        .label {{
            font-size: 11px;
            fill: white;
            text-shadow: 1px 1px 2px black;
            pointer-events: none;
        }}
        .stats {{
            background: #0f3460;
            padding: 10px;
            border-radius: 4px;
            margin-bottom: 15px;
        }}
        .tooltip {{
            position: absolute;
            background: rgba(0,0,0,0.9);
            color: white;
            padding: 10px;
            border-radius: 4px;
            font-size: 12px;
            max-width: 300px;
            display: none;
            z-index: 1000;
        }}
        #details {{
            margin-top: 15px;
            padding: 10px;
            background: #0f3460;
            border-radius: 4px;
            min-height: 100px;
        }}
        .cmd {{
            font-family: monospace;
            font-size: 11px;
            background: #1a1a2e;
            padding: 4px 8px;
            margin: 2px 0;
            border-radius: 3px;
            word-break: break-all;
        }}
    </style>
</head>
<body>
    <h1>🎮 VND Scene Renderer</h1>
    <p>File: <code>{os.path.basename(self.filepath)}</code> |
       Size: {len(self.data):,} bytes |
       Screen: {self.width}x{self.height}</p>

    <div class="container">
        <div class="scene-view">
            <svg id="scene" width="{self.width}" height="{self.height}"
                 style="background: #2d2d44; border: 1px solid #4ECDC4;">

                <!-- Grid -->
                <defs>
                    <pattern id="grid" width="50" height="50" patternUnits="userSpaceOnUse">
                        <path d="M 50 0 L 0 0 0 50" fill="none" stroke="#3a3a5a" stroke-width="0.5"/>
                    </pattern>
                </defs>
                <rect width="100%" height="100%" fill="url(#grid)"/>

                <!-- Polygons -->
'''

        # Add polygons
        for i, scene in enumerate(self.scenes):
            for j, hs in enumerate(scene.hotspots):
                if hs.polygon:
                    color = colors[j % len(colors)]
                    bbox = hs.polygon.bounding_box
                    center_x = (bbox[0] + bbox[2]) // 2
                    center_y = (bbox[1] + bbox[3]) // 2

                    html += f'''
                <g class="hotspot-group" data-index="{j}">
                    <polygon class="polygon"
                             points="{hs.polygon.svg_points}"
                             fill="{color}"
                             stroke="{color}"
                             data-name="{hs.name}"
                             data-commands="{'; '.join(hs.commands[:2])}"
                             onclick="selectHotspot({j})"/>
                    <text class="label" x="{center_x}" y="{center_y}"
                          text-anchor="middle">{hs.name[:15]}</text>
                </g>
'''

        html += '''
            </svg>
        </div>

        <div class="info-panel">
            <div class="stats">
'''

        total_hotspots = sum(len(s.hotspots) for s in self.scenes)
        with_polygon = sum(1 for s in self.scenes for h in s.hotspots if h.polygon)

        html += f'''
                <strong>📊 Statistics</strong><br>
                Hotspots: {total_hotspots}<br>
                With Polygons: {with_polygon}<br>
                Backgrounds: {len(self.find_backgrounds())}
            </div>

            <strong>🎯 Hotspots</strong>
            <ul class="hotspot-list">
'''

        for i, scene in enumerate(self.scenes):
            for j, hs in enumerate(scene.hotspots):
                poly_info = f"({hs.polygon.bounding_box[0]},{hs.polygon.bounding_box[1]})" if hs.polygon else "(no poly)"
                html += f'''
                <li class="hotspot-item" data-index="{j}" onclick="selectHotspot({j})">
                    <strong>{hs.name[:25]}</strong> {poly_info}
                </li>
'''

        html += '''
            </ul>

            <div id="details">
                <em>Click a hotspot to see details</em>
            </div>
        </div>
    </div>

    <div id="tooltip" class="tooltip"></div>

    <script>
        const hotspots = ''' + self._hotspots_to_json() + ''';

        function selectHotspot(index) {
            // Update list selection
            document.querySelectorAll('.hotspot-item').forEach((el, i) => {
                el.classList.toggle('active', i === index);
            });

            // Update details
            const hs = hotspots[index];
            let html = '<strong>' + hs.name + '</strong><br><br>';
            html += '<b>Text BBox:</b> (' + hs.text_bbox.join(', ') + ')<br>';
            if (hs.polygon) {
                html += '<b>Polygon:</b> ' + hs.polygon.length + ' points<br>';
                html += '<b>BBox:</b> ' + hs.polygon_bbox.join(', ') + '<br>';
            }
            if (hs.commands.length > 0) {
                html += '<br><b>Commands:</b><br>';
                hs.commands.forEach(cmd => {
                    html += '<div class="cmd">' + cmd + '</div>';
                });
            }
            document.getElementById('details').innerHTML = html;

            // Highlight polygon
            document.querySelectorAll('.polygon').forEach((el, i) => {
                el.style.strokeWidth = (i === index) ? '4' : '2';
                el.style.fillOpacity = (i === index) ? '0.6' : '0.3';
            });
        }

        // Tooltip on hover
        document.querySelectorAll('.polygon').forEach(poly => {
            poly.addEventListener('mousemove', (e) => {
                const tooltip = document.getElementById('tooltip');
                tooltip.innerHTML = poly.dataset.name;
                tooltip.style.left = (e.pageX + 10) + 'px';
                tooltip.style.top = (e.pageY + 10) + 'px';
                tooltip.style.display = 'block';
            });
            poly.addEventListener('mouseout', () => {
                document.getElementById('tooltip').style.display = 'none';
            });
        });
    </script>
</body>
</html>
'''
        return html

    def _hotspots_to_json(self) -> str:
        """Convert hotspots to JSON for JavaScript"""
        import json
        result = []
        for scene in self.scenes:
            for hs in scene.hotspots:
                item = {
                    'name': hs.name,
                    'text_bbox': list(hs.text_bbox),
                    'polygon': hs.polygon.points if hs.polygon else None,
                    'polygon_bbox': list(hs.polygon.bounding_box) if hs.polygon else None,
                    'commands': hs.commands
                }
                result.append(item)
        return json.dumps(result)

    def render(self, output_path: str = None) -> str:
        """Parse and render to HTML file"""
        self.parse()
        html = self.generate_html()

        if output_path is None:
            output_path = Path(self.filepath).stem + '_scene.html'

        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html)

        return output_path


def main():
    if len(sys.argv) < 2:
        print("Usage: python vnd_renderer.py <file.vnd> [output.html]")
        print("\nGenerates interactive HTML visualization of VND scenes.")
        sys.exit(1)

    filepath = sys.argv[1]
    output = sys.argv[2] if len(sys.argv) > 2 else None

    renderer = VNDRenderer(filepath)
    output_path = renderer.render(output)

    print(f"Generated: {output_path}")
    print(f"Scenes: {len(renderer.scenes)}")
    print(f"Hotspots: {sum(len(s.hotspots) for s in renderer.scenes)}")
    print(f"With polygons: {sum(1 for s in renderer.scenes for h in s.hotspots if h.polygon)}")

    # Try to open in browser
    try:
        webbrowser.open(f'file://{os.path.abspath(output_path)}')
        print(f"\nOpened in browser: {output_path}")
    except:
        print(f"\nOpen in browser: {output_path}")


if __name__ == "__main__":
    main()
