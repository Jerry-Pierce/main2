#!/usr/bin/env python3
"""
Cutlet PWA 아이콘 생성 스크립트
SVG 아이콘을 다양한 사이즈의 PNG로 변환합니다.
"""

import os
from cairosvg import svg2png

def generate_icons():
    """SVG 아이콘을 다양한 사이즈의 PNG로 변환"""
    
    # 아이콘 사이즈 정의
    icon_sizes = {
        'icon-192x192.png': 192,
        'icon-512x512.png': 512,
        'shortcut-96x96.png': 96
    }
    
    # SVG 파일 경로
    svg_path = 'static/icons/icon.svg'
    
    if not os.path.exists(svg_path):
        print(f"❌ SVG 파일을 찾을 수 없습니다: {svg_path}")
        return False
    
    print("🎨 PWA 아이콘 생성 중...")
    
    for filename, size in icon_sizes.items():
        output_path = f'static/icons/{filename}'
        
        try:
            # SVG를 PNG로 변환
            svg2png(
                url=svg_path,
                write_to=output_path,
                output_width=size,
                output_height=size
            )
            print(f"✅ {filename} 생성 완료 ({size}x{size})")
            
        except Exception as e:
            print(f"❌ {filename} 생성 실패: {e}")
            return False
    
    print("🎉 모든 PWA 아이콘 생성 완료!")
    return True

if __name__ == "__main__":
    generate_icons()
