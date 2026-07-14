"""Export 7-4 HTML as viewer-stable rasterized A4 PDF pages."""

from __future__ import annotations

import base64
from pathlib import Path
from tempfile import TemporaryDirectory


_PDF_DPI = 144
_A4_PIXELS = (
    round(210 / 25.4 * _PDF_DPI),
    round(297 / 25.4 * _PDF_DPI),
)


def export_pdf(html_path: Path, pdf_path: Path) -> None:
    try:
        from playwright.sync_api import sync_playwright
    except ImportError as exc:  # pragma: no cover
        raise RuntimeError("Playwright is required to export the report PDF") from exc
    try:
        from PIL import Image
    except ImportError as exc:  # pragma: no cover
        raise RuntimeError("Pillow is required to assemble the report PDF") from exc

    pdf_path.parent.mkdir(parents=True, exist_ok=True)
    with TemporaryDirectory(prefix="argus-g74-pdf-") as temp_dir:
        page_images: list[Path] = []
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(
                headless=True,
                args=["--disable-gpu"],
            )
            context = browser.new_context(
                viewport={"width": 1280, "height": 1200},
                device_scale_factor=2,
            )
            page = context.new_page()
            page.goto(html_path.resolve().as_uri(), wait_until="load")
            page.emulate_media(media="screen")
            locators = page.locator(".page")
            page_count = locators.count()
            if page_count < 1:
                context.close()
                browser.close()
                raise RuntimeError("The rendered report contains no .page elements")

            for index in range(page_count):
                page.evaluate(
                    """(index) => {
                      let style = document.getElementById('argus-capture-page');
                      if (!style) {
                        style = document.createElement('style');
                        style.id = 'argus-capture-page';
                        document.head.appendChild(style);
                      }
                      style.textContent = `.page { display: none !important; }
                        .page:nth-child(${index + 1}) { display: flex !important; }`;
                    }""",
                    index,
                )
                screenshot = Path(temp_dir) / f"page-{index + 1:04d}.png"
                locators.nth(index).screenshot(path=str(screenshot), animations="disabled")
                with Image.open(screenshot) as source:
                    if source.mode == "RGBA":
                        opaque = Image.new("RGB", source.size, "white")
                        opaque.paste(source, mask=source.getchannel("A"))
                    else:
                        opaque = source.convert("RGB")
                    resized = opaque.resize(_A4_PIXELS, Image.Resampling.LANCZOS)
                    jpeg = Path(temp_dir) / f"page-{index + 1:04d}.jpg"
                    resized.save(jpeg, "JPEG", quality=95, subsampling=0)
                    page_images.append(jpeg)

            print_page = context.new_page()
            image_markup = "".join(
                f'<section><img src="data:image/jpeg;base64,{base64.b64encode(path.read_bytes()).decode("ascii")}"></section>'
                for path in page_images
            )
            print_page.set_content(
                f'''<!doctype html><html><head><style>
                @page {{ size: A4; margin: 0; }}
                * {{ box-sizing: border-box; }}
                html, body {{ margin: 0; padding: 0; }}
                section {{ margin: 0; width: 210mm; height: 297mm; overflow: hidden;
                  page-break-after: always; break-after: page; }}
                section:last-child {{ page-break-after: auto; break-after: auto; }}
                img {{ display: block; width: 210mm; height: 297mm; }}
                </style></head><body>{image_markup}</body></html>''',
                wait_until="load",
            )
            print_page.emulate_media(media="print")
            temp_output = pdf_path.with_suffix(pdf_path.suffix + ".tmp")
            print_page.pdf(
                path=str(temp_output),
                format="A4",
                print_background=True,
                margin={"top": "0", "right": "0", "bottom": "0", "left": "0"},
                prefer_css_page_size=True,
            )
            context.close()
            browser.close()

        temp_output.replace(pdf_path)
