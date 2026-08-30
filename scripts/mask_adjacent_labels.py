#!/usr/bin/env python3
"""
Mask Adjacent Labels (OpenCV + NumPy)
=====================================
Detects existing solid black redaction boxes in form images and dynamically
extends black boxes to the LEFT to obscure corresponding text labels (e.g. "Password",
"Credit Card Number") so VLMs cannot read the labels and hallucinate data.

Usage:
    python scripts/mask_adjacent_labels.py input_form.png -o masked_form.png
    python scripts/mask_adjacent_labels.py input_form.png --label-offset 300 --min-area 800
"""

import argparse
import sys
from pathlib import Path
from typing import List, Tuple, Optional

try:
    import cv2
    import numpy as np
except ImportError:
    print("[Error] Required libraries missing. Please install opencv-python and numpy:", file=sys.stderr)
    print("        pip install opencv-python-headless numpy", file=sys.stderr)
    sys.exit(1)


def mask_adjacent_labels(
    image: np.ndarray,
    label_offset: int = 250,
    min_area: int = 500,
    max_area_ratio: float = 0.9,
    color_threshold: int = 15,
    padding_y: int = 4,
) -> Tuple[np.ndarray, List[Tuple[int, int, int, int]]]:
    """
    Detects existing black redaction boxes and masks the text regions immediately
    to their left.

    Parameters:
        image (np.ndarray): BGR image loaded via cv2.imread.
        label_offset (int): Maximum horizontal pixel distance to extend leftward.
        min_area (int): Minimum contour area in pixels to qualify as a valid redaction box.
        max_area_ratio (float): Maximum bounding box area ratio (to ignore whole-image borders).
        color_threshold (int): Upper bound for B, G, R channels to consider a pixel "black" (0-255).
        padding_y (int): Extra vertical padding in pixels for the label mask to ensure full coverage.

    Returns:
        Tuple[np.ndarray, List[Tuple[int, int, int, int]]]:
            - Processed image with leftward masks applied.
            - List of new leftward bounding boxes (x1, y1, w, h).
    """
    if image is None or image.size == 0:
        raise ValueError("Invalid or empty image array provided.")

    height, width = image.shape[:2]
    total_image_area = height * width

    # Output image copy to preserve original if needed
    output_image = image.copy()

    # Step 1: Isolate pixels that are near strictly black (0, 0, 0)
    # Define lower and upper BGR bounds for black
    lower_black = np.array([0, 0, 0], dtype=np.uint8)
    upper_black = np.array([color_threshold, color_threshold, color_threshold], dtype=np.uint8)

    # Binary mask where 255 = black pixel, 0 = non-black
    black_mask = cv2.inRange(image, lower_black, upper_black)

    # Morphological closing to fill small internal gaps or anti-aliased edges
    kernel = cv2.getStructuringElement(cv2.MORPH_RECT, (3, 3))
    black_mask = cv2.morphologyEx(black_mask, cv2.MORPH_CLOSE, kernel)

    # Step 2: Find external contours of black regions
    contours, _ = cv2.findContours(black_mask, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)

    added_label_boxes = []

    for cnt in contours:
        area = cv2.contourArea(cnt)

        # Filter out noise (tiny dots/lines) and overly large regions (whole page border)
        if area < min_area or area > (total_image_area * max_area_ratio):
            continue

        x, y, w, h = cv2.boundingRect(cnt)

        # Ignore thin single-line borders (aspect ratio sanity check)
        if w < 10 or h < 8:
            continue

        # Step 3: Calculate leftward bounding box to cover the text label
        # Left boundary clamped to 0 to prevent negative indices
        label_x1 = max(0, x - label_offset)
        label_x2 = x

        # Ensure vertical bounds stay within image dimensions
        label_y1 = max(0, y - padding_y)
        label_y2 = min(height, y + h + padding_y)

        label_w = label_x2 - label_x1
        label_h = label_y2 - label_y1

        # Only draw if there is space to the left
        if label_w > 0 and label_h > 0:
            # Step 4: Draw solid black filled rectangle over the leftward zone
            cv2.rectangle(
                output_image,
                (label_x1, label_y1),
                (label_x2, label_y2),
                color=(0, 0, 0),
                thickness=-1  # Solid fill
            )
            added_label_boxes.append((label_x1, label_y1, label_w, label_h))

    return output_image, added_label_boxes


def process_file(
    input_path: str,
    output_path: Optional[str] = None,
    label_offset: int = 250,
    min_area: int = 500,
    color_threshold: int = 15,
) -> str:
    """Processes an image file and saves the output."""
    in_file = Path(input_path)
    if not in_file.exists():
        raise FileNotFoundError(f"Input file not found: {input_path}")

    image = cv2.imread(str(in_file))
    if image is None:
        raise ValueError(f"cv2 could not read image from: {input_path}")

    processed, boxes = mask_adjacent_labels(
        image=image,
        label_offset=label_offset,
        min_area=min_area,
        color_threshold=color_threshold,
    )

    if output_path is None:
        out_file = in_file.parent / f"{in_file.stem}_masked{in_file.suffix}"
    else:
        out_file = Path(output_path)

    out_file.parent.mkdir(parents=True, exist_ok=True)
    cv2.imwrite(str(out_file), processed)

    print(f"[Done] Detected {len(boxes)} black redaction box(es).")
    print(f"       Masked adjacent text labels with offset={label_offset}px.")
    print(f"       Saved to: {out_file}")
    return str(out_file)


def main():
    parser = argparse.ArgumentParser(
        description="Detect black redaction boxes in form images and mask adjacent labels to the left."
    )
    parser.add_argument("input", help="Path to input form image.")
    parser.add_argument("-o", "--output", help="Path to save output image (default: <input>_masked.<ext>).")
    parser.add_argument(
        "--label-offset",
        type=int,
        default=250,
        help="Horizontal distance in pixels to mask to the left of each black box (default: 250).",
    )
    parser.add_argument(
        "--min-area",
        type=int,
        default=500,
        help="Minimum pixel area for a black region to qualify as a redaction box (default: 500).",
    )
    parser.add_argument(
        "--color-threshold",
        type=int,
        default=15,
        help="Max BGR value to consider a pixel black (default: 15).",
    )

    args = parser.parse_args()

    try:
        process_file(
            input_path=args.input,
            output_path=args.output,
            label_offset=args.label_offset,
            min_area=args.min_area,
            color_threshold=args.color_threshold,
        )
    except Exception as e:
        print(f"[Error] {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
