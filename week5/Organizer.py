from pathlib import Path
import shutil
import json
from collections import Counter

CATEGORIES = {
     "Images": ["jpg", "jpeg", "png", "gif", "bmp", "tiff", "svg"],
    "Documents": ["pdf", "doc", "docx", "txt", "ppt", "pptx", "xls", "xlsx"],
    "Audio": ["mp3", "wav", "aac", "flac", "ogg", "m4a"],
    "Video": ["mp4", "mov", "avi", "mkv", "wmv"],
    "Archives": ["zip", "rar", "7z", "tar", "gz"],
    "Executables": ["sh", "exe"],
    "Other": ["weird.FILE",],
}

def categorize_extension(ext):
    for category, ext_list in CATEGORIES.items():
        if ext in ext_list:
            return category
    return "Other"

def process_directory(directory):
    directory = Path(directory)

    if not directory.exists() or not directory.is_dir():
        print("Directory does not exist.")
        return

    extensions = []

    for file in directory.iterdir():
        if file.is_file():
            ext = file.suffix.lower().lstrip(".")
            extensions.append(ext)

            category = categorize_extension(ext)
            target_folder = directory / category
            target_folder.mkdir(exist_ok=True)

            shutil.move(str(file), str(target_folder / file.name))
            print(f"Moved: {file.name} → {category}")

    create_text_summary(directory, extensions)
    create_json_summary(directory, extensions)

    print("\nSummary reports created.")

def create_text_summary(directory, extensions):
    total = len(extensions)
    ext_counts = Counter(extensions)
    summary_path = directory / "organizer_summary.txt"

    with summary_path.open("w", encoding="utf-8") as txt:
        txt.write("FILE ORGANIZER SUMMARY\n")
        txt.write("=======================\n\n")
        txt.write(f"Total files processed: {total}\n\n")
        txt.write("Extension distribution:\n")

        for ext, count in ext_counts.items():
            pct = (count / total) * 100 if total else 0
            txt.write(f" - {ext or 'no_extension'}: {pct:.2f}% ({count})\n")

def create_json_summary(directory, extensions):
    total = len(extensions)
    ext_counts = Counter(extensions)

    json_data = {
        "total_files": total,
        "extensions": {}
    }

    for ext, count in ext_counts.items():
        pct = (count / total) * 100 if total else 0
        json_data["extensions"][ext or "no_extension"] = {
            "count": count,
            "percentage": round(pct, 2)
        }

    json_path = directory / "organizer_summary.json"
    with json_path.open("w", encoding="utf-8") as jf:
        json.dump(json_data, jf, indent=4)

if __name__ == "__main__":
    folder = input("Enter directory to organize: ").strip()
    process_directory(folder)
