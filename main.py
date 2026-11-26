from pathlib import Path
from src.analysis_utils import load_data, prepare_data, run_analysis

def main():
    public_csv = Path("Dataset/cybersecurity_data.csv")
    demo_csv = Path("Dataset/demo_cybersecurity_data.csv")
    csv_path = public_csv if public_csv.exists() else demo_csv
    if csv_path == demo_csv:
        print("NOTICE: Using DEMO data only. Replace it with a public dataset before final analysis.")
    df = load_data(csv_path)
    print("First five records:")
    print(df.head())
    print("\nDataset shape:", df.shape)
    print("\nColumn names:")
    print(df.columns.tolist())
    prepared, mapping = prepare_data(df)
    print("\nDetected fields:", mapping)
    cleaned, report = run_analysis(prepared, mapping, csv_path.name)
    print("\nAnalysis completed.")
    print("Charts saved in Graphs/")
    print("Tables saved in outputs/")
    print("Summary saved in Final_Report/analysis_summary.txt")
    print("\n".join(report[:16]))

if __name__ == "__main__":
    main()
