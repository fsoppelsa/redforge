"""Lettori di sorgenti per datakit."""

from datakit.readers.csv_reader import read_csv
from datakit.readers.excel_reader import read_excel
from datakit.readers.json_reader import read_json
from datakit.readers.pdf_reader import read_pdf

__all__ = ["read_csv", "read_excel", "read_json", "read_pdf"]
