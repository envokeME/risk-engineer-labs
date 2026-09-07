from pathlib import Path
import nbformat
from nbclient import NotebookClient
root = Path(__file__).resolve().parent
path = root / 'lab-01-continuous-risk-identification.ipynb'
nb = nbformat.read(path, as_version=4)
NotebookClient(nb, timeout=180, kernel_name='python3', resources={'metadata': {'path': str(root)}}).execute()
nbformat.write(nb, path)
print('Fresh-kernel notebook execution completed')
