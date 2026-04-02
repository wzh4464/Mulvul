# CWE Top-Level Category Chart Generator

This program generates pie charts and bar charts for CWE (Common Weakness Enumeration) top-level category distribution based on the `CWE2toplevelclass.csv` file.

## Features

- **Pie Chart**: Visual representation of CWE category distribution
- **Bar Chart**: Alternative view for better comparison of categories
- **Configurable Font Sizes**: All font sizes are defined as constants for easy customization
- **High Resolution**: 300 DPI output suitable for printing and presentations
- **English Labels**: No Chinese characters to avoid font issues

## Font Size Constants

All font sizes are defined at the top of the file for easy modification:

```python
# Font size constants for different chart elements
FONT_SIZE_TITLE = 48                    # Main chart title
FONT_SIZE_SUBTITLE = 36                 # Subtitle or secondary title
FONT_SIZE_AXIS_LABEL = 24              # X and Y axis labels
FONT_SIZE_TICK_LABEL = 18              # Axis tick labels
FONT_SIZE_LEGEND = 18                  # Legend text
FONT_SIZE_LEGEND_TITLE = 18            # Legend title
FONT_SIZE_PIE_LABEL = 18               # Pie chart slice labels
FONT_SIZE_BAR_LABEL = 18               # Bar chart value labels
FONT_SIZE_STATS_INFO = 24              # Statistics information box
```

## Usage

### Basic Usage
```bash
# Generate pie chart only
python cwe_category_pie_chart.py data/primevul_1percent_sample/CWE2toplevelclass.csv

# Generate both pie chart and bar chart
python cwe_category_pie_chart.py data/primevul_1percent_sample/CWE2toplevelclass.csv --bar

# Save with custom filename
python cwe_category_pie_chart.py data/primevul_1percent_sample/CWE2toplevelclass.csv -o my_chart.png

# Save only (no display)
python cwe_category_pie_chart.py data/primevul_1percent_sample/CWE2toplevelclass.csv --no-show
```

### Command Line Arguments

- `input_file`: Path to the CSV file (required)
- `-o, --output`: Output image file path (optional, default: `cwe_category_distribution.png`)
- `--no-show`: Do not display chart, save only
- `--bar`: Also generate bar chart
- `-h, --help`: Show help message

## Input File Format

The program expects a CSV file with the following columns:

```csv
CWE ID, Top-Level Category, Confidence
CWE-787, Improper Control of a Resource Through its Lifetime (CWE-664), High
CWE-125, Improper Control of a Resource Through its Lifetime (CWE-664), High
CWE-476, Improper Control of a Resource Through its Lifetime (CWE-664), High
...
```

## Output Files

- **Pie Chart**: `cwe_category_distribution.png` (or custom name)
- **Bar Chart**: `cwe_category_distribution_bar.png` (if `--bar` flag is used)

## Chart Features

### Pie Chart
- **Legend Position**: Bottom right corner
- **Color Scheme**: Set3 color palette for good distinction
- **Statistics Box**: Shows total CWE types and unique categories
- **Percentage Labels**: Each slice shows percentage

### Bar Chart
- **Value Labels**: Count displayed on top of each bar
- **Grid Lines**: Horizontal grid for better readability
- **Rotated Labels**: X-axis labels rotated 45° for better fit

## Sample Output

Based on your data, the program generates charts showing:

1. **Improper Control of a Resource Through its Lifetime**: 14 (33.3%)
2. **Improper Neutralization**: 6 (14.3%)
3. **Protection Mechanism Failure**: 6 (14.3%)
4. **Improper Access Control**: 5 (11.9%)
5. **Incorrect Calculation**: 3 (7.1%)
6. **Improper Check or Handling of Exceptional Conditions**: 3 (7.1%)
7. **Insufficient Control Flow Management**: 3 (7.1%)
8. **Others**: 2 (4.8%)

## Customization

### Font Sizes
To change font sizes, simply modify the constants at the top of the file:

```python
# Example: Increase title font size
FONT_SIZE_TITLE = 56                    # Increase from 48 to 56

# Example: Increase all label sizes
FONT_SIZE_PIE_LABEL = 24               # Increase from 18 to 24
FONT_SIZE_BAR_LABEL = 24               # Increase from 18 to 24
FONT_SIZE_TICK_LABEL = 24              # Increase from 18 to 24

# Example: Increase axis labels
FONT_SIZE_AXIS_LABEL = 30              # Increase from 24 to 30
```

### Colors
The color scheme can be modified in the `create_pie_chart` and `create_bar_chart` functions:

```python
# Change from Set3 to other colormaps
colors = plt.cm.tab10(np.linspace(0, 1, len(categories)))  # tab10 colormap
colors = plt.cm.Pastel1(np.linspace(0, 1, len(categories)))  # Pastel1 colormap
```

### Chart Size
Modify the `figsize` parameter in both chart functions:

```python
fig, ax = plt.subplots(figsize=(16, 10))  # Wider and taller
```

## Dependencies

- `pandas`: For CSV data processing
- `matplotlib`: For chart generation
- `numpy`: For numerical operations

## Installation

Using uv (recommended):
```bash
uv add pandas matplotlib numpy
```

Or using pip:
```bash
pip install pandas matplotlib numpy
```

## Notes

- The program automatically handles column name cleaning (removes leading/trailing spaces)
- Layout warnings may appear with large font sizes due to space constraints
- Charts are saved in PNG format with 300 DPI for high quality
- The legend position is optimized to avoid overlapping with chart content
