"""
Template loader utility.

Reads an HTML/text template from disk and returns its contents as a string.
Used by SummaryService to fill placeholders via Python's `.format(...)`.
"""

def load_template(template_path):
    """Open `template_path` with UTF-8 encoding and return the file contents."""
    # Read the template file and return its content as a single string
    with open(template_path, 'r', encoding='utf-8') as f:
        return f.read()
