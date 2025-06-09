def load_template(template_path):
    with open(template_path, 'r', encoding='utf-8') as f:
        return f.read()
