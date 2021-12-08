ALLOWED_EXTENSION = ['txt', 'pdf', 'jpg', 'jpeg',
                     'png', 'pptx', 'docx', 'doc', 'doc', 'gif']


def allowed_files(filename: str) -> bool: return '.' in filename and filename.rsplit(
    '.', 1)[1].lower() in ALLOWED_EXTENSION
