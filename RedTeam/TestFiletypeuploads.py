import requests

# A list of file types to test
file_types = [
    ('page','.html'),
    ('page','.js'),
    ('page','.css'),
    ('file','.pdf'),
    ('image','.jpg'),
    ('image','.jpeg'),
    ('image','.png'),
    ('image','.gif'),
    ('image','.bmp'),
    ('audio','.mp3'),
    ('video','.mp4'),
    ('video','.avi'),
    ('video','.wmv'),
    ('video','.mov'),
    ('file','.doc'),
    ('file','.docx'),
    ('file','.xls'),
    ('file','.xlsx'),
    ('file','.ppt'),
    ('file','.pptx'),
    ('file','.zip'),
    ('file','.rar'),
    ('file','.7z'),
    ('file','.tar'),
    ('file','.gz'),
    ('audio','.wav'),
    ('audio','.midi'),
    ('image','.tiff'),
    ('image','.svg'),
    ('file','.txt'),
    ('file','.xml'),
    ('file','.json'),
    ('page','.php'),
    ('page','.asp'),
    ('page','.aspx'),
    ('page','.jsp'),
    ('page','.swf'),
    ('video','.flv'),
    ('audio','.aiff'),
    ('audio','.ogg'),
    ('audio','.m4a'),
    ('audio','.ram'),
    ('audio','.ra'),
    ('audio','.aac'),
]

# The URL of the website to test
url = 'http://www.example.com/upload'

# Iterate over the file types and attempt to upload each one
for file_type in file_types:
    file_name = 'sample.' + file_type[1]
    files = {'file': (file_name, open(file_name, 'rb'), 'multipart/form-data')}
    response = requests.post(url, files=files)
    if response.status_code == 200:
        print(f"{file_type[0]} file with {file_type[1]} extension accepted.")
    else:
        print(f"{file_type[0]} file with {file_type[1]} extension not accepted.")