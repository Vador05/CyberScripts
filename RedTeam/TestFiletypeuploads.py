import requests

# A list of file types to test
file_types = [
    ('text', 'txt'),
    ('image', 'jpg'),
    ('image', 'png'),
    ('audio', 'mp3'),
    ('video', 'mp4'),
    ('pdf', 'pdf')
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