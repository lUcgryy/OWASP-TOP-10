import requests

data = {'username': 'giang2', 'password1': '1', 'password2': '1'}
r = requests.post('https://localhost:3443/admin', data=data, verify=False)
