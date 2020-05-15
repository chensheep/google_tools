# -*- coding: utf-8 -*-

import os.path
from os import path

import webbrowser

import requests
import json

HTTP_DEBUG = False
if HTTP_DEBUG == True:
    import logging
    try:
        import http.client as http_client
    except ImportError:
        # Python 2
        import httplib as http_client
    http_client.HTTPConnection.debuglevel = 1

    # You must initialize logging, otherwise you'll not see debug output.
    logging.basicConfig()
    logging.getLogger().setLevel(logging.DEBUG)
    requests_log = logging.getLogger("requests.packages.urllib3")
    requests_log.setLevel(logging.DEBUG)
    requests_log.propagate = True

from pprint import pprint
from PyInquirer import style_from_dict, Token, prompt, Separator
from PyInquirer import Validator, ValidationError
from colorama import init

from termcolor import colored
init()

style = style_from_dict({
    Token.QuestionMark: '#E91E63 bold',
    Token.Selected: '#673AB7 bold',
    Token.Instruction: '',  # default
    Token.Answer: '#2196f3 bold',
    Token.Question: '',
})

def prompt_input_questions(name, message, validator):
    questions = [
        {
            'type': 'input',
            'name': name,
            'message': message,
            'validate': validator
        },
    ]
    answers = prompt(questions, style=style)
    return answers[name]

def get_client_id():
    client_id = ""
    with open("client_secret.json", "r") as file:
        cj = json.loads(file.readline())
        client_id = cj["installed"]["client_id"]
    return client_id

def get_client_secret():
    client_secret = ""
    with open("client_secret.json", "r") as file:
        cj = json.loads(file.readline())
        client_secret = cj["installed"]["client_secret"]
    return client_secret

def check_client_secret():
    return path.exists("client_secret.json")

def check_token_exist ():
    access_token = ""
    if (path.exists("accsee_token") != True):
        return ""
    with open("accsee_token", "r") as file:
        access_token = file.readline()
    return access_token

def record_access_token(access_token):
    with open('accsee_token', 'w+') as the_file:
        the_file.write(access_token)

def build_authorization_link(scopes):

    scope_cancat = "+"
    scope_cancat = scope_cancat.join(scopes)

    BASE_URL = "https://accounts.google.com/o/oauth2/v2/auth?"
    REDIRECT_URI = "redirect_uri=urn:ietf:wg:oauth:2.0:oob"
    PROMPT = "prompt=consent"
    RESPONSE_TYPE="response_type=code"
    CLIENT_ID="client_id="+get_client_id()
    SCOPE="scope="+scope_cancat
    ACCESS_TYPE="access_type=offline"

    return BASE_URL+"&"+REDIRECT_URI+"&"+PROMPT+"&"+RESPONSE_TYPE+"&"+CLIENT_ID+"&"+SCOPE+"&"+ACCESS_TYPE

def open_link(link_url):
    webbrowser.open_new_tab(link_url)


url = 'https://www.w3schools.com/python/demopage.php'
myobj = {'somekey': 'somevalue'}

x = requests.post(url, data = myobj)

def get_access_token(auth_code):
    post_url = "https://oauth2.googleapis.com/token"
    post_data = {
        'code': auth_code,
        'client_id': get_client_id(),
        'client_secret': get_client_secret(),
        'redirect_uri': 'urn:ietf:wg:oauth:2.0:oob',
        'grant_type': 'authorization_code'
    }
    result = requests.post(post_url, data = post_data)
    print("%s" % result.text)
    rj = json.loads(result.text)
    return rj["access_token"]

def export_gdoc_to_pdf(access_token, gdoc_id):
    get_url = "https://docs.google.com/document/d/" + gdoc_id + "/export?format=pdf"
    get_headers = {"Authorization": "Bearer " + access_token}
    result = requests.get(get_url, headers=get_headers, allow_redirects=True)
    if result.status_code != 200:
        print("export failed! error : %d" % (result.status_code))
        return
    with open('./output.pdf', 'wb+') as f:
        f.write(result.content)
    print("pdf output.pdf saved!")

class InputValidator(Validator):
    def validate(self, document):
        if document.text == "":
            raise ValidationError(
                message='Please enter a valid version descrption',
                cursor_position=len(document.text))  # Move cursor to end

if __name__ == '__main__':

    if check_client_secret() == False:
        print ("Please get client_secret.json with https://console.developers.google.com/")
        exit()

    access_token = check_token_exist()
    if access_token == "":

        scopes = [
            "https://www.googleapis.com/auth/documents",
            "https://www.googleapis.com/auth/documents.readonly",
            "https://www.googleapis.com/auth/drive",
            "https://www.googleapis.com/auth/drive.file",
            "https://www.googleapis.com/auth/drive.readonly",
        ]

        authorization_link = build_authorization_link(scopes)

        open_link(authorization_link)

        authorization_code = prompt_input_questions('authorization_code', 'Please enter authorization code:', InputValidator)

        access_token = get_access_token(authorization_code)

        if access_token != "":
            record_access_token(access_token)

    else:
        #TODO check token is available & refresh token
        print ("Using exisiting access_token ... ")
        print ("If you wanna use new token, please remove file accsee_token and run program again")

    gdoc_id = prompt_input_questions('gdoc_id', 'Please enter google document id:', InputValidator)

    export_gdoc_to_pdf(access_token, gdoc_id)

