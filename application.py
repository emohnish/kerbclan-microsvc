#imports
from flask import Flask
from flask import request
from flask import make_response
from flask import render_template
from azure.keyvault import KeyVaultClient
from azure.common.credentials import ServicePrincipalCredentials

from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient

import psycopg2


# for the api
import json

import logging

app = Flask(__name__)

# Just that we have a start page for the web application
@app.route("/")
def hello():
    
    # https://www.tutorialspoint.com/flask/flask_templates.htm
    app.logger.info("hello called")

    return render_template("hello.html"),200

# The api method. Expects a parameter named "input"
@app.route("/api", methods=["GET"])
def api():

    retdict ={} 

    try:
        input_string = request.args.get("input","[you forgot to feed in input]")
        app.logger.info("FAKE API CALL, input = "+input_string)

        response = {
            'input':input_string,
            'my_api_output':"hello api "+input_string
        } 
        
        retdict['response']=response

    except Exception as e:
        msg = "Bad Request (400): "+str(e)
        app.logger.info(msg)
        # print(msg)
        return msg,400
    
    retJson = json.dumps(retdict)
    app.logger.info("retjson :"+retJson)

    resp = make_response(retJson)
    resp.headers['content-type']="application/json"
    resp.headers['Access-Control-Allow-Origin']="*"

    # http://www.flaskapi.org/api-guide/status-codes/#successful-2xx
    return resp, 200

# The login method.
@app.route("/login", methods=["GET"])
def login():

    #data = request.get_json(silent=True)

    userName = request.args.get("userName","[you forgot to feed in userName]")
    password = request.args.get("password","[you forgot to feed in password]")

    retdict ={} 

    try:

        #Retrieving secret value from key vault


        ############


        #input_string = request.args.get("input","[you forgot to feed in input]")
        app.logger.info("FAKE API CALL, userName = "+ userName)

        authenticate = False

        if ((userName == 'user1' and password == 'abc') 
            or (userName == 'user2' and password == 'abc2')
            or (userName == 'user3' and password == 'abc3')):
            authenticate = True  

        response = {
            'userName': userName,
            'authenticate': authenticate
        } 
        
        retdict['response']=response

    except Exception as e:
        msg = "Bad Request (400): "+str(e)
        app.logger.info(msg)
        # print(msg)
        return msg,400
    
    retJson = json.dumps(retdict)
    app.logger.info("retjson :"+retJson)

    resp = make_response(retJson)
    resp.headers['content-type']="application/json"
    resp.headers['Access-Control-Allow-Origin']="*"

    return resp, 200


# The login method.
@app.route("/getSecret", methods=["GET"])
def getSecret():

    retdict ={} 

    try:

        #Retrieving secret value from key vault

        #credentials = ServicePrincipalCredentials(
#            client_id = 'dafcc756-612f-496a-a580-22014aff8ea5'
 #           secret = '...',
  #          tenant = '...'
   #     )

    #    client = KeyVaultClient(credentials)

        # VAULT_URL must be in the format 'https://<vaultname>.vault.azure.net'
        # SECRET_VERSION is required, and can be obtained with the KeyVaultClient.get_secret_versions(self, vault_url, secret_id) API
     #   secret_bundle = client.get_secret('https://db-hackathon-keyvault.vault.azure.net/secrets/', 'user-pwd', '229dd206b576478793801a4d739f7c65')
      #  secret = secret_bundle.value


        credential = DefaultAzureCredential()
        secret_client = SecretClient(vault_endpoint='https://db-hackathon-keyvault.vault.azure.net', credential=credential)

        secret = secret_client.get_secret("user-pwd")

        print(secret.name)
        print(secret.value)
        
        ############

        response = {
            'secret_name': secret.name,
            'secret_value': secret.value
        } 
        
        retdict['response']=response

    except Exception as e:
        msg = "Bad Request (400): "+str(e)
        app.logger.info(msg)
        # print(msg)
        return msg,400
    
    retJson = json.dumps(retdict)
    app.logger.info("retjson :"+retJson)

    resp = make_response(retJson)
    resp.headers['content-type']="application/json"
    resp.headers['Access-Control-Allow-Origin']="*"

    return resp, 200

# The login method.
@app.route("/getDBTableData", methods=["GET"])
def getDBTableData():

    retdict ={} 

    try:

        credential = DefaultAzureCredential()
        secret_client = SecretClient(vault_endpoint='https://db-hackathon-keyvault.vault.azure.net', credential=credential)

        secret = secret_client.get_secret("postgre-pwd")

        connection = psycopg2.connect(user = "adminuser@postgresql-hackathon",
                                  password = secret.value,
                                  host = "postgresql-hackathon.postgres.database.azure.com",
                                  port = "5432",
                                  database = "postgres")

        cur = connection.cursor()
        
        # execute a statement
        print('PostgreSQL database version:')
        cur.execute('SELECT version()')
 
        # display the PostgreSQL database server version
        db_version = cur.fetchone()
        print(db_version[0])  

        cur.execute('select username from employee where age < 40')       

        username = cur.fetchone()                 

        response = {
            'db_version': db_version[0],
            'username': username[0]
        } 
        
        retdict['response']=response

    except Exception as e:
        msg = "Bad Request (400): "+str(e)
        app.logger.info(msg)
        # print(msg)
        return msg,400
    
    retJson = json.dumps(retdict)
    app.logger.info("retjson :"+retJson)

    resp = make_response(retJson)
    resp.headers['content-type']="application/json"
    resp.headers['Access-Control-Allow-Origin']="*"

    return resp, 200
