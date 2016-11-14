from flask import Flask, render_template, request, redirect, jsonify, url_for, flash
from sqlalchemy import create_engine, asc
from sqlalchemy.orm import sessionmaker
from database_setup import Base, Bakery, MenuItem, User
from flask import session as login_session
import random
import string
from flask.ext.seasurf import SeaSurf

# IMPORTS FOR GCONNECT
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
import json
from flask import make_response
import requests


app = Flask(__name__)
csrf = SeaSurf(app)

# FOR GCONNECT
CLIENT_ID = json.loads(
    open('client_secrets.json', 'r').read())['web']['client_id']
APPLICATION_NAME = "Restaurant Menu Application"


# CONNECT TO DATABASE AND CREATE DATABASE SESSION

engine = create_engine('sqlite:///pastryparadise.db')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()

# Create anti-forgery state token


@app.route('/login')
def showLogin():
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in xrange(32))
    login_session['state'] = state
    return render_template('login.html', STATE=state)


@csrf.exempt
@app.route('/fbconnect', methods=['POST'])
def fbconnect():
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    access_token = request.data
    print "access token received %s " % access_token

    app_id = json.loads(open('fb_client_secrets.json', 'r').read())[
        'web']['app_id']
    app_secret = json.loads(
        open('fb_client_secrets.json', 'r').read())['web']['app_secret']
    url = 'https://graph.facebook.com/oauth/access_token?grant_type=fb_exchange_token&client_id=%s&client_secret=%s&fb_exchange_token=%s' % (
        app_id, app_secret, access_token)
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]

    # Use token to get user info from API
    userinfo_url = "https://graph.facebook.com/v2.4/me"
    # strip expire tag from access token
    token = result.split("&")[0]

    url = 'https://graph.facebook.com/v2.4/me?%s&fields=name,id,email' % token
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    # print "url sent for API access:%s"% url
    # print "API JSON result: %s" % result
    data = json.loads(result)
    login_session['provider'] = 'facebook'
    login_session['username'] = data["name"]
    login_session['email'] = data["email"]
    login_session['facebook_id'] = data["id"]

    # The token must be stored in the login_session in order to properly
    # logout, let's strip out the information before the equals sign in our
    # token
    stored_token = token.split("=")[1]
    login_session['access_token'] = stored_token

    # Get user picture
    url = 'https://graph.facebook.com/v2.4/me/picture?%s&redirect=0&height=200&width=200' % token
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    data = json.loads(result)

    login_session['picture'] = data["data"]["url"]

    # see if user exists
    user_id = getUserID(login_session['email'])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    output = 'Wait a moment while we set things up!'
    #output += '<div style="background-color:black; color:white"><h1>Welcome, '
    #output += login_session['username']

    #output += '!</h1>'
    #output += '<img src="'
    #output += login_session['picture']
    # output += ' " style = "width: 300px; height: \
    #         300px;border-radius: 150px;-webkit-border-radius: \
    #       150px;-moz-border-radius: 150px;"></div> '
    print "NOW"
    flash("Now logged in as %s" % login_session['username'])
    return output


@csrf.exempt
@app.route('/fbdisconnect')
def fbdisconnect():
    facebook_id = login_session['facebook_id']
    # The access token must me included to successfully logout
    access_token = login_session['access_token']
    url = 'https://graph.facebook.com/%s/permissions?access_token=%s' % (
        facebook_id, access_token)
    h = httplib2.Http()
    result = h.request(url, 'DELETE')[1]
    return "you have been logged out"


@csrf.exempt
@app.route('/gconnect', methods=['POST'])
def gconnect():
    # Validate state token
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Obtain authorization code
    code = request.data

    try:
        # Upgrade the authorization code into a credentials object
        oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(
            json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Check that the access token is valid.
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])
    # If there was an error in the access token info, abort.
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is used for the intended user.
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is valid for this app.
    if result['issued_to'] != CLIENT_ID:
        response = make_response(
            json.dumps("Token's client ID does not match app's."), 401)
        print "Token's client ID does not match app's."
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_credentials = login_session.get('credentials')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_credentials is not None and gplus_id == stored_gplus_id:
        response = make_response(json.dumps('Current user is already \
            connected.'),
                                 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.
    login_session['access_token'] = credentials.access_token
    login_session['gplus_id'] = gplus_id

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()

    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']
    # ADD PROVIDER TO LOGIN SESSION
    login_session['provider'] = 'google'

    # see if user exists, if it doesn't make a new one
    user_id = getUserID(data["email"])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    output = 'Wait a moment while we set things up!'
    #output += '<div style="background-color:black; color:white"><h1>Welcome, '
    #output += login_session['username']
    #output += '!</h1>'
    #output += '<img src="'
    #output += login_session['picture']
    # output += ' " style = "width: 300px; height: 300px;border-radius: \
    #        150px;-webkit-border-radius: 150px;-moz-border-radius: \
    #        150px;"> </div>'
    flash("you are now logged in as %s" % login_session['username'])
    # print "done!"
    return output

# FOR DISCONNECTING/LOG OUT


@csrf.exempt
@app.route('/gdisconnect')
def gdisconnect():
    credentials = login_session.get('credentials')
    print credentials
    print 'In gdisconnect access token is %s', credentials
    print login_session['username']
    if credentials is None:
        print 'Access Token is None'
        response = make_response(
            json.dumps('Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % login_session[
        'credentials'].access_token
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]

    if result['status'] == '200':
        del login_session['credentials']
        del login_session['gplus_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        login_session.clear()

        response = make_response(json.dumps('Successfully disconnected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response
    else:

        response = make_response(
            json.dumps('Failed to revoke token for given user.', 400))
        response.headers['Content-Type'] = 'application/json'
        return response


# Disconnect based on provider
@app.route('/disconnect')
def disconnect():
    if 'provider' in login_session:
        if login_session['provider'] == 'google':
            gdisconnect()
            del login_session['gplus_id']
            login_session.clear()

        elif login_session['provider'] == 'facebook':
            fbdisconnect()
            del login_session['facebook_id']
            login_session.clear()

        flash("You have successfully been logged out.")
        return redirect(url_for('showBakeries'))
    else:
        flash("You were not logged in")
        return redirect(url_for('showBakeries'))
        # return "You were not logged in"


# User Helper Functions


def createUser(login_session):
    newUser = User(name=login_session['username'], email=login_session[
                   'email'], picture=login_session['picture'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email']).one()
    return user.id


def getUserInfo(user_id):
    user = session.query(User).filter_by(id=user_id).one()
    return user


def getUserID(email):
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except:
        return None


# JSON APIs FOR INFORMATION ABOUT BAKERIES

@app.route('/bakeries/<int:bakery_id>/menu/JSON')
def bakeryMenuJSON(bakery_id):
    bakery = session.query(Bakery).filter_by(id=bakery_id).one()
    items = session.query(MenuItem).filter_by(
        bakery_id=bakery_id).all()
    return jsonify(MenuItems=[i.serialize for i in items])


@app.route('/bakeries/<int:bakery_id>/menu/<int:menu_id>/JSON')
def menuItemJSON(bakery_id, menu_id):
    Menu_Item = session.query(MenuItem).filter_by(id=menu_id).one()
    return jsonify(Menu_Item=Menu_Item.serialize)


@app.route('/bakeries/JSON')
def bakeriesJSON():
    bakeries = session.query(Bakery).all()
    return jsonify(bakeries=[r.serialize for r in bakeries])


# SHOW ALL BAKERIES


@app.route('/')
@app.route('/bakeries/')
def showBakeries():

    bakeries = session.query(Bakery).order_by(asc(Bakery.name))
    return render_template('bakeries.html', bakeries=bakeries)

# CREATE A NEW BAKERY


@app.route('/bakeries/new', methods=['GET', 'POST'])
def newBakery():
    if 'username' not in login_session:
        return redirect('/login')

    if request.method == 'POST':
        newbakery = Bakery(name=request.form['name'])
        session.add(newbakery)
        session.commit()
        flash('New Bakery Created Successfully!')
        return redirect(url_for('showBakeries'))

    else:
        return render_template('newBakery.html')

# EDIT A BAKERY


@app.route('/bakeries/<int:bakery_id>/edit/', methods=['GET', 'POST'])
def editBakery(bakery_id):
    if 'username' not in login_session:
        return redirect('/login')

    bakery = session.query(Bakery).filter_by(id=bakery_id).one()
    if request.method == 'POST':
        bakery.name = request.form['name']
        flash('Bakery Edited Successfully!')
        return redirect(url_for('showBakeries'))
    else:
        return render_template('editBakery.html', bakery=bakery)

# DELETE A BAKERY


@app.route('/bakeries/<int:bakery_id>/delete/', methods=['GET', 'POST'])
def deleteBakery(bakery_id):
    if 'username' not in login_session:
        return redirect('/login')

    bakery = session.query(Bakery).filter_by(id=bakery_id).one()
    if request.method == 'POST':
        session.delete(bakery)
        session.commit()
        flash('Bakery Deleted Successfully!')
        return redirect(url_for('showBakeries'))
    else:
        return render_template('deleteBakery.html', bakery=bakery)


# SHOW A BAKERY MENU


@app.route('/bakeries/<int:bakery_id>')
@app.route('/bakeries/<int:bakery_id>/menu/')
def showMenu(bakery_id):
    bakery = session.query(Bakery).filter_by(id=bakery_id).one()
    items = session.query(MenuItem).filter_by(
        bakery_id=bakery_id).all()
    return render_template('menu.html', items=items, bakery=bakery)

# CREATE A NEW MENU ITEM


@app.route('/bakeries/<int:bakery_id>/menu/new/', methods=['GET', 'POST'])
def newMenuItem(bakery_id):
    if 'username' not in login_session:
        return redirect('/login')

    bakery = session.query(Bakery).filter_by(id=bakery_id).one()
    if request.method == 'POST':
        newItem = MenuItem(name=request.form['name'],
                           description=request.form['description'],
                           price=request.form['price'], bakery_id=bakery_id)
        session.add(newItem)
        session.commit()
        flash('New Menu Item Created Successfully!')
        return redirect(url_for('showMenu', bakery_id=bakery_id))
    else:
        return render_template('newmenuitem.html', bakery_id=bakery_id)


# EDIT A MENU ITEM


@app.route('/bakeries/<int:bakery_id>/menu/<int:menu_id>/edit/', methods=['GET', 'POST'])
def editMenuItem(bakery_id, menu_id):
    if 'username' not in login_session:
        return redirect('/login')

    editedItem = session.query(MenuItem).filter_by(id=menu_id).one()
    bakery = session.query(Bakery).filter_by(id=bakery_id).one()
    if request.method == 'POST':
        if request.form['name']:
            editedItem.name = request.form['name']
        if request.form['description']:
            editedItem.description = request.form['description']
        if request.form['price']:
            editedItem.price = request.form['price']

        session.add(editedItem)
        session.commit()
        flash('Menu Item Edited Successfully!')
        return redirect(url_for('showMenu', bakery_id=bakery_id))
    else:
        return render_template('editmenuitem.html',
                               bakery_id=bakery_id, menu_id=menu_id, item=editedItem)


# DELETE A MENU ITEM


@app.route('/bakeries/<int:bakery_id>/menu/<int:menu_id>/delete', methods=['GET', 'POST'])
def deleteMenuItem(bakery_id, menu_id):
    if 'username' not in login_session:
        return redirect('/login')

    bakery = session.query(Bakery).filter_by(id=bakery_id).one()
    itemToDelete = session.query(MenuItem).filter_by(id=menu_id).one()
    if request.method == 'POST':
        session.delete(itemToDelete)
        session.commit()
        flash('Menu Item Deleted Successfully!')
        return redirect(url_for('showMenu', bakery_id=bakery_id))
    else:
        return render_template('deleteMenuItem.html', item=itemToDelete)


if __name__ == '__main__':
    app.secret_key = 'super_secret_key'
    app.debug = True
    app.run(host='0.0.0.0', port=8081)
