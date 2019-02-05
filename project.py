from flask import Flask, render_template, request, redirect,jsonify, url_for, flash
app = Flask(__name__)

from sqlalchemy import create_engine, asc
from sqlalchemy.orm import sessionmaker
from database_setup import Base, Restaurant, MenuItem, User

# OAuth setup
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
import json
from flask import make_response
import requests

from flask import session as login_session
import random, string

# Add Google Client ID from json file
CLIENT_ID = json.loads(open('client_secrets.json', 'r')
                       .read())['web']['client_id']
APPLICATION_NAME = "Restaurant Menu Application"

#Connect to Database and create database session
engine = create_engine('sqlite:///restaurantmenuwithusers_new.db')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()

# Create a state token to prevent request forgery
# Store it in the the session for later validation
@app.route('/login/')
def showLogin():
    state = ''.join(random.choice(string.ascii_uppercase
                                  + string.digits) for x in range(32))
    login_session['state'] = state
    print("State within showLogin: ", state)
    return render_template('login.html', state=state)

@app.route('/gconnect', methods=['POST'])
def gconnect():
    # Make sure the the token that the client is sending to the server
    # matches the token that the server previously sent to the client
    if request.args.get('state') != login_session['state']:
        print("Invalid state parameter")
        print("requst State: ", request.args.get('state'))
        print("login session state: ", login_session['state'])
        response = make_response(json.dumps('Invalid state parameter'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Collect the one-time code from the server
    code = request.data
    # Try to use the one-time code and exchange it for a credentials object
    # which contains access token from the server
    try:
        # Upgrade the authorization code into a credentials object
        # Creates a oauth flow object, and adds clients secret key info to it
        oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
        # 'postmessage' specifies that this is the onetime code flow my server
        # will be sending off
        oauth_flow.redirect_uri = 'postmessage'
        # Initiate the exchange
        # step2_exchange exchanges the code for a credentials object
        # Response from google will be a credentials object stores in
        # 'credentials'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        print("Failed to upgrade the authorization code.")
        response = make_response(
            json.dumps('Failed to upgrade the authorization code'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # We have the credentials object. Now we check to see if it has a valid
    # access token inside it

    # Get the token
    access_token = credentials.access_token
    print("debug1", "reached access token creation", access_token)
    # Add the tokken to the google api URL
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    # Create a json get request with the url and access token
    # Make the request and store the result
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])
    print("debug2", "performed new GET request", result)
    # Abort if there was an error in the access token info
    if result.get('error') is not None:
        print('debug0', result.get('error'))
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'

    # Verify that we have the RIGHT access token
    gplus_id = credentials.id_token['sub']
    print("debug3", "retrieved gplus_id", gplus_id)
    if result['user_id'] != gplus_id:
        print("Token's user ID doesn't mathc given User ID")
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID"), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is valid for THIS app.
    if result['issued_to'] != CLIENT_ID:
        print("Token's client ID doesn't match the app's")
        response = make_response(
            json.dumps("Token's client ID does not match app's."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Check to see if the user is already logged in
    stored_credentials = login_session.get('credentials')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_credentials is not None and gplus_id == stored_gplus_id:
        response = make_response(json.dumps('Current user is already connected.'),
                                 200)
        response.headers['Content-Type'] = 'application/json'

    # Store the access token in the session for later use.
    #login_session['credentials'] = credentials
    login_session['access_token'] = credentials.access_token
    login_session['gplus_id'] = gplus_id

    # Get User info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {
        'access_token': login_session['access_token'], 'alt':'json' }
    answer = requests.get(userinfo_url, params=params)
    data = json.loads(answer.text)

    login_session['username'] = data["name"]
    login_session['picture'] = data["picture"]
    login_session['email'] = data["email"]

    # See if the user exists, if it doesn't, make a new one
    if getUserId( login_session['email'] ) is None:
        # Create a new user, if nothing returned
        login_session['user_id'] = createUser(login_session)


    output=''
    output += '<h1>Welcome, %s!</h1>' % login_session['username']
    output += '<img src="%s"' % login_session['picture']
    output += ' style="width: 300px; height: 300px;">'
    print("debug6", output)
    flash("You are now logged in as %s" %login_session['username'])
    return output

#DISCONNECT - Revoke a current user's token and reset their login_session
@app.route('/gdisconnect')
def gdisconnect():
    if 'username' not in login_session:
        return redirect('/login')
    # Only disconnect a connected user
    access_token = login_session.get('access_token')
    if access_token is None:
        response = make_response(json.dumps('Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Execute HTTP GET request to revoke current token.
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % access_token
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]

    if result['status'] == '200':
        # reset the user's session
        del login_session['access_token']
        del login_session['gplus_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']

        response = make_response(json.dumps('Successfully disconnected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response


#JSON APIs to view Restaurant Information
@app.route('/restaurant/<int:restaurant_id>/menu/JSON')
def restaurantMenuJSON(restaurant_id):
    restaurant = session.query(Restaurant).filter_by(id = restaurant_id).one()
    items = session.query(MenuItem).filter_by(restaurant_id = restaurant_id).all()
    return jsonify(MenuItems=[i.serialize for i in items])


@app.route('/restaurant/<int:restaurant_id>/menu/<int:menu_id>/JSON')
def menuItemJSON(restaurant_id, menu_id):
    Menu_Item = session.query(MenuItem).filter_by(id = menu_id).one()
    return jsonify(Menu_Item = Menu_Item.serialize)

@app.route('/restaurant/JSON')
def restaurantsJSON():
    restaurants = session.query(Restaurant).all()
    return jsonify(restaurants= [r.serialize for r in restaurants])


#Show all restaurants
@app.route('/')
@app.route('/restaurant/')
def showRestaurants():
  restaurants = session.query(Restaurant).order_by(asc(Restaurant.name))
  if 'username' not in login_session:
      return render_template('publicrestaurants.html', restaurants=restaurants)
  else:
      return render_template('restaurants.html', restaurants = restaurants)

#Create a new restaurant
@app.route('/restaurant/new/', methods=['GET','POST'])
def newRestaurant():
    if 'username' not in login_session:
        return redirect('/login')

    if request.method == 'POST':
      newRestaurant = Restaurant(name = request.form['name'],
                                 user_id = login_session['user_id'])
      session.add(newRestaurant)
      flash('New Restaurant %s Successfully Created' % newRestaurant.name)
      session.commit()
      return redirect(url_for('showRestaurants'))
    else:
      return render_template('newRestaurant.html')

#Edit a restaurant
@app.route('/restaurant/<int:restaurant_id>/edit/', methods = ['GET', 'POST'])
def editRestaurant(restaurant_id):
  
    if 'username' not in login_session:
        return redirect('/login')
    editedRestaurant = session.query(Restaurant).filter_by(id = restaurant_id).one()
    if request.method == 'POST':
        if request.form['name']:
            editedRestaurant.name = request.form['name']
            flash('Restaurant Successfully Edited %s' % editedRestaurant.name)
            return redirect(url_for('showRestaurants'))
    else:
        return render_template('editRestaurant.html', restaurant = editedRestaurant)


#Delete a restaurant
@app.route('/restaurant/<int:restaurant_id>/delete/', methods = ['GET','POST'])
def deleteRestaurant(restaurant_id):
    if 'username' not in login_session:
        return redirect('/login')
    restaurantToDelete = session.query(Restaurant).filter_by(id = restaurant_id).one()
    if not is_owner(restaurant):
        return redirect('/restaurant')
    if request.method == 'POST':
        session.delete(restaurantToDelete)
        flash('%s Successfully Deleted' % restaurantToDelete.name)
        session.commit()
        return redirect(url_for('showRestaurants', restaurant_id = restaurant_id))
    else:
        return render_template('deleteRestaurant.html',restaurant = restaurantToDelete)

#Show a restaurant menu
@app.route('/restaurant/<int:restaurant_id>/')
@app.route('/restaurant/<int:restaurant_id>/menu/')
def showMenu(restaurant_id):
    restaurant = session.query(Restaurant).filter_by(id = restaurant_id).one()
    items = session.query(MenuItem).filter_by(restaurant_id = restaurant_id).all()
    # check if a user is signed in AND that user is the creator of the rest
    print("debug_showMenu", "Current viewer is owner", is_owner(restaurant))
    if is_owner(restaurant):
    #   Get creator
        creator = getUserInfo(restaurant.user_id)
    #   Render private menu
        return render_template('menu.html', items=items, creator=creator)
    # Render public menu
    else:
        return render_template('publicmenu.html', items = items, restaurant = restaurant)
        

#Create a new menu item
@app.route('/restaurant/<int:restaurant_id>/menu/new/',methods=['GET','POST'])
def newMenuItem(restaurant_id):
    #if 'username' not in login_session:
     #   return redirect('/login')
    restaurant = session.query(Restaurant).filter_by(id = restaurant_id).one()

    if not is_owner(restaurant):
        return redirect('/restaurant')

    if request.method == 'POST':
        newItem = MenuItem(name = request.form['name'],
                           description = request.form['description'],
                           price = request.form['price'],
                           course = request.form['course'],
                           restaurant_id = restaurant_id,
                           user_id = restaurant.user_id)
        session.add(newItem)
        session.commit()
        flash('New Menu %s Item Successfully Created' % (newItem.name))
        return redirect(url_for('showMenu', restaurant_id = restaurant_id))
    else:
        return render_template('newmenuitem.html', restaurant_id = restaurant_id)

#Edit a menu item
@app.route('/restaurant/<int:restaurant_id>/menu/<int:menu_id>/edit', methods=['GET','POST'])
def editMenuItem(restaurant_id, menu_id): 
    if 'username' not in login_session:
        return redirect('/login')
    editedItem = session.query(MenuItem).filter_by(id = menu_id).one()
    if not is_owner(editedItem):
        return redirect('/restaurant')

    restaurant = session.query(Restaurant).filter_by(id = restaurant_id).one()
    if request.method == 'POST':
        if request.form['name']:
            editedItem.name = request.form['name']
        if request.form['description']:
            editedItem.description = request.form['description']
        if request.form['price']:
            editedItem.price = request.form['price']
        if request.form['course']:
            editedItem.course = request.form['course']
        session.add(editedItem)
        session.commit() 
        flash('Menu Item Successfully Edited')
        return redirect(url_for('showMenu', restaurant_id = restaurant_id))
    else:
        return render_template('editmenuitem.html', restaurant_id = restaurant_id, menu_id = menu_id, item = editedItem)


#Delete a menu item
@app.route('/restaurant/<int:restaurant_id>/menu/<int:menu_id>/delete', methods = ['GET','POST'])
def deleteMenuItem(restaurant_id,menu_id):
    if 'username' not in login_session:
        return redirect('/login')
    restaurant = session.query(Restaurant).filter_by(id = restaurant_id).one()
    itemToDelete = session.query(MenuItem).filter_by(id = menu_id).one() 
    if not is_owner(itemToDelete):
        return redirect('/restaurant')
    if request.method == 'POST':
        session.delete(itemToDelete)
        session.commit()
        flash('Menu Item Successfully Deleted')
        return redirect(url_for('showMenu', restaurant_id = restaurant_id))
    else:
        return render_template('deleteMenuItem.html', item = itemToDelete)

# Methods to help get user information
def createUser(login_session):
    newUser = User(name = login_session['username'],
                   email=login_session['email'],
                   picture=login_session['picture'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email = login_session['email']).one()
    return user.id

def getUserInfo(user_id):
    user = session.query(User).filter_by(id=user_id).one()
    return user

def getUserId(email):
    try:
        user = session.query(User).filter_by(email = email).one()
        return user.id
    except:
        return None
def is_owner(restaurant):
    if 'username' not in login_session or restaurant.user_id is None:
        return False
    else:
        return login_session['username'] == getUserInfo(restaurant.user_id).name

if __name__ == '__main__':
  app.secret_key = 'super_secret_key'
  app.debug = True
  app.run(host = '0.0.0.0', port = 5000)
