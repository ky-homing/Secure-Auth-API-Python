import secrets 
import sqlite3 
import os 
import json
import hashlib 
import base64
import hmac

from flask import Flask, request, jsonify 

user_query = "SELECT user_id, username, email_address, first_name, last_name, salt, moderator FROM users WHERE username = ?"
email_query = "SELECT user_id FROM users WHERE email_address = ?"
pass_hash_query = "SELECT password_hash FROM passwords WHERE user_id = ? ORDER BY password_id DESC LIMIT 1"
pass_used_query = "SELECT * FROM passwords WHERE user_id = ? AND password_hash = ?"
create_user_query = "INSERT INTO users (username, email_address, first_name, last_name, salt, moderator) VALUES (?, ?, ?, ?, ?, ?)"
create_password_query = "INSERT INTO passwords (user_id, password_hash) VALUES (?, ?)"
update_username_query = "UPDATE users SET username = ? WHERE user_id = ?"
update_password_query = create_password_query

create_post_query = "INSERT INTO posts (post_id, owner_id, title, body) VALUES (?, ?, ?, ?)"
create_post_tag_query = "INSERT INTO tags (post_id, tag) VALUES (?, ?)"
follow_check = "SELECT * FROM follows WHERE follower_id = ? AND following_id = ?"
follow_query = "INSERT INTO follows (follower_id, following_id) VALUES (?, ?)"
owner_query = "SELECT owner_id FROM posts WHERE post_id = ?"
follower_following_query = "SELECT 1 FROM follows WHERE follower_id = ? AND following_id = ?"
like_query = "INSERT INTO likes (user_id, post_id) VALUES (?, ?)"
view_post_query = "SELECT title, body, owner_id FROM posts WHERE post_id = ?"
username_query = "SELECT username FROM users WHERE user_id = ?"
not_owner_query = follower_following_query
tags_view_query = "SELECT tag FROM tags WHERE post_id = ?"
likes_view_query = "SELECT COUNT(*) FROM likes WHERE post_id = ?"
feed_query = "SELECT p.post_id, p.title, p.body, u.username FROM posts AS p JOIN users AS u ON p.owner_id = u.user_id WHERE p.owner_id IN (SELECT following_id FROM follows WHERE follower_id = ?) ORDER BY p.post_id DESC LIMIT 5"
tag_query = "SELECT p.post_id, p.title, p.body, u.username FROM posts AS p JOIN users AS u ON p.owner_id = u.user_id JOIN tags AS t ON p.post_id = t.post_id WHERE t.tag = ? AND p.owner_id IN (SELECT following_id FROM follows WHERE follower_id = ?)"
tags_response_query = tags_view_query
likes_response_query = likes_view_query
delete_user_query = "DELETE FROM users WHERE username = ?"
owner_post_query = owner_query
delete_post_query = "DELETE FROM posts WHERE post_id = ?"

app = Flask(__name__)
db_name = "project2.db"
sql_file = "project2.sql"
db_flag = False

def create_db():
    global db_flag 
    conn = sqlite3.connect(db_name)
    conn.execute("PRAGMA foreign_keys = ON")

    with open(sql_file, "r") as sql_startup: 
        init_db = sql_startup.read()
    
    cursor = conn.cursor()
    cursor.executescript(init_db)
    
    conn.commit() 
    conn.close() 
    db_flag = True 

def get_db():
    global db_flag
    if not db_flag:
        create_db()

    conn = sqlite3.connect(db_name)
    conn.execute("PRAGMA foreign_keys = ON")
    return conn

def hash_password(password, salt):
    return hashlib.pbkdf2_hmac(
        "sha256", 
        password.encode("utf-8"), 
        salt.encode("utf-8"), 
        100000
    ).hex()

def read_key_file():
    with open("key.txt", "r") as key_file:
        return key_file.read().strip()

def b64url_encode(datas):
    json_string = json.dumps(datas)
    encoded = base64.urlsafe_b64encode(json_string.encode("utf-8")).decode("utf-8")
    return encoded

def b64url_decode(encoded_string):
    decoded = base64.urlsafe_b64decode(encoded_string.encode("utf-8")).decode("utf-8")
    return json.loads(decoded)

def make_signature(catenated_hp, key):
    return hmac.new(key.encode("utf-8"), catenated_hp.encode("utf-8"), hashlib.sha256).hexdigest()

def generate_jwt(username):
    user = get_user_by_username(username)
    if user is None: 
        return None
    
    header = {
        "alg": "HS256", 
        "typ": "JWT"
    }

    payload = {
        "username": username, 
        "access": "True"
    }

    moderator_value = user[6]
    if moderator_value == "True":
        payload["moderator"] = "True"

    encoded_header = b64url_encode(header)
    encoded_payload = b64url_encode(payload)
    catenated_hp = encoded_header + "." + encoded_payload

    key = read_key_file()
    signature = make_signature(catenated_hp, key)

    return catenated_hp + "." + signature

def verify_jwt(jwt_token):
    parts = jwt_token.split(".")
    if len(parts) != 3:
        return None
        
    encoded_header = parts[0]
    encoded_payload = parts[1]
    given_signature = parts[2]

    catenated_hp = encoded_header + "." + encoded_payload
    key = read_key_file()
    expected_signature = make_signature(catenated_hp, key)

    if not hmac.compare_digest(given_signature, expected_signature): 
        return None
        
    header = b64url_decode(encoded_header)
    payload = b64url_decode(encoded_payload)

    if header.get("alg") != "HS256" or header.get("typ") != "JWT":
        return None
    
    if payload.get("access") != "True":
        return None
    if "username" not in payload:
        return None
        
    return payload
    
def get_user_by_username(username):
    conn = get_db()
    try: 
        cursor = conn.cursor()
        cursor.execute(user_query, (username,))
        result = cursor.fetchone()
        conn.close()
        return result
    except Exception:
        conn.close()
        return None
    
def get_user_by_email(email_address):
    conn = get_db()
    try: 
        cursor = conn.cursor()
        cursor.execute(email_query, (email_address,))
        result = cursor.fetchone()
        conn.close()
        return result 
    except Exception:
        conn.close()
        return None
    
def get_current_password_hash(user_id):
    conn = get_db()
    try: 
        cursor = conn.cursor()
        cursor.execute(pass_hash_query, (user_id,))
        row = cursor.fetchone()
        conn.close()

        if row is None: 
            return None
        return row[0]
    except Exception:
        conn.close()
        return None
    
def password_used_before(user_id, new_hash): 
    conn = get_db()
    try: 
        cursor = conn.cursor()
        cursor.execute(pass_used_query, (user_id, new_hash))
        row = cursor.fetchone()
        conn.close()

        return row is not None
    except Exception:
        conn.close()
        return None
    
def is_valid_password(password, username, first_name, last_name):
    if password is None:
        return False
    
    if len(password) < 8:
        return False
    
    has_upper = False
    has_lower = False
    has_digit = False

    for c in password:
        if c.isupper():
            has_upper = True
        elif c.islower():
            has_lower = True
        elif c.isdigit():
            has_digit = True

    if not has_upper or not has_lower or not has_digit: 
        return False
    
    lowered_password = password.lower()

    if username is not None and username.lower() in lowered_password:
        return False
    if first_name is not None and first_name.lower() in lowered_password:
        return False
    if last_name is not None and last_name.lower() in lowered_password:
        return False
    
    return True

@app.route('/', methods=['GET'])
def index():
    return jsonify({"status": 1})

@app.route('/create_user', methods=(['POST']))
def create_user():
    first_name = request.form.get('first_name')
    last_name = request.form.get('last_name')
    username = request.form.get('username')
    email_address = request.form.get('email_address')
    password = request.form.get('password')
    salt = secrets.token_hex(16)
    moderator = request.form.get('moderator')


    if not username or not email_address or not password:
        return jsonify({
            "status": 4, 
            "pass_hash": "NULL"
        })3
    
    if moderator is None: 
        moderator = "False"
    else: 
        moderator = str(moderator)

    if get_user_by_username(username) is not None:
        return jsonify({
            "status": 2, 
            "pass_hash": "NULL"
        })
    
    if get_user_by_email(email_address) is not None:
        return jsonify({
            "status": 3, 
            "pass_hash": "NULL"
        })
    
    if not is_valid_password(password, username, first_name, last_name):
        return jsonify({
            "status": 4, 
            "pass_hash": "NULL"
        })
    
    password_hash = hash_password(password, salt)

    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute(create_user_query, (username, email_address, first_name, last_name, salt, moderator))

        user_id = cursor.lastrowid 

        cursor.execute(create_password_query, (user_id, password_hash))

        conn.commit()
        conn.close()

        return jsonify({
            "status": 1, 
            "pass_hash": password_hash
        })
    
    except Exception: 
        return jsonify({
            "status": 4, 
            "pass_hash": "NULL"
        })

@app.route('/login', methods=(['POST']))
def login():
    username = request.form.get('username')
    password = request.form.get('password')

    user = get_user_by_username(username)
    if user is None:
        return jsonify({
            "status": 2, 
            "jwt": "NULL"
        })
    
    user_id = user[0]
    salt = user[5]

    current_hash = get_current_password_hash(user_id)
    given_hash = hash_password(password, salt)

    if current_hash != given_hash:
        return jsonify({
            "status": 2, 
            "jwt": "NULL"
        })
    
    token = generate_jwt(username)

    return jsonify({
        "status": 1, 
        "jwt": token
    })

@app.route('/update', methods=(['POST']))
def update():
    jwt_token = request.headers.get('Authorization')
    payload = verify_jwt(jwt_token)

    if payload is None:
        return jsonify({"status": 3})
    
    jwt_username = payload.get("username")
    user = get_user_by_username(jwt_username)

    if user is None:
        return jsonify({"status": 3})
    
    user_id = user[0]
    current_username = user[1]
    first_name = user[3]
    last_name = user[4]
    salt = user[5]

    old_username = request.form.get('username')
    new_username = request.form.get('new_username')
    old_password = request.form.get('old_password')
    new_password = request.form.get('new_password')

    if old_username is not None and new_username is not None:
        if old_username != current_username:
            return jsonify({"status": 2})
        
        if get_user_by_username(new_username) is not None:
            return jsonify({"status": 2})

        try: 
            conn = get_db()
            cursor = conn.cursor()
            cursor.execute(update_username_query, (new_username, user_id))

            conn.commit()
            conn.close()

            return jsonify({"status": 1})
        
        except Exception: 
            return jsonify({"status": 2})
        
    if old_password is not None and new_password is not None:
        old_hash = hash_password(old_password, salt)
        current_hash = get_current_password_hash(user_id)

        if old_hash != current_hash:
            return jsonify({"status": 2})
        
        if not is_valid_password(new_password, current_username, first_name, last_name):
            return jsonify({"status": 2})
        
        new_hash = hash_password(new_password, salt)

        if password_used_before(user_id, new_hash):
            return jsonify({"status": 2})

        try:
            conn = get_db()
            cursor = conn.cursor()
            cursor.execute(update_password_query, (user_id, new_hash))

            conn.commit()
            conn.close()

            return jsonify({"status": 1})
        
        except Exception:
            return jsonify({"status": 2})
        
    return jsonify({"status": 2})

@app.route('/view', methods=(['POST']))
def view():
    jwt_token = request.headers.get('Authorization')
    payload = verify_jwt(jwt_token)

    if payload is None:
        return jsonify({
            "status": 2, 
            "data": "NULL"
        })
    
    username = payload.get("username")
    user = get_user_by_username(username)

    if user is None:
        return jsonify({
            "status": 2, 
            "data": "NULL"
        })
    
    return jsonify({
        "status": 1, 
        "data": { 
            "username": user[1], 
            "email_address": user[2], 
            "first_name": user[3], 
            "last_name": user[4]
        }
    })

# needs JWT in header, takes title, body, post id, tags
# tags = request.form.get('tags') | if tags: tags = json.loads(tags) | loop and insert into tags table
@app.route('/create_post', methods=(['POST']))
def create_post():
    jwt_token = request.headers.get('Authorization')
    payload = verify_jwt(jwt_token)

    if payload is None: 
        return jsonify({"status": 2})
    
    username = payload.get("username")
    user = get_user_by_username(username)

    if user is None: 
        return jsonify({"status": 2})
    
    owner_id = user[0]
    title = request.form.get('title')
    body = request.form.get('body')
    post_id = request.form.get('post_id')
    tags_json = request.form.get('tags')

    if not title or not body or not post_id:
        return jsonify({"status": 2})

    try: 
        conn = get_db()
        cursor = conn.cursor()

        cursor.execute(create_post_query, (post_id, owner_id, title, body))

        if tags_json is not None: 
            tags_dict = json.loads(tags_json)
            for key in tags_dict: 
                tag_text = tags_dict[key]
                cursor.execute(create_post_tag_query, (post_id, tag_text))

        conn.commit()
        conn.close()

        return jsonify({"status": 1})
    except Exception: 
        return jsonify({"status": 2})
    
# get JWT from header, find current user, get username from request, insert into follows table, prevent duplicates
@app.route('/follow', methods=(['POST']))
def follow():
    jwt_token = request.headers.get('Authorization')
    payload = verify_jwt(jwt_token)

    if payload is None: 
        return jsonify({"status": 2})
    
    follower_username = payload.get("username")
    target_username = request.form.get("username")

    if follower_username is None or target_username is None:
        return jsonify({"status": 2})

    follower_user = get_user_by_username(follower_username)
    target_user = get_user_by_username(target_username)

    if follower_user is None or target_user is None: 
        return jsonify({"status": 2})
    
    follower_id = follower_user[0]
    following_id = target_user[0]

    if following_id == follower_id: 
        return jsonify({"status": 2})
        
    try: 
        conn = get_db()
        cursor = conn.cursor()

        cursor.execute(follow_check, (follower_id, following_id))
        existing_follow = cursor.fetchone()

        if existing_follow is not None: 
            conn.close()
            return jsonify({"status": 2})
        
        cursor.execute(follow_query, (follower_id, following_id))
        conn.commit()
        conn.close()

        return jsonify({"status": 1})
    except Exception: 
        return jsonify({"status": 2})

# verify JWT, check if user follows post owner, insert into likes table
@app.route('/like', methods=(['POST']))
def like():
    jwt_token = request.headers.get('Authorization')
    payload = verify_jwt(jwt_token)

    if payload is None: 
        return jsonify({"status": 2})
    
    username = payload.get("username")
    user = get_user_by_username(username)

    if user is None: 
        return jsonify({"status": 2})
    
    user_id = user[0]
    post_id = request.form.get("post_id")

    try: 
        conn = get_db()
        cursor = conn.cursor()

        cursor.execute(owner_query, (post_id,))
        post_row = cursor.fetchone()

        if post_row is None:
            conn.close()
            return jsonify({"status": 2})
        
        owner_id = post_row[0]

        cursor.execute(follower_following_query, (user_id, owner_id))
        follows_row = cursor.fetchone()

        if follows_row is None: 
            conn.close()
            return jsonify({"status": 2})
        
        cursor.execute(like_query, (user_id, post_id))

        conn.commit()
        conn.close()
        return jsonify({"status": 1})
    except Exception:
        return jsonify({"status": 2})

# only return requested fields, must check if user follows owner or user is owner
@app.route('/view_post/<post_id>', methods=(['GET']))
def view_post(post_id):
    jwt_token = request.headers.get('Authorization')
    payload = verify_jwt(jwt_token)

    if payload is None: 
        return jsonify({"status": 2, "data": "NULL"})
    
    viewer_username = payload.get("username")
    viewer_user = get_user_by_username(viewer_username)

    if viewer_user is None: 
        return jsonify({"status": 2, "data": "NULL"})
    
    viewer_id = viewer_user[0]

    try: 
        conn = get_db()
        cursor = conn.cursor()

        cursor.execute(view_post_query, (post_id,)) 
        post_row = cursor.fetchone()

        if post_row is None:
            conn.close()
            return jsonify({"status": 2, "data": "NULL"})
        
        title = post_row[0] 
        body = post_row[1]
        owner_id = post_row[2]

        cursor.execute(username_query, (owner_id,))
        owner_row = cursor.fetchone()

        if owner_row is None:
            conn.close()
            return jsonify({"status": 2, "data": "NULL"})
        
        owner_username = owner_row[0]

        if viewer_id != owner_id:
            cursor.execute(not_owner_query, (viewer_id, owner_id))
            follow_row = cursor.fetchone()

            if follow_row is None:
                conn.close()
                return jsonify({"status": 2, "data": "NULL"})
            
        data = {}

        if request.args.get('title') is not None:
            data["title"] = title
        if request.args.get('body') is not None:
            data["body"] = body

        if request.args.get('tags') is not None:
            cursor.execute(tags_view_query, (post_id,))   
            tag_rows = cursor.fetchall()
            data["tags"] = [row[0] for row in tag_rows]
            
        if request.args.get('owner') is not None:
            data["owner"] = owner_username
        
        if request.args.get('likes') is not None:
            cursor.execute(likes_view_query, (post_id,)) 
            like_count = cursor.fetchone()[0]
            data["likes"] = str(like_count)

        conn.close()
        return jsonify({"status": 1, "data": data})
    except Exception:
        return jsonify({"status": 2, "data": "NULL"})

# feed = true: return 5 most recent posts
# tag = something: filter by tag
@app.route('/search', methods=(['GET']))
def search():
    jwt_token = request.headers.get('Authorization')
    payload = verify_jwt(jwt_token)

    if payload is None:
        return jsonify({"status": 2, "data": "NULL"})
    
    username = payload.get("username")
    user = get_user_by_username(username)

    if user is None:
        return jsonify({"status": 2, "data": "NULL"})
    
    user_id = user[0]

    try:
        conn = get_db()
        cursor = conn.cursor()

        result = {}

        if request.args.get("feed") is not None:
            cursor.execute(feed_query, (user_id,))
            posts = cursor.fetchall()

        elif request.args.get("tag") is not None:
            tag_value = request.args.get("tag")
            cursor.execute(tag_query, (tag_value, user_id))
            posts = cursor.fetchall()

        else:
            return jsonify({"status": 2, "data": "NULL"})
        
        for row in posts:
            post_id = str(row[0])
            title = row[1]
            body = row[2]
            owner = row[3]

            cursor.execute(tags_response_query, (post_id,))
            tag_rows = cursor.fetchall()
            tags = [t[0] for t in tag_rows]

            cursor.execute(likes_response_query, (post_id,))
            like_count = cursor.fetchone()[0]
            
            result[post_id] = {
                "title": title, 
                "body": body, 
                "tags": tags, 
                "owner": owner, 
                "likes": str(like_count)
            }

        conn.close()
        return jsonify({"status": 1, "data": result})
    except Exception as e:
        print("SEARCH ERROR:", e)
        return jsonify({"status": 2, "data": "NULL"})
        
# delete post, delete user, moderator logic 
# use ON DELETE CASCADE
@app.route('/delete', methods=(['POST']))
def delete():
    jwt_token = request.headers.get('Authorization')
    payload = verify_jwt(jwt_token)

    if payload is None:
        return jsonify({"status": 2})
    
    username = payload.get("username")
    requester = get_user_by_username(username)

    if requester is None:
        return jsonify({"status": 2})
    
    requester_id = requester[0]
    is_moderator = False

    if len(requester) > 6 and requester[6] == "True":
        is_moderator = True

    target_username = request.form.get("username")
    post_id = request.form.get("post_id")

    try:
        conn = get_db()
        cursor = conn.cursor()

        if target_username is not None:
            if target_username != username:
                conn.close()
                return jsonify({"status": 2})
            
            cursor.execute(delete_user_query, (target_username,))

            conn.commit()
            conn.close()
            return jsonify({"status": 1})
        
        if post_id is not None: 
            cursor.execute(owner_post_query, (post_id,))
            row = cursor.fetchone()

            if row is None:
                conn.close()
                return jsonify({"status": 2})
            
            owner_id = row[0]

            if owner_id != requester_id and not is_moderator:
                conn.close()
                return jsonify({"status": 2})
            
            cursor.execute(delete_post_query, (post_id,))

            conn.commit()
            conn.close()
            return jsonify({"status": 1})
        
        conn.close()
        return jsonify({"status": 2})
    except Exception:
        return jsonify({"status": 2})

@app.route('/clear', methods=(['GET']))
def clear():
    global db_flag

    try: 
        if os.path.exists(db_name):
            os.remove(db_name)

        db_flag = False
        return json.dumps({"status": 1})
    except Exception: 
        return json.dumps({"status": 2})

if __name__ == "__main__":
    app.run()
