from io import BytesIO
import os

from flask import render_template, url_for, flash, redirect, request , abort , send_file , send_from_directory
from flask_login import login_user, current_user, logout_user, login_required
from werkzeug.utils import secure_filename
from vault_app import app, db, bcrypt
from vault_app.forms import RegistrationForm, LoginForm 
from vault_app.models import User, Post
from vault_app.checkfiletype import *

from vault_app.encrypt import encrypt_file
from vault_app.decrypt import decrypt_file



BASE_DIR = os.getcwd()

ENCRYPT_DIR = BASE_DIR + "\\ENCRYPTED_FILES\\"

DECRYPT_DIR = BASE_DIR + "\\DECRYPTED_FILES\\"


@app.route('/')
def home():
    return render_template('home.html')


@app.route("/register", methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(
            form.password.data).decode('utf-8')
        user = User(username=form.username.data,
                    email=form.email.data, password=hashed_password)
        db.session.add(user)
        db.session.commit()
        flash('Your account has been created! You are now able to log in', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', title='Register', form=form)


@app.route("/login", methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('account'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user, remember=False)
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('account'))
        else:
            flash('Login Unsuccessful. Please check email and password', 'danger')
    return render_template('login.html', title='Login', form=form)


@app.route("/logout")
def logout():
    logout_user()
    return redirect(url_for('home'))


@app.route("/account")
@login_required
def account():
    files = Post.query.filter_by(author=current_user).order_by(Post.date_posted.desc())
    #files = Post.query.all()
    return render_template('account.html', title='Account' , files = files)


@app.route("/post/new", methods=['GET', 'POST'])
@login_required
def new_post():
    if request.method == 'POST':
        title = request.form.get("title")
        if 'file' not in request.files:
            flash('No file selected', 'danger')
            return redirect(request.url)

        file = request.files.get('file')
        if file.filename == '':
            flash("no file selected", "danger")
            return redirect(request.url)

        if file and allowed_files(file.filename):
            uploaded_file = file.read()
            post = Post(title=title, fname=file.filename,
                        content=uploaded_file, author=current_user)
            db.session.add(post)
            db.session.commit()
            flash('File Added to Vault successfully', 'success')
        return redirect(request.url)
    return render_template('addToVault.html', title='Add to Vault', legend='ADD TO VAULT:')


@app.route('/download/<int:id>', methods=['GET'])
def download(id):
    file = Post.query.filter_by(id=id).first()
    return send_file(BytesIO(file.content),  mimetype='image/jpg', as_attachment=True, attachment_filename=file.fname)
"""
@app.route("/post/<int:post_id>")
def post(post_id):
    post = Post.query.get_or_404(post_id)
    return render_template('post.html', title=post.title, post=post)
"""

@app.route("/post/<int:post_id>/delete", methods=['GET'])
@login_required
def delete_post(post_id):
    post = Post.query.get_or_404(post_id)
    if post.author != current_user:
        abort(403)
    db.session.delete(post)
    db.session.commit()
    flash('Your post has been deleted!', 'success')
    return redirect(url_for('account'))


@app.route('/encrypt', methods=["GET", "POST"])
def encrypt():
    if request.method == "POST":
        password = request.form.get("pass")
        if request.files:
            file = request.files["file"]
            if(file.filename == ""):
                flash("image must have filename", "danger")
                return redirect(request.url)
            # fh = open(ENCRYPT_DIR + "key.txt", "w")
            # fh.write(password)
            # fh.close()
            fname = secure_filename(file.filename)
            fpath = ENCRYPT_DIR + fname
            file.save(fpath)
            flag = encrypt_file(fpath, password)
            if flag == 1:
                flash("File Encrypted Successfully", 'success')
                return redirect(url_for('download_encrypted_file', filename=fname))
            else:
                flash("Error during Encryption Try Again!","danger")
                return redirect(url_for('encrypt'))
        else:
            flash("File could not be uploaded Try Again!","danger")
            return redirect(url_for('encrypt'))
    return render_template('encrypt.html')


@app.route('/encrypt/download/<path:filename>')
def download_encrypted_file(filename):
    return send_from_directory(ENCRYPT_DIR, path=filename, as_attachment=True)


@app.route('/decrypt', methods=["GET", "POST"])
def decrypt():
    if request.method == "POST":
        password = request.form.get("pass")
        if request.files:
            file = request.files["file"]
            if(file.filename == ""):
                flash("image must have filename","danger")
                return redirect(request.url)
            fname = secure_filename(file.filename)
            fpath = DECRYPT_DIR + fname
            file.save(fpath)
            flag = decrypt_file(fpath, password)
            if flag == 1:
                return redirect(url_for('download_decrypted_file', filename=fname))
            elif flag == -1:
                #flash("Incorrect Password")
                #return redirect(url_for('decrypt'))
                flash("Incorrect Password", "danger")
                return redirect(url_for('decrypt'))
            else:
                flash("Error during Decryption Try Again!","danger")
                return redirect(url_for('decrypt'))
        else:
            flash("File could not be uploaded Try Again!","danger")
            return redirect(url_for('decrypt'))
    return render_template('decrypt.html')


@app.route('/decrypt/download/<path:filename>')
def download_decrypted_file(filename):
    return send_from_directory(DECRYPT_DIR, path=filename, as_attachment=True)
