import os
import io
import json

import torch
import torchvision.transforms as transforms
from PIL import Image
import model

import string
import random

from flask import Flask, jsonify, request, render_template, redirect, session, url_for, g
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from exts import db
from modules import User
import config
from flask_migrate import Migrate
from forms import RefisterForm, LoginForm
from werkzeug.security import generate_password_hash, check_password_hash
import hashlib

app = Flask(__name__)
CORS(app)  # 跨域
app.config.from_object(config)
db.init_app(app)
migrate=Migrate(app,db)

weights_path = "./model-9.pth"
class_json_path = "./class_indices.json"
assert os.path.exists(weights_path), "weights path does not exist..."
assert os.path.exists(class_json_path), "class json path does not exist..."

device = torch.device("cuda:0" if torch.cuda.is_available() else "cpu")
print(device)

model = model.swin_tiny_patch4_window7_224(num_classes=5).to(device)
model.load_state_dict(torch.load(weights_path, map_location=device))

model.eval()

json_file = open(class_json_path, 'rb')
class_indict = json.load(json_file)

def transform_image(image_bytes):
    my_transforms = transforms.Compose([transforms.Resize(255),
                                        transforms.CenterCrop(224),
                                        transforms.ToTensor(),
                                        transforms.Normalize(
                                            [0.485, 0.456, 0.406],
                                            [0.229, 0.224, 0.225])])
    image = Image.open(io.BytesIO(image_bytes))
    if image.mode != "RGB":
        raise ValueError("input file does not RGB image...")
    return my_transforms(image).unsqueeze(0).to(device)


def get_prediction(image_bytes):
    try:
        tensor = transform_image(image_bytes=image_bytes)
        print(tensor.size())
        outputs = torch.softmax(model.forward(tensor).squeeze(), dim=0)
        prediction = outputs.detach().cpu().numpy()
        template = "class:{:<15} probability:{:.3f}"  #template = "class:{:<15} probability:{:.3f}"
        index_pre = [(class_indict[str(index)], float(p)) for index, p in enumerate(prediction)]
        index_pre.sort(key=lambda x: x[1], reverse=True)
        k=index_pre[0][0]
        v=index_pre[0][1]
        text = [k,v]  # text = [template.format(k, v) for k, v in index_pre]
        return_info = {"result": text} #return_info = {"result": text}
    except Exception as e:
        return_info = {"result": [str(e)]}
    return return_info

@app.route("/predict", methods=["POST"])
@torch.no_grad()
def predict():
    image = request.files["file"]
    img_bytes = image.read()
    info = get_prediction(image_bytes=img_bytes)
    return jsonify(info)

@app.route("/low_pro", methods=["POST"])
def low_pro():
    image = request.files["file"]
    label = request.form["label"]
    print(image,label)
    app.config['UPLOAD_FOLDER'] = './upload/'+label+'/'
    file_dir = app.config['UPLOAD_FOLDER']
    if not os.path.exists(file_dir):
        os.makedirs(file_dir)
    image.save(os.path.join(app.config['UPLOAD_FOLDER'], image.filename))
    return jsonify("done")


@app.route("/use", methods=["GET", "POST"])
def root():
    return render_template("up.html")


@app.route("/register", methods=["GET", "POST"])
def register():                     #p=sha256(md5(psw)+salt)
    if request.method == 'GET':
        return render_template("register.html")
    else:
        form = RefisterForm(request.form)
        if form.validate():
            username=form.username.data
            password=form.password.data
            length_of_string = 20
            randomkey=''.join(random.choice(string.ascii_letters + string.digits) for _ in range(length_of_string))
            password=hashlib.md5(password.encode('utf-8')).hexdigest()
            password=password+randomkey
            password=hashlib.sha256(password.encode('utf-8')).hexdigest()
            user=User(username=username,password=password,salt=randomkey)
            db.session.add(user)
            db.session.commit()
            return redirect(url_for("login"))
        else:
            print(form.errors)
            return redirect(url_for("register"))

@app.route("/", methods=["GET", "POST"])
def login():
    if session.get('user_id'):
       return render_template("up.html")
    if request.method == 'GET':
        return  render_template("login.html")
    else:
        form=LoginForm(request.form)
        if form.validate():
            username=form.username.data
            password=form.password.data
            user=User.query.filter_by(username=username).first()
            if not user:
                print("用户名不存在")
                return redirect(url_for("login"))
            password=hashlib.md5(password.encode('utf-8')).hexdigest()
            password=password+user.salt
            password=hashlib.sha256(password.encode('utf-8')).hexdigest()
            if password==user.password:
                session['user_id']=user.id
                return redirect(url_for("root"))
            else:
                print("密码错误")
                return redirect(url_for("login"))
        else:
            print(form.errors)
            return redirect(url_for("login"))

@app.route("/logout",methods=["GET"])
def logout():
    session.clear()
    return redirect(url_for("login"))

@app.before_request
def before_request():
    user_id=session.get("user_id")
    if user_id:
        user=User.query.get(user_id)
        setattr(g,"user",user)
    else:
        setattr(g,"user",None)

@app.context_processor
def context_processor():
    return {"user":g.user}

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=5000)




