import wtforms
from wtforms.validators import Length
from modules import User
class RefisterForm(wtforms.Form):
    username = wtforms.StringField(validators=[Length(min=1,max=15,message="用户名格式错误")])
    password=wtforms.StringField(validators=[Length(min=6,max=18,message="密码格式错误")])

    def validate_username(self,field):
        username=field.data
        user=User.query.filter_by(username=username).first()
        if user:
            raise wtforms.ValidationError(message="改用户名已存在")

class LoginForm(wtforms.Form):
    username = wtforms.StringField(validators=[Length(min=1,max=15,message="用户名格式错误")])
    password=wtforms.StringField(validators=[Length(min=6,max=18,message="密码格式错误")])