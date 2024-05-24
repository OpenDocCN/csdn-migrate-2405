# Flask 框架秘籍（二）

> 译者：[Liusple](https://blog.csdn.net/Liusple)
> 
> 来源：<https://blog.csdn.net/liusple/category_7379896.html>

# 第五章：使用 WTForms 处理表单

表单处理是任何应用程序中不可或缺的一部分。无数的案例说明任何 web 应用中表单的存在都是非常重要的。用户登录或者提交一些数据，或者需要从用户得到一些输入，这些都需要表单。和表单同样重要的是表单验证。以交互的方式向用户展示验证信息会提高用户体验。

这一章，将涉及以下小节：

*   SQLAlchemy 模型数据做为表单展现
*   在服务器端验证字段
*   创建一个通用的表单集
*   创建自定义字段和验证
*   创建自定义部件（widget）
*   通过表单上传文件
*   CSRF 保护

## 介绍

web 应用中有许多设计和实现表单的方法。随着 Web2.0 的出现，表单验证和向用户展示验证信息变得非常重要。客户端验证可以在前端使用 JavaScript 和 HTML5 完成。服务端验证在增加应用安全方面扮演一个重要的角色，防止添加任何不正确的数据进入数据库。

WTForms 默认情况下给服务端提供了许多的字段，这加快了开发的速度减少了工作量。它同样提供了根据需要编写自定义验证器和自定义字段的灵活性。
我们这一章将使用一个 Flask 扩展，叫做 Flask-WTF（`https://flask-wtf.readthedocs.org/en/latest/`）。它集成了了 WTForms 和 Flask，为我们处理了大量我们需要做的事情，使得我们开发应用高效更安全。安装它：

```py
$ pip install Flask-WTF 
```

## SQLAlchemy 模型数据作为表单展现

首先，用 SQLAlchemy 模型创建一个表单。我们将用商品目录应用中的商品模型，然后给它添加在前端使用表单创建商品的功能。

#### 准备

我们将用第四章的商品目录应用,为 Product 模型创建一个表。

#### 怎么做

Product 模型看起来像 models.py 里这些代码：

```py
class Product(db.Model):

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255))
    price = db.Column(db.Float)
    category_id = db.Column(db.Integer, db.ForeignKey('category.id'))
    category = db.relationship('Category', backref=db.backref('products', lazy='dynamic'))
    company = db.Column(db.String(100)) 
```

现在，我们将创建一个 ProductForm 类来表示表单需要的字段，ProductForm 将继承由 flask_wtf 提供的 Form 类。

```py
from flask_wtf import Form
from wtforms import TextField, DecimalField, SelectField

class ProductForm(Form):
    name = TextField('Name')
    price = DecimalField('Price'）
    category = SelectField('Category', coerce=int) 
```

我们从 flask-wtf 扩展导入 Form。其他东西比如 fields 和 validators 都是直接从 wtforms 导入的。字段 Name 是 TextField 类型，它需要 text 数据，Price 是 DecimalField 类型，数据将会被解析为 Python 的十进制类型。设置 Category 类型为 SelectField，这意味着，当创建商品时，只能从之前创建好的类别里选择一个。

###### 注意

注意在 category 字段里有一个叫做 coerce 的参数，它的意思是会在任何验证或者处理之前强制转化表单的输入为一个整数。在这里，强制仅仅意味着转换，由一个特定数据类型到另一个不同的数据类型。

views.py 中 create_product()处理程序需要修改：

```py
from my_app.catalog.models import ProductForm

@catalog.route('/product-create', methods=['GET', 'POST'])
def create_product():
    form = ProductForm(request.form, csrf_enabled=False)
    categories = [(c.id, c.name) for c in Category.query.all()]
    form.category.choices = categories
    if request.method == 'POST':
        name = request.form.get('name')
        price = request.form.get('price')
        category = Category.query.get_or_404(
            request.form.get('category')
        )
        product = Product(name, price, category)
        db.session.add(product)
        db.session.commit()
        flash('The product %s has been created' % name, 'success')
        return redirect(url_for('catalog.product', id=product.id))
    return render_template('product-create.html', form=form) 
```

create_product()方法从 POST 请求中的 form 获取参数。这个方法会在 GET 请求时渲染一个空的表单，其中包含预先填充的选项。在 POST 请求中，表单数据将用来创建一个新的商品，并且当商品创建完成的时候，将会展示创建好的商品页。

###### 注意

你将注意到使用`form=ProductForm(request.form, csrf_enabled=False)`时，我们设置 csrf_enabled 为 False。CSRF 是任何应用中重要的一部分。我们将在这章 CSRF 保护一节做详细讨论。

模板`templates/product-create.html`同样需要修改。WTForms 创建的 objects 对象提供了一个简单的方式去创建 HTML 表单，代码如下：

```py
{% extends 'home.html' %}

{% block container %}
    <div class="top-pad">
        <form method="POST" action="{{ url_for('catalog.create_product') }}" role="form">
            <div class="form-group">{{ form.name.label }}: {{ form.name() }}</div>
            <div class="form-group">{{ form.price.label }}: {{ form.price() }}</div>
            <div class="form-group">{{ form.category.label }}: {{ form.category() }}</div>
            <button type="submit" class="btn btndefault">Submit</button>
        </form>
    </div>
{% endblock %} 
```

#### 原理

在一个 GET 请求中，打开`http://127.0.0.1:5000/product-create`，我们将看到和下面截图类似的表单：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/flask-fw-cb/img/d391c53dbd1c3d25609177075bc949f6.png)

你可以填写这个表单去创建一个新的商品。

#### 其他

*   下一小节将帮助理解怎么验证我们刚刚创建的字段

## 在服务器端验证字段

现在有了表单和字段，我们必须验证他们以确保只有正确的数据存入数据库，并且提前处理这些错误，可以避免破坏数据库。这些验证通常可以用来防止 XSS 和 CSRF 攻击。WTForms 提供了许多字段类型，他们自身有默认验证。除了这些，还有一些验证器可以根据选择和需要使用。我们将使用他们其中的一些来进一步理解这个概念。

#### 怎么做

在 WTForm 字段中很容易添加验证器。我们仅仅需要传递一个 validators 参数，它接收要实现的验证器列表。每个验证器有它自己的参数，这使得可以在很大程度上控制验证。
让我们使用 validations 来修改 ProductForm 类：

```py
from decimal import Decimal
from wtforms.validators import InputRequired, NumberRange

class ProductForm(Form):
    name = TextField('Name', validators=[InputRequired()])
    price = DecimalField('Price', validators=[
        InputRequired(), NumberRange(min=Decimal('0.0'))
    ])
    category = SelectField(
        'Category', validators=[InputRequired()], coerce=int
    ) 
```

这里，在许多字段中添加了 InputRequired 验证器，它意味着这些字段是必须填写的，这些字段如果不填写，表单就不会被提交。

Price 字段有一个额外的验证器 NumberRange，并将 min 参数设置为了 0。这意味着，我们不能用小于 0 的值做为商品的价格。为了完成配合这些调整，我们得修改 create_product()：

```py
@catalog.route('/product-create', methods=['GET', 'POST'])
def create_product():
    form = ProductForm(request.form, csrf_enabled=False)
    categories = [(c.id, c.name) for c in Category.query.all()]
    form.category.choices = categories

    if request.method == 'POST' and form.validate():
        name = form.name.data
        price = form.price.data
        category = Category.query.get_or_404(form.category.data)
        product = Product(name, price, category)
        db.session.add(product)
        db.session.commit()
        flash('The product %s has been created' % name, 'success')
        return redirect(url_for('product', id=product.id))
    if form.errors:
        flash(form.errors, 'danger')
    return render_template('product-create.html', form=form) 
```

###### 提示

form.errors 消息将会以 JSON 形式展示表单错误。可以用更好的形式向用户展示他们，这留给你们自己实现。

这里，我们修改了 create_product()方法去验证输入表单的值，并且检查了请求方法类型。在 POST 请求里，表单数据将先进行验证。如果因为一些原因验证失败了，这个页面将重新渲染一遍，并显示一些错误信息在上面。如果验证成功了，并且商品成功创建了，新建的商品将被展示出来。

#### 原理

现在，试着不填写任何字段进行提交。一个错误警告消息会像下面进行展示：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/flask-fw-cb/img/d7d36e04ff06b5fbe07f3cacb730970e.png)

尝试一些非法验证的不同组合，可以看到不同的错误消息提示。

#### 更多

我们可以使用 validate_on_submit 替代既要检查请求类型是 POST 还是 PUT，还要进行表单验证的过程。之前代码是：

```py
if request.method == 'POST' and form.validate(): 
```

可以用下面方法来替代：

```py
if form.validate_on_submit(): 
```

## 创建一个通用的表单集

一个应用取决于设计和目的会存在各种各样的表单。其中大部分都有相同的字段并且有相同的验证器。我们有可能会想，我们能不能将这些共同的表单分离出来并且当需要的时候重用他们，这对于 WTForms 提供的表单定义的类结构来说，是可能的。

#### 怎么做

在商品目录应用中，我们有两个表单，一个用于 Product，一个用于 Category。这些表单都有一个共同的字段：Name。我们可以为这个字段创建一个通用的表单，然后 Product 和 Category 可以使用这个通用表单而不是都去创建一个 Name 字段。通过下面代码，可以实现这个功能：

```py
class NameForm(Form):
    name = TextField('Name', validators=[InputRequired()])

class ProductForm(NameForm):
    price = DecimalField('Price', validators=[
        InputRequired(), NumberRange(min=Decimal('0.0'))
    ])
    category = SelectField(
        'Category', validators=[InputRequired()], coerce=int
    )
    company = TextField('Company', validators=[Optional()])

class CategoryForm(NameForm):
    pass 
```

我们创建了一个通用的表单 NameForm。表单 ProductForm 和 CategoryForm，他们继承了 NameForm，默认有一个名为 Name 的字段。然后根据需要添加其他字段。

我们可以修改 category_create()方法去使用 CategoryForm 创建种类：

```py
@catalog.route('/category-create', methods=['GET', 'POST'])
def create_category():
    form = CategoryForm(request.form, csrf_enabled=False)

    if form.validate_on_submit():
        name = form.name.data
        category = Category(name)
        db.session.add(category)
        db.session.commit()
        flash('The category %s has been created' % name, 'success')
        return redirect(url_for('catalog.category', id=category.id))
    if form.errors:
        flash(form.errors)
    return render_template('category-create.html', form=form) 
```

为了商品类别的创建，需要新增`templates/category-create.html`模板：

```py
{% extends 'home.html' %}

{% block container %}
    <div class="top-pad">
        <form method="POST" action="{{ url_for('catalog.create_category') }}" role="form">
            <div class="form-group">{{ form.name.label }}: {{ form.name() }}</div>
            <button type="submit" class="btn btndefault">Submit</button>
        </form>
    </div>
{% endblock %} 
```

###### 译者注

新版本 Flask 建议用 StringField 代替使用 TextField

#### 原理

新增商品类别表单看起来像这样：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/flask-fw-cb/img/78bfee9a94903da237e0d647d238e8aa.png)

###### 提示

这是演示如何使用通用表单的一个小例子。这种方法的实际好处可以在电子商务应用程序中看到，我们可以使用公共地址表单，然后可以将它们扩展到单独的计费账单和发货地址表单上。

## 创建自定义字段和验证

除了提供一些字段和验证器，Flask 也提供了创建自定义字段和验证器的灵活性。有时，我们需要解析一些表单参数，但是他们不能利用现有的字段来实现。这种情况下，我们需要自定义字段了。

#### 怎么做

在我们的商品目录中，category 使用 SelectField，我们在 create_product()方法的 GET 请求中，填充了该字段。如果该字段可以自行填充将会变得很方便。我们在 models.py 里实现一个自定义的字段 ：

```py
class CategoryField(SelectField):

    def iter_choices(self):
        categories = [(c.id, c.name) for c in Category.query.all()]
        for value, label in categories:
            yield (value, label, self.coerce(value) == self.data)

    def pre_validate(self, form):
        for v, _ in [(c.id, c.name) for c in Category.query.all()]:
            if self.data == v:
                break
            else:
                raise ValueError(self.gettext('Not a valid choice'))

class ProductForm(NameForm):

    price = DecimalField('Price', validators=[
        InputRequired(), NumberRange(min=Decimal('0.0'))
    ])
    category = CategoryField(
        'Category', validators=[InputRequired()], coerce=int
    ) 
```

SelectField 实现了一个叫做`iter_choices()`的方法，这个方法使用`choices`参数提供的值列表填充表单值。我们重写了`iter_choices()`方法，从数据库里直接获取类别的值，这避免了在每次使用表单的时候每次都需要填写字段的麻烦。

###### 提示

这里通过使用 CategoryField 的行为，同样可以使用 QuerySelectField 实现。参见`http://wtforms.readthedocs.org/en/latest/ext.html#wtforms.ext.sqlalchemy.fields.QuerySelectField`寻求更多信息。

views.py 里的 create_product()方法也需要修改。需移除下面两句：

```py
categories = [(c.id, c.name) for c in Category.query.all()]
form.category.choices = categories 
```

## 原理

上面程序不会有任何视觉效果。唯一的更改是在表单中填充类别值，如上一节所解释的那样。

#### 更多

我们刚刚看了如何自定义字段。相似的，我们可以自定义验证器。假设我们不允许有重复的类别。我们可以在模型里很轻松的实现该功能，现在让我们在表单里使用一个自定义验证器：

```py
from wtforms.validators import ValidationError

def check_duplicate_category(case_sensitive=True):
    def _check_duplicate(form, field):
        if case_sensitive:
            res = Category.query.filter(Category.name.like('%' + field.data + '%')).first()
        else:
            res = Category.query.filter(Category.name.ilike('%' + field.data + '%')).first()
        if res:
            raise ValidationError(
                'Category named %s already exists' % field.data
            )
    return _check_duplicate

class CategoryForm(NameForm):
    name = TextField('Name', validators=[
        InputRequired(), check_duplicate_category()
    ]) 
```

我们用工厂方式（factory style）创建了一个装饰器，我们可以根据是否需要区分大小写来获得不同的验证结果。
我们甚至可以使用基于类的设计，这可以使验证器更加通用和灵活，这留给读者自行探索。

## 创建自定义控件（widget）

就像我们创建自定义字段和验证器一样，我们同样可以创建自定义控件。这些控件允许我们控制前端字段看起来像什么样子。每个字段类型都有一个与之关联的控件。WTForms 本身提供了许多基础的 HTML5 的控件。为了理解如何创建一个自定义控件，我们将转换填写商品类别的 select 控件为一个 radio 控件。我想很多人会说，可以直接使用 WTForms 提供的 radio 字段啊！这里我们仅仅尝试去理解并自己实现它。

#### 怎么做

前面小节，我们创建了 CategoryField。这个字段使用了超类（superclass）Select 提供的 Select 控件。让我们用 radio 输入替换 select 控件：

```py
from wtforms.widgets import html_params, Select, HTMLString

class CustomCategoryInput(Select):

    def __call__(self, field, **kwargs):
        kwargs.setdefault('id', field.id)
        html = []
        for val, label, selected in field.iter_choices():
            html.append(
                '<input type="radio" %s> %s' % (html_params(name=field.name, value=val, checked=selected, **kwargs), label)
            )
        return HTMLString(' '.join(html))

class CategoryField(SelectField):
    widget = CustomCategoryInput()

    # Rest of the code remains same as in last recipe Creating custom field and validation 
```

我们在`CategoryField`类中新增了叫做`widget`的类属性。这个`widget`指向了`CustomCategoryInput`，它处理该字段要呈现出来样子的 HTML 代码生成。`CustomCategoryInput`类有一个`__call__`方法，重写了`iter_choices()`提供的值，现在返回`radio`。

#### 原理

当打开`http://127.0.0.1:5000/product-create`，将会看到：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/flask-fw-cb/img/f66da160458f276a8834904b1faa1ff7.png)

## 通过表单上传文件

通过表单上传文件是许多 Web 框架关注的问题。Flask 和 WTForms 使用了一个简洁的方式为我们处理了。

#### 怎么做

首先需要一点配置。需要向应用配置提供一个参数：`UPLOAD_FOLDER`。这个参数告诉 Flask 上传文件被存储的位置。我们将实现一个存储商品图片的功能。

###### 提示

一种存储商品图片的方式是以二进制的方式存储在数据库里。但是这种方式很低效的，在任何应用中都不推荐使用。我们应该总是将图片和其他文件存储在文件系统中，然后将他们的路径以字符串的形式存储在数据库中。

在`my_app/__init__.py`新增下面配置：

```py
import os

ALLOWED_EXTENSIONS = set(['txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'])
app.config['UPLOAD_FOLDER'] = os.path.realpath('.') + '/my_app/static/uploads' 
```

###### # 译者注

如果是在 windows 运行程序，需要处理反斜杠。简单方式是将/my_app/static/uploads 更改为\my_app\static\uploads，并且需要新建 uploads 文件夹，当然最好的处理方法是兼容 linux 和 windows 两种不同的文件路径处理方式。

###### 提示

看一下`app.config['UPLOAD_FOLDER']`语句，我们存储图片到 static 里的一个子文件中。这将使得渲染图片变得非常容易。`ALLOWED_EXTENSIONS`语句被用来确保只有特定格式的文件才能被上传。这个列表仅仅用作演示，对于图片，我们可以过滤更多类型。

修改模型文件`my_app/catalog/models.py`：

```py
from wtforms import FileField

class Product(db.Model):
    image_path = db.Column(db.String(255))

    def __init__(self, name, price, category, image_path):
        self.image_path = image_path

class ProductForm(NameForm):
    image = FileField('Product Image') 
```

看`ProductForm`中`image`字段`FileField`，和`Product`中`image_path`字段。这就是之前我们讨论的，在文件系统中存储图片，并在数据库中存储他们的路径。

现在修改文件`my_app/catalog/views.py`里的 create_product()方法来保存文件：

```py
import os
from werkzeug import secure_filename
from my_app import ALLOWED_EXTENSIONS

def allowed_file(filename):
    return '.' in filename and filename.lower().rsplit('.', 1)[1] in ALLOWED_EXTENSIONS

@catalog.route('/product-create', methods=['GET', 'POST'])
def create_product():
    form = ProductForm(request.form, csrf_enabled=False)

    if form.validate_on_submit():
        name = form.name.data
        price = form.price.data
        category = Category.query.get_or_404(form.category.data)
        image = request.files['image']
        filename = ''
        if image and allowed_file(image.filename):
            filename = secure_filename(image.filename)
            image.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        product = Product(name, price, category, filename)
        db.session.add(product)
        db.session.commit()
        flash('The product %s has been created' % name, 'success')
        return redirect(url_for('catalog.product', id=product.id))

    if form.errors:
        flash(form.errors, 'danger')
    return render_template('product-create.html', form=form) 
```

我们需要向模板`templates/product-create.html`新增 product-create 表单。修改表单标签定义来包含
enctype 参数，在 Submit 按钮前新增图片字段（或者表单里其他你感觉必要的地方）：

```py
<form method="POST" action="{{ url_for('create_product') }}" role="form" enctype="multipart/form-data">
    <!-- The other field definitions as always -->
    <div class="formgroup">
        {{ form.image.label }}: {{ form.image(style='display:inline;') }}
    </div> 
```

这个表单应该包含参数`enctype="multipart/form-data"`，以便告诉应用该表单参数含有多个数据。

渲染存储在 static 文件夹中的图片非常容易。`templates/product.html`中需要显示图片的地方仅仅需增加 img 标记。

```py
<img src="{{ url_for('static', filename='uploads/' + product.image_path) }}"/> 
```

#### 原理

上传图片的页面将看起来像这样：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/flask-fw-cb/img/7a76f6f58a8d0340f94535e1fbaa0afc.png)

创建了商品之后，图片被显示出来像这样：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/flask-fw-cb/img/7bb9ff037ffd4e02b1e6a886c0674188.png)

## CSRF（Cross-site Request Forgery protection)保护

本章第一小节，我们已经知道了 CSRF 是 web 表单安全中重要的一部分。这里我们将讨论细节。CSRF 指的是跨站请求伪造，即一些人黑进了携带 cookie 的请求，然后使用它触发一些破坏性的活动。我们不会讨论 CSRF 的细节，因为网上有很多关于此的资源。我们将讨论 WTForms 怎么帮助我们防止 CSRF。Flask 默认不提供任何 CSRF 保护，因为这得从表单验证层面进行处理，而不是由 Flask 提供。我们可以使用 Flask-WTF 扩展处理这些。

###### 提示

参加`http://en.wikipedia.org/wiki/Cross-site_request_forgery`了解更多 CSRF。

#### 怎么做

Flask-WTF 默认情况下提供的表单是 CSRF 保护的。如果我们看一下之前的小节，可以看到我们明确的告诉表单不要开启 CSRF 保护。我们仅仅需要删除相应的语句就可以使能 CSRF。
所以，`form = ProductForm(request.form, csrf_enabled=False)`将变为`form = ProductForm(request.form)`。
我们应用同样需要做些配置上的改动。

```py
app.config['WTF_CSRF_SECRET_KEY'] = 'random key for form' 
```

默认情况下，CSRF key 和应用 secret key 是一样的。

当 CSRF 启动的时候，我们得在表单里提供一个额外的字段，这是一个隐藏的字段，包含了 CSRF token。WTForms 为我们处理隐藏的字段，我们仅需在表单里添加`{{ form.csrf_token }}`：

```py
<form method="POST" action="/some-action-like-create-product">
    {{ form.csrf_token }}
</form> 
```

很容易嘛！但是表单提交方式不仅这一种。我们同样会通过 AJAX 提交表单；实际上这比使用普通表单很普遍，这种形式也正取代传统 web 应用。
因为这个原因，我们得在应用配置里增加额外的一步：

```py
from flask_wtf.csrf import CsrfProtect

# Add configurations
CsrfProtect(app) 
```

前面的配置将允许我们可以在模板的任何位置通过使用{{ csrf_token() }}获取 CSRF token。现在，有两种方式向 AJAX POST 请求添加 CSRF token。
一种方式是在 script 标签里获取 CSRF token，然后在 POST 请求中使用：

```py
<script type="text/javascript">
    var csrfToken = "{{ csrf_token() }}";
</script> 
```

另外一种方式是在 meta 标签中渲染 token，然后在需要的地方使用它：

```py
<meta name="csrf-token" content="{{ csrf_token() }}"/> 
```

两者之间的区别是，第一种方法可能会在多个地方存在重复，这要取决于应用里 script 标签的数量。

现在，向 AJAX POST 里添加 CSRF token，得先添加 X-CSRFToken 属性。这属性值可以通过之前两种方法里任一一种都可以取得。我们将用第二种方法做为例子：

```py
var csrfToken = $('meta[name="csrf-token"]').attr('content');
$.ajaxSetup({
    beforeSend: function(xhr, settings) {
        if (!/^(GET|HEAD|OPTIONS|TRACE)$/i.test(settings.type)) {
            xhr.setRequestHeader("X-CSRFToken", csrftoken)
        }
    }
}) 
```

这将确保在所有 AJAX POST 请求发出去之前都添加了 CSRF token。

#### 原理

下面的截图显示了我们表单添加了 CSRF token 的样子：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/flask-fw-cb/img/c01ee1fc89f0cf51c46a1bfa556f8210.png)

token 是完全随机的，所有请求都是不同的。实现 CSRF-token 生成的方式有很多种，但这些已经超出了本书的范围，但还是鼓励读者去看一下是如何实现的，并且理解他们。



# 第六章：Flask 认证

认证是任何应用重要的部分，无论是 web，还是桌面，还是手机应用。每个应用都有处理它用户认证最好的方法。基于 web 的应用，尤其是 SaaS 应用，这一过程极其重要，因为这是应用安全与不安全的之间的界限。
这一章，将包含下面小节：

*   基于 session 的简单认证
*   使用 Flask-Login 扩展认证
*   使用 OpenID 认证
*   使用 Facebook 认证
*   使用 Google 认证
*   使用 Twitter 认证

## 介绍

Flask 为了保持简单和灵活，默认不提供认证机制。但是开发者可以根据每个应用的需求自己实现。
应用的用户认证可以通过多种方式完成。它可以通过使用简单的 session 完成，也可以通过更安全的 Flask-Login 扩展完成。同样也可以集成受欢迎的第三方服务比如 OpenID，或者 Facebook，Google 等等。这一章将看到这些方法的使用。

## 基于 session 的简单认证

在基于 session 的认证中，当用户第一次登陆后，用户信息被存储在服务器的 session 和浏览器的 cookie 中。之后，当用户打开应用时，存储在 cookie 中的用户信息将和服务器中的 seesion 做比较。如果 session 是存活的，用户将自动登陆。

###### 注意

应用配置应该总是指定 SECRET_KEY，否则存储在 cookie 中的数据和服务器的 session 都将是明文，这样很不安全。

我们将自己完成一个简单的认证机制。

###### 注意

这一小节完成的东西只是用来演示基本的认证的原理。这种方法不能用来任何生产环境中。

#### 准备

我们从第五章的 Flask 应用开始。它使用了 SQLAlchemy 和 WTForms 扩展（详情见前一章）。

#### 怎么做

在开始认证之前，我们需要一个模型来存储用户详细信息。首先在`flask_authentication/my_app/auth/models.py`里创建一个模型和表单：

```py
from werkzeug.security import generate_password_hash,check_password_hash
from flask_wtf import Form
from wtforms import TextField, PasswordField
from wtforms.validators import InputRequired, EqulTo
from my_app import db

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100))
    pwdhash = db.Column(db.String())

    def __init__(self, username, password):
        self.username = username
        self.pwdhash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.pwdhash, password) 
```

前面的代码是 User 模型，拥有两个字段：username 和 pwdhash。username 字段意思从名字可以看出。pwdhash 字段存储加了盐的密码，因为建议不要在数据库直接存储密码。

然后，创建两个表单：一个用于用户注册，一个用于登录。在 RegistrationForm 中，我们将创建两个 PasswordField，就像其他网站注册一样；目的是确保用户在两个字段里输入的密码一致：

```py
class RegistrationForm(Form):
    username = TextField('Username', [InputRequired()])
    password = PasswordField(
        'Password', [
            InputRequired(), EqualTo('confirm', message='Passwords must match')
        ]
    )
    confirm = PasswordField('Confirm Password', [InputRequired()])

class LoginForm(Form):
    username = TextField('Username', [InputRequired()])
    password = PasswordField('Password', [InputRequired()]) 
```

然后，在`flask_authentication/my_app/auth/views.py`创建视图处理用户的注册和登录请求：

```py
from flask import request, render_template, flash, redirect, url_for, session, Blueprint
from my_app import app, db
from my_app.auth.models import User, RegisterationForm, LoginForm

auth = Blueprint('auth', __name__)

@auth.route('/')
@auth.reoute('/home')
def home():
    return render_template('home.html')

@auth.route('/register', methods=['GET', 'POST'])
def register():
    if session.get('username'):
        flash('You are already logged in.', 'info')
        return rendirect(url_for('auth.home'))

    form = RegistrationForm(request.form)

    if request.method == 'POST' and form.validate():
        username = request.form.get('username')
        password = request.form.get('password')
        existing_username = User.query.filter_by(username=username).first()
        if existing_username:
            flash('This username has been already taken. Try another one.', 'warning')
            return render_template('register.html', form=form)
        user = User(username, password)
        db.session.add(user)
        db.session.commit()
        flash('You are now registered. Please login.', 'success')
        return redirect(url_for('auth.login'))

    if form.errors:
        flash(form.errors, 'danger')
    return render_template('register.html', form=form) 
```

前面的方法处理用户注册。在 GET 请求中，注册表单展示给了用户；表单需要填写用户名和密码。然后检查用户名是否已经被注册。如何用户名已经被注册，用户需要填写一个新的用户名。之后一个新的用户在数据库里被创建，然后重定向到登录页面。登录通过下面代码处理：

```py
@auth.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm(request.form)
    if request.method == 'POST' and form.validate():
        username = request.form.get('username')
        password = request.form.get('password')
        existing_user = User.query.filter_by(username=username).first()
        if not (existing_user and existing_user.check_password(password)):
            flash('Invalid username or password. Please try again.', 'danger')
            return render_template('login.html', form=form)
        session['username'] = username
        flash('You have successfully logged in.', 'success')
        return redirect(url_for('auth.home'))

    if form.errors:
        flash(form.errors, 'danger')
    return render_template('login.html', form=form) 
```

前面的方法处理了用户登录。在表单验证之后，我们首先检查用户名是否存在。如果不存在，用户需重新输入用户名。同样的，我们检查密码是否正确。如果不正确，用户需重新填写密码。如果所有的检查通过了，session 使用 username 作为键存储用户的用户名。如果 session 存在则表示用户已登录。现在看下面用户注销代码：

```py
@auth.route('/logout')
def logout():
    if 'username' in session:
        session.pop('username')
        flash('You have successfully logged out.', 'success')

    return redirect(url_for('auth.home')) 
```

在理解了 login()方法后，前面的代码是很容易理解的。这里，我们从 session 中删除了 username，用户就自动注销了。

之后，我们将创建 register()和 login()用到的模板。
`flask_authentication/my_app/templates/base.html`模板几乎和第五章一样。唯一的区别是使用 catalog 的地方被 auth 替换了。
首先，我们将有一个简单的主页`flask_authentication/my_app/templates/home.html`，其中会根据用户是否注册和登录显示出不同的链接：

```py
{% extends 'base.html' %}
{% block container %}
    <h1>Welcome to the Authentication Demo</h1>
    {% if session.username %}
        <h3>Hey {{ session.username }}!!</h3>
        <a href="{{ url_for('auth.logout') }}">Click here to logout</a>
    {% else %}
    Click here to <a href="{{ url_for('auth.login') }}">login</a> or
        <a href="{{ url_for('auth.register') }}">register</a>
    {% endif %}
{% endblock %} 
```

之后，创建一个注册页，`flask_authentication/my_app/templates/register.html`：

```py
{% extends 'home.html' %}
{% block container %}
    <div class="top-pad">
        <form method="POST" action="{{ url_for('auth.register') }}" role="form">
            {{ form.csrf_token }}
            <div class="form-group">{{ form.username.label }}: {{ form.username() }}</div>
            <div class="form-group">{{ form.password.label }}: {{ form.password() }}</div>
            <div class="form-group">{{ form.confirm.label }}: {{ form.confirm() }}</div>
            <button type="submit" class="btn btn-default"> Submit</button>
        </form>
    </div>
{% endblock %} 
```

最后，我们创建一个简单的登录页，`flask_authentication/my_app/templates/login.html`：

```py
{% extends 'home.html' %}
{% block container %}
    <div class="top-pad">
        <form method="POST" action="{{ url_for('auth.login') }}" role="form">
            {{ form.csrf_token }}
            <div class="form-group">{{ form.username.label }}: {{ form.username() }}</div>
            <div class="form-group">{{ form.password.label }}: {{ form.password() }}</div>
            <button type="submit" class="btn btn-default"> Submit</button>
        </form>
    </div>
{% endblock %} 
```

#### 原理

看下面的截图，可以知道应用是如何工作的。
第一个截图是当打开`http://127.0.0.1:5000/home`时的主页：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/flask-fw-cb/img/33bafd5940210e9159bb16a1f968ea54.png)

这是用户未登录时的主页样子。

打开`http://127.0.0.1:5000/register`是注册页：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/flask-fw-cb/img/8a6e6b305b16b1ee94caedd42702d38c.png)

注册之后，打开`ttp://127.0.0.1:5000/register`可以看到登录页：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/flask-fw-cb/img/616426cb3a14a0d3d35244b3de38e1d4.png)

最后，用户登录后的主页`http://127.0.0.1:5000/home`看起来是：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/flask-fw-cb/img/141363cbf3cf27bccfd867e82b0fd628.png)

## 使用 Flask-Login 扩展进行认证

前面一节，我们已经学习了如何完成基于 session 的认证。Flask-Login 是一个受欢迎的扩展，可以为我们以很好的方式处理很多东西，防止我们重新造轮子。它也不限制我们使用任何特定的数据库或者限制我们使用特定的字段/方法进行身份验证。它同样可以处理 Remember me 特性和账户找回等功能。

#### 准备

我们可以修改上一小节创建的应用，来用 Flask-Login 扩展完成同样的功能。
开始之前，需安装扩展：

```py
$ pip install Flask-Login 
```

#### 怎么做

为了使用 Flask-Login，首先需修改应用配置，`flask_authentication/my_app/__init__.py`：

```py
from flask_login import LoginManager

# Do other application config

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login' 
```

从扩展导入`LoginManager`之后，我们创建了这个类的一个对象。然后，使用`LoginManager`的`init_app()`方法配置 app 对象。之后，根据需要，`login_manager`还有很多配置可以设置。这里，我们演示一个基本的和必须的配置，即`login_view`，它表示登录请求的视图处理函数。我们甚至可以配置需要展示给用户的信息，我们 session 将会持续多久，应用处理登录使用的请求头等等。更多`Flask-Login`信息，参见`https://flask-login.readthedocs.org/en/latest/#customizing-the-login-process`。

Flask-Login 需要我们在 User 模型里增加一些额外的方法：

```py
def is_authenticated(self):
    return True

def is_active(self):
    return True

def is_anonymous(self):
    return False

def get_id(self):
    return self.id 
```

###### 译者注

使用 flask_login 替换 flask_ext_login
原书为 return unicode(self.id)，应为 return self.id

在前面的代码里，我们增加了四个方法，它们的解释在下面：

*   is_authenticated(): 这个方法通常返回 True。仅在我们不希望用户不被认证的时候返回 False。

*   is_active(): 这个方法通常返回 True。仅在我们封锁了或者禁止了一个用户的时候返回 False。

*   is_anonymous(): 这个方法用来表示一个用户不应该登录系统，应该作为一个匿名用户登录系统。对于正常登录的用户来说这个方法通常返回 False。

*   get_id(): 这个方法代表了认证用户的唯一 ID。这应该是一个 unicode 值。

接下来，我们得去修改`my_app/views.py`：

```py
from flask import g
from flask_login import current_user, login_user, logout_user, login_required
from my_app import login_manager

@login_manager.user_loader
def load_user(id):
    return User.query.get(int(id))

@auth.before_request
def get_current_user():
    g.user = current_user 
```

前面的方法中，@auth.before_request 装饰方法表示当收到每个请求时，在视图函数前调用该方法。这里我们记住了已经登录的用户：

```py
@auth.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        flash('You are already logged in.')
        return redirect(url_for('auth.home'))

        # 这边好像有问题
        # Same block of code as from last recipe Simple session based authentication
        # Next replace the statement session['username'] = username by the one below
        login_user(existing_user)
        flash('You have successfully logged in.', 'success')
        return redirect(url_for('auth.home'))

    if form.errors:
        flash(form.errors, 'danger')
    return render_template('login.html', form=form)

@auth.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('auth.home')) 
```

在`login()`方法中，在任何其他操作前，我们先检查`current_user`是否已认证。这里，`current_user`是一个代理，用来表示当前已登录的用户。在所有验证通过之后，使用`login_user()`方法进行用户登录。这个方法接收一个`user`对象并处理所有为登录用户而进行的会话活动。
现在，看`logout`方法，首先看到这个方法用`login_required()`装饰。这个装饰器确保这个方法执行前用户是登录的。它可以用在应用里的任何视图方法中。注销一个用户，我们需要去调用`logout_user()`，这将清除当前已登录用户的`session`，然后将用户从应用中注销。
我们不需要自己处理`session`。模板也存在一个小的改动。每当需要根据用户是登录状态时来显示一些内容，应该这样处理：

```py
{% if current_user.is_authenticated %}
    ...do something...
{% endif %} 
```

###### 译者注

原书为 current_user.is_authenticated()，这是错误的，应该去掉括号。
原书为 redirect(url_for(‘home’))，这是错误的，应为 redirect(url_for(‘auth.home’))。

#### 原理

这一小节的演示效果和上一小节是一样的。仅仅是完成方式的不同。

#### 更多

Flask-Login 使得实现 Remember me 特性相当简单。仅仅需要性 login_user()方法传递 remember=True。这将在用户电脑上保存一个 cookie，当 session 是存活的时候，Flask-Login 会自动登录。读者可以自行实现。

#### 其他

*   Flask 提供了一个特殊的对象：g。可以阅读`http://flask.pocoo.org/docs/0.10/api/#flask.g`了解更多。

下面暂不进行翻译

## 使用 OpenID 认证

## 使用 Facebook 认证

## 使用 Google 认证

## 使用 Twitter 认证



# 第七章：构建 RESTful API

API，即应用编程接口，可以概括为应用对开发者的接口。就像用户有一个可以和应用沟通的可视化界面一样，开发者同样需要一个接口和应用交互。REST，即表现层状态转移，它不是一个协议或者标准。它只是一种软件架构风格，或者是为编写应用程序定义的一组约束，旨在简化应用程序内外接口。当 web 服务 API 遵循了 REST 风格进行编写时，它们就可以称为 RESTful API。RESTful 使得 API 和应用内部细节分离。这使得扩展很容易，并且使得事情变得简单。统一接口确保每个请求都得文档化。

###### 提示

关于 REST 和 SOAP 哪个好存在一个争论。它实际上是一个主观问题，因为它取决于需要做什么。每个都有它自己的好处，应该根据应用程序的需要来进行选择。

这一章，我们将包含下面小节：

*   创建一个基于类的 REST 接口
*   创建一个基于扩展的 REST 接口
*   创建一个 SQLAlchemy-independent REST API
*   一个完整的 REST API 例子

## 介绍

从名字可以看出，表现层状态转移（REST）意味着可以分离 API 到逻辑资源，这些资源可以通过使用 HTTP 请求获得和操作，一个 HTTP 请求由 GET，POST，PUT，PATCH，DELETE 中的一个（还有其他 HTTP 方法，但这些是最常使用的）。这些方法中的每一个都有一个特定的意义。REST 的关键隐含原则之一是资源的逻辑分组应该是简单容易理解的，提供简单性和可移植性。
这本书到这里，我们一直在使用一个资源叫做 Product。让我们来看看怎么讲 API 调用映射到资源分离上：

*   GET /products/1:获取 ID 为 1 的商品
*   GET /products:获取商品列表
*   POST /products:创建一个新商品
*   PUT /products/1:更新 ID 为 1 的商品
*   PATCH /products/1:部分更新 ID 为 1 的商品
*   DELETE /products/1:删除 ID 为 1 的商品

## 创建一个基于类的 REST 接口

在第四章里我们看到了在 Flask 里如何使用基于类的视图。我们将使用相同的概念去创建视图，为我们应用提供 REST 接口。

#### 准备

让我们写一个简单的视图来处理 Product 模型的 REST 接口。

#### 怎么做

需要简单的修改商品视图，来继承 MethodView 类：

```py
from flask.views import MethodView

class ProductView(MethodView):

    def get(self, id=None, page=1):
        if not id:
            products = Product.query.paginate(page, 10).items
            res = {}
            for product in products:
                res[product.id] = {
                    'name': product.name,
                    'price': product.price,
                    'category': product.category.name
                }
            # 译者注 加上这一句，否则会报错
            res = json.dumps(res)
        else:
            product = Product.query.filter_by(id=id).first()
            if not product:
                abort(404)
            res = json.dumps({
                'name': product.name,
                'price': product.price,
                'category': product.category.name
            })
        return res 
```

get()方法搜索 product，然后返回 JSON 结果。
可以用同样的方式完成 post(),put(),delete()方法：

```py
def post(self):
    # Create a new product.
    # Return the ID/object of newly created product.
    return

def put(self, id):
    # Update the product corresponding provided id.
    # Return the JSON corresponding updated product.
    return

def delete(self, id):
    # Delete the product corresponding provided id.
    # Return success or error message.
    return 
```

很多人会想为什么我们没在这里写路由。为了包含路由，我们得像下面这样做：

```py
product_view = ProductView.as_view('product_view')
app.add_url_rule('/products/', view_func=product_view, methods=['GET', 'POST'])
app.add_url_rule('/products/<int:id>', view_func=product_view, methods=['GET', 'PUT', 'DELETE']) 
```

第一句首先转换类为实际的视图函数，这样才可以用在路由系统中。后面两句是 URL 规则和其对应的请求方法。

###### 译者注

测试时如果遇到/products/路由已经注册，原因可能是第四章已经定义了一个/products/视图函数，注释掉即可，或者修改这里的路由名称。

#### 原理

MethodView 类定义了请求中的 HTTP 方法，并将名字转为小写。请求到来时，HTTP 方法匹配上类中定义的方法，就会调用相应的方法。所以，如果对 ProductView 进行一个 GET 调用，它将自动的匹配上 get()方法。

#### 更多

我们还可以使用一个叫做 Flask-Classy 的扩展（`https://pythonhosted.or/Flask-Classy`）。这将在很大程度上自动处理类和路由，并使生活更加美好。我们不会在这里讨论这些，但它是一个值得研究的扩展。

## 创建基于扩展的 REST 接口

前面一节中，我们看到如何使用热插拔的视图创建一个 REST 接口。这里我们将使用一个 Flask 扩展叫做 Flask-Restless。Flask-Restless 是完全为了构建 REST 接口而开发的。它提供了一个简单的为使用 SQLAlchemy 创建的数据模型构建 RESTful APIs 的方法。这些生成的 api 以 JSON 格式发送和接收消息。

#### 准备

首先，需安装 Flask-Restless 扩展：

```py
$ pip install Flask-Restless 
```

我们借用第四章的程序构建我们的应用，以此来包含 RESTful API 接口。

###### 提示

如果 views 和 handlers 的概念不是很清楚，建议在继续阅读之前，先去阅读第四章。

#### 怎么做

通过使用 Flask-Restless 是非常容易向一个 SQLAlchemy 模型新增 RESTful API 接口的。首先，需向应用新增扩展提供的 REST API 管理器，然后通过使用 app 对象创建一个实例：

```py
from flask_restless import APIManager
manager = APIManager(app, flask_sqlalchemy_db=db) 
```

之后，我们需要通过使用 manager 实例使能模型里的 API 创建。为此，需向 views.py 新增下面代码：

```py
from my_app import manager

manager.create_api(Product, methods=['GET', 'POST', 'DELETE'])
manager.create_api(Category, methods=['GET', 'POST', 'DELETE']) 
```

这将在 Product 和 Category 模型里创建 GET，POST，DELETE 这些 RESTful API。通常，如果 methods 参数缺失的话，只支持 GET 方法。

#### 原理

为了测试和理解这些是如何工作的，我们通过使用 Python requests 库发送一些请求:

```py
>>> import requests
>>> import json
>>> res = requests.get("http://127.0.0.1:5000/api/category")
>>> res.json()
{u'total_pages': 0, u'objects': [], u'num_results': 0, u'page': 1} 
```

###### 译者注

res.json()可能会从出错，可使用 res.text

我们发送了一个 GET 请求去获取类别列表，但是现在没有记录。来看一下商品：

```py
>>> res = requests.get('http://127.0.0.1:5000/api/product')
>>> res.json()
{u'total_pages': 0, u'objects': [], u'num_results': 0, u'page': 1} 
```

我们发送了一个 GET 请求去获取商品列表，但是没有记录。现在让我们创建一个商品：

```py
>>> d = {'name': u'iPhone', 'price': 549.00, 'category':{'name':'Phones'}}
>>> res = requests.post('http://127.0.0.1:5000/api/product', data=json.dumps(d), headers={'Content-Type': 'application/json'})
>>> res.json()
{u'category': {u'id': 1, u'name': u'Phones'}, u'name': u'iPhone', 
u'company': u'', u'price': 549.0, u'category_id': 1, u'id': 2, u'image_path': u''} 
```

我们发送了一个 POST 请求去创建一个商品。注意看请求里的 headers 参数。每个发给 Flask-Restless 的 POST 请求都应该包含这个头。现在，我们再一次搜索商品列表：

```py
>>> res = requests.get('http://127.0.0.1:5000/api/product')
>>> res.json()
{u'total_pages': 1, u'objects': [{u'category': {u'id': 1, u'name': u'Phones'}, u'name': u'iPhone', u'company': u'', u'price': 549.0, u'category_id': 1, u'id': 1, u'image_path': u''}], u'num_results': 1, u'page': 1} 
```

我们可以看到新创建的商品已经在数据库中了。
同样需要注意的是，查询结果默认已经分好页了，这是优秀的 API 的标识之一。

#### 更多

自动创建 RESTful API 接口非常的酷，但是每个应用都需要一些自定义，验证，处理业务的逻辑。
这使得使用 preprocessors 和 postprocessors 成为可能。从名字可以看出，preprocessors 会在请求被处理前运行，postprocessors 会在请求处理完，发送给应用前运行。它们被定义在 create_api()中，做为请求类型（GET，POST 等）映射，并且作为前处理程序或后处理程序的方法列表，用于处理指定的请求：

```py
manager.create_api(
    Product,
    methods=['GET', 'POST', 'DELETE'],
    preprocessors={
        'GET_SINGLE': ['a_preprocessor_for_single_get'],
        'GET_MANY': ['another_preprocessor_for_many_get'],
        'POST': ['a_preprocessor_for_post']
    },
    postprocessors={
        'DELETE': ['a_postprocessor_for_delete']
    }
) 
```

单个或多个记录都可以调用 GET，PUT，PATCH 方法；但是它们各有两个变体（variants）。举个例子，前面的代码里，对于 GET 请求有 GET_SINGLE 和 GET_MANY。preprocessors 和 postprocessors 对于各自请求接收不同的参数，然后执行它们，并且没有返回值。参见`https://flask-restless.readthedocs.org/en/latest/`了解更多细节。

###### 译者注

对 preprocessor 和 postprocessors 的理解，参见`http://flask-restless.readthedocs.io/en/stable/customizing.html#request-preprocessors-and-postprocessors`

## 创建一个 SQLAlchemy-independent REST API

在前一小节中，我们看到了如何使用依赖于 SQLAlchemy 的扩展创建一个 REST API 接口。现在我们将使用一个名为 Flask-Restful 的扩展，它是在 Flask 可插拔视图上编写的，并且独立于 ORM。

#### 准备

首先，安装扩展:

```py
$ pip install Flask-Restful 
```

我们将修改前面的商品目录应用，通过使用这个扩展增加一个 REST 接口。

#### 怎么做

通常，首先要修改应用的配置，看起来像这样：

```py
from flask_restful import Api   

api = Api(app) 
```

这里，app 是我们应用的对象/实例。
接下来，在 views.py 里创建 API。在这里，我们将尝试理解 API 的框架，更详细的实现在下一小节里：

```py
from flask_restful import Resource
from my_app import api

class ProductApi(Resource):

    def get(self, id=None):
        # Return product data
        return 'This is a GET response'

    def post(self):
        # Create a new product
        return 'This is a POST response'

    def put(self, id):
        # Update the product with given id
        return 'This is a PUT response'

    def delete(self, id):
        # Delete the product with given id
        return 'This is a DELETE response' 
```

前面的 API 结构是很容易理解的。看下面代码：

```py
api.add_resource(ProductApi, '/api/product', '/api/product/<int:id>') 
```

这里，我们为 ProductApi 创建路由，我们可以根据需要指定多条路由。

#### 原理

我们将使用 Python requests 库在看这些是如何工作的，就像前一小节那样：

```py
>>> import requests
>>> res = requests.get('http://127.0.0.1:5000/api/product')
>>> res.json()
u'This is a GET response'
>>> res = requests.post('http://127.0.0.1:5000/api/product')
>u'This is a POST response'
>>> res = requests.put('http://127.0.0.1:5000/api/product/1')
u'This is a PUT response'
>>> res = requests.delete('http://127.0.0.1:5000/api/product/1')
u'This is a DELETE response' 
```

在前面一小段代码中，我们看到了我们的请求被相应的方法处理了；从回复中可以确认这一点。

#### 其他

*   确保在继续向下阅读之前先阅读完这一小节

## 一个完整的 REST API 例子

这一小节，我们将上一小节的 API 框架改写为一个完整的 RESTful API 接口。

#### 准备

我们将使用上一小节的 API 框架作为基础，来创建一个完整的 SQLAlchemy-independent RESTful API。尽管我们使用 SQLAlchemy 作为 ORM 来进行演示，这一小节可以使用任何 ORM 或者底层数据库进行编写。

#### 怎么做

下面的代码是 Product 模型完整的 RESTful API 接口。views.py 看起来像这样：

```py
from flask_restful import reqparse

parser = reqparse.RequestParser()
parser.add_argument('name', type=str)
parser.add_argument('price', type=float)
parser.add_argument('category', type=dict) 
```

前面的一小段代码，我们为希望在 POST，PUT 请求中解析出来的参数创建了 parser。请求期待每个参数不是空值。如果任何参数的值是缺失的，则将使用 None 做为值。看下面代码：

```py
class ProductApi(Resource):

    def get(self, id=None, page=1):
        if not id:
            products = Product.query.paginate(page, 10).items
        else:
            products = [Product.query.get(id)]
        if not products:
            abort(404)
        res = {}
        for product in products:
            res[product.id] = {
                'name': product.name,
                'price': product.price,
                'category': product.category.name
            }
        return json.dumps(res) 
```

前面的 get 方法对应于 GET 请求，如果没有传递 id，将返回商品分好页的商品列表；否则，返回匹配的商品。看下面 POST 请求代码：

```py
def post(self):
    args = parser.parse_args()
    name = args['name']
    price = args['price']
    categ_name = args['category']['name']
    category = Category.query.filter_by(name=categ_name).first()
    if not category:
        category = Category(categ_name)
    product = Product(name, price, category)
    db.session.add(product)
    db.session.commit()
    res = {}
    res[product.id] = {
        'name': product.name,
        'price': product.price,
        'category': product.category.name,
    }
    return json.dumps(res) 
```

前面 post()方法将在 POST 请求时创建一个新的商品。看下面代码：

```py
def put(self, id):
    args = parser.parse_args()
    name = args['name']
    price = args['price']
    categ_name = args['category']['name']
    category = Category.query.filter_by(name=categ_name).first()
    Product.query.filter_by(id=id).update({
        'name': name,
        'price': price,
        'category_id': category.id,
    })
    db.session.commit()
    product = Product.query.get_or_404(id)
    res = {}
    res[product.id] = {
        'name': product.name,
        'price': product.price,
        'category': product.category.name,
    }
    return json.dumps(res) 
```

前面代码，通过 PUT 请求更新了一个已经存在的商品。这里，我们应该提供所有的参数，即使我们仅仅想更新一部分。这是因为 PUT 被定义的工作方式就是这样。如果我们想要一个请求只传递那些我们想要更新的参数，这应该使用 PATCH 请求。看下面代码：

```py
def delete(self, id):
    product = Product.query.filter_by(id=id)
    product.delete()
    db.session.commit()
    return json.dumps({'response': 'Success'}) 
```

最后同样重要的是，DELETE 请求将删除匹配上 id 的商品。看下面代码：

```py
api.add_resource(
    ProductApi,
    '/api/product',
    '/api/product/<int:id>',
    '/api/product/<int:id>/<int:page>'
) 
```

上一句代码是我们的 API 可以容纳的所有 URL 的定义。

###### 提示

REST API 的一个重要方面是基于令牌的身份验证，它只允许有限和经过身份验证的用户能够使用和调用 API。这将留给你自己探索。我们在第六章 Flask 认证中介绍的用户身份验证的基础知识，将作为此概念的基础。



# 第八章：为 Flask 应用提供管理员接口

每个应用需要一些接口给用户提供一些特权，以此来维护和升级应用资源。举个例子，我们可以在电商应用里有这样一个接口：这个接口允许一些特殊用户来创建商品类别和商品等。一些用户可能有权限来处理在网站购物的用户，处理他们的账单信息等等。相似的，还有很多案例需要从应用里隔离出一个接口，和普通用户分开。

这一章将包含下面小节：

*   创建一个简单的 CRUD 接口
*   使用 Flask-Admin 扩展
*   使用 Flask-Admin 注册模型
*   创建自定义表单和行为
*   WYSIWYG 文本集成
*   创建用户角色

## 介绍

和其他 Python web 框架比如 Django 不同的是，Flask 默认情况下不提供管理员接口。尽管如此，这被很多人视为缺点，但这其实是给了开发者去根据需要创建管理员接口的灵活性。
我们可以选择从头开始为我们的应用程序编写管理界面，也可以使用 Flask 扩展。扩展为我们做了大部分的事情，但也允许我们去根据需要自定义逻辑处理。Flask 中一个受欢迎的创建管理员接口的扩展是 Flask-Admin（`https://pypi.python.org/pypi/Flask-Admin`）。这一章我们将从自己创建管理员接口开始，然后使用 Flask-Admin 扩展。

## 创建一个简单的 CRUD 接口

CRUD 指的是 Create，Read，Update，Delete。一个管理员接口必要的能力是可以根据需要创建，修改或者删除应用里的记录/资源。我们将创建一个简单的管理员接口，这将允许管理员用户进行这些操作，而其他普通用户则不能。

#### 准备

我们将从第六章的应用开始，给它添加管理员认证和管理员接口。接口只允许管理员创建，修改，删除用户记录。这一小节，会提到一些特定的内容以帮助理解一些概念。

#### 怎么做

首先修改 models.py，向 User 模型新增一个字段：admin。这个字段将帮助我们区别这个用户是否是管理员。

```py
from wtforms import BooleanField

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(60))
    pwdhash = db.Column(db.String())
    admin = db.Column(db.Boolean())

    def __init__(self, username, password, admin=False):
        self.username = username
        self.pwdhash = generate_password_hash(password)
        self.admin = admin

    def is_admin(self):
        return self.admin 
```

前面 is_admin()方法仅仅返回了 admin 字段的值。这个可以根据需要自定义的实现。看下面代码：

```py
class AdminUserCreateForm(Form):
    username = TextField('Username', [InputRequired()])
    password = PasswordField('Password', [InputRequired()])
    admin = BooleanField('Is Admin ?')

class AdminUserUpdateForm(Form):
    username = TextField('Username', [InputRequired()])
    admin = BooleanField('Is Admin ?') 
```

同时，我们创建了两个用在管理员视图里的表单。
现在修改 views.py 里的视图，来完成管理员接口：

```py
from functools import wraps
from my_app.auth.models import AdminUserCreateForm, AdminUserUpdateForm

def admin_login_required(func):
    @wraps(func)
    def decorated_view(*args, **kwargs):
        if not current_user.is_admin:
            return abort(403)
        return func(*args, **kwargs)
    return decorated_view 
```

前面代码是`admin_login_required`装饰器，效果和`login_required`装饰器类似。区别在于它需要使用`login_required`，并且检查当前登录用户是否是管理员。

接下来用来创建管理员接口的处理程序。注意`@admin_login_required`装饰器的使用方法。其他内容和我们之前学到的事一样的，现在只关注视图和认证处理：

```py
@auth.route('/admin')
@login_required
@admin_login_required
def home_admin():
    return render_template('admin-home.html')

@auth.route('/admin/users-list')
@login_required
@admin_login_required
def users_list_admin():
    users = User.query.all()
    return render_template('users-list-admin.html', users=users)

@auth.route('/admin/create-user', methods=['GET', 'POST'])
@login_required
@admin_login_required
def user_create_admin():
    form = AdminUserCreateForm(request.form)
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        admin = form.admin.data
        existing_username = User.query.filter_by(username=username).first()
        if existing_username:
            flash('This username has been already taken. Try another one.', 'warning')
            return render_template('register.html', form=form)
        user = User(username, password, admin)
        db.session.add(user)
        db.session.commit()
        flash('New User Created.', 'info')
        return redirect(url_for('auth.users_list_admin'))
    if form.errors:
        flash(form.errors, 'danger')
    return render_template('user-create-admin.html', form=form) 
```

前面的方法允许管理员用户在系统里创建新用户。这个行为和 register()方法是类似的，但是允许设置用户的 admin 标志。看下面代码:

```py
@auth.route('/admin/update-user/<id>', methods=['GET', 'POST'])
@login_required
@admin_login_required
def user_update_admin(id):
    user = User.query.get(id)
    form = AdminUserUpdateForm(
        rquest.form,
        username=user.username, 
        admin=user.admin
    )

    if form.validate_on_submit():
        username = form.username.data
        admin = form.admin.data

        User.query.filter_by(id=id).update({
            'username': usernmae,
            'admin': admin,
        })
        db.session.commit()
        flash('User Updated', 'info')
        return redirect(url_for('auth.users_list_admin'))

    if form.errors:
        flash(form.errors, 'danger')

    return render_template('user-update-admin.html', form=form, user=user) 
```

前面的方法允许管理员更新其他用户的记录。但是，最好别允许管理员修改任何用户的密码。大多数情况下，只能允许用户自己修改密码。尽管如此，一些情况下，管理员还是有修改密码的权限，但是不应该看到用户设置的密码。看下面代码：

```py
@auth.route('/admin/delete-user/<id>')
@login_required
@admin_login_required
def user_delete_admin(id):
    user = User.query.get(id)
    db.session.delete(user)
    db.session.commit()
    flash('User Deleted.'， 'info')
    return redirect(url_for('auth.users_list_admin')) 
```

`user_delete_admin()`方法实际上应该在 POST 请求里完成。这留给读者自己完成。
下面需要创建模板。从前面视图代码里可以看出，我们需要新增四个模板，分别是`admin-home.html，user-create-admin.html，user-update-admin.html，users-list-admin.html`。下一小节看一下他们如何工作的。读者现在应该可以自己实现这些模板了，作为参考，具体代码可下载本书示例代码。

###### 译者注

原文为 user.delete()，现修改为 db.session.delete(user)。
原味为 if form.validate()，现修改为 if form.validate_on_submit():

#### 原理

我们为应用新增一个菜单条目，这在管理员主页上添加了一个链接，页面看起来像这样：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/flask-fw-cb/img/b29fdbd0dc8b3dfb52c54c65006acb19.png)

一个用户必须作为管理员登录才能访问这些页面和其他管理员页面。如果一个用户不是作为管理员登录的，应该展示一个错误，看起来像下面这样：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/flask-fw-cb/img/bd1e51e62636f3aacfa97db15b05bc3c.png)

管理员登录后主页看起来像这样：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/flask-fw-cb/img/035e7e07a68d2fb7d55c41bcab31c070.png)

管理员可以看到系统里的用户列表也可以创建一个新用户。用户列表页本身也提供了编辑和删除用户的选项。

###### 提示

创建第一个管理员，需要通过使用控制台命令创建一个用户，设置 admin 标记为 True。

## 使用 Flask-Admin 扩展

Flask-Admin 是一个扩展，用来帮助更简单更快速的为应用创建管理员接口。这一小节将专注于使用这个扩展。

#### 准备

首先，需要安装 Flask-Admin 扩展：

```py
$ pip install Flask-Admin 
```

我们扩展上一小节的应用来使用 Flask-Admin 完成它。

#### 怎么做

使用 Flask-Admin 扩展为任何 Flask 应用新增一个简单的管理员接口只需要几句。
我们仅仅需要向应用配置里增加下面几句：

```py
from flask_admin import Admin
app = Flask(__name__)
# Add any other application configuration
admin = Admin(app) 
```

仅仅用 Flask-Admin 扩展提供的 Admin 类初始化应用，只会提供一个基本的管理员界面，看起来像这样：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/flask-fw-cb/img/481a37c469767821c0ed0752fc69bdc6.png)

注意截图里的 URL 是`http://127.0.0.1:5000/admin/`。我们同样可以添加自己的视图，仅仅需要继承 BaseView 类就可以添加一个类作为视图了：

```py
from flask_admin import BaseView, expose

class HelloView(BaseView):
    @expose('/')
    def index(self):
        return self.render('some-template.html') 
```

之后，我们需要在 Flask 配置里添加这个视图到 admin 对象上：

```py
import my_app.auth.views as views
admin.add_view(views.HelloView(name='Hello')) 
```

现在管理员主页看起来像这样：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/flask-fw-cb/img/b4b0c664942199026a1992d3b7182906.png)

需要注意的一件事是，默认情况下这个页面没有进行任何的认证，这需要自行实现。因为 Flask-Admin 没有对认证系统做任何的假设。我们的应用使用的是 Flask-Login 进行登录，所以我们可以新增一个方法叫 is_accessible()到 HelloView 类中：

```py
def is_accessible(self):
    return current_user.is_authenticated and current_user.is_admin 
```

###### 译者注

原书为`current_user.is_authenticated() and current_user.is_admin()`，这会报错，不是函数，不能调用，所以需去掉()。

#### 更多

在完成前面的代码之后，还有一个管理员视图不需要认证，任何人就可以访问。这就是管理员主页。为了仅仅向管理员开放这个页面，我们需要继承 AdminIndexView 并完成 is_accessible()方法：

```py
from flask_admin import AdminIndexView

class MyAdminIndexView(AdminIndexView):
    def is_accessible(self):
        return current_user.is_authenticated and current_user.is_admin 
```

之后，需要在应用配置里把这个视图做为 index_view 传递到 admin 对象，实现如下：

```py
admin = Admin(app, index_view=views.MyadminIndexView()) 
```

这个方法使得所有的管理员视图仅向管理员开放。我们还可以在需要时在 is_accessible()中实现任何权限或条件访问规则。

## 使用 Flask-Admin 注册模型

上一小节，我们看到了如何使用 Flask-Admin 扩展在应用里创建管理员接口。这一小节，我们将会看到如何为已存在的模型创建管理员接口/视图，使得可以进行 CRUD 操作。

#### 准备

我们将扩展上一小节应用来为 User 模型创建管理员接口。

#### 怎么做

使用 Flask-Admin 注册一个模型到管理员接口里是非常简单的。需要像下面这样添加几行代码：

```py
from flask_admin.contrib.sqla import ModelView

# Other admin configuration as shown in last recipe
admin.add_view(ModelView(views.User, db.session)) 
```

这里，第一行，我们从 flask_admin.contrib.sqla 导入了 ModelView。flask_admin.contrib.sqla 是由 Flask-Admin 提供的一个继承 SQLAlehcmy 模型的视图。这将为 User 模型创建一个新的管理员视图。视图看起来像这样：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/flask-fw-cb/img/11348dc64cd475c6e5fb3070d476e8da.png)

看前面的截图，很多人都会认为向用户显示密码的哈希值是没有意义的。同时，Flask-Admin 默认的模型创建机制在创建 User 时会失败，因为我们 User 模型里有一个`__init__()`方法。这个方法期望三个字段，然而 Flask-Admin 里面的模型创建逻辑是非常通用的，在模型创建的时候不会提供任何值。
现在，我们将自定义 Flask-Admin 的一些默认行为，来修改 User 创建机制，以及隐藏视图里的密码哈希值：

```py
class UserAdminView(ModelView):
    column_searchable_list = ('username',)
    column_sortable_list = ('username', 'admin')
    column_exclude_list = ('pwdhash',)
    form_excluded_columns = ('pwdhash',)
    form_edit_rules = ('username', 'admin')

    def is_accessible(self):
        return current_user.is_authenticated and current_user.is_admin 
```

前面的代码展示了 User 的管理员视图遵循的一些规则和配置。其中有一些是很容易理解的。可能会对`column_exclude_list`和`form_excluded_columns`有点困惑。前者将排除管理员视图自身提供的列，不能在搜索，创建和其他 CRUD 操作里使用这些列。后者将防止在 CRUD 表单上显示这些字段。看下面代码：

```py
def scaffold_form(self):
    form_class = super(UserAdminView, self).scaffold_form()
    form_class.password = PasswordField('Password')
    return form_class 
```

前面方法将重写模型的表单创建，添加了一个密码字段，这将替换密码哈希值。看下面代码：

```py
def create_model(self, form):
    model = self.model(
            form.username.data, form.password.data, form.admin.data
        )
    form.populate_obj(model)
    self.session.add(model)
    self._on_model_change(form, model, True)
    self.session.commit() 
```

前面方法重写了模型创建逻辑，以适应我们的应用。
为了在应用配置里向 admin 对象添加一个模型，得像下面这样编码：

```py
admin.add_view(views.UserAdminView(views.User, db.session)) 
```

#### 提示

看`self._on_model_change(form, model, True)`一句。最后一个参数 True 表示调用是为了创建一个新的记录。

User 模型的管理员界面将看起来像下面这样：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/flask-fw-cb/img/33eafa6bc5f5b06c7e7283945b051528.png)

这里有一个搜索框，没有显示密码哈希值。用户创建和编辑视图也有更改，建议读者亲自运行这个程序看看效果。

## 创建自定义表单和动作

这一小节，我们将使用 Flask-Admin 提供的表单来创建自定义的表单。同时将使用自定义表单创建一个自定义动作。

#### 准备

上一小节，我们看到 User 更新表单没有更新密码的选项。表单看起来像这样：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/flask-fw-cb/img/cc3f79d3a15ee8f8828f286a4ce79f87.png)

这一小节，我们将自定义这个表单允许管理员为任何用户更改密码。

#### 怎么做

完成这个特性仅仅需要修改 views.py。首先，我们从 Flask-Admin 表单里导入 rules 开始：

```py
from flask_admin.form import rules 
```

上一小节，`form_edit_rules`设置了两个字段：username 和 admin。这表示 User 模型更新视图中可供管理用户编辑的字段。

更新密码不是一个简单的事情，不是向列表 form_edit_rules 仅仅添加一个或者多个字段就可以完成的。因为我们不能存储密码的明文。我们得存储密码的哈希值，这不能被任何用户直接修改。我们需要用户输入密码，然后在存储的时候转为一个哈希值进行存储。我们将看到如何在下面的代码里实现这个：

```py
form_edit_rules = (
    'username', 'admin',
    rules.Header('Reset Password'),
    'new_password', 'confirm'
)
form_create_rules = (
    'username', 'admin', 'notes', 'password'
) 
```

前面代码表示现在表单有了一个 header，它将密码重置部分和其他部分分离开了。之后，我们将新增两个字段 new_password 和 confirm，这将帮助我们安全的修改密码：

```py
def scaffold_form(self):
    form_class = super(UserAdminView, self).scaffold_form()
    form_class.password = PasswordField('Password')
    form_class.new_password = PasswordField('New Password')
    form_class.confirm = PasswordField('Confirm New Password')
    return form_class 
```

`scaffold_form()`方法需要修改，以便使得这两个新的字段在表单渲染的时候变得有效。
最后，我们将实现 update_model()方法，这在更新记录的时候会被调用：

```py
def update_model(self, form, model):
    form.populate_obj(model)
    if form.new_password.data:
        if form.new_password.data != form.confirm.data:
            flash('Passwords must match')
            return
        model.pwdhash = generate_password_hash(form.new_password.data)
    self.session.add(model)
    self._on_model_change(form, model, False)
    self.session.commit() 
```

前面代码中，我们首先确保两个字段中输入的密码是一样的。如果是，我们将继续重置密码以及任何其他更改。

###### 提示

看`self._on_model_change(form, model, False)`。这里最后一个参数 False 表示这个调用不能用于创建一个新记录。这同样用在了上一小节创建用户那里。那个例子中，最后一个参数设置为了 True。

#### 原理

用户更新表单看起来像下面这样：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/flask-fw-cb/img/afd8ade3eb7e30d812575dd1d2881d87.png)

如果我们在两个密码字段里输入的密码是相同的，才会更新用户密码。

## WYSIWYG 文本集成

做为一个网站的用户，我们都知道使用传统的 textarea 字段编写出漂亮的格式化的文本是一个噩梦。有许多插件使得生活变得美好，可以转换简单的文本字段到 What you see is what you get（WYSIWYG）编辑器。CKEditor 就是这样一个编辑器。这是一个开源项目，提供了非常好的扩展，并且有大型社区的支持。同时允许用户根据需要构建附加物（add-ons）。

#### 准备

我们从向 User 模型新增一个新的 notes 字段开始，然后使用 CKEditor 集成这个字段来编写格式化的文本。这会添加额外的 Javascript 库和 CSS 类到普通 textarea 字段中，以将其转换为与 CKEditor 兼容的 textarea 字段。

#### 怎么做

首先，我们将向 User 模型添加 notes 字段，看起来像这样：

```py
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(60))
    pwdhash = db.Column(db.String())
    admin = db.Column(db.Boolean())
    notes = db.Column(db.UnicodeText)

    def __init__(self, username, password, admin=False, notes=''):
        self.username = username
        self.pwdhash = generate_password_hash(password)
        self.admin = admin
        self.notes = notes 
```

之后，我们将创建一个自定义的 wtform 控件和一个字段:

```py
from wtforms import widgets, TextAreaField

class CKTextAreaWidget(widgets.TextArea):
    def __call__(self, field, **kwargs):
        kwargs.setdefault('class_', 'ckeditor')
        return super(CKTextAreaWidget, self).__call__(field, **kwargs) 
```

在前面自定义控件中，我们向 TextArea 控件添加了一个 ckeditor 类。如果需要了解更多的 WTForm 控件，参见第五章创建一个自定义控件这一节。看下面代码：

```py
class CKTextAreaField(TextAreaField):
    widget = CKTextAreaWidget() 
```

前面代码里，我们设置控件为 CKTextAreaWidget，当这个文本字段进行渲染的时候，CSS 类 ckeditor 会被添加进去。

接下来，我们需要修改 UserAdminView 类中表单规则，我们可以指定创建和编辑表单时使用的模板。我们同样需要用 CKTextAreaField 重写 TextAreaField：

```py
form_overrides = dict(notes=CKTextAreaField)
create_template = 'edit.html'
edit_template = 'edit.html' 
```

前面的代码中，form_overrides 允许用 CKTextAreaFiled 字段替代普通的 textarea 字段。

剩下部分是之前提到的`templates/edit.html`模板：

```py
{% extends 'admin/model/edit.html' %}

{% block tail %}
    {{ super() }}
    <script src="http://cdnjs.cloudflare.com/ajax/libs/ckeditor/4.0.1/ckeditor.js"></script>
{% endblock %} 
```

这里，我们扩展 Flask-Admin 提供的默认 edit.html，向里面添加了 CKEditors JS 文件，这样 ckeditors 类的 CKTextAreaField 才可以使用。

#### 原理

在做了这些修改之后，用户创建表单将看起来像这样，需注意 Notes 字段：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/flask-fw-cb/img/d9677d05db761bc3a0849d2cd1d12af3.png)

这里，任何在 Note 字段里输入的东西将会在保存的时候被自动转成 HTML，这使得可以用在任何地方以进行显示。

## 创建用户权限

现在为止，我们看到了使用 is_accessible()方法可以轻松地创建对特定管理用户可访问的视图。可以将其扩展到不同类型的场景，特定用户只能查看特定视图。在模型中，还有另一种在更细粒度级别上实现用户角色的方法，其中角色决定用户是否能够执行所有或部分 CRUD 操作。

#### 准备

这一小节，我们将看到一种创建用户角色的基本方法，其中管理员用户只能执行他们有权执行的操作。

###### 提示

记住这只是完成用户角色的一种方法。还有很多更好的方法，但是现在讲解的方式是演示创建用户角色的最好例子。
一个合适的方法是去创建用户组，给用户组分配角色而不是个人用户。另一种方法可以是基于复杂策略的用户角色，包括根据复杂的业务逻辑定义角色。这种方法通常被企业系统所采用比如 ERP，CRM 等等。

#### 怎么做

首先，我们向 User 模型添加一个字段：roles：

```py
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Colum(db.String(60))
    pwdhash = db.Column(db.String())
    admin = db.Column(db.Boolean())
    notes = db.Column(db.UnicodeText)
    roles = db.Column(db.String(4))

    def __init__(self, username, password, admin=False, notes='', roles='R'):
        self.username = username
        self.pwdhash = generate_password_hash(password)
        self.admin = admin
        self.notes = notes
        self.roles = self.admin and self.roles or '' 
```

这里，我们添加了一个新的字段：roles，这个字段是长度为 4 的字符串字段。我们假定任何用户这个字段值是 C,R,U,D 的组合。一个用户如果 roles 字段值是 CRUD，即有执行所有操作的权限。缺少哪个权限就不允许执行相应的动作。读权限是对任何管理员开放的。

接下来，我们需要对 UserAdminView 类做一些修改：

```py
from flask.ext.admin.actions import ActionsMixin

class UserAdminView(ModelView, ActionsMixin):

    form_edit_rules = (
        'username','admin','roles','notes',
        rules.Header('Reset Password'),
        'new_password', 'confirm'
    )

    form_create_rules = (
        'username','admin','roles','notes','password'
    ) 
```

前面的代码中，我们仅仅向创建和编辑表单里添加了 roles 字段。我们同样继承了一个叫做 ActionsMixin 的类。这在大规模更新时（如大规模删除）是必须的。看下面代码：

```py
def create_model(self, form):
    if 'C' not in current_user.roles:
        flash('You are not allowed to create users.', 'warning')
        return
    model = self.model(
        form.username.data, form.password.data, form.admin.data,
        form.notes.data
    )
    form.populate_obj(model)
    self.session.add(model)
    self._on_model_change(form, model, True)
    self.session.commit() 
```

这个方法里，首先检查当前用户 roles 字段是否含有创建的权限（是否有 C）。如果没有，就显示一个错误，然后返回。看下面代码：

```py
 def update_model(self, form, model):
    if 'U' not in current_user.roles:
        flash('You are not allowed to edit users.', 'warning')
        return
    form.populate_obj(model)
    if form.new_password.data:
        if form.new_password.data != form.confirm.data:
            flash('Passwords must match')
            return
        model.pwdhash = generate_password_hash(form.new_password.data)
    self.session.add(model)
    self._on_model_change(form, model, False)
    self.session.commit() 
```

这个方法中，我们首先检查当前用户 roles 字段是否含有修改记录的权限（是否有 U）。如果没有，就显示一个错误，然后返回。看下面代码：

```py
def delete_model(self, model):
    if 'D' not in current_user.roles:
        flash('You are not allowed to delete users.', 'warning')
        return
    super(UserAdminView, self).delete_model(model) 
```

相似的，这里我们检查当前用户是否被允许去删除记录。看下面代码：

```py
def is_action_allowed(self, name):
    if name == 'delete' and 'D' not in current_user.roles:
        flash('You are not allowed to delete users.', 'warning')
        return False
    return True 
```

前面方法中，我们检查当前操作是否是 delete 并且检查当前用户是否被允许去删除。如果不，就显示一个错误，返回一个 False。

#### 原理

这一小节代码的效果和之前应用运行起来的效果类似，但是，现在用户只有有了相应的权限才能执行相应的操作。否则将显示错误信息。

用户列表看起来像下面这样：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/flask-fw-cb/img/126b19193531bb80b191d5fd0cf50bb9.png)

测试其余的功能，比如创建用户（普通用户或者管理员用户），删除用户，更新用户等等，这些读者最好自己尝试做一遍。


# 第九章：国际化和本地化

web 应用通常不限制于一个地区或者为一种特定语言的人群服务。比如，一个 web 应用意图服务于欧洲的用户，除了英语同样需要支持其它欧洲语言国家比如德国，法国，意大利，西班牙等等。这一章节将讲述如何在一个 Flask 应用中支持多种语言。

这一章将包括下面小节：

*   新增一种语言
*   延迟计算和 gettext/ngettext 函数
*   全球语言转换动作

## 介绍

在任何 web 应用中支持第二种语言都是一件麻烦的事情。每次应用发生修改的时候都增加了额外的开销，并且这种开销随着语言数量的增加而增加。除了为每种语言修改文本之外，还有很多事情需要去处理。其中一些是处理货币，数字，时间日期格式等等。

Flask-Babel 是一个扩展，用来向 Flask 应用添加 i18n 和 l1on 支持，它提供了一些工具和技术来使得这个过程更简单和更容易实现。

###### 提示

i18n 表示国际化，l10n 表示本地化。
这一章节，我们将使用这个扩展来理解这些概念。

## 新增一种语言

默认情况下 Flask 应用的语言是英语（大多数 web 框架都是如此）。我们将为我们的应用新增第二种语言并且为应用字符串新增一些转换。向用户展示的语言将依据用户浏览器中设置的语言而定。

#### 准备

我们从安装 Flask-Babel 扩展开始：

```py
$ pip install Flask-Babel 
```

这个扩展使用 Babel，pytz 和 speaklater 来向应用添加 i18b 和 l1on。
我们将使用第五章的应用来做演示。

#### 怎么做

首先，我们从配置部分开始，使用 app 对象创建一个 Babel 类的实例，并且指定这里可以使用的语言。French 被添加作为第二种语言：

```py
from flask_babel import Babel

ALLOWED_LANGUAGES = {
    'en': 'English',
    'fr': 'French',
}
babel = Babel(app) 
```

###### 提示

我们使用 en 和 fr 作为语言代码。他们分别表示英语（标准）和法语（标准）。如果我们想新增其他同一标准但是地区不同的语言比如英语（US）和英语（GB），这样的话需要使用这些代码比如 en-us 和 en-gb。

接下来，我们将在应用文件夹创建一个文件叫做 babel.cfg。这个文件的路径将是`flask_catalog/my_app/babel.cfg`，它将包含下面内容：

```py
[python: catalog/**.py]
[jinja2: templates/**.html]
extensions=jinja2.ext.autoescape,jinja2.ext.with_ 
```

这里，前两行告诉 Babel 哪些文件需要进行文本转换。第三行加载了一些扩展使得这些文件里的文本搜索变得可能。

应用的语言环境依赖于使用@babel.localeselector 装饰器修饰的这个方法的输出结果。向视图文件 views.py 新增下面方法：

```py
from my_app import ALLOWED_EXTENSIONS, babel

@babel.localeselector
def get_locale():
    return request.accept_languages.best_match(ALLOWED_LANGUAGES.keys())
    # return g.get('current_lang', 'en') 
```

前面方法从请求获取 Accept-Languages 头，然后寻找我们允许的最佳匹配语言。

###### 提示

修改浏览器的语言首选项是非常简单的。但是任何情况下，如果你不打算弄乱浏览器的语言首选项，仅仅需要从 get_locale()方法返回期待的语言代码。

接下来，我们需要标记一些文本是打算用来根据语言进行转换的。首先从 home.html 开始：

```py
{% block container %}
<h1>{{ _('Welcome to the Catalog Home') }}</h1>
  <a href="{{ url_for('catalog.products') }}" id="catalog_link">
      {{ _('Click here to see the catalog ') }}
  </a>
{% endblock %} 
```

这里，_ 是 Babel 提供的 gettext 函数的简写，它用来转换字符串。
之后，我们需要运行下面命令来使得被标记的文本在浏览器渲染我们模板时变得可用：

```py
$ pybabel extract -F my_app/babel.cfg -o my_app/messages.pot my_app 
```

前面命令遍历 babel.cfg 中所配置的文件内容，挑选出那些被标记为可转换的文本。所有这些文本被放置在 my_app/messages.pot 文件中。看下面命令：

```py
$ pybabel init -i my_app/messages.pot -d my_app/translations -l fr 
```

前面初始化命令创建了一个.po 文件，它包含那些需要被翻译文本的翻译。这个文件被创建在特定的文件夹里，即`my_app/translations/fr/LC_MESSAGES/messages.po`。当我们添加越多的语言时，越多的文件夹就会被添加。

现在，我们需要向 messages.po 文件新增一些翻译。这可以手动处理，或者我们也可以使用 GUI 工具比如 Poedit(`http://poedit.net/`)。使用这个工具，转换将看起来像下面截图这样：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/flask-fw-cb/img/8ecdf6886116538f1004163f4a1ae6da.png)

手动编辑 messages.po 将看起来像下面代码。为了演示只有一条信息被翻译：

```py
#:my_app/templates/home.html:6
msgid "Click here to see the catalog"
msgstr "Cliquez ici pour voir le catalogue" 
```

在翻译添加完之后保存 messages.po 文件，然后运行下面命令：

```py
$ pybabel compile -d my_app/translations 
```

这将在 message.po 文件旁边创建一个 messages.mo 文件，它将被应用用来去渲染翻译文本。

###### 提示

有时在运行上面代码之后消息不会被编译。这是因为这些信息可能被标记为模糊的（以#开头）。这需要进行人工排查，如果信息需要被编译器更新则需要移除#标记。为了通过检查，向前面编译命令添加一个-f 标记，这将强制编译所有东西。

#### 原理

如果我们设置浏览器语言为 French，然后运行应用，主页将看起来像下面截图这样：
![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/flask-fw-cb/img/ff1300dc2996639f74cafc2f5e07703b.png)

如果浏览器首选项语言不是法语，文本将以英语展示，英语是默认语言。

#### 更多

接下来，如果我们需要去更新 messages.po 文件的翻译，我们不需要再一次运行 init 命令。取而代之的是运行更新命令即：

```py
$ pybabel update -i my_app/messages.pot -d my_app/translations 
```

之后，像之前一样运行编译命令。

#### 提示

通常会依据于用户的 IP 和位置（有 IP 推断而来）来改变网站的语言。和使用 Accept-Language 头相比，这是一个更好的处理本地化的方法。

#### 其他

*   全球语言转换动作一节将允许用户直接去修改应用语言而不是在浏览器层面处理。
*   多语言的一个重要方面是需要处理日期，时间，货币。Babel 处理这些同样非常的简洁。我建议你自己尝试实现。参见 Babel 文档寻求更多信息`http://babel.pocoo.org/docs/`。

## 延迟计算和 gettext/negettext 函数

延迟计算（lazy evaluation）是一种计算策略，用来延迟表达的计算，直到需要值的时候才进行计算，因此这也叫做 call-by-need 机制。在我们的应用中，存在一些文本实例需要在渲染模板的时候才进行计算。通常情况下，当我们的文本在请求上下文之外被标记为可翻译时，我们就会推迟这些文本的执行，直到它们真正需要时。

#### 准备

让我们从前一小节应用开始。现在，我们希望商品和类别创建表单中的标签可以显示翻译的值。

#### 怎么做

为了标记商品和类别表单中的所有字段都是可以翻译的，我们需要对 models.py 做下面的修改：

```py
class NameForm(Form):
    name = StringField(_('Name'), validators=[InputRequired()])

class ProductForm(NameForm):
    price = DecimalField(_('Price'), validators=[
        InputRequired(), NumberRange(min=Decimal('0.0'))
    ])
    category = CategoryField(
        _('Category'), validators=[InputRequired()], coerce=int
    )
    image = FileField(_('Product Image'))

class CategoryForm(NameForm):
    name = StringField(_('Name'), validators=[
        InputRequired(), check_duplicate_category()
    ]) 
```

注意到所有这些字段标签都使用了 _()进行了标记。
现在，运行 pybabel extract 和 update 命令来更新 messages.po 文件，然后填充相关翻译，并且运行编译命令。具体细节参见上一小节。
使用`http://127.0.0.1:5000/product-create`打开商品创建页面。但是，它像我们期待的那样工作了吗？没有！因为，我们中的大多数应该猜到出现这样的情况原因可能是因为文本被标记为在请求上下文之外可翻译。

为了使之生效，我们仅仅需要修改下面的 import 语句：

```py
from flask_babel import lazy_ggetext as _ 
```

现在，我们有了更多的文本要来翻译。比如我们需要翻译商品创建的 flash 消息文本，像下面这样：

```py
flash("The product %s has been created" % name) 
```

为了标记它为可翻译的，我们不能仅仅简单的将所有东西包在 _()或 gettext()里面。gettext()函数支持占位符，可以使用%(name)s 替代。使用这种方法，前面代码将看起来像下面这样：

```py
flash(_('The product %(name)s has been created', name=name)) 
```

这句话的翻译结果看起来像这样 le produit %(name)s a été créé。

有些情况下，我们需要根据条目的数量来管理翻译，也就是单数或复数的名称。通过使用 ngettext()方法处理它。我们以在 products.html 模板中显示页码为例进行说明。
为此我们需要添加下面这行：

```py
{{ngettext('%(num)d page', '%(num)d pages', products.pages)}} 
```

这里，模板将渲染 page 如果只有一个页面，如果不止一个页面，将渲染 pages。

这是非常有趣的去注意 messages.po 文件里的翻译看起来是什么样子：

```py
#:my_app/templates/products.html:20
#,python-format
msgid "%(num)d page"
msgid_plural "%(num)d pages"
msgstr[0] "%(num)d page"
msgstr[1] "%(num)d pages" 
```

## 全球语言转换动作

前面一节，我们看到了依赖于当前浏览器语言首选项改变语言的处理。但是现在，我们需要一个机制来脱离浏览器的语言首选项转换语言。为此，我们需要在应用层面进行处理。

#### 准备

我们将修改上一小节的应用来完成语言转换。我们将新增一个额外的 URL 部分到所有的路由中来增加当前语言。我们可以仅仅在 URL 里修改语言就可以实现语言的切换。

#### 怎么做

首先需要修改所有的 URL 规则来增加一个额外的 URL 部分。
`@app.route('/')`将变为`@app.route('/<lang>/')`，同时`@app.route('/home')`将变为`@app.route('/<lang>/home')`。相似的，`@app.route('/product-search/<int:page>')`将变为`@app.route('/<lang>/product-search/<int:page>')`。所有的 URL 规则都需要这样处理。

现在，需要新增一个函数来添加 URL 中传递过来的语言到全局代理对象 g 中：

```py
@app.before_request
def before():
    if request.view_args and 'lang' in request.view_args:
        g.current_lang = request.view_args['lang']
        request.view_args.pop('lang') 
```

这个方法将在每个请求之前运行，向 g 中添加当前语言。
但是这意味着当前应用的所有的 url_for()调用需要修改来传递一个额外的参数 lang。幸运的是，有一个简单的方法处理它，像下面这样：

```py
from flask import url_for as flask_url_for

@app.context_processor
def inject_url_for():
    return {
        'url_for': lambda endpoint, **kwargs: flask_url_for(
            endpoint, lang=g.current_lang, **kwargs
        )   
    }

url_for = inject_url_for()['url_for'] 
```

前面代码中，我们首先导入`url_for`为`flask_url_for`。然后我们更新应用上下文处理器来添加`url_for()`函数，它是 Flask 提供的`url_for()`的修改版本，其中添加了额外的参数。

#### 原理

现在，运行这个应用，你会注意到所有的 URLs 有了一个语言部分。下面截图显示了渲染的模板看起来像什么样子。
打开`http://127.0.0.1:5000/en/home`我们将看到下面这样子：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/flask-fw-cb/img/8a2c1825da0d646d3be8093b1bcf2b20.png)

主页使用英语作为语言。
现在，仅仅修改 URL 为`http://127.0.0.1:5000/fr/home`然后主页将看起来像这样：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/flask-fw-cb/img/fbad18fff3678bb4de30cc9e58661289.png)

主页使用法语作为语言。

#### 其他

*   第一小节，新增一个语言，是依赖于浏览器设置的语言来处理本地化。

###### 译者注

Flask-Babel 使用方法参见其中文文档:
[`translations.readthedocs.io/en/latest/flask-babel.html`](https://translations.readthedocs.io/en/latest/flask-babel.html)

