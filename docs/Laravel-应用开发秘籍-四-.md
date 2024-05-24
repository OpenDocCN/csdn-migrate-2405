# Laravel 应用开发秘籍（四）

> 原文：[`zh.annas-archive.org/md5/d81d8d9e8c3a4da47310e721ff4953e5`](https://zh.annas-archive.org/md5/d81d8d9e8c3a4da47310e721ff4953e5)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第九章：有效使用安全和会话

在本章中，我们将涵盖：

+   加密和解密数据

+   哈希密码和其他数据

+   在表单中使用 CSRF 令牌和过滤器

+   在表单中使用高级验证

+   构建购物车

+   使用 Redis 保存会话

+   使用基本会话和 cookies

+   创建安全的 API 服务器

# 介绍

安全是我们在构建 Web 应用程序时需要考虑的最重要的事情之一，特别是如果我们处理敏感的用户信息。Laravel 为我们提供了许多方法来保护我们的应用程序安全。

在本章中，我们将看看掩盖敏感数据的各种方法，如何保护我们的表单免受跨站点攻击，以及如何保护 API。我们还将看到如何使用会话来构建购物车，并使用 Redis 存储会话数据。

# 加密和解密数据

在编写处理敏感数据的应用程序时，我们经常希望加密我们存储在数据库中的任何数据。Laravel 为我们提供了解决这个问题的解决方案。

## 准备工作

对于这个配方，我们需要一个标准的 Laravel 安装，以及一个正确设置和配置的 MySQL 数据库。

## 如何做…

这是我们将使用以下步骤完成该配方的方法：

1.  在`app/config`目录中，打开`app.php`文件，并确保`key`为空

```php
  'key' => '',
```

1.  在命令行中，转到应用程序的根目录，并使用以下命令生成一个新的密钥：

```php
  php artisan key:generate
```

1.  使用以下命令在数据库中创建一个表来保存我们的敏感信息：

```php
CREATE TABLE accounts(
  id int(11) unsigned NOT NULL AUTO_INCREMENT,
    business varchar(255) DEFAULT NULL,
    total_revenue varchar(255) DEFAULT NULL,
    projected_revenue varchar(255) DEFAULT NULL,
    PRIMARY KEY (id)) 
    ENGINE=InnoDB DEFAULT CHARSET=utf8;

```

1.  在我们的`app/models`目录中，通过输入以下代码创建一个名为`Account.php`的文件：

```php
<?php

class Account extends Eloquent {
  protected $table = 'accounts';
  public $timestamps = false;
  public function setBusinessAttribute($business) {$this->attributes['business'] = Crypt::encrypt($business);
}

public function setTotalrevenueAttribute($total_revenue)
  {$this->attributes['total_revenue'] = Crypt::encrypt($total_revenue);
}

  public functionsetProjectedrevenueAttribute($projected_revenue)
{
  $this->attributes['projected_revenue'] = Crypt::encrypt($projected_revenue);
}

public function getBusinessAttribute()
{
  return Crypt::decrypt($this->attributes['business'])
}

public function getTotalrevenueAttribute()
{
  return number_format(Crypt::decrypt($this>attributes['total_revenue'])) ;
}

public function getProjectedrevenueAttribute()
{
  return number_format(Crypt::decrypt($this>attributes['projected_revenue']));
}
}
```

1.  在我们的`routes.php`文件中，通过添加以下代码创建查看和提交信息的路由：

```php
Route::get('accounts', function()
{
  $accounts = Account::all();
  return View::make('accounts')->with('accounts', $accounts);
});

Route::post('accounts', function()
{
  $account = new Account();
  $account->business = Input::get('business');
  $account->total_revenue = Input::get('total_revenue');
  $account->projected_revenue = Input::get('projected_revenue');
  $account->save();
  return Redirect::to('accounts');
});
```

1.  在我们的`views`目录中，创建一个名为`accounts.php`的文件

```php
  <form action="accounts" method="post">
  <label for="business">Business:</label><br>
  <input name="business"><br><br>
  <label for="total_revenue">Total Revenue ($):</label><br>
  <input name="total_revenue"><br><br>
  <label for="projected_revenue">Projected Revenue($):</label><br>
  <input name="projected_revenue"><br><br>
  <input type="submit">
  </form>
  <hr>
  <?php if ($accounts): ?>
  <table border="1">
  <thead>
  <tr>
  <th>Business</th>
  <th>Total Revenue</th>
  <th>Projected Revenue</th>
  </tr>
  </thead>
  <tbody>
  <?php foreach ($accounts as $account): ?>
  <tr>
  <td><?= $account->business ?></td>
  <td>$<?= $account->total_revenue ?></td>
  <td>$<?= $account->projected_revenue ?></td>
  </tr>
  <?php endforeach; ?>
  </tbody>
  </table>
  <?php endif; ?>
```

## 工作原理…

我们首先移除 Laravel 默认的密钥。然后，我们使用`artisan`命令为我们生成一个新的密钥，并且它会自动保存在正确的文件中。`artisan`命令创建了一个相当强大的密钥，所以我们不必担心自己想出一个密钥。

在为应用程序创建密钥之后，请确保不要更改它，因为如果您已经使用了一些加密，那么更改密钥将会破坏您的应用程序。

然后我们设置一个数据库表，用来保存我们的敏感数据。在这个例子中，我们将存储企业名称以及一些财务数据。

我们的下一步是设置我们的模型，使用`Eloquent`模型。为了让事情变得更容易一些，我们将在模型中使用 getter 和 setter，这样每当在我们的`Account`模型中设置一个值时，它都会自动使用 Laravel 的`Crypt::encrypt`类进行加密。此外，为了从数据库中获取信息，我们的模型将自动为我们解密它。

接下来，我们创建了一些路由。第一个路由将显示一个表单来添加信息，并显示数据库中已经保存的任何内容。下一个路由只是获取表单输入，并将其保存到我们的账户表中的新行中。添加信息后，我们将被重定向回账户列表和表单页面，并且新数据将显示在页面底部。

然而，如果我们查看数据库本身，我们存储的信息是不可读的文本。这样，如果有人成功入侵我们的数据库，他们也得不到太多信息。

# 哈希密码和其他数据

当我们将用户的密码存储在数据库中时，对密码进行哈希处理是常见的做法。这有助于防止任何未经授权访问数据库的人看到用户的密码。然而，我们可能还希望隐藏用户的电子邮件地址或其他信息，以便没有人能够访问它们。我们可以使用 Laravel 的**Hash**来轻松实现这一点。

## 准备工作

对于这个配方，我们需要一个标准的 Laravel 安装，以及一个正确设置和配置的 MySQL 数据库。

## 如何做…

以下是此配方的步骤…

1.  使用以下命令设置数据库表：

```php
CREATE TABLE register (
  id int(10) unsigned NOT NULL AUTO_INCREMENT,
  username varchar(255) DEFAULT NULL,
  email char(60) DEFAULT NULL,
  password char(60) DEFAULT NULL,
  PRIMARY KEY (id)
  ) ENGINE=InnoDB AUTO_INCREMENT=1

```

1.  在`views`目录中，使用以下代码创建一个名为`register.php`的文件：

```php
  <!doctype html>
  <html lang="en">
  <head>
  <meta charset="utf-8">
  <title>Register</title>
  </head>
  <body>
  <p>
  <h3>Register</h3>
  <form method="post" action="register">
  <label>User Name</label>
  <input name="username"><br>
  <label>Email</label>
  <input name="email"><br>
  <label>Password</label>
  <input name="password"><br>
  <input type="submit">
  </form>
  </p>
  <p style="border-top:1px solid #555">
  <h3>Login</h3>
  <form method="post" action="login">
  <label>User Name</label>
  <input name="username"><br>
  <label>Email</label>
  <input name="email"><br>
  <label>Password</label>
  <input name="password"><br>
  <input type="submit">
  </form>
  </p>
  <hr>
  <table border='1'>
  <?php if ($users): ?>
  <tr>
  <th>User Name</th>
  <th>Email</th>
  <th>Password</th>
  </tr>
  <?php foreach ($users as $user): ?>
  <tr>
  <td><?= $user->username ?></td>
  <td><?= $user->email ?></td>
  <td><?= $user->password ?></td>
  </tr>
  <?php endforeach; ?>
  <?php endif; ?>
  </table>
  </body>
  </html>
```

1.  在我们的`routes.php`文件中，通过添加以下代码创建我们的路由：

```php
Route::get('register', function()
{
  $users = DB::table('register')->get();
  return View::make('register')->with('users', $users);
});

Route::post('register', function()
{
  $data = array(
    'username' => Input::get('username'),
    'email' => Hash::make(Input::get('email')),
    'password' => Hash::make(Input::get('password')));

  DB::table('register')->insert($data);

  return Redirect::to('register');
});

Route::post('login', function()
{
  $user = DB::table('register')->where('username', '=',
    Input::get('username'))->first();
  if (!is_null($user) and Hash::check(Input::get('email'),
    $user->email) and Hash::check(Input::get('password'),
    $user->password)) {
    echo "Log in successful";
  } else {
  echo "Not able to login";
}
});

```

## 它是如何工作的...

要开始这个示例，我们首先设置一个基本的用户表，用于保存用户名、电子邮件地址和密码。在这个示例中，用户名是唯一需要以常规文本形式存在的内容。

在我们的视图中，我们将创建两个表单——一个用于注册，一个用于登录。为了显示来自数据库的原始数据，我们还将显示所有用户的列表，以及他们的电子邮件和密码在表中的样子。

当我们提交注册表单时，信息将被发布到我们的注册路由并放入一个数组中。对于电子邮件和密码，我们使用 Laravel 的`Hash::make()`函数进行哈希处理。然后，我们将数组插入到我们的注册表中，并重定向回表单和列表页面。

重定向后，我们将看到新添加的行，我们的电子邮件和密码已经被哈希处理，并且是一个无法识别的字符串。有趣的是，通过哈希处理的方式，我们可以使用完全相同的数据添加两行，哈希值将完全不同。

接下来，我们可以尝试使用用户名、电子邮件和密码登录。该路由将从与用户名对应的表中抓取一行，然后对输入值和数据库结果运行 Laravel 的`Hash::check()`函数。如果通过，它将返回`TRUE`，我们可以继续进行应用程序。

## 还有更多...

要在生产环境中使用此示例，我们需要对输入进行一些验证。我们可能还希望利用**Eloquent ORM**来使哈希处理变得更容易一些。

如果我们不需要隐藏用户的电子邮件，我们也可以使用 Laravel 内置的`Auth::attempt()`方法。关于此方法的更多信息可以在 Laravel 网站上找到：[`laravel.com/docs/security#authenticating-users`](http://laravel.com/docs/security#authenticating-users)

# 在表单中使用 CSRF 令牌和过滤器

网络表单以黑客试图访问网站或用户信息而臭名昭著。为了使我们的表单更安全，我们可以使用内置在 Laravel 中的**跨站请求伪造**（**CSRF**）策略。这将阻止来自用户会话外部的表单提交。

## 准备工作

对于这个示例，我们需要一个标准的 Laravel 安装。

## 如何做...

以下是完成此示例的步骤：

1.  在`routes.php`文件中，通过以下代码创建用于保存和处理表单的路由：

```php
Route::get('cross-site', function()
{
  return View::make('cross-site');
});

Route::post('cross-site', array('before' => 'csrf',function()
{
  echo 'Token: ' . Session::token() . '<br>';
  dd(Input::all());
}));
```

1.  在`filters.php`文件中，确保`csrf`令牌的`filter`存在，如下所示：

```php
Route::filter('csrf', function()
{
  if (Session::token() != Input::get('_token'))
{
  throw new Illuminate\Session\TokenMismatchException;
}
});
```

1.  在我们的`views`目录中，创建一个名为`cross-site.php`的文件，并按以下代码添加两个测试表单：

```php
  <!doctype html>
  <html lang="en">
  <head>
  <meta charset="utf-8">
  <title>CSRF Login</title>
  </head>
  <body>
  <p>
  <h3>CSRF Login</h3>
  <?= Form::open(array('url' => 'cross-site', 'method' =>'post')) ?>
  <?= Form::token() ?>
  <?= Form::label('email', 'Email') ?>
  <?= Form::text('email') ?>
  <?= Form::label('password', 'Password') ?>
  <?= Form::password('password') ?>
  <?= Form::submit('Submit') ?>
  <?= Form::close() ?>
  </p>
  <hr>
  <p>
  <h3>CSRF Fake Login</h3>
  <?= Form::open(array('url' => 'cross-site', 'method' =>'post')) ?>
  <?= Form::hidden('_token', 'smurftacular') ?>
  <?= Form::label('email', 'Email') ?>
  <?= Form::text('email') ?>
  <?= Form::label('password', 'Password') ?>
  <?= Form::password('password') ?>
  <?= Form::submit('Submit') ?>
  <?= Form::close() ?>
  </p>
  </body>
  </html>
```

1.  在浏览器中，转到`http://{your-server}/cross-site`（其中`{your-server}`是我们正在使用的服务器的名称），然后提交每个表单以查看结果。

## 它是如何工作的...

我们的第一步是为我们的 CSRF 表单创建路由。在表单中，我们只需要添加`Form::token()`函数；这将插入一个隐藏字段，名称为`_token`，值为用户会话 ID。对于提交表单的路由，我们在路由中添加`csrf`前过滤器。如果请求被确定为伪造，页面将返回服务器错误。

我们的下一个表单是一个示例，展示了如果请求试图被伪造会发生什么。对于这个表单，我们手动添加隐藏字段并添加一些随机值，而不是使用`Form::token()`函数。然后当我们提交表单时，页面将显示一个失败消息，并显示`TokenMismatchException`错误。

## 还有更多...

当您使用`Form::open()`函数时，Laravel 还会自动生成一个`csrf`令牌，因此您不需要手动添加它。

# 在表单中使用高级验证

有时我们需要验证表单中不属于框架的内容。这个配方将向您展示如何构建自定义验证规则并应用它。

## 准备工作

对于这个配方，我们需要一个标准的 Laravel 安装。

## 如何做...

以下是完成这个配方的步骤：

1.  在`views`目录中，创建一个名为`valid.php`的文件，使用以下代码来保存我们的表单：

```php
  <!doctype html>
  <html lang="en">
  <head>
  <meta charset="utf-8">
  <title>Custom Validation</title>
  </head>
  <body>
  <p>
  <?php if ($errors): ?>
  <?php echo $errors->first('email') ?>
  <?php echo $errors->first('captain') ?>
  <?php endif; ?>
  </p>
  <p>
  <h3>Custom Validation</h3>
  <?= Form::open(array('url' => 'valid', 'method' => 'post'))?>
  <?= Form::label('email', 'Email') ?>
  <?= Form::text('email') ?><br><br>
  <?= Form::label('captain', 'Your favorite captains (choosethree)') ?><br>
  <?= 'Pike: ' . Form::checkbox('captain[]', 'Pike') ?><br>
  <?= 'Kirk: ' . Form::checkbox('captain[]', 'Kirk') ?><br>
  <?= 'Picard: ' . Form::checkbox('captain[]', 'Picard')?><br>
  <?= 'Sisko: ' . Form::checkbox('captain[]', 'Sisko') ?><br>
  <?= 'Janeway: ' . Form::checkbox('captain[]', 'Janeway')?><br>
  <?= 'Archer: ' . Form::checkbox('captain[]', 'Archer')?><br>
  <?= 'Crunch: ' . Form::checkbox('captain[]', 'Crunch')?><br>
  <?= Form::submit('Submit') ?>
  <?= Form::close() ?>
  </p>
  </body>
  </html>
```

1.  在`routes.php`文件中，使用以下代码创建我们的路由：

```php
Route::get('valid', function()
{
  return View::make('valid');
});
Route::post('valid', function()
{
  $rules = array('email' => 'required|email','captain' => 'required|check_three');
  $messages = array('check_three' => 'Thou shalt choose three captains. Nomore. No less. Three shalt be the number thou shaltchoose, and the number of the choosing shall bethree.',);
  $validation = Validator::make(Input::all(), $rules,$messages);
  if ($validation->fails())
  {
  return Redirect::to('valid')->withErrors($validation);
}
  echo "Form is valid!";
});
```

1.  同样在`routes.php`文件中，按照以下代码创建我们的自定义验证：

```php
  Validator::extend('check_three', function($attribute,$value, $parameters)
{
  return count($value) == 3;
});
```

## 它是如何工作的...

首先，我们在视图中创建表单。我们要求一个有效的电子邮件和确切地三个复选框被选中。由于没有确切地三个复选框的 Laravel 验证方法，我们需要创建一个自定义验证。

我们的自定义验证接受输入数组并进行简单计数。如果计数达到三个，它返回`TRUE`。如果不是，则返回`FALSE`并且验证失败。

回到我们的表单处理路由，我们只需要将我们创建的自定义验证器的名称添加到我们的验证规则中。如果我们想设置自定义消息，也可以添加。

## 还有更多...

这个配方的额外验证器在`routes.php`文件中，为了简单起见。如果我们有多个自定义验证器，将它们放在自己的验证器文件中可能是一个更好的主意。为此，我们应该在`app`目录中创建一个名为`validator.php`的文件，并添加任何我们想要的代码。然后，打开`app/start`目录中的`global.php`文件，在文件的最后添加`require app_path().'/validator.php'`函数。这将自动加载所有的验证器。

# 构建一个购物车

电子商务在网络上是一个巨大的业务。大多数电子商务网站的一个重要部分是使用购物车系统。这个配方将介绍如何使用 Laravel 会话来存储销售商品并构建购物车。

## 准备工作

对于这个配方，我们需要一个标准的 Laravel 安装，以及一个正确设置和配置的 MySQL 数据库。

## 如何做...

要完成这个配方，按照以下给定的步骤进行操作：

1.  在我们的数据库中，使用以下 SQL 代码创建一个表并添加一些数据：

```php
CREATE TABLE items (
    id int(10) unsigned NOT NULL AUTO_INCREMENT,
    name varchar(255) DEFAULT NULL,
    description text,
    price int(11) DEFAULT NULL,
    PRIMARY KEY (id)
    ) ENGINE=InnoDB;

  INSERT INTO items VALUES ('1', 'Lamp', 'This is a Lamp.','14');
  INSERT INTO items VALUES ('2', 'Desk', 'This is a Desk.','75');
  INSERT INTO items VALUES ('3', 'Chair', 'This is a
    Chair.', '22');
  INSERT INTO items VALUES ('4', 'Sofa', 'This is a
    Sofa/Couch.', '144');
  INSERT INTO items VALUES ('5', 'TV', 'This is a
    Television.', '89');

```

1.  在`routes.php`文件中，使用以下代码为我们的购物车创建路由：

```php
Route::get('items', function() 
{
  $items = DB::table('items')->get();
  return View::make('items')->with('items', $items)>nest('cart', 'cart', array('cart_items' =>Session::get('cart')));
});

Route::get('item-detail/{id}', function($id)
{
  $item = DB::table('items')->find($id);
  return View::make('item-detail')->with('item', $item)>nest('cart', 'cart', array('cart_items' =>Session::get('cart')));
});

Route::get('add-item/{id}', function($id)
{
  $item = DB::table('items')->find($id);
  $cart = Session::get('cart');
  $cart[uniqid()] = array ('id' => $item->id, 'name' => $item >name, 'price' => $item->price);
  Session::put('cart', $cart);
  return Redirect::to('items');
});

Route::get('remove-item/{key}', function($key)
{
  $cart = Session::get('cart');
  unset($cart[$key]);
  Session::put('cart', $cart);
  return Redirect::to('items');
});

Route::get('empty-cart', function()
{
  Session::forget('cart');
  return Redirect::to('items');
});
```

1.  在`views`目录中，使用以下代码创建一个名为`items.php`的文件：

```php
  <!doctype html>
  <html lang="en">
  <head>
  <meta charset="utf-8">
  <title>Item List</title>
  </head>
  <body>
  <div>
  <?php foreach ($items as $item): ?>
  <p>
  <a href="item-detail/<?= $item->id ?>">
  <?= $item->name ?>
  </a> --
  <a href="add-item/<?= $item->id ?>">Add to Cart</a>
  </p>
  <?php endforeach; ?>
  </div>
  <?php $cart_session = Session::get('cart') ?>
  <?php if ($cart_session): ?>
  <?= $cart ?>
  <?php endif; ?>
  </body>
  </html>
```

1.  在`views`目录中，按照给定的代码创建一个名为`item-detail.php`的文件：

```php
  <!doctype html>
  <html lang="en">
  <head>
  <meta charset="utf-8">
  <title>Item: <?= $item->name ?></title>
  </head>
  <body>
  <div>
  <h2><?= $item->name ?></h2>
  <p>Price: <?= $item->price ?></p>
  <p>Description: <?= $item->description ?></p>
  <p>
  <a href="../add-item/<?= $item->id ?>">Add to Cart</a>
  </p>
  <p><a href="../items">Item list</a></p>
  </div>
  <? if (Session::has('cart')): ?>
  <?= $cart ?>
  <? endif; ?>
  </body>
  </html>
```

1.  在`views`目录中，创建一个名为`cart.php`的文件，使用以下代码：

```php
  <div class="cart" style="border: 1px solid #555">
  <?php if ($cart_items): ?>
  <?php $price = 0 ?>
  <ul>
  <?php foreach ($cart_items as $cart_item_key =>$cart_item_value): ?>
  <?php $price += $cart_item_value['price']?>
  <li>
  <?= $cart_item_value['name'] ?>: 
  <?= $cart_item_value['price'] ?> (<a href="remove-item/<?= $cart_item_key ?>">remove</a>)
  </li>
  <?php endforeach; ?>
  </ul>
  <p><strong>Total: </strong> <?= $price ?></p>
  <?php endif; ?>
  </div>
```

1.  现在，我们可以在浏览器中输入`http://{your-server}/items`来查看来自我们数据库的项目列表，链接到它们的详细页面，并有一个选项将它们添加到购物车。添加到购物车后，它们将显示在页面底部。

## 它是如何工作的...

要开始这个配方，我们需要设置一个将保存我们想要添加到购物车的项目的数据库表。我们还将添加一些测试项目，这样我们就有一些数据可以使用。

在我们的第一个路由中，我们获取表中所有现有的项目并显示它们。我们还嵌套了一个购物车视图，将显示我们已经添加的项目。在嵌套视图中，我们还发送我们的购物车会话，以便列表可以填充。

我们的下一个路由做了类似的事情，但它只接受一个项目并显示完整信息。

下一个路由实际上添加了项目。首先，我们根据其 ID 从数据库中获取项目。然后我们将现有的购物车会话保存到一个变量中，以便我们可以操作它。我们使用 php 的`uniqid()`函数作为键将项目添加到数组中。然后我们将`cart`数组放回`Session`并将其重定向。

如果我们想要删除一个项目，首先我们要找到获取项目的 ID 并从`cart`数组中删除它。另一种方法是只删除所有会话并重新开始。

在我们的视图中，我们还会注意到，只有在购物车中实际有东西的情况下，才允许显示`cart`列表。

## 还有更多...

这个配方可以很容易地扩展为更全面的功能。例如，如果我们多次点击同一项，可以存储每个项目的总数，而不是添加新记录。这样，我们可以在项目旁边添加一个要求数量的表单字段。

# 使用 Redis 保存会话

Redis 是一种流行的键/值数据存储，速度相当快。Laravel 包括对 Redis 的支持，并且可以轻松地与 Redis 数据交互。

## 准备工作

对于这个配方，我们需要一个正确配置和运行的 Redis 服务器。关于这方面的更多信息可以在[`redis.io/`](http://redis.io/)找到。

## 如何做...

按照以下步骤完成这个配方：

1.  在我们的`routes.php`文件中，按照以下代码创建路由：

```php
Route::get('redis-login', function()
{
  return View::make('redis-login');
});

Route::post('redis-login', function()
{
  $redis = Redis::connection();
  $redis->hset('user', 'name', Input::get('name'));
  $redis->hset('user', 'email', Input::get('email'));
  return Redirect::to('redis-view');
});

Route::get('redis-view', function()
{
  $redis = Redis::connection();
  $name = $redis->hget('user', 'name');
  $email = $redis->hget('user', 'email');
  echo 'Hello ' . $name . '. Your email is ' . $email;
});
```

1.  在`views`目录中，创建一个名为`redis-login.php`的文件，其中包含以下代码：

```php
  <!doctype html>
  <html lang="en">
  <head>
  <meta charset="utf-8">
  <title>Redis Login</title>
  </head>
  <body>
  <p>
  <h3>Redis Login</h3>
  <?= Form::open(array('url' => 'redis-login', 'method' =>'post')) ?>
  <?= Form::label('name', 'Your Name') ?>
  <?= Form::text('name') ?>
  <?= Form::label('email', 'Email') ?>
  <?= Form::text('email') ?>
  <?= Form::submit('Submit') ?>
  <?= Form::close() ?>
  </p>
  </body>
  </html>
```

1.  现在，我们可以打开浏览器，转到`http://{your-server}/redis-login`，并填写表单。提交后，我们将显示来自 Redis 的信息。

## 工作原理...

我们的第一步是创建一个简单的表单，用于将数据输入到 Redis 中。在我们的`redis-login`路由中，我们使用一个视图，该视图将要求输入姓名和电子邮件地址，并在提交时将发布到`redis-login`路由。

发布后，我们使用`Redis::connection()`函数创建一个新的 Redis 实例，该函数将使用我们的`app/config/database.php`文件中找到的默认设置。为了将信息存储在 Redis 中，我们使用一个哈希并使用`hset()`函数设置数据。我们的 Redis 实例可以使用 Redis 接受的任何命令，因此我们可以很容易地在`set()`或`sadd()`等函数之间进行选择。

一旦数据在 Redis 中，我们重定向到一个将显示数据的路由。为此，我们只需要使用键和我们添加的字段调用`hget()`函数。

# 使用基本会话和 cookie

有时我们希望在应用程序的一个页面和另一个页面之间传递数据，而不需要将信息存储在数据库中。为了实现这一点，我们可以使用 Laravel 提供的各种`Session`和`Cookie`方法。

## 准备工作

对于这个配方，我们需要一个标准的 Laravel 安装。

## 如何做...

对于这个配方，按照给定的步骤：

1.  在`views`文件夹中，创建一个名为`session-one.php`的文件，其中包含以下代码：

```php
  <!DOCTYPE html>
  <html>
  <head>
  <title>Laravel Sessions and Cookies</title>
  <meta charset="utf-8">
  </head>
  <body>
  <h2>Laravel Sessions and Cookies</h2>
  <?= Form::open() ?>
  <?= Form::label('email', 'Email address: ') ?>
  <?= Form::text('email') ?>
  <br>
  <?= Form::label('name', 'Name: ') ?>
  <?= Form::text('name') ?>
  <br>
  <?= Form::label('city', 'City: ') ?>
  <?= Form::text('city') ?>
  <br>
  <?= Form::submit('Go!') ?>
  <?= Form::close() ?>
  </body>
  </html>
```

1.  在`routes.php`文件中，按照以下代码创建我们的路由：

```php
Route::get('session-one', function()
{
  return View::make('session-one');
});

Route::post('session-one', function()
{
  Session::put('email', Input::get('email'));
  Session::flash('name', Input::get('name'));
  $cookie = Cookie::make('city', Input::get('city'), 30);
  return Redirect::to('session-two')->withCookie($cookie);
});

Route::get('session-two', function()
{
  $return = 'Your email, from a Session, is 'Session::get('email') . '. <br>';
  $return .= 'You name, from flash Session, is 'Session::get('name') . '. <br>';
  $return .= 'You city, from a cookie, is ' .Cookie::get('city') . '.<br>';
  $return .= '<a href="session-three">Next page</a>';
  echo  $return;
});

Route::get('session-three', function()
{
  $return = '';

  if (Session::has('email')) {
  $return .= 'Your email, from a Session, is ' . Session::get('email') . '. <br>';
} else {
$return .= 'Email session is not set.<br>';
}

if (Session::has('name')) {
  $return .= 'Your name, from a flash Session, is ' . Session::get('name') . '. <br>';
} else {
$return .= 'Name session is not set.<br>';
}

if (Cookie::has('city')) {
  $return .= 'Your city, from a cookie, is ' . Cookie::get('city') . '. <br>';
} else {
  $return .= 'City cookie is not set.<br>';
}
  Session::forget('email');
  $return .= '<a href="session-three">Reload</a>';
  echo $return;
});
```

## 工作原理...

首先，我们创建一个简单的表单，用于提交信息到会话和 cookie。在提交值之后，我们取`email`字段并将其添加到常规会话中。`name`字段将被添加到闪存会话中，`city`将被添加到 cookie 中。此外，我们将设置 cookie 在 30 分钟后过期。一旦它们都设置好了，我们重定向到我们的第二个页面，并确保将 cookie 传递给返回值。

我们的第二个页面只是获取我们设置的值，并显示它们以验证它们是否被正确设置。此时，一旦请求完成，我们的闪存会话，即名称，应该不再可用。

当我们点击到第三个页面时，我们添加了一些检查，以确保会话和 cookie 仍然存在，使用`has()`方法。我们的`email`和`city`应该仍然显示，但`name`会话不应该。然后我们使用`forget()`方法删除`email`会话。当我们重新加载页面时，我们会注意到唯一仍然显示的是`city` cookie。

## 还有更多...

闪存数据仅在我们进行的下一个请求中可用，然后被删除。但是，如果我们想保留我们的闪存数据，我们可以使用`Session::reflash()`命令，它也会将数据发送到我们的下一个请求。如果我们有多个闪存数据，我们还可以使用`Session::keep(array('your-session-key', 'your-other-session'))`函数选择保留特定会话以供下一个请求使用。

# 创建安全的 API 服务器

在这个食谱中，我们将创建一个简单的 API 来显示来自我们数据库的一些信息。为了控制谁可以访问数据，我们允许用户创建密钥并在其 API 请求中使用该密钥。

## 准备工作

对于这个食谱，我们需要一个标准的 Laravel 安装和一个配置好的 MySQL 数据库。

## 如何做到这一点...

要完成这个食谱，我们将按照以下给定的步骤进行：

1.  在我们的数据库中，创建一个表来保存 API 密钥，如下面的代码所示：

```php
CREATE TABLE api (
id int(10) unsigned NOT NULL AUTO_INCREMENT,
 name varchar(255) DEFAULT NULL,
 api_key varchar(255) DEFAULT NULL,
 status tinyint(1) DEFAULT NULL,
 PRIMARY KEY (id)
 ) ENGINE=InnoDB DEFAULT CHARSET=utf8;
```

1.  在数据库中，创建一个表以访问一些示例数据，如下面的代码所示：

```php
CREATE TABLE shows (id int(10) unsigned NOT NULL AUTO_INCREMENT,name varchar(200) NOT NULL,year int(11) NOT NULL,created_at datetime NOT NULL,updated_at datetime NOT NULL,PRIMARY KEY (id)) ENGINE=InnoDB CHARSET=utf8;

  INSERT INTO shows VALUES ('1', 'Happy Days', '1979','2013-01-01 00:00:00', '2013-01-01 00:00:00');
  INSERT INTO shows VALUES ('2', 'Seinfeld', '1999', '2013-01-01 00:00:00', '2013-01-01 00:00:00');
  INSERT INTO shows VALUES ('3', 'Arrested Development', '2006', '2013-01-01 00:00:00', '2013-01-01 00:00:00');
  INSERT INTO shows VALUES ('4', 'Friends', '1997','2013-01-01 00:00:00', '2013-01-01 00:00:00');
```

1.  在`models`目录中，创建一个名为`Api.php`的文件

```php
  <?php

class Api extends Eloquent {

  public $table = 'api';
  public $timestamps = FALSE;
}
```

1.  在`models`目录中，创建一个名为`Show.php`的文件

```php
  <?php
class Show extends Eloquent {
}
```

1.  在`views`目录中，创建一个名为`api-key.php`的文件

```php
  <!DOCTYPE html>
  <html>
  <head>
  <title>Create an API key</title>
  <meta charset="utf-8">
  </head>
  <body>
  <h2>Create an API key</h2>
  <?php echo Form::open() ?>
  <?php echo Form::label('name', 'Your Name: ') ?>
  <?php echo Form::text('name') ?>
  <br>
  <?php echo Form::submit('Go!') ?>
  <?php echo Form::close() ?>
  </body>
  </html>
```

1.  在`routes.php`文件中，创建路由以允许`api-key`注册

```php
Route::get('api-key', function() {
  return View::make('api-key');
});

Route::post('api-key', function() {
  $api = new Api();
  $api->name = Input::get('name');
  $api->api_key = Str::random(16);
  $api->status = 1;
  $api->save();
  echo 'Your key is: ' . $api->api_key;
});
```

1.  在`routes.php`中，通过以下代码创建访问`api`的路由：

```php
Route::get('api/{api_key}/shows', function($api_key)
{
  $client = Api::where('api_key', '=', $api_key)->where('status', '=', 1)->first();
  if ($client) {
  return Show::all();
  } else {
  return Response::json('Not Authorized', 401);
  }
});
Route::get('api/{api_key}/show/{show_id}', function($api_key, $show_id)
{
  $client = Api::where('api_key', '=', $api_key)->where('status', '=', 1)->first();
  if ($client) {
  if ($show = Show::find($show_id)) {
  return $show;
  } else {
  return Response::json('No Results', 204);
  }
  } else {
  return Response::json('Not Authorized', 401);
  }
});
```

1.  要测试它，在浏览器中，转到`http://{your-server}/api-key`（其中`{your-server}`是开发服务器的名称），并填写表单。在下一页中，复制生成的密钥。然后，转到`http://{your-server}/api/{your-copied-key}/shows`，应该以`json`格式显示节目列表。

## 它是如何工作的...

我们首先设置我们的表和模型。我们的 API 表将用于检查密钥，`show`表将是我们将使用密钥访问的测试数据。

我们的下一个任务是创建一种为我们的应用程序生成密钥的方法。在这个例子中，我们只会接受一个名称值。提交后，我们创建一个随机的 16 个字符的字符串，这将是用户的密钥。然后，我们将信息保存到表中，并将密钥显示给用户。

要使用此密钥，我们创建两个路由来显示信息。第一个路由在 URL 中使用`{api_key}`通配符，并将该值传递给我们的函数。然后，我们查询该密钥的数据库，并确保状态仍然是活动的。这样，如果我们决定撤销用户的密钥，我们可以将状态设置为 false，他们将无法使用 API。如果它们不存在或状态为 false，则以 401 的 HTTP 代码响应，以显示他们未经授权。否则，我们返回 Eloquent 对象，这将允许我们以`json`格式显示记录。

我们的第二个路由将显示单个节目的记录。对于该 URL，我们使用`{api_key}`通配符作为密钥，使用`{show_id}`通配符作为节目的 ID。我们将这些传递给函数，然后像以前一样检查密钥。如果密钥有效，我们确保具有该 ID 的节目存在，并再次使用 Eloquent 对象以`json`格式仅显示具有给定 ID 的节目。

## 还有更多...

我们还可以选择使用 Laravel 过滤器，如果我们宁愿使用 API 密钥发布。为此，我们将在`filters.php`文件中创建一个新的过滤器

```php
Route::filter('api', function()
{
  if ($api_key = Input::get('api_key')) {
  $client = Api::where('api_key', '=', $api_key)->where('status', '=', 1)->first();
  if (!$client) {
  return Response::json('Not Authorized', 401);
}
  } else {
  return Response::json('Not Authorized', 401);
}
});
```

然后，对于我们的`shows`路由，我们响应一个 post 请求，并添加`before`过滤器，如下面的代码所示：

```php
Route::post('api/shows', array('before' => 'api', function()
{
  return Show::all();
}));
```


# 第十章：测试和调试您的应用程序

在本章中，我们将涵盖：

+   设置和配置 PHPUnit

+   编写和运行测试用例

+   使用 Mockery 测试控制器

+   使用 Codeception 编写验收测试

+   调试和分析您的应用程序

# 介绍

随着 Web 应用程序变得更加复杂，我们需要确保对现有代码所做的任何更改或更新不会对其他代码产生负面影响。检查这一点的一种方法是创建单元测试。Laravel 为我们提供了非常有用的方法来包含单元测试。

# 设置和配置 PHPUnit

在这个配方中，我们将看到如何安装和设置流行的 PHPUnit 测试软件包：PHPUnit。

## 准备工作

对于这个配方，我们需要一个正常安装的 Laravel 4。我们还需要从[`getcomposer.org`](http://getcomposer.org)安装 Composer 依赖工具。

## 如何做...

要完成这个配方，请按照给定的步骤进行操作：

1.  在应用程序的根目录中，将以下行添加到`composer.json`文件中：

```php
  "require-dev": {
  "phpunit/phpunit": "3.7.*"
  },
```

1.  打开命令行窗口，导航到根目录，并使用以下行在 Composer 工具上运行更新：

```php
 **php composer update**

```

1.  安装后，在命令行窗口中使用以下命令快速测试：

```php
 **vendor/bin/phpunit**

```

## 它是如何工作的...

我们的`composer.json`文件告诉 Composer 工具应安装哪些软件包。因此，我们的第一个任务是将`phpunit`软件包添加为要求。保存该文件后，我们将运行`update`命令，`phpunit`将被添加到我们的`vendor`目录。

安装后，我们可以运行命令来测试`phpunit`，并确保它已正确安装。Laravel 在`app/tests`目录中附带了一个示例测试用例，并且应该通过所有测试。

# 编写和运行测试用例

对于这个配方，如果我们已经安装并正常工作的 PHPUnit，我们可以编写一个测试用例，并使用 PHPUnit 来检查它是否有效。

## 准备工作

要运行测试用例，我们需要一个正常安装的 Laravel。我们还需要从前面的配方*设置和配置 PHPUnit*中安装 PHPUnit。

## 如何做...

要完成这个配方，请按照给定的步骤进行操作：

1.  在`app/tests`目录中，创建一个名为`MyAppTest.php`的文件，并添加以下代码：

```php
  <?php
class MyAppTest extends TestCase {

  /**
   * Testing the MyApp route
   *
   * @return void
   */
  public function testMyAppRoute()
{
  $response = $this->call('GET', 'myapp');
  $this->assertResponseOk();
  $this->assertEquals('This is my app', $response >getContent());
}
}
```

1.  在命令行窗口中运行测试，我们应该在输入以下命令时得到失败的测试：

```php
 **vendor/bin/phpunit**

```

1.  在我们的`routes.php`文件中，添加以下代码的新路由：

```php
  Route::get('myapp', function()
{
  return 'This is my app';
});
```

1.  再次运行测试以获得通过的单元测试

```php
 **vendor/bin/phpunit**

```

## 它是如何工作的...

当我们运行 PHPUnit 测试时，Laravel 将自动查找`app/tests`目录。我们首先在该目录中创建一个新文件来保存名为`MyAppTest`的测试，并扩展`TestCase`。

对于这个简单的测试，我们使用`call`方法并在`myapp`路由上执行`GET`请求。我们首先检查的是我们收到了`Ok`或 200 状态代码，然后返回的内容是字符串`This is my app`。在这一点上，当我们运行测试时，它将失败，因为我们还没有创建路由。

接下来，我们创建我们的`myapp`路由并返回字符串`This is my app`。最后，我们重新运行测试，应该得到成功的结果。

## 另请参阅

+   *设置和配置 PHPUnit*配方

# 使用 Mockery 测试控制器

有时，我们需要测试使用我们的数据库的代码。通常接受的做法是在运行单元测试时不应实际在数据库上执行实时查询。为了解决这个问题，我们可以使用 Mockery 包来伪造我们的数据。

## 准备工作

对于这个配方，我们需要已安装和正常工作的 Laravel，以及来自*设置和配置 PHPUnit*配方的 PHPUnit。

## 如何做...

要完成这个配方，请按照给定的步骤进行操作：

1.  打开我们的`composer.json`文件，并确保包含以下代码：

```php
  "require-dev": 
{
  "phpunit/phpunit": "3.7.*",
  "mockery/mockery": "dev-master"
},
```

1.  打开命令行终端，并使用以下命令运行 Composer 更新：

```php
 **php composer.phar update**

```

1.  更新后，在`app/controllers`目录中，使用以下代码创建`ShipsController.php`文件：

```php
<?php

class ShipsController extends BaseController {

  protected $ships; 
  public function __construct(Spaceship $ships) 
{
  $this->ships = $ships;
}

  public function showShipName()
{
  $ship = $this->ships->first();
  return $ship->name;
}
}
```

1.  在`routes.php`文件中，使用以下命令添加一个路由到这个控制器：

```php
 **Route::get('ship', 'ShipsController@showShipName');**

```

1.  在`app/tests`目录中，使用以下代码创建一个名为`SpaceshipTest.php`的文件：

```php
<?php

class SpaceshipTest extends TestCase {

  public function testFirstShip ()
{
  $this->call('GET', 'ship');
  $this->assertResponseOk();
}
}
```

1.  回到命令行窗口，使用以下命令运行我们的测试：

```php
 **vendor/bin/phpunit**

```

1.  此时，我们将得到一个显示以下消息的失败测试：

```php
**ReflectionException: Class Spaceship does not exist**

```

1.  由于`Spaceship`类将是我们的模型，我们将使用 Mockery 来模拟它。使用以下代码更新`SpaceshipTest`类：

```php
<?php

class SpaceshipTest extends TestCase {

  public function testFirstShip()
{
  $ship = new stdClass();
  $ship->name = 'Enterprise';

  $mock = Mockery::mock('Spaceship');
  $mock->shouldReceive('first')->once()->andReturn($ship);

  $this->app->instance('Spaceship', $mock);
  $this->call('GET', 'ship');
  $this->assertResponseOk();
}

   public function tearDown()
{
  Mockery::close();
}
}
```

1.  现在，回到命令行窗口，再次运行测试，它应该通过。

## 工作原理...

我们首先通过 Composer 安装 Mockery 软件包。这将允许我们在整个应用程序中使用它。接下来，我们创建一个控制器，其中包含一个将显示单个飞船名称的方法。在控制器的构造函数中，我们传入要使用的模型，这种情况下将命名为`Spaceship`并使用 Laravel 的 Eloquent ORM。

在`showShipName`方法中，我们将从 ORM 中获取第一条记录，然后简单地返回记录的名称。然后，我们需要创建一个指向控制器和`showShipName`方法的路由。

当我们首次创建测试时，我们只是发出一个`GET`请求，看看它是否返回一个 OK 响应。此时，由于我们还没有创建`Spaceship`模型，当我们运行测试时会显示错误。我们可以向数据库添加所需的表并创建模型，测试将通过。但是，在测试控制器时，我们不想担心数据库，应该只测试控制器代码是否有效。为此，我们现在可以使用 Mockery。

当我们在`Spaceship`类上调用`first`方法时，它将给我们一个包含所有返回字段的对象，因此我们首先创建一个通用对象，并将其分配给`$ship`控制器。然后，我们为`Spaceship`类创建我们的`mock`对象，当我们的控制器请求`first`方法时，`mock`对象将返回我们之前创建的通用对象。

接下来，我们需要告诉 Laravel，每当请求`Spaceship`实例时，它应该使用我们的`mock`对象。最后，在我们的船舶路线上调用`GET`，确保它返回一个 OK 响应。

## 另请参阅

+   *设置和配置 PHPUnit*配方

# 使用 Codeception 编写验收测试

验收测试是测试应用程序是否向浏览器输出正确信息的有用方法。使用 Codeception 等软件包，我们可以自动化这些测试。

## 准备工作

对于这个配方，我们需要安装一个 Laravel 的工作副本。

## 如何做...

要完成此配方，请按照给定的步骤进行：

1.  打开`composer.json`文件，并将以下行添加到我们的`require-dev`部分：

```php
  "codeception/codeception": "dev-master",
```

1.  打开命令行窗口，并使用以下命令更新应用程序：

```php
 **php composer.phar update**

```

1.  安装完成后，我们需要在终端中运行`bootstrap`命令，如下所示：

```php
 **vendor/bin/codecept bootstrap app**

```

1.  在`app/tests/acceptance`目录中，使用以下代码创建一个名为`AviatorCept.php`的文件：

```php
<?php

$I = new WebGuy($scenario);
$I->wantTo('Make sure all the blueprints are shown');
$I->amOnPage('/');
$I->see('All The Blueprints');
```

1.  在我们的主`routes.php`文件中，使用以下代码更新默认路由：

```php
Route::get('/', function()
{
return 'Way of the future';
});
```

1.  打开命令行窗口，并使用以下命令运行验收测试：

```php
 **vendor/bin/codecept run –c app**

```

1.  此时，我们应该看到它失败了。为了使其通过，再次更新默认路由，输入以下代码：

```php
Route::get('/', function()
{
return 'All The Blueprints';
});
```

1.  在命令行窗口中，使用以下命令再次运行测试：

```php
 **vendor/bin/codecept run –c app**

```

1.  这次应该通过。

## 工作原理...

我们首先通过 Composer 安装 Codeception 软件包。一旦下载完成，我们运行`bootstrap`命令，它将创建所有所需的文件和目录。Codeception 会自动将文件和文件夹添加到`tests`目录中；因此，为了确保它们被添加到 Laravel 的测试目录中，我们在`bootstrap`命令的末尾添加`app`目录。

接下来，在`acceptance`目录中创建一个文件来保存我们的测试。我们首先创建一个新的`WebGuy`对象，这是 Codeceptions 类来运行验收测试。接下来的一行描述了我们想要做的事情，在这种情况下是查看所有的蓝图。下一行告诉测试我们需要在哪个页面，这将对应我们的路由。对于我们的目的，我们只是检查默认路由。最后，我们告诉测试我们想在页面上`看到`什么。我们在这里放的任何文本都应该显示在页面的某个地方。

我们对默认路由的第一次尝试将显示`Way of the future`；因此，当运行 Codeception 测试时，它将失败。要运行测试，我们使用`run`命令，并确保我们使用`-c`标志，并指定`app`作为测试路径，因为我们安装了引导文件在`app/tests`目录内。

然后，我们可以更新路由以显示文本`All The Blueprints`并重新运行测试。这次，它会通过。

## 还有更多...

Codeception 是一个非常强大的测试套件，有许多不同的选项。要完全了解它的所有功能，请访问[`codeception.com/`](http://codeception.com/)。

# 调试和配置您的应用

如果我们想知道我们的应用在幕后是如何工作的，我们需要对其进行配置。这个步骤将展示如何向我们的 Laravel 应用添加一个配置文件。

## 准备工作

对于这个步骤，我们需要一个配置正确的 Laravel 工作副本和一个 MySQL 数据库。

## 如何做...

要完成这个步骤，请按照以下步骤进行：

1.  打开命令行窗口，并使用`artisan`命令按照以下代码创建我们的迁移：

```php
 **php artisan migrate::make create_spaceships_table –create –table="spaceships"**

```

1.  在`app/database/migrations`文件夹中，打开以日期开头并以`create_spaceships_table.php`结尾的文件，将其用于我们的数据库表

```php
<?php

  use Illuminate\Database\Schema\Blueprint;
  use Illuminate\Database\Migrations\Migration;

class CreateSpaceshipsTable extends Migration {

  /**
  * Run the migrations.
  *
  * @return void
  */
public function up()
{
  Schema::create('spaceships', function(Blueprint $table)
{
  $table->increments('id');
  $table->string('name');
  $table->string('movie');
  $table->timestamps();
});
}

  /**
  * Reverse the migrations.
  *
  * @return void
  */
public function down()
{
  Schema::drop('spaceships');
}

}
```

1.  在`app/database/seeds`文件夹中，创建一个名为`SpaceshipSeeder.php`的文件，如下所示：

```php
<?php

class SpaceshipSeeder extends Seeder {

  /**
  * Run the database seeds.
  *
  * @return void
  */
  public function run()
{
  DB::table('spaceships')->delete();

  $ships = array(
  array(
  'name'   => 'Enterprise',
  'movie'  => 'Star Trek'
),
  array(
  'name'   => 'Millenium Falcon',
  'movie'  => 'Star Wars'
),
  array(
  'name'   => 'Serenity',
  'movie'  => 'Firefly'
),
);

  DB::table('spaceships')->insert($ships);
}
}
```

1.  在同一个目录中，打开`DatabaseSeeder.php`文件，并确保`run()`方法看起来像以下代码片段：

```php
public function run()
{
  Eloquent::unguard();
  $this->call('SpaceshipSeeder');
}
```

1.  回到命令行窗口，使用以下代码安装迁移并运行 seeder：

```php
 **php artisan migrate**
 **php artisan db:seed**

```

1.  在`app/models`目录中，创建一个名为`Spaceship.php`的文件，如下代码所示：

```php
<?php

class Spaceship extends Eloquent{

  protected $table = 'spaceships';
}
```

1.  在`app/controllers`目录中，创建一个名为`ShipsController.php`的文件

```php
<?php

class ShipsController extends BaseController {

  protected $ships; 

  public function __construct(Spaceship $ships) 
  {
  $this->ships = $ships;
}

  public function showShipName()
{
  $ships = $this->ships->all();
  Log::info('Ships loaded: ' . print_r($ships, TRUE));
  return View::make('ships')->with('ships', $ships);
}
}
```

1.  在`routes.php`文件中，注册路由如下命令所示：

```php
 **Route::get('ship', 'ShipsController@showShipName');**

```

1.  在`app/views`目录中，创建一个名为`ships.blade.php`的视图，如下代码所示：

```php
  @foreach ($ships as $s)
  {{ $s->name }} <hr>
  @endforeach
```

1.  此时，如果我们转到`http://{your-dev-url}/public/ship`，我们将看到船只列表。接下来，我们需要打开`composer.json`文件，并在`require-dev`部分中添加以下行：

```php
  "loic-sharma/profiler": "dev-master"
```

1.  然后在命令行窗口中，使用以下命令更新 Composer：

```php
 **php composer.phar update**

```

1.  在所有东西都下载完成后，在`app/config`文件夹中，打开`app.php`文件。在`providers`数组中，在代码的末尾添加以下行：

```php
  'Profiler\ProfilerServiceProvider',
```

1.  在同一个文件中，在`aliases`数组中，添加以下行：

```php
  'Profiler' => 'Profiler\Facades\Profiler',
```

1.  在这个文件的顶部，确保`debug`设置为 true，然后在浏览器中返回`http://{your-dev-url}/public/ship`。`profiler`将显示在浏览器窗口底部。

## 它是如何工作的...

我们的第一步是创建我们想要配置文件的页面。我们首先使用`artisan`命令创建一个`migrations`文件，然后添加 Schema 构建器代码来创建我们的 spaceships 表。完成后，我们可以使用 seeder 文件向表中添加一些信息。

完成后，我们现在可以运行迁移和 seeder，我们的表将被创建，并且所有信息已经被填充。

接下来，我们为我们的数据创建一个简单的模型和一个控制器。在控制器中，我们将简单地获取所有的船只，并将变量传递给我们的船只视图。我们还将在代码中间添加一个日志事件。这将允许我们以后调试代码，如果需要的话。

完成后，我们可以看到我们创建的船只列表。

然后，我们需要安装基于 Laravel 早期版本的性能分析器包。更新了我们的 Composer 文件后，我们注册性能分析器，这样我们的应用程序就知道它的存在；如果以后想要更多地使用它，我们还可以注册 Façade。

在我们的配置文件中，如果我们将`debug`设置为`TRUE`，那么性能分析器将在我们访问的每个页面上显示。我们可以通过简单地将`debug`设置为`FALSE`来禁用性能分析器。

## 还有更多...

我们还可以使用以下代码段中显示的 startTimer 和 endTimer 方法向我们的应用程序添加定时器：

```php
  Profiler::startTimer('myTime');
  {some code}
  Profiler::endTimer('myTime');
```


# 第十一章：将第三方服务部署和集成到您的应用程序中

在本章中，我们将涵盖：

+   创建队列并使用 Artisan 运行它

+   将 Laravel 应用程序部署到 Pagoda Box

+   在 Laravel 中使用 Stripe 支付网关

+   进行 GeoIP 查找并设置自定义路由

+   收集电子邮件地址并与第三方电子邮件服务一起使用

+   从 Amazon S3 存储和检索云内容

# 介绍

Web 应用程序通常会依赖第三方服务来帮助我们的应用程序运行。使用 Composer 和 Laravel，我们可以集成现有的代码，以便与这些服务进行交互。在本章中，我们将看到如何将我们的应用程序部署到 Pagoda Box，使用 Stripe 支付，进行 GeoIP 查找，使用第三方电子邮件服务，并将内容存储到云中。

# 创建队列并使用 Artisan 运行它

有时我们的应用程序需要在后台执行大量工作来完成任务。我们可以将它们添加到队列中，并稍后进行处理，而不是让用户等待任务完成。有许多队列系统可用，但 Laravel 有一些非常容易实现的。在本示例中，我们将使用 IronMQ。

## 准备工作

对于此示例，我们将需要一个安装良好的 Laravel 4，以及 IronMQ 的 API 凭据。可以在[`www.iron.io/`](http://www.iron.io/)创建免费帐户。

## 如何做...

要完成此示例，请按照给定的步骤进行操作：

1.  在`app/config`目录中，打开`queue.php`文件，将默认值设置为`iron`，并填写来自 IronMQ 的凭据。

1.  打开 Laravel 的`composer.json`文件并更新所需部分，使其类似于以下代码片段：

```php
"require": {
"laravel/framework": "4.0.*",
"iron-io/iron_mq": "dev-master"
}
```

1.  在命令行窗口中，使用以下命令更新 composer 文件：

```php
**php composer.phar update**

```

1.  安装完成后，打开`routes.php`文件并创建一个命中队列的路由：

```php
Route::get('queueships', function() {
$ships = array(
  array(
    'name' => 'Galactica',
    'show' => 'Battlestar Galactica'),
    array(
    'name' => 'Millennium Falcon',
    'show' => 'Star Wars'),
    array(
    'name' => 'USS Prometheus',
    'show' => 'Stargate SG-1')
);
$queue = Queue::push('Spaceship', array('ships' => 
$ships));
  return 'Ships are queued.';
});
```

1.  在`app/models`目录中创建一个名为`Spaceship.php`的文件，如下面的代码所示：

```php
<?php

class Spaceship extends Eloquent{

  protected $table = 'spaceships';

  public function fire($job, $data)
{
// Could be added to database here!
  Log::info('We can put this in the database: ' . print_r($data, TRUE));
  $job->delete();
}
}
```

1.  在浏览器中，转到`http://{your-url}}/public/queueships`，然后刷新几次。

1.  在 IronMQ 窗口中检查是否添加了新消息。

1.  打开命令行窗口并运行以下命令：

```php
 **php artisan queue:listen**

```

1.  几分钟后，查看`app/storage/logs`文件夹，并找到带有今天日期的文件。它将打印出我们添加到队列中的数组。

## 它是如何工作的...

首先，我们要确保在`config`文件中将 IronMQ 作为我们的默认队列驱动程序。如果我们想要使用另一个队列系统，可以在这里设置。然后，我们使用 composer 将 IronMQ 包安装到我们的应用程序中。这将添加我们需要的所有文件，以及 Iron 需要工作的任何依赖项。

此时，Laravel 已经设置好了使用我们选择的任何队列系统，因此我们可以开始使用它。我们首先在我们的路由中创建一个数据数组。这可以很容易地成为表单输入，因此我们希望等待处理的其他一些数据。然后，我们使用`Queue::push()`方法，设置应该使用的类（`Spaceship`），然后传递数据到该类。

如果我们现在转到这个路由，然后检查 IronMQ 队列，我们会看到有一个作业正在等待处理。我们的下一个任务是创建一个类来处理队列。为此，我们创建一个名为`Spaceship`的模型。我们需要创建一个`fire()`方法来解析我们从队列中获取的数据。在这里，我们可以将信息保存到数据库或进行其他一些繁重的处理。现在，我们只是将数据发送到日志文件。在`fire()`方法的末尾，我们确保删除作业。

如果我们转到我们的`queueships`路由并刷新几次，我们会看到我们的队列中有多个作业，但我们还没有处理它们。因此，在命令行中，我们运行 artisan 的`queue:listen`命令，这将开始处理我们的队列。很快，我们可以进入我们的日志目录，看到从队列中发送的信息。

## 还有更多...

我们可能需要队列的原因有很多。最常见的是处理图像或进行大量数据解析等。将我们想要从网站发送的任何电子邮件排队也很有用，而 Laravel 有一种特殊的方法可以使用`Mail::queue()`命令来实现。

# 将 Laravel 应用程序部署到 Pagoda Box

Pagoda Box 是一个流行的云托管服务，可以很容易地创建 Web 应用程序。有了 Laravel 的预制框，我们可以在云中创建自己的网站。

## 准备工作

为了完成此操作，我们需要在 Pagoda Box 拥有一个免费帐户，可以在[`dashboard.pagodabox.com/account/register`](https://dashboard.pagodabox.com/account/register)上获得。注册后，我们还需要在我们的帐户中添加一个 SSH 密钥。有关 SSH 密钥的更多信息，请访问[`help.pagodabox.com/customer/portal/articles/202068`](http://help.pagodabox.com/customer/portal/articles/202068)。

## 如何做...

要完成此操作，请按照给定的步骤进行：

1.  登录 Pagodabox 后，点击**新应用程序**选项卡，如下面的屏幕截图所示：![如何做...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/lrv-app-dev-cb/img/2827OS_11_01.jpg)

1.  确保选择**Quickstart**，然后向下滚动找到 laravel-4 quickstart。然后点击**免费**按钮，如下面的屏幕截图所示：![如何做...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/lrv-app-dev-cb/img/2827OS_11_02.jpg)

1.  在下一页中，点击**启动**按钮，如下面的屏幕截图所示：![如何做...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/lrv-app-dev-cb/img/2827OS_11_03.jpg)

1.  等待几分钟，直到所有内容都安装完成。![如何做...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/lrv-app-dev-cb/img/2827OS_11_04.jpg)

1.  完成后，点击蓝色的**管理您的应用**按钮，如下面的屏幕截图所示：![如何做...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/lrv-app-dev-cb/img/2827OS_11_05.jpg)

1.  复制 git clone URL，如下面的屏幕截图所示：![如何做...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/lrv-app-dev-cb/img/2827OS_11_06.jpg)

1.  在命令行窗口中，转到服务器的根目录并运行 git clone 命令。在我们的情况下，它将是：

```php
**git clone git@git.pagodabox.com:erratic-eladia.git pagodaapp**

```

1.  下载所有内容后，打开`app/routes.php`文件并添加一个路由，以便我们可以根据以下代码进行测试：

```php
Route::get('cool', function()
{
  return 'Pagoda Box is awesome!';
});
```

1.  在命令行窗口中，提交以下更改并将其发送回 Pagoda Box

```php
 **git commit –am 'Added route'**
 **git push origin master**

```

1.  Pagoda Box 完成更改后，转到新路由查看是否有效。在我们的情况下，它将是[`erratic-eladia.gopagoda.com/cool`](http://erratic-eladia.gopagoda.com/cool)。

## 工作原理...

如果我们想要托管我们的应用程序并确保它是可扩展的，我们可能需要考虑使用云托管服务。这将使我们能够在出现大量流量时提高其性能，并在流量减少时降低性能。一个与 PHP 和 Laravel 兼容的优秀主机是 Pagoda Box。Pagoda Box 还有一个非常好的免费选项，可以让我们测试并创建一个完整的应用程序而无需付费。

首先，在 Pagoda Box 仪表板中，我们创建一个新应用程序并选择我们想要使用的 Quickstart 包。列表中有一个方便的 Laravel 4 安装；如果我们选择它，所有依赖项都将被安装。

设置完成后，我们可以复制 git clone 代码并将文件下载到本地服务器。下载后，我们可以进行任何更新并提交。将其推送回 Pagoda Box 后，我们的更新代码将自动部署，并且我们将在实时站点上看到更改。

## 还有更多...

还有其他与 Laravel 兼容的云托管提供商。它们通常都有免费选项，因此我们可以尝试它们。其他一些主机如下：

+   Engine Yard [`www.engineyard.com/`](https://www.engineyard.com/)

+   Digital Ocean [`www.digitalocean.com/`](https://www.digitalocean.com/)

+   Heroku（有隐藏的 PHP 支持）[`www.heroku.com/`](https://www.heroku.com/)

# 使用 Stripe 支付网关与 Laravel

电子商务网站是网站开发中的一个持续的重点。过去，诸如信用卡处理之类的事情一直很困难，学习曲线非常陡峭。使用 Laravel 和 Stripe 服务，提供信用卡交易变得更容易。

## 准备工作

对于这个食谱，我们需要一个正常安装的 Laravel 4 和 Stripe 的正确凭据。可以在[`stripe.com/`](https://stripe.com/)创建一个免费的 Stripe 账户。

## 如何做...

要完成这个食谱，请按照以下步骤进行：

1.  打开应用的`composer.json`文件，并更新`require`部分以类似以下代码片段的方式进行更新：

```php
"require": {
  "laravel/framework": "4.0.*",
  "stripe/stripe-php": "dev-master"
},
```

1.  在命令行窗口中，使用以下命令运行 composer update：

```php
 **php composer.phar update**

```

1.  在`app/config`目录中，创建一个名为`stripe.php`的新文件，使用以下代码：

```php
<?php

return array(
  'key' => 'fakeKey-qWerTyuuIo4f5'
);
```

1.  在`routes.php`文件中，添加一个`Route`到付款表单，如下所示的代码：

```php
Route::get('pay', function()
{
  return View::make('pay');
});
```

1.  在`app/views`文件夹中，使用以下代码片段创建一个名为`pay.blade.php`的文件，用于我们的表单：

```php
{{ Form::open(array('url' => 'pay', 'method' => 'post')) }}
  Card Number: {{ Form::text('cc_number', 
    '4242424242424242') }}<br>

  Expiration (month):
    {{ Form::select('cc_exp_month', array(1 => '01', 2 => 
    '02', 3 => '03', 4 => '04', 5 => '05',6 => '06', 7 => 
    '07', 8 => '08', 9 => '09', 10 => '10', 11 
    => '11', 12 => '12')) }}<br>

  Expiration (year):
    {{ Form::select('cc_exp_year', array(2013 => 2013,
    2014 => 2014, 2015 => 2015, 2016 => 2016)) }}<br>

  {{ Form::submit('Charge $37 to my card') }}
  {{ Form::close() }}
```

1.  回到`routes.php`，创建一个`Route`来接受表单提交，并按照以下代码对卡进行收费：

```php
Route::post('pay', function()
{
  Stripe::setApiKey(Config::get('stripe.key'));
  $chargeCard = array(
    'number' => Input::get('cc_number'),
    'exp_month' => Input::get('cc_exp_month'),
    'exp_year'  => Input::get('cc_exp_year')
);
  $charge = Stripe_Charge::create(array('card' => 
    $chargeCard, 'amount' => 3700, 'currency' => 'usd'));

// Save returned info here
  var_dump($charge);
});
```

## 工作原理...

我们首先将 Stripe 包添加到我们的 composer 文件中并进行更新。这将安装 Stripe 代码，以及如果需要的话任何依赖项。然后我们需要创建一个配置文件来保存我们的 API 密钥。在这里，我们可以创建另一个与我们的环境变量相同的目录，并将文件添加到那里。因此，如果我们有一个开发和一个生产服务器，我们可以在`app/config/development`目录中有一个 Stripe `config`文件，其中保存我们的测试 API 密钥，然后在`app/config/production`目录中有一个文件来保存我们的生产 API 密钥。

接下来，我们需要一个表单，让用户输入他们的信用卡信息。我们创建一个`pay`路由来显示我们的`pay`视图。在该视图中，我们将使用 Blade 模板来创建表单。Stripe 所需的最少信息是卡号和到期日，尽管有时我们可能需要获取卡的 CVV 码或用户的地址。

在表单提交后，我们使用 API 密钥创建一个 Stripe 实例。然后我们将信用卡信息添加到一个数组中。最后，我们将金额（以美分为单位）、卡数组和货币发送到 Stripe 进行处理。

然后可以将从 Stripe 返回的数据添加到数据库中，或者进行其他跟踪。

## 还有更多...

Stripe 提供了许多易于使用的方法来管理信用卡交易，甚至订阅等事项。有关更多信息，请务必查看[`stripe.com/docs`](https://stripe.com/docs)上提供的文档。

# 进行 GeoIP 查找和设置自定义路由

也许我们的应用程序在某些时候需要根据用户所在的国家/地区提供不同的页面。使用 Laravel 和 MaxMind 的 GeoIP 数据，我们可以根据用户的 IP 地址查找其所在的国家/地区，然后将其重定向到我们需要的页面。

## 准备工作

对于这个食谱，我们只需要一个正常的 Laravel 4 安装。

## 如何做...

要完成这个食谱，请按照以下步骤进行：

1.  打开`composer.json`文件并更新`require`部分，使其看起来像以下代码片段：

```php
"require": {
  "laravel/framework": "4.0.*",
  "geoip/geoip": "dev-master"
},
```

1.  在命令行窗口中，使用以下命令运行 composer update：

```php
 **php composer.phar update**

```

1.  转到[`dev.maxmind.com/geoip/legacy/geolite/`](http://dev.maxmind.com/geoip/legacy/geolite/)并下载最新的**GeoLite Country**数据库。解压缩并将`GeoIP.dat`文件放在我们应用的根目录中。

1.  在`app/config`目录中，创建一个名为`geoip.php`的文件，使用以下代码：

```php
<?php

return array(
  'path' => realpath("path/to/GeoIP.dat")
);
```

1.  打开`app/filters.php`文件，并添加一个用于我们的`geoip`文件的过滤器，使用以下代码：

```php
  Route::filter('geoip', function($route, $request, $value = NULL)
{
  $ip = is_null($value) ? Request::getClientIp() : $value;
  $gi = geoip_open(Config::get('geoip.path'), GEOIP_STANDARD);
  $code = geoip_country_code_by_addr($gi, $ip);
  return Redirect::to('geo/' . strtolower($code));
});
```

1.  在我们的`routes.php`文件中，创建一个路由来应用过滤器，并创建一个接受国家代码的路由，如下所示的代码：

```php
Route::get('geo', array('before' => 'geoip:80.24.24.24', function()
{
return '';
}));
Route::get('geo/{country_code}', function($country_code)
{
return 'Welcome! Your country code is: ' . $country_code;
});
```

## 工作原理...

我们首先通过将其添加到我们的`composer.json`文件并进行更新来安装`geoip`库。一旦下载完成，我们就可以下载 MaxMind 的免费`geoip`数据文件并将其添加到我们的应用程序中。在我们的情况下，我们将文件放在我们的应用程序的根目录中。然后，我们需要创建一个`config`文件，用于保存`geoip`数据文件的位置。

接下来，我们想要检查用户的 IP 地址并将他们重定向到特定国家的页面。为此，我们将使用 Laravel 的 before 过滤器。它从设置`$ip`变量开始。如果我们手动传递一个 IP 地址，那就是它将使用的；否则，我们运行`Request::getClientIp()`方法来尝试确定它。一旦我们有了 IP 地址，我们就通过`geoip`函数运行它来获取 IP 地址的国家代码。然后我们将用户重定向到带有国家代码作为参数的路由。

然后我们创建一个路由来添加过滤器。在我们的情况下，我们将手动传递一个 IP 地址给过滤器，但如果没有，它将尝试使用用户的地址。我们的下一个路由将以国家代码作为参数。在这一点上，我们可以根据国家提供自定义内容，甚至自动设置要使用的语言文件。

# 收集电子邮件地址并与第三方电子邮件服务一起使用

电子邮件列表和通讯简报仍然是与大量人群沟通的一种流行和高效的方式。在这个步骤中，我们将使用 Laravel 和免费的 MailChimp 服务来建立一个收集电子邮件订阅的简单方式。

## 准备工作

对于这个步骤，我们将需要一个可用的 Laravel 4 安装，以及在 Mailchimp 帐户部分生成的[`mailchimp.com/`](http://mailchimp.com/)免费帐户和 API 密钥。我们还需要在 Mailchimp 中创建至少一个列表。

## 如何做...

要完成这个步骤，请按照以下步骤操作：

1.  在`app`目录中，创建一个名为`libraries`的新目录。

1.  从[`apidocs.mailchimp.com/api/downloads/#php`](http://apidocs.mailchimp.com/api/downloads/#php)下载 Mailchimp 的 API 库，然后解压缩并将文件`MCAPI.class.php`放入新的`libraries`文件夹中。

1.  打开 Laravel 的`composer.json`文件，并将 libraries 目录添加到`autoload`部分。该部分应该类似于以下代码片段：

```php
"autoload": {
    "classmap": [
    "app/commands",
    "app/controllers",
    "app/models",
    "app/database/migrations",
    "app/database/seeds",
    "app/tests/TestCase.php",
    "app/libraries"
]
},

```

1.  打开命令行窗口，并运行 composer 的`dump-autoload`命令，如下所示：

```php
 **php composer.phar dump-autoload**

```

1.  在`app/config`目录中，创建一个名为`mailchimp.php`的文件，并使用以下代码：

```php
<?php

return array(
  'key' => 'mykey12345abcde-us1',
  'list' => 'q1w2e3r4t5'
);
```

1.  要获取我们的 Mailchimp 列表，并查看它们的 ID，请打开`routes.php`文件并添加一个新的路由，如下所示：

```php
Route::get('lists', function()
{
  $mc = new MCAPI(Config::get('mailchimp.key'));
  $lists = $mc->lists();

  if($mc->errorCode) {
    echo 'Error loading list: ' . $mc->errorMessage;
  } else {
    echo '<h1>Lists and IDs</h1><h3>Total lists: '
    $lists['total'] . '</h3>';
  foreach($lists['data'] as $list) {
   echo '<strong>' . $list['name'] . ':</strong> ' .
   $list['id'] . '<br>';
}
}
});

```

1.  在`routes.php`文件中，使用以下代码创建一个路由来显示`subscribe`表单：

```php
Route::get('subscribe', function()
{
  return View::make('subscribe');
});
```

1.  在`app/views`目录中，创建一个名为`subscribe.blade.php`的文件，如下所示：

```php
  {{ Form::open() }}
  First Name: {{ Form::text('fname') }} <br>
  Last Name: {{ Form::text('lname') }} <br>
  Email: {{ Form::text('email') }} <br>
  {{ Form::submit() }}
  {{ Form::close() }}
```

1.  在`routes.php`文件中，创建一个路由来接受和处理表单提交，如下所示：

```php
Route::post('subscribe', function()
{
  $mc = new MCAPI(Config::get('mailchimp.key'));

  $merge_vars = array('FNAME' => Input::get('fname'), 'LNAME' => Input::get('lname'));
  $ret = $mc->listSubscribe(Config::get('mailchimp.list'), Input::get('email'), $merge_vars);

if ($mc->errorCode){
  return 'There was an error: ' . $mc->errorMessage;
} else {
  return 'Thank you for your subscription!';
}
});
```

## 它是如何工作的...

要开始这个步骤，我们需要添加 Mailchimp 的 PHP 库。由于我们不会使用 composer，我们需要设置一个目录来保存我们的非 composer 库。因此，我们在`app`文件夹中创建一个`libraries`目录，并在其中添加 Mailchimp。

为了让 Laravel 知道我们想要在新目录中`autoload`任何内容，我们需要更新`composer.json`文件。然后我们将目录位置添加到`Classmap`部分。然后我们需要运行 composer 的`dump-autoload`命令来重新创建我们的`autload`文件，并将其添加到我们的新目录中。

然后我们需要创建一个新的`config`文件来保存我们的 Mailchimp 凭据和我们想要使用的列表的 ID。我们可以从 Mailchimp 仪表板获取`list` ID，或者我们可以使用`lists`路由来显示它们。

为了捕获用户的电子邮件，我们创建一个路由和视图来保存我们的表单。这个表单也可以是一个弹出窗口、模态框或更大页面的一部分。我们要求他们的姓名和电子邮件，然后将其发布到 Mailchimp。

在我们的`post`路由中，我们只需要实例化 Mailchimp 类，创建一个数组来保存名称，并将所有内容发送到`listSubscribe()`方法。最后，我们检查来自 Mailchimp 的任何错误并显示成功消息。

## 还有更多...

Mailchimp 提供了一个非常广泛的 API，允许我们轻松管理我们的电子邮件列表。要查看他们提供的所有内容，请查看在线文档：[`apidocs.mailchimp.com/`](http://apidocs.mailchimp.com/)

# 从亚马逊 S3 存储和检索云内容

使用像亚马逊的 S3 这样的服务来存储我们的文件将使我们能够利用他们服务器的速度和可靠性。要使用该服务，我们可以轻松地实现一个 Laravel 包来处理我们上传到亚马逊的文件。

## 准备工作

对于这个食谱，我们需要一个可用的 Laravel 4 安装。我们还需要一个免费的亚马逊 AWS 账户，可以在以下网址注册：[`aws.amazon.com/s3/`](http://aws.amazon.com/s3/)

注册后，我们需要从“安全凭据”页面获取我们的**访问密钥 ID**和**秘密 ID**。此外，在 S3 管理控制台中，我们需要至少创建一个存储桶。对于这个食谱，我们将把存储桶命名为`laravelcookbook`。

## 如何做…

完成这个食谱，按照给定的步骤进行：

1.  打开 Laravel 的`composer.json`文件并添加亚马逊 SDK 包。要求部分应该类似于以下片段：

```php
"require": {
  "laravel/framework": "4.0.*",
  "aws/aws-sdk-php-laravel": "dev-master"
},
```

1.  打开命令行窗口，并使用 Composer 包安装包，如下所示：

```php
 **php composer.phar update**

```

1.  安装完成后，在`app/config`目录中，创建一个名为`aws.php`的文件，如下所示：

```php
<?php

return array(
  'key'    => 'MYKEY12345',
  'secret' => 'aLongS3cretK3y1234abcdef',
  'region' => '',
);
```

1.  在`app/config`目录中，打开`app.php`文件。在`providers`数组的末尾，按照以下代码添加 AWS 提供程序：

```php
  'Aws\Laravel\AwsServiceProvider',
```

1.  还在`app.php`文件中，在别名数组中，添加以下别名：

```php
  'AWS' => 'Aws\Laravel\AwsFacade',
```

1.  在我们的`routes.php`文件中，通过创建一个列出我们的`buckets`的路由来测试一切是否正常，如下所示：

```php
Route::get('buckets', function()
{
  $list = AWS::get('s3')->listBuckets();
    foreach ($list['Buckets'] as $bucket) {
    echo $bucket['Name'] . '<br>';
}
});

```

1.  要测试存储桶，请转到`http://{your-server}/buckets`，它应该显示我们设置的所有存储桶的列表。

1.  现在让我们创建一个用户上传图像的表单。我们首先创建一个包含表单的路由，如下所示：

```php
Route::get('cloud', function()
{
  return View::make('cloud');
});
```

1.  在`app/views`文件夹中，创建一个名为`cloud.blade.php`的文件，其中包含以下代码：

```php
  {{ Form::open(array('files' => true)) }}
  Image: {{ Form::file('my_image') }} <br>
  {{ Form::submit() }}
  {{ Form::close() }}
```

1.  回到`routes.php`文件，在下面的代码中创建一个路由来处理文件并将其上传到 S3：

```php
Route::post('cloud', function()
{
  $my_image = Input::file('my_image');
  $s3_name = date('Ymdhis') . '-' . $my_image
    >getClientOriginalName();
  $path = $my_image->getRealPath();

  $s3 = AWS::get('s3');
  $obj = array(
    'Bucket'     => 'laravelcookbook',
    'Key'        => $s3_name,
    'SourceFile' => $path,
    'ACL'        => 'public-read',
);

  if ($s3->putObject($obj)) {
  return
    Redirect::to('https://s3.amazonaws.com/laravelcookbook/
    ' . $s3_name);
} else {
  return 'There was an S3 error';
}
});

```

## 它是如何工作的…

我们首先通过安装亚马逊的 AWS SDK 来开始这个食谱。幸运的是，亚马逊发布了一个专门为 Laravel 4 设计的 composer 包，所以我们只需将其添加到我们的`composer.json`文件中并进行更新。

安装完成后，我们需要创建一个配置文件并添加我们的亚马逊凭据。我们还可以添加`region`（例如`Aws\Common\Enum\Region::US_WEST_2`），但是，如果我们将其留空，它将使用`US Standard`区域。然后我们更新我们的`app.php`配置，包括亚马逊提供的 AWS `ServiceProvider`和`Facade`。

如果我们已经在 S3 中有存储桶，我们可以创建一个路由来列出这些存储桶。它通过创建一个新的 S3 实例并简单调用`listBuckets()`方法开始。然后我们循环遍历`Buckets`数组并显示它们的名称。

我们的下一个目标是创建一个表单，用户可以在其中添加图像。我们创建一个名为`cloud`的路由，显示`cloud`视图。我们的视图是一个简单的 Blade 模板表单，只有一个`file`字段。然后该表单将被提交到`cloud`。

在我们的`cloud` post 路由中，我们首先使用`Input::file()`方法检索图像。接下来，我们通过在文件名的开头添加日期来为我们的图像创建一个新名称。然后我们获取上传图像的路径，这样我们就知道要发送到 S3 的文件是哪个。

接下来，我们创建一个 S3 实例。我们还需要一个数组来保存要发送到 S3 的值。`Bucket`只是我们想要使用的 S3 存储桶的名称，`Key`是我们想要给文件的名称，`SourceFile`是我们想要发送的文件的位置，然后`ACL`是我们想要给文件的权限。在我们的情况下，我们将`ACL`设置为`public-read`，这允许任何人查看图像。

我们的最后一步是调用`putObject()`方法，这应该将所有内容发送到我们的 S3 存储桶。如果成功，我们将重定向用户查看已上传的文件。

## 还有更多...

在我们的示例中，用户被迫等待图像上传到亚马逊之前才能继续。这将是一个使用队列处理一切的绝佳案例。

## 参见

+   *创建队列并使用 Artisan 运行它*的配方
