# CouchDB 和 PHP Web 开发初学者指南（二）

> 原文：[`zh.annas-archive.org/md5/175c6f9b2383dfb7631db24032548544`](https://zh.annas-archive.org/md5/175c6f9b2383dfb7631db24032548544)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第五章：将您的应用程序连接到 CouchDB

> 现在我们已经建立了应用程序的框架，让我们谈谈我们的应用程序需要与 CouchDB 通信的情况。

在本章中，我们将讨论以下几点：

+   调查与 CouchDB 交互的快速简便方法，并讨论其缺点

+   查看现有库以便于 PHP 和 CouchDB 开发

+   安装 Sag 并将其集成到 Bones 中

+   让我们的注册表单创建 CouchDB 文档，并在 Futon 中进行验证

# 在我们开始之前

在我们做任何事情之前，让我们创建一个数据库，从此时起我们将在 Verge 中使用。与以前一样，让我们使用`curl`创建一个数据库。

# 行动时间-使用 curl 为 Verge 创建数据库

我们在第三章中使用`curl`创建了一个数据库，*与 CouchDB 和 Futon 入门*。让我们快速回顾如何使用`PUT`请求在 CouchDB 中创建一个新数据库。

1.  通过在**终端**中运行以下命令来创建一个新的数据库。确保用第三章中创建的数据库管理员用户替换`username`和`password`。

```php
**curl -X PUT username:password@localhost:5984/verge** 

```

1.  **终端**将以以下输出做出响应：

```php
**{"ok":true}** 

```

## 刚刚发生了什么？

我们使用**终端**通过`curl`触发了一个`PUT`请求，使用 CouchDB 的**RESTful JSON API**创建了一个数据库。我们在 CouchDB 的根 URL 末尾传递`verge`作为数据库的名称。成功创建数据库后，我们收到了一条消息，说明一切都很顺利。

# 头顶冲入

在本节中，我们将创建一些快速脏代码来与 CouchDB 通信，然后讨论这种方法的一些问题。

## 向我们的注册脚本添加逻辑

在上一章中，我们在`views/signup.php`中创建了一个表单，具有以下功能：

+   我们要求用户在文本框中输入名称的值

+   我们获取了表单中输入的值并将其发布到注册路由

+   我们使用 Bones 来获取表单传递的值，并将其设置为名为`message`的变量，以便我们可以在主页上显示它

+   我们呈现了主页并显示了`message`变量

这是我们的一项重大工作，但我们无法保存任何东西以供以后阅读或写入。

让我们进一步采取一些步骤，并要求用户输入姓名和电子邮件地址，然后将这些字段保存为 CouchDB 中的文档。

# 行动时间-向注册表单添加电子邮件字段

让我们添加一个输入字段，以便用户可以在`views/signup.php`页面中输入电子邮件地址。

1.  在文本编辑器中打开`signup.php`（`/Library/Webserver/Documents/verge/views/signup.php`）

1.  添加突出显示的代码以为电子邮件地址添加标签和输入字段：

```php
Signup
<form action="<?php echo $this->make_route('signup') ?>" method="post">
<label for="name">Name</label>
<input id="name" name="name" type="text"> <br />
**<label for="email">Email</label>
<input id="email" name="email" type="text"> <br />** 
<input type="Submit" value="Submit">
</form>

```

## 刚刚发生了什么？

我们向注册表单添加了一个额外的字段，用于接受电子邮件地址的输入。通过向此表单添加`email`字段，我们将能够在表单提交时访问它，并最终将其保存为 CouchDB 文档。

### 使用 curl 调用将数据发布到 CouchDB

在以前的章节中，我们已经使用了**终端**通过`curl`与 CouchDB 进行交互。您会高兴地知道，您还可以通过 PHP 使用`curl`。为了在 CouchDB 中表示数据，我们首先需要将我们的数据转换为 JSON 格式。

# 行动时间-创建一个标准对象以编码为 JSON

让我们以 JSON 的形式表示一个简单的对象，以便 CouchDB 可以解释它。

在文本编辑器中打开`index.php`，并将以下代码添加到`/signup POST`路由中：

```php
post('/signup', function($app) {
**$user = new stdClass;
$user->type = 'user';
$user->name = $app->form('name');
$user->email = $app->form('email');
echo json_encode($user);** 
$app->set('message', 'Thanks for Signing Up ' . $app->form('name') . '!');
$app->render('home');
});

```

## 刚刚发生了什么？

我们添加了创建存储用户具体信息的对象的代码。我们使用了`stdClass`的一个实例，并将其命名为`$user`。`stdClass`是 PHP 的通用空类，对于匿名对象、动态属性和快速上手非常有用。因为文档要求应该设置一个类型来分类文档，我们将这个文档的类型设置为`user`。然后我们取自表单提交的值，并将它们保存为`$user`类的属性。最后，我们使用了一个名为`json_encode`的 PHP 函数，将对象转换为 JSON 表示形式。

让我们来测试一下。

1.  在浏览器中打开`http://localhost/verge/signup`。

1.  在**名称**文本框中输入`John Doe`，在**电子邮件**文本框中输入`<john@example.com>`。

1.  点击**提交**。

1.  您的浏览器将显示以下内容：![刚刚发生了什么？](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/couchdb-php-webdev-bgd/img/3586_05_005.jpg)

太好了！我们的表单已经正确提交了，并且我们能够在我们网站的顶部用 JSON 表示`stdClass $user`。

### 提交到 Git

让我们将我们的代码提交到 Git，这样我们以后可以回顾这段代码。

1.  打开**终端**。

1.  输入以下命令以更改目录到我们的工作目录：

```php
**cd /Library/Webserver/Documents/verge/** 

```

1.  给 Git 一个描述，说明我们自上次提交以来做了什么：

```php
**git commit am 'Added functionality to collect name and email through stdClass and display it onscreen.'** 

```

现在我们已经用 JSON 表示了我们的数据，让我们使用一个`curl`语句来使用 PHP 创建一个 CouchDB 文档。

# 接下来的步骤——使用 PHP 和 curl 创建 CouchDB 文档

自本书开始以来，我们一直在使用命令行通过`curl`，但这次，我们将使用 PHP 触发一个`curl`语句。

1.  让我们从初始化一个`curl`会话开始，执行它，然后关闭它。在文本编辑器中打开`index.php`，并将以下代码添加到`/signup POST`路由中：

```php
post('/signup', function($app) {
$user = new stdClass;
$user->type = 'user';
$user->name = $app->form('name');
$user->email = $app->form('email');
echo json_encode($user);
**$curl = curl_init();
// curl options
curl_exec($curl);
curl_close($curl);** 
$app->set('message', 'Thanks for Signing Up ' . $app- >form('name') . '!');
$app->render('home');
});

```

1.  现在，让我们告诉`curl`实际要执行什么。我们使用一个`options`数组来做到这一点。在`curl_init()`和`curl_exec`语句之间添加以下代码：

```php
post('/signup', function($app) {
$user = new stdClass;
$user->name = $app->form('name');
$user->email = $app->form('email');
echo json_encode($user);
$curl = curl_init();
// curl options
**$options = array(
CURLOPT_URL => 'localhost:5984/verge',
CURLOPT_POSTFIELDS => json_encode($user),
CURLOPT_HTTPHEADER => array ("Content-Type: application/json"),
CURLOPT_CUSTOMREQUEST => 'POST',
CURLOPT_RETURNTRANSFER => true,
CURLOPT_ENCODING => "utf-8",
CURLOPT_HEADER => false,
CURLOPT_FOLLOWLOCATION => true,
CURLOPT_AUTOREFERER => true
);
curl_setopt_array($curl, $options);** 
curl_exec($curl);
curl_close($curl);
$app->set('message', 'Thanks for Signing Up ' . $app-> form('name') . '!');
$app->render('home');
});

```

## 刚刚发生了什么？

我们首先使用 PHP 初始化了一个`curl`会话，通过使用`curl_init()`资源设置了一个名为`$curl`的变量。然后我们创建了一个包含各种键和值的数组。我们选择所有这些选项的原因对我们现在来说并不太重要，但我想强调前三个对象：

1.  我们将`CURLOPT_URL`选项设置为我们要将文档保存到的数据库的 URL。请记住，此语句将使用 CouchDB 的 RESTful JSON API 在`verge`数据库中创建一个文档。

1.  然后我们将`CURLOPT_POSTFIELDS`设置为我们的`$user`的 JSON 编码值。这将把我们的 JSON 字符串作为数据与 URL 一起包含进去。

1.  最后，我们将`CURLOPT_HTTPHEADER`设置为`array ("Content-Type: application/json")`，以确保`curl`知道我们正在传递一个 JSON 请求。

设置了我们的选项数组之后，我们需要告诉我们的`curl`实例使用它：

```php
curl_setopt_array($curl, $options);

```

然后我们用以下两行代码执行并关闭`curl`：

```php
curl_exec($curl);
curl_close($curl);

```

有了这段代码，我们应该能够提交表单并将其发布到 CouchDB。让我们来测试一下。

1.  在浏览器中打开`http://localhost/verge/signup`。

1.  在**名称**文本框中输入`John Doe`，在**电子邮件**文本框中输入`<john@example.com>`。

1.  点击**提交**。

1.  您的浏览器将显示以下内容：![刚刚发生了什么？](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/couchdb-php-webdev-bgd/img/3586_05_005.jpg)

这次也没有出现任何错误，就像以前一样。但是这次应该已经创建了一个 CouchDB 文档。让我们通过 Futon 检查文档是否已经正确创建。

1.  在浏览器中打开`http://localhost:5984/_utils/database.html?verge`。这个直接链接将显示 verge 数据库。您会看到这里有一个新的文档！请记住，您的`ID`和`rev`将与我的不同：![刚刚发生了什么？](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/couchdb-php-webdev-bgd/img/3586_05_010.jpg)

1.  点击文档，以便您可以查看详细信息。

1.  您文档中的数据应该与我们在`curl`会话中传递的信息相匹配。请注意，`type, email`和`name`都已正确设置，CouchDB 为我们设置了`_id`和`_rev`。![刚刚发生了什么？](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/couchdb-php-webdev-bgd/img/3586_05_015.jpg)

### 将其提交到 Git

让我们将我们的代码提交到 Git，以便将来可以参考这段代码。

1.  打开**终端**。

1.  键入以下命令以更改目录到我们的工作目录：

```php
cd /Library/Webserver/Documents/verge/

```

1.  向 Git 描述我们自上次提交以来所做的工作：

```php
git commit am 'CouchDB Documents can now be created through the signup form using curl.'

```

我们刚刚看了使用 PHP 创建 CouchDB 文档的最简单的方法之一。然而，我们需要评估我们刚刚编写的代码是否可持续，并且是否是我们开发应用程序的明智方式。

## 这种技术足够好吗？

棘手的问题。从技术上讲，我们可以以这种方式构建我们的应用程序，但我们需要添加更多的代码，并花费本书的其余时间重构我们对`curl`的调用，直到它完美运行。然后，我们需要花大量时间将我们的调用重构为一个简单的库，以便更容易修复问题。简而言之，这种技术不起作用，因为我们想专注于构建我们的应用程序，而不是解决 PHP 和 CouchDB 之间的所有通信问题。幸运的是，有各种各样的 CouchDB 库可以简化我们的开发过程。

# 可用的 CouchDB 库

有各种库可以在使用 PHP 和 CouchDB 开发时使我们的生活更轻松。所有这些库都是开源项目，这很棒！但是，其中一些库已经不再积极开发以支持较新版本的 CouchDB。因此，我们需要选择要使用的库。

一些 PHP 和 CouchDB 库的列表可以在这里看到：[`wiki.apache.org/couchdb/Getting_started_with_PHP`](http://wiki.apache.org/couchdb/Getting_started_with_PHP)，还有一些其他的库托管在 GitHub 上，需要更深入挖掘。

每个库都有其优势，但由于简单是 Bones 的关键概念，因此在我们的 PHP 库中也应该追求简单。说到这一点，我们最好的解决方案就是**Sag**。

# Sag

Sag 是由 Sam Bisbee 创建的用于 CouchDB 的出色的 PHP 库。Sag 的指导原则是简单，创建一个功能强大的接口，几乎没有额外开销，可以轻松集成到任何应用程序结构中。它不强制您的应用程序使用框架、文档的特殊类或 ORM，但如果您愿意，仍然可以使用。Sag 接受基本的 PHP 数据结构（对象、字符串等），并返回原始 JSON 或响应和对象中的 HTTP 信息。

我将为您介绍 Sag 的安装和基本功能，但您也可以访问 Sag 的网站：[`www.saggingcouch.com/`](http://www.saggingcouch.com/)，了解示例和文档。

## 下载并设置 Sag

Sag 相当不显眼，将完全适应我们当前的应用程序结构。我们只需要使用 Git 从其 GitHub 存储库中获取 Sag，并将其放在我们的`lib`目录中。

# 采取行动——使用 Git 安装 Sag

Git 使设置第三方库变得非常容易，并允许我们在可用时更新到新版本。

1.  打开**终端**。

1.  键入以下命令以确保您在工作目录中：

```php
**cd /Library/Webserver/Documents/verge/** 

```

1.  使用 Git 将 Sag 添加到我们的存储库：

```php
**git submodule add git://github.com/sbisbee/sag.git lib/sag
git submodule init** 

```

## 刚刚发生了什么？

我们使用 Git 使用`git submodule add`将 Sag 添加到我们的项目中，然后通过键入`git submodule init`来初始化子模块。Git 的子模块允许我们在我们的存储库中拥有一个完整的 Git 存储库。每当 Sag 发布新版本时，您可以运行`git submodule update`，您将收到最新和最棒的代码。

### 将 Sag 添加到 Bones

为了使用 Sag，我们将在`Bones`中添加几行代码，以确保我们的库可以看到并利用它。

# 行动时间-将 Sag 添加到 Bones

启用并设置 Sag 与`Bones`一起工作非常容易。让我们一起来看看！

1.  打开我们的工作目录中的`lib/bones.php`，并在我们的类顶部添加以下行：

```php
<?php
define('ROOT', __DIR__ . '/..');
**require_once ROOT . '/lib/sag/src/Sag.php';** 

```

1.  我们需要确保 Sag 已准备好并在每个请求中可用。让我们通过在`Bones`中添加一个名为`$couch`的新变量，并在我们的`__construct`函数中设置它来实现这一点：

```php
public $route_segments = array();
public $route_variables = array();
**public $couch;** 
public function __construct() {
$this->route = $this->get_route();
$this->route_segments = explode('/', trim($this->route, '/'));
$this->method = $this->get_method();
**$this->couch = new Sag('127.0.0.1', '5984');
$this->couch->setDatabase('verge');** 
}

```

## 刚刚发生了什么？

我们确保`Bones`可以访问和使用 Sag，通过使用`require_once`加载 Sag 资源。然后，我们确保每次构造`Bones`时，我们都会定义数据库服务器和端口，并设置我们要使用的数据库。

### 注意

请注意，我们与`Verge`数据库交互时不需要任何凭据，因为我们尚未对此数据库设置任何权限。

## 使用 Sag 简化我们的代码

在我们的应用程序中包含 Sag 后，我们可以简化我们的数据库调用，将处理和异常处理交给 Sag，并专注于构建我们的产品。

# 行动时间-使用 Sag 创建文档

现在我们已经在应用程序中随处可用并准备好使用 Sag，让我们重构放置在`/signup post`路由中的用户类的保存。

打开`index.php`，删除我们在之前部分添加的所有额外代码，这样我们的`/signup post`路由看起来类似于以下代码片段：

```php
post('/signup', function($app) {
$user = new stdClass;
$user->name = $app->form('name');
$user->email = $app->form('email');
**$app->couch->post($user);** 
$app->set('message', 'Thanks for Signing Up ' . $app->form('name') . '!');
$app->render('home');
});

```

## 刚刚发生了什么？

我们使用 Sag 创建了一个到我们的 CouchDB 数据库的帖子，使用的代码大大减少了！Sag 的 post 方法允许您传递数据，因此触发起来非常容易。

让我们快速通过注册流程：

1.  打开浏览器，输入`http://localhost/verge/signup`。

1.  在**名称**文本框中输入一个新名称，然后在**电子邮件**文本框中输入一个新电子邮件。

1.  点击**提交**。

在 CouchDB 中创建了一个新文档，让我们检查一下 Futon，确保它在那里：

1.  打开浏览器，输入`http://localhost:5984/_utils/database.html?verge`，查看 verge 数据库。

1.  点击列表中的第二个文档。

1.  查看这个新文档的详细信息，您会发现它与我们制作的第一个文档具有相同的结构。

完美！结果与我们快速而肮脏的 curl 脚本完全一样，但我们的代码更简化，Sag 在幕后处理了很多事情。

### 注意

目前我们没有捕获或处理任何错误。我们将在以后的章节中更多地讨论如何处理这些错误。幸运的是，CouchDB 以友好的方式处理错误，并且 Sag 已经确保了很容易追踪问题。

## 添加更多结构

我们可以如此轻松地创建文档，这很棒，但对于我们的类来说，有一个强大的结构也很重要，这样我们可以保持有条理。

# 行动时间-包括类目录

为了我们能够使用我们的类，我们需要在`Bones`中添加一些代码，以便我们可以在使用时自动加载类名。这将实现这一点，这样我们就不必在添加新类时不断包含更多文件。

将以下代码添加到`lib/bones.php`：

```php
<?php
define('ROOT', __DIR__ . '/..');
**require_once ROOT . '/lib/sag/src/Sag.php';
function __autoload($classname) {
include_once(ROOT . "/classes/" . strtolower($classname) . ".php");
}** 

```

## 刚刚发生了什么？

我们在我们的`Bones`库中添加了一个`__autoload`函数，如果找不到类，它将给 PHP 最后一次尝试加载类名。`__autoload`函数传递了`$classname`，我们使用`$classname`来找到命名类的文件。我们使用`strtolower`函数使请求的`$classname`变成小写，这样我们就可以找到命名文件。然后我们添加了工作目录的根目录和`classes`文件夹。

### 使用类

现在我们有了加载类的能力，让我们创建一些！我们将从创建一个基类开始，所有其他类都将继承它的属性。

# 行动时间-创建一个基本对象

在这一部分，我们将创建一个名为`base.php`的基类，所有我们的类都将继承它。

1.  让我们从创建一个名为`base.php`的新文件开始，并将其放在工作目录内的`/Library/Webserver/Documents/verge/classes/base.php`文件夹中。

1.  在`base.php`中创建一个带有`__construct`函数的抽象类。在对象的`__construct`中，让我们将`$type`作为一个选项，并将其设置为一个受保护的变量，也称为`$type`。

```php
<?php
abstract class Base
{
protected $type;
public function __construct($type)
{
$this->type = $type;
}
}

```

1.  为了方便以后在我们的类中获取和设置变量，让我们在`__construct`函数之后添加`__get()`和`__set()`函数。

```php
<?php
abstract class Base
{
protected $type;
public function __construct($type)
{
$this->type = $type;
}
**public function __get($property) {
return $this->$property;
}
public function __set($property, $value) {
$this->$property = $value;
}** 
}

```

1.  每次我们将对象保存到 Couch DB 时，我们希望能够将其表示为 JSON 字符串。因此，让我们创建一个名为`to_json()`的辅助函数，它将把我们的对象转换成 JSON 格式。

```php
<?php
abstract class Base
{
protected $type;
public function __construct($type)
{
$this->type = $type;
}
public function __get($property) {
return $this->$property;
}
public function __set($property, $value) {
$this->$property = $value;
}
**public function to_json() {
return json_encode(get_object_vars($this));
}** 
}

```

## 刚刚发生了什么？

我们创建了一个名为`base.php`的基类，它将作为我们构建的所有其他类的基础。在类内部，我们定义了一个受保护的变量`$type`，它将存储文档的分类，如`user`或`post`。接下来，我们添加了一个`__construct`函数，它将在每次创建对象时被调用。这个函数接受选项`$type`，我们将在每个继承`Base`的类中设置它。然后，我们创建了`__get`和`__set`函数。`__get`和`__set`被称为**魔术方法**，它们将允许我们使用`get`和`set`受保护的变量，而无需任何额外的代码。最后，我们添加了一个名为`to_json`的函数，它使用`get_object_vars`和`json_encode`来表示我们的对象为 JSON 字符串。在我们的基类中做这样的小事情将使我们未来的生活变得更加轻松。

# 时间来行动了——创建一个 User 对象

现在我们已经创建了我们的`Base`类，让我们创建一个`User`类，它将包含与用户相关的所有属性和函数。

1.  创建一个名为`user.php`的新文件，并将其放在`base.php`所在的`classes`文件夹中。

1.  让我们创建一个继承我们`Base`类的类。

```php
<?php
class User extends Base
{
}

```

1.  让我们添加我们已经知道需要的两个属性`name`和`email`到我们的`User`类中。

```php
<?php
class User extends Base
{
**protected $name;
protected $email;** 
}

```

1.  让我们添加一个`__construct`函数，告诉我们的`Base`类，在创建时我们的文档类型是`user`。

```php
<?php
class User extends Base
{
protected $name;
protected $email;
**public function __construct()
{
parent::__construct('user');
}** 
}

```

## 刚刚发生了什么？

我们创建了一个简单的类`user.php`，它继承了`Base`。**继承**意味着它将继承可用的属性和函数，以便我们可以利用它们。然后，我们包括了两个受保护的属性`$name`和`$email`。最后，我们创建了一个`__construct`函数。在这种情况下，构造函数告诉父类（即我们的`Base`类），文档的类型是`user`。

# 时间来行动了——插入 User 对象

有了我们的新的`User`对象，我们可以轻松地将其插入到我们的应用程序代码中，然后就可以运行了。

1.  打开`index.php`文件，将`stdClass`改为`User()`。与此同时，我们还可以移除`$user->type = 'user'`，因为现在这个问题已经在我们的类中处理了：

```php
post('/signup', function($app) {
**$user = new User();** 
$user->name = $app->form('name');
$user->email = $app->form('email');
$app->couch->post($user);
}

```

1.  调整 Sag 的`post`语句，以便我们可以以 JSON 格式传递我们的类。

```php
post('/signup', function($app) {
$user = new User();
$user->name = $app->form('name');
$user->email = $app->form('email');
**$app->couch->post($user->to_json);** 
}

```

## 刚刚发生了什么？

我们用`User()`替换了`stdClass`的实例。这将使我们完全控制获取和设置变量。然后，我们移除了`$user->type = 'user'`，因为我们的`User`和`Base`对象中的`__construct`函数已经处理了这个问题。最后，我们添加了之前创建的`to_json()`函数，这样我们就可以将我们的对象作为 JSON 编码的字符串发送出去。

### 注意

Sag 在技术上可以自己处理一个对象的 JSON，但重要的是我们能够从我们的对象中检索到一个 JSON 字符串，这样你就可以以任何你想要的方式与 CouchDB 交互。将来可能需要回来使用`curl`或另一个库重写所有内容，所以重要的是你知道如何表示你的数据为 JSON。

### 测试一下

让我们快速再次通过我们的注册流程，确保一切仍然正常运行：

1.  打开浏览器到`http://localhost/verge/signup`。

1.  在**名称**文本框中输入一个新名称，在**电子邮件**文本框中输入一个新电子邮件。

1.  点击**提交**。

在 CouchDB 中应该已经创建了一个新文档。让我们检查 Futon，确保它在那里：

1.  打开浏览器到`http://localhost:5984/_utils/database.html?verge`查看 verge 数据库。

1.  点击列表中的第三个文档

1.  查看这个新文档的细节，你会发现它和我们制作的前两个文档结构相同。

完美！一切都和以前一样，但现在我们使用了一个更加优雅的解决方案，我们将能够在未来的章节中构建在其基础上。

### 提交到 Git

让我们把代码提交到 Git，这样我们就可以追踪我们到目前为止的进展：

1.  打开**终端**。

1.  输入以下命令以更改目录到我们的工作目录：

```php
**cd /Library/Webserver/Documents/verge/** 

```

1.  我们在`classes`文件夹中添加了一些新文件。所以，让我们确保将这些文件添加到 Git 中。

```php
**git add classes/*** 

```

1.  给 Git 一个描述，说明我们自上次提交以来做了什么：

```php
**git commit am 'Added class structure for Users and tested its functionality'** 

```

通过使用`classes/*`语法，我们告诉 Git 添加 classes 文件夹中的每个文件。当你添加了多个文件并且不想逐个添加每个文件时，这很方便。

# 总结

我们已经完成了这一章的代码。定期将代码推送到 GitHub 是一个很好的做法。事实上，当你与多个开发人员一起工作时，这是至关重要的。我不会在这本书中再提醒你这样做。所以，请确保经常这样做：

```php
**git push origin master** 

```

这行代码读起来像一个句子，如果你在其中加入一些词。这句话告诉 Git 要`push`到`origin`（我们已经定义为 GitHub），并且我们要发送`master`分支。

# 总结

希望你喜欢这一章。当所有这些技术一起工作，让我们能够轻松地保存东西到 CouchDB 时，这是很有趣的。

让我们回顾一下这一章我们谈到的内容：

+   我们看了几种不同的方法，我们可以用 PHP 与 CouchDB 交流

+   我们将 Sag 与 Bones 联系起来

+   我们建立了一个面向对象的类结构，这将为我们节省很多麻烦

+   我们测试了一下，确保当我们提交我们的注册表单时，CouchDB 文档被创建了

在下一章中，我们将积极地研究 CouchDB 已经为我们的用户提供的一些很棒的功能，以及我们如何使用 CouchDB 来构建大多数应用程序都具有的标准注册和登录流程。伸展你的打字手指，准备一大杯咖啡，因为我们即将开始真正的乐趣。


# 第六章：建模用户

> 信不信由你，我们已经做了很多工作，使我们与 CouchDB 的交互变得简单。在本章中，我们将直接进入 CouchDB 的核心，并开始对用户文档进行建模。

更具体地说，我们将：

+   安装 Bootstrap，这是 Twitter 的一个工具包，将处理 CSS、表单、按钮等繁重的工作

+   仔细观察 CouchDB 默认存储用户文档的方式以及我们如何向其中添加字段

+   为用户添加基本功能，以便他们可以在我们的应用程序中注册、登录和注销

+   学习如何处理异常和错误

这将是我们迄今为止最有价值的一章；您将喜欢将一些标准的身份验证和安全性外包给 CouchDB。系好安全带。这将是一次有趣的旅程！

# 在我们开始之前

我们已经玩弄了很多文件来测试 Bones 和 Sag，但您会注意到我们的应用程序看起来仍然相当空旷。所以，让我们稍微改善一下设计。由于设计和实现 UI 并不是本书的目的，我们将使用一个名为**Bootstrap**的工具包来为我们做大部分工作。Bootstrap ([`twitter.github.com/bootstrap/`](http://twitter.github.com/bootstrap/))是由 Twitter 创建的，旨在启动 Web 应用程序和网站的开发。它将使我们能够轻松进行前端开发而不需要太多工作。让我们先让 Bootstrap 运行起来，然后对我们的布局进行一些整理。

## 通过安装 Bootstrap 来清理我们的界面

设置 Bootstrap 非常容易。我们可以引用它们的远程服务器上的 CSS，但我们将下载并在本地调用 CSS，因为最佳实践是减少外部调用的数量。

# 执行时间-本地安装 Bootstrap

安装 Bootstrap 非常简单；我们将在本节中介绍安装它的基础知识。

1.  打开您的浏览器，转到[`twitter.github.com/bootstrap/`](http://twitter.github.com/bootstrap/)。

1.  点击**下载 Bootstrap**。

1.  一个`.zip`文件将被下载到您的`downloads`文件夹中；双击它或使用您喜欢的解压工具解压它。

1.  您将在`bootstrap`文件夹中找到三个目录，分别是`css, img`和`js`，每个目录中都包含若干文件。![执行时间-本地安装 Bootstrap](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/couchdb-php-webdev-bgd/img/3586_06_002.jpg)

1.  将这些文件夹中的所有文件复制到您的`verge`项目的相应文件夹中：`/public/css, public/img`和`public/js`。完成后，您的`verge`目录应该类似于以下屏幕截图：![执行时间-本地安装 Bootstrap](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/couchdb-php-webdev-bgd/img/3586_06_003.jpg)

## 刚刚发生了什么？

我们刚刚通过下载一个包含所有资产的`.zip`文件并将它们放在本地机器的正确文件夹中，将 Twitter 的 Bootstrap 安装到我们的项目中。

仅仅通过查看我们项目中的新文件，您可能会注意到每个文件似乎出现了两次，一个带有文件名中的`min`，一个没有。这两个文件是相同的，除了包含`min`在文件名中的文件已经被压缩。**压缩**意味着从代码中删除所有非必要的字符以减小文件大小。删除的字符包括空格、换行符、注释等。因为这些文件是从网站上按需加载的，所以它们尽可能小以加快应用程序的速度是很重要的。如果您尝试打开一个压缩文件，通常很难看出发生了什么，这没关系，因为我们一开始就不想对这些文件进行任何更改。

所有这些文件的作用可能很明显——`css`文件定义了 Bootstrap 的一些全局样式。`img`文件用于帮助我们在网站周围使用图标，如果我们愿意的话，`js`文件用于帮助我们为网站添加交互、过渡和效果。但是，在`css`文件夹中，有`bootstrap`和`bootstrap-responsive`两个 css 文件，这可能会让人感到困惑。**响应式设计**是近年来真正爆发的东西，本身已经有很多书籍写到了这个主题。简而言之，`bootstrap`包括了`bootstrap-responsive`文件中的样式，以帮助我们的网站在不同的分辨率和设备上工作。因此，我们的网站应该可以在 Web 和现代移动设备上正常工作（大部分情况下）。

现在，你可能能够理解为什么我选择使用 Bootstrap 了；我们只需复制文件到我们的项目中，就获得了很多功能。但是，还没有完全连接好；我们需要告诉我们的`layout.php`文件去哪里查找，以便它可以使用这些新文件。

# 采取行动——包括 Bootstrap 并调整我们的布局以适应它

因为 Bootstrap 框架只是一系列文件，所以我们可以像在第四章中处理`master.css`文件一样轻松地将其包含在我们的项目中，

1.  在`layout.php`文件中，在`master.css`之前添加一个链接到`bootstrap.min.css`和`bootstrap-responsive.min.css`：

```php
<head>
**<link href="<?php echo $this->make_route('/css/bootstrap.min.css') ?>" rel="stylesheet" type="text/css" />
<link href="<?php echo $this->make_route('/css/master.css') ?>" rel="stylesheet" type="text/css" />
<link href="<?php echo $this->make_route('/css/bootstrap-responsive.min.css') ?>" rel="stylesheet" type="text/css" />** 
</head>

```

1.  接下来，让我们确保 Bootstrap 在较旧版本的 Internet Explorer 和移动浏览器中能够良好运行，通过添加以下一小段代码：

```php
<link href="<?php echo $this->make_route('/css/bootstrap- responsive.min.css') ?>" rel="stylesheet" type="text/css" />
**<!--[if lt IE 9]>
<script src="http://html5shim.googlecode.com/svn/trunk/html5.js">
</script>
<![endif]-->
<meta name="viewport" content="width=device-width, initial-scale=1.0">** 
</head>

```

1.  通过以下内容替换`views/layout.php`文件的内容，为我们的应用程序创建一个干净简单的包装：

```php
<body>
**<div class="navbar navbar-fixed-top">
<div class="navbar-inner">
<div class="container">
<a class="btn btn-navbar" data-toggle="collapse" data- target=".nav-collapse">
<span class="icon-bar"></span>
<span class="icon-bar"></span>
<span class="icon-bar"></span>
</a>
<a class="brand" href="<?php echo $this->make_route('/') ?>">Verge</a>
<div class="nav-collapse">
<ul class="nav">
<li><a href="<?php echo $this->make_route('/') ?>">
Home
</a></li>
<li>
<a href="<?php echo $this->make_route('/signup') ?>">Signup</a>
</li>
</ul>
</div>
</div>
</div>
</div>
<div class="container">
<?php include($this->content); ?>
</div>** 
</body>

```

1.  删除`master.css`文件的内容，并用以下内容替换，对我们的布局进行一些小的调整：

```php
.page-header {margin-top: 50px;}
input {height: 20px;}

```

## 刚刚发生了什么？

我们在`layout.php`文件中包含了 Bootstrap，并确保了 Internet Explorer 的版本可以正常工作，通过添加了许多开发人员使用的 HTML5 shim。如果你想了解更多关于这是如何工作的，可以随时访问[`html5shim.googlecode.com/`](http://html5shim.googlecode.com/)。

接下来，我们添加了一些 HTML 来符合 Bootstrap 中定义的 CSS。你不需要太在意 HTML 为什么设置成这样，但如果你好奇的话，你可以参考 Bootstrap 的主页了解更多（[`twitter.github.com/bootstrap/`](http://twitter.github.com/bootstrap/)）。然后，我们在`main.css`文件中添加了一些规则，以在 Bootstrap 的基础上添加额外的样式。我这样做是为了在我们的应用程序中创造一些空间，使事情不会杂乱。

如果你现在去首页[`localhost/verge/`](http://localhost/verge/)，标题看起来确实很酷，但首页需要一些爱。让我们快速清理一下首页。

# 采取行动——装饰首页

Bootstrap 将再次为我们节省一些真正的时间；我们只需要一点 HTML 标记，我们的应用程序就会看起来相当不错！用以下内容替换`views/home.php`的内容：

```php
<div class="hero-unit">
<h1>Welcome to Verge!</h1>
<p>Verge is a simple social network that will make you popular.</p>
<p>
<a href="<?php echo $this->make_route('/signup') ?>" class="btn btn-primary btn-large">
Signup Now
</a>
</p>
</div>

```

## 刚刚发生了什么？

我们刚刚为我们的首页添加了一个漂亮简洁的布局，还有一个按钮，提示人们在来到我们的网站时注册。请注意，我们从文件中删除了`<? php echo $message; ?>`，当我们最初添加它来向用户显示简单的消息时，但我们将在本章后面探索更清晰的方法。

准备看到一些魔法吗？打开你的浏览器，转到[`localhost/verge/`](http://localhost/verge/)。

![刚刚发生了什么？](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/couchdb-php-webdev-bgd/img/3586_06_005.jpg)

我们几乎没有花费任何时间在设计上，但我们已经有了一个更友好的应用程序。当我们深入处理用户时，这种新设计将会派上用场。

准备看到一些很酷的东西吗？试着把浏览器窗口缩小，看看会发生什么。

![刚刚发生了什么？](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/couchdb-php-webdev-bgd/img/3586_06_007.jpg)

注意内容如何根据屏幕大小调整；这意味着在移动设备上，您的应用程序将调整以便轻松查看。Bootstrap 的响应式样板代码只是一个开始。您可以选择根据浏览器的大小来显示和隐藏内容。

浏览器窗口变小后，您会注意到导航栏也被压缩了，而不是看到您的链接，您会看到一个有三条杠的按钮。尝试点击它...什么也没有发生！

这个组件需要 Bootstrap 的 JavaScript 文件，以及一个名为**jQuery**的 JavaScript 库。我们现在还没有必要让这一切都工作，所以让我们在下一章回来吧！

## 将所有用户文件移动到用户文件夹中

我们的应用程序在这一部分将开始大幅增长。如果我们继续像现在这样随意地把文件扔来扔去，我们的视图将变得非常混乱。让我们进行一些整理工作，并为我们的`views`目录添加一些结构。

# 行动时间 - 组织我们的用户视图

随着我们继续为我们的应用程序创建视图，对我们来说很聪明的是要有一些组织，以确保我们保持事情简单明了。

1.  在`views`目录中创建一个名为`user`的文件夹。

1.  将现有的`signup.php`视图移动到这个文件夹中。结果的目录结构将类似于以下截图：![行动时间 - 组织我们的用户视图](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/couchdb-php-webdev-bgd/img/3586_06_010.jpg)

1.  我们需要更新`index.php`并让它知道在哪里找到我们刚刚移动的注册视图：

```php
get('/signup', function($app) {
**$app->render('user/signup');** 
});

```

## 刚刚发生了什么？

我们通过创建一个`user`文件夹来清理我们的`views`文件夹结构，将所有与用户相关的视图放入其中。然后我们将现有的`signup.php`文件移动到`user`文件夹，并告诉我们的`index.php`文件在哪里找到`user/signup.php`文件。请注意，注册页面的路由`/signup`并没有改变。

# 设计我们的用户文档

我们在第三章中已经看到了 CouchDB 如何查看用户文档。在本章中，我们将学习如何利用现有的 CouchDB 功能，并在其上添加一些额外的字段。

## CouchDB 如何查看基本用户文档

CouchDB 已经有一个存储用户文档的机制，我们已经看到并使用过。我们将使用相同的结构来处理我们应用程序的用户：

```php
{
"_id": "org.couchdb.user:your_username",
"_rev": "1-b9af54a7cdc392c2c298591f0dcd81f3",
"name": "your_username",
"password_sha": "3bc7d6d86da6lfed6d4d82e1e4d1c3ca587aecc8",
"roles": [],
"salt": "9812acc4866acdec35c903f0cc072c1d",
"type": "user"
}

```

这七个字段是 CouchDB 要求用户在 CouchDB 中正确操作所必需的：

+   `_id`是用户的唯一标识符。它需要以`org.couchdb.user:`开头，并以`name`属性的相同值结尾。这些角色由`_auth`设计文档强制执行。我们还没有太多讨论设计文档。但是，此时，您需要知道设计文档是直接在数据库中运行的代码。它们可以用于强制执行验证和业务角色。

+   `_rev`是文档的修订标识符。我们在第三章中快速涉及了修订。

+   `name`是用户的用户名。这个字段是`_auth`设计文档所必需的，并且它还需要与冒号后文档的`_id`的值匹配。

+   `password_sha`是密码与`salt`组合后进行 SHA-1 加密的值。我们稍后会介绍 SHA-1 加密。

+   `password_sha`是密码与`salt`组合后进行 SHA-1 加密的值。我们稍后会介绍 SHA-1 加密。

+   `roles`是用户可能拥有的特权数组。通过具有`[]`的值，我们知道这个用户没有特权。

+   `salt`是用户的唯一`salt`。`salt`与密码的明文值组合，并通过 SHA-1 加密得到`password_sha`的值。

+   `type`是 CouchDB 用来标识文档类型的标识符。请记住，CouchDB 是一个扁平的文档存储。这个`type`字段标识了文档的分类。

这些用户文档是独特的，因为它们需要一定结构，但我们总是可以向其添加额外字段。让我们接着做吧！

## 向用户文档添加更多字段

让我们谈谈一些额外的字段，我们知道我们将想要从 Verge 的用户那里收集信息。请记住，如果您的应用程序需要，您总是可以添加更多字段。

+   **用户名：** 我们知道我们将想要存储一个唯一的用户名，这样我们的用户将拥有一个唯一的 URL，例如`/user/johndoe`。幸运的是，这个功能已经由 CouchDB 的`name`字段处理了。考虑到这一点，这里没有什么要做的。我们只需使用现有的`name`即可！

+   **全名：** 用户的全名，这样我们就可以显示用户的名称为`John Doe`。这将是一个用户友好的名称，我们可以用来展示给访问用户，我们需要向文档中添加一个字段来支持这一点。

+   **电子邮件：** 电子邮件地址，以便我们可以与用户进行通信，例如通知电子邮件：`<john@example.com>`。实际上，我们已经在当前类中保存了电子邮件，所以我们也可以忽略这一点。

听起来很容易；我们只需要添加一个字段！每当您向文档添加新字段时，您都应该考虑如何格式化它。让我们讨论一下我们可以采用的 CouchDB 的不同方法。

### 讨论添加这些字段的选项

我们可能会使用各种方法来在 CouchDB 的基本用户文档上添加字段：

+   我们可以创建一个新类型的文档，称之为`verge_user`。这个文档将包含我们在应用程序中需要的任何额外用户属性，然后将引用回用户文档。

+   我们可以在用户文档内创建一个数组，其中包含特定于应用程序的属性，并将所有用户属性添加到其中。

+   或者我们可以只是在用户文档内添加这两个新字段。

我认为，目前我们可以一致同意通过添加一个字段来选择最后提到的选项。

考虑到这一点，我们的最终文档将类似于以下内容：

```php
{
"_id": "org.couchdb.user:johndoe",
"_rev": "1-b9af54a7cdc392c2c298591f0dcd81f3",
"name": "johndoe",
"full_name": "John Doe",
"email": "john@example.com",
"password_sha": "3bc7d6d86da6lfed6d4d82e1e4d1c3ca587aecc8",
"roles": [],
"salt": "9812acc4866acdec35c903f0cc072c1d",
"type": "user"
}

```

您可能会觉得在许多地方看到用户名称的变化很奇怪：`_id、name`和`full_name`。但请记住，CouchDB 有充分的理由这样做。通过将用户名存储在`_id`中，CouchDB 将自动检查每个用户名是否唯一。

### 注意

请记住，如果我们想要开始存储诸如`网站、传记`或`位置`等字段，我们可能会想要更有创意。我们将在本书后面更详细地讨论这个问题。

### 添加对额外字段的支持

为了向用户文档中添加这些字段，我们不需要在代码中做太多更改；我们只需要在`user.php`类中添加一些变量即可。

# 采取行动-添加字段以支持用户文档

我们已经在`classes/user.php`文件中设置了用户文档的基本结构，但让我们继续添加一些字段。

1.  我们目前没有在任何项目中设置`_id`，但我们需要为我们的用户文档这样做。让我们打开`classes/base.php`，并添加`_id`，这样我们就有了在任何文档上设置`_id`的选项。

```php
<?php
abstract class Base {
**protected $_id;** 
protected $type;

```

1.  我们需要将我们刚刚讨论的所有用户字段添加到`classes/user.php`文件中，以及一些其他字段。将以下代码添加到`classes/user.php`中，使其看起来如下：

```php
<?php
class User extends Base {
protected $name;
protected $email;
**protected $full_name;
protected $salt;
protected $password_sha;
protected $roles;** 

```

## 刚刚发生了什么？

我们添加了所有需要保存用户文档到系统中的字段。我们在`base.php`类中添加了`_id`，因为我们知道每个 CouchDB 文档都需要这个字段。到目前为止，我们已经能够在没有`_id`的情况下生活，因为 CouchDB 自动为我们设置了一个。然而，在本章中，我们需要能够设置和检索我们的用户文档的`_id`。然后，我们添加了`full_name`和其他一些可能让您感到困惑的字段。`$salt`和`$password_sha`用于安全存储密码。这个过程通过一个例子更容易解释，所以我们将在我们的注册过程中详细介绍这个过程。最后，我们添加了角色，在本书中将为空，但对于您开发基于角色的系统可能会有用，允许某些用户能够看到应用程序的某些部分等。

现在我们已经定义了用户结构，我们需要走一遍注册过程，这比我们迄今为止所做的 CouchDB 文档创建要复杂一些。

# 注册过程

现在我们已经支持用户类中的所有字段，让我们为用户注册 Verge 添加支持。注册是一个有点复杂的过程，但我们将尝试逐步分解它。在本节中，我们将：

1.  定义我们的数据库管理员用户名和密码，以便我们可以创建新的用户文档

1.  创建一个新的注册界面来支持我们添加的所有字段

1.  添加一个 Bootstrap 助手，使创建表单输入更容易

1.  开发一个快速而简单的注册过程的实现

1.  深入了解我们密码的 SHA-1 加密

1.  重构我们的注册过程，使其更加结构化

## 一点管理员设置

在第三章中，我们锁定了`our _users`数据库，这样我们就可以保护我们的用户数据，这意味着每当我们处理`_users`数据库时，我们需要提供管理员登录。为此，我们将在`index.php`文件的顶部添加用户和密码的 PHP 常量，以便我们在需要执行管理员功能时随时引用它。如果这看起来混乱，不要担心；我们将在本书的后面整理这一点。

```php
<?php
include 'lib/bones.php';
**define('ADMIN_USER', 'tim');
define('ADMIN_PASSWORD', 'test');** 

```

## 更新界面

如果您现在打开浏览器并转到`http://localhost/verge/signup`，您会注意到它与我们的新 Bootstrap 更改不符。实际上，您可能甚至看不到所有的输入框！让我们使用 Bootstrap 来帮助清理我们的注册界面，使其看起来正确。

1.  用以下 HTML 代码替换`views/user/signup.php`页面的所有内容：

```php
<div class="page-header">
<h1>Signup</h1>
</div>
<div class="row">
<div class="span12">
<form class="form-vertical" action="<?php echo $this- >make_route('/signup') ?>" method="post">
<fieldset>
<label for="full_name">Full Name</label>
<input class="input-large" id="full_name" name="full_name" type="text" value="">
<label for="email">Email</label>
<input class="input-large" id="email" name="email" type="text" value="">
<div class="form-actions">
<button class="btn btn-primary">Sign Up!</button>
</div>
</fieldset>
</form>
</div>
</div>

```

1.  刷新注册页面，您将看到我们的表单现在很棒！![更新界面](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/couchdb-php-webdev-bgd/img/3586_06_015.jpg)

+   我们的表单看起来很干净。但是，让我们诚实点，随着我们添加更多字段，为输入字段添加代码将开始变得痛苦。让我们创建一个小的辅助类，帮助我们创建一个可以与 Bootstrap 很好地配合的 HTML 标记：

1.  在`lib`目录中创建一个名为`bootstrap.php`的新文件。

1.  在`bones.php`中引用`lib/bootstrap.php`。

```php
define('ROOT', __DIR__ . '/..');
**require_once ROOT . '/lib/bootstrap.php';** 
require_once ROOT . '/lib/sag/src/Sag.php';

```

1.  打开`lib/bootstrap.php`，并创建一个基本类。

```php
<?php
class Bootstrap {
}

```

1.  我们将创建一个名为`make_input`的函数，它将接受四个参数：`$id, $label, $type`和`$value`。

```php
<?php
class Bootstrap {
**public static function make_input($id, $label, $type, $value = '') {
echo '<label for="' . $id . '">' . $label . '</label> <input class="input-large" id="' . $id . '" name="' . $id . '" type="' . $type . '" value="' . $value . '">';
}** 
}

```

1.  返回到`views/user/signup.php`，并简化代码以使用新的`make_input`函数。

```php
<div class="page-header">
<h1>Signup</h1>
</div>
<div class="row">
<div class="span12">
<form action="<?php echo $this->make_route('/signup') ?>" method="post">
<fieldset>
**<?php Bootstrap::make_input('full_name', 'Full Name', 'text'); ?>
<?php Bootstrap::make_input('email', 'Email', 'text'); ?>** 
<div class="form-actions">
<button class="btn btn-primary">Sign Up!</button>
</div>
</fieldset>
</form>
</div>
</div>

```

1.  现在我们有了`lib/bootstrap.php`来让我们的生活更轻松，让我们向用户询问另外两个字段：`username`和`password`。

```php
<fieldset>
<?php Bootstrap::make_input('full_name', 'Full Name', 'text'); ?>
<?php Bootstrap::make_input('email', 'Email', 'text'); ?>
**<?php Bootstrap::make_input('username', 'Username', 'text'); ?>
<?php Bootstrap::make_input('password', 'Password', 'password'); ?>** 
<div class="form-actions">
<button class="btn btn-primary">Sign Up!</button>
</div>
</fieldset>

```

1.  刷新您的浏览器，您会看到一个大大改进的注册表单。如果它看起来不像下面的截图，请检查您的代码是否与我的匹配。![更新界面](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/couchdb-php-webdev-bgd/img/3586_06_017.jpg)

我们的表单看起来很棒！不幸的是，当您点击**注册！**时，它实际上还没有注册用户。让我们在下一节中改变这一点。

## 快速而简单的注册

现在，我们将直接将用户注册代码写入`index.php`。我们将多次重构此代码，并在本章结束时，将大部分注册功能移至`classes/user.php`文件。

# 行动时间-处理简单用户注册

让我们逐步进行注册过程，在此过程中，我们将从头开始重建注册`POST`路由中的代码。我会逐步解释每段代码，然后在本节结束时进行全面回顾。

1.  打开`index.php`，并开始收集简单字段：`full_name, email`和`roles`。`full_name`和`email`字段将直接来自表单提交，`roles`我们将设置为空数组，因为此用户没有特殊权限。

```php
post('/signup', function($app) {
$user = new User();
$user->full_name = $app->form('full_name');
$user->email = $app->form('email');
$user->roles = array();

```

1.  接下来，我们将捕获用户提交的用户名，但我们希望防止奇怪的字符或空格，因此我们将使用正则表达式将提交的用户名转换为不带任何特殊字符的小写字符串。最终结果将作为我们的`name`字段，也将作为 ID 的一部分。请记住，用户文档要求`_id`必须以`org.couchdb.user`开头，并以用户的`name`结尾。

```php
post('/signup', function($app) {
$user = new User();
$user->full_name = $app->form('full_name'); $user->email = $app->form('email');
$user->roles = array();
**$user->name = preg_replace('/[^a-z0-9-]/', '', strtolower($app- >form('username')));
$user->_id = 'org.couchdb.user:' . $user->name;** 

```

1.  为了加密用户输入的明文密码值，我们将临时设置一个字符串作为`salt`的值。然后，我们将明文密码传递给 SHA-1 函数，并将其保存在`password_sha`中。我们将在接下来的几分钟内深入了解 SHA-1 的工作原理。

```php
post('/signup', function($app) {
$user = new User();
$user->full_name = $app->form('full_name'); $user->email = $app->form('email');
$user->roles = array();
$user->name = preg_replace('/[^a-z0-9-]/', '', strtolower($app- >form('username')));
$user->_id = 'org.couchdb.user:' . $user->name;
**$user->salt = 'secret_salt';
$user->password_sha = sha1($app->form('password') . $user- >salt);** 

```

1.  为了保存用户文档，我们需要将数据库设置为`_users`，并以我们在 PHP 常量中设置的管理员用户身份登录。然后，我们将使用 Sag 将用户放入 CouchDB。

```php
post('/signup', function($app) {
$user = new User();
$user->full_name = $app->form('full_name'); $user->email = $app->form('email');
$user->roles = array();
$user->name = preg_replace('/[^a-z0-9-]/', '', strtolower($app- >form('username')));
$user->_id = 'org.couchdb.user:' . $user->name;
$user->salt = 'secret_salt';
$user->password_sha = sha1($app->form('password') . $user- >salt);
**$app->couch->setDatabase('_users');
$app->couch->login(ADMIN_USER, ADMIN_PASSWORD);
$app->couch->put($user->_id, $user->to_json());** 

```

1.  最后，让我们关闭用户注册功能并呈现主页。

```php
post('/signup', function($app) {
$user = new User();
$user->full_name = $app->form('full_name'); $user->email = $app->form('email');
$user->roles = array();
$user->name = preg_replace('/[^a-z0-9-]/', '', strtolower($app- >form('username')));
$user->_id = 'org.couchdb.user:' . $user->name;
$user->salt = 'secret_salt';
$user->password_sha = sha1($app->form('password') . $user- >salt);
$app->couch->setDatabase('_users');
$app->couch->login(ADMIN_USER, ADMIN_PASSWORD);
$app->couch->put($user->_id, $user->to_json());
**$app->render('home');** 
});

```

## 刚刚发生了什么？

我们刚刚添加了代码来设置 CouchDB 用户文档的所有值。收集`full_name, email`和`roles`的值非常简单；我们只需从提交的表单中获取这些值。设置`name`变得更加复杂，我们将用户名的提交值转换为小写字符串，然后使用**正则表达式（Regex）**函数将任何特殊字符更改为空字符。有了干净的名称，我们将其附加到`org.couchdb.user`并保存到文档的`_id`中。哇！这真是一大堆。

迅速进入加密世界，我们设置了一个静态（非常不安全的）`salt`。将`salt`与明文密码结合在 SHA-1 函数中，得到了一个加密密码，保存在我们对象的`password_sha`字段中。接下来，我们使用`setDatabase`设置了 Sag 的数据库，以便我们可以与 CouchDB 的`_users`数据库进行通信。为了与用户进行通信，我们需要管理员凭据。因此，我们使用`ADMIN_USER`和`ADMIN_PASSWORD`常量登录到 CouchDB。最后，我们使用 HTTP 动词`PUT`在 CouchDB 中创建文档，并为用户呈现主页。

让我们测试一下，看看当我们提交注册表单时会发生什么。

1.  在浏览器中打开注册页面，访问`http://localhost/verge/signup`。

1.  填写表格，将**全名**设置为`John Doe`，**电子邮件**设置为`<john@example.com>`，**用户名**设置为`johndoe`，**密码**设置为`temp123`。完成后，点击**注册**！![刚刚发生了什么？](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/couchdb-php-webdev-bgd/img/3586_06_020.jpg)

1.  您的用户已创建！让我们通过访问`http://localhost:5984/_utils`，并查看`_users`数据库的新文档。![刚刚发生了什么？](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/couchdb-php-webdev-bgd/img/3586_06_025.jpg)

1.  完美，一切应该已经保存正确！查看完毕后，点击**删除文档**删除用户。如果您当前未以管理员用户身份登录，您需要先登录，然后 CouchDB 才允许您删除文档。

我让您删除用户，因为如果每个用户的“盐”等于`secret_salt`，我们的密码实际上就是明文。为了让您理解为什么会这样，让我们退一步看看 SHA-1 的作用。

## SHA-1

在安全方面，存储明文密码是最大的禁忌之一。因此，我们使用 SHA-1 ([`en.wikipedia.org/wiki/SHA-1`](http://en.wikipedia.org/wiki/SHA-1))来创建加密哈希。SHA-1 是由**国家安全局（NSA）**创建的加密哈希函数。SHA-1 的基本原理是我们将密码与**盐**结合在一起，使我们的密码无法辨认。**盐**是一串随机位，我们将其与密码结合在一起，使我们的密码以独特的方式加密。

在我们刚刚编写的注册代码中，我们忽略了一些非常重要的事情。我们的“盐”每次都被设置为`secret_salt`。我们真正需要做的是为每个密码创建一个随机的“盐”。

为了创建随机盐，我们可以使用 CouchDB 的 RESTful JSON API。Couch 在`http://localhost:5984/_uuids`提供了一个资源，当调用时，将为我们返回一个唯一的`UUID`供我们使用。每个`UUID`都是一个长而随机的字符串，这正是盐所需要的！Sag 通过一个名为`generateIDs`的函数非常容易地获取 UUID。

让我们更新我们的注册代码，以反映我们刚刚讨论的内容。打开`index.php`，并更改`盐`值的设置以匹配以下内容：

```php
post('/signup', function($app) {
$user = new User();
$user->full_name = $app->form('full_name'); $user->email = $app->form('email');
$user->roles = array();
$user->name = preg_replace('/[^a-z0-9-]/', '', strtolower($app- >form('username')));
$user->_id = 'org.couchdb.user:' . $user->name;
**$user->salt = $app->couch->generateIDs(1)->body->uuids[0];** 
$user->password_sha = sha1($app->form('password') . $user->salt);
$app->couch->setDatabase('_users');
$app->couch->login(ADMIN_USER, ADMIN_PASSWORD);
$app->couch->put($user->_id, $user->to_json());
$app->render('home');
});

```

### 再次测试注册流程

现在我们已经解决了盐的不安全性，让我们回去再试一次注册流程。

1.  通过在浏览器中转到`http://localhost/verge/signup`来打开注册页面。

1.  填写表格，**全名**为`John Doe`，**电子邮件**为`<john@example.com>`，**用户名**为`johndoe`，**密码**为`temp123`。完成后，点击**注册**。

1.  您的用户已创建！让我们通过转到`http://localhost:5984/_utils`，并在`_users`数据库中查找我们的新文档来到 Futon。这次我们的“盐”是随机且唯一的！再次测试注册流程

## 重构注册流程

正如我之前提到的，我们将把这段代码重构为干净的函数，放在我们的用户类内部，而不是直接放在`index.php`中。我们希望保留`index.php`用于处理路由、传递值和渲染视图。

# 行动时间-清理注册流程

通过在`User`类内创建一个名为`signup`的公共函数来清理我们的注册代码。

1.  打开`classes/user.php`，并创建一个用于注册的`public`函数。

```php
public function signup($username,$password) {
}

```

1.  输入以下代码以匹配下面的代码。它几乎与我们在上一节输入的代码相同，只是不再引用`$user`，而是引用`$this`。您还会注意到`full_name`和`email`不在这个函数中；您马上就会看到它们。

```php
public function signup($username, $password) {
**$bones = new Bones();
$bones->couch->setDatabase('_users');
$bones->couch->login(ADMIN_USER, ADMIN_PASSWORD);
$this->roles = array();
$this->name = preg_replace('/[^a-z0-9-]/', '', strtolower($username));
$this->_id = 'org.couchdb.user:' . $this->name;
$this->salt = $bones->couch->generateIDs(1)->body->uuids[0];
$this->password_sha = sha1($password . $this->salt);
$bones->couch->put($this->_id, $this->to_json());
}** 

```

1.  打开`index.php`，清理注册路由，使其与以下代码匹配：

```php
post('/signup', function($app) {
$user = new User();
$user->full_name = $app->form('full_name');
$user->email = $app->form('email');
**$user->signup($app->form('username'), $app->form('password'));** 
$app->set('message', 'Thanks for Signing Up ' . $user->full_name . '!');
$app->render('home');
});

```

## 刚刚发生了什么？

我们创建了一个名为`signup`的公共函数，它将包含我们的用户注册所需的所有注册代码。然后我们从`index.php`注册路由中复制了大部分代码。你会注意到里面有一些以前没有看到的新东西。例如，所有对`$user`的引用都已更改为`$this`，因为我们使用的所有变量都附加到当前用户对象上。你还会注意到，在开始时，我们创建了一个新的`Bones`对象，以便我们可以使用它。我们还创建了 Sag，我们已经连接到 Bones，我们能够初始化而不会造成任何开销，因为我们使用了单例模式。请记住，单例模式允许我们在此请求中调用我们在其他地方使用的相同对象，而不创建新对象。最后，我们回到`index.php`文件，并简化了我们的注册代码路由，以便我们只处理直接来自表单的值。然后我们通过注册函数传递了未经修改的用户名和密码，以便我们可以处理它们并执行注册代码。

我们的注册代码现在清晰并且在类级别上运行，并且不再影响我们的应用程序。但是，如果你尝试测试我们的表单，你会意识到它还不够完善。

# 异常处理和解决错误

如果你试图返回到你的注册表单并保存另一个名为`John Doe`的文档，你会看到一个相似于以下截图的相当不友好的错误页面：

![异常处理和解决错误](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/couchdb-php-webdev-bgd/img/3586_06_030.jpg)

如果你使用的是 Chrome 以外的浏览器，你可能收到了不同的消息，但结果仍然是一样的。发生了我们没有预料到的不好的事情，更糟糕的是，我们没有捕获这些异常。

当出现问题时会发生什么？我们如何找出出了什么问题？答案是：我们查看日志。

## 解读错误日志

当 PHP 和 Apache 一起工作时，它们会为我们产生大量的日志。有些是访问级别的日志，而另一些是错误级别的。所以让我们看看是否可以通过查看 Apache 错误日志来调查这里发生了什么。

# 行动时间——检查 Apache 的日志

让我们开始找 Apache 的错误日志。

1.  打开终端。

1.  运行以下命令询问 Apache 的`config`文件保存日志的位置：

```php
**grep ErrorLog /etc/apache2/httpd.conf** 

```

1.  终端会返回类似以下的内容：

```php
**# ErrorLog: The location of the error log file.
# If you do not specify an ErrorLog directive within a <VirtualHost>
ErrorLog "/private/var/log/apache2/error_log"** 

```

1.  通过运行以下命令检索日志的最后几行：

```php
**tail /private/var/log/apache2/error_log** 

```

1.  日志会显示很多东西，但最重要的消息是这个，它说 PHP`致命错误`。你的消息可能略有不同，但总体消息是一样的。

```php
**[Sun Sep 11 22:10:31 2011] [error] [client 127.0.0.1] PHP Fatal error: Uncaught exception 'SagCouchException' with message 'CouchDB Error: conflict (Document update conflict.)' in /Library/WebServer/Documents/verge/lib/sag/src/Sag.php:1126\nStack trace:\n#0 /Library/WebServer/Documents/verge/lib/sag/src/Sag.php(286): Sag->procPacket('PUT', '/_users/org.cou...', '{"name":"johndoe')\n#1 /Library/WebServer/Documents/verge/classes/user.php(30): Sag->put('org.couchdb.use...', '{"name":"johndoe')\n#2 /Library/WebServer/Documents/verge/index.php(20): User->signup('w')\n#3 /Library/WebServer/Documents/verge/lib/bones.php(91): {closure}(Object(Bones))\n#4 /Library/WebServer/Documents/verge/lib/bones.php(17): Bones::register('/signup', Object(Closure), 'POST')\n#5 /Library/WebServer/Documents/verge/index.php(24): post('/signup', Object(Closure))\n#6 {main}\n thrown in /Library/WebServer/Documents/verge/lib/sag/src/Sag.php on line 1126, referer: http://localhost/verge/signup
[Sun Sep 11 22:10:31 2011] [error] [client 127.0.0.1] PHP Fatal error: Uncaught exception 'SagCouchException' with message 'CouchDB Error: conflict (Document update conflict.)' in /Library/WebServer/Documents/verge/lib/sag/src/Sag.php:1126\nStack trace:\n#0 /Library/WebServer/Documents/verge/lib/sag/src/Sag.php(286): Sag->procPacket('PUT', '/_users/org.cou...', '{"name":"johndoe')\n#1 /Library/WebServer/Documents/verge/classes/user.php(30): Sag->put('org.couchdb.use...', '{"name":"johndoe')\n#2 /Library/WebServer/Documents/verge/index.php(20): User->signup('w')\n#3 /Library/WebServer/Documents/verge/lib/bones.php(91): {closure}(Object(Bones))\n#4 /Library/WebServer/Documents/verge/lib/bones.php(17): Bones::register('/signup', Object(Closure), 'POST')\n#5 /Library/WebServer/Documents/verge/index.php(24): post('/signup', Object(Closure))\n#6 {main}\n thrown in /Library/WebServer/Documents/verge/lib/sag/src/Sag.php on line 1126, referer: http://localhost/verge/signup** 

```

## 刚刚发生了什么？

我们询问 Apache 它存储日志的位置，一旦我们找到日志文件的保存位置。我们使用`tail`命令返回 Apache 日志的最后几行。

### 注意

有各种各样的方法来阅读日志，我们不会深入讨论，但你可以选择让自己感到舒适的方式。你可以通过搜索互联网来研究`tail`，或者你可以在预装在你的 Mac OSX 机器上的控制台应用程序中打开日志。

查看我们收到的 PHP 致命错误相当令人困惑。如果你开始深入研究，你会发现这是一个 CouchDB 错误。更具体地说，这个错误的主要行是：

```php
**Uncaught exception 'SagCouchException' with message 'CouchDB Error: conflict (Document update conflict.)** 

```

这个消息意味着 CouchDB 对我们传递给它的内容不满意，而且我们没有处理 Sag 以`SagCouchException`形式抛出的异常。`SagCouchException`是一个类，将帮助我们解读 CouchDB 抛出的异常，但为了做到这一点，我们需要知道 CouchDB 返回的状态码是什么。

为了获取状态码，我们需要查看我们的 CouchDB 日志。

# 行动时间：检查 CouchDB 的日志

由于我们都是用 Homebrew 相同的方式安装了 CouchDB，我们可以确保我们的 CouchDB 日志都在同一个位置。考虑到这一点，让我们看看我们的 CouchDB 日志。

1.  打开终端。

1.  通过运行以下命令检索日志的最后几行：

```php
**tail /usr/local/var/log/couchdb/couch.log** 

```

1.  终端将返回类似以下内容：

```php
**[Mon, 12 Sep 2011 16:04:56 GMT] [info] [<0.879.0>] 127.0.0.1 - - 'GET' /_uuids?count=1 200
[Mon, 12 Sep 2011 16:04:56 GMT] [info] [<0.879.0>] 127.0.0.1 - - 'PUT' /_users/org.couchdb.user:johndoe 409** 

```

## 刚刚发生了什么？

我们使用`tail`命令返回 CouchDB 日志的最后几行。

您将注意到的第一条记录是`/uuids?count=1`，这是我们在`signup`函数中抓取`salt`的 UUID。请注意，它返回了`200`状态，这意味着它执行成功。

下一行说`'PUT' /_users/org.couchdb.user:johndoe`，并返回了`409`响应。`409`响应意味着存在更新冲突，这是因为我们传递给用户的名称与已存在的名称相同。这应该很容易解决，但首先我们需要讨论如何捕获错误。

## 捕获错误

幸运的是，借助我们友好的`try...catch`语句，捕获错误相对容易。`try...catch`语句允许您测试一段代码块是否存在错误。`try`块包含您要尝试运行的代码，如果出现问题，将执行`catch`块。

`try...catch`语句的语法看起来类似于以下内容：

```php
try {
// Code to execute
} catch {
// A problem occurred, do this
}

```

正如我之前提到的，Sag 包括一个名为`SagCouchException`的异常类。这个类让我们能够看到 CouchDB 的响应，然后我们可以相应地采取行动。

# 行动时间 - 使用 SagCouchException 处理文档更新冲突

我们在上一节中确定，我们的代码由于`409`响应而中断。因此，让我们调整`classes/user.php`文件中的注册功能，以使用`SagCouchException`处理异常。

```php
public function signup($username, $password) {
...
**try {
$bones->couch->put($this->_id, $this->to_json());
} catch(SagCouchException $e) {
if($e->getCode() == "409") {
$bones->set('error', 'A user with this name already exists.');
$bones->render('user/signup');
exit;
}
}** 
}

```

## 刚刚发生了什么？

我们使用了`try...catch`语句来解决触发的重复文档更新冲突。通过将其转换为`(SagCouchException $e)`，我们告诉它现在只捕获通过的`SagCouchExceptions`。一旦捕获到这个异常，我们就会检查返回的代码是什么。如果是`409`的代码，我们将设置一个带有错误消息的`error`变量。然后我们需要重新显示用户/注册表单，以便用户有机会再次尝试注册流程。为了确保在此错误之后不再执行任何代码，我们使用`exit`命令，以便应用程序停在那里。

我们刚刚设置了一个`error`变量。让我们讨论如何显示这个变量。

## 显示警报

在我们的应用程序中，我们将根据用户交互显示标准通知，我们将其称为警报。我们刚刚设置了一个错误变量，用于错误警报，但我们也希望能够显示成功消息。

# 行动时间 - 显示警报

在这一部分，我们将使用我们现有的变量在 bones 中允许我们向用户显示警报消息。

1.  打开`lib/bones.php`并创建一个名为`display_alert()`的新函数。将调用此函数以查看`alert`变量是否设置。如果设置了`alert`变量，我们将回显一些 HTML 以在布局上显示警报框。

```php
public function display_alert($variable = 'error') {
if (isset($this->vars[$variable])) {
return "<div class='alert alert-" . $variable . "'><a class='close' data-dismiss='alert'>x</a>" . $this- >vars[$variable] . "</div>";
}
}

```

1.  在`layout.php`中添加代码，就在容器`div`内部显示 Flash 调用`display_flash`函数。

```php
<div class="container">
**<?php echo $this->display_alert('error'); ?>
<?php echo $this->display_alert('success'); ?>** 
<?php include($this->content); ?>
</div>

```

1.  现在我们已经添加了这些 Flash 消息，让我们回到`index.php`中的注册`POST`路由，并添加一个 Flash 消息，感谢用户注册。

```php
$user->signup($app->form('username'), $app->form('password'));
**$app->set('success', 'Thanks for Signing Up ' . $user->full_name . '!');** 
$app->render('home');
});

```

## 刚刚发生了什么？

我们创建了一个名为`display_alert`的函数，用于检查传递变量的变量是否设置。如果设置了，我们将借助 Bootstrap 在警报框中显示变量的内容。然后我们在`layout.php`中添加了两行代码，以便我们可以显示错误和成功的 Flash 消息。最后，我们为我们的注册流程添加了一个成功的 Flash 消息。

让我们测试一下。

1.  返回并尝试再次注册用户名为`johndoe`的用户。

你会看到这个友好的错误消息，告诉你有问题：

![刚刚发生了什么？](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/couchdb-php-webdev-bgd/img/3586_06_032.jpg)

1.  现在，让我们测试一下成功的警报消息。将用户名更改为`johndoe2`。点击**注册！**，你将收到一个漂亮的绿色警报。![刚刚发生了什么？](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/couchdb-php-webdev-bgd/img/3586_06_035.jpg)

+   即使有了这些简单的警报，我们的注册表单还不完美。随机的异常和错误可能会发生，我们无法处理。更令人担忧的是，我们并没有要求表单中的字段填写。这些项目需要在我们的视线范围内，但我们无法在本书中涵盖所有这些。

让我们继续讨论用户认证。

# 用户认证

现在我们已经创建了用户，我们肯定需要找到一种让他们登录到我们系统的方法。幸运的是，CouchDB 和 Sag 在这个领域真的会为我们做很多繁重的工作。在这一部分，我们将：

+   设置登录表单

+   了解会话、cookie，以及 CouchDB 和 Sag 如何处理我们的认证

+   添加支持用户登出

+   为已登录和未登录的用户不同处理 UI

## 设置登录表单

让我们创建一些登录表单，这样我们的用户就可以登录到我们的网站并使用他们新创建的账户。

## 试试吧——设置登录的路由和表单

我们已经多次经历了创建页面、设置路由和创建表单的过程。所以，让我们看看这次你能否自己尝试一下。我不会完全不帮助你。我会先告诉你需要尝试做什么，然后当你完成时，我们会进行回顾，确保我们的代码匹配起来。

你需要做的是：

1.  创建一个名为`user/login.php`的新页面。

1.  在`index.php`文件中为登录页面创建新的`GET`和`POST`路由。

1.  告诉登录页面的`GET`路由渲染`user/login`视图。

1.  使用`user/signup.php`作为指南创建一个包含`username`和`password`字段的表单。

1.  使用 Bootstrap 助手和`submit`按钮添加名为`username`和`password`的字段。

在你这样做的时候，我会去看电视。当你准备好了，翻到下一页，我们看看进展如何！

干得好！我希望你能够在不需要太多帮助的情况下完成。如果你需要回头看旧代码寻求帮助，不要担心，因为当开发者陷入困境时，很多人最终都会这样做。让我们看看你的代码与我的代码匹配程度如何。

此外，你的`index.php`文件应该类似于以下内容：

```php
get('/login', function($app) {
$app->render('user/login');
});
post('/login', function($app) {
});

```

你的`views/user/login.php`页面应该类似于以下内容：

```php
<div class="page-header">
<h1>Login</h1>
</div>
<div class="row">
<div class="span12">
<form action="<?php echo $this->make_route('/login') ?>" method="post">
<fieldset>
<?php Bootstrap::make_input('username', 'Username', 'text'); ?>
<?php Bootstrap::make_input('password', 'Password', 'password'); ?>
<div class="form-actions">
<button class="btn btn-primary">Login</button>
</div>
</fieldset>
</form>
</div>
</div>

```

确保将你的代码更新到与我的相匹配，这样我们的代码在未来能够匹配起来。

## 登录和登出

现在我们已经准备好表单了，让我们谈谈我们需要做什么才能让表单真正起作用。让我们快速谈谈我们在登录过程中要实现的目标。

1.  Sag 将连接到 CouchDB 的`_users`数据库。

1.  Sag 将从我们的 PHP 直接将登录信息传递给 CouchDB。

1.  如果登录成功，CouchDB 将返回一个认证的 cookie。

1.  然后，我们将查询 CouchDB 以获取当前登录的用户名，并将其保存到会话变量中以供以后使用。

如果你已经使用其他数据库开发了一段时间，你会立刻看到登录过程有多酷。CouchDB 正在处理我们通常需要自己处理的大部分认证问题！

让我们来看看登录功能。幸运的是，它比注册过程要简单得多。

# 行动时间——为用户添加登录功能

我们将慢慢地进行这个过程，但我认为你会喜欢我们能够如此快速地添加这个功能，因为我们迄今为止编写的所有代码。

1.  打开`classes/user.php`。

1.  创建一个名为`login`的`public`函数，我们可以将我们的明文`$password`作为参数传递。

```php
public function login($password) {
}
Create a new bones object and set the database to _users.
public function login($password) {
**$bones = new Bones();
$bones->couch->setDatabase('_users');** 
}

```

1.  为我们的登录代码创建一个`try...catch`语句。在`catch`块中，我们将捕获错误代码`401`。如果触发了错误代码，我们希望告诉用户他们的登录是不正确的。

```php
public function login($password) {
$bones = new Bones();
$bones->couch->setDatabase('_users');
**try {
}
catch(SagCouchException $e) {
if($e->getCode() == "401") {
$bones->set('error', ' Incorrect login credentials.');
$bones->render('user/login');
exit;
}
}** 
}

```

1.  添加代码来启动会话，然后通过 Sag 将用户名和密码传递到 CouchDB。当用户成功登录时，从 CouchDB 获取当前用户的用户名。

```php
public function login($password) {
$bones = new Bones();
$bones->couch->setDatabase('_users');
**try {
$bones->couch->login($this->name, $password, Sag::$AUTH_COOKIE);
session_start();
$_SESSION['username'] = $bones->couch->getSession()->body- >userCtx->name;
session_write_close();** 
}

```

## 刚刚发生了什么？

我们在`user`类中创建了一个名为`login`的`public`函数，允许用户登录。然后我们创建了一个新的 Bones 引用，以便我们可以访问 Sag。为了处理无效的登录凭据，我们创建了一个`try...catch`块，并先处理`catch`块。这次，我们检查错误代码是否为`401`。如果错误代码匹配，我们设置`error`变量来显示错误消息，渲染登录页面，最后退出当前代码。

接下来，我们通过将用户名和明文密码传递给 Sag 的登录方法来处理登录代码，同时设置`Sag::$AUTH_COOKIE`。这个参数告诉我们使用 CouchDB 的 cookie 身份验证。通过使用 cookie 身份验证，我们可以处理身份验证，而无需每次传递用户名和密码。

在幕后，正在发生的是我们的用户名和密码被发布到`/_session` URL。如果登录成功，它将返回一个 cookie，我们可以在此之后的每个请求中使用它，而不是用户名和密码。幸运的是，Sag 为我们处理了所有这些！

接下来，我们使用`session_start`函数初始化了一个会话，这允许我们设置会话变量，只要我们的会话存在，它就会持续存在。然后，我们为用户名设置了一个会话变量，等于当前登录用户的用户名。我们通过使用 Sag 来获取会话信息，使用`$bones->couch->getSession()`。然后使用`->body()`获取响应的主体，最后使用`userCtx`获取当前用户，并进一步获取`username`属性。这一切都导致了一行代码，如下所示：

```php
**$_SESSION['username'] = $bones->couch->getSession()->body->userCtx->name;** 

```

最后，我们使用`session_write_close`来写入会话变量并关闭会话。这将提高速度并减少锁定的机会。别担心；通过再次调用`session_start()`，我们可以再次检索我们的`session`变量。

最后，我们需要将登录函数添加到`index.php`中的`post`路由。让我们一起快速完成。

```php
post('/login', function($app) {
**$user = new User();
$user->name = $app->form('username');
$user->login($app->form('password'));
$app->set('success', 'You are now logged in!');
$app->render('home');** 
});

```

我们现在可以去测试这个，但让我们完成更多的事情，以便完全测试这里发生了什么。

# 行动时间-为用户添加注销功能

我敢打赌你认为登录脚本非常简单。等到你看到我们如何让用户注销时，你会觉得更容易。

1.  打开`classes/user.php`，创建一个名为`logout`的`public static`函数。

```php
public static function logout() {
$bones = new Bones();
$bones->couch->login(null, null);
session_start();
session_destroy();
}

```

1.  在`index.php`文件中添加一个路由，并调用`logout`函数。

```php
get('/logout', function($app) {
User::logout();
$app->redirect('/');
});

```

1.  注意，我们在 Bones 内部调用了一个新功能`redirect`函数。为了使其工作，让我们在底部添加一个快速的新功能

```php
public function redirect($path = '/') {
header('Location: ' . $this->make_route($path));
}

```

## 刚刚发生了什么？

我们添加了一个名为`logout`的`public static`函数。我们将其设置为`public static`的原因是，我们目前登录的用户对我们来说并不重要。我们只需要执行一些简单的会话级操作。首先，我们像往常一样创建了一个`$bones`实例，但接下来的部分非常有趣，所以我们设置了`$bones->couch->login(null, null)`。通过这样做，我们将当前用户设置为匿名用户，有效地注销了他们。然后，我们调用了`session_start`和`session_destroy`。请记住，通过`session_start`，我们使我们的会话可访问，然后我们销毁它，这将删除与当前会话相关的所有数据。

在完成`login`函数后，我们打开了`index.php`，并调用了我们的`public static`函数，使用`User::logout()`。

最后，我们使用了一个重定向函数，将其添加到了`index.php`文件中。因此，我们迅速在 Bones 中添加了一个函数，这样就可以使用`make_route`将用户重定向到一个路由。

## 处理当前用户

我们真的希望能够确定用户是否已登录，并相应地更改导航。幸运的是，我们可以在几行代码中实现这一点。

# 行动时间 - 处理当前用户

大部分拼图已经就位，让我们来看看根据用户是否已登录来更改用户布局的过程。

1.  让我们在`classes/user.php`中添加一个名为`current_user`的函数，这样我们就可以从会话中检索当前用户的用户名。

```php
public static function current_user() {
session_start();
return $_SESSION['username'];
session_write_close();
}

```

1.  在`classes/user.php`中添加一个名为`is_authenticated`的`public static`函数，以便我们可以查看用户是否已经认证。

```php
public static function is_authenticated() {
if (self::current_user()) {
return true;
} else {
return false;
}
}

```

1.  既然我们的身份验证已经就绪，让我们来收紧`layout.php`中的导航，以便根据用户是否已登录来显示不同的导航项。

```php
<ul class="nav">
**<li><a href="<?php echo $this->make_route('/') ?>">Home</a></li>
<?php if (User::is_authenticated()) { ?>
<li>
<a href="<?php echo $this->make_route('/logout') ?>">
Logout
</a>
</li>
<?php } else { ?>
<li>
<a href="<?php echo $this->make_route('/signup') ?>">
Signup
</a>
</li>
<li>
<a href="<?php echo $this->make_route('/login') ?>">
Login
</a>
</li>
<?php } ?>** 
</ul>

```

## 刚刚发生了什么？

我们首先创建了一个名为`current_user`的`public static`函数，用于检索存储在会话中的用户名。然后我们创建了另一个名为`is_authenticated`的`public static`函数。该函数检查`current_user`是否有用户名，如果有，则用户已登录。如果没有，则用户当前未登录。

最后，我们迅速进入我们的布局，这样我们就可以在用户登录时显示首页和注销的链接，以及在用户当前未登录时显示首页、注册和登录的链接。

让我们来测试一下：

1.  通过转到`http://localhost/verge/`登录页面在浏览器中打开。请注意，标题显示**首页、注册**和**登录**，因为您当前未登录。![刚刚发生了什么？](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/couchdb-php-webdev-bgd/img/3586_06_040.jpg)

1.  使用您的一个用户帐户的凭据登录。您将收到一个很好的警报消息，并且标题更改为显示**首页**和**注销**。![刚刚发生了什么？](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/couchdb-php-webdev-bgd/img/3586_06_045.jpg)

# 总结

我希望你对我们在本章中所取得的成就感到震惊。我们的应用程序真的开始成形了。

具体来说，我们涵盖了：

+   如何通过使用 Twitter 的 Bootstrap 大大改善界面

+   如何在现有 CouchDB 用户文档的基础上创建额外的字段

+   如何处理错误并通过日志调试问题

+   如何完全构建出用户可以使用 Sag 和 CouchDB 注册、登录和注销应用程序的能力

这只是我们应用程序的开始。我们还有很多工作要做。在下一章中，我们将开始着手用户个人资料，并开始创建 CouchDB 中的新文档。这些文档将是我们用户的帖子。


# 第七章：用户个人资料和帖子建模

> 随着我们的应用程序的基础创建，我们允许用户注册并登录到我们的应用程序。这是任何应用程序的重要部分，但我们仍然缺少可以连接到用户帐户的内容的创建。我们将在本章中详细介绍所有内容！

在本章中，我们将：

+   创建一个用户个人资料，以公开显示用户的信息

+   使用 Bootstrap 清理个人资料

+   处理各种异常

+   讨论在 CouchDB 中对帖子和关系的建模

+   创建一个表单，从已登录用户的个人资料中创建帖子

有了我们的路线图，让我们继续讨论用户个人资料！

# 用户个人资料

任何社交网络的主要吸引力是用户的个人资料；用户个人资料通常显示用户的基本信息，并显示他们创建的任何内容。

到本节结束时，我们的用户个人资料将按以下方式工作：

+   如果访问者转到`http://localhost/verge/user/johndoe`，我们的路由系统将将其与路由`/user/:username`匹配

+   `index.php`文件将`johndoe`作为`username`的值，并将其传递给`User`类，尝试查找具有匹配 ID 的用户文档

+   如果找到`johndoe`，`index.php`将显示一个带有`johndoe`信息的个人资料

+   如果找不到`johndoe`，访问者将看到一个`404`错误，这意味着该用户名的用户不存在

## 使用路由查找用户

为了找到用户，我们首先需要创建一个函数，该函数将以用户名作为参数，并在有效时返回一个用户对象。

# 行动时间-获取单个用户文档

您可能还记得，在第三章中，*使用 CouchDB 和 Futon 入门*，我们能够通过传递所需文档的 ID 来从 CouchDB 中检索文档。这一次，我们将使用 Sag 来找到用户的信息。需要注意的一点是，当我们使用 ID 查找用户时，我们需要确保在查找用户时，需要使用`org.couchdb.user:`命名空间进行前置。

让我们从打开`classes/user.php`并滚动到底部开始。

1.  添加一个名为`get_by_username()`的`public static`函数。

```php
public static function get_by_username() {
}

```

1.  为了通过 ID 查找用户，我们需要允许我们的函数接受参数`$username`。

```php
public static function get_by_username($username = null) {
}

```

1.  现在，让我们设置数据库来实例化 Bones 和代理 Sag。记住，我们正在处理`_users`数据库，所以我们需要以`admin`权限登录。

```php
public static function get_by_username($username = null) {
**$bones = new Bones();
$bones->couch->setDatabase('_users');
$bones->couch->login(ADMIN_USER, ADMIN_PASSWORD);
}**

```

1.  现在我们可以连接到`_users`数据库，让我们通过 Sag 发出一个`get`调用，通过添加`org.couchdb.user:`来返回一个用户的传递用户名。

```php
public static function get_by_username($username = null) {
$bones = new Bones()
$bones->couch->login(ADMIN_USER, ADMIN_PASSWORD);
$bones->couch->setDatabase('_users');
**$user = new User();
$document = $bones->couch->get('org.couchdb.user:' . $username)- >body;
$user->_id = $document->_id;
$user->name = $document->name;
$user->email = $document->email;
$user->full_name = $document->full_name;
return $user;
}** 

```

## 刚刚发生了什么？

我们创建了一个名为`get_by_username`的`public static`函数，允许我们传入`$username`。要实际获取文档，我们需要使用我们的`ADMIN_USER`和`ADMIN_PASSWORD`常量来访问`_users`数据库。为了返回一个用户对象，我们需要创建一个名为`$user`的新用户对象。然后我们使用 Sag 的`get`调用通过 ID 标识文档并将其作为名为`$document`的`stdClass`对象返回。然后我们从`document`变量中获取值，并将它们传递到`$user`对象上的相应值。最后，我们将用户文档返回到调用函数的地方。

现在我们有一个处理按用户名查找用户的函数，让我们在`index.php`中创建一个路由，将用户名传递给这个函数。

# 行动时间-为用户个档案创建路由

我们将创建一个路由，以便人们可以通过转到唯一的 URL 来查看个人资料。这将是我们真正利用我们的路由系统处理路由变量的能力的第一次。

1.  打开`index.php`，并创建一个用户个人资料的`get`路由，输入以下代码：

```php
get('/user/:username', function($app) {
});

```

1.  让我们使用路由变量`:username`告诉我们要查找的用户名；我们将把这个变量传递给我们在`User`类中创建的`get_by_username`函数。最后，我们将返回的`user`对象传递给视图中的`user`变量：

```php
get('/user/:username', function($app) {
**$app->set('user', User::get_by_username($app- >request('username')));** 
});

```

1.  最后，我们将呈现`user/profile.php`视图，我们很快就会创建。

```php
get('/user/:username', function($app) {
$app->set('user', User::get_by_username($app- >request('username')));
**$app->render('user/profile');** 
});

```

## 刚刚发生了什么？

我们在短短的四行代码中做了很多事情！首先，我们通过使用`route /user/:username`定义了用户配置文件路由。接下来，我们创建了一段代码，将`route`变量中的`:username`传递给我们`user`类中的`get_by_username`函数。`get_by_username`函数将返回一个包含用户信息的对象，并且我们使用`$app->set('user')`将其发送到我们的视图中。最后，我们呈现了用户配置文件。

让我们继续创建用户配置文件，这样我们就可以看到我们的辛勤工作在发挥作用！

# 行动时间——创建用户配置文件

在本章中，我们将多次清理`user`视图。但是，让我们首先将所有用户文档内容都转储到我们的视图中。

1.  在我们的`working`文件夹中的`views`目录中创建一个名为`user/profile.php`的视图。

1.  为配置文件创建一个简单的标题，使用以下 HTML：

```php
<div class="page-header">
<h1>User Profile</h1>
</div>

```

1.  由于我们还没有设计，让我们只使用`var_dump`来显示`User`文档的所有内容：

```php
<div class="page-header">
<h1>User Profile</h1>
</div>
<div class="container">
**<div class="row">
<?php var_dump($user); ?>
</div>
</div>** 

```

## 刚刚发生了什么？

我们刚刚创建了一个非常基本的用户配置文件，其中包含一个标题，告诉我们这个页面是用户配置文件。然后，我们使用`var_dump`来显示`user`对象的所有内容。`var_dump`是一个通用的 PHP 函数，用于输出关于变量或对象的结构化信息，在你只想确保事情正常运行时非常有用。

### 测试一下

现在我们有了一个简单的用户配置文件设置，让我们看看它的效果如何。

1.  打开你的浏览器，然后转到`http://localhost/verge/user/johndoe`。

1.  你的浏览器将显示以下内容：![测试](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/couchdb-php-webdev-bgd/img/3586_07_005.jpg)

+   还不错，但当然我们需要很快清理一下这些数据的格式。但是，现在让我们确保将我们的更改提交到 Git。

### 将你的更改添加到 Git。

在本节中，我们开始创建用户配置文件，并直接从 CouchDB 输出用户信息。让我们将所有更改添加到 Git，以便跟踪我们的进度。

1.  打开终端。

1.  输入以下命令以更改目录到我们的工作目录。

```php
**cd /Library/Webserver/Documents/verge/** 

```

1.  我们只添加了一个文件`views/user/profile.php`，所以让我们告诉 Git 将这个文件添加到源代码控制中。

```php
**git add views/user/profile.php** 

```

1.  给`Git`一个描述，说明自上次提交以来我们做了什么。

```php
**git commit am 'Created the get_by_username function, a basic user profile, and a route to display it'** 

```

## 修复一些问题

你可能已经注意到，我们忽略了一个潜在的问题，即当找不到用户配置文件时我们没有优雅地处理发生了什么。

例如：

如果你访问`http://localhost/verge/user/someone`，你的浏览器会显示这个非常不友好的错误消息：

![修复一些问题](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/couchdb-php-webdev-bgd/img/3586_07_010.jpg)

### 查找错误

在第六章中，我们通过终端使用`tail`命令查看 Apache 的错误日志。我们将再次做同样的事情。让我们看看 Apache 的日志，看看我们能否弄清楚出了什么问题。

# 行动时间——检查 Apache 的日志

在第六章中，我们首先尝试定位我们的 Apache 日志。默认情况下，它保存在`/private/var/log/apache2/error_log`。如果在上一章中发现它位于其他位置，你可以通过在终端中输入`grep ErrorLog /etc/apache2/httpd.conf`来再次找到它的位置。

让我们找出问题出在哪里。

1.  打开终端。

1.  通过运行以下命令检索日志的最后几行：

```php
**tail /private/var/log/apache2/error_log** 

```

1.  日志会显示很多东西，但最重要的消息是这个，说`PHP 致命错误`。你的消息可能略有不同，但总体消息是一样的。

```php
**[Wed Sep 28 09:29:49 2011] [error] [client 127.0.0.1] PHP Fatal error: Uncaught exception 'SagCouchException' with message 'CouchDB Error: not_found (missing)' in /Library/WebServer/Documents/verge/lib/sag/src/Sag.php:1221\nStack trace:\n#0 /Library/WebServer/Documents/verge/lib/sag/src/Sag.php(206): Sag->procPacket('GET', '/_users/org.cou...')\n#1 /Library/WebServer/Documents/verge/classes/user.php(81): Sag->get('org.couchdb.use...')\n#2 /Library/WebServer/Documents/verge/index.php(44): User::get_by_username('someone')\n#3 /Library/WebServer/Documents/verge/lib/bones.php(91): {closure}(Object(Bones))\n#4 /Library/WebServer/Documents/verge/lib/bones.php(13): Bones::register('/user/:username', Object(Closure), 'GET')\n#5 /Library/WebServer/Documents/verge/index.php(46): get('/user/:username', Object(Closure))\n#6 {main}\n thrown in /Library/WebServer/Documents/verge/lib/sag/src/Sag.php on line 1221** 

```

## 刚刚发生了什么？

我们使用了`tail`命令来返回 Apache 日志的最后几行。如果你仔细看日志，你会看到`CouchDB error`。更具体地说，错误如下：

```php
**error: Uncaught exception 'SagCouchException' with message 'CouchDB Error: not_found (missing)'** 

```

这个消息意味着 CouchDB 对我们的操作不满意，Sag 以`SagCouchException`的形式抛出了一个错误。为了适当地处理`SagCouchException`，我们需要在对 Sag 的调用中添加一些代码。

在上一章中，我们通过检查状态代码并将其与分辨率进行匹配来修复了一个错误。我们可以继续这样做，但最终会发生我们不知道的错误。从现在开始，当发生未处理的异常时，我们希望显示友好的错误消息，以便我们可以调试它。

在接下来的部分，我们将使用 Bones 来帮助我们显示一个异常页面。

## 处理 500 错误

我们真正想解决的是如何处理应用程序中的 500 错误。**500 错误**指的是 HTTP 状态代码`500`，即*"内部服务器错误"。通常，这意味着发生了某些事情，我们没有正确处理。

# 行动时间 - 使用 Bones 处理 500 错误

让我们首先创建一个简单的视图，用于向我们显示错误。

1.  让我们首先在我们的`views`目录内创建一个名为`error`的新文件夹。

1.  创建一个名为`500.php`的新视图，并将其放入`errors`文件夹中（views/error/500.php）。

1.  在`500.php`中添加以下代码以输出异常信息：

```php
<div class="hero-unit">
<h1>An Error Has Occurred</h1>
<p>
<strong>Code:</strong><?php echo $exception->getCode(); ?>
</p>
<p>
<strong>Message:</strong>
<?php echo $exception->getMessage(); ?>
</p>
<p><strong>Exception:</strong> <?php echo $exception; ?></p>
</div>

```

1.  在`lib/bones.php`中添加一个名为`error500`的函数，以便我们可以在我们的应用程序中轻松地显示 500 错误。

```php
public function error500($exception) {
$this->set('exception', $exception);
$this->render('error/500');
exit;
}

```

## 刚才发生了什么？

我们在`views`目录中创建了一个名为`error`的新文件夹，其中包含了我们在应用程序中使用的所有错误视图。然后我们创建了一个名为`500.php`的新视图，以友好的方式显示我们的异常。异常是 Sag 扩展的内置类，使用`SagCouchException`类。有了这个，我们可以很容易地直接与我们的视图中的这个异常类交谈。这个`Exception`类有很多属性。但是，在这个应用程序中，我们只会显示代码、消息和以字符串格式表示的异常。最后，我们创建了一个函数在 Bones 中，允许我们传递异常进去，以便我们可以在视图中显示它。在这个函数中，我们将异常传递给`error/500`视图，然后使用`exit`，告诉 PHP 停止在我们的应用程序中做任何其他事情。这样做是因为发生了问题，我们的应用程序停止做任何其他事情。

# 行动时间 - 处理异常

现在我们可以处理异常了，让我们在`get_by_username`函数中添加一些代码，以便我们可以更深入地查看我们的问题。

1.  让我们打开`classes/user.php`，并在我们的 Sag 调用周围添加一个`try...catch`语句，以确保我们可以处理任何发生的错误。

```php
public static function get_by_username($username = null) {
$bones = new Bones();
$bones->couch->login(ADMIN_USER, ADMIN_PASSWORD);
$bones->couch->setDatabase('_users');
$user = new User();
**try {** 
$document = $bones->couch->get('org.couchdb.user:' . $username)->body;
$user->_id = $document->_id;
$user->name = $document->name;
$user->email = $document->email;
$user->full_name = $document->full_name;
return $user;
**} catch (SagCouchException $e) {
}** 
}

```

1.  既然我们正在捕获错误，让我们在`error500`函数中添加。

```php
public static function get_by_username($username = null) {
$bones = new Bones();
$bones->couch->login(ADMIN_USER, ADMIN_PASSWORD);
$bones->couch->setDatabase('_users');
$user = new User();
try {
$document = $bones->couch->get('org.couchdb.user:' . $username)->body;
$user->_id = $document->_id;
$user->name = $document->name;
$user->email = $document->email;
$user->full_name = $document->full_name;
return $user;
} catch (SagCouchException $e) {
**$bones->error500($e);** 
}
}

```

1.  当我们在`classes/user.php`中时，让我们捕获一些可能的异常。让我们从`public`函数注册开始。

```php
public function signup($username, $password) {
$bones = new Bones();
$bones->couch->setDatabase('_users');
$bones->couch->login(ADMIN_USER, ADMIN_PASSWORD);
$this->roles = array();
$this->name = preg_replace('/[^a-z0-9-]/', '', strtolower($username));
$this->_id = 'org.couchdb.user:' . $this->name;
$this->salt = $bones->couch->generateIDs(1)->body->uuids[0];
$this->password_sha = sha1($password . $this->salt);
try {
$bones->couch->put($this->_id, $this->to_json());
}
catch(SagCouchException $e) {
if($e->getCode() == "409") {
$bones->set('error', 'A user with this name already exists.');
$bones->render('user/signup');
**} else {
$bones->error500($e);
}** 
}
}

```

1.  接下来，让我们在我们的公共函数登录中添加到`catch`语句。

```php
public function login($password) {
$bones = new Bones();
$bones->couch->setDatabase('_users');
try {
$bones->couch->logiBn($this->name, $password, Sag::$AUTH_COOKIE);
session_start();
$_SESSION['username'] = $bones->couch->getSession()->body- >userCtx->name;
session_write_close();
}
catch(SagCouchException $e) {
if($e->getCode() == "401") {
$bones->set('error', 'Incorrect login credentials.');
$bones->render('user/login');
exit;
**} else {
$bones->error500($e);
}** 
}
}

```

## 刚才发生了什么？

现在我们可以优雅地处理异常了，我们通过我们的`User`类，并在发生意外情况时添加了抛出`500`错误的能力。在我们已经预期到某些问题的调用中，如果发生了意外情况，我们可以使用`if...else`语句触发`500`错误。

### 测试我们的异常处理程序

让我们再试一次，看看我们是否能找到异常的根源。

1.  转到`http://localhost/verge/user/someone`。

1.  现在你会看到一个更友好的错误页面，告诉我们代码、消息和完整的错误，你会在错误日志中看到。![测试我们的异常处理程序](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/couchdb-php-webdev-bgd/img/3586_07_015.jpg)

对我们来说，从中弄清楚发生了什么是更容易的。在我们调试应用程序的过程中，这个页面对我们来说将非常有用，以跟踪发生了什么错误。

通过查看这段代码，我们可以知道 CouchDB 正在抛出一个`404`错误。我们可能期望这个错误会发生，因为我们正在寻找一个不存在的用户文档。让我们进一步了解一下`404`错误是什么，以及我们如何处理它。

## 显示 404 错误

`404`错误指的是 HTTP 状态码`404`，意思是“未找到”。`404`错误通常发生在您尝试访问不存在的内容时，比如访问错误的 URL。在我们的情况下，我们收到`404`错误是因为我们试图查找一个不存在的 CouchDB 文档。

### 如果找不到用户，则显示 404

`404`错误是一种特殊的错误，我们会在应用程序的不同位置看到。让我们创建另一个错误页面，以便在发生`404`错误时使用。

# 采取行动：使用 Bones 处理 404 错误

让我们为应用程序中的`404`错误创建一个视图。

1.  首先，在我们的`views/error/`目录中创建一个名为`404.php`的新视图。

1.  让我们在`404.php`中添加一些非常基本的代码，以通知访问者我们的应用程序找不到请求的页面。

```php
<div class="hero-unit">
<h1>Page Not Found</h1>
</div>

```

1.  为了呈现这个视图，让我们在`lib/bones.php`文件中添加另一个名为`error404`的函数。这个函数将为我们很好地显示`404`错误。

```php
public function error404() {
$this->render('error/404');
exit;
}

```

## 刚才发生了什么？

我们创建了一个简单的视图，名为`404.php`，我们可以在应用程序中任何时候显示`404`错误。然后我们在`lib/bones.php`中创建了一个名为`error404`的简单函数，它呈现`error/404.php`并终止当前脚本，以便不会发生进一步的操作。

### 为未知用户显示 404 错误

现在我们有了`404`错误处理程序，让我们在`classes/user.php`的`get_by_username`函数中发生`404`错误时显示它。

打开`classes/user.php`，并修改`get_by_username`函数以匹配以下内容：

```php
public static function get_by_username($username = null) {
$bones = new Bones();
$bones->couch->login(ADMIN_USER, ADMIN_PASSWORD);
$bones->couch->setDatabase('_users');
$user = new User();
**try {** 
$document = $bones->couch->get('org.couchdb.user:' . $username)- >body;
$user->_id = $document->_id;
$user->name = $document->name;
$user->email = $document->email;
$user->full_name = $document->full_name;
return $user;
**} catch (SagCouchException $e) {
if($e->getCode() == "404") {
$bones->error404();
} else {
$bones->error500($e);
}** 
}

```

```php
}

```

### 在整个站点上挂接 404

`404`错误的有趣之处在于，它们可以在访问者通过 Bones 不理解的路由时发生。因此，让我们在 Bones 中添加代码来处理这个问题。

# 采取行动-使用 Bones 处理 404 错误

让我们在`lib/bones.php`和`index.php`周围添加一些简单的代码，以便处理`404`错误。

1.  打开`lib/bones.php`，在`Bones`类内部创建一个名为`resolve`的函数，我们可以在路由的末尾调用它，并确定是否找到了路由。

```php
public static function resolve() {
if (!static::$route_found) {
$bones = static::get_instance();
$bones->error404();
}
}

```

1.  转到`lib/bones.php`的顶部，并创建一个名为`resolve`的函数，放在`Bones`类之外（例如`get, post, put`或`delete`），我们可以在任何地方调用它。

```php
function resolve() {
Bones::resolve();
}

```

1.  我们要做的最后一件事就是在`index.php`的最底部添加一行代码，如果没有找到路由，就可以调用它。随着添加更多的路由，确保`resolve()`始终位于文件的末尾。

```php
get('/user/:username', function($app) {
$app->set('user', User::get_by_username($app- >request('username')));
$app->render('user/profile');
});
**resolve();** 

```

## 刚才发生了什么？

我们创建了一个名为`resolve`的函数，在我们的`index.php`文件的底部执行，它会在所有路由之后执行。这个函数作为一个“清理”函数，如果没有匹配的路由，它将向访问者显示一个`404`错误并终止当前脚本。

### 测试一下

既然我们优雅地处理了`404`错误，让我们测试一下，看看会发生什么。

1.  打开您的浏览器，转到`http://localhost/verge/user/anybody`。

1.  您的浏览器将显示以下内容：![测试一下](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/couchdb-php-webdev-bgd/img/3586_07_017.jpg)

+   太好了！我们的`User`类正在转发给我们一个`404`错误，因为我们在`get_by_username`函数中添加了代码。

1.  接下来，让我们检查一下我们的`index.php`，看看如果找不到请求的路由，它是否会转发给我们一个`404`错误。

1.  打开您的浏览器，转到`http://localhost/verge/somecrazyurl`。

1.  您的浏览器将显示以下内容：![测试一下](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/couchdb-php-webdev-bgd/img/3586_07_018.jpg)

完美！我们的`404`错误处理程序正是我们需要的。如果我们将来需要再次使用它，我们只需要在我们的`Bones`类中调用`error404`，然后一切都设置好了！

## 给用户一个链接到他们的个人资料

在大多数社交网络中，一旦您登录，就会显示一个链接，以查看当前登录用户的个人资料。让我们打开`view/layout.php`，并在导航中添加一个`My Profile`链接。

```php
<ul class="nav">
<li><a href="<?php echo $this->make_route('/') ?>">Home</a></li>
<?php if (User::is_authenticated()) { ?> <li>
<a href="<?php echo $this->make_route('/user/' . User::current_user()) ?>">
My Profile
</a>
</li>
<li>
<a href="<?php echo $this->make_route('/logout') ?>">
Logout
</a>
</li>
<?php } else { ?>
<li>
<a href="<?php echo $this->make_route('/signup') ?>">
Signup
</a>
</li>
<li>
<a href="<?php echo $this->make_route('/login') ?>">
Login
</a>
</li>
<?php } ?>
</ul>

```

## 使用 Bootstrap 创建更好的个人资料

我们的个人资料并不是很好地组合在一起，这开始让我感到困扰，我们需要在本章后面再添加更多内容。让我们准备好我们的用户个人资料，以便我们可以很好地显示用户的信息和帖子。

# 行动时间-检查用户当前是否已登录

我们需要能够弄清楚用户正在查看的个人资料是否是他们自己的。所以，让我们在我们的视图中添加一个变量，告诉我们是否是这种情况。

1.  打开`index.php`，并添加一个名为`is_current_user`的变量，用于确定您正在查看的个人资料是否等于当前登录用户。

```php
get('/user/:username', function($app) {
$app->set('user', User::get_by_username($app- >request('username')));
**$app->set('is_current_user', ($app->request('username') == User::current_user() ? true : false));** 
$app->render('user/profile');
});

```

1.  让我们更改`views/user/profile.php`头部的代码，这样我们就可以输出用户的全名以及`This is you!`，如果这是当前用户的个人资料。

```php
<div class=－page-header－>
**<h1><?php echo $user->full_name; ?>
<?php if ($is_current_user) { ?>
<code>This is you!</code>
<?php } ?>
</h1>** 
</div>

```

## 刚刚发生了什么？

我们使用了一个称为`ternary`的简写操作。`ternary`操作是`if-else`语句的简写形式。在这种情况下，我们说如果从路由传递的用户名等于当前登录用户的用户名，则返回`true`，否则返回`false`。然后，我们进入我们的个人资料，并且如果`is_current_user`变量设置为`true`，则显示`This is you!`。

### 清理个人资料的设计

再次，Bootstrap 将通过允许我们用有限的代码清理我们的个人资料来拯救我们。

1.  让我们通过以下代码将我们的行`div`分成两列：

```php
<div class="page-header">
<h1><?php echo $user->full_name; ?>
<?php if ($is_current_user) { ?>
<code>This is you!</code>
<?php } ?>
</h1>
</div>
**<div class="container">
<div class="row">
<div class="span4">
<div class="well sidebar-nav">
<ul class="nav nav-list">
<li><h3>User Information</h3>
</ul>
</div>
</div>
<div class="span8">
<h2>Posts</h2>
</div>
</div>
</div>** 

```

1.  通过将更多的列表项添加到无序列表中，将用户的信息输出到左列。

```php
<div class="container">
<div class="row">
<div class="span4">
<div class="well sidebar-nav">
<ul class="nav nav-list">
<li><h3>User Information</h3></li>
**<li><b>Username:</b> <?php echo $user->name; ?></li>
<li><b>Email:</b> <?php echo $user->email; ?></li>** 
</ul>
</div>
</div>
<div class="span8">
<h2>Posts</h2>
</div>
</div>
</div>

```

#### 让我们来看看我们的新个人资料

有了这个，我们的新的改进的个人资料已经出现了！让我们来看看。

1.  通过转到`http://localhost/verge/user/johndoe`，在浏览器中打开`johndoe`用户的 URL。

1.  您的浏览器将显示一个精心改造的用户个人资料。![让我们来看看我们的新个人资料](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/couchdb-php-webdev-bgd/img/3586_07_019.jpg)

1.  现在，让我们检查一下我们的`$is_current_user`变量是否正常工作。为了做到这一点，请使用`johndoe`作为用户名登录，并转到`http://localhost/verge/user/johndoe`。

1.  您的浏览器将显示用户个人资料，以及一个友好的消息告诉您这是您的个人资料。![让我们来看看我们的新个人资料](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/couchdb-php-webdev-bgd/img/3586_07_020.jpg)

太棒了！我们的个人资料真的开始变得完整起来了。这是我们应用程序的一个重要里程碑。所以，让我们确保将我们的更改提交到 Git。

#### 将您的更改添加到 Git

在这一部分，我们添加了支持清晰处理异常的功能，并且还改进了用户个人资料。让我们把所有的更改都添加到 Git 中，这样我们就可以跟踪我们的进展。

1.  打开终端。

1.  输入以下命令以更改目录到我们的`working`目录： 

```php
**cd /Library/Webserver/Documents/verge/** 

```

1.  我们在这一部分添加了一些文件。所以，让我们把它们都加入到源代码控制中。

```php
**git add .** 

```

1.  给 Git 一个描述，说明自上次提交以来我们做了什么。

```php
**git commit -am 'Added 404 and 500 error exception handling and spruced up the layout of the user profile'** 

```

# 帖子

我们在个人资料中有一个帖子的占位符。但是，让我们开始填充一些真实内容。我们将允许用户发布小段内容，并将它们与用户帐户关联起来。

## 建模帖子

让我们讨论一下我们需要做什么才能将帖子保存到 CouchDB 并与用户关联起来。在我们使用 CouchDB 进行此操作之前，让我们尝试通过查看如何在 MySQL 中进行操作来加深理解。

### 如何在 MySQL 中建模帖子

如果我们要为 MySQL（或其他 RDBMS）建模这种关系，它可能看起来类似于以下截图：

![如何在 MySQL 中建模帖子](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/couchdb-php-webdev-bgd/img/3586_07_023.jpg)

简而言之，这个图表显示了一个`posts`表，它有一个外键`user_id`，引用了用户表的`id`。这种一对多的关系在大多数应用程序中都很常见，在这种情况下，意味着一个用户可以有多个帖子。

既然我们已经看过一个熟悉的图表，让我们再看看与 CouchDB 相关的相同关系。

### 如何在 CouchDB 中建模帖子

令人惊讶的是，CouchDB 以非常相似的方式处理关系。你可能会想，等一下，我以为你说它不是关系数据库。请记住，无论你使用什么数据库，它们处理关系的方式都可能有共同之处。让我们看看 CouchDB 如何说明相同的数据和模型。

![如何在 CouchDB 中建模帖子](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/couchdb-php-webdev-bgd/img/3586_07_025.jpg)

这很相似，对吧？最大的区别始终是，在关系数据库中，数据存储在固定的行和列中，而在 CouchDB 中，它们存储在自包含的文档中，具有无模式的键和值集。无论你如何查看数据，关系都是相同的，即，通过对用户 ID 的引用，帖子与用户相连接。

为了确保我们在同一页面上，让我们逐个浏览`post`文档中的每个字段，并确保我们理解它们是什么。

+   `_id`是文档的唯一标识符。

+   `_rev`是文档的修订标识符。我们在第三章中提到过修订，如果你想重新了解这个概念。

+   `type`告诉我们我们正在查看什么类型的文档。在这种情况下，每个`post`文档都将等于`post`。

+   `date_created`是文档创建时的时间戳。

+   `content`包含我们想要放在帖子中的任何文本。

+   `user`包含创建帖子的用户的用户名，并引用回`_users`文档。有趣的是，我们不需要在这个字段中放入`org.couchdb.user`，因为 CouchDB 实际上会查看用户名。

现在我们已经定义了需要保存到 CouchDB 的值，我们准备在一个新类`Post`中对其进行建模。

## 试试看-设置帖子类

创建`Post`类将与我们的`User`类非常相似。如果你感到足够自信，请尝试自己创建基本类。

你需要做的是：

1.  创建一个名为`post.php`的新类，它扩展了`Base`类。

1.  为之前定义的每个必需字段创建变量。

1.  添加一个`construct`函数来定义文档的类型。

完成后，继续阅读下一页，并确保你的工作与我的匹配。

让我们检查一下一切的结果。

你应该已经创建了一个名为`post.php`的新文件，并将其放在我们`working`文件夹中的`classes`目录中。post.php 的内容应该类似于以下内容：

```php
<?php
class Post extends Base
{
protected $date_created;
protected $content;
protected $user;
public function __construct() {
parent::__construct('post');
}
}

```

这就是我们在 PHP 中处理帖子文档所需要的一切。现在我们已经建立了这个类，让我们继续创建帖子。

# 创建帖子

现在对我们来说，创建帖子将是小菜一碟。我们只需要添加几行代码，它就会出现在数据库中。

# 行动时间-制作处理帖子创建的函数

让我们创建一个名为`create`的公共函数，它将处理我们应用程序的帖子创建。

1.  打开`classes/post.php`，并滚动到底部。在这里，我们将创建一个名为`create`的新公共函数。

```php
public function create() {
}

```

1.  让我们首先获得一个新的 Bones 实例，然后设置当前`post`对象的变量。

```php
public function create() {
**$bones = new Bones();
$this->_id = $bones->couch->generateIDs(1)->body->uuids[0];
$this->date_created = date('r');
$this->user = User::current_user();
}** 

```

1.  最后，让我们使用 Sag 将文档放入 CouchDB。

```php
public function create() {
$bones = new Bones();
$this->_id = $bones->couch->generateIDs(1)->body->uuids[0];
$this->date_created = date('r');
$this->user = User::current_user();
**$bones->couch->put($this->_id, $this->to_json());** 
}

```

1.  让我们用一个`try...catch`语句包装对 CouchDB 的调用，在`catch`语句中，让我们像以前一样将其弹到`500`错误。

```php
public function create() {
$bones = new Bones();
$this->_id = $bones->couch->generateIDs(1)->body->uuids[0];
$this->date_created = date('r');
$this->user = User::current_user();
**try {
$bones->couch->put($this->_id, $this->to_json());
}
catch(SagCouchException $e) {
$bones->error500($e);
}** 
}

```

## 刚刚发生了什么？

我们刚刚创建了一个名为`create`的函数，使我们能够创建一个新的`Post`文档。我们首先实例化了一个 Bones 对象，以便我们可以使用 Sag。接下来，我们使用 Sag 为我们获取了一个`UUID`作为我们的`post`的 ID。然后，我们使用`date('r')`将日期输出为`RFC 2822`格式（这是 CouchDB 和 JavaScript 所喜欢的格式），并将其保存到帖子的`date_created`变量中。然后，我们将帖子的用户设置为当前用户的用户名。

在设置了所有字段后，我们使用 Sag 的`put`命令将帖子文档保存到 CouchDB。最后，为了确保我们没有遇到任何错误，我们将`put`命令包装在一个`try...catch`语句中。在`catch`部分中，如果出现问题，我们将用户传递给 Bones 的`error500`函数。就是这样！我们现在可以在我们的应用程序中创建帖子。我们唯一剩下的就是在用户个人资料中创建一个表单。

# 开始行动-创建一个表单来启用帖子创建

让我们直接在用户的个人资料页面中编写用于创建帖子的表单。只有当已登录用户查看自己的个人资料时，该表单才会显示出来。

1.  打开`user/profile.php`。

1.  让我们首先检查用户正在查看的个人资料是否是他们自己的。

```php
<div class="span8">
**<?php if ($is_current_user) { ?>
<h2>Create a new post</h2>
<?php } ?>** 
<h2>Posts</h2>
</div>

```

1.  接下来，让我们添加一个表单，允许当前登录的用户发布帖子。

```php
<div class="span8">
<?php if ($is_current_user) { ?>
<h2>Create a new post</h2>
**<form action="<?php echo $this->make_route('/post')?>" method="post">
<textarea id="content" name="content" class="span8" rows="3">
</textarea>
<button id="create_post" class="btn btn-primary">Submit
</button>
</form>
<?php } ?>** 
<h2>Posts</h2>
</div>

```

## 刚刚发生了什么？

我们使用`$is_current_user`变量来确定查看个人资料的用户是否等于当前登录的用户。接下来，我们创建了一个表单，该表单提交到`post`路由（接下来我们将创建）。在表单中，我们放置了一个`id`为`content`的`textarea`和一个`submit`按钮来实际提交表单。

现在我们已经准备好一切，让我们通过在`index.php`文件中创建一个名为`post`的路由来完成`post`的创建。

# 开始行动-创建一个路由并处理帖子的创建

为了实际创建一个帖子，我们需要创建一个路由并处理表单输入。

1.  打开`index.php`。

1.  创建一个基本的`post`路由，并将其命名为`post`。

```php
post('/post', function($app) {
});

```

1.  在我们的`post`路由中，让我们接受传递的值`content`并在我们的`Post`类上使用`create`函数来实际创建帖子。帖子创建完成后，我们将用户重定向回他们的个人资料页面。

```php
post('/post', function($app) {
**$post = new Post();
$post->content = $app->form('content');
$post->create();
$app->redirect('/user/' . User::current_user());** 
});

```

1.  我们已经做了很多工作，以确保用户在创建帖子时经过身份验证，但让我们再三检查用户是否在这里经过了身份验证。如果他们没有经过身份验证，我们的应用程序将将他们转发到用户登录页面，并显示错误消息。

```php
post('/post', function($app) {
**if (User::is_authenticated()) {** 
$post = new Post();
$post->content = $app->form('content');
$post->create();
$app->redirect('/user/' . User::current_user());
**} else {
$app->set('error', 'You must be logged in to do that.');
$app->render('user/login');
}** 
});

```

## 刚刚发生了什么？

在这一部分，我们为`post`路由创建了一个`post`路由（抱歉，这是一个令人困惑的句子）。在`post`路由内部，我们实例化了一个`Post`对象，并将其实例变量`content`设置为来自提交表单的`textarea`的内容。接下来，我们通过调用公共的`create`函数创建了`post`。帖子保存后，我们将用户重定向回他/她自己的个人资料。最后，我们在整个`route`周围添加了功能，以确保用户已登录。如果他们没有登录，我们将把他们弹到登录页面，并要求他们登录以执行此操作。

## 测试一下

现在我们已经编写了创建帖子所需的一切，让我们一步一步地测试一下。

1.  首先以`johndoe`的身份登录，并通过在浏览器中打开`http://localhost/verge/user/johndoe`来转到他的个人资料。

1.  您的浏览器将显示一个用户个人资料，就像我们以前看到的那样，但这次您将看到`post`表单。![测试一下](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/couchdb-php-webdev-bgd/img/3586_07_027.jpg)

1.  在文本区域中输入一些内容。我输入了`我不喜欢花生酱`，但您可以随意更改。

1.  完成后，点击**提交**按钮。

1.  您已被转发回`johndoe`的用户个人资料，但您还看不到任何帖子。因此，让我们登录 Futon，确保帖子已创建。

1.  通过转到`http://localhost:5984/_utils/database.html?verge`，在 Futon 中转到`verge`数据库。

1.  太棒了！这里有一个文档；让我们打开它并查看内容。![测试一下](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/couchdb-php-webdev-bgd/img/3586_07_030.jpg)

这个完美解决了！当用户登录时，他们可以通过转到他们的个人资料并提交**创建新帖子**表单来创建帖子。

## 将您的更改添加到 Git

在这一部分，我们添加了一个基于我们的`Post`模型来创建帖子的函数。然后我们在用户个人资料中添加了一个表单，这样用户就可以真正地创建帖子。让我们把所有的更改都添加到 Git 中，这样我们就可以跟踪我们的进展。

1.  打开终端。

1.  输入以下命令以更改目录到我们的`working`目录：

```php
**cd /Library/Webserver/Documents/verge/** 

```

1.  我们添加了`classes/post.php`文件，所以让我们把那个文件加入到源代码控制中：

```php
**git add classes/post.php** 

```

1.  给`Git`一个描述，说明自上次提交以来我们做了什么：

```php
**git commit –am 'Added a Post class, built out basic post creation into the user profile. Done with chapter 7.'**

```

1.  我知道我说过我不会再提醒你了，但我也只是个人。让我们把这些更改推送到 GitHub 上去。

```php
**git push origin master**

```

# 总结

信不信由你，这就是我们在本章中要写的所有代码。收起你的抗议标语，上面写着“我们甚至还没有查询用户的帖子！”我们停在这里的原因是 CouchDB 有一种非常有趣的方式来列出和处理文档。为了讨论这个问题，我们需要定义如何使用**设计文档**来进行视图和验证。幸运的是，这正是我们将在下一章中涵盖的内容！

与此同时，让我们快速回顾一下我们在本章中取得的成就。

# 摘要

在本章中，我们涵盖了创建用户个人资料来显示用户信息，如何优雅地处理异常并向用户显示`500`和`404`错误页面，如何在 CouchDB 中对帖子进行建模，以及最后，创建一个为已登录用户创建帖子的表单。

正如我所说，在下一章中，我们将涉及一些 CouchDB 带来的非常酷的概念。这可能是本书中最复杂的一章，但会非常有趣。
