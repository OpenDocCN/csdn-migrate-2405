# PHP7 编程秘籍（六）

> 原文：[`zh.annas-archive.org/md5/2ddf943a2c311275def462dcde4895fb`](https://zh.annas-archive.org/md5/2ddf943a2c311275def462dcde4895fb)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十二章：改进 Web 安全

在本章中，我们将涵盖以下主题：

+   过滤`$_POST`数据

+   验证`$_POST`数据

+   保护 PHP 会话

+   使用令牌保护表单

+   构建一个安全的密码生成器

+   使用 CAPTCHA 保护表单

+   加密/解密而不使用`mcrypt`

# 介绍

在本章中，我们将向您展示如何建立一个简单而有效的机制，用于过滤和验证一块发布数据。然后，我们将介绍如何保护您的 PHP 会话免受潜在的会话劫持和其他形式的攻击。下一个配方将展示如何使用随机生成的令牌保护表单免受**跨站点请求伪造**（**CSRF**）攻击。有关密码生成的配方将向您展示如何将 PHP 7 真正的随机化结合起来生成安全密码。然后，我们将向您展示两种形式的**CAPTCHA**：一种是基于文本的，另一种是使用扭曲图像的。最后，有一个配方涵盖了强加密，而不使用被废弃和即将被弃用的`mcrypt`扩展。

# 过滤`$_POST`数据

过滤数据的过程可以包括以下任何或所有内容：

+   删除不需要的字符（即删除`<script>`标签）

+   对数据执行转换（即将引号转换为`&quot;`）

+   加密或解密数据

加密在本章的最后一个配方中有所涵盖。否则，我们将介绍一个基本机制，可用于过滤表单提交后到达的`$_POST`数据。

## 如何做...

1.  首先，您需要了解将出现在`$_POST`中的数据。而且，也许更重要的是，您需要了解表单数据将被存储的数据库表所施加的限制。例如，看一下`prospects`表的数据库结构：

```php
COLUMN          TYPE              NULL   DEFAULT
first_name      varchar(128)      No     None     NULL
last_name       varchar(128)      No     None     NULL
address         varchar(256)      Yes    None     NULL
city            varchar(64)       Yes    None     NULL
state_province  varchar(32)       Yes    None     NULL
postal_code     char(16)          No     None     NULL
phone           varchar(16)       No     None     NULL
country         char(2)           No     None     NULL
email           varchar(250)      No     None     NULL
status          char(8)           Yes    None     NULL
budget          decimal(10,2)     Yes    None     NULL
last_updated    datetime          Yes    None     NULL
```

1.  完成对要发布和存储的数据的分析后，可以确定要发生的过滤类型，以及哪些 PHP 函数将用于此目的。

1.  例如，如果您需要摆脱用户提供的表单数据中的前导和尾随空格，这是完全可能的，您可以使用 PHP 的`trim()`函数。根据数据库结构，所有字符数据都有长度限制。因此，您可能需要考虑使用`substr()`来确保长度不超过。如果您想要删除非字母字符，您可能需要考虑使用`preg_replace()`与适当的模式。

1.  现在，我们可以将所需的 PHP 函数集合成一个回调函数的单一数组。以下是一个基于表单数据过滤需求的示例，最终将存储在`prospects`表中：

```php
$filter = [
  'trim' => function ($item) { return trim($item); },
  'float' => function ($item) { return (float) $item; },
  'upper' => function ($item) { return strtoupper($item); },
  'email' => function ($item) { 
     return filter_var($item, FILTER_SANITIZE_EMAIL); },
  'alpha' => function ($item) { 
     return preg_replace('/[^A-Za-z]/', '', $item); },
  'alnum' => function ($item) { 
     return preg_replace('/[⁰-9A-Za-z ]/', '', $item); },
  'length' => function ($item, $length) { 
     return substr($item, 0, $length); },
  'stripTags' => function ($item) { return strip_tags($item); },
];
```

1.  接下来，我们定义一个与`$_POST`中预期的字段名称匹配的数组。在此数组中，我们指定`$filter`数组中的键，以及任何参数。请注意第一个键`*`。我们将使用它作为应用于所有字段的通配符：

```php
$assignments = [
  '*'             => ['trim' => NULL, 'stripTags' => NULL],
  'first_name'    => ['length' => 32, 'alnum' => NULL],
  'last_name'     => ['length' => 32, 'alnum' => NULL],
  'address'       => ['length' => 64, 'alnum' => NULL],
  'city'          => ['length' => 32],
  'state_province'=> ['length' => 20],
  'postal_code'   => ['length' => 12, 'alnum' => NULL],
  'phone'         => ['length' => 12],
  'country'       => ['length' => 2, 'alpha' => NULL, 
                      'upper' => NULL],
  'email'         => ['length' => 128, 'email' => NULL],
  'budget'        => ['float' => NULL],
];
```

1.  然后，我们循环遍历数据集（即来自`$_POST`）并依次应用回调。我们首先运行分配给通配符（`*`）键的所有回调。

### 注意

重要的是要实现通配符过滤器以避免冗余设置。在前面的示例中，我们希望应用代表 PHP 函数`strip_tags()`和`trim()`的过滤器到每个项目。

1.  接下来，我们运行分配给特定数据字段的所有回调。完成后，`$data`中的所有值都将被过滤：

```php
foreach ($data as $field => $item) {
  foreach ($assignments['*'] as $key => $option) {
    $item = $filter$key;
  }
  foreach ($assignments[$field] as $key => $option) {
    $item = $filter$key;
  }
}
```

## 工作原理...

将步骤 4 到 6 中显示的代码放入一个名为`chap_12_post_data_filtering_basic.php`的文件中。您还需要定义一个数组来模拟`$_POST`中可能存在的数据。在这种情况下，您可以定义两个数组，一个包含*好*数据，另一个包含*坏*数据：

```php
$testData = [
  'goodData'   => [
    'first_name'    => 'Doug',
    'last_name'     => 'Bierer',
    'address'       => '123 Main Street',
    'city'          => 'San Francisco',
    'state_province'=> 'California',
    'postal_code'   => '94101',
    'phone'         => '+1 415-555-1212',
    'country'       => 'US',
    'email'         => 'doug@unlikelysource.com',
    'budget'        => '123.45',
  ],
  'badData' => [
    'first_name' => 'This+Name<script>bad tag</script>Valid!',
    'last_name' 	=> 'ThisLastNameIsWayTooLongAbcdefghijklmnopqrstuvwxyz0123456789Abcdefghijklmnopqrstuvwxyz0123456789Abcdefghijklmnopqrstuvwxyz0123456789Abcdefghijklmnopqrstuvwxyz0123456789',
    //'address' 	=> '',    // missing
    'city'      => 'ThisCityNameIsTooLong012345678901234567890123456789012345678901234567890123456789  ',
    //'state_province'=> '',    // missing
    'postal_code'     => '!"£$%^Non Alpha Chars',
    'phone'           => ' 12345 ',
    'country'         => '12345',
    'email'           => 'this.is@not@an.email',
    'budget'          => 'XXX',
  ]
];
```

最后，您需要循环遍历过滤器分配，呈现好的和坏的数据：

```php
foreach ($testData as $data) {
  foreach ($data as $field => $item) {
    foreach ($assignments['*'] as $key => $option) {
      $item = $filter$key;
    }
    foreach ($assignments[$field] as $key => $option) {
      $item = $filter$key;
    }
    printf("%16s : %s\n", $field, $item);
  }
}
```

这是此示例的输出可能如何出现的：

![工作原理...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-prog-cb/img/B05314_12_01.jpg)

请注意，名称已被截断，标签已被删除。 您还会注意到，尽管电子邮件地址已经被过滤，但它仍然不是一个有效的地址。 需要注意的是，为了正确处理数据，可能需要*验证*和过滤。

## 另请参阅

在第六章中，*构建可扩展的网站*，名为*链接$_POST 过滤器*的示例讨论了如何将此处介绍的基本过滤概念合并到全面的过滤器链接机制中。

# 验证$_POST 数据

过滤和验证之间的主要区别在于后者不会更改原始数据。 另一个区别在于意图。 验证的目的是确认数据是否符合根据客户需求建立的某些标准。

## 如何做...

1.  我们将在这里介绍的基本验证机制与前面的示例相同。 与过滤一样，了解要验证的数据的性质，它如何符合客户的要求，以及它是否符合数据库强制执行的标准是至关重要的。 例如，如果在数据库中，列的最大宽度为 128，则验证回调可以使用`strlen()`来确认提交的数据的长度是否小于或等于 128 个字符。 同样，您可以使用`ctype_alnum()`来确认数据是否只包含适当的字母和数字。

1.  验证的另一个考虑因素是提供适当的验证失败消息。 在某种意义上，验证过程也是一个*确认*过程，某人可能会审查验证以确认成功或失败。 如果验证失败，该人将需要知道失败的原因。

1.  对于本示例，我们将再次专注于`prospects`表。 现在，我们可以将一组所需的 PHP 函数集合到一个回调函数的数组中。 以下是基于表单数据的验证需求的示例，这些数据最终将存储在`prospects`表中：

```php
$validator = [
  'email' => [
    'callback' => function ($item) { 
      return filter_var($item, FILTER_VALIDATE_EMAIL); },
    'message'  => 'Invalid email address'],
  'alpha' => [
    'callback' => function ($item) { 
      return ctype_alpha(str_replace(' ', '', $item)); },
    'message'  => 'Data contains non-alpha characters'],
  'alnum' => [
    'callback' => function ($item) { 
      return ctype_alnum(str_replace(' ', '', $item)); },
    'message'  => 'Data contains characters which are '
       . 'not letters or numbers'],
  'digits' => [
    'callback' => function ($item) { 
      return preg_match('/[⁰-9.]/', $item); },
    'message'  => 'Data contains characters which '
      . 'are not numbers'],
  'length' => [
    'callback' => function ($item, $length) { 
      return strlen($item) <= $length; },
    'message'  => 'Item has too many characters'],
  'upper' => [
    'callback' => function ($item) { 
      return $item == strtoupper($item); },
    'message'  => 'Item is not upper case'],
  'phone' => [
    'callback' => function ($item) { 
      return preg_match('/[⁰-9() -+]/', $item); },
    'message'  => 'Item is not a valid phone number'],
];
```

### 注意

请注意，对于 alpha 和 alnum 回调，我们通过首先使用`str_replace()`来允许空格。 然后我们可以调用`ctype_alpha()`或`ctype_alnum()`，这将确定是否存在任何不允许的字符。

1.  接下来，我们定义一个分配数组，与`$_POST`中预期的字段名称匹配。 在此数组中，我们指定`$validator`数组中的键，以及任何参数：

```php
$assignments = [
  'first_name'    => ['length' => 32, 'alpha' => NULL],
  'last_name'     => ['length' => 32, 'alpha' => NULL],
  'address'       => ['length' => 64, 'alnum' => NULL],
  'city'          => ['length' => 32, 'alnum' => NULL],
  'state_province'=> ['length' => 20, 'alpha' => NULL],
  'postal_code'   => ['length' => 12, 'alnum' => NULL],
  'phone'         => ['length' => 12, 'phone' => NULL],
  'country'       => ['length' => 2, 'alpha' => NULL, 
                      'upper' => NULL],
  'email'         => ['length' => 128, 'email' => NULL],
  'budget'        => ['digits' => NULL],
];
```

1.  然后，我们使用嵌套的`foreach()`循环逐个字段地遍历数据块。 对于每个字段，我们循环遍历分配给该字段的回调函数：

```php
foreach ($data as $field => $item) {
  echo 'Processing: ' . $field . PHP_EOL;
  foreach ($assignments[$field] as $key => $option) {
    if ($validator[$key]'callback') {
        $message = 'OK';
    } else {
        $message = $validator[$key]['message'];
    }
    printf('%8s : %s' . PHP_EOL, $key, $message);
  }
}
```

### 提示

而不是直接回显输出，如所示，您可以记录验证成功/失败的结果，以便在以后向审阅人呈现。 此外，如第六章中所示，*构建可扩展的网站*，您可以将验证机制集成到表单中，显示验证消息与其匹配的表单元素旁边。

## 工作原理...

将步骤 3 到 5 中显示的代码放入名为`chap_12_post_data_validation_basic.php`的文件中。 您还需要定义一个数据数组，模拟将出现在`$_POST`中的数据。 在这种情况下，您使用前面示例中提到的两个数组，一个包含*好*数据，另一个包含*坏*数据。 最终输出应该看起来像这样：

![工作原理...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-prog-cb/img/B05314_12_02.jpg)

## 另请参阅

+   在第六章中，*构建可扩展的网站*，名为*链接$_POST 验证器*的示例讨论了如何将此处介绍的基本验证概念合并到全面的过滤器链接机制中。

# 保护 PHP 会话

PHP 会话机制非常简单。一旦使用`session_start()`或`php.ini session.autostart`设置开始会话，PHP 引擎会生成一个唯一的令牌，默认情况下通过 cookie 传递给用户。在后续请求中，当会话仍然被视为活动状态时，用户的浏览器（或等效物）再次通常通过 cookie 呈现会话标识符进行检查。然后，PHP 引擎使用此标识符定位服务器上的适当文件，并使用存储的信息填充`$_SESSION`。当会话标识符是识别返回的网站访问者的唯一手段时，存在巨大的安全问题。在本教程中，我们将介绍几种技术，这些技术将帮助您保护会话，从而大大提高网站的整体安全性。

## 如何做...

1.  首先，重要的是要认识到将会话作为唯一的身份验证手段可能是危险的。想象一下，当有效用户登录到您的网站时，您在`$_SESSION`中设置了一个`loggedIn`标志：

```php
session_start();
$loggedIn = $_SESSION['isLoggedIn'] ?? FALSE;
if (isset($_POST['login'])) {
  if ($_POST['username'] == // username lookup
      && $_POST['password'] == // password lookup) {
      $loggedIn = TRUE;
      $_SESSION['isLoggedIn'] = TRUE;
  }
}
```

1.  在您的程序逻辑中，如果`$_SESSION['isLoggedIn']`设置为`TRUE`，则允许用户查看敏感信息：

```php
<br>Secret Info
<br><?php if ($loggedIn) echo // secret information; ?>
```

1.  如果攻击者能够获取会话标识符，例如，通过成功执行的**跨站脚本**（**XSS**）攻击，他/她只需要将`PHPSESSID` cookie 的值设置为非法获取的值，他们现在被您的应用程序视为有效用户。

1.  缩小`PHPSESSID`有效时间窗口的一种快速简单方法是使用`session_regenerate_id()`。这个非常简单的命令生成一个新的会话标识符，使旧的会话标识符无效，保持会话数据完整，并对性能影响很小。此命令只能在会话开始后执行：

```php
session_start();
session_regenerate_id();
```

1.  另一个经常被忽视的技术是确保网站访问者有注销选项。然而，重要的是不仅使用`session_destroy()`销毁会话，还要取消`$_SESSION`数据并使会话 cookie 过期：

```php
session_unset();
session_destroy();
setcookie('PHPSESSID', 0, time() - 3600);
```

1.  另一种可以用来防止会话劫持的简单技术是开发网站访问者的指纹。实现这种技术的一种方法是收集与会话标识符不同的网站访问者的唯一信息。这些信息包括用户代理（即浏览器）、接受的语言和远程 IP 地址。您可以从这些信息中派生出一个简单的哈希，并将哈希存储在服务器上的一个单独文件中。下次用户访问网站时，如果您已经确定他们基于会话信息已登录，那么您可以通过匹配指纹进行二次验证：

```php
$remotePrint = md5($_SERVER['REMOTE_ADDR'] 
                   . $_SERVER['HTTP_USER_AGENT'] 
                   . $_SERVER['HTTP_ACCEPT_LANGUAGE']);
$printsMatch = file_exists(THUMB_PRINT_DIR . $remotePrint);
if ($loggedIn && !$printsMatch) {
    $info = 'SESSION INVALID!!!';
    error_log('Session Invalid: ' . date('Y-m-d H:i:s'), 0);
    // take appropriate action
}
```

### 注意

我们使用`md5()`作为快速哈希算法，非常适合内部使用。*不建议*在任何外部使用中使用`md5()`，因为它容易受到暴力攻击。

## 它是如何工作的...

为了演示会话的漏洞性，编写一个简单的登录脚本，成功登录后设置`$_SESSION[`'`isLoggedIn`'`] flag`。您可以将文件命名为`chap_12_session_hijack.php`：

```php
session_start();
$loggedUser = $_SESSION['loggedUser'] ?? '';
$loggedIn = $_SESSION['isLoggedIn'] ?? FALSE;
$username = 'test';
$password = 'password';
$info = 'You Can Now See Super Secret Information!!!';

if (isset($_POST['login'])) {
  if ($_POST['username'] == $username
      && $_POST['password'] == $password) {
        $loggedIn = TRUE;
        $_SESSION['isLoggedIn'] = TRUE;
        $_SESSION['loggedUser'] = $username;
        $loggedUser = $username;
  }
} elseif (isset($_POST['logout'])) {
  session_destroy();
}
```

然后，您可以添加显示简单登录表单的代码。要测试会话漏洞，请按照使用我们刚刚创建的`chap_12_session_hijack.php`文件的步骤：

1.  切换到包含文件的目录。

1.  运行`php -S localhost:8080`命令。

1.  使用一个浏览器，打开 URL `http://localhost:8080/<filename>`。

1.  使用用户名`test`和密码`password`登录。

1.  您应该能够看到**您现在可以查看超级秘密信息!!!**。

1.  刷新页面：每次都应该看到一个新的会话标识符。

1.  复制`PHPSESSID` cookie 的值。

1.  在同一个网页上用另一个浏览器打开。

1.  通过复制`PHPSESSID`的值修改浏览器发送的 cookie。

为了说明，我们还在以下截图中使用 Vivaldi 浏览器显示了`$_COOKIE`和`$_SESSION`的值：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-prog-cb/img/B05314_12_03.jpg)

然后我们复制`PHPSESSID`的值，打开 Firefox 浏览器，并使用一个名为 Tamper Data 的工具来修改 cookie 的值：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-prog-cb/img/B05314_12_04.jpg)

您可以在下一个截图中看到，我们现在是经过身份验证的用户，而无需输入用户名或密码：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-prog-cb/img/B05314_12_05.jpg)

现在，您可以实施前面步骤中讨论的更改。将先前创建的文件复制到`chap_12_session_protected.php`。现在继续重新生成会话 ID：

```php
<?php
define('THUMB_PRINT_DIR', __DIR__ . '/../data/');
session_start();
session_regenerate_id();
```

接下来，初始化变量并确定登录状态（与以前一样）：

```php
$username = 'test';
$password = 'password';
$info = 'You Can Now See Super Secret Information!!!';
$loggedIn = $_SESSION['isLoggedIn'] ?? FALSE;
$loggedUser = $_SESSION['user'] ?? 'guest';
```

您可以使用远程地址、用户代理和语言设置添加会话指纹：

```php
$remotePrint = md5($_SERVER['REMOTE_ADDR']
  . $_SERVER['HTTP_USER_AGENT']
  . $_SERVER['HTTP_ACCEPT_LANGUAGE']);
$printsMatch = file_exists(THUMB_PRINT_DIR . $remotePrint);
```

如果登录成功，我们将会话中的指纹信息和登录状态存储起来：

```php
if (isset($_POST['login'])) {
  if ($_POST['username'] == $username
      && $_POST['password'] == $password) {
        $loggedIn = TRUE;
        $_SESSION['user'] = strip_tags($username);
        $_SESSION['isLoggedIn'] = TRUE;
        file_put_contents(
          THUMB_PRINT_DIR . $remotePrint, $remotePrint);
  }
```

您还可以检查注销选项并实施适当的注销过程：取消设置`$_SESSION`变量，使会话无效，并使 cookie 过期。您还可以删除指纹文件并实施重定向：

```php
} elseif (isset($_POST['logout'])) {
  session_unset();
  session_destroy();
  setcookie('PHPSESSID', 0, time() - 3600);
  if (file_exists(THUMB_PRINT_DIR . $remotePrint)) 
    unlink(THUMB_PRINT_DIR . $remotePrint);
    header('Location: ' . $_SERVER['REQUEST_URI'] );
  exit;
```

否则，如果操作不是登录或注销，您可以检查用户是否被视为已登录，如果指纹不匹配，则会话被视为无效，并采取适当的操作：

```php
} elseif ($loggedIn && !$printsMatch) {
    $info = 'SESSION INVALID!!!';
    error_log('Session Invalid: ' . date('Y-m-d H:i:s'), 0);
    // take appropriate action
}
```

现在，您可以使用新的`chap_12_session_protected.php`文件运行与之前提到的相同的过程。您将首先注意到的是会话现在被视为无效。输出将类似于这样：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-prog-cb/img/B05314_12_06.jpg)

原因是指纹不匹配，因为您现在正在使用不同的浏览器。同样，如果您刷新第一个浏览器的页面，会话标识符将被重新生成，使任何先前复制的标识符都将变得过时。最后，注销按钮将完全清除会话信息。

## 另请参阅

有关网站漏洞的出色概述，请参阅[`www.owasp.org/index.php/Category:Vulnerability`](https://www.owasp.org/index.php/Category:Vulnerability)上的文章。有关会话劫持的信息，请参阅[`www.owasp.org/index.php/Session_hijacking_attack`](https://www.owasp.org/index.php/Session_hijacking_attack)。

# 使用令牌保护表单

这个配方提供了另一种非常简单的技术，可以保护您的表单免受**跨站点请求伪造**（**CSRF**）攻击。简而言之，当攻击者可能使用其他技术时，可以在您网站上的网页上感染一个 CSRF 攻击。在大多数情况下，受感染的页面将开始发出请求（即使用 JavaScript 购买物品或进行设置更改）使用有效的已登录用户的凭据。您的应用程序极其难以检测到这种活动。可以采取的一个措施是生成一个随机令牌，该令牌包含在要提交的每个表单中。由于受感染的页面将无法访问令牌，也无法生成与之匹配的令牌，因此表单验证将失败。

## 如何做...

1.  首先，为了演示问题，我们创建一个模拟受感染页面的网页，该页面生成一个请求以将条目发布到数据库。为此示例，我们将文件命名为`chap_12_form_csrf_test_unprotected.html`：

```php
<!DOCTYPE html>
  <body onload="load()">
  <form action="/chap_12_form_unprotected.php" 
    method="post" id="csrf_test" name="csrf_test">
    <input name="name" type="hidden" value="No Goodnick" />
    <input name="email" type="hidden" value="malicious@owasp.org" />
    <input name="comments" type="hidden" 
       value="Form is vulnerable to CSRF attacks!" />
    <input name="process" type="hidden" value="1" />
  </form>
  <script>
    function load() { document.forms['csrf_test'].submit(); }
  </script>
</body>
</html>
```

1.  接下来，我们创建一个名为`chap_12_form_unprotected.php`的脚本，用于响应表单提交。与本书中的其他调用程序一样，我们设置自动加载并使用第五章中介绍的`Application\Database\Connection`类，*与数据库交互*。

```php
<?php
define('DB_CONFIG_FILE', '/../config/db.config.php');
require __DIR__ . '/../Application/Autoload/Loader.php';
Application\Autoload\Loader::init(__DIR__ . '/..');
use Application\Database\Connection;
$conn = new Connection(include __DIR__ . DB_CONFIG_FILE);
```

1.  然后我们检查处理按钮是否已被按下，并实施一个过滤机制，如本章中*过滤$_POST 数据*食谱中所述。这是为了证明 CSRF 攻击很容易绕过过滤器：

```php
if ($_POST['process']) {
    $filter = [
      'trim' => function ($item) { return trim($item); },
      'email' => function ($item) { 
        return filter_var($item, FILTER_SANITIZE_EMAIL); },
      'length' => function ($item, $length) { 
        return substr($item, 0, $length); },
      'stripTags' => function ($item) { 
      return strip_tags($item); },
  ];

  $assignments = [
    '*'         => ['trim' => NULL, 'stripTags' => NULL],
    'email'   => ['length' => 249, 'email' => NULL],
    'name'    => ['length' => 128],
    'comments'=> ['length' => 249],
  ];

  $data = $_POST;
  foreach ($data as $field => $item) {
    foreach ($assignments['*'] as $key => $option) {
      $item = $filter$key;
    }
    if (isset($assignments[$field])) {
      foreach ($assignments[$field] as $key => $option) {
        $item = $filter$key;
      }
      $filteredData[$field] = $item;
    }
  }
```

1.  最后，我们使用预处理语句将过滤后的数据插入数据库。然后重定向到另一个名为`chap_12_form_view_results.php`的脚本，该脚本简单地转储`visitors`表的内容：

```php
try {
    $filteredData['visit_date'] = date('Y-m-d H:i:s');
    $sql = 'INSERT INTO visitors '
        . ' (email,name,comments,visit_date) '
        . 'VALUES (:email,:name,:comments,:visit_date)';
    $insertStmt = $conn->pdo->prepare($sql);
    $insertStmt->execute($filteredData);
} catch (PDOException $e) {
    echo $e->getMessage();
}
}
header('Location: /chap_12_form_view_results.php');
exit;
```

1.  当然，结果是，尽管进行了过滤并使用了预处理语句，攻击仍然被允许。

1.  实际上，实现表单保护令牌非常容易！首先，您需要生成令牌并将其存储在会话中。我们利用新的`random_bytes()` PHP 7 函数来生成一个真正随机的令牌，这个令牌对于攻击者来说将是困难的，如果不是不可能的匹配：

```php
session_start();
$token = urlencode(base64_encode((random_bytes(32))));
$_SESSION['token'] = $token;
```

### 注意

`random_bytes()`的输出是二进制的。我们使用`base64_encode()`将其转换为可用的字符串。然后我们使用`urlencode()`进一步处理它，以便在 HTML 表单中正确呈现。

1.  当我们呈现表单时，我们将令牌呈现为隐藏字段：

```php
<input type="hidden" name="token" value="<?= $token ?>" />
```

1.  然后，我们复制并修改先前提到的`chap_12_form_unprotected.php`脚本，添加逻辑来首先检查会话中存储的令牌是否匹配。请注意，我们取消当前令牌以使其对将来的使用无效。我们将新脚本命名为`chap_12_form_protected_with_token.php`：

```php
if ($_POST['process']) {
    $sessToken = $_SESSION['token'] ?? 1;
    $postToken = $_POST['token'] ?? 2;
    unset($_SESSION['token']);
    if ($sessToken != $postToken) {
        $_SESSION['message'] = 'ERROR: token mismatch';
    } else {
        $_SESSION['message'] = 'SUCCESS: form processed';
        // continue with form processing
    }
}
```

## 它是如何工作的...

为了测试感染的网页如何发起 CSRF 攻击，创建以下文件，如前面的示例所示：

+   `chap_12_form_csrf_test_unprotected.html`

+   `chap_12_form_unprotected.php`

然后，您可以定义一个名为`chap_12_form_view_results.php`的文件，其中转储`visitors`表的内容：

```php
<?php
session_start();
define('DB_CONFIG_FILE', '/../config/db.config.php');
require __DIR__ . '/../Application/Autoload/Loader.php';
Application\Autoload\Loader::init(__DIR__ . '/..');
use Application\Database\Connection;
$conn = new Connection(include __DIR__ . DB_CONFIG_FILE);
$message = $_SESSION['message'] ?? '';
unset($_SESSION['message']);
$stmt = $conn->pdo->query('SELECT * FROM visitors');
?>
<!DOCTYPE html>
<body>
<div class="container">
  <h1>CSRF Protection</h1>
  <h3>Visitors Table</h3>
  <?php while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) : ?>
  <pre><?php echo implode(':', $row); ?></pre>
  <?php endwhile; ?>
  <?php if ($message) : ?>
  <b><?= $message; ?></b>
  <?php endif; ?>
</div>
</body>
</html>
```

从浏览器中启动`chap_12_form_csrf_test_unprotected.html`。以下是输出可能会出现的样子：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-prog-cb/img/B05314_12_07.jpg)

正如您所看到的，尽管进行了过滤并使用了预处理语句，攻击仍然成功！

接下来，将`chap_12_form_unprotected.php`文件复制到`chap_12_form_protected.php`。按照食谱中的第 8 步所示进行更改。您还需要修改测试 HTML 文件，将`chap_12_form_csrf_test_unprotected.html`复制到`chap_12_form_csrf_test_protected.html`。将`FORM`标签中的 action 参数的值更改如下：

```php
<form action="/chap_12_form_protected_with_token.php" 
  method="post" id="csrf_test" name="csrf_test">
```

当您从浏览器运行新的 HTML 文件时，它会调用`chap_12_form_protected.php`，该文件寻找一个不存在的令牌。以下是预期的输出：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-prog-cb/img/B05314_12_08.jpg)

最后，继续定义一个名为`chap_12_form_protected.php`的文件，生成一个令牌并将其显示为隐藏元素：

```php
<?php
session_start();
$token = urlencode(base64_encode((random_bytes(32))));
$_SESSION['token'] = $token;
?>
<!DOCTYPE html>
<body onload="load()">
<div class="container">
<h1>CSRF Protected Form</h1>
<form action="/chap_12_form_protected_with_token.php" 
     method="post" id="csrf_test" name="csrf_test">
<table>
<tr><th>Name</th><td><input name="name" type="text" /></td></tr>
<tr><th>Email</th><td><input name="email" type="text" /></td></tr>
<tr><th>Comments</th><td>
<input name="comments" type="textarea" rows=4 cols=80 />
</td></tr>
<tr><th>&nbsp;</th><td>
<input name="process" type="submit" value="Process" />
</td></tr>
</table>
<input type="hidden" name="token" value="<?= $token ?>" />
</form>
<a href="/chap_12_form_view_results.php">
    CLICK HERE</a> to view results
</div>
</body>
</html>
```

当我们显示并提交表单中的数据时，将验证令牌并允许数据插入继续进行，如下所示：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-prog-cb/img/B05314_12_09.jpg)

## 另请参阅

有关 CSFR 攻击的更多信息，请参阅[`www.owasp.org/index.php/Cross-Site_Request_Forgery_(CSRF)`](https://www.owasp.org/index.php/Cross-Site_Request_Forgery_(CSRF))。

# 构建一个安全的密码生成器

一个常见的误解是，攻击者破解哈希密码的唯一方法是使用**暴力攻击**和**彩虹表**。虽然这通常是攻击序列中的第一步，但攻击者会在第二、第三或第四步使用更复杂的攻击。其他攻击包括*组合*、*字典*、*掩码*和基于规则的攻击。字典攻击使用来自字典的单词数据库来猜测密码。组合是指组合字典中的单词。掩码攻击类似于暴力攻击，但更有选择性，因此缩短了破解时间。基于规则的攻击将检测诸如用数字 0 替换字母 o 之类的事情。

好消息是，通过简单地增加密码长度超过六个字符的长度，可以指数级增加破解哈希密码所需的时间。其他因素，例如随机将大写字母与小写字母交错、随机数字和特殊字符，也会对破解所需的时间产生指数影响。最终，我们需要牢记的是，最终需要有人输入创建的密码，这意味着密码至少需要稍微记忆。

### 提示

**最佳实践**

密码应该以哈希形式存储，而不是明文。MD5 和 SHA*不再被认为是安全的（尽管 SHA*比 MD5 好得多）。使用诸如`oclHashcat`之类的实用程序，攻击者可以在密码使用 MD5 哈希后通过漏洞（即成功的 SQL 注入攻击）生成平均每秒 55 亿次尝试。

## 如何做...

1.  首先，我们定义一个`Application\Security\PassGen`类，该类将包含生成密码所需的方法。我们还定义了一些类常量和属性，这些常量和属性将作为流程的一部分使用：

```php
namespace Application\Security;
class PassGen
{
  const SOURCE_SUFFIX = 'src';
  const SPECIAL_CHARS = 
    '\`¬|!"£$%^&*()_-+={}[]:@~;\'#<>?,./|\\';
  protected $algorithm;
  protected $sourceList;
  protected $word;
  protected $list;
```

1.  然后我们定义将用于生成密码的低级方法。正如名称所示，`digits()`生成随机数字，`special()`从`SPECIAL_CHARS`类常量中生成一个字符：

```php
public function digits($max = 999)
{
  return random_int(1, $max);
}

public function special()
{
  $maxSpecial = strlen(self::SPECIAL_CHARS) - 1;
  return self::SPECIAL_CHARS[random_int(0, $maxSpecial)];
}
```

### 注意

请注意，在此示例中，我们经常使用新的 PHP 7 函数`random_int()`。尽管稍慢，但与更陈旧的`rand()`函数相比，这种方法提供了真正的**密码安全伪随机数生成器**（**CSPRNG**）功能。

1.  现在是棘手的部分：生成一个难以猜测的单词。这就是`$wordSource`构造函数参数发挥作用的地方。它是一个网站数组，我们的单词库将从中派生。因此，我们需要一个方法，该方法将从指定的来源中提取一个唯一的单词列表，并将结果存储在文件中。我们将`$wordSource`数组作为参数接受，并循环遍历每个 URL。我们使用`md5()`生成网站名称的哈希值，然后将其构建成文件名。然后将新生成的文件名存储在`$sourceList`中：

```php
public function processSource(
$wordSource, $minWordLength, $cacheDir)
{
  foreach ($wordSource as $html) {
    $hashKey = md5($html);
    $sourceFile = $cacheDir . '/' . $hashKey . '.' 
    . self::SOURCE_SUFFIX;
    $this->sourceList[] = $sourceFile;
```

1.  如果文件不存在或为空字节，我们处理内容。如果来源是 HTML，我们只接受`<body>`标签内的内容。然后我们使用`str_word_count()`从字符串中提取单词列表，同时使用`strip_tags()`去除任何标记：

```php
if (!file_exists($sourceFile) || filesize($sourceFile) == 0) {
    echo 'Processing: ' . $html . PHP_EOL;
    $contents = file_get_contents($html);
    if (preg_match('/<body>(.*)<\/body>/i', 
        $contents, $matches)) {
        $contents = $matches[1];
    }
    $list = str_word_count(strip_tags($contents), 1);
```

1.  然后我们删除任何太短的单词，并使用`array_unique()`去除重复项。最终结果存储在文件中：

```php
     foreach ($list as $key => $value) {
       if (strlen($value) < $minWordLength) {
         $list[$key] = 'xxxxxx';
       } else {
         $list[$key] = trim($value);
       }
     }
     $list = array_unique($list);
     file_put_contents($sourceFile, implode("\n",$list));
   }
  }
  return TRUE;
}
```

1.  接下来，我们定义一个*翻转*单词中随机字母为大写的方法：

```php
public function flipUpper($word)
{
  $maxLen   = strlen($word);
  $numFlips = random_int(1, $maxLen - 1);
  $flipped  = strtolower($word);
  for ($x = 0; $x < $numFlips; $x++) {
       $pos = random_int(0, $maxLen - 1);
       $word[$pos] = strtoupper($word[$pos]);
  }
  return $word;
}
```

1.  最后，我们准备定义一个从我们的来源选择单词的方法。我们随机选择一个单词来源，并使用`file()`函数从适当的缓存文件中读取：

```php
public function word()
{
  $wsKey    = random_int(0, count($this->sourceList) - 1);
  $list     = file($this->sourceList[$wsKey]);
  $maxList  = count($list) - 1;
  $key      = random_int(0, $maxList);
  $word     = $list[$key];
  return $this->flipUpper($word);
}
```

1.  为了不总是生成相同模式的密码，我们定义了一个方法，允许我们将密码的各个组件放置在最终密码字符串的不同位置。算法被定义为此类中可用的方法调用数组。例如，一个`['word', 'digits', 'word', 'special']`的算法最终可能看起来像`hElLo123aUTo!`：

```php
public function initAlgorithm()
{
  $this->algorithm = [
    ['word', 'digits', 'word', 'special'],
    ['digits', 'word', 'special', 'word'],
    ['word', 'word', 'special', 'digits'],
    ['special', 'word', 'special', 'digits'],
    ['word', 'special', 'digits', 'word', 'special'],
    ['special', 'word', 'special', 'digits', 
    'special', 'word', 'special'],
  ];
}
```

1.  构造函数接受单词来源数组、最小单词长度和缓存目录的位置。然后处理源文件并初始化算法：

```php
public function __construct(
  array $wordSource, $minWordLength, $cacheDir)
{
  $this->processSource($wordSource, $minWordLength, $cacheDir);
  $this->initAlgorithm();
}
```

1.  最后，我们能够定义实际生成密码的方法。它只需要随机选择一个算法，然后循环调用适当的方法：

```php
public function generate()
{
  $pwd = '';
  $key = random_int(0, count($this->algorithm) - 1);
  foreach ($this->algorithm[$key] as $method) {
    $pwd .= $this->$method();
  }
  return str_replace("\n", '', $pwd);
}

}
```

## 工作原理...

首先，您需要将前面一篇文章中描述的代码放入`Application\Security`文件夹中名为`PassGen.php`的文件中。现在您可以创建一个名为`chap_12_password_generate.php`的调用程序，设置自动加载，使用`PassGen`，并定义缓存目录的位置：

```php
<?php
define('CACHE_DIR', __DIR__ . '/cache');
require __DIR__ . '/../Application/Autoload/Loader.php';
Application\Autoload\Loader::init(__DIR__ . '/..');
use Application\Security\PassGen;
```

接下来，您需要定义一个网站数组，用作密码生成中的单词库的来源。在这个例子中，我们将从 Project Gutenberg 的文本《尤利西斯》（J.乔伊斯）、《战争与和平》（L.托尔斯泰）和《傲慢与偏见》（J.奥斯汀）中进行选择：

```php
$source = [
  'https://www.gutenberg.org/files/4300/4300-0.txt',
  'https://www.gutenberg.org/files/2600/2600-h/2600-h.htm',
  'https://www.gutenberg.org/files/1342/1342-h/1342-h.htm',
];
```

接下来，我们创建`PassGen`实例，并运行`generate()`：

```php
$passGen = new PassGen($source, 4, CACHE_DIR);
echo $passGen->generate();
```

以下是`PassGen`生成的一些示例密码：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-prog-cb/img/B05314_12_10.jpg)

## 另请参阅

关于攻击者如何破解密码的优秀文章可以在[`arstechnica.com/security/2013/05/how-crackers-make-minced-meat-out-of-your-passwords/`](http://arstechnica.com/security/2013/05/how-crackers-make-minced-meat-out-of-your-passwords/)上查看。要了解更多关于暴力破解攻击的信息，您可以参考[`www.owasp.org/index.php/Brute_force_attack`](https://www.owasp.org/index.php/Brute_force_attack)。有关`oclHashcat`的信息，请参阅此页面：[`hashcat.net/oclhashcat/`](http://hashcat.net/oclhashcat/)。

# 使用 CAPTCHA 保护表单

**CAPTCHA**实际上是**Completely Automated Public Turing Test to Tell Computers and Humans Apart**的缩写。这种技术类似于前面的配方“使用令牌保护表单”。不同之处在于，它不是将令牌存储在隐藏的表单输入字段中，而是将令牌呈现为对自动攻击系统难以解密的图形。此外，CAPTCHA 的目的与表单令牌略有不同：它旨在确认网页访问者是人类，而不是自动系统。

## 操作步骤...

1.  CAPTCHA 有几种方法：基于只有人类才会知道的知识提出问题，文本技巧和需要解释的图形图像。

1.  图像方法向网页访问者展示了一个带有严重扭曲的字母和/或数字的图像。然而，这种方法可能会很复杂，因为它依赖于 GD 扩展，而并非所有服务器都可用。GD 扩展可能很难编译，并且对主机服务器上必须存在的各种库有很重的依赖。

1.  文本方法是呈现一系列字母和/或数字，并给网页访问者一个简单的指令，比如“请将这个倒过来输入”。另一种变化是使用 ASCII“艺术”来形成人类网页访问者能够解释的字符。

1.  最后，您可能会有一个问题/答案方法，例如“头部是由什么身体部位连接到身体上”，并且有答案如“手臂”、“腿”和“脖子”。这种方法的缺点是自动攻击系统有三分之一的机会通过测试。

### 生成文本 CAPTCHA

1.  在这个例子中，我们将从文本方法开始，然后再使用图像方法。无论哪种情况，我们首先需要定义一个生成要呈现的短语（并由网页访问者解码）的类。为此，我们定义一个`Application\Captcha\Phrase`类。我们还定义了在短语生成过程中使用的属性和类常量：

```php
namespace Application\Captcha;
class Phrase
{
  const DEFAULT_LENGTH   = 5;
  const DEFAULT_NUMBERS  = '0123456789';
  const DEFAULT_UPPER    = 'ABCDEFGHJKLMNOPQRSTUVWXYZ';
  const DEFAULT_LOWER    = 'abcdefghijklmnopqrstuvwxyz';
  const DEFAULT_SPECIAL  = 
    '¬\`|!"£$%^&*()_-+={}[]:;@\'~#<,>.?/|\\';
  const DEFAULT_SUPPRESS = ['O','l'];

  protected $phrase;
  protected $includeNumbers;
  protected $includeUpper;
  protected $includeLower;
  protected $includeSpecial;
  protected $otherChars;
  protected $suppressChars;
  protected $string;
  protected $length;
```

1.  构造函数如您所期望的那样，接受各种属性的值，分配默认值，以便可以创建一个实例而无需指定任何参数。`$include*`标志用于表示将在生成短语的基本字符串中存在哪些字符集。例如，如果您只希望有数字，则`$includeUpper`和`$includeLower`都将设置为`FALSE`。`$otherChars`提供了额外的灵活性。最后，`$suppressChars`表示将从基本字符串中删除的字符数组。默认情况下，删除大写字母`O`和小写字母`l`：

```php
public function __construct(
  $length = NULL,
  $includeNumbers = TRUE,
  $includeUpper= TRUE,
  $includeLower= TRUE,
  $includeSpecial = FALSE,
  $otherChars = NULL,
  array $suppressChars = NULL)
  {
    $this->length = $length ?? self::DEFAULT_LENGTH;
    $this->includeNumbers = $includeNumbers;
    $this->includeUpper = $includeUpper;
    $this->includeLower = $includeLower;
    $this->includeSpecial = $includeSpecial;
    $this->otherChars = $otherChars;
    $this->suppressChars = $suppressChars 
      ?? self::DEFAULT_SUPPRESS;
    $this->phrase = $this->generatePhrase();
  }
```

1.  然后，我们定义一系列的 getter 和 setter，每个属性都有一个。请注意，为了节省空间，我们只显示前两个。

```php
public function getString()
{
  return $this->string;
}

public function setString($string)
{
  $this->string = $string;
}

// other getters and setters not shown
```

1.  接下来，我们需要定义一个初始化基本字符串的方法。这由一系列简单的 if 语句组成，检查各种`$include*`标志并根据需要附加到基本字符串。最后，我们使用`str_replace()`来删除`$suppressChars`中表示的字符：

```php
public function initString()
{
  $string = '';
  if ($this->includeNumbers) {
      $string .= self::DEFAULT_NUMBERS;
  }
  if ($this->includeUpper) {
      $string .= self::DEFAULT_UPPER;
  }
  if ($this->includeLower) {
      $string .= self::DEFAULT_LOWER;
  }
  if ($this->includeSpecial) {
      $string .= self::DEFAULT_SPECIAL;
  }
  if ($this->otherChars) {
      $string .= $this->otherChars;
  }
  if ($this->suppressChars) {
      $string = str_replace(
        $this->suppressChars, '', $string);
  }
  return $string;
}
```

### 提示

**最佳实践**

摆脱可能与数字混淆的字母（即，字母`O`可能与数字`0`混淆，小写字母`l`可能与数字`1`混淆。

1.  现在我们准备定义生成随机短语的核心方法，这是验证码呈现给网站访问者的。我们设置一个简单的`for()`循环，并使用新的 PHP 7 `random_int()`函数在基本字符串中跳转：

```php
public function generatePhrase()
{
  $phrase = '';
  $this->string = $this->initString();
  $max = strlen($this->string) - 1;
  for ($x = 0; $x < $this->length; $x++) {
    $phrase .= substr(
      $this->string, random_int(0, $max), 1);
  }
  return $phrase;
}
}
```

1.  现在我们将注意力从短语转移到将生成文本验证码的类上。为此，我们首先定义一个接口，以便将来可以创建额外的验证码类，所有这些类都使用`Application\Captcha\Phrase`。请注意，`getImage()`将返回文本、文本艺术或实际图像，具体取决于我们决定使用哪个类：

```php
namespace Application\Captcha;
interface CaptchaInterface
{
  public function getLabel();
  public function getImage();
  public function getPhrase();
}
```

1.  对于文本验证码，我们定义了一个`Application\Captcha\Reverse`类。这个名字的原因是这个类不仅产生文本，而且是反向的文本。`__construct()`方法构建了一个`Phrase`的实例。请注意，`getImage()`以反向返回短语：

```php
namespace Application\Captcha;
class Reverse implements CaptchaInterface
{
  const DEFAULT_LABEL = 'Type this in reverse';
  const DEFAULT_LENGTH = 6;
  protected $phrase;
  public function __construct(
    $label  = self::DEFAULT_LABEL,
    $length = self:: DEFAULT_LENGTH,
    $includeNumbers = TRUE,
    $includeUpper   = TRUE,
    $includeLower   = TRUE,
    $includeSpecial = FALSE,
    $otherChars     = NULL,
    array $suppressChars = NULL)
  {
    $this->label  = $label;
    $this->phrase = new Phrase(
      $length, 
      $includeNumbers, 
      $includeUpper,
      $includeLower, 
      $includeSpecial, 
      $otherChars, 
      $suppressChars);
    }

  public function getLabel()
  {
    return $this->label;
  }

  public function getImage()
  {
    return strrev($this->phrase->getPhrase());
  }

  public function getPhrase()
  {
    return $this->phrase->getPhrase();
  }

}
```

### 生成图像验证码

1.  正如你可以想象的那样，图像方法要复杂得多。短语生成过程是相同的。主要区别在于，我们不仅需要在图形上印刷短语，还需要以不同的方式扭曲每个字母，并引入随机点的噪音。

1.  我们定义了一个实现`CaptchaInterface`的`Application\Captcha\Image`类。该类的常量和属性不仅包括短语生成所需的内容，还包括图像生成所需的内容：

```php
namespace Application\Captcha;
use DirectoryIterator;
class Image implements CaptchaInterface
{

  const DEFAULT_WIDTH = 200;
  const DEFAULT_HEIGHT = 50;
  const DEFAULT_LABEL = 'Enter this phrase';
  const DEFAULT_BG_COLOR = [255,255,255];
  const DEFAULT_URL = '/captcha';
  const IMAGE_PREFIX = 'CAPTCHA_';
  const IMAGE_SUFFIX = '.jpg';
  const IMAGE_EXP_TIME = 300;    // seconds
  const ERROR_REQUIRES_GD = 'Requires the GD extension + '
    .  ' the JPEG library';
  const ERROR_IMAGE = 'Unable to generate image';

  protected $phrase;
  protected $imageFn;
  protected $label;
  protected $imageWidth;
  protected $imageHeight;
  protected $imageRGB;
  protected $imageDir;
  protected $imageUrl;
```

1.  构造函数需要接受前面步骤中描述的短语生成所需的所有参数。此外，我们还需要接受图像生成所需的参数。两个必需参数是`$imageDir`和`$imageUrl`。第一个是图形将被写入的位置。第二个是基本 URL，之后我们将附加生成的文件名。如果我们想提供 TrueType 字体，可以提供`$imageFont`，这将产生更安全的验证码。否则，我们只能使用默认字体，引用一部著名电影中的一句台词，*不是一道美丽的风景*：

```php
public function __construct(
  $imageDir,
  $imageUrl,
  $imageFont = NULL,
  $label = NULL,
  $length = NULL,
  $includeNumbers = TRUE,
  $includeUpper= TRUE,
  $includeLower= TRUE,
  $includeSpecial = FALSE,
  $otherChars = NULL,
  array $suppressChars = NULL,
  $imageWidth = NULL,
  $imageHeight = NULL,
  array $imageRGB = NULL
)
{
```

1.  接下来，在构造函数中，我们检查`imagecreatetruecolor`函数是否存在。如果返回`FALSE`，我们知道 GD 扩展不可用。否则，我们将参数分配给属性，生成短语，删除旧图像，并写出验证码图形：

```php
if (!function_exists('imagecreatetruecolor')) {
    throw new \Exception(self::ERROR_REQUIRES_GD);
}
$this->imageDir   = $imageDir;
$this->imageUrl   = $imageUrl;
$this->imageFont  = $imageFont;
$this->label      = $label ?? self::DEFAULT_LABEL;
$this->imageRGB   = $imageRGB ?? self::DEFAULT_BG_COLOR;
$this->imageWidth = $imageWidth ?? self::DEFAULT_WIDTH;
$this->imageHeight= $imageHeight ?? self::DEFAULT_HEIGHT;
if (substr($imageUrl, -1, 1) == '/') {
    $imageUrl = substr($imageUrl, 0, -1);
}
$this->imageUrl = $imageUrl;
if (substr($imageDir, -1, 1) == DIRECTORY_SEPARATOR) {
    $imageDir = substr($imageDir, 0, -1);
}

$this->phrase = new Phrase(
  $length, 
  $includeNumbers, 
  $includeUpper,
  $includeLower, 
  $includeSpecial, 
  $otherChars, 
  $suppressChars);
$this->removeOldImages();
$this->generateJpg();
}
```

1.  删除旧图像的过程非常重要；否则我们最终会得到一个充满过期验证码图像的目录！我们使用`DirectoryIterator`类来扫描指定目录并检查访问时间。我们将旧图像文件定义为当前时间减去`IMAGE_EXP_TIME`指定值的文件：

```php
public function removeOldImages()
{
  $old = time() - self::IMAGE_EXP_TIME;
  foreach (new DirectoryIterator($this->imageDir) 
           as $fileInfo) {
    if($fileInfo->isDot()) continue;
    if ($fileInfo->getATime() < $old) {
      unlink($this->imageDir . DIRECTORY_SEPARATOR 
             . $fileInfo->getFilename());
    }
  }
}
```

1.  现在我们准备转向主要内容。首先，我们将`$imageRGB`数组分成`$red`、`$green`和`$blue`。我们使用核心的`imagecreatetruecolor()`函数生成指定宽度和高度的基本图形。我们使用 RGB 值对背景进行着色：

```php
public function generateJpg()
{
  try {
      list($red,$green,$blue) = $this->imageRGB;
      $im = imagecreatetruecolor(
        $this->imageWidth, $this->imageHeight);
      $black = imagecolorallocate($im, 0, 0, 0);
      $imageBgColor = imagecolorallocate(
        $im, $red, $green, $blue);
      imagefilledrectangle($im, 0, 0, $this->imageWidth, 
        $this->imageHeight, $imageBgColor);
```

1.  接下来，我们根据图像宽度和高度定义*x*和*y*边距。然后，我们初始化要用于将短语写入图形的变量。然后我们循环多次，次数与短语的长度相匹配：

```php
$xMargin = (int) ($this->imageWidth * .1 + .5);
$yMargin = (int) ($this->imageHeight * .3 + .5);
$phrase = $this->getPhrase();
$max = strlen($phrase);
$count = 0;
$x = $xMargin;
$size = 5;
for ($i = 0; $i < $max; $i++) {
```

1.  如果指定了`$imageFont`，我们可以使用不同的大小和角度写入每个字符。我们还需要根据大小调整*x*轴（即水平）的值：

```php
if ($this->imageFont) {
    $size = rand(12, 32);
    $angle = rand(0, 30);
    $y = rand($yMargin + $size, $this->imageHeight);
    imagettftext($im, $size, $angle, $x, $y, $black, 
      $this->imageFont, $phrase[$i]);
    $x += (int) ($size  + rand(0,5));
```

1.  否则，我们将被默认字体所困扰。我们使用最大尺寸的`5`，因为较小的尺寸是不可读的。我们通过交替使用`imagechar()`（正常写入图像）和`imagecharup()`（侧向写入）来提供低级别的扭曲：

```php
} else {
    $y = rand(0, ($this->imageHeight - $yMargin));
    if ($count++ & 1) {
        imagechar($im, 5, $x, $y, $phrase[$i], $black);
    } else {
        imagecharup($im, 5, $x, $y, $phrase[$i], $black);
    }
    $x += (int) ($size * 1.2);
  }
} // end for ($i = 0; $i < $max; $i++)
```

1.  接下来，我们需要添加随机点的噪音。这是必要的，以使图像对自动化系统更难以检测。建议您也添加代码来绘制一些线条：

```php
$numDots = rand(10, 999);
for ($i = 0; $i < $numDots; $i++) {
  imagesetpixel($im, rand(0, $this->imageWidth), 
    rand(0, $this->imageHeight), $black);
}
```

1.  然后，我们使用我们的老朋友`md5()`创建一个随机图像文件名，其中日期和从`0`到`9999`的随机数作为参数。请注意，我们可以安全地使用`md5()`，因为我们并不试图隐藏任何秘密信息；我们只是想快速生成一个唯一的文件名。我们也清除图像对象以节省内存：

```php
$this->imageFn = self::IMAGE_PREFIX 
. md5(date('YmdHis') . rand(0,9999)) 
. self::IMAGE_SUFFIX;
imagejpeg($im, $this->imageDir . DIRECTORY_SEPARATOR 
. $this->imageFn);
imagedestroy($im);
```

1.  整个结构都在一个`try/catch`块中。如果发生错误或异常，我们会记录消息并采取适当的措施：

```php
} catch (\Throwable $e) {
    error_log(__METHOD__ . ':' . $e->getMessage());
    throw new \Exception(self::ERROR_IMAGE);
}
}
```

1.  最后，我们定义接口所需的方法。请注意，`getImage()`返回一个 HTML `<img>`标签，然后可以立即显示：

```php
public function getLabel()
{
  return $this->label;
}

public function getImage()
{
  return sprintf('<img src="%s/%s" />', 
    $this->imageUrl, $this->imageFn);
}

public function getPhrase()
{
  return $this->phrase->getPhrase();
}

}
```

## 它是如何工作的...

确保定义本配方中讨论的类，总结如下表：

| 类 | 子节 | 出现的步骤 |
| --- | --- | --- |
| `Application\Captcha\Phrase` | 生成文本 CAPTCHA | 1 - 5 |
| `Application\Captcha\CaptchaInterface` |   | 6 |
| `Application\Captcha\Reverse` |   | 7 |
| `Application\Captcha\Image` | 生成图像 CAPTCHA | 2 - 13 |

接下来，定义一个名为`chap_12_captcha_text.php`的调用程序，实现文本 CAPTCHA。您首先需要设置自动加载并使用适当的类：

```php
<?php
require __DIR__ . '/../Application/Autoload/Loader.php';
Application\Autoload\Loader::init(__DIR__ . '/..');
use Application\Captcha\Reverse;
```

之后，请确保启动会话。您还应该采取适当的措施来保护会话。为了节省空间，我们只显示了一个简单的措施，`session_regenerate_id()`：

```php
session_start();
session_regenerate_id();
```

接下来，您可以定义一个函数，该函数创建 CAPTCHA；检索短语、标签和图像（在本例中为反向文本）；并将该值存储在会话中：

```php
function setCaptcha(&$phrase, &$label, &$image)
{
  $captcha = new Reverse();
  $phrase  = $captcha->getPhrase();
  $label   = $captcha->getLabel();
  $image   = $captcha->getImage();
  $_SESSION['phrase'] = $phrase;
}
```

现在是初始化变量并确定`loggedIn`状态的好时机：

```php
$image      = '';
$label      = '';
$phrase     = $_SESSION['phrase'] ?? '';
$message    = '';
$info       = 'You Can Now See Super Secret Information!!!';
$loggedIn   = $_SESSION['isLoggedIn'] ?? FALSE;
$loggedUser = $_SESSION['user'] ?? 'guest';
```

然后您可以检查登录按钮是否已被按下。如果是，则检查 CAPTCHA 短语是否已输入。如果没有，初始化一条消息，告知用户他们需要输入 CAPTCHA 短语：

```php
if (!empty($_POST['login'])) {
  if (empty($_POST['captcha'])) {
    $message = 'Enter Captcha Phrase and Login Information';
```

如果 CAPTCHA 短语存在，请检查它是否与会话中存储的内容匹配。如果不匹配，请继续处理表单无效。否则，处理登录与以往一样。为了说明这一点，您可以使用用户名和密码的硬编码值模拟登录：

```php
} else {
    if ($_POST['captcha'] == $phrase) {
        $username = 'test';
        $password = 'password';
        if ($_POST['user'] == $username 
            && $_POST['pass'] == $password) {
            $loggedIn = TRUE;
            $_SESSION['user'] = strip_tags($username);
            $_SESSION['isLoggedIn'] = TRUE;
        } else {
            $message = 'Invalid Login';
        }
    } else {
        $message = 'Invalid Captcha';
    }
}
```

您可能还想添加注销选项的代码，如*Safeguarding the PHP session*配方中所述：

```php
} elseif (isset($_POST['logout'])) {
  session_unset();
  session_destroy();
  setcookie('PHPSESSID', 0, time() - 3600);
  header('Location: ' . $_SERVER['REQUEST_URI'] );
  exit;
}
```

然后您可以运行`setCaptcha()`：

```php
setCaptcha($phrase, $label, $image);
```

最后，不要忘记视图逻辑，在本例中，它呈现一个基本的登录表单。在表单标记内，您需要添加视图逻辑来显示 CAPTCHA 和标签：

```php
<tr>
  <th><?= $label; ?></th>
  <td><?= $image; ?><input type="text" name="captcha" /></td>
</tr>
```

以下是生成的输出：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-prog-cb/img/B05314_12_11.jpg)

为了演示如何使用图像 CAPTCHA，将`chap_12_captcha_text.php`中的代码复制到`cha_12_captcha_image.php`中。我们定义代表我们将写入 CAPTCHA 图像的目录位置的常量。（确保创建此目录！）否则，自动加载和使用语句结构类似。请注意，我们还定义了一个 TrueType 字体。差异以**粗体**标出：

```php
<?php
define('IMAGE_DIR', __DIR__ . '/captcha');
define('IMAGE_URL', '/captcha');
define('IMAGE_FONT', __DIR__ . '/FreeSansBold.ttf');
require __DIR__ . '/../Application/Autoload/Loader.php';
Application\Autoload\Loader::init(__DIR__ . '/..');
use Application\Captcha\Image;

session_start();
session_regenerate_id();
```

### 提示

**重要！**

字体可能受版权、商标、专利或其他知识产权法的保护。如果您使用未经许可的字体，您和您的客户可能会在法庭上承担责任！请使用开源字体，或者您拥有有效许可的 Web 服务器上可用的字体。

当然，在`setCaptcha()`函数中，我们使用`Image`类而不是`Reverse`：

```php
function setCaptcha(&$phrase, &$label, &$image)
{
  $captcha = new Image(IMAGE_DIR, IMAGE_URL, IMAGE_FONT);
  $phrase  = $captcha->getPhrase();
  $label   = $captcha->getLabel();
  $image   = $captcha->getImage();
  $_SESSION['phrase'] = $phrase;
  return $captcha;
}
```

变量初始化与先前的脚本相同，登录处理与先前的脚本相同：

```php
$image      = '';
$label      = '';
$phrase     = $_SESSION['phrase'] ?? '';
$message    = '';
$info       = 'You Can Now See Super Secret Information!!!';
$loggedIn   = $_SESSION['isLoggedIn'] ?? FALSE;
$loggedUser = $_SESSION['user'] ?? 'guest';

if (!empty($_POST['login'])) {

  // etc.  -- identical to chap_12_captcha_text.php
```

即使视图逻辑保持不变，因为我们正在使用`getImage()`，在图像验证码的情况下，它返回直接可用的 HTML。这是使用 TrueType 字体的输出：

![工作原理...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-prog-cb/img/B05314_12_12.jpg)

## 还有更多...

如果您不愿意使用上述代码生成自己的内部 CAPTCHA，那么有很多库可用。大多数流行的框架都具有此功能。例如，Zend Framework 有其 Zend\Captcha 组件类。还有 reCAPTCHA，通常作为一项服务调用，您的应用程序会调用外部网站生成 CAPTCHA 和令牌。开始寻找的好地方是[`www.captcha.net/`](http://www.captcha.net/)网站。

## 另请参阅

有关字体作为知识产权的保护的更多信息，请参阅[`en.wikipedia.org/wiki/Intellectual_property_protection_of_typefaces`](https://en.wikipedia.org/wiki/Intellectual_property_protection_of_typefaces)上的文章。

# 加密/解密无需 mcrypt

在一般 PHP 社区的成员中，一个鲜为人知的事实是，被认为是安全的大多数基于 PHP 的加密的核心`mcrypt`扩展实际上并不安全。从安全的角度来看，最大的问题之一是`mcrypt`扩展需要对加密学有高级知识才能成功操作，而这是很少有程序员具备的。这导致了严重的误用，最终会出现诸如 256 分之 1 的数据损坏的问题。这不是一个好的几率。此外，对于`libmcrypt`，`mcrypt`扩展所基于的核心库，开发支持在 2007 年就被*放弃*了，这意味着代码库已经过时，存在错误，并且没有机制来应用补丁。因此，非常重要的是要了解如何在*不*使用`mcrypt`的情况下执行强大的加密/解密！

## 如何做...

1.  解决之前提出的问题的方法是使用`openssl`。这个扩展是被很好地维护的，并且具有现代和非常强大的加密/解密能力。

### 提示

**重要**

为了使用任何`openssl*`函数，必须编译和启用`openssl` PHP 扩展！此外，您需要在 Web 服务器上安装最新的 OpenSSL 软件包。

1.  首先，您需要确定安装中有哪些密码方法。为此，您可以使用`openssl_get_cipher_methods()`命令。示例将包括基于**高级** **加密标准**（**AES**），**BlowFish**（**BF**），**CAMELLIA**，**CAST5**，**数据** **加密标准**（**DES**），**Rivest** **Cipher**（**RC**）（也可亲切地称为**Ron's** **Code**），和**SEED**的算法。您会注意到，此方法显示了大小写重复的密码方法。

1.  接下来，您需要弄清楚哪种方法最适合您的需求。这里有一个快速总结各种方法的表：

| 方法 | 发布 | 密钥大小（位） | 密钥块大小（字节） | 注释 |
| --- | --- | --- | --- | --- |
| `camellia` | 2000 | 128, 192, 256 | 16 | 由三菱和 NTT 开发 |
| `aes` | 1998 | 128, 192, 256 | 16 | 由 Joan Daemen 和 Vincent Rijmen 开发。最初提交为 Rijndael |
| `seed` | 1998 | 128 | 16 | 由韩国信息安全机构开发 |
| `cast5` | 1996 | 40 到 128 | 8 | 由 Carlisle Adams 和 Stafford Tavares 开发 |
| `bf` | 1993 | 1 到 448 | 8 | 由 Bruce Schneier 设计 |
| `rc2` | 1987 | 8 到 1,024 默认为 64 | 8 | 由 Ron Rivest 设计（RSA 的核心创始人之一） |
| `des` | 1977 | 56（+8 奇偶校验位） | 8 | 由 IBM 开发，基于 Horst Feistel 的工作 |

1.  另一个考虑因素是您首选的块密码**操作模式**是什么。常见选择总结在这个表中：

| 模式 | 代表 | 注释 |
| --- | --- | --- |
| ECB | 电子密码本 | 不需要**初始化向量**（IV）；支持加密和解密的并行化；简单快速；不隐藏数据模式；不推荐！！！ |
| CBC | 密码块链接 | 需要 IV；即使相同，后续块也与前一个块进行异或运算，从而获得更好的整体加密；如果 IV 可预测，第一个块可以被解码，剩余消息暴露；消息必须填充到密码块大小的倍数；仅支持解密的并行化 |
| CFB | 密码反馈 | 与 CBC 密切相关，只是加密是反向进行的 |
| OFB | 输出反馈 | 非常对称：加密和解密相同；不支持任何并行化 |
| CTR | 计数器 | 在操作上类似于 OFB；支持加密和解密的并行化 |
| CCM | 计数器与 CBC-MAC | CTR 的派生；仅设计用于块长度为 128 位；提供认证和保密性；**CBC-MAC**代表**密码块链接 - 消息认证码** |
| GCM | Galois/Counter Mode | 基于 CTR 模式；每个要加密的流应使用不同的 IV；吞吐量异常高（与其他模式相比）；支持加密和解密的并行化 |
| XTS | 基于 XEX 的改进密码本模式与密文窃取 | 相对较新（2010 年）和快速；使用两个密钥；增加了可以安全加密的数据量 |

1.  在选择密码方法和模式之前，您还需要确定加密内容是否需要在 PHP 应用程序之外解密。例如，如果您将数据库凭据加密存储到独立的文本文件中，您是否需要能够从命令行解密？如果是这样，请确保您选择的密码方法和操作模式受目标操作系统支持。

1.  提供的**IV**的字节数取决于所选择的密码方法。为了获得最佳结果，使用`random_bytes()`（PHP 7 中的新功能），它返回真正的**CSPRNG**字节序列。IV 的长度差别很大。首先尝试大小为 16。如果生成了*警告*，将显示应为该算法提供的正确字节数，因此请相应调整大小：

```php
$iv  = random_bytes(16);
```

1.  要执行加密，使用`openssl_encrypt()`。以下是应该传递的参数：

| Parameter | 注释 |
| --- | --- |
| Data | 需要加密的明文。 |
| Method | 使用`openssl_get_cipher_methods()`识别的方法之一。识别如下：*method* - *key_size* - *cipher_mode*。所以，例如，如果您想要 AES 方法，密钥大小为 256，以及 GCM 模式，您将输入`aes-256-gcm`。 |
| Password | 虽然文档中称为*password*，但这个参数可以被视为*key*。使用`random_bytes()`生成一个与所需密钥大小匹配的密钥。 |
| Options | 在您对`openssl`加密有更多经验之前，建议您坚持使用默认值`0`。 |
| IV | 使用`random_bytes()`生成一个与密码方法匹配字节数的 IV。 |

1.  举个例子，假设你想选择 AES 密码方法，密钥大小为 256，并且选择 XTS 模式。以下是用于加密的代码：

```php
$plainText = 'Super Secret Credentials';
$key = random_bytes(16);
$method = 'aes-256-xts';
$cipherText = openssl_encrypt($plainText, $method, $key, 0, $iv);
```

1.  要解密，使用相同的`$key`和`$iv`值，以及`openssl_decrypt()`函数：

```php
$plainText = openssl_decrypt($cipherText, $method, $key, 0, $iv);
```

## 工作原理...

为了查看可用的密码方法，创建一个名为`chap_12_openssl_encryption.php`的 PHP 脚本，并运行以下命令：

```php
<?php
echo implode(', ', openssl_get_cipher_methods());
```

输出应该看起来像这样：

![工作原理...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-prog-cb/img/B05314_12_13.jpg)

接下来，您可以添加要加密的明文、方法、密钥和 IV 的值。例如，尝试 AES，密钥大小为 256，使用 XTS 操作模式：

```php
$plainText = 'Super Secret Credentials';
$method = 'aes-256-xts';
$key = random_bytes(16);
$iv  = random_bytes(16);
```

要进行加密，可以使用`openssl_encrypt()`，指定之前配置的参数：

```php
$cipherText = openssl_encrypt($plainText, $method, $key, 0, $iv);
```

您可能还希望对结果进行 base 64 编码，以使其更易于使用：

```php
$cipherText = base64_encode($cipherText);
```

要解密，请使用相同的 `$key` 和 `$iv` 值。不要忘记先解码 base 64 值：

```php
$plainText = openssl_decrypt(base64_decode($cipherText), 
$method, $key, 0, $iv);
```

这里是输出，显示了 base 64 编码的密文，然后是解密后的明文：

![工作原理...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-prog-cb/img/B05314_12_14.jpg)

如果您为 IV 提供了不正确数量的字节，对于所选择的密码方法，将显示警告消息：

![工作原理...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-prog-cb/img/B05314_12_15.jpg)

## 还有更多...

在 PHP 7 中，使用 `open_ssl_encrypt()` 和 `open_ssl_decrypt()` 以及支持的 **Authenticated Encrypt with Associated Data** (**AEAD**) 模式：GCM 和 CCM 时存在问题。因此，在 PHP 7.1 中，这些函数已添加了三个额外的参数，如下所示：

| 参数 | 描述 |
| --- | --- |
| `$tag` | 通过引用传递的认证标签；如果认证失败，变量值保持不变 |
| `$aad` | 附加的认证数据 |
| `$tag_length` | GCM 模式为 4 到 16；CCM 模式没有限制；仅适用于 `open_ssl_encrypt()` |

有关更多信息，您可以参考 [`wiki.php.net/rfc/openssl_aead`](https://wiki.php.net/rfc/openssl_aead)。

## 另请参阅

有关在 PHP 7.1 中为什么要弃用 `mcrypt` 扩展的出色讨论，请参阅 [`wiki.php.net/rfc/mcrypt-viking-funeral`](https://wiki.php.net/rfc/mcrypt-viking-funeral) 上的文章。有关分组密码的良好描述，这构成了各种密码方法的基础，请参阅 [`en.wikipedia.org/wiki/Block_cipher`](https://en.wikipedia.org/wiki/Block_cipher) 上的文章。有关 AES 的出色描述，请参阅 [`en.wikipedia.org/wiki/Advanced_Encryption_Standard`](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard)。可以在 [`en.wikipedia.org/wiki/Block_cipher_mode_of_operation`](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation) 上看到描述加密操作模式的出色文章。

### 注意

对于一些较新的模式，如果要加密的数据小于块大小，`openssl_decrypt()` 将不返回任何值。如果 *填充* 要至少达到块大小的数据，则问题就消失了。大多数模式实现了内部填充，因此这不是问题。对于一些较新的模式（即 `xts`），您可能会遇到这个问题。在将代码投入生产之前，请务必对少于八个字符的短数据字符串进行测试。


# 第十三章：最佳实践、测试和调试

在本章中，我们将涵盖以下主题：

+   使用特征和接口

+   通用异常处理程序

+   通用错误处理程序

+   编写一个简单的测试

+   编写测试套件

+   生成假测试数据

+   使用`session_start`参数自定义会话

# 介绍

在本章中，我们将向您展示特征和接口如何一起工作。然后，我们将把注意力转向设计一个回退机制，它将在您无法（或忘记）定义特定的`try/catch`块的情况下捕获错误和异常。然后，我们将进入单元测试的世界，首先向您展示如何编写简单的测试，然后如何将这些测试组合成测试套件。接下来，我们定义一个类，让您可以创建任意数量的通用测试数据。最后，我们讨论如何利用新的 PHP 7 功能轻松管理会话。

# 使用特征和接口

使用接口作为一种建立一组类的分类并保证某些方法存在的手段被认为是最佳实践。特征和接口经常一起工作，是实现的重要方面。无论何时您有一个经常使用的接口，定义了一个代码不会改变的方法（比如一个 setter 或 getter），也定义一个包含实际代码实现的特征是有用的。

## 如何做...

1.  在这个例子中，我们将使用`ConnectionAwareInterface`，首次在第四章中介绍，*使用 PHP 面向对象编程*。这个接口定义了一个`setConnection()`方法，用于设置一个`$connection`属性。`Application\Generic`命名空间中的两个类，`CountryList`和`CustomerList`，包含了冗余的代码，与接口中定义的方法相匹配。

1.  在进行更改之前，`CountryList`的样子如下：

```php
class CountryList
{
  protected $connection;
  protected $key   = 'iso3';
  protected $value = 'name';
  protected $table = 'iso_country_codes';

  public function setConnection(Connection $connection)
  {
    $this->connection = $connection;
  }
  public function list()
  {
    $list = [];
    $sql  = sprintf('SELECT %s,%s FROM %s', $this->key, 
                    $this->value, $this->table);
    $stmt = $this->connection->pdo->query($sql);
    while ($item = $stmt->fetch(PDO::FETCH_ASSOC)) {
      $list[$item[$this->key]] =  $item[$this->value];
    }
    return $list;
  }

}
```

1.  我们现在将`list()`移到一个名为`ListTrait`的特征中：

```php
trait ListTrait
{
  public function list()
  {
    $list = [];
    $sql  = sprintf('SELECT %s,%s FROM %s', 
                    $this->key, $this->value, $this->table);
    $stmt = $this->connection->pdo->query($sql);
    while ($item = $stmt->fetch(PDO::FETCH_ASSOC)) {
           $list[$item[$this->key]] = $item[$this->value];
    }
    return $list;
  }
}
```

1.  然后，我们可以将`ListTrait`中的代码插入到一个新的类`CountryListUsingTrait`中，如下所示：

```php
class CountryListUsingTrait
{
  use ListTrait;   
  protected $connection;
  protected $key   = 'iso3';
  protected $value = 'name';
  protected $table = 'iso_country_codes';
  public function setConnection(Connection $connection)
  {
    $this->connection = $connection;
  }

}
```

1.  接下来，我们注意到许多类需要设置一个连接实例。同样，这需要一个特征。然而，这一次，我们将特征放在`Application\Database`命名空间中。这是新的特征：

```php
namespace Application\Database;
trait ConnectionTrait
{
  protected $connection;
  public function setConnection(Connection $connection)
  {
    $this->connection = $connection;
  }
}
```

1.  特征经常用于避免代码重复。通常情况下，您还需要确定使用特征的类。一个好的方法是开发一个与特征匹配的接口。在这个例子中，我们将定义`Application\Database\ConnectionAwareInterface`：

```php
namespace Application\Database;
use Application\Database\Connection;
interface ConnectionAwareInterface
{
  public function setConnection(Connection $connection);
}
```

1.  这是修订后的`CountryListUsingTrait`类。请注意，由于特征的位置受到其命名空间的影响，我们需要在类的顶部添加一个`use`语句。您还会注意到，我们实现了`ConnectionAwareInterface`来确定这个类需要特征中定义的方法。请注意，我们正在利用新的 PHP 7 组使用语法：

```php
namespace Application\Generic;
use PDO;
use Application\Database\ { 
Connection, ConnectionTrait, ConnectionAwareInterface 
};
class CountryListUsingTrait implements ConnectionAwareInterface
{
  use ListTrait;
  use ConnectionTrait;

  protected $key   = 'iso3';
  protected $value = 'name';
  protected $table = 'iso_country_codes';

}
```

## 它是如何工作的...

首先，确保在第四章中开发的类已经创建。这些包括在第四章中讨论的`Application\Generic\CountryList`和`Application\Generic\CustomerList`类，在*使用接口*一节中。将每个类保存在`Application\Generic`文件夹中的一个新文件中，分别命名为`CountryListUsingTrait.php`和`CustomerListUsingTrait.php`。确保更改类名以匹配新文件的名称！

如第 3 步所讨论的，从`CountryListUsingTrait.php`和`CustomerListUsingTrait.php`中删除`list()`方法。在删除的方法的位置添加`use ListTrait;`。将删除的代码放入同一文件夹中的一个单独的文件中，命名为`ListTrait.php`。

您还会注意到两个列表类之间进一步的代码重复，这种情况下是`setConnection()`方法。这需要另一个 trait！

从`CountryListUsingTrait.php`和`CustomerListUsingTrait.php`列表类中剪切`setConnection()`方法，并将删除的代码放入名为`ConnectionTrait.php`的单独文件中。由于这个 trait 在逻辑上与`ConnectionAwareInterface`和`Connection`相关，因此将文件放在`Application\Database`文件夹中，并相应地指定其命名空间是有意义的。

最后，在步骤 6 中讨论的地方定义`Application\Database\ConnectionAwareInterface`。在所有更改之后，以下是最终的`Application\Generic\CustomerListUsingTrait`类：

```php
<?php
namespace Application\Generic;
use PDO;
use Application\Database\Connection;
use Application\Database\ConnectionTrait;
use Application\Database\ConnectionAwareInterface;
class CustomerListUsingTrait implements ConnectionAwareInterface
{

  use ListTrait;
  use ConnectionTrait;

  protected $key   = 'id';
  protected $value = 'name';
  protected $table = 'customer';
}
```

您现在可以将第四章中提到的`chap_04_oop_simple_interfaces_example.php`文件复制到一个名为`chap_13_trait_and_interface.php`的新文件中。将引用从`CountryList`改为`CountryListUsingTrait`。同样，将引用从`CustomerList`改为`CustomerListUsingTrait`。否则，代码可以保持不变：

```php
<?php
define('DB_CONFIG_FILE', '/../config/db.config.php');
require __DIR__ . '/../Application/Autoload/Loader.php';
Application\Autoload\Loader::init(__DIR__ . '/..');
$params = include __DIR__ . DB_CONFIG_FILE;
try {
    $list = Application\Generic\ListFactory::factory(
      new Application\Generic\CountryListUsingTrait(), $params);
    echo 'Country List' . PHP_EOL;
    foreach ($list->list() as $item) echo $item . ' ';
    $list = Application\Generic\ListFactory::factory(
      new Application\Generic\CustomerListUsingTrait(), 
      $params);
    echo 'Customer List' . PHP_EOL;
    foreach ($list->list() as $item) echo $item . ' ';

} catch (Throwable $e) {
    echo $e->getMessage();
}
```

输出将与第四章中*使用接口*一节中描述的完全相同，*使用面向对象编程*。您可以在以下截图中看到输出的国家列表部分：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-prog-cb/img/B05314_13_01.jpg)

下一张图片显示了输出的客户列表部分：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-prog-cb/img/B05314_13_19.jpg)

# 通用异常处理程序

在`try/catch`块中与代码结合使用时，异常特别有用。然而，在某些情况下，使用这种结构可能会很笨拙，使代码几乎无法阅读。另一个考虑因素是，许多类最终会抛出您未预料到的异常。在这种情况下，拥有某种回退异常处理程序将是非常理想的。

## 如何做...

1.  首先，我们定义一个通用异常处理类，`Application\Error\Handler`：

```php
namespace Application\Error;
class Handler
{
  // code goes here
}
```

1.  我们定义了代表日志文件的属性。如果未提供名称，则以年、月和日命名。在构造函数中，我们使用`set_exception_handler()`将`exceptionHandler()`方法（在这个类中）分配为回退处理程序：

```php
protected $logFile;
public function __construct(
  $logFileDir = NULL, $logFile = NULL)
{
  $logFile = $logFile    ?? date('Ymd') . '.log';
  $logFileDir = $logFileDir ?? __DIR__;
  $this->logFile = $logFileDir . '/' . $logFile;
  $this->logFile = str_replace('//', '/', $this->logFile);
  set_exception_handler([$this,'exceptionHandler']);
}
```

1.  接下来，我们定义`exceptionHandler()`方法，它以`Exception`对象作为参数。我们记录异常的日期和时间、异常的类名以及其消息在日志文件中：

```php
public function exceptionHandler($ex)
{
  $message = sprintf('%19s : %20s : %s' . PHP_EOL,
    date('Y-m-d H:i:s'), get_class($ex), $ex->getMessage());
  file_put_contents($this->logFile, $message, FILE_APPEND); 
}
```

1.  如果我们在代码中明确放置了`try/catch`块，这将覆盖我们的通用异常处理程序。另一方面，如果我们不使用 try/catch 并且抛出异常，通用异常处理程序将发挥作用。

### 提示

**最佳实践**

您应该始终使用 try/catch 来捕获异常，并可能在应用程序中继续。这里描述的异常处理程序仅旨在允许您的应用程序在未捕获的异常情况下“优雅”地结束。

## 它是如何工作的...

首先，将前面一节中显示的代码放入`Application\Error`文件夹中的`Handler.php`文件中。接下来，定义一个将抛出异常的测试类。为了举例，创建一个`Application\Error\ThrowsException`类，它将抛出一个异常。例如，设置一个 PDO 实例，错误模式设置为`PDO::ERRMODE_EXCEPTION`。然后编写一个肯定会失败的 SQL 语句：

```php
namespace Application\Error;
use PDO;
class ThrowsException
{
  protected $result;
  public function __construct(array $config)
  {
    $dsn = $config['driver'] . ':';
    unset($config['driver']);
    foreach ($config as $key => $value) {
      $dsn .= $key . '=' . $value . ';';
    }
    $pdo = new PDO(
      $dsn, 
      $config['user'],
      $config['password'],
      [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);
      $stmt = $pdo->query('This Is Not SQL');
      while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
        $this->result[] = $row;
      }
  }
}
```

接下来，定义一个名为`chap_13_exception_handler.php`的调用程序，设置自动加载，使用适当的类：

```php
<?php
define('DB_CONFIG_FILE', __DIR__ . '/../config/db.config.php');
$config = include DB_CONFIG_FILE;
require __DIR__ . '/../Application/Autoload/Loader.php';
Application\Autoload\Loader::init(__DIR__ . '/..');
use Application\Error\ { Handler, ThrowsException };
```

此时，如果您创建一个没有实现通用处理程序的`ThrowsException`实例，将生成一个`致命错误`，因为已经抛出了一个异常但没有被捕获：

```php
$throws1 = new ThrowsException($config);
```

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-prog-cb/img/B05314_13_02.jpg)

另一方面，如果你使用`try/catch`块，异常将被捕获，你的应用程序将被允许继续，如果它足够稳定的话。

```php
try {
    $throws1 = new ThrowsException($config);
} catch (Exception $e) {
    echo 'Exception Caught: ' . get_class($e) . ':' . $e->getMessage() . PHP_EOL;
}
echo 'Application Continues ...' . PHP_EOL;
```

你会观察到以下输出：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-prog-cb/img/B05314_13_03.jpg)

为了演示异常处理程序的使用，首先定义一个`Handler`实例，传递一个表示包含日志文件的目录的参数，然后在`try/catch`块之前。在`try/catch`块之后，块外部，创建另一个`ThrowsException`实例。当运行这个示例程序时，你会注意到第一个异常在`try/catch`块内被捕获，第二个异常被处理程序捕获。你还会注意到，在处理程序之后，应用程序结束了。

```php
$handler = new Handler(__DIR__ . '/logs');
try {
    $throws1 = new ThrowsException($config);
} catch (Exception $e) {
    echo 'Exception Caught: ' . get_class($e) . ':' 
      . $e->getMessage() . PHP_EOL;
}
$throws1 = new ThrowsException($config);
echo 'Application Continues ...' . PHP_EOL;
```

这是完成示例程序的输出，以及日志文件的内容：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-prog-cb/img/B05314_13_04.jpg)

## 另请参阅

+   可能是一个好主意去查看`set_exception_handler()`函数的文档。特别要看看 Anonymous 在 7 年前发布的评论，澄清了这个函数的工作原理：[`php.net/manual/en/function.set-exception-handler.php`](http://php.net/manual/en/function.set-exception-handler.php)。

# 通用错误处理程序

开发通用错误处理程序的过程与前面的步骤非常相似。然而，也有一些区别。首先，在 PHP 7 中，一些错误被抛出并可以被捕获，而其他错误会直接停止你的应用程序。更让人困惑的是，一些错误被视为异常，而另一些则源自新的 PHP 7 `Error`类。幸运的是，在 PHP 7 中，`Error`和`Exception`都实现了一个叫做`Throwable`的新接口。因此，如果你不确定你的代码会抛出一个`Exception`还是一个`Error`，只需捕获`Throwable`的一个实例，你就能捕获两者。

## 如何做...

1.  修改前面步骤中定义的`Application\Error\Handler`类。在构造函数中，将一个新的`errorHandler()`方法设置为默认的错误处理程序：

```php
public function __construct($logFileDir = NULL, $logFile = NULL)
{
  $logFile    = $logFile    ?? date('Ymd') . '.log';
  $logFileDir = $logFileDir ?? __DIR__;
  $this->logFile = $logFileDir . '/' . $logFile;
  $this->logFile = str_replace('//', '/', $this->logFile);
  set_exception_handler([$this,'exceptionHandler']);
  set_error_handler([$this, 'errorHandler']);
}
```

1.  然后，使用文档化的参数定义新方法。与我们的异常处理程序一样，我们将信息记录到日志文件中。

```php
public function errorHandler($errno, $errstr, $errfile, $errline)
{
  $message = sprintf('ERROR: %s : %d : %s : %s : %s' . PHP_EOL,
    date('Y-m-d H:i:s'), $errno, $errstr, $errfile, $errline);
  file_put_contents($this->logFile, $message, FILE_APPEND);
}
```

1.  另外，为了能够区分错误和异常，将`EXCEPTION`添加到`exceptionHandler()`方法中发送到日志文件的消息中：

```php
public function exceptionHandler($ex)
{
  $message = sprintf('EXCEPTION: %19s : %20s : %s' . PHP_EOL,
    date('Y-m-d H:i:s'), get_class($ex), $ex->getMessage());
  file_put_contents($this->logFile, $message, FILE_APPEND);
}
```

## 它是如何工作的...

首先，按照之前定义的方式更改`Application\Error\Handler`。接下来，创建一个类，抛出一个错误，可以定义为`Application\Error\ThrowsError`。例如，你可以有一个尝试除以零的方法，另一个尝试使用`eval()`解析非 PHP 代码的方法。

```php
<?php
namespace Application\Error;
class ThrowsError
{
  const NOT_PARSE = 'this will not parse';
  public function divideByZero()
  {
    $this->zero = 1 / 0;
  }
  public function willNotParse()
  {
    eval(self::NOT_PARSE);
  }
}
```

然后，你可以定义一个名为`chap_13_error_throwable.php`的调用程序，设置自动加载，使用适当的类，并创建一个`ThrowsError`实例。

```php
<?php
require __DIR__ . '/../Application/Autoload/Loader.php';
Application\Autoload\Loader::init(__DIR__ . '/..');
use Application\Error\ { Handler, ThrowsError };
$error = new ThrowsError();
```

如果你调用这两个方法，没有`try/catch`块，也没有定义通用错误处理程序，第一个方法会生成一个`Warning`，而第二个会抛出一个`ParseError`。

```php
$error->divideByZero();
$error->willNotParse();
echo 'Application continues ... ' . PHP_EOL;
```

因为这是一个错误，程序执行停止，你将看不到`Application continues ...`：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-prog-cb/img/B05314_13_05.jpg)

如果你将方法调用包装在`try/catch`块中，并捕获`Throwable`，代码执行将继续：

```php
try {
    $error->divideByZero();
} catch (Throwable $e) {
    echo 'Error Caught: ' . get_class($e) . ':' 
      . $e->getMessage() . PHP_EOL;
}
try {
    $error->willNotParse();
} catch (Throwable $e) {
    echo 'Error Caught: ' . get_class($e) . ':' 
    . $e->getMessage() . PHP_EOL;
}
echo 'Application continues ... ' . PHP_EOL;
```

从以下输出中，你还会注意到程序以`code 0`退出，这告诉我们一切都很好：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-prog-cb/img/B05314_13_06.jpg)

最后，在`try/catch`块之后再次运行错误，将 echo 语句移到最后。你会在输出中看到错误被捕获，但在日志文件中，注意到`DivisionByZeroError`被异常处理程序捕获，而`ParseError`被错误处理程序捕获：

```php
$handler = new Handler(__DIR__ . '/logs');
$error->divideByZero();
$error->willNotParse();
echo 'Application continues ... ' . PHP_EOL;
```

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-prog-cb/img/B05314_13_07.jpg)

## 另请参阅

+   PHP 7.1 允许您在`catch` `()`子句中指定多个类。因此，您可以说`catch` `(Exception` `|` `Error $e)` `{` `xxx` `}`

# 编写一个简单的测试

测试 PHP 代码的主要方法是使用**PHPUnit**，它基于一种称为**单元测试**的方法论。单元测试背后的哲学非常简单：将代码分解为尽可能小的逻辑单元。然后分别测试每个单元，以确认其表现如预期。这些期望被编码为一系列**断言**。如果所有断言返回`TRUE`，则该单元通过了测试。

### 注意

在程序化 PHP 的情况下，一个单元是一个函数。对于 OOP PHP，单元是类中的一个方法。

## 如何做...

1.  首要任务是直接在开发服务器上安装 PHPUnit，或者下载源代码，源代码以单个**phar**（**PHP 存档**）文件的形式提供。快速访问 PHPUnit 的官方网站（[`phpunit.de/`](https://phpunit.de/)）让我们可以直接从主页下载。

1.  然而，最佳实践是使用软件包管理器来安装和维护 PHPUnit。为此，我们将使用一个名为**Composer**的软件包管理程序。要安装 Composer，请访问主网站[`getcomposer.org/`](https://getcomposer.org/)，并按照下载页面上的说明进行操作。在撰写本文时，当前的过程如下。请注意，您需要用当前版本的哈希替换`<hash>`：

```php
php -r "copy('https://getcomposer.org/installer', 'composer-setup.php');"
php -r "if (hash_file('SHA384', 'composer-setup.php') === '<hash>') { 
    echo 'Installer verified'; 
} else { 
    echo 'Installer corrupt'; unlink('composer-setup.php'); 
} echo PHP_EOL;"
php composer-setup.php
php -r "unlink('composer-setup.php');"
```

### 提示

**最佳实践**

使用 Composer 等软件包管理程序的优势在于它不仅可以安装，还可以用于更新应用程序使用的任何外部软件（如 PHPUnit）。

1.  接下来，我们使用 Composer 来安装 PHPUnit。这是通过创建一个包含一系列指令的`composer.json`文件来实现的，这些指令概述了项目参数和依赖关系。这些指令的完整描述超出了本书的范围；然而，为了这个示例，我们使用`require`关键参数创建了一组最小的指令。您还会注意到文件的内容是以**JavaScript 对象表示**（**JSON**）格式呈现的：

```php
{
  "require-dev": {
    "phpunit/phpunit": "*"
  }
}
```

1.  要从命令行执行安装，我们运行以下命令。输出如下所示：

```php
**php composer.phar install**

```

![如何做...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-prog-cb/img/B05314_13_08.jpg)

1.  PHPUnit 及其依赖项被放置在`vendor`文件夹中，如果不存在，Composer 将创建它。然后，调用 PHPUnit 的主要命令被符号链接到`vendor/bin`文件夹中。如果您将此文件夹放在您的`PATH`中，您只需要运行此命令，它将检查版本并顺便确认安装：

```php
**phpunit --version**

```

### 运行简单测试

1.  为了说明这一点，让我们假设我们有一个包含`add()`函数的`chap_13_unit_test_simple.php`文件：

```php
<?php
function add($a = NULL, $b = NULL)
{
  return $a + $b;
}
```

1.  测试然后被写成扩展`PHPUnit\Framework\TestCase`的类。如果你正在测试一个函数库，在测试类的开头，包括包含函数定义的文件。然后你会写一些以单词`test`开头的方法，通常后面跟着你正在测试的函数的名称，可能还有一些额外的驼峰命名的单词来进一步描述测试。为了这个示例，我们将定义一个`SimpleTest`测试类：

```php
<?php
use PHPUnit\Framework\TestCase;
require_once __DIR__ . '/chap_13_unit_test_simple.php';
class SimpleTest extends TestCase
{
  // testXXX() methods go here
}
```

1.  断言构成了任何一组测试的核心。`另请参阅`部分为您提供了完整断言列表的文档参考。断言是一个 PHPUnit 方法，它比较一个已知值与您希望测试的值产生的值。例如`assertEquals()`，它检查第一个参数是否等于第二个参数。以下示例测试了一个名为`add()`的方法，并确认`add(1,1)`的返回值为**2**：

```php
public function testAdd()
{
  $this->assertEquals(2, add(1,1));
}
```

1.  您也可以测试某些事情是否*不*成立。这个例子断言 1 + 1 不等于 3：

```php
$this->assertNotEquals(3, add(1,1));
```

1.  在测试字符串时，使用`assertRegExp()`断言非常有用。假设，为了举例说明，我们正在测试一个函数，该函数从多维数组中生成 HTML 表：

```php
function table(array $a)
{
  $table = '<table>';
  foreach ($a as $row) {
    $table .= '<tr><td>';
    $table .= implode('</td><td>', $row);
    $table .= '</td></tr>';
  }
  $table .= '</table>';
  return $table;
}
```

1.  我们可以构建一个简单的测试，确认输出包含`<table>`，一个或多个字符，然后是`</table>`。此外，我们希望确认存在一个`<td>B</td>`元素。在编写测试时，我们构建一个测试数组，其中包含三个子数组，分别包含字母 A—C，D—F 和 G—I。然后我们将测试数组传递给函数，并对结果运行断言：

```php
public function testTable()
{
  $a = [range('A', 'C'),range('D', 'F'),range('G','I')];
  $table = table($a);
  $this->assertRegExp('!^<table>.+</table>$!', $table);
  $this->assertRegExp('!<td>B</td>!', $table);
}
```

1.  为了测试一个类，而不是包含一个函数库，只需包含定义要测试的类的文件。为了举例说明，让我们将先前显示的函数库移动到一个`Demo`类中：

```php
<?php
class Demo
{
  public function add($a, $b)
  {
    return $a + $b;
  }

  public function sub($a, $b)
  {
    return $a - $b;
  }
  // etc.
}
```

1.  在我们的`SimpleClassTest`测试类中，我们不包含库文件，而是包含代表`Demo`类的文件。我们需要`Demo`的一个实例来运行测试。为此，我们使用一个专门设计的`setup()`方法，在每次测试之前运行。此外，您会注意到一个`teardown()`方法，在每次测试后立即运行：

```php
<?php
use PHPUnit\Framework\TestCase;
require_once __DIR__ . '/Demo.php';
class SimpleClassTest extends TestCase
{
  protected $demo;
  public function setup()
  {
    $this->demo = new Demo();
  }
  public function teardown()
  {
    unset($this->demo);
  }
  public function testAdd()
  {
    $this->assertEquals(2, $this->demo->add(1,1));
  }
  public function testSub()
  {
    $this->assertEquals(0, $this->demo->sub(1,1));
  }
  // etc.
}
```

### 注意

在每次测试之前和之后运行`setup()`和`teardown()`的原因是确保一个新鲜的测试环境。这样，一个测试的结果不会影响另一个测试的结果。

### 测试数据库模型类

1.  在测试具有数据库访问权限的类（例如模型类）时，还有其他考虑因素。主要考虑因素是，您应该针对测试数据库而不是生产中使用的真实数据库运行测试。最后一点是，通过使用测试数据库，您可以提前使用适当的受控数据填充它。`setup()`和`teardown()`也可以用于添加或删除测试数据。

1.  作为使用数据库的类的示例，我们将定义一个`VisitorOps`类。新类将包括添加、删除和查找访问者的方法。请注意，我们还添加了一个方法来返回最新执行的 SQL 语句：

```php
<?php
require __DIR__ . '/../Application/Database/Connection.php';
use Application\Database\Connection;
class VisitorOps
{

const TABLE_NAME = 'visitors';
protected $connection;
protected $sql;

public function __construct(array $config)
{
  $this->connection = new Connection($config);
}

public function getSql()
{
  return $this->sql;
}

public function findAll()
{
  $sql = 'SELECT * FROM ' . self::TABLE_NAME;
  $stmt = $this->runSql($sql);
  while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
    yield $row;
  }
}

public function findById($id)
{
  $sql = 'SELECT * FROM ' . self::TABLE_NAME;
  $sql .= ' WHERE id = ?';
  $stmt = $this->runSql($sql, [$id]);
  return $stmt->fetch(PDO::FETCH_ASSOC);
}

public function removeById($id)
{
  $sql = 'DELETE FROM ' . self::TABLE_NAME;
  $sql .= ' WHERE id = ?';
  return $this->runSql($sql, [$id]);
}

public function addVisitor($data)
{
  $sql = 'INSERT INTO ' . self::TABLE_NAME;
  $sql .= ' (' . implode(',',array_keys($data)) . ') ';
  $sql .= ' VALUES ';
  $sql .= ' ( :' . implode(',:',array_keys($data)) . ') ';
  $this->runSql($sql, $data);
  return $this->connection->pdo->lastInsertId();
}

public function runSql($sql, $params = NULL)
{
  $this->sql = $sql;
  try {
      $stmt = $this->connection->pdo->prepare($sql);
      $result = $stmt->execute($params);
  } catch (Throwable $e) {
      error_log(__METHOD__ . ':' . $e->getMessage());
      return FALSE;
  }
  return $stmt;
}
}
```

1.  对于涉及数据库的测试，建议使用测试数据库，而不是实际生产数据库。因此，您需要额外的数据库连接参数集，可以在`setup()`方法中用于建立数据库连接。

1.  您可能希望建立一个一致的样本数据块。这可以在`setup()`方法中插入到测试数据库中。

1.  最后，您可能希望在每次测试后重置测试数据库，这可以在`teardown()`方法中完成。

### 使用模拟类

1.  在某些情况下，测试将访问需要外部资源的复杂组件。一个例子是需要访问数据库的服务类。最佳实践是尽量减少测试套件中对数据库的访问。另一个考虑因素是我们不是在测试数据库访问；我们只是在测试一个特定类的功能。因此，有时需要定义**模拟**类，模仿其父类的行为，但限制对外部资源的访问。

### 提示

**最佳实践**

在测试中，将实际数据库访问限制在模型（或等效）类中。否则，运行整套测试所需的时间可能会变得过多。

1.  在这种情况下，为了举例说明，定义一个服务类`VisitorService`，它使用先前讨论的`VisitorOps`类：

```php
<?php
require_once __DIR__ . '/VisitorOps.php';
require_once __DIR__ . '/../Application/Database/Connection.php';
use Application\Database\Connection;
class VisitorService
{
  protected $visitorOps;
  public function __construct(array $config)
  {
    $this->visitorOps = new VisitorOps($config);
  }
  public function showAllVisitors()
  {
    $table = '<table>';
    foreach ($this->visitorOps->findAll() as $row) {
      $table .= '<tr><td>';
      $table .= implode('</td><td>', $row);
      $table .= '</td></tr>';
    }
    $table .= '</table>';
    return $table;
  }
```

1.  为了测试目的，我们为`$visitorOps`属性添加了 getter 和 setter。这使我们能够在真实的`VisitorOps`类的位置插入一个模拟类：

```php
public function getVisitorOps()
{
  return $this->visitorOps;
}

public function setVisitorOps(VisitorOps $visitorOps)
{
  $this->visitorOps = $visitorOps;
}
} // closing brace for VisitorService
```

1.  接下来，我们定义一个`VisitorOpsMock`模拟类，模拟其父类的功能。类常量和属性都会被继承。然后我们添加模拟测试数据，并添加一个 getter 以便以后访问测试数据：

```php
<?php
require_once __DIR__ . '/VisitorOps.php';
class VisitorOpsMock extends VisitorOps
{
  protected $testData;
  public function __construct()
  {
    $data = array();
    for ($x = 1; $x <= 3; $x++) {
      $data[$x]['id'] = $x;
      $data[$x]['email'] = $x . 'test@unlikelysource.com';
      $data[$x]['visit_date'] = 
        '2000-0' . $x . '-0' . $x . ' 00:00:00';
      $data[$x]['comments'] = 'TEST ' . $x;
      $data[$x]['name'] = 'TEST ' . $x;
    }
    $this->testData = $data;
  }
  public function getTestData()
  {
    return $this->testData;
  }
```

1.  接下来，我们覆盖`findAll()`以使用`yield`返回测试数据，就像父类一样。请注意，我们仍然构建 SQL 字符串，因为这是父类的做法：

```php
public function findAll()
{
  $sql = 'SELECT * FROM ' . self::TABLE_NAME;
  foreach ($this->testData as $row) {
    yield $row;
  }
}
```

1.  为了模拟`findById()`，我们只需从`$this->testData`返回该数组键。对于`removeById()`，我们从`$this->testData`中取消设置为参数的数组键：

```php
public function findById($id)
{
  $sql = 'SELECT * FROM ' . self::TABLE_NAME;
  $sql .= ' WHERE id = ?';
  return $this->testData[$id] ?? FALSE;
}
public function removeById($id)
{
  $sql = 'DELETE FROM ' . self::TABLE_NAME;
  $sql .= ' WHERE id = ?';
  if (empty($this->testData[$id])) {
      return 0;
  } else {
      unset($this->testData[$id]);
      return 1;
  }
}
```

1.  添加数据稍微复杂一些，因为我们需要模拟`id`参数可能不会被提供的情况，因为数据库通常会自动生成这个参数。为了解决这个问题，我们检查`id`参数。如果没有设置，我们找到最大的数组键并递增：

```php
public function addVisitor($data)
{
  $sql = 'INSERT INTO ' . self::TABLE_NAME;
  $sql .= ' (' . implode(',',array_keys($data)) . ') ';
  $sql .= ' VALUES ';
  $sql .= ' ( :' . implode(',:',array_keys($data)) . ') ';
  if (!empty($data['id'])) {
      $id = $data['id'];
  } else {
      $keys = array_keys($this->testData);
      sort($keys);
      $id = end($keys) + 1;
      $data['id'] = $id;
  }
    $this->testData[$id] = $data;
    return 1;
  }

} // ending brace for the class VisitorOpsMock
```

### 使用匿名类作为模拟对象

1.  模拟对象的一个很好的变化是使用新的 PHP 7 匿名类来代替创建定义模拟功能的正式类。使用匿名类的优势在于可以扩展现有类，使对象看起来合法。如果您只需要覆盖一两个方法，这种方法尤其有用。

1.  在这个示例中，我们将修改之前介绍的`VisitorServiceTest.php`，将其命名为`VisitorServiceTestAnonClass.php`：

```php
<?php
use PHPUnit\Framework\TestCase;
require_once __DIR__ . '/VisitorService.php';
require_once __DIR__ . '/VisitorOps.php';
class VisitorServiceTestAnonClass extends TestCase
{
  protected $visitorService;
  protected $dbConfig = [
    'driver'   => 'mysql',
    'host'     => 'localhost',
    'dbname'   => 'php7cookbook_test',
    'user'     => 'cook',
    'password' => 'book',
    'errmode'  => PDO::ERRMODE_EXCEPTION,
  ];
    protected $testData;
```

1.  您会注意到在`setup()`中，我们定义了一个匿名类，它扩展了`VisitorOps`。我们只需要覆盖`findAll()`方法：

```php
public function setup()
{
  $data = array();
  for ($x = 1; $x <= 3; $x++) {
    $data[$x]['id'] = $x;
    $data[$x]['email'] = $x . 'test@unlikelysource.com';
    $data[$x]['visit_date'] = 
      '2000-0' . $x . '-0' . $x . ' 00:00:00';
    $data[$x]['comments'] = 'TEST ' . $x;
    $data[$x]['name'] = 'TEST ' . $x;
  }
  $this->testData = $data;
  $this->visitorService = 
    new VisitorService($this->dbConfig);
  $opsMock = 
    new class ($this->testData) extends VisitorOps {
      protected $testData;
      public function __construct($testData)
      {
        $this->testData = $testData;
      }
      public function findAll()
      {
        return $this->testData;
      }
    };
    $this->visitorService->setVisitorOps($opsMock);
}
```

1.  请注意，在`testShowAllVisitors()`中，当执行`$this->visitorService->showAllVisitors()`时，访客服务会调用匿名类，然后调用覆盖的`findAll()`：

```php
public function teardown()
{
  unset($this->visitorService);
}
public function testShowAllVisitors()
{
  $result = $this->visitorService->showAllVisitors();
  $this->assertRegExp('!^<table>.+</table>$!', $result);
  foreach ($this->testData as $key => $value) {
    $dataWeWant = '!<td>' . $key . '</td>!';
    $this->assertRegExp($dataWeWant, $result);
  }
}
}
```

### 使用模拟构建器

1.  另一种技术是使用`getMockBuilder()`。虽然这种方法不能对生成的模拟对象进行精细控制，但在您只需要确认返回某个类的对象，并且当运行指定方法时，该方法返回某个预期值的情况下，它非常有用。

1.  在下面的例子中，我们复制了`VisitorServiceTestAnonClass`；唯一的区别在于在`setup()`中提供`VisitorOps`的实例的方式，在这种情况下使用`getMockBuilder()`。请注意，尽管在这个例子中我们没有使用`with()`，但它被用来向模拟方法提供受控参数：

```php
<?php
use PHPUnit\Framework\TestCase;
require_once __DIR__ . '/VisitorService.php';
require_once __DIR__ . '/VisitorOps.php';
class VisitorServiceTestAnonMockBuilder extends TestCase
{
  // code is identical to VisitorServiceTestAnon
  public function setup()
  {
    $data = array();
    for ($x = 1; $x <= 3; $x++) {
      $data[$x]['id'] = $x;
      $data[$x]['email'] = $x . 'test@unlikelysource.com';
      $data[$x]['visit_date'] = 
        '2000-0' . $x . '-0' . $x . ' 00:00:00';
      $data[$x]['comments'] = 'TEST ' . $x;
      $data[$x]['name'] = 'TEST ' . $x;
  }
  $this->testData = $data;
    $this->visitorService = 
      new VisitorService($this->dbConfig);
    $opsMock = $this->getMockBuilder(VisitorOps::class)
                    ->setMethods(['findAll'])
                    ->disableOriginalConstructor()
                    ->getMock();
                    $opsMock->expects($this->once())
                    ->method('findAll')
                    ->with()
                    ->will($this->returnValue($this->testData));
                    $this->visitorService->setVisitorOps($opsMock);
  }
  // remaining code is the same
}
```

### 注意

我们已经展示了如何创建简单的一次性测试。然而，在大多数情况下，您将需要测试许多类，最好一次性测试所有类。这可以通过开发一个*测试套件*来实现，下一个示例中将更详细地讨论。

## 它是如何工作的...

首先，您需要安装 PHPUnit，如步骤 1 到 5 所述。确保在您的 PATH 中包含`vendor/bin`，这样您就可以从命令行运行 PHPUnit。

### 运行简单测试

接下来，定义一个`chap_13_unit_test_simple.php`程序文件，其中包含一系列简单的函数，如`add()`、`sub()`等，如步骤 1 所述。然后，您可以按照步骤 2 和 3 中提到的方式定义一个包含在`SimpleTest.php`中的简单测试类。

假设`phpunit`在您的`PATH`中，从终端窗口，切换到为这个示例开发的代码所在的目录，并运行以下命令：

```php
**phpunit SimpleTest SimpleTest.php**

```

您应该看到以下输出：

![运行简单测试](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-prog-cb/img/B05314_13_09.jpg)

在`SimpleTest.php`中进行更改，使测试失败（步骤 4）：

```php
public function testDiv()
{
  $this->assertEquals(2, div(4, 2));
  $this->assertEquals(99, div(4, 0));
}
```

这是修改后的输出：

![运行简单测试](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-prog-cb/img/B05314_13_10.jpg)

接下来，添加`table()`函数到`chap_13_unit_test_simple.php`（步骤 5），并在`SimpleTest.php`中添加`testTable()`（步骤 6）。重新运行单元测试并观察结果。

要测试一个类，将在`chap_13_unit_test_simple.php`中开发的函数复制到一个`Demo`类中（步骤 7）。在按照步骤 8 建议的对`SimpleTest.php`进行修改后，重新运行简单测试并观察结果。

### 测试数据库模型类

首先，创建一个要测试的示例类`VisitorOps`，如本小节中的步骤 2 所示。现在，您可以定义一个名为`SimpleDatabaseTest`的类来测试`VisitorOps`。首先使用`require_once`加载要测试的类。（我们将讨论如何在下一个示例中使用自动加载！）然后定义关键属性，包括测试数据库配置和测试数据。您可以使用`php7cookbook_test`作为测试数据库：

```php
<?php
use PHPUnit\Framework\TestCase;
require_once __DIR__ . '/VisitorOps.php';
class SimpleDatabaseTest extends TestCase
{
  protected $visitorOps;
  protected $dbConfig = [
    'driver'   => 'mysql',
    'host'     => 'localhost',
    'dbname'   => 'php7cookbook_test',
    'user'     => 'cook',
    'password' => 'book',
    'errmode'  => PDO::ERRMODE_EXCEPTION,
  ];
  protected $testData = [
    'id' => 1,
    'email' => 'test@unlikelysource.com',
    'visit_date' => '2000-01-01 00:00:00',
    'comments' => 'TEST',
    'name' => 'TEST'
  ];
}
```

接下来，定义`setup()`，插入测试数据，并确认最后一个 SQL 语句是`INSERT`。您还应该检查返回值是否为正数：

```php
public function setup()
{
  $this->visitorOps = new VisitorOps($this->dbConfig);
  $this->visitorOps->addVisitor($this->testData);
  $this->assertRegExp('/INSERT/', $this->visitorOps->getSql());
}
```

之后，定义`teardown()`，删除测试数据，并确认`id = 1`的查询结果为`FALSE`：

```php
public function teardown()
{
  $result = $this->visitorOps->removeById(1);
  $result = $this->visitorOps->findById(1);
  $this->assertEquals(FALSE, $result);
  unset($this->visitorOps);
}
```

第一个测试是`findAll()`。首先，确认结果的数据类型。您可以使用`current()`来获取顶部元素。我们确认有五个元素，其中一个是`name`，并且该值与测试数据中的值相同：

```php
public function testFindAll()
{
  $result = $this->visitorOps->findAll();
  $this->assertInstanceOf(Generator::class, $result);
  $top = $result->current();
  $this->assertCount(5, $top);
  $this->assertArrayHasKey('name', $top);
  $this->assertEquals($this->testData['name'], $top['name']);
}
```

下一个测试是`findById()`。它几乎与`testFindAll()`相同：

```php
public function testFindById()
{
  $result = $this->visitorOps->findById(1);
  $this->assertCount(5, $result);
  $this->assertArrayHasKey('name', $result);
  $this->assertEquals($this->testData['name'], $result['name']);
}
```

不需要为`removeById()`编写测试，因为这已经在`teardown()`中完成了。同样，也不需要测试`runSql()`，因为这是其他测试的一部分。

### 使用模拟类

首先，按照本小节中步骤 2 和 3 的描述定义一个`VisitorService`服务类。接下来，定义一个`VisitorOpsMock`模拟类，步骤 4 到 7 中有讨论。

现在，您可以为服务类开发一个名为`VisitorServiceTest`的测试。请注意，您需要提供自己的数据库配置，因为最佳实践是使用测试数据库而不是生产版本：

```php
<?php
use PHPUnit\Framework\TestCase;
require_once __DIR__ . '/VisitorService.php';
require_once __DIR__ . '/VisitorOpsMock.php';

class VisitorServiceTest extends TestCase
{
  protected $visitorService;
  protected $dbConfig = [
    'driver'   => 'mysql',
    'host'     => 'localhost',
    'dbname'   => 'php7cookbook_test',
    'user'     => 'cook',
    'password' => 'book',
    'errmode'  => PDO::ERRMODE_EXCEPTION,
  ];
}
```

在`setup()`中，创建服务的实例，并将`VisitorOpsMock`替换原始类：

```php
public function setup()
{
  $this->visitorService = new VisitorService($this->dbConfig);
  $this->visitorService->setVisitorOps(new VisitorOpsMock());
}
public function teardown()
{
  unset($this->visitorService);
}
```

在我们的测试中，从访客列表生成 HTML 表格，您可以查找特定元素，事先知道可以期望什么，因为您对测试数据有控制：

```php
public function testShowAllVisitors()
{
  $result = $this->visitorService->showAllVisitors();
  $this->assertRegExp('!^<table>.+</table>$!', $result);
  $testData = $this->visitorService->getVisitorOps()->getTestData();
  foreach ($testData as $key => $value) {
    $dataWeWant = '!<td>' . $key . '</td>!';
    $this->assertRegExp($dataWeWant, $result);
  }
}
}
```

然后，您可能希望尝试最后两个小节中建议的变体，即*使用匿名类作为模拟对象*和*使用模拟构建器*。

## 还有更多...

其他断言测试操作包括数字、字符串、数组、对象、文件、JSON 和 XML，如下表所总结的：

| Category | 断言 |
| --- | --- |
| General | `assertEquals()`，`assertFalse()`，`assertEmpty()`，`assertNull()`，`assertSame()`，`assertThat()`，`assertTrue()` |
| Numeric | `assertGreaterThan()`，`assertGreaterThanOrEqual()`，`assertLessThan()`，`assertLessThanOrEqual()`，`assertNan()`，`assertInfinite()` |
| String | `assertStringEndsWith()`，`assertStringEqualsFile()`，`assertStringStartsWith()`，`assertRegExp()`，`assertStringMatchesFormat()`，`assertStringMatchesFormatFile()` |
| Array/iterator | `assertArrayHasKey()`，`assertArraySubset()`，`assertContains()`，`assertContainsOnly()`，`assertContainsOnlyInstancesOf()`，`assertCount()` |
| File | `assertFileEquals()`，`assertFileExists()` |
| Objects | `assertClassHasAttribute()`，`assertClassHasStaticAttribute()`，`assertInstanceOf()`，`assertInternalType()`，`assertObjectHasAttribute()` |
| JSON | `assertJsonFileEqualsJsonFile()`，`assertJsonStringEqualsJsonFile()`，`assertJsonStringEqualsJsonString()` |
| XML | `assertEqualXMLStructure()`，`assertXmlFileEqualsXmlFile()`，`assertXmlStringEqualsXmlFile()`，`assertXmlStringEqualsXmlString()` |

## 另请参阅...

+   要了解有关单元测试的讨论，请查看这里：[`en.wikipedia.org/wiki/Unit_testing`](https://en.wikipedia.org/wiki/Unit_testing)。

+   有关`composer.json`文件指令的更多信息，请参阅[`getcomposer.org/doc/04-schema.md`](https://getcomposer.org/doc/04-schema.md)。

+   要查看完整的断言列表，请查看 PHPUnit 文档页面：[`phpunit.de/manual/current/en/phpunit-book.html#appendixes.assertions`](https://phpunit.de/manual/current/en/phpunit-book.html#appendixes.assertions)。

+   PHPUnit 文档还详细介绍了在这里使用`getMockBuilder()`：[`phpunit.de/manual/current/en/phpunit-book.html#test-doubles.mock-objects`](https://phpunit.de/manual/current/en/phpunit-book.html#test-doubles.mock-objects)

# 编写测试套件

在阅读完上一篇后，您可能已经注意到手动运行`phpunit`并指定测试类和 PHP 文件可能会变得乏味。特别是在处理应用程序时，这些应用程序使用数十甚至数百个类和文件。PHPUnit 项目具有处理单个命令运行多个测试的内置功能。这样的一组测试称为**测试套件**。

## 如何做...

1.  最简单的情况下，您只需要将所有测试移动到一个文件夹中：

```php
**mkdir tests**
**cp *Test.php tests**

```

1.  您需要调整包含或需要外部文件的命令，以适应新位置。所示的示例（SimpleTest）是在前一篇中开发的：

```php
<?php
use PHPUnit\Framework\TestCase;
require_once __DIR__ . '/../chap_13_unit_test_simple.php';

class SimpleTest extends TestCase
{
  // etc.
```

1.  然后，您可以简单地使用目录路径作为参数运行`phpunit`。PHPUnit 将自动运行该文件夹中的所有测试。在此示例中，我们假设有一个`tests`子目录：

```php
**phpunit tests**

```

1.  您可以使用`--bootstrap`选项指定在运行测试之前执行的文件。此选项的典型用法是初始化自动加载：

```php
**phpunit --boostrap tests_with_autoload/bootstrap.php tests**

```

1.  这是实现自动加载的示例`bootstrap.php`文件：

```php
<?php
require __DIR__ . '/../../Application/Autoload/Loader.php';
Application\Autoload\Loader::init([__DIR__]);
```

1.  另一种可能性是使用 XML 配置文件定义一个或多个测试集。以下是一个示例，仅运行 Simple*测试：

```php
<phpunit>
  <testsuites>
    <testsuite name="simple">
      <file>SimpleTest.php</file>
      <file>SimpleDbTest.php</file>
      <file>SimpleClassTest.php</file>
    </testsuite>
  </testsuites>
</phpunit>
```

1.  以下是另一个示例，它基于目录运行测试，并指定了一个引导文件：

```php
<phpunit bootstrap="bootstrap.php">
  <testsuites>
    <testsuite name="visitor">
      <directory>Simple</directory>
    </testsuite>
  </testsuites>
</phpunit>
```

## 它是如何工作...

确保在上一篇中讨论的所有测试“编写简单测试”中已经定义。然后可以创建一个`tests`文件夹，并将所有`*Test.php`文件移动或复制到此文件夹中。然后需要调整`require_once`语句中的路径，如第 2 步所示。

为了演示 PHPUnit 如何运行本章为您定义的源代码中的所有测试，运行以下命令：

```php
**phpunit tests**

```

您应该看到以下输出：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-prog-cb/img/B05314_13_11.jpg)

为了演示通过引导文件进行自动加载，创建一个新的`tests_with_autoload`目录。在此文件夹中，使用步骤 5 中显示的代码定义一个`bootstrap.php`文件。在`tests_with_autoload`中创建两个目录：`Demo`和`Simple`。

从包含本章源代码的目录中，将文件（在上一篇中的第 12 步中讨论）复制到`tests_with_autoload/Demo/Demo.php`中。在开头的`<?php`标记后，添加这一行：

```php
namespace Demo;
```

接下来，将`SimpleTest.php`文件复制到`tests_with_autoload/Simple/ClassTest.php`中（注意文件名更改！）。您需要将前几行更改为以下内容：

```php
<?php
namespace Simple;
use Demo\Demo;
use PHPUnit\Framework\TestCase;

class ClassTest extends TestCase
{
  protected $demo;
  public function setup()
  {
    $this->demo = new Demo();
  }
// etc.
```

之后，创建一个`tests_with_autoload/phpunit.xml`文件，将所有内容整合在一起：

```php
<phpunit bootstrap="bootstrap.php">
  <testsuites>
    <testsuite name="visitor">
      <directory>Simple</directory>
    </testsuite>
  </testsuites>
</phpunit>
```

最后，切换到包含本章代码的目录。现在，您可以运行一个包含引导文件的单元测试，以及自动加载和命名空间，如下所示：

```php
**phpunit -c tests_with_autoload/phpunit.xml**

```

输出应如下所示：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-prog-cb/img/B05314_13_12.jpg)

## 另请参阅...

+   有关编写 PHPUnit 测试套件的更多信息，请参阅此文档页面：[`phpunit.de/manual/current/en/phpunit-book.html#organizing-tests.xml-configuration`](https://phpunit.de/manual/current/en/phpunit-book.html#organizing-tests.xml-configuration)。

# 生成虚假测试数据

测试和调试过程的一部分涉及整合真实的测试数据。在某些情况下，特别是在测试数据库访问和生成基准时，需要大量的测试数据。可以通过从网站中抓取数据的过程，然后将数据以真实但随机的组合放入数据库中来实现这一点。

## 如何做...

1.  第一步是确定测试应用程序所需的数据。另一个考虑因素是网站是否面向国际受众，还是市场主要来自单一国家？

1.  为了生成一致的假数据工具，将数据从其来源移动到可用的数字格式非常重要。第一选择是一系列数据库表。另一个不太吸引人的选择是 CSV 文件。

1.  您可能会分阶段转换数据。例如，您可以从列出国家代码和国家名称的网页中提取数据到一个文本文件中。![操作步骤...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-prog-cb/img/B05314_13_13.jpg)

1.  由于这个列表很短，将其直接剪切并粘贴到文本文件中非常容易。

1.  然后我们可以搜索“ ”并替换为“`\n`”，得到如下结果：![操作步骤...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-prog-cb/img/B05314_13_14.jpg)

1.  然后可以将其导入电子表格，然后可以将其导出为 CSV 文件。从那里，将其导入数据库就变得很简单。例如，phpMyAdmin 就有这样的功能。

1.  为了说明这一点，我们假设我们正在生成最终将出现在`prospects`表中的数据。以下是用于创建此表的 SQL 语句：

```php
CREATE TABLE 'prospects' (
  'id' int(11) NOT NULL AUTO_INCREMENT,
  'first_name' varchar(128) NOT NULL,
  'last_name' varchar(128) NOT NULL,
  'address' varchar(256) DEFAULT NULL,
  'city' varchar(64) DEFAULT NULL,
  'state_province' varchar(32) DEFAULT NULL,
  'postal_code' char(16) NOT NULL,
  'phone' varchar(16) NOT NULL,
  'country' char(2) NOT NULL,
  'email' varchar(250) NOT NULL,
  'status' char(8) DEFAULT NULL,
  'budget' decimal(10,2) DEFAULT NULL,
  'last_updated' datetime DEFAULT NULL,
  PRIMARY KEY ('id'),
  UNIQUE KEY 'UNIQ_35730C06E7927C74' ('email')
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
```

1.  现在是时候创建一个能够生成假数据的类了。然后我们将创建方法来为上面显示的每个字段生成数据，除了`id`，它是自动生成的：

```php
namespace Application\Test;

use PDO;
use Exception;
use DateTime;
use DateInterval;
use PDOException;
use SplFileObject;
use InvalidArgumentsException;
use Application\Database\Connection;

class FakeData
{
  // data generation methods here
}
```

1.  接下来，我们定义将用作过程一部分的常量和属性：

```php
const MAX_LOOKUPS     = 10;
const SOURCE_FILE     = 'file';
const SOURCE_TABLE    = 'table';
const SOURCE_METHOD   = 'method';
const SOURCE_CALLBACK = 'callback';
const FILE_TYPE_CSV   = 'csv';
const FILE_TYPE_TXT   = 'txt';
const ERROR_DB        = 'ERROR: unable to read source table';
const ERROR_FILE      = 'ERROR: file not found';
const ERROR_COUNT     = 'ERROR: unable to ascertain count or ID column missing';
const ERROR_UPLOAD    = 'ERROR: unable to upload file';
const ERROR_LOOKUP    = 'ERROR: unable to find any IDs in the source table';

protected $connection;
protected $mapping;
protected $files;
protected $tables;
```

1.  然后我们定义将用于生成随机字母、街道名称和电子邮件地址的属性。您可以将这些数组视为种子，可以根据需要进行修改和/或扩展。例如，您可以为法国受众替换巴黎的街道名称片段：

```php
protected $alpha = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
protected $street1 = ['Amber','Blue','Bright','Broad','Burning',
  'Cinder','Clear','Dewy','Dusty','Easy']; // etc. 
protected $street2 = ['Anchor','Apple','Autumn','Barn','Beacon',
  'Bear','Berry','Blossom','Bluff','Cider','Cloud']; // etc.
protected $street3 = ['Acres','Arbor','Avenue','Bank','Bend',
  'Canyon','Circle','Street'];
protected $email1 = ['northern','southern','eastern','western',
  'fast','midland','central'];
protected $email2 = ['telecom','telco','net','connect'];
protected $email3 = ['com','net'];
```

1.  在构造函数中，我们接受一个用于数据库访问的`Connection`对象，一个映射到假数据的数组：

```php
public function __construct(Connection $conn, array $mapping)
{
  $this->connection = $conn;
  $this->mapping = $mapping;
}
```

1.  为了生成街道名称，而不是尝试创建一个数据库表，使用一组种子数组来生成随机组合可能更有效。以下是这种方法可能的工作方式的示例：

```php
public function getAddress($entry)
{
  return random_int(1,999)
   . ' ' . $this->street1[array_rand($this->street1)]
   . ' ' . $this->street2[array_rand($this->street2)]
   . ' ' . $this->street3[array_rand($this->street3)];
}
```

1.  根据所需的逼真程度，您还可以构建一个将邮政编码与城市匹配的数据库表。邮政编码也可以随机生成。以下是一个为英国生成邮政编码的示例：

```php
public function getPostalCode($entry, $pattern = 1)
{
  return $this->alpha[random_int(0,25)]
   . $this->alpha[random_int(0,25)]
   . random_int(1, 99)
   . ' '
   . random_int(1, 9)
   . $this->alpha[random_int(0,25)]
   . $this->alpha[random_int(0,25)];
}
```

1.  生成假电子邮件也可以使用一组种子数组来产生随机结果。我们还可以编程让它接收一个现有的`$entry`数组，并使用这些参数来创建地址的名称部分：

```php
public function getEmail($entry, $params = NULL)
{
  $first = $entry[$params[0]] ?? $this->alpha[random_int(0,25)];
  $last  = $entry[$params[1]] ?? $this->alpha[random_int(0,25)];
  return $first[0] . '.' . $last
   . '@'
   . $this->email1[array_rand($this->email1)]
   . $this->email2[array_rand($this->email2)]
   . '.'
   . $this->email3[array_rand($this->email3)];
}
```

1.  对于日期生成，一个方法是接受一个现有的`$entry`数组作为参数。参数将是一个数组，其中第一个值是开始日期。第二个参数将是从开始日期*减去*的最大天数。这实际上让您从一个范围返回一个随机日期。请注意，我们使用`DateTime::sub()`来减去随机天数。`sub()`需要一个`DateInterval`实例，我们使用`P`、随机天数和`'D'`来构建它：

```php
public function getDate($entry, $params)
{
  list($fromDate, $maxDays) = $params;
  $date = new DateTime($fromDate);
  $date->sub(new DateInterval('P' . random_int(0, $maxDays) . 'D'));
  return $date->format('Y-m-d H:i:s');
}
```

1.  正如本教程开始时提到的，我们用于生成假数据的数据源会有所不同。在某些情况下，如前面几个步骤所示，我们使用种子数组，并构建假数据。在其他情况下，我们可能希望使用文本或 CSV 文件作为数据源。以下是这种方法可能的样子：

```php
public function getEntryFromFile($name, $type)
{
  if (empty($this->files[$name])) {
      $this->pullFileData($name, $type);
  }
  return $this->files[$name][
  random_int(0, count($this->files[$name]))];
}
```

1.  您会注意到，我们首先需要将文件数据提取到一个数组中，这个数组形成了返回值。以下是为我们执行此操作的方法。如果找不到指定的文件，我们会抛出一个`Exception`。文件类型被识别为我们的类常量之一：`FILE_TYPE_TEXT`或`FILE_TYPE_CSV`。根据类型，我们使用`fgetcsv()`或`fgets()`：

```php
public function pullFileData($name, $type)
{
  if (!file_exists($name)) {
      throw new Exception(self::ERROR_FILE);
  }
  $fileObj = new SplFileObject($name, 'r');
  if ($type == self::FILE_TYPE_CSV) {
      while ($data = $fileObj->fgetcsv()) {
        $this->files[$name][] = trim($data);
      }
  } else {
      while ($data = $fileObj->fgets()) {
        $this->files[$name][] = trim($data);
      }
  }
```

1.  这个过程中可能最复杂的部分是从数据库表中抽取随机数据。我们接受表名、包含主键的列的名称、在查找表中数据库列名和目标列名之间映射的数组作为参数：

```php
public function getEntryFromTable($tableName, $idColumn, $mapping)
{
  $entry = array();
  try {
      if (empty($this->tables[$tableName])) {
        $sql  = 'SELECT ' . $idColumn . ' FROM ' . $tableName 
          . ' ORDER BY ' . $idColumn . ' ASC LIMIT 1';
        $stmt = $this->connection->pdo->query($sql);
        $this->tables[$tableName]['first'] = 
          $stmt->fetchColumn();
        $sql  = 'SELECT ' . $idColumn . ' FROM ' . $tableName 
          . ' ORDER BY ' . $idColumn . ' DESC LIMIT 1';
        $stmt = $this->connection->pdo->query($sql);
        $this->tables[$tableName]['last'] = 
          $stmt->fetchColumn();
    }
```

1.  现在我们可以设置准备好的语句并初始化一些关键变量：

```php
$result = FALSE;
$count = self::MAX_LOOKUPS;
$sql  = 'SELECT * FROM ' . $tableName 
  . ' WHERE ' . $idColumn . ' = ?';
$stmt = $this->connection->pdo->prepare($sql);
```

1.  我们将实际的查找放在一个`do...while`循环中。原因是我们至少需要运行一次查询才能得到结果。只有当我们没有得到结果时，我们才继续循环。我们生成一个介于最低 ID 和最高 ID 之间的随机数，然后在查询的参数中使用这个数。请注意，我们还要减少一个计数器以防止无限循环。这是因为 ID 不是连续的情况下，我们可能会意外地生成一个不存在的 ID。如果我们超过了最大尝试次数，仍然没有结果，我们会抛出一个`Exception`：

```php
do {
  $id = random_int($this->tables[$tableName]['first'], 
    $this->tables[$tableName]['last']);
  $stmt->execute([$id]);
  $result = $stmt->fetch(PDO::FETCH_ASSOC);
} while ($count-- && !$result);
  if (!$result) {
      error_log(__METHOD__ . ':' . self::ERROR_LOOKUP);
      throw new Exception(self::ERROR_LOOKUP);
  }
} catch (PDOException $e) {
    error_log(__METHOD__ . ':' . $e->getMessage());
    throw new Exception(self::ERROR_DB);
}
```

1.  然后，我们使用映射数组从源表中检索值，使用目标表中预期的键：

```php
foreach ($mapping as $key => $value) {
  $entry[$value] = $result[$key] ?? NULL;
}
return $entry;
}
```

1.  这个类的核心是一个`getRandomEntry()`方法，它生成一个假数据的数组。我们逐个遍历`$mapping`，并检查各种参数：

```php
public function getRandomEntry()
{
  $entry = array();
  foreach ($this->mapping as $key => $value) {
    if (isset($value['source'])) {
      switch ($value['source']) {
```

1.  `source`参数用于实现有效地作为策略模式的功能。我们支持四种不同的`source`，都定义为类常量。第一个是`SOURCE_FILE`。在这种情况下，我们使用之前讨论过的`getEntryFromFile()`方法：

```php
        case self::SOURCE_FILE :
            $entry[$key] = $this->getEntryFromFile(
            $value['name'], $value['type']);
          break;
```

1.  回调选项根据`$mapping`数组中提供的回调返回一个值：

```php
        case self::SOURCE_CALLBACK :
            $entry[$key] = $value['name']();
          break;
```

1.  `SOURCE_TABLE`选项使用`$mapping`中定义的数据库表作为查找。请注意，之前讨论的`getEntryFromTable()`能够返回一个值数组，这意味着我们需要使用`array_merge()`来合并结果：

```php
        case self::SOURCE_TABLE :
            $result = $this->getEntryFromTable(
            $value['name'],$value['idCol'],$value['mapping']);
            $entry = array_merge($entry, $result);
          break;
```

1.  `SOURCE_METHOD`选项，也是默认选项，使用了这个类中已经包含的一个方法。我们检查是否包括了参数，如果有，就将其添加到方法调用中。注意使用`{}`来影响插值。如果我们进行了`$this->$value['name']()`的 PHP 7 调用，由于抽象语法树（AST）的重写，它会插值为`${$this->$value}['name']()`，这不是我们想要的：

```php
        case self::SOURCE_METHOD :
        default :
          if (!empty($value['params'])) {
              $entry[$key] = $this->{$value['name']}(
                $entry, $value['params']);
          } else {
              $entry[$key] = $this->{$value['name']}($entry);
          }
        }
    }
  }
  return $entry;
}
```

1.  我们定义一个循环遍历`getRandomEntry()`以生成多行假数据的方法。我们还添加了一个选项来插入到目标表。如果启用了这个选项，我们设置一个准备好的语句来插入，并检查是否需要截断当前表中的任何数据：

```php
public function generateData(
$howMany, $destTableName = NULL, $truncateDestTable = FALSE)
{
  try {
      if ($destTableName) {
        $sql = 'INSERT INTO ' . $destTableName
          . ' (' . implode(',', array_keys($this->mapping)) 
          . ') '. ' VALUES ' . ' (:' 
          . implode(',:', array_keys($this->mapping)) . ')';
        $stmt = $this->connection->pdo->prepare($sql);
        if ($truncateDestTable) {
          $sql = 'DELETE FROM ' . $destTableName;
          $this->connection->pdo->query($sql);
        }
      }
  } catch (PDOException $e) {
      error_log(__METHOD__ . ':' . $e->getMessage());
      throw new Exception(self::ERROR_COUNT);
  }
```

1.  接下来，我们循环请求的数据行数，并运行`getRandomEntry()`。如果请求插入数据库，我们在`try/catch`块中执行准备好的语句。无论如何，我们使用`yield`关键字将这个方法转换为生成器：

```php
for ($x = 0; $x < $howMany; $x++) {
  $entry = $this->getRandomEntry();
  if ($insert) {
    try {
        $stmt->execute($entry);
    } catch (PDOException $e) {
        error_log(__METHOD__ . ':' . $e->getMessage());
        throw new Exception(self::ERROR_DB);
    }
  }
  yield $entry;
}
}
```

### 提示

**最佳实践**

如果要返回的数据量很大，最好在生成数据时将数据作为生成的数据，从而节省数组所需的内存。

## 工作原理...

首先要做的是确保你已经准备好了随机数据生成的数据。在这个示例中，我们假设目标表是`prospects`，其 SQL 数据库定义如步骤 7 所示。

作为名字的数据源，你可以创建名字和姓氏的文本文件。在这个示例中，我们将引用`data/files`目录和文件`first_names.txt`和`surnames.txt`。对于城市、州或省、邮政编码和国家，可能有必要从[`www.geonames.org/`](http://www.geonames.org/)这样的来源下载数据，并上传到`world_city_data`表中。对于其余的字段，比如地址、电子邮件、状态等，你可以使用`FakeData`中内置的方法，或者定义回调函数。

接下来，请确保定义`Application\Test\FakeData`，添加步骤 8 到 29 中讨论的内容。完成后，创建一个名为`chap_13_fake_data.php`的调用程序，设置自动加载并使用适当的类。您还应该定义与数据库配置路径和文件名匹配的常量：

```php
<?php
define('DB_CONFIG_FILE', __DIR__ . '/../config/db.config.php');
define('FIRST_NAME_FILE', __DIR__ . '/../data/files/first_names.txt');
define('LAST_NAME_FILE', __DIR__ . '/../data/files/surnames.txt');
require __DIR__ . '/../Application/Autoload/Loader.php';
Application\Autoload\Loader::init(__DIR__ . '/..');
use Application\Test\FakeData;
use Application\Database\Connection;
```

接下来，定义一个映射数组，该数组使用目标表（prospects）中的列名作为键。然后，您需要为`source`、`name`和任何其他所需的参数定义子键。首先，'`first_name`'和'`last_name`'都将使用文件作为源，'name'指向文件的名称，'`type`'表示文本文件类型：

```php
$mapping = [
  'first_name'   => ['source' => FakeData::SOURCE_FILE,
  'name'         => FIRST_NAME_FILE,
  'type'         => FakeData::FILE_TYPE_TXT],
  'last_name'    => ['source' => FakeData::SOURCE_FILE,
  'name'         => LAST_NAME_FILE,
  'type'         => FakeData::FILE_TYPE_TXT],
```

`'address'`、`'email'`和`'last_updated'`都使用内置方法作为数据源。最后两个还定义了要传递的参数：

```php
  'address'      => ['source' => FakeData::SOURCE_METHOD,
  'name'         => 'getAddress'],
  'email'        => ['source' => FakeData::SOURCE_METHOD,
  'name'         => 'getEmail',
  'params'       => ['first_name','last_name']],
  'last_updated' => ['source' => FakeData::SOURCE_METHOD,
  'name'         => 'getDate',
  'params'       => [date('Y-m-d'), 365*5]]
```

`'phone'`、`'status'`和`'budget'`都可以使用回调来提供虚假数据：

```php
  'phone'        => ['source' => FakeData::SOURCE_CALLBACK,
  'name'         => function () {
                    return sprintf('%3d-%3d-%4d', random_int(101,999),
                    random_int(101,999), random_int(0,9999)); }],
  'status'       => ['source' => FakeData::SOURCE_CALLBACK,
  'name'         => function () { $status = ['BEG','INT','ADV']; 
                    return $status[rand(0,2)]; }],
  'budget'       => ['source' => FakeData::SOURCE_CALLBACK,
                     'name' => function() { return random_int(0, 99999) 
                     + (random_int(0, 99) * .01); }]
```

最后，`'city'`从查找表中获取数据，该表还为`'mapping'`参数中列出的字段提供数据。然后，您可以将这些键未定义。请注意，您还应指定表示表的主键的列：

```php
'city' => ['source' => FakeData::SOURCE_TABLE,
'name' => 'world_city_data',
'idCol' => 'id',
'mapping' => [
'city' => 'city', 
'state_province' => 'state_province',
'postal_code_prefix' => 'postal_code', 
'iso2' => 'country']
],
  'state_province'=> [],
  'postal_code'  => [],
  'country'    => [],
];
```

然后，您可以定义目标表、`Connection`实例，并创建`FakeData`实例。`foreach()`循环足以显示给定数量的条目：

```php
$destTableName = 'prospects';
$conn = new Connection(include DB_CONFIG_FILE);
$fake = new FakeData($conn, $mapping);
foreach ($fake->generateData(10) as $row) {
  echo implode(':', $row) . PHP_EOL;
}
```

对于 10 行，输出将如下所示：

![工作原理...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-prog-cb/img/B05314_13_15.jpg)

## 还有更多...

以下是各种数据列表的网站摘要，这些数据列表在生成测试数据时可能有用：

| 数据类型 | URL | 备注 |
| --- | --- | --- |
| 名字 | [`nameberry.com/`](http://nameberry.com/) |   |
|   | [`www.babynamewizard.com/international-names-lists-popular-names-from-around-the-world`](http://www.babynamewizard.com/international-names-lists-popular-names-from-around-the-world) |   |
| 原始姓名列表 | [`deron.meranda.us/data/census-dist-female-first.txt`](http://deron.meranda.us/data/census-dist-female-first.txt) | 美国女性名字 |
|   | [`deron.meranda.us/data/census-dist-male-first.txt`](http://deron.meranda.us/data/census-dist-male-first.txt) | 美国男性名字 |
|   | [`www.avss.ucsb.edu/NameFema.HTM`](http://www.avss.ucsb.edu/NameFema.HTM) | 美国女性名字 |
|   | [`www.avss.ucsb.edu/namemal.htm`](http://www.avss.ucsb.edu/namemal.htm) | 美国男性名字 |
| 姓氏 | [`names.mongabay.com/data/1000.html`](http://names.mongabay.com/data/1000.html) | 美国人口普查中的美国姓氏 |
|   | [`surname.sofeminine.co.uk/w/surnames/most-common-surnames-in-great-britain.html`](http://surname.sofeminine.co.uk/w/surnames/most-common-surnames-in-great-britain.html) | 英国姓氏 |
|   | [`gist.github.com/subodhghulaxe/8148971`](https://gist.github.com/subodhghulaxe/8148971) | 以 PHP 数组形式列出的美国姓氏列表 |
|   | [`www.dutchgenealogy.nl/tng/surnames-all.php`](http://www.dutchgenealogy.nl/tng/surnames-all.php) | 荷兰姓氏 |
|   | [`www.worldvitalrecords.com/browsesurnames.aspx?l=A`](http://www.worldvitalrecords.com/browsesurnames.aspx?l=A) | 国际姓氏；只需更改最后一个或多个字母，即可获得以该字母开头的名字列表 |
| 城市 | [`www.travelgis.com/default.asp?framesrc=/cities/`](http://www.travelgis.com/default.asp?framesrc=/cities/) | 世界城市 |
|   | [`www.maxmind.com/en/free-world-cities-database`](https://www.maxmind.com/en/free-world-cities-database) |   |
|   | [`github.com/David-Haim/CountriesToCitiesJSON`](https://github.com/David-Haim/CountriesToCitiesJSON) |   |
|   | [`www.fallingrain.com/world/index.html`](http://www.fallingrain.com/world/index.html) |   |
| 邮政编码 | [`boutell.com/zipcodes/`](https://boutell.com/zipcodes/) | 仅限美国；包括城市、邮政编码、纬度和经度 |
|   | [`www.geonames.org/export/`](http://www.geonames.org/export/) | 国际; 城市名称，邮政编码，一切！; 免费下载 |

# 使用 session_start 参数自定义会话

直到 PHP 7，为了覆盖`php.ini`设置以进行安全会话管理，您必须使用一系列`ini_set()`命令。这种方法非常恼人，因为您还需要知道哪些设置是可用的，并且很难在其他应用程序中重复使用相同的设置。然而，从 PHP 7 开始，您可以向`session_start()`命令提供一系列参数，这将立即设置这些值。

## 如何做...

1.  我们首先开发一个`Application\Security\SessOptions`类，该类将保存会话参数，并且还具有启动会话的能力。我们还定义了一个类常量，以防传递无效的会话选项：

```php
namespace Application\Security;
use ReflectionClass;
use InvalidArgumentsException;
class SessOptions
{
  const ERROR_PARAMS = 'ERROR: invalid session options';
```

1.  接下来，我们扫描`php.ini`会话指令列表（在[`php.net/manual/en/session.configuration.php`](http://php.net/manual/en/session.configuration.php)中记录）。我们特别寻找`Changeable`列中标记为`PHP_INI_ALL`的指令。这些指令可以在运行时被覆盖，因此可以作为`session_start()`的参数使用：![如何做...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-prog-cb/img/B05314_13_16.jpg)

1.  然后，我们将这些定义为类常量，这将使该类更易于开发。大多数优秀的代码编辑器都能够扫描类并为您提供常量列表，从而轻松管理会话设置。请注意，并非所有设置都显示在书中，以节省空间：

```php
const SESS_OP_NAME         = 'name';
const SESS_OP_LAZY_WRITE   = 'lazy_write';  // AVAILABLE // SINCE PHP 7.0.0.
const SESS_OP_SAVE_PATH    = 'save_path';
const SESS_OP_SAVE_HANDLER = 'save_handler';
// etc.
```

1.  然后，我们可以定义构造函数，它接受一个`php.ini`会话设置数组作为参数。我们使用`ReflectionClass`来获取类常量列表，并通过循环运行`$options`参数来确认设置是否允许。还要注意使用`array_flip()`，它可以翻转键和值，以便我们的类常量的实际值形成数组键，类常量的名称成为值：

```php
protected $options;
protected $allowed;
public function __construct(array $options)
{
  $reflect = new ReflectionClass(get_class($this));
  $this->allowed = $reflect->getConstants();
  $this->allowed = array_flip($this->allowed);
  unset($this->allowed[self::ERROR_PARAMS]);
  foreach ($options as $key => $value) {
    if(!isset($this->allowed[$key])) {
      error_log(__METHOD__ . ':' . self::ERROR_PARAMS);
      throw new InvalidArgumentsException(
      self::ERROR_PARAMS);
    }
  }
  $this->options = $options;
}
```

1.  最后，我们以另外两种方法结束；一种方法让我们可以从外部访问允许的参数，另一种方法启动会话：

```php
public function getAllowed()
{
  return $this->allowed;
}

public function start()
{
  session_start($this->options);
}
```

## 它是如何工作的...

将本章讨论的所有代码放入`Application\Security`目录中的`SessOptions.php`文件中。然后，您可以定义一个名为`chap_13_session_options.php`的调用程序来测试新类，该程序设置自动加载并使用该类：

```php
<?php
require __DIR__ . '/../Application/Autoload/Loader.php';
Application\Autoload\Loader::init(__DIR__ . '/..');
use Application\Security\SessOptions;
```

接下来，定义一个数组，使用类常量作为键，所需的值来管理会话。请注意，在此处显示的示例中，会话信息存储在一个名为`session`的子目录中，您需要创建该目录：

```php
$options = [
  SessOptions::SESS_OP_USE_ONLY_COOKIES => 1,
  SessOptions::SESS_OP_COOKIE_LIFETIME => 300,
  SessOptions::SESS_OP_COOKIE_HTTPONLY => 1,
  SessOptions::SESS_OP_NAME => 'UNLIKELYSOURCE',
  SessOptions::SESS_OP_SAVE_PATH => __DIR__ . '/session'
];
```

现在，您可以创建`SessOptions`实例并运行`start()`来启动会话。您可以在此处使用`phpinfo()`显示有关会话的一些信息：

```php
$sessOpt = new SessOptions($options);
$sessOpt->start();
$_SESSION['test'] = 'TEST';
phpinfo(INFO_VARIABLES);
```

如果您使用浏览器的开发人员工具查找有关 cookie 的信息，您会注意到名称设置为`UNLIKELYSOURCE`，到期时间是从现在开始的 5 分钟：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-prog-cb/img/B05314_13_17.jpg)

如果您扫描会话目录，您会看到会话信息已存储在那里：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-prog-cb/img/B05314_13_18.jpg)

## 另请参阅...

+   有关与会话相关的`php.ini`指令的更多信息，请参阅此摘要：[`php.net/manual/en/session.configuration.php`](http://php.net/manual/en/session.configuration.php)
